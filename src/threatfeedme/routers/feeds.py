"""Feed source management, custom-list uploads, and manual refresh endpoints."""
import os
import re
from typing import Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile

from threatfeedme import pipeline
from threatfeedme.auth import csrf_check, require_auth
from threatfeedme import core
from threatfeedme.credentials import KeyPolicy, split_vars
from threatfeedme.feed_ingestor import parse_domain_feed_content, parse_feed_content
from threatfeedme.models import FeedSource, FeedType
from threatfeedme.scheduler import _refresh_state, start_refresh_async
from threatfeedme.schemas import ApiKeyRequest, FeedRequest, WhitelistResponse
from threatfeedme.scorer import fp_penalty_factor

router = APIRouter()

# Uploaded custom lists are stored here (never a client-supplied path), and all
# runtime local-file feeds must resolve within this directory.
MAX_UPLOAD_BYTES = 5 * 1024 * 1024  # 5 MB cap on uploaded lists


def _safe_upload_path(feed_name: str) -> str:
    """Resolve a feed name to a storage path inside UPLOAD_DIR.

    The client filename is never used. The name is slugified to a safe token,
    and the resolved path is boundary-checked to guarantee it cannot escape
    UPLOAD_DIR (defence against path traversal).
    """
    slug = re.sub(r'[^A-Za-z0-9._-]', '_', feed_name).strip('._')[:64]
    if not slug:
        raise ValueError("invalid feed name")
    # realpath resolves any symlink so the containment check can't be fooled by
    # a symlinked component (belt-and-suspenders; the slug already strips '/').
    path = os.path.realpath(os.path.join(core.UPLOAD_DIR, slug + ".txt"))
    if os.path.commonpath([core.UPLOAD_DIR, path]) != core.UPLOAD_DIR:
        raise ValueError("resolved path escapes the uploads directory")
    return path


def _is_within_uploads(path: str) -> bool:
    """True if an absolute/real path is contained within UPLOAD_DIR."""
    try:
        real = os.path.realpath(path)
        return os.path.commonpath([core.UPLOAD_DIR, real]) == core.UPLOAD_DIR
    except (ValueError, OSError):
        return False


@router.get("/api/feeds")
def get_feeds(_=Depends(require_auth)):
    """Get feed statistics (last ingest run per feed)."""
    return core.db.get_feed_stats()


# ---------------------- Feed source management ----------------------

# Formats an operator may pick for a feed they add, and the scraper each maps
# to. Deliberately a closed list: scraper names are never taken from a client.
_FORMAT_SCRAPERS = {"list": None, "taxii21": "taxii21"}


@router.get("/api/feed-sources")
def get_feed_sources(_=Depends(require_auth)):
    """List configured feed sources."""
    return core.db.get_feed_sources()


@router.post("/api/feed-sources", response_model=WhitelistResponse)
def add_feed_source(request: FeedRequest, _=Depends(require_auth), _csrf=Depends(csrf_check)):
    """Add or update a feed source (custom feeds included)."""
    name = request.name.strip()
    url = request.url.strip()
    # Constrain the name to a safe slug (keeps it usable as a source key and
    # prevents any markup/script from a crafted name reaching the dashboard).
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", name):
        raise HTTPException(
            status_code=400,
            detail="Feed name may only contain letters, numbers, dot, dash, underscore (max 64)",
        )
    # Remote feeds must be plain http/https URLs (no file://, ftp://, etc.).
    if not request.local_file and not re.match(r"https?://", url, re.IGNORECASE):
        raise HTTPException(status_code=400, detail="Feed URL must start with http:// or https://")
    if request.indicator_kind not in ("ip", "domain"):
        raise HTTPException(status_code=400, detail="indicator_kind must be 'ip' or 'domain'")
    scraper = _FORMAT_SCRAPERS.get(request.format, "unknown")
    if scraper == "unknown":
        raise HTTPException(status_code=400, detail="format must be 'list' or 'taxii21'")
    if scraper == "taxii21":
        if request.local_file:
            raise HTTPException(status_code=400, detail="A TAXII feed must be a URL")
        from threatfeedme.feed_ingestor import taxii_objects_url
        try:
            taxii_objects_url(url)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
    # auth_env names the env var whose VALUE is sent as this feed's key, so it
    # must never name someone else's secret (UNIFI_PASSWORD, DASHBOARD_*) or a
    # process knob (HTTPS_PROXY). See credentials.py.
    if request.auth_env:
        policy = KeyPolicy.from_config(core.config)
        for var in split_vars(request.auth_env):
            reason = policy.disallowed_reason(var)
            if reason:
                raise HTTPException(status_code=400, detail=reason)
    try:
        feed = FeedSource(
            name=name,
            url=url,
            feed_type=FeedType(request.feed_type),
            weight=request.weight,
            update_interval=request.update_interval,
            requires_auth=request.requires_auth or bool(request.auth_env),
            auth_env=request.auth_env,
            auth_header=request.auth_header,
            local_file=request.local_file,
            enabled=request.enabled,
            indicator_kind=request.indicator_kind,
            scraper=scraper,
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid feed: {e}")
    if not feed.name or not feed.url:
        raise HTTPException(status_code=400, detail="name and url are required")
    # Security: a runtime-added local-file feed may only reference files inside
    # the uploads directory. This prevents pointing a feed at arbitrary server
    # files (e.g. /etc/passwd) to have their contents read. Use the upload
    # endpoint to add a local list.
    if feed.local_file and not _is_within_uploads(feed.url):
        raise HTTPException(
            status_code=400,
            detail="Local-file feeds must be uploaded via /api/feeds/upload",
        )
    existing = core.db.get_feed_source(feed.name)
    if existing is not None and not request.overwrite:
        raise HTTPException(
            status_code=409,
            detail=(f"A feed named '{feed.name}' already exists "
                    f"({'uploaded list' if existing.local_file else existing.url}). "
                    "Choose another name, or confirm to replace it."),
        )
    # Early SSRF feedback: an internal or metadata-service URL is refused here
    # with a clear reason, instead of being stored and failing every refresh.
    # Not the enforcing check (the connect-time guard is, on every fetch); an
    # unresolvable host is accepted and reports its error when fetched.
    safety_cfg = core.config.get('safety', {}) or {}
    if not feed.local_file and not safety_cfg.get('allow_private_feed_urls', False):
        from threatfeedme import feed_ingestor
        try:
            feed_ingestor._require_public_url(feed.url)
        except RuntimeError as e:
            raise HTTPException(status_code=400, detail=str(e))
        except Exception:
            pass
    core.db.add_feed(feed)
    return WhitelistResponse(success=True, message=f"Feed '{feed.name}' saved")


# Alias so the UI can POST to /api/feeds too (GET returns stats, POST adds).
@router.post("/api/feeds", response_model=WhitelistResponse)
def add_feed_alias(request: FeedRequest, _=Depends(require_auth), _csrf=Depends(csrf_check)):
    return add_feed_source(request, _)


@router.post("/api/feeds/upload", response_model=WhitelistResponse)
async def upload_feed(
    name: str = Form(...),
    weight: float = Form(1.0),
    feed_type: str = Form(FeedType.CUSTOM.value),
    indicator_kind: str = Form("ip"),
    file: UploadFile = File(...),
    _=Depends(require_auth),
    _csrf=Depends(csrf_check),
):
    """Upload a custom IP/CIDR or domain list as a local-file feed.

    Security controls:
      - storage path is derived from the feed name and boundary-checked to stay
        inside UPLOAD_DIR (the client filename is never trusted);
      - the upload is size-capped and read in bounded chunks;
      - binary content (null bytes) is rejected;
      - the list must contain at least one valid entry of the declared kind
        (D8: the kind is declared, never sniffed — an IP upload never yields
        domains and vice versa).
    """
    # Validate the feed type early.
    try:
        ftype = FeedType(feed_type)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid feed_type")
    if indicator_kind not in ("ip", "domain"):
        raise HTTPException(status_code=400, detail="indicator_kind must be 'ip' or 'domain'")

    # Resolve a safe destination path (raises on traversal / bad name).
    try:
        dest = _safe_upload_path(name)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # Read with a hard size cap so a huge upload can't exhaust memory/disk.
    data = bytearray()
    while True:
        chunk = await file.read(64 * 1024)
        if not chunk:
            break
        data.extend(chunk)
        if len(data) > MAX_UPLOAD_BYTES:
            raise HTTPException(
                status_code=413,
                detail=f"File exceeds {MAX_UPLOAD_BYTES // (1024*1024)} MB limit",
            )

    # Reject binary content: null bytes, or anything that isn't valid UTF-8
    # (strict decode rather than silently replacing mangled bytes).
    if b"\x00" in data:
        raise HTTPException(status_code=415, detail="Binary files are not allowed")
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise HTTPException(status_code=415, detail="File must be UTF-8 text")
    if indicator_kind == "domain":
        indicators = parse_domain_feed_content(text)
        if not indicators:
            raise HTTPException(status_code=422, detail="No valid domains found in file")
    else:
        indicators = parse_feed_content(text)
        if not indicators:
            raise HTTPException(status_code=422, detail="No valid IPs or CIDRs found in file")

    # Persist the sanitized list, then register/point the feed at it.
    with open(dest, "w", encoding="utf-8", newline="\n") as f:
        for entry in indicators:
            f.write((entry.get("cidr") or entry["ip"]) + "\n")

    feed = FeedSource(
        name=re.sub(r'[^A-Za-z0-9._-]', '_', name).strip('._')[:64],
        url=dest, feed_type=ftype, weight=weight, local_file=True, enabled=True,
        indicator_kind=indicator_kind,
    )
    # Re-uploading your own list is how it gets updated; turning a REMOTE feed
    # (a shipped default, say) into an upload by reusing its name is not.
    existing = core.db.get_feed_source(feed.name)
    if existing is not None and not existing.local_file:
        raise HTTPException(
            status_code=409,
            detail=f"'{feed.name}' is a remote feed ({existing.url}); upload under another name",
        )
    core.db.add_feed(feed)
    return WhitelistResponse(
        success=True,
        message=f"Uploaded '{feed.name}' with {len(indicators)} indicators",
    )


@router.delete("/api/feeds/{name}")
def delete_feed(name: str, _=Depends(require_auth), _csrf=Depends(csrf_check)):
    """Remove a configured feed source (and purge the data it contributed)."""
    if core.db.remove_feed(name):
        # Purging that feed's source attributions changes source counts, so
        # rescore the remaining indicators to update their tiers.
        pipeline.recalculate(core.db, core.config)
        return {"success": True, "message": f"Feed '{name}' removed"}
    raise HTTPException(status_code=404, detail="Feed not found")


@router.post("/api/feeds/restore-defaults")
def restore_default_feeds(_=Depends(require_auth), _csrf=Depends(csrf_check)):
    """Re-add the curated default feeds from config that are missing, without
    touching feeds the user has customized."""
    added = core.db.restore_default_feeds(core.config)
    return {"success": True, "added": added, "count": len(added)}


@router.post("/api/feeds/{name}/enabled")
def toggle_feed(name: str, enabled: bool, _=Depends(require_auth), _csrf=Depends(csrf_check)):
    """Enable or disable a feed without deleting it."""
    if core.db.set_feed_enabled(name, enabled):
        return {"success": True, "name": name, "enabled": enabled}
    raise HTTPException(status_code=404, detail="Feed not found")


# ---------------------- Feed API keys ----------------------
# Keys are stored in a .env file next to the database (persisted on the
# Docker data volume) and applied to os.environ immediately. They are write-
# only through this API: status endpoints report configured true/false and
# never echo the value.

_ENV_VAR_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")


def _write_env_var(path: str, var: str, value: Optional[str]) -> None:
    """Set or remove VAR in the .env file, preserving other lines. Written
    atomically; file permissions restricted best-effort (no-op on Windows)."""
    lines = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            lines = [l.rstrip("\n") for l in f]
    except (FileNotFoundError, OSError):
        pass
    lines = [l for l in lines if not l.strip().startswith(f"{var}=")]
    if value is not None:
        lines.append(f"{var}={value}")
    tmp = path + ".tmp"
    # Create the temp file 0600 from the first byte. It used to be created
    # with the umask default (often world-readable) and only chmod'ed after
    # the rename, leaving a window in which the secrets file was readable.
    fd = os.open(tmp, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
    try:
        os.chmod(tmp, 0o600)   # O_CREAT's mode is ignored if tmp pre-existed
    except OSError:
        pass
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines) + ("\n" if lines else ""))
    os.replace(tmp, path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


# ---------------------- Feed false-positive attributions ----------------------
# Flagging an IP as a false positive penalizes the feeds that reported it.
# The penalty is meant to last only as long as the whitelist entry, but an
# operator may also want to forgive a feed directly — these endpoints back the
# dashboard's clickable "N FP" badge.

@router.get("/api/feeds/{name}/false-positives")
def feed_false_positives(name: str, _=Depends(require_auth)):
    """List the false positives attributed to a feed, with its current
    reputation penalty. `orphaned` entries have no whitelist entry left."""
    if core.db.get_feed_source(name) is None:
        raise HTTPException(status_code=404, detail="Feed not found")
    entries = core.db.get_feed_false_positives(name)
    reported = core.db.get_feed_report_counts().get(name, 0)
    factor = fp_penalty_factor(len(entries), reported)
    return {
        "feed": name,
        "count": len(entries),
        "reported": reported,
        "penalty_pct": int(round((1 - factor) * 100)),
        "entries": entries,
    }


@router.delete("/api/feeds/{name}/false-positives")
def clear_feed_false_positives(name: str, ip: Optional[str] = None,
                               _=Depends(require_auth), _csrf=Depends(csrf_check)):
    """Forgive false positives against a feed: one with ?ip=<ip>, or all of
    them. Restores the feed's reputation and rescores immediately so the
    change shows up in the served tiers without waiting for a refresh.

    The whitelist entries themselves are left alone — an IP stays whitelisted
    (still excluded from the feeds); only the blame against this feed is
    withdrawn.
    """
    if core.db.get_feed_source(name) is None:
        raise HTTPException(status_code=404, detail="Feed not found")
    if ip:
        core.db.clear_feedback(ip, feed_name=name)
        cleared = 1
    else:
        cleared = core.db.clear_feed_feedback(name)
    if cleared:
        # Reputation changed for this feed, so every indicator it reported
        # can shift tier — full rescore, then re-export the tier files.
        pipeline.recalculate(core.db, core.config)
        pipeline.export_tiers_async(core.db, core.config)
    return {"success": True, "cleared": cleared, "feed": name}


@router.get("/api/feeds/{name}/api-key")
def api_key_status(name: str, _=Depends(require_auth)):
    """Whether the feed's API key is configured. Never returns the key."""
    feed = core.db.get_feed_source(name)
    if feed is None:
        raise HTTPException(status_code=404, detail="Feed not found")
    if not feed.auth_env:
        return {"auth_env": None, "configured": False, "vars": []}
    env_vars = [v.strip() for v in feed.auth_env.split(',') if v.strip()]
    return {
        "auth_env": feed.auth_env,
        "vars": [{"name": v, "configured": bool(os.environ.get(v))} for v in env_vars],
        "configured": all(os.environ.get(v) for v in env_vars),
    }


@router.post("/api/feeds/{name}/api-key")
def set_api_key(name: str, request: ApiKeyRequest,
                _=Depends(require_auth), _csrf=Depends(csrf_check)):
    """Save (or clear, with an empty key) a feed's API key.

    The key is written to the data-volume .env so it survives restarts, and
    exported to the process environment so the next fetch uses it without a
    restart. An env var set by the operator (compose/shell) wins on restart.
    """
    feed = core.db.get_feed_source(name)
    if feed is None:
        raise HTTPException(status_code=404, detail="Feed not found")
    if not feed.auth_env:
        raise HTTPException(
            status_code=400,
            detail="This feed has no auth_env configured; set one on the feed first",
        )
    declared = [v.strip() for v in feed.auth_env.split(',') if v.strip()]
    if not all(_ENV_VAR_RE.fullmatch(v) for v in declared):
        raise HTTPException(status_code=400, detail="Feed auth_env is not a valid variable name")
    # Re-checked here, not only at add time: a feed stored before this rule
    # (auth_env=HTTPS_PROXY) must not turn this endpoint into an environment
    # editor that reroutes every outbound request through an attacker proxy.
    policy = KeyPolicy.from_config(core.config)
    for var in declared:
        reason = policy.disallowed_reason(var)
        if reason:
            raise HTTPException(status_code=400, detail=reason)

    # Multi-credential feeds submit {ENV_VAR: value}; single-var feeds may
    # keep using the plain api_key field. Only vars the feed declares in
    # auth_env are writable — this endpoint must never become a generic
    # environment editor.
    if request.keys is not None:
        submitted = request.keys
        unknown = sorted(set(submitted) - set(declared))
        if unknown:
            raise HTTPException(
                status_code=400,
                detail=f"Variable(s) not declared by this feed: {', '.join(unknown)}",
            )
    elif len(declared) == 1:
        submitted = {declared[0]: request.api_key}
    else:
        raise HTTPException(
            status_code=400,
            detail=f"This feed needs multiple credentials ({feed.auth_env}); "
                   "submit them as {\"keys\": {VAR: value}}",
        )

    for var, raw in submitted.items():
        value = raw.strip()
        if any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise HTTPException(status_code=400, detail="API key contains control characters")
        _write_env_var(core.env_file(), var, value or None)
        if value:
            os.environ[var] = value
        else:
            os.environ.pop(var, None)
    return {"success": True, "auth_env": feed.auth_env,
            "configured": all(os.environ.get(v) for v in declared)}


# ---------------------- Refresh (manual) ----------------------

@router.post("/api/refresh")
def trigger_refresh(feed: Optional[str] = None, _=Depends(require_auth), _csrf=Depends(csrf_check)):
    """Force a refresh now (all enabled feeds, or one via ?feed=<name>).

    Runs in a background thread; returns immediately. 409 if one is already
    running. Poll /api/refresh/status for completion."""
    if feed is not None and core.db.get_feed_source(feed) is None:
        raise HTTPException(status_code=404, detail="Feed not found")
    if _refresh_state["running"]:
        raise HTTPException(status_code=409, detail="A refresh is already running")

    # start_refresh_async sets running=True before returning, so the client's
    # first status poll already sees the refresh in progress; its lock also
    # closes the race where two rapid POSTs both pass the check above.
    if not start_refresh_async([feed] if feed else None):
        raise HTTPException(status_code=409, detail="A refresh is already running")
    return {"success": True, "started": True, "feed": feed or "all"}


@router.get("/api/refresh/status")
def refresh_status(_=Depends(require_auth)):
    """Current refresh state, the result of the last run, and the soonest feed
    to come due (each feed runs on its own clock, so there's no single "next")."""
    from threatfeedme import pipeline
    from threatfeedme.scheduler import _refresh_interval_minutes
    try:
        nxt = pipeline.next_due(core.db, _refresh_interval_minutes() * 60)
    except Exception:
        nxt = None
    return {**_refresh_state, "next": nxt}
