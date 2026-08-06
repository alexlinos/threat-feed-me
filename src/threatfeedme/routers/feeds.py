"""Feed source management, custom-list uploads, and manual refresh endpoints."""
import os
import re
from typing import Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile

from threatfeedme import pipeline
from threatfeedme.auth import csrf_check, require_auth
from threatfeedme import core
from threatfeedme.feed_ingestor import parse_feed_content
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
    file: UploadFile = File(...),
    _=Depends(require_auth),
    _csrf=Depends(csrf_check),
):
    """Upload a custom IP/CIDR list as a local-file feed.

    Security controls:
      - storage path is derived from the feed name and boundary-checked to stay
        inside UPLOAD_DIR (the client filename is never trusted);
      - the upload is size-capped and read in bounded chunks;
      - binary content (null bytes) is rejected;
      - the list must contain at least one valid IP/CIDR.
    """
    # Validate the feed type early.
    try:
        ftype = FeedType(feed_type)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid feed_type")

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
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
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
        return {"auth_env": None, "configured": False}
    return {"auth_env": feed.auth_env, "configured": bool(os.environ.get(feed.auth_env))}


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
    if not _ENV_VAR_RE.fullmatch(feed.auth_env):
        raise HTTPException(status_code=400, detail="Feed auth_env is not a valid variable name")
    key = request.api_key.strip()
    if any(ord(c) < 32 or ord(c) == 127 for c in key):
        raise HTTPException(status_code=400, detail="API key contains control characters")

    _write_env_var(core.env_file(), feed.auth_env, key or None)
    if key:
        os.environ[feed.auth_env] = key
    else:
        os.environ.pop(feed.auth_env, None)
    return {"success": True, "auth_env": feed.auth_env, "configured": bool(key)}


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
    """Current refresh state and the result of the last run."""
    return _refresh_state
