"""Integrations endpoints: dashboard-driven UniFi push management.

Settings (enabled/host/site/tier) live in a DB settings row that overrides
the config.yaml seed block — the "no config editing" promise. Credentials
follow the feed-API-key model exactly: write-only through this API, stored
in the data-volume .env, applied to the process environment immediately,
never echoed back in any response.
"""
import json
import os
import re
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from threatfeedme.auth import csrf_check, require_auth
from threatfeedme import core
from threatfeedme.pusher_unifi import (ENV_PASSWORD, ENV_USER, SETTINGS_KEY,
                                       LAST_PUSH_KEY, UniFiPusher,
                                       effective_block, push_to_unifi)
from threatfeedme.routers.feeds import _write_env_var

router = APIRouter()

_VALID_TIERS = ("high", "medium", "low")
# Bare hostname/IP or http(s) URL — enough to catch pastes of whole URLs
# with paths, which the pusher would mangle into bad API endpoints.
_HOST_RE = re.compile(r'^(https?://)?[A-Za-z0-9.:\[\]-]+/?$')
# The site id is interpolated into authenticated gateway API paths, so '/',
# '?', or '..' would retarget those calls; UniFi site ids are short slugs.
_SITE_RE = re.compile(r'^[A-Za-z0-9_-]{1,64}$')


def _host_key(host: str) -> str:
    """Comparable form of a gateway host: scheme, trailing slash, case gone."""
    h = (host or "").strip().lower()
    for prefix in ("https://", "http://"):
        if h.startswith(prefix):
            h = h[len(prefix):]
    return h.rstrip("/")


def _clear_credentials() -> None:
    for var in (ENV_USER, ENV_PASSWORD):
        _write_env_var(core.env_file(), var, None)
        os.environ.pop(var, None)


def _status() -> dict:
    block = effective_block(core.db, core.config)
    last = None
    try:
        raw = core.db.get_setting(LAST_PUSH_KEY)
        if raw:
            last = json.loads(raw)
    except Exception:
        pass
    return {
        "enabled": bool(block.get("enabled")),
        "host": block.get("host") or "",
        "site": block.get("site", "default"),
        "tier": block.get("tier", "high"),
        # "" = domain push off; else the domain tier pushed into
        # Domain-type network lists ({prefix}-dom-{tier}-1..N).
        "domain_tier": block.get("domain_tier", ""),
        "group_prefix": block.get("group_prefix", "threatfeedme"),
        # Presence only — the values are write-only by design.
        "credentials_configured": bool(os.environ.get(ENV_USER)) and bool(os.environ.get(ENV_PASSWORD)),
        "last_push": last,
    }


@router.get("/api/integrations/unifi")
def unifi_status(_=Depends(require_auth)):
    """Current effective settings + last push outcome. Never credentials."""
    return _status()


class UniFiSettingsRequest(BaseModel):
    enabled: Optional[bool] = None
    host: Optional[str] = None
    site: Optional[str] = None
    tier: Optional[str] = None
    # "" turns the domain arm off (the default).
    domain_tier: Optional[str] = None


@router.post("/api/integrations/unifi")
def unifi_save(request: UniFiSettingsRequest, _=Depends(require_auth), _csrf=Depends(csrf_check)):
    """Update the runtime settings (merged over previously saved values)."""
    if request.tier is not None and request.tier not in _VALID_TIERS:
        raise HTTPException(status_code=400, detail="tier must be high, medium, or low")
    if request.domain_tier is not None and request.domain_tier not in ("",) + _VALID_TIERS:
        raise HTTPException(status_code=400,
                            detail="domain_tier must be high, medium, low, or empty (off)")
    if request.host is not None:
        host = request.host.strip()
        if host and not _HOST_RE.match(host):
            raise HTTPException(status_code=400,
                                detail="host must be an IP/hostname or http(s) URL without a path")
    if request.site is not None and not _SITE_RE.match(request.site.strip()):
        raise HTTPException(status_code=400,
                            detail="site must be the UniFi site id (letters, digits, - or _)")
    stored = {}
    try:
        raw = core.db.get_setting(SETTINGS_KEY)
        if raw:
            stored = json.loads(raw) or {}
    except Exception:
        stored = {}
    # The saved login is bound to the gateway it was entered for. Repointing
    # the host must not silently carry it along — otherwise saving
    # {"host": "attacker"} and pressing Test posts the gateway admin's
    # password to that host (review 2026-09-22). First-time setup (no host
    # yet) keeps credentials, since they may be entered before the host.
    credentials_cleared = False
    previous_host = effective_block(core.db, core.config).get("host") or ""
    if (request.host is not None and _host_key(previous_host)
            and _host_key(request.host) != _host_key(previous_host)):
        _clear_credentials()
        credentials_cleared = True
    for field in ("enabled", "host", "site", "tier", "domain_tier"):
        value = getattr(request, field)
        if value is not None:
            stored[field] = value.strip() if isinstance(value, str) else value
    core.db.set_setting(SETTINGS_KEY, json.dumps(stored))
    status = _status()
    status["credentials_cleared"] = credentials_cleared
    return status


class UniFiCredentialsRequest(BaseModel):
    username: str = ""
    password: str = ""


@router.post("/api/integrations/unifi/credentials")
def unifi_credentials(request: UniFiCredentialsRequest,
                      _=Depends(require_auth), _csrf=Depends(csrf_check)):
    """Save (or clear, with empty values) the UniFi login. Same mechanics as
    feed API keys: data-volume .env + process env, write-only, never logged,
    never echoed. Use a dedicated local-only UniFi admin, not a real account."""
    for value in (request.username, request.password):
        if any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise HTTPException(status_code=400, detail="Credential contains control characters")
    pairs = ((ENV_USER, request.username.strip()), (ENV_PASSWORD, request.password))
    for var, value in pairs:
        _write_env_var(core.env_file(), var, value or None)
        if value:
            os.environ[var] = value
        else:
            os.environ.pop(var, None)
    return {"success": True,
            "credentials_configured": bool(os.environ.get(ENV_USER)) and bool(os.environ.get(ENV_PASSWORD))}


@router.post("/api/integrations/unifi/test")
def unifi_test(_=Depends(require_auth), _csrf=Depends(csrf_check)):
    """Login + read the gateway's firewall groups. NO writes — safe to run
    before enabling. Errors come back as ok:false so the panel can show
    them inline instead of a bare 500."""
    block = effective_block(core.db, core.config)
    pusher = UniFiPusher.from_block(block)
    if pusher is None:
        raise HTTPException(status_code=400, detail="Set the gateway host first")
    if not pusher.credentials_configured():
        raise HTTPException(status_code=400, detail="Set the UniFi credentials first")
    try:
        result = pusher.test_connection()
    except Exception as e:
        return {"ok": False, "message": f"Connection failed: {e}"}
    n = len(result["our_groups"])
    return {"ok": True,
            "message": (f"Connected — {result['groups_total']} firewall group(s) on the gateway"
                        + (f", {n} maintained by threat-feed-me" if n else
                           "; none pushed yet (Push now, or wait for the next refresh)")),
            **result}


@router.post("/api/integrations/unifi/push")
def unifi_push(_=Depends(require_auth), _csrf=Depends(csrf_check)):
    """Push the configured tier now. Requires the integration to be enabled
    (the scheduled path pushes after every refresh once enabled)."""
    block = effective_block(core.db, core.config)
    if not block.get("enabled"):
        raise HTTPException(status_code=400, detail="Enable the integration first (and Save)")
    try:
        summary = push_to_unifi(core.db, core.config)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Push failed: {e}")
    if summary is None:  # enabled flag raced off, or host missing
        raise HTTPException(status_code=400, detail="Integration is not fully configured")
    return {"success": True, "summary": summary}


# ---------------------------------------------------------------------------
# CrowdSec (v2.5.0): push the tier into the operator's LAPI as decisions, and
# pull its decisions back as feeds. Same credential model as UniFi: write-only,
# data-volume .env, bound to the configured LAPI (cleared on a host change).
# ---------------------------------------------------------------------------
from threatfeedme import crowdsec as _cs


def _cs_stored() -> dict:
    try:
        raw = core.db.get_setting(_cs.SETTINGS_KEY)
        return (json.loads(raw) or {}) if raw else {}
    except Exception:
        return {}


def _cs_status() -> dict:
    block = _cs.effective_block(core.db, core.config)
    last = None
    try:
        raw = core.db.get_setting(_cs.LAST_PUSH_KEY)
        if raw:
            last = json.loads(raw)
    except Exception:
        pass
    return {
        "enabled": bool(block.get("enabled")),
        "lapi_url": _cs.lapi_url(core.db, core.config),
        "tier": block.get("tier", _cs.DEFAULT_TIER),
        "duration_hours": _cs.duration_hours(block),
        "verify_ssl": bool(block.get("verify_ssl", True)),
        "console_integration_id": _cs.console_integration_id(core.db, core.config),
        # presence only, never values
        "machine_configured": _cs.CrowdSecPusher.credentials_configured(),
        "bouncer_configured": bool(os.environ.get(_cs.ENV_BOUNCER_KEY)),
        "last_push": last,
    }


@router.get("/api/integrations/crowdsec")
def crowdsec_status(_=Depends(require_auth)):
    return _cs_status()


class CrowdSecSettingsRequest(BaseModel):
    enabled: Optional[bool] = None
    lapi_url: Optional[str] = None
    tier: Optional[str] = None
    duration_hours: Optional[int] = None
    verify_ssl: Optional[bool] = None
    console_integration_id: Optional[str] = None


@router.post("/api/integrations/crowdsec")
def crowdsec_save(request: CrowdSecSettingsRequest, _=Depends(require_auth),
                  _csrf=Depends(csrf_check)):
    if request.tier is not None and request.tier not in _VALID_TIERS:
        raise HTTPException(status_code=400, detail="tier must be high, medium, or low")
    new_url = None
    if request.lapi_url is not None:
        try:
            new_url = _cs.normalize_lapi_url(request.lapi_url)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
    if request.duration_hours is not None and not (
            _cs._MIN_DURATION_H <= request.duration_hours <= _cs._MAX_DURATION_H):
        raise HTTPException(status_code=400, detail=(
            f"duration_hours must be {_cs._MIN_DURATION_H}-{_cs._MAX_DURATION_H}"))
    if request.console_integration_id is not None:
        cid = request.console_integration_id.strip()
        if cid and not _cs._CONSOLE_ID_RE.match(cid):
            raise HTTPException(status_code=400, detail="console_integration_id must be the "
                                "integration's id (letters, digits, - or _)")
    stored = _cs_stored()
    # The LAPI credentials are bound to the LAPI they were entered for:
    # repointing it must not carry them along (else saving an attacker's URL
    # and pressing Test posts the machine password there).
    credentials_cleared = False
    previous = _cs.lapi_url(core.db, core.config)
    if new_url is not None and previous and _host_key(new_url) != _host_key(previous):
        for var in _cs.CREDENTIAL_VARS:
            _write_env_var(core.env_file(), var, None)
            os.environ.pop(var, None)
        credentials_cleared = True
    for field in ("enabled", "tier", "duration_hours", "verify_ssl"):
        value = getattr(request, field)
        if value is not None:
            stored[field] = value
    if new_url is not None:
        stored["lapi_url"] = new_url
    if request.console_integration_id is not None:
        stored["console_integration_id"] = request.console_integration_id.strip()
    core.db.set_setting(_cs.SETTINGS_KEY, json.dumps(stored))
    status = _cs_status()
    status["credentials_cleared"] = credentials_cleared
    return status


class CrowdSecCredentialsRequest(BaseModel):
    # None = leave unchanged, "" = clear
    machine_id: Optional[str] = None
    machine_password: Optional[str] = None
    bouncer_key: Optional[str] = None


@router.post("/api/integrations/crowdsec/credentials")
def crowdsec_credentials(request: CrowdSecCredentialsRequest,
                         _=Depends(require_auth), _csrf=Depends(csrf_check)):
    """Write-only. Values are never echoed, logged or returned."""
    pairs = ((_cs.ENV_MACHINE_ID, request.machine_id),
             (_cs.ENV_MACHINE_PASSWORD, request.machine_password),
             (_cs.ENV_BOUNCER_KEY, request.bouncer_key))
    for _var, value in pairs:
        if value is not None and any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise HTTPException(status_code=400, detail="Credential contains control characters")
    for var, value in pairs:
        if value is None:
            continue
        value = value.strip() if var != _cs.ENV_MACHINE_PASSWORD else value
        _write_env_var(core.env_file(), var, value or None)
        if value:
            os.environ[var] = value
        else:
            os.environ.pop(var, None)
    s = _cs_status()
    return {"success": True, "machine_configured": s["machine_configured"],
            "bouncer_configured": s["bouncer_configured"]}


@router.post("/api/integrations/crowdsec/test")
def crowdsec_test(_=Depends(require_auth), _csrf=Depends(csrf_check)):
    """Read-only checks of whatever is configured: the machine login (push)
    and a decisions read with the bouncer key (pull). Nothing is written."""
    url = _cs.lapi_url(core.db, core.config)
    if not url:
        raise HTTPException(status_code=400, detail="Set the LAPI URL first")
    block = _cs.effective_block(core.db, core.config)
    out = {"ok": True, "checks": {}}
    if _cs.CrowdSecPusher.credentials_configured():
        try:
            _cs.CrowdSecPusher.from_block(block).test_connection()
            out["checks"]["push"] = "machine login OK"
        except Exception as e:
            out["ok"] = False
            out["checks"]["push"] = f"machine login failed: {e}"
    key = os.environ.get(_cs.ENV_BOUNCER_KEY)
    if key:
        try:
            session = _cs._session(verify=bool(block.get("verify_ssl", True)))
            r = _cs._check(session.get(
                f"{url}/v1/decisions", headers={"X-Api-Key": key},
                params={"type": "ban", "scenarios_not_containing": "threatfeedme"},
                timeout=30, allow_redirects=False), "pull")
            n = len(_cs.decision_values(r.json()))
            out["checks"]["pull"] = f"bouncer key OK, {n} active ban decision(s) to ingest"
        except Exception as e:
            out["ok"] = False
            out["checks"]["pull"] = f"bouncer read failed: {e}"
    if not out["checks"]:
        raise HTTPException(status_code=400, detail="Set the machine login and/or bouncer key first")
    out["message"] = "; ".join(f"{k}: {v}" for k, v in out["checks"].items())
    return out


@router.post("/api/integrations/crowdsec/push")
def crowdsec_push(_=Depends(require_auth), _csrf=Depends(csrf_check)):
    block = _cs.effective_block(core.db, core.config)
    if not block.get("enabled"):
        raise HTTPException(status_code=400, detail="Enable the push first (and Save)")
    try:
        summary = _cs.push_to_crowdsec(core.db, core.config, force=True)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Push failed: {e}")
    if summary is None:
        raise HTTPException(status_code=400, detail="Set the LAPI URL and machine login first")
    return {"success": True, "summary": summary}
