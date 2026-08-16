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
    stored = {}
    try:
        raw = core.db.get_setting(SETTINGS_KEY)
        if raw:
            stored = json.loads(raw) or {}
    except Exception:
        stored = {}
    for field in ("enabled", "host", "site", "tier", "domain_tier"):
        value = getattr(request, field)
        if value is not None:
            stored[field] = value.strip() if isinstance(value, str) else value
    core.db.set_setting(SETTINGS_KEY, json.dumps(stored))
    return _status()


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
