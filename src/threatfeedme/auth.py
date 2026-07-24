"""
Optional HTTP Basic auth on the dashboard/API, enabled via config and
configured entirely through environment variables so no credentials live in
the repo. Feed endpoints (/feeds/*) are intentionally NOT gated: a firewall
polling a block list generally cannot present credentials, and the lists
contain only known-bad IPs, not secrets.

CSRF protection: state-changing requests (POST, PUT, DELETE) must include
an X-Requested-With header to prove they come from the dashboard's own JS,
not a cross-site form/script. Browsers won't auto-set this header
cross-origin. This is enforced even when auth is off: a no-auth dashboard
on a LAN is ambient authority, so a drive-by page in any LAN user's
browser could otherwise forge form/query-param POSTs (e.g. upload a
malicious blocklist the firewall then enforces).

All configuration is evaluated lazily on first access, not at import time,
so tests and alternate entry points can set env vars before the first call
without needing subprocess isolation.
"""
import os
import secrets
from typing import Optional

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from threatfeedme import core

# Lazy: these are populated on first access via _ensure_auth_config().
_AUTH_REQUIRED = None
_AUTH_USER = None
_AUTH_PASSWORD = None
_security = HTTPBasic(auto_error=False)


def _ensure_auth_config():
    """Read auth config from core.config on first call rather than at import
    time. This lets tests set env vars before calling a function that triggers
    auth, instead of needing subprocess isolation."""
    global _AUTH_REQUIRED, _AUTH_USER, _AUTH_PASSWORD
    if _AUTH_REQUIRED is not None:
        return
    cfg = core.config.get('dashboard', {})
    _AUTH_REQUIRED = bool(cfg.get('auth_required', False))
    _AUTH_USER = os.environ.get("DASHBOARD_USER", "")
    _AUTH_PASSWORD = os.environ.get("DASHBOARD_PASSWORD", "")


def require_auth(credentials: Optional[HTTPBasicCredentials] = Depends(_security)):
    """Enforce Basic auth when enabled; a no-op otherwise."""
    _ensure_auth_config()
    if not _AUTH_REQUIRED:
        return
    if not _AUTH_USER or not _AUTH_PASSWORD:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Dashboard auth is enabled but DASHBOARD_USER/DASHBOARD_PASSWORD are not set",
        )
    valid = credentials is not None and secrets.compare_digest(
        credentials.username, _AUTH_USER
    ) and secrets.compare_digest(credentials.password, _AUTH_PASSWORD)
    if not valid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )


def csrf_check(request: Request):
    """Reject a state-changing request that lacks an X-Requested-With header.
    Browsers do not auto-set this header cross-origin, so a forged POST from
    another site will be blocked.

    Enforced unconditionally: even with auth off, the app is ambient
    authority on its network, so cross-site form POSTs (feed upload,
    disable, refresh) must not be honored.
    """
    header = request.headers.get("X-Requested-With", "")
    if header != "XMLHttpRequest":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="CSRF check failed — mutating requests must include X-Requested-With: XMLHttpRequest",
        )
