"""
Optional HTTP Basic auth on the dashboard/API. Two sources, the environment
first: setting both DASHBOARD_USER and DASHBOARD_PASSWORD turns it on, and
otherwise a sign-in set from the System page does (a username and a salted
scrypt hash in settings, never the password). config's
dashboard.auth_required can also force it. Feed endpoints (/feeds/*) are intentionally NOT gated: a firewall
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
import hashlib
import hmac
import json
import os
import secrets
import time
from typing import Optional

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from threatfeedme import core

# Lazy: these are populated on first access via _ensure_auth_config().
_AUTH_REQUIRED = None
_AUTH_USER = None
_AUTH_PASSWORD = None
_security = HTTPBasic(auto_error=False)

# Sign-in set from the System page (v2.5.1). scrypt because Basic auth sends
# the password on every request and a stolen DB/backup must not hand it over;
# n=2^14 costs ~50 ms, so a verified login is remembered (keyed by a process
# secret, never stored) instead of re-hashed on every dashboard poll.
AUTH_SETTING = "dashboard_auth"
_SCRYPT = {"n": 2 ** 14, "r": 8, "p": 1}
MIN_PASSWORD, MAX_PASSWORD, MAX_USER = 12, 128, 64
_STORED_TTL = 5.0        # a CLI reset from another process lands within 5 s
_stored_cache = {"at": 0.0, "val": None}
_process_key = secrets.token_bytes(32)
_verified: dict = {}     # stored hash -> digests of logins that verified


def _dashboard_config() -> dict:
    """The dashboard config block. A seam, so tests can supply one without
    touching core.config — reading that attribute lazily INITIALIZES core from
    the repo's real config.yaml, which then leaks into every later test."""
    return core.config.get('dashboard', {}) or {}


def _ensure_auth_config():
    """Read auth config from core.config on first call rather than at import
    time. This lets tests set env vars before calling a function that triggers
    auth, instead of needing subprocess isolation."""
    global _AUTH_REQUIRED, _AUTH_USER, _AUTH_PASSWORD
    if _AUTH_REQUIRED is not None:
        return
    cfg = _dashboard_config()
    _AUTH_USER = os.environ.get("DASHBOARD_USER", "")
    _AUTH_PASSWORD = os.environ.get("DASHBOARD_PASSWORD", "")
    # Setting both credentials turns auth ON. config.yaml is baked into the
    # published image, so anyone running `docker compose pull` could not flip
    # dashboard.auth_required at all — the environment was the only lever, and
    # it did nothing (review 2026-09-22). Providing credentials is an
    # unambiguous request for auth; config can still require it with creds
    # unset (that fails closed with a 503 below). Never read from the
    # data-volume .env (credentials.env_file_may_set refuses DASHBOARD_*), so
    # an API-writable file can't switch auth on with attacker-chosen creds.
    _AUTH_REQUIRED = (bool(cfg.get('auth_required', False))
                      or bool(_AUTH_USER and _AUTH_PASSWORD))


def _hash(password: str, salt: bytes) -> bytes:
    return hashlib.scrypt(password.encode("utf-8"), salt=salt, dklen=32, **_SCRYPT)


def stored_credentials() -> Optional[dict]:
    """The System-page sign-in, or None. Cached briefly: it sits on every request."""
    now = time.monotonic()
    if now - _stored_cache["at"] > _STORED_TTL:
        try:
            raw = core.db.get_setting(AUTH_SETTING)
            val = json.loads(raw) if raw else None
            val = val if isinstance(val, dict) and val.get("user") and val.get("hash") else None
        except Exception:
            val = None
        _stored_cache.update(at=now, val=val)
    return _stored_cache["val"]


def _invalidate() -> None:
    _stored_cache["at"] = 0.0
    _verified.clear()


def check_stored_password(stored: dict, password: str) -> bool:
    try:
        salt, want = bytes.fromhex(stored["salt"]), bytes.fromhex(stored["hash"])
    except (KeyError, ValueError):
        return False
    return hmac.compare_digest(_hash(password, salt), want)


def save_credentials(db, username: str, password: str) -> None:
    salt = secrets.token_bytes(16)
    db.set_setting(AUTH_SETTING, json.dumps(
        {"user": username, "salt": salt.hex(), "hash": _hash(password, salt).hex(), "kdf": "scrypt"}))
    _invalidate()


def clear_credentials(db) -> None:
    db.set_setting(AUTH_SETTING, "")
    _invalidate()


def invalid_new_credentials(username: str, password: str) -> Optional[str]:
    """Why a new sign-in is refused, or None. Basic auth splits on the first
    colon, so a username can't hold one; control characters never belong."""
    if not username or len(username) > MAX_USER:
        return f"Username must be 1-{MAX_USER} characters"
    if ":" in username or any(ord(c) < 32 or ord(c) == 127 for c in username + password):
        return "Username can't contain ':' and neither field may contain control characters"
    if not MIN_PASSWORD <= len(password) <= MAX_PASSWORD:
        return f"Password must be {MIN_PASSWORD}-{MAX_PASSWORD} characters"
    return None


def auth_source() -> Optional[str]:
    """'env' (DASHBOARD_USER/PASSWORD win), 'dashboard' (set on the System
    page), or None (no sign-in: auth off unless config forces it)."""
    _ensure_auth_config()
    if _AUTH_USER and _AUTH_PASSWORD:
        return "env"
    return "dashboard" if stored_credentials() else None


def auth_enabled() -> bool:
    _ensure_auth_config()
    return bool(_AUTH_REQUIRED or auth_source())


def _stored_login_ok(stored: dict, username: str, password: str) -> bool:
    user_ok = hmac.compare_digest(username.encode("utf-8"), stored["user"].encode("utf-8"))
    digest = hmac.new(_process_key, f"{username}\0{password}".encode("utf-8"), "sha256").digest()
    seen = _verified.setdefault(stored["hash"], set())
    if digest in seen:
        return user_ok
    pass_ok = check_stored_password(stored, password)      # always hashed: no user timing leak
    if user_ok and pass_ok and len(seen) < 16:
        seen.add(digest)
    return user_ok and pass_ok


def require_auth(credentials: Optional[HTTPBasicCredentials] = Depends(_security)):
    """Enforce Basic auth when enabled; a no-op otherwise."""
    source = auth_source()
    if not (_AUTH_REQUIRED or source):
        return
    if source is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Dashboard auth is required but no sign-in is set: set DASHBOARD_USER/DASHBOARD_PASSWORD",
        )
    # Compare bytes, and always evaluate BOTH: compare_digest raises TypeError
    # on non-ASCII str (a non-ASCII password turned every request into a 500),
    # and the old `a and b` short-circuit skipped the password check for a
    # wrong username, leaking which usernames are valid through timing.
    if credentials is None:
        valid = False
    elif source == "dashboard":
        valid = _stored_login_ok(stored_credentials(), credentials.username, credentials.password)
    else:
        user_ok = secrets.compare_digest(credentials.username.encode("utf-8"),
                                         _AUTH_USER.encode("utf-8"))
        pass_ok = secrets.compare_digest(credentials.password.encode("utf-8"),
                                         _AUTH_PASSWORD.encode("utf-8"))
        valid = user_ok and pass_ok
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
