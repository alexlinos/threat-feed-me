"""
ASGI middleware that sits in front of every route.

BodyLimitMiddleware — request-size cap (review 2026-09-22). FastAPI reads and
parses a request body (JSON, or a multipart upload spooled to disk) BEFORE it
runs a route's dependencies, so require_auth and csrf_check ran only after an
unauthenticated client had already made the app buffer the whole body: a LAN
client could fill memory or disk even with auth turned on. This rejects an
oversized body before the app reads it — at once when Content-Length says so,
and by counting streamed bytes when it doesn't (chunked uploads carry no
length) — so the cap holds regardless of auth or route.
"""
import ipaddress
import json
import os
import re
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set

from starlette.exceptions import HTTPException

# The upload route accepts a 5 MB list; multipart framing needs a little more.
UPLOAD_PATH = "/api/feeds/upload"
UPLOAD_LIMIT = 6 * 1024 * 1024
# Every other body is a small JSON document (a feed, a whitelist entry, a
# setting). 1 MB is orders of magnitude above any legitimate one.
DEFAULT_LIMIT = 1024 * 1024


class _BodyTooLarge(HTTPException):
    """Raised from inside receive() when a streamed body passes the limit. An
    HTTPException so FastAPI's body parser re-raises it as-is (a plain
    exception there is rewritten into a 400) and the app answers 413."""

    def __init__(self, limit: int):
        super().__init__(status_code=413,
                         detail=f"Request body exceeds {limit // 1024} KB")


class BodyLimitMiddleware:
    def __init__(self, app, default_limit: int = DEFAULT_LIMIT,
                 path_limits: Dict[str, int] = None):
        self.app = app
        self.default_limit = default_limit
        self.path_limits = path_limits if path_limits is not None else {UPLOAD_PATH: UPLOAD_LIMIT}

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        limit = self.path_limits.get(scope.get("path", ""), self.default_limit)

        declared = None
        for name, value in scope.get("headers") or []:
            if name == b"content-length":
                try:
                    declared = int(value)
                except ValueError:
                    return await self._reject(send, 400, "Invalid Content-Length")
                break
        if declared is not None and declared > limit:
            return await self._reject(send, 413, f"Request body exceeds {limit // 1024} KB")

        received = 0

        async def limited_receive():
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    raise _BodyTooLarge(limit)
            return message

        started = False

        async def tracking_send(message):
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        try:
            await self.app(scope, limited_receive, tracking_send)
        except _BodyTooLarge as e:
            if started:
                raise
            await self._reject(send, 413, e.detail)

    @staticmethod
    async def _reject(send, status: int, detail: str):
        body = json.dumps({"detail": detail}).encode()
        await send({"type": "http.response.start", "status": status,
                    "headers": [(b"content-type", b"application/json"),
                                (b"content-length", str(len(body)).encode()),
                                (b"connection", b"close")]})
        await send({"type": "http.response.body", "body": body})


# ---------------------------------------------------------------------------
# HostCheckMiddleware — Host-header allowlist against DNS rebinding.
#
# The CSRF check (X-Requested-With) assumes the attacker's page is a different
# ORIGIN. DNS rebinding defeats that: a page on attacker.example re-resolves
# its own name to this server's LAN IP, so the browser treats the dashboard as
# same-origin — it can send the header and read every response. The only thing
# the browser can't fake is the Host header, which still says attacker.example.
#
# Policy (ratified 2026-09-22 for upgrades like the maintainer's: a reverse
# proxy in front, dashboard reached by name):
#   * /feeds/*, /healthz and /static/* are NEVER checked — a firewall polling a
#     feed by name through a proxy can't be broken by this, in any mode.
#   * IP-literal and localhost Hosts are ALWAYS allowed, so nobody can lock
#     themselves out: the server's IP is always a way back in (rebinding needs
#     the attacker's hostname in Host, never an IP).
#   * Nothing is enforced until an allowlist exists (TFM_ALLOWED_HOSTS and/or
#     the dashboard's list). Until then it only RECORDS which hostnames reach
#     the dashboard, so the operator can lock to exactly the names they use —
#     an upgrade never breaks named access on its own.
# ---------------------------------------------------------------------------

ALLOWED_HOSTS_ENV = "TFM_ALLOWED_HOSTS"
ALLOWED_HOSTS_SETTING = "allowed_hosts"
_EXEMPT_PREFIXES = ("/feeds/", "/static/")
_EXEMPT_PATHS = frozenset({"/healthz", "/favicon.ico"})
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(?:\.(?!-)[a-z0-9-]{1,63}(?<!-))*$")
_CACHE_TTL = 5.0

# In-memory only: counting on the request path must not write the DB. The
# dashboard itself is a request, so the operator's own hostname shows up the
# moment they open it; counts restart with the process.
_seen: Dict[str, Dict] = {}
_cache = {"at": 0.0, "hosts": frozenset()}


def host_of_header(value: Optional[str]) -> str:
    """Bare, lowercase host from a Host header: port and IPv6 brackets gone."""
    h = (value or "").strip().lower()
    if h.startswith("["):
        return h[1:h.find("]")] if "]" in h else h[1:]
    if h.count(":") == 1:          # host:port (bare IPv6 has several colons)
        h = h.split(":", 1)[0]
    return h.rstrip(".")


def always_allowed(host: str) -> bool:
    if not host or host == "localhost":
        return True
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def normalize_hostname(value: str) -> Optional[str]:
    """A configured allowlist entry, or None if it isn't a valid hostname."""
    h = host_of_header(value)
    return h if _HOSTNAME_RE.match(h) else None


def env_allowed_hosts() -> Set[str]:
    return {h for h in (normalize_hostname(x) for x in
                        os.environ.get(ALLOWED_HOSTS_ENV, "").split(",")) if h}


def configured_hosts(db) -> List[str]:
    try:
        raw = db.get_setting(ALLOWED_HOSTS_SETTING)
        return sorted({h for h in (normalize_hostname(x) for x in json.loads(raw or "[]")) if h})
    except Exception:
        return []


def effective_allowlist(db) -> frozenset:
    return frozenset(env_allowed_hosts() | set(configured_hosts(db)))


def invalidate_allowlist_cache() -> None:
    _cache["at"] = 0.0


def seen_hosts() -> List[Dict]:
    return sorted(({"host": h, **v} for h, v in _seen.items()),
                  key=lambda e: -e["count"])


def _record(host: str) -> None:
    now = datetime.now(timezone.utc).isoformat()
    entry = _seen.get(host)
    if entry is None:
        if len(_seen) >= 200:      # a flood of junk Hosts can't grow this forever
            return
        _seen[host] = {"count": 1, "first_seen": now, "last_seen": now}
    else:
        entry["count"] += 1
        entry["last_seen"] = now


class HostCheckMiddleware:
    def __init__(self, app, db_getter=None):
        self.app = app
        self._db_getter = db_getter

    def _db(self):
        if self._db_getter is not None:
            return self._db_getter()
        from threatfeedme import core
        return core.db

    def _allowed(self) -> frozenset:
        now = time.monotonic()
        if now - _cache["at"] > _CACHE_TTL:
            _cache["hosts"] = effective_allowlist(self._db())
            _cache["at"] = now
        return _cache["hosts"]

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        path = scope.get("path", "")
        if path in _EXEMPT_PATHS or path.startswith(_EXEMPT_PREFIXES):
            return await self.app(scope, receive, send)
        raw = next((v.decode("latin-1") for k, v in scope.get("headers") or []
                    if k == b"host"), "")
        host = host_of_header(raw)
        if not always_allowed(host):
            allowed = self._allowed()
            if host not in allowed:
                _record(host)
                if allowed:   # an allowlist exists -> enforcing
                    return await self._reject(send, host)
        await self.app(scope, receive, send)

    @staticmethod
    async def _reject(send, host: str):
        body = (f"This dashboard doesn't answer to the hostname '{host}'.\n\n"
                f"Open it at the server's IP address, or allow the name: add it "
                f"to {ALLOWED_HOSTS_ENV} or to the dashboard's allowed-hosts "
                f"list. (Feed URLs under /feeds/ are not affected.)\n").encode()
        await send({"type": "http.response.start", "status": 400,
                    # the requested host is echoed back: plain text + nosniff
                    # so no browser renders it as markup
                    "headers": [(b"content-type", b"text/plain; charset=utf-8"),
                                (b"x-content-type-options", b"nosniff"),
                                (b"content-length", str(len(body)).encode())]})
        await send({"type": "http.response.body", "body": body})
