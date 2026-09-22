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
from typing import Dict

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
        import json
        body = json.dumps({"detail": detail}).encode()
        await send({"type": "http.response.start", "status": status,
                    "headers": [(b"content-type", b"application/json"),
                                (b"content-length", str(len(body)).encode()),
                                (b"connection", b"close")]})
        await send({"type": "http.response.body", "body": body})
