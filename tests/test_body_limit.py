"""Request-body cap (v2.5.0): oversized bodies are refused before the app —
or its auth dependency — reads them, whether or not they declare a length."""
import pytest
from fastapi import Depends, FastAPI, HTTPException
from starlette.testclient import TestClient

from threatfeedme.middleware import BodyLimitMiddleware

LIMIT = 1024
reached = []


def _deny():
    reached.append("auth")
    raise HTTPException(status_code=401, detail="no")


def _app():
    app = FastAPI()

    @app.post("/echo")
    async def echo(payload: dict):
        reached.append("route")
        return {"n": len(str(payload))}

    @app.post("/guarded")
    async def guarded(payload: dict, _=Depends(_deny)):
        return {}

    @app.post("/big")
    async def big(payload: dict):
        return {"ok": True}

    app.add_middleware(BodyLimitMiddleware, default_limit=LIMIT,
                       path_limits={"/big": 10 * LIMIT})
    return TestClient(app)


@pytest.fixture(autouse=True)
def _reset():
    reached.clear()


def test_small_body_passes():
    r = _app().post("/echo", json={"a": "x" * 100})
    assert r.status_code == 200 and reached == ["route"]


def test_declared_oversize_is_refused_without_reading():
    r = _app().post("/echo", json={"a": "x" * (2 * LIMIT)})
    assert r.status_code == 413
    assert reached == []        # the route never ran


def test_chunked_oversize_without_a_length_is_refused():
    # a chunked body carries no Content-Length, so the cap must count bytes
    def chunks():
        yield b'{"a": "'
        for _ in range(8):
            yield b"x" * 512
        yield b'"}'
    r = _app().post("/echo", content=chunks(),
                    headers={"content-type": "application/json"})
    assert r.status_code == 413
    assert reached == []


def test_oversize_is_refused_before_auth():
    # the point of the fix: an unauthenticated client can't make the app
    # buffer a huge body just because auth runs after body parsing
    r = _app().post("/guarded", json={"a": "x" * (2 * LIMIT)})
    assert r.status_code == 413
    assert reached == []        # auth never ran either


def test_per_path_limit():
    c = _app()
    assert c.post("/big", json={"a": "x" * (2 * LIMIT)}).status_code == 200
    assert c.post("/big", json={"a": "x" * (20 * LIMIT)}).status_code == 413


def test_the_real_app_upload_route_gets_room_for_a_5mb_list():
    from threatfeedme.middleware import DEFAULT_LIMIT, UPLOAD_LIMIT, UPLOAD_PATH
    from threatfeedme.routers.feeds import MAX_UPLOAD_BYTES
    assert UPLOAD_PATH == "/api/feeds/upload"
    assert UPLOAD_LIMIT > MAX_UPLOAD_BYTES > DEFAULT_LIMIT
