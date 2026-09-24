"""Dashboard sign-in set from the System page (v2.5.1): stored as a salted
scrypt hash, the environment wins, a change needs the current password, and
the first one can't be set by a DNS-rebinding page."""
import json

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.security import HTTPBasicCredentials
from starlette.testclient import TestClient

# Modules are looked up at fixture time, never bound at import: other suites
# purge and re-import threatfeedme, and a stale `core` here would patch a
# module the live auth code no longer reads.
H = {"X-Requested-With": "XMLHttpRequest"}
IP = {**H, "host": "192.0.2.10:8080"}
PW = "correct horse battery"


class _DB:
    def __init__(self):
        self.s = {}

    def get_setting(self, key, default=None):
        return self.s.get(key, default)

    def set_setting(self, key, value):
        self.s[key] = value


def _mw():
    from threatfeedme import middleware
    return middleware


@pytest.fixture
def db(monkeypatch):
    from threatfeedme import auth, core
    d = _DB()
    monkeypatch.setitem(core.__dict__, "db", d)       # never read core.db (lazy init)
    monkeypatch.setattr(auth, "_AUTH_REQUIRED", None)
    monkeypatch.setattr(auth, "_dashboard_config", lambda: {"auth_required": False})
    for var in ("DASHBOARD_USER", "DASHBOARD_PASSWORD", _mw().ALLOWED_HOSTS_ENV):
        monkeypatch.delenv(var, raising=False)
    auth._invalidate()
    yield d
    auth._invalidate()


@pytest.fixture
def client(db):
    from threatfeedme.routers import system
    app = FastAPI()
    app.add_api_route("/api/dashboard-auth", system.dashboard_auth_status, methods=["GET"])
    app.add_api_route("/api/dashboard-auth", system.dashboard_auth_update, methods=["POST"])
    return TestClient(app)


def _creds(u, p):
    return HTTPBasicCredentials(username=u, password=p)


def _set(client, user="alex", pw=PW, current="", headers=IP, auth=None):
    return client.post("/api/dashboard-auth", headers=headers, auth=auth,
                       json={"username": user, "password": pw, "current_password": current})


def test_setting_a_sign_in_turns_auth_on_and_stores_only_a_hash(client, db):
    from threatfeedme import auth
    assert auth.require_auth(None) is None                    # off to begin with
    assert _set(client).status_code == 200
    stored = db.s[auth.AUTH_SETTING]
    assert PW not in stored and json.loads(stored)["kdf"] == "scrypt"
    with pytest.raises(HTTPException) as e:
        auth.require_auth(None)
    assert e.value.status_code == 401
    assert auth.require_auth(_creds("alex", PW)) is None
    for bad in (_creds("alex", PW + "x"), _creds("root", PW)):
        with pytest.raises(HTTPException):
            auth.require_auth(bad)


def test_status_never_returns_the_hash(client):
    _set(client)
    body = client.get("/api/dashboard-auth", auth=("alex", PW)).json()
    assert body["source"] == "dashboard" and body["username"] == "alex"
    assert "hash" not in json.dumps(body) and "salt" not in json.dumps(body)


def test_first_password_needs_an_ip_or_a_saved_name(client, db):
    rebound = {**H, "host": "evil.example"}
    assert _set(client, headers=rebound).status_code == 403
    db.set_setting(_mw().ALLOWED_HOSTS_SETTING, json.dumps(["threatfeedme.lan"]))
    assert _set(client, headers={**H, "host": "threatfeedme.lan"}).status_code == 200


def test_a_change_needs_the_current_password(client):
    from threatfeedme import auth
    _set(client)
    new = "another long password"
    assert _set(client, pw=new, current="wrong", auth=("alex", PW)).status_code == 403
    assert _set(client, pw=new, current=PW, auth=("alex", PW)).status_code == 200
    assert auth.require_auth(_creds("alex", new)) is None
    with pytest.raises(HTTPException):
        auth.require_auth(_creds("alex", PW))


@pytest.mark.parametrize("user, pw", [("alex", "short"), ("a:b", PW), ("", PW), ("al\nex", PW)])
def test_bad_sign_ins_are_refused(client, user, pw):
    assert _set(client, user=user, pw=pw).status_code == 400


def test_the_environment_wins_and_cant_be_changed_here(client, monkeypatch):
    from threatfeedme import auth
    _set(client)
    monkeypatch.setenv("DASHBOARD_USER", "ops")
    monkeypatch.setenv("DASHBOARD_PASSWORD", "env-password-123")
    monkeypatch.setattr(auth, "_AUTH_REQUIRED", None)
    assert auth.require_auth(_creds("ops", "env-password-123")) is None
    with pytest.raises(HTTPException):
        auth.require_auth(_creds("alex", PW))
    assert _set(client, auth=("ops", "env-password-123")).status_code == 409


def test_reset_clears_the_sign_in(client, db):
    from threatfeedme import auth
    _set(client)
    auth.clear_credentials(db)
    assert auth.auth_source() is None and auth.require_auth(None) is None


def test_a_verified_login_is_not_rehashed_on_every_request(client, monkeypatch):
    from threatfeedme import auth
    _set(client)
    calls = []
    real = auth._hash
    monkeypatch.setattr(auth, "_hash", lambda p, s: calls.append(1) or real(p, s))
    for _ in range(5):
        auth.require_auth(_creds("alex", PW))
    assert len(calls) == 1

