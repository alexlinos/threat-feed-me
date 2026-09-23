"""Host-header allowlist (v2.5.0) against DNS rebinding: off until the operator
switches it on, IPs always allowed, feeds never checked."""
import pytest
from fastapi import FastAPI
from fastapi.responses import PlainTextResponse
from starlette.testclient import TestClient

from threatfeedme import middleware as mw


class _DB:
    def __init__(self, allowed=None, enforce=None):
        import json
        self._v = json.dumps(allowed) if allowed is not None else None
        self._enforce = enforce      # None = flag never written (pre-flag list)

    def get_setting(self, key):
        if key == mw.ENFORCE_SETTING:
            return self._enforce
        return self._v if key == mw.ALLOWED_HOSTS_SETTING else None


@pytest.fixture(autouse=True)
def _fresh(monkeypatch):
    mw._seen.clear()
    mw.invalidate_allowlist_cache()
    monkeypatch.delenv(mw.ALLOWED_HOSTS_ENV, raising=False)
    yield
    mw._seen.clear()
    mw.invalidate_allowlist_cache()


def _client(allowed=None, enforce=None):
    app = FastAPI()

    @app.get("/api/stats")
    def stats():
        return {"ok": True}

    @app.get("/feeds/high.txt", response_class=PlainTextResponse)
    def feed():
        return "185.1.1.1\n"

    @app.get("/healthz")
    def health():
        return {"ok": True}

    db = _DB(allowed, enforce)
    app.add_middleware(mw.HostCheckMiddleware, db_getter=lambda: db)
    return TestClient(app)


def _get(c, path, host):
    return c.get(path, headers={"host": host})


def test_report_only_lets_unknown_names_through_and_records_them():
    c = _client()
    assert _get(c, "/api/stats", "threatfeedme.tnh.local").status_code == 200
    assert _get(c, "/api/stats", "threatfeedme.tnh.local").status_code == 200
    seen = {e["host"]: e["count"] for e in mw.seen_hosts()}
    assert seen == {"threatfeedme.tnh.local": 2}


def test_enforcing_refuses_unknown_names():
    c = _client(["threatfeedme.tnh.local"], enforce="1")
    assert _get(c, "/api/stats", "threatfeedme.tnh.local:80").status_code == 200
    r = _get(c, "/api/stats", "attacker.example")
    assert r.status_code == 400
    assert "attacker.example" in r.text and mw.ALLOWED_HOSTS_ENV in r.text
    assert r.headers["x-content-type-options"] == "nosniff"


@pytest.mark.parametrize("host", ["172.31.10.4:8080", "172.31.10.4", "[::1]:8080",
                                  "localhost:8080", "LOCALHOST"])
def test_ip_literals_and_localhost_always_work(host):
    # nobody can lock themselves out: the server's IP is always a way in
    assert _get(_client(["only.example"], enforce="1"), "/api/stats", host).status_code == 200


@pytest.mark.parametrize("path", ["/feeds/high.txt", "/healthz"])
def test_feeds_and_healthz_are_never_checked(path):
    # a firewall polling a feed by name through a proxy can't be broken
    assert _get(_client(["only.example"], enforce="1"), path, "attacker.example").status_code == 200


def test_env_var_alone_enforces(monkeypatch):
    monkeypatch.setenv(mw.ALLOWED_HOSTS_ENV, "tfm.corp.example, Other.Example")
    c = _client()
    assert _get(c, "/api/stats", "other.example").status_code == 200
    assert _get(c, "/api/stats", "attacker.example").status_code == 400


@pytest.mark.parametrize("header,host", [
    ("Name.Example:8080", "name.example"), ("name.example.", "name.example"),
    ("[2001:db8::1]:8443", "2001:db8::1"), ("10.0.0.1:8080", "10.0.0.1"),
])
def test_host_header_parsing(header, host):
    assert mw.host_of_header(header) == host


@pytest.mark.parametrize("value,ok", [
    ("threatfeedme.tnh.local", True), ("soc-grfna01", True),
    ("bad_name.example", False), ("-lead.example", False), ("a b", False), ("", False),
])
def test_allowlist_entries_are_validated(value, ok):
    assert (mw.normalize_hostname(value) is not None) is ok


def test_saved_but_unlocked_names_refuse_nothing():
    """The first-run guide saves a DNS name the operator is about to create;
    saving it must not start refusing other names (maintainer, 2026-09-23)."""
    c = _client(["threatfeedme.lan"], enforce="0")
    assert _get(c, "/api/stats", "threatfeedme.lan").status_code == 200
    assert _get(c, "/api/stats", "other-name.example").status_code == 200
    # still report-only: the unknown name is recorded for the Lock step
    assert "other-name.example" in {e["host"] for e in mw.seen_hosts()}


def test_switched_on_enforces_and_a_missing_switch_is_off():
    """Maintainer, 2026-09-23: the host check is OFF on upgrade; only the
    explicit switch (or TFM_ALLOWED_HOSTS) turns refusal on."""
    assert _get(_client(["threatfeedme.lan"], enforce="1"), "/api/stats",
                "other.example").status_code == 400
    mw.invalidate_allowlist_cache()
    assert _get(_client(["threatfeedme.lan"], enforce=None), "/api/stats",
                "other.example").status_code == 200


def test_env_enforcing_keeps_the_guides_saved_names(monkeypatch):
    monkeypatch.setenv(mw.ALLOWED_HOSTS_ENV, "proxy.example")
    c = _client(["threatfeedme.lan"], enforce="0")
    assert _get(c, "/api/stats", "threatfeedme.lan").status_code == 200
    assert _get(c, "/api/stats", "proxy.example").status_code == 200
    assert _get(c, "/api/stats", "attacker.example").status_code == 400
