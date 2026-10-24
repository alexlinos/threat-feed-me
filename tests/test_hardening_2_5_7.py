"""2.5.7 review fixes: forwarded-scheme guard, request caps, redacted logs,
Test-button error categories, TLS switch, ?hosts=1, the UniFi certificate pin,
the scrypt concurrency cap, and a loud missing config."""
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    work = tmp_path_factory.mktemp("hard")
    db_path = str(work / "t.db").replace("\\", "/")
    cfg_path = work / "config.yaml"
    cfg_path.write_text(
        "database:\n"
        f"  path: {db_path}\n"
        "scoring:\n"
        "  source_weight: 0.45\n"
        "  reputation_weight: 0.33\n"
        "  recency_weight: 0.22\n"
        "  high_confidence: {min_sources: 3, min_score: 0.75}\n"
        "  medium_confidence: {min_sources: 2, min_score: 0.5}\n"
        "feeds:\n"
        "  - {name: spamhaus_drop, url: 'https://example.com/drop.txt', feed_type: spam, weight: 0.95}\n"
        "  - {name: custom_honeypot, url: './sample_honeypot_ips.txt', feed_type: custom, weight: 0.7, local_file: true}\n"
        "safety: {drop_private_reserved: false, protect_known_good: true}\n"
        "dashboard: {auth_required: false}\n"
    )
    os.environ["CONFIG_PATH"] = str(cfg_path)
    from threatfeedme.database import Database
    from threatfeedme.scorer import ConfidenceScorer
    import yaml
    db = Database(db_path)
    db.add_indicator("45.66.230.0", "spamhaus_drop", {"cidr": "45.66.230.0/24"})
    db.add_indicator("45.66.230.99", "custom_honeypot", {})
    db.add_indicator("198.51.100.7", "spamhaus_drop", {})
    ConfidenceScorer(db, yaml.safe_load(cfg_path.read_text())).recalculate_all_scores()
    from starlette.testclient import TestClient
    from threatfeedme import core
    core.reset()
    core.init(str(cfg_path))
    # Auth off for this module whatever ran before: the sign-in tests leave
    # DASHBOARD_* / a cached stored login behind for a few seconds
    # (auth._stored_cache TTL), which 401s the first request here.
    from threatfeedme import auth
    for var in ("DASHBOARD_USER", "DASHBOARD_PASSWORD"):
        os.environ.pop(var, None)
    auth._AUTH_REQUIRED = auth._AUTH_USER = auth._AUTH_PASSWORD = None
    auth._dashboard_config = lambda: {"auth_required": False}
    auth._invalidate()
    from threatfeedme import dashboard
    yield TestClient(dashboard.app, headers={"X-Requested-With": "XMLHttpRequest"})
    auth._invalidate()


# ---- served lists -----------------------------------------------------------

def test_hosts_only_omits_network_entries_in_every_format(client):
    plain = client.get("/feeds/all.txt")
    hosts = client.get("/feeds/all.txt?hosts=1")
    assert "45.66.230.0/24" in plain.text and "45.66.230.99" in plain.text
    assert "45.66.230.0/24" not in hosts.text and "45.66.230.0\n" not in hosts.text
    assert "45.66.230.99" in hosts.text and "198.51.100.7" in hosts.text
    assert plain.headers["etag"] != hosts.headers["etag"], "a different body needs a different ETag"
    assert "45.66.230.0/24" not in client.get("/feeds/all.csv?hosts=1").text
    j = client.get("/feeds/all.json?hosts=1").json()
    assert all("/" not in i["value"] for i in j["indicators"]) and j["total_count"] == 2
    assert client.get("/feeds/all.txt?hosts=0").text == plain.text
    assert client.get("/feeds/all.txt?hosts=2").status_code == 422


def test_hosts_only_and_limit_compose(client):
    body = client.get("/feeds/all.txt?hosts=1&limit=1").text.strip().splitlines()
    assert len(body) == 1 and "/" not in body[0]


# ---- forwarded scheme -------------------------------------------------------

def test_forwarded_proto_is_only_ever_http_or_https(client):
    r = client.get("/", headers={"X-Forwarded-Proto": "javascript:alert(1)//", "Host": "tfm.lan"})
    assert r.status_code == 200 and "javascript:" not in r.text
    r = client.get("/taxii2/", headers={"X-Forwarded-Proto": "javascript:alert(1)//",
                                         "Host": "tfm.lan", "Accept": "application/taxii+json;version=2.1"})
    assert "javascript:" not in r.text
    r = client.get("/", headers={"X-Forwarded-Proto": "https", "Host": "tfm.lan"})
    assert "https://tfm.lan" in r.text


# ---- request caps -----------------------------------------------------------

def test_feed_url_and_header_name_are_bounded(client):
    r = client.post("/api/feeds", json={"name": "big", "url": "https://example.com/" + "a" * 3000})
    assert r.status_code == 422
    r = client.post("/api/feeds", json={"name": "hdr", "url": "https://example.com/l.txt",
                                        "auth_header": "X-Key\r\nEvil: 1"})
    assert r.status_code == 400
    r = client.post("/api/feeds", json={"name": "hdr", "url": "https://example.com/l.txt",
                                        "auth_header": "X-Api-Key"})
    assert r.status_code == 200, r.text
    client.delete("/api/feeds/hdr")


# ---- logging ----------------------------------------------------------------

def test_fetch_log_lines_drop_the_query_string():
    from threatfeedme.feed_ingestor import _redact
    out = _redact("HTTPSConnectionPool: GET https://h.example/list.txt?key=SECRET123&x=1 failed")
    assert "SECRET123" not in out and "list.txt?…" in out


# ---- Test-button error categories ------------------------------------------

def test_integration_failures_are_categories_not_exception_text():
    import requests
    from threatfeedme.routers.integrations import _failure_reason

    class _Resp:
        status_code = 401
    refused = requests.exceptions.ConnectionError("HTTPSConnectionPool(host='10.0.0.7', port=445): refused")
    assert _failure_reason(refused) == "could not reach the host"
    assert "445" not in _failure_reason(refused)
    assert _failure_reason(requests.exceptions.Timeout("x")) == "could not reach the host"
    assert "TLS" in _failure_reason(requests.exceptions.SSLError("bad cert"))
    err = requests.exceptions.HTTPError("401"); err.response = _Resp()
    assert _failure_reason(err) == "login refused"
    assert _failure_reason(RuntimeError("the gateway's TLS certificate changed")).startswith("the gateway")


# ---- TLS switch -------------------------------------------------------------

def test_tls_files_both_or_neither(tmp_path, monkeypatch):
    from threatfeedme import main as m
    monkeypatch.delenv(m.TLS_CERT_ENV, raising=False)
    monkeypatch.delenv(m.TLS_KEY_ENV, raising=False)
    assert m.tls_files() is None and m.tls_kwargs() == {}
    cert = tmp_path / "cert.pem"; key = tmp_path / "key.pem"
    cert.write_text("c"); key.write_text("k")
    monkeypatch.setenv(m.TLS_CERT_ENV, str(cert))
    with pytest.raises(SystemExit):            # one without the other
        m.tls_files()
    monkeypatch.setenv(m.TLS_KEY_ENV, str(tmp_path / "missing.pem"))
    with pytest.raises(SystemExit):            # unreadable file
        m.tls_files()
    monkeypatch.setenv(m.TLS_KEY_ENV, str(key))
    assert m.tls_kwargs() == {"ssl_certfile": str(cert), "ssl_keyfile": str(key)}


# ---- UniFi certificate pin --------------------------------------------------

class _FakeResp:
    headers = {"x-csrf-token": "t"}
    def raise_for_status(self): pass
    def json(self): return {"data": []}


class _FakeSession:
    def __init__(self):
        self.verify = False
        self.posts = []
    def post(self, url, **kw):
        self.posts.append(url); return _FakeResp()
    def request(self, *a, **kw):
        return _FakeResp()


def _pusher(monkeypatch, pinned, presented, verify=False):
    from threatfeedme import pusher_unifi as pu
    monkeypatch.setitem(pu.__dict__, "cert_fingerprint", lambda host, timeout=20: presented)
    monkeypatch.setenv(pu.ENV_USER, "svc"); monkeypatch.setenv(pu.ENV_PASSWORD, "pw")
    session = _FakeSession(); session.verify = verify
    return pu.UniFiPusher("192.0.2.1", session=session, verify_ssl=verify, cert_sha256=pinned), session


def test_unifi_login_refuses_a_changed_certificate_before_sending_the_password(monkeypatch):
    p, session = _pusher(monkeypatch, pinned="aa" * 32, presented="bb" * 32)
    with pytest.raises(RuntimeError, match="certificate changed"):
        p.login()
    assert session.posts == [], "the password must not leave the box"


def test_unifi_login_proceeds_on_matching_or_absent_pin_and_reports_the_fingerprint(monkeypatch):
    p, session = _pusher(monkeypatch, pinned="aa" * 32, presented="aa" * 32)
    p.login(); assert len(session.posts) == 1
    p, session = _pusher(monkeypatch, pinned=None, presented="cc" * 32)
    assert p.test_connection()["cert_sha256"] == "cc" * 32


def test_unifi_pin_is_skipped_when_the_ca_check_is_on(monkeypatch):
    from threatfeedme import pusher_unifi as pu
    p, session = _pusher(monkeypatch, pinned="aa" * 32, presented="bb" * 32, verify=True)
    monkeypatch.setitem(pu.__dict__, "cert_fingerprint",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("probe must not run")))
    p.login(); assert len(session.posts) == 1


def test_unifi_test_pins_on_first_success_and_host_change_clears_it(client, monkeypatch):
    import json
    from threatfeedme import pusher_unifi as pu
    from threatfeedme import core
    monkeypatch.setitem(pu.__dict__, "cert_fingerprint", lambda host, timeout=20: "dd" * 32)
    monkeypatch.setattr(pu.UniFiPusher, "login", lambda self: setattr(self, "seen_cert", "dd" * 32))
    monkeypatch.setattr(pu.UniFiPusher, "_api", lambda self, *a, **k: [])
    monkeypatch.setenv(pu.ENV_USER, "svc"); monkeypatch.setenv(pu.ENV_PASSWORD, "pw")
    assert client.post("/api/integrations/unifi", json={"host": "192.0.2.9"}).status_code == 200
    r = client.post("/api/integrations/unifi/test").json()
    assert r["ok"] and "pinned" in r["message"]
    assert json.loads(core.db.get_setting(pu.SETTINGS_KEY))["cert_sha256"] == "dd" * 32
    assert client.get("/api/integrations/unifi").json()["cert_sha256"] == "dd" * 32
    r = client.post("/api/integrations/unifi/test").json()
    assert "matches the pin" in r["message"]
    client.post("/api/integrations/unifi", json={"host": "192.0.2.10"})
    assert "cert_sha256" not in json.loads(core.db.get_setting(pu.SETTINGS_KEY))
    # trust-certificate re-pins whatever is presented now (the host change
    # above also cleared the saved login, as it should: set it again)
    client.post("/api/integrations/unifi", json={"host": "192.0.2.9"})
    monkeypatch.setenv(pu.ENV_USER, "svc"); monkeypatch.setenv(pu.ENV_PASSWORD, "pw")
    r = client.post("/api/integrations/unifi/trust-certificate").json()
    assert r["ok"] and "pinned" in r["message"]


# ---- scrypt concurrency cap -------------------------------------------------

def test_password_checks_beyond_the_slot_cap_are_turned_away_not_queued(monkeypatch):
    import threading
    from fastapi import HTTPException
    from threatfeedme import auth
    monkeypatch.setitem(auth.__dict__, "_SCRYPT_SLOTS", threading.BoundedSemaphore(1))
    monkeypatch.setitem(auth.__dict__, "_SCRYPT_WAIT_S", 0.05)
    auth._SCRYPT_SLOTS.acquire()                       # the one slot is busy
    try:
        with pytest.raises(HTTPException) as e:
            auth._stored_login_ok({"user": "u", "salt": "00", "hash": "00"}, "u", "wrong")
        assert e.value.status_code == 503
    finally:
        auth._SCRYPT_SLOTS.release()
    # with a slot free the check runs (and fails on the bogus hash)
    assert auth._stored_login_ok({"user": "u", "salt": "00", "hash": "00"}, "u", "wrong") is False


# ---- config -----------------------------------------------------------------

def test_missing_config_file_is_an_error_not_an_empty_config(tmp_path):
    from threatfeedme import core
    with pytest.raises(FileNotFoundError, match="CONFIG_PATH"):
        core.load_config(str(tmp_path / "nope.yaml"))


# ---- Talos scraper transport ------------------------------------------------

class _TalosResp:
    encoding = "utf-8"
    headers = {"content-type": "text/plain"}

    def __init__(self, text, status=200):
        self.text, self.status_code = text, status

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def iter_content(self, chunk_size=65536, decode_unicode=False):
        yield self.text.encode()


class _TalosSession:
    def __init__(self, post_status=200):
        self.headers, self.calls, self.post_status = {}, [], post_status

    def get(self, url, **kw):
        self.calls.append(("get", kw))
        return _TalosResp('<input name="authenticity_token" value="tok123">')

    def post(self, url, data=None, **kw):
        self.calls.append(("post", kw))
        return _TalosResp("" if self.post_status >= 300 else "203.0.113.9\n", self.post_status)


def _talos(monkeypatch, tmp_path, allow_private, post_status=200):
    from threatfeedme import feed_ingestor as fi
    from threatfeedme.database import Database
    from threatfeedme.models import FeedSource, FeedType
    session = _TalosSession(post_status)
    monkeypatch.setattr("requests.Session", lambda: session)
    ing = fi.FeedIngestor(Database(str(tmp_path / "t.db")), allow_private_urls=allow_private)
    feed = FeedSource(name="talos_snort", url=fi._TALOS_TERMS_URL, feed_type=FeedType.THREAT_INTEL)
    return fi, ing, feed, session


def test_talos_keeps_the_operators_proxy_only_when_private_urls_are_allowed(monkeypatch, tmp_path):
    fi, ing, feed, session = _talos(monkeypatch, tmp_path, allow_private=False)
    assert fi._scrape_talos(ing, feed) == "203.0.113.9"
    assert session.trust_env is False
    assert all(kw["proxies"] == fi._NO_PROXIES and kw["stream"] for _, kw in session.calls)
    fi, ing, feed, session = _talos(monkeypatch, tmp_path, allow_private=True)
    fi._scrape_talos(ing, feed)
    assert session.trust_env is True
    assert all(kw["proxies"] is None for _, kw in session.calls)
    assert session.calls[1][1]["allow_redirects"] is False


def test_talos_accept_terms_redirect_is_an_error_not_an_empty_list(monkeypatch, tmp_path):
    fi, ing, feed, session = _talos(monkeypatch, tmp_path, allow_private=False, post_status=302)
    with pytest.raises(RuntimeError, match="redirect"):
        fi._scrape_talos(ing, feed)
