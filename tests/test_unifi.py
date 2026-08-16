"""UniFi pusher: config gating, credential handling, collection (kind/v6/
whitelist/truncation), and group reconciliation against a fake UniFi API.

No live gateway in CI — the API surface (login CSRF dance, /rest/firewallgroup
shapes) is faked at the session level, matching what UniFi OS returns.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from threatfeedme.pusher_unifi import (UniFiPusher, push_ready, push_to_unifi,
                                       ENV_USER, ENV_PASSWORD)


class FakeResponse:
    def __init__(self, data=None, headers=None, status=200):
        self._data = data if data is not None else []
        self.headers = headers or {}
        self.status_code = status

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def json(self):
        return {"meta": {"rc": "ok"}, "data": self._data}


class FakeSession:
    """Session stub speaking just enough UniFi OS API."""

    def __init__(self, groups=None):
        self.verify = True
        self.groups = {g["_id"]: dict(g) for g in (groups or [])}
        self.calls = []          # (method, url, json)
        self._next_id = 100

    def post(self, url, json=None, timeout=None):
        self.calls.append(("POST", url, json))
        assert url.endswith("/api/auth/login")
        return FakeResponse(headers={"x-csrf-token": "tok-1"})

    def request(self, method, url, headers=None, timeout=None, json=None):
        self.calls.append((method, url, json))
        if method in ("POST", "PUT"):
            # Mutations must carry the CSRF token from login.
            assert headers and headers.get("X-CSRF-Token"), "missing CSRF token"
        if method == "GET" and url.endswith("/rest/firewallgroup"):
            return FakeResponse(list(self.groups.values()))
        if method == "POST" and url.endswith("/rest/firewallgroup"):
            gid = f"g{self._next_id}"
            self._next_id += 1
            self.groups[gid] = dict(json, _id=gid)
            return FakeResponse([self.groups[gid]])
        if method == "PUT":
            gid = url.rsplit("/", 1)[1]
            self.groups[gid].update(json)
            return FakeResponse([self.groups[gid]])
        raise AssertionError(f"unexpected call {method} {url}")


def _pusher(session, **kw):
    kw.setdefault("host", "192.168.1.1")
    kw.setdefault("tier", "medium")
    kw.setdefault("group_prefix", "tfm")
    p = UniFiPusher(session=session, **kw)
    return p


# ---------------- config / credentials ----------------

def test_from_config_disabled_or_hostless_is_none():
    assert UniFiPusher.from_config({}) is None
    assert UniFiPusher.from_config({"integrations": {"unifi": {"enabled": True}}}) is None
    assert UniFiPusher.from_config(
        {"integrations": {"unifi": {"enabled": False, "host": "10.0.0.1"}}}) is None


def test_from_config_builds_and_normalizes_host():
    p = UniFiPusher.from_config(
        {"integrations": {"unifi": {"enabled": True, "host": "192.168.1.1", "tier": "bogus"}}})
    assert p is not None
    assert p.host == "https://192.168.1.1"
    assert p.tier == "high"  # unknown tier falls back to the default


def test_login_requires_env_credentials(monkeypatch):
    monkeypatch.delenv(ENV_USER, raising=False)
    monkeypatch.delenv(ENV_PASSWORD, raising=False)
    p = _pusher(FakeSession())
    with pytest.raises(RuntimeError, match="UNIFI_USER"):
        p.login()


def test_push_disabled_returns_none(tmp_path):
    from threatfeedme.database import Database
    db = Database(str(tmp_path / "t.db"))
    assert push_to_unifi(db, {}) is None


def test_push_ready_requires_all_variables(tmp_path, monkeypatch):
    """The if-gate for high-frequency callers: enabled AND host AND both
    credential vars non-empty — anything missing means skip, silently."""
    from threatfeedme.database import Database
    db = Database(str(tmp_path / "t.db"))
    enabled_cfg = {"integrations": {"unifi": {"enabled": True, "host": "192.168.1.1"}}}
    monkeypatch.delenv(ENV_USER, raising=False)
    monkeypatch.delenv(ENV_PASSWORD, raising=False)
    assert push_ready(db, {}) is False                       # nothing configured
    assert push_ready(db, enabled_cfg) is False              # no credentials
    monkeypatch.setenv(ENV_USER, "svc")
    assert push_ready(db, enabled_cfg) is False              # password missing
    monkeypatch.setenv(ENV_PASSWORD, "pw")
    assert push_ready(db, enabled_cfg) is True               # all set
    assert push_ready(db, {"integrations": {"unifi": {"enabled": False,
                                                      "host": "192.168.1.1"}}}) is False
    monkeypatch.setenv(ENV_PASSWORD, "")                     # set-but-EMPTY is unset
    assert push_ready(db, enabled_cfg) is False


def test_whitelist_export_worker_pushes_when_ready(tmp_path, monkeypatch):
    """A whitelist change rides the background export worker to the gateway:
    push fires when the integration is fully configured, never otherwise."""
    import threading
    from threatfeedme.database import Database
    from threatfeedme import pipeline, pusher_unifi
    db = Database(str(tmp_path / "t.db"))
    cfg = {"output": {"base_dir": str(tmp_path / "out"), "formats": ["text"]},
           "integrations": {"unifi": {"enabled": True, "host": "192.168.1.1"}}}
    pushed = threading.Event()
    monkeypatch.setattr(pusher_unifi, "push_to_unifi",
                        lambda db_, cfg_: pushed.set())
    # Not ready (no creds): the worker must NOT push.
    monkeypatch.delenv(ENV_USER, raising=False)
    monkeypatch.delenv(ENV_PASSWORD, raising=False)
    pipeline.export_tiers_async(db, cfg)
    assert not pushed.wait(timeout=2)
    # Ready: the same worker pushes.
    monkeypatch.setenv(ENV_USER, "svc")
    monkeypatch.setenv(ENV_PASSWORD, "pw")
    pipeline.export_tiers_async(db, cfg)
    assert pushed.wait(timeout=5), "configured integration did not push on export"


# ---------------- collection ----------------

def test_collect_is_ip_only_whitelisted_and_v4(tmp_path):
    from threatfeedme.database import Database
    db = Database(str(tmp_path / "t.db"))
    db.add_indicator("203.0.113.1", "f1", {})
    db.add_indicator("203.0.113.0", "f1", {"cidr": "203.0.113.0/24"})
    db.add_indicator("2001:db8::1", "f1", {})                      # v6: skipped
    db.add_indicator("evil.example.com", "f1", {}, kind="domain")  # wrong kind
    db.add_indicator("198.51.100.9", "f1", {})
    db.add_to_whitelist("198.51.100.9", "fp", "t")                 # whitelisted
    for ip, tier in (("203.0.113.1", "medium"), ("203.0.113.0", "high"),
                     ("2001:db8::1", "medium"), ("evil.example.com", "medium"),
                     ("198.51.100.9", "high")):
        db.set_indicator_score(ip, 0.5, tier)

    values = _pusher(FakeSession()).collect(db)
    assert set(values) == {"203.0.113.1", "203.0.113.0/24"}


def test_collect_truncates_keeping_strongest(tmp_path):
    from threatfeedme.database import Database
    db = Database(str(tmp_path / "t.db"))
    for i, score in ((1, 0.9), (2, 0.5), (3, 0.1)):
        ip = f"203.0.113.{i}"
        db.add_indicator(ip, "f1", {})
        db.set_indicator_score(ip, score, "medium")
    values = _pusher(FakeSession(), max_entries=2).collect(db)
    # iter_indicators_by_tiers streams in confidence order.
    assert values == ["203.0.113.1", "203.0.113.2"]


# ---------------- sync reconciliation ----------------

@pytest.fixture(autouse=True)
def _fake_creds(monkeypatch):
    monkeypatch.setenv(ENV_USER, "svc-tfm")
    monkeypatch.setenv(ENV_PASSWORD, "hunter2")


def test_sync_creates_chunked_groups():
    s = FakeSession()
    p = _pusher(s, max_per_group=2)
    p.login()
    summary = p.sync(["1.1.1.1", "2.2.2.2", "3.3.3.3"])
    assert summary == {"entries": 3, "groups": 2, "created": 2,
                       "updated": 0, "unchanged": 0, "emptied": 0}
    names = {g["name"]: g["group_members"] for g in s.groups.values()}
    assert names == {"tfm-medium-1": ["1.1.1.1", "2.2.2.2"],
                     "tfm-medium-2": ["3.3.3.3"]}
    assert all(g["group_type"] == "address-group" for g in s.groups.values())


def test_sync_updates_changed_keeps_identical_empties_stale():
    s = FakeSession(groups=[
        {"_id": "a", "name": "tfm-medium-1", "group_type": "address-group",
         "group_members": ["1.1.1.1", "2.2.2.2"]},          # identical -> untouched
        {"_id": "b", "name": "tfm-medium-2", "group_type": "address-group",
         "group_members": ["9.9.9.9"]},                     # differs -> updated
        {"_id": "c", "name": "tfm-medium-3", "group_type": "address-group",
         "group_members": ["8.8.8.8"]},                     # stale -> emptied
        {"_id": "d", "name": "unrelated", "group_type": "address-group",
         "group_members": ["7.7.7.7"]},                     # not ours -> untouched
    ])
    p = _pusher(s, max_per_group=2)
    p.login()
    summary = p.sync(["1.1.1.1", "2.2.2.2", "3.3.3.3"])
    assert summary["created"] == 0
    assert summary["unchanged"] == 1
    assert summary["updated"] == 1
    assert summary["emptied"] == 1
    assert s.groups["b"]["group_members"] == ["3.3.3.3"]
    assert s.groups["c"]["group_members"] == []       # emptied, NOT deleted
    assert s.groups["d"]["group_members"] == ["7.7.7.7"]


def test_sync_switching_tier_empties_other_tiers_groups():
    """A tier change must not leave the previous tier's groups silently
    blocking the old list: every group under our prefix that isn't part of
    the current chunk set gets emptied (bit a real gateway: a tier=low push
    left threatfeedme-low-1..10 populated after switching to medium)."""
    s = FakeSession(groups=[
        {"_id": "L1", "name": "tfm-low-1", "group_type": "address-group",
         "group_members": ["5.5.5.5"]},
        {"_id": "L2", "name": "tfm-low-2", "group_type": "address-group",
         "group_members": ["6.6.6.6"]},
    ])
    p = _pusher(s, max_per_group=2)   # tier=medium
    p.login()
    summary = p.sync(["1.1.1.1"])
    assert summary["created"] == 1 and summary["emptied"] == 2
    assert s.groups["L1"]["group_members"] == []
    assert s.groups["L2"]["group_members"] == []


def test_sync_fixed_list_count_pads_with_empty_lists():
    """UniFi policies reference exactly ONE list each, so the list count
    must never grow past what the operator built policies for: fixed count,
    unused lists pre-created empty, overflow truncated strongest-kept."""
    s = FakeSession()
    p = _pusher(s, max_per_group=2)
    p.login()
    summary = p.sync(["1.1.1.1", "2.2.2.2", "3.3.3.3"], list_count=4)
    assert summary["groups"] == 4 and summary["created"] == 4
    by_name = {g["name"]: g["group_members"] for g in s.groups.values()}
    assert by_name == {"tfm-medium-1": ["1.1.1.1", "2.2.2.2"],
                       "tfm-medium-2": ["3.3.3.3"],
                       "tfm-medium-3": [], "tfm-medium-4": []}
    # Overflow beyond count x per_group truncates, never mints list 5.
    summary = p.sync([f"10.0.0.{i}" for i in range(1, 12)], list_count=4)
    assert summary["groups"] == 4
    assert sum(len(g["group_members"]) for g in s.groups.values()) == 8


def test_sync_empty_corpus_pushes_one_empty_group():
    s = FakeSession()
    p = _pusher(s)
    p.login()
    summary = p.sync([])
    assert summary["groups"] == 1 and summary["entries"] == 0
    (g,) = s.groups.values()
    assert g["name"] == "tfm-medium-1" and g["group_members"] == []


# ---------------- domain arm (Content Filtering profile) ----------------

def test_collect_domains_is_domain_only_and_whitelisted(tmp_path):
    from threatfeedme.database import Database
    db = Database(str(tmp_path / "t.db"))
    db.add_indicator("203.0.113.1", "f1", {})                        # wrong kind
    db.add_indicator("evil-a.example.io", "f1", {}, kind="domain")
    db.add_indicator("evil-b.example.io", "f1", {}, kind="domain")
    db.add_to_whitelist("evil-b.example.io", "fp", "t")
    for v, tier in (("203.0.113.1", "high"), ("evil-a.example.io", "high"),
                    ("evil-b.example.io", "high")):
        db.set_indicator_score(v, 0.5, tier)
    p = _pusher(FakeSession(), domain_tier="high")
    assert p.collect_domains(db) == ["evil-a.example.io"]


def test_domain_sync_creates_domain_groups_isolated_from_ip_groups():
    """Both arms share sync() but scope stale detection to their own
    group_type — the IP pass must never empty the domain lists (they share
    the name prefix) and vice versa."""
    s = FakeSession(groups=[
        {"_id": "d1", "name": "tfm-dom-high-1", "group_type": "domain-group",
         "group_members": ["old.example.io"]},
    ])
    p = _pusher(s, tier="high", domain_tier="high", max_per_group=2)
    p.login()
    # IP sync runs first and must not touch the (stale-looking) domain list.
    p.sync(["1.1.1.1"])
    assert s.groups["d1"]["group_members"] == ["old.example.io"]
    # Domain sync updates its own list and leaves the IP group alone.
    r = p.sync(["evil-a.example.io", "evil-b.example.io", "evil-c.example.io"],
               label="dom-high", group_type="domain-group")
    assert r["entries"] == 3 and r["groups"] == 2
    assert r["updated"] == 1 and r["created"] == 1
    by_name = {g["name"]: g for g in s.groups.values()}
    assert by_name["tfm-dom-high-1"]["group_members"] == ["evil-a.example.io", "evil-b.example.io"]
    assert by_name["tfm-dom-high-2"]["group_type"] == "domain-group"
    assert by_name["tfm-high-1"]["group_members"] == ["1.1.1.1"]


def test_push_includes_domain_summary(tmp_path, monkeypatch):
    from threatfeedme.database import Database
    from threatfeedme import pusher_unifi as pu
    db = Database(str(tmp_path / "t.db"))
    db.add_indicator("203.0.113.9", "f1", {})
    db.add_indicator("evil.example.io", "f1", {}, kind="domain")
    db.set_indicator_score("203.0.113.9", 0.9, "high")
    db.set_indicator_score("evil.example.io", 0.9, "high")
    monkeypatch.setenv(ENV_USER, "svc")
    monkeypatch.setenv(ENV_PASSWORD, "pw")
    session = FakeSession()
    monkeypatch.setattr(pu.UniFiPusher, "from_config",
                        classmethod(lambda cls, config, db=None: _pusher(
                            session, tier="high", domain_tier="high")))
    summary = pu.push_to_unifi(db, {"integrations": {"unifi": {
        "enabled": True, "host": "192.168.1.1"}}})
    assert summary["entries"] == 1                       # IP arm
    assert summary["domains"]["entries"] == 1            # domain arm
    assert "domain_error" not in summary
    names = {g["name"]: g["group_type"] for g in session.groups.values()}
    assert names == {"tfm-high-1": "address-group", "tfm-dom-high-1": "domain-group"}


# ---------------- dashboard API (settings, credentials, test, push) ----------------

@pytest.fixture(scope="module")
def api_client(tmp_path_factory):
    work = tmp_path_factory.mktemp("unifi_api")
    db_path = str(work / "t.db").replace("\\", "/")
    cfg_path = work / "config.yaml"
    cfg_path.write_text(
        "database:\n"
        f"  path: {db_path}\n"
        "feeds: []\n"
        "dashboard: {auth_required: false}\n"
    )
    os.environ["CONFIG_PATH"] = str(cfg_path)
    for m in list(sys.modules.keys()):
        if m == "threatfeedme" or m.startswith("threatfeedme."):
            sys.modules.pop(m, None)
    from threatfeedme import core
    core.reset()
    core.init(str(cfg_path))
    from starlette.testclient import TestClient
    from threatfeedme import dashboard
    return TestClient(dashboard.app, headers={"X-Requested-With": "XMLHttpRequest"})


def test_api_status_defaults_and_no_credential_echo(api_client, monkeypatch):
    monkeypatch.delenv(ENV_USER, raising=False)
    monkeypatch.delenv(ENV_PASSWORD, raising=False)
    j = api_client.get("/api/integrations/unifi").json()
    assert j["enabled"] is False and j["tier"] == "high"
    assert j["credentials_configured"] is False
    # The status payload must never carry credential VALUES under any key.
    assert "password" not in str(j).lower()


def test_api_settings_roundtrip_and_validation(api_client):
    r = api_client.post("/api/integrations/unifi",
                        json={"enabled": True, "host": "192.168.1.1", "tier": "high"})
    assert r.status_code == 200
    j = api_client.get("/api/integrations/unifi").json()
    assert j["enabled"] is True and j["host"] == "192.168.1.1" and j["tier"] == "high"
    assert api_client.post("/api/integrations/unifi", json={"tier": "bogus"}).status_code == 400
    assert api_client.post("/api/integrations/unifi",
                           json={"host": "https://gw/path/x"}).status_code == 400
    # Partial update merges — host survives a tier-only change.
    api_client.post("/api/integrations/unifi", json={"tier": "medium"})
    assert api_client.get("/api/integrations/unifi").json()["host"] == "192.168.1.1"


def test_api_credentials_write_only(api_client, monkeypatch):
    from threatfeedme import core
    r = api_client.post("/api/integrations/unifi/credentials",
                        json={"username": "svc-tfm", "password": "s3cret!"})
    assert r.status_code == 200
    assert r.json() == {"success": True, "credentials_configured": True}
    assert os.environ[ENV_USER] == "svc-tfm"
    with open(core.env_file(), encoding="utf-8") as f:
        env_text = f.read()
    assert "UNIFI_PASSWORD=s3cret!" in env_text  # persisted for restarts
    # ...but no API response ever echoes it back.
    assert "s3cret" not in api_client.get("/api/integrations/unifi").text
    # Clearing works.
    api_client.post("/api/integrations/unifi/credentials", json={})
    assert api_client.get("/api/integrations/unifi").json()["credentials_configured"] is False
    assert ENV_PASSWORD not in os.environ


def test_api_test_endpoint(api_client, monkeypatch):
    # Fresh module identity after the fixture's purge — patch the live one.
    from threatfeedme import pusher_unifi as pu
    api_client.post("/api/integrations/unifi/credentials",
                    json={"username": "svc", "password": "pw"})
    monkeypatch.setattr(pu.UniFiPusher, "test_connection",
                        lambda self: {"ok": True, "groups_total": 4,
                                      "our_groups": ["threatfeedme-medium-1"]})
    j = api_client.post("/api/integrations/unifi/test").json()
    assert j["ok"] is True and "4 firewall group(s)" in j["message"]
    # A connection failure comes back inline, not as a 500.
    def boom(self):
        raise RuntimeError("connection refused")
    monkeypatch.setattr(pu.UniFiPusher, "test_connection", boom)
    j = api_client.post("/api/integrations/unifi/test").json()
    assert j["ok"] is False and "connection refused" in j["message"]
    api_client.post("/api/integrations/unifi/credentials", json={})


def test_api_push_requires_enabled(api_client):
    api_client.post("/api/integrations/unifi", json={"enabled": False})
    r = api_client.post("/api/integrations/unifi/push")
    assert r.status_code == 400
    api_client.post("/api/integrations/unifi", json={"enabled": True})


def test_api_push_records_outcome(api_client, monkeypatch):
    from threatfeedme import pusher_unifi as pu, core
    api_client.post("/api/integrations/unifi/credentials",
                    json={"username": "svc", "password": "pw"})
    monkeypatch.setattr(pu.UniFiPusher, "login", lambda self: None)
    monkeypatch.setattr(pu.UniFiPusher, "collect", lambda self, db: ["1.1.1.1"])
    monkeypatch.setattr(pu.UniFiPusher, "sync",
                        lambda self, values, **kw: {"entries": 1, "groups": 1, "created": 1,
                                                    "updated": 0, "unchanged": 0, "emptied": 0})
    r = api_client.post("/api/integrations/unifi/push")
    assert r.status_code == 200 and r.json()["summary"]["entries"] == 1
    # Outcome is persisted for the panel's status line.
    j = api_client.get("/api/integrations/unifi").json()
    assert j["last_push"]["summary"]["entries"] == 1
    assert j["last_push"]["error"] is None
    api_client.post("/api/integrations/unifi/credentials", json={})
