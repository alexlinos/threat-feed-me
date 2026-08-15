"""UniFi pusher: config gating, credential handling, collection (kind/v6/
whitelist/truncation), and group reconciliation against a fake UniFi API.

No live gateway in CI — the API surface (login CSRF dance, /rest/firewallgroup
shapes) is faked at the session level, matching what UniFi OS returns.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from threatfeedme.pusher_unifi import UniFiPusher, push_to_unifi, ENV_USER, ENV_PASSWORD


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
    assert p.tier == "medium"  # unknown tier falls back


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


def test_sync_empty_corpus_pushes_one_empty_group():
    s = FakeSession()
    p = _pusher(s)
    p.login()
    summary = p.sync([])
    assert summary["groups"] == 1 and summary["entries"] == 0
    (g,) = s.groups.values()
    assert g["name"] == "tfm-medium-1" and g["group_members"] == []
