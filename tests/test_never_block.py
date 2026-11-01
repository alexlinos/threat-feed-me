"""Operator never-block list (issue #19): storage, matching, the emission
gate, refusal accounting, and CRUD.

The whole point is that the veto is enforced at the collect/serve chokepoint
(exporter.row_included) and cannot be overridden by tier, provenance, rescore
or re-ingest — so the absence tests run against the pusher's select() and the
raw is_included gate, not only the HTTP layer. No live gateway: the push
summary test drives push_to_unifi against a faked UniFi session.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from threatfeedme.database import Database
from threatfeedme.exporter import is_included
from threatfeedme.models import ConfidenceTier, NeverBlockMatcher
from threatfeedme.pusher_unifi import UniFiPusher


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
    """Speaks just enough UniFi OS API for login + firewallgroup CRUD."""

    def __init__(self):
        self.verify = True
        self.groups = {}
        self._next_id = 100

    def post(self, url, json=None, timeout=None):
        assert url.endswith("/api/auth/login")
        return FakeResponse(headers={"x-csrf-token": "tok"})

    def request(self, method, url, headers=None, timeout=None, json=None):
        if method in ("POST", "PUT"):
            assert headers and headers.get("X-CSRF-Token")
        if method == "GET" and url.endswith("/rest/firewallgroup"):
            return FakeResponse(list(self.groups.values()))
        if method == "POST" and url.endswith("/rest/firewallgroup"):
            gid = f"g{self._next_id}"; self._next_id += 1
            self.groups[gid] = dict(json, _id=gid)
            return FakeResponse([self.groups[gid]])
        if method == "PUT":
            gid = url.rsplit("/", 1)[1]
            self.groups[gid].update(json)
            return FakeResponse([self.groups[gid]])
        raise AssertionError(f"unexpected call {method} {url}")


def _seed_high(db, value, score=0.9, votes=3, kind="ip"):
    db.add_indicator(value, "f1", {}, kind=kind)
    db.set_indicator_score(value, score, "high", votes)


# ---------------- matcher (pure) ----------------

def test_matcher_matches_ip_cidr_domain_and_wildcard():
    nb = NeverBlockMatcher(["203.0.113.5", "198.51.100.0/24", "evil.example",
                            "*.bad.example"])
    assert nb.matches("203.0.113.5")                     # exact IP
    assert nb.matches("198.51.100.77")                   # inside a CIDR
    assert not nb.matches("198.51.101.77")               # outside it
    assert nb.matches("evil.example")                    # exact domain
    assert nb.matches("bad.example")                     # apex of a wildcard
    assert nb.matches("login.bad.example")               # any depth subdomain
    assert not nb.matches("notbad.example")              # label-edge, not substring
    assert not nb.matches("203.0.113.6")
    assert bool(nb)


def test_matcher_empty_is_falsy():
    assert not NeverBlockMatcher([])


# ---------------- the emission gate (collect layer) ----------------

def test_is_included_rejects_never_block_at_every_tier(tmp_path):
    db = Database(str(tmp_path / "t.db"))
    _seed_high(db, "203.0.113.9")
    db.add_never_block("203.0.113.9", "ip", reason="load-bearing")
    wl = db.get_whitelist_map()
    ind = db.get_indicator("203.0.113.9")
    assert ind is not None
    for tier in (None, ConfidenceTier.HIGH, ConfidenceTier.MEDIUM, ConfidenceTier.LOW):
        assert is_included(ind, wl, tier=tier) is False, tier
    # an unrelated value still flows
    _seed_high(db, "203.0.113.10")
    assert is_included(db.get_indicator("203.0.113.10"), wl, tier=ConfidenceTier.HIGH) is True


def test_never_block_survives_rescore_and_reingest(tmp_path):
    """Re-adding the feed value (re-ingest) or re-scoring must not re-emit it."""
    db = Database(str(tmp_path / "t.db"))
    _seed_high(db, "203.0.113.20")
    db.add_never_block("203.0.113.20", "ip")
    db.add_indicator("203.0.113.20", "f2", {})          # another feed reports it again
    db.set_indicator_score("203.0.113.20", 1.0, "high", votes=5)
    wl = db.get_whitelist_map()
    assert is_included(db.get_indicator("203.0.113.20"), wl, tier=ConfidenceTier.HIGH) is False


def test_wildcard_never_block_covers_subdomains_from_domain_select(tmp_path):
    db = Database(str(tmp_path / "t.db"))
    for dom in ("bad.example", "login.bad.example", "good.example"):
        _seed_high(db, dom, kind="domain")
    db.add_never_block("*.bad.example", "domain")
    p = UniFiPusher(host="", domain_tier="high", tier="high")
    sel = p.select(db, "domain", "high")
    assert "good.example" in sel.values
    assert "bad.example" not in sel.values and "login.bad.example" not in sel.values
    assert sel.refused_count == 2


# ---------------- pusher select(): absent + counted apart ----------------

def test_select_excludes_never_block_and_counts_refusals(tmp_path):
    db = Database(str(tmp_path / "t.db"))
    for i in (1, 2, 3):
        _seed_high(db, f"203.0.113.{i}", score=0.9)
    db.add_never_block("203.0.113.2", "ip", reason="our SaaS")
    p = UniFiPusher(host="", tier="high", max_per_group=10)
    sel = p.select(db, "ip", "high")
    assert set(sel.values) == {"203.0.113.1", "203.0.113.3"}
    assert "203.0.113.2" not in sel.values
    assert sel.refused_count == 1 and sel.refused == ["203.0.113.2"]
    # a refusal is not a truncation: everything that is not vetoed is enforced
    assert sel.total == 2 and sel.withheld == []


def test_cidr_never_block_swallows_hosts_from_select(tmp_path):
    db = Database(str(tmp_path / "t.db"))
    for i in (10, 11, 12):
        _seed_high(db, f"198.51.100.{i}", score=0.9)
    _seed_high(db, "192.0.2.5", score=0.9)              # outside the range
    db.add_never_block("198.51.100.0/24", "ip")
    p = UniFiPusher(host="", tier="high", max_per_group=10)
    sel = p.select(db, "ip", "high")
    assert sel.values == ["192.0.2.5"]
    assert sel.refused_count == 3


# ---------------- push summary names the trigger ----------------

def test_push_summary_reports_never_block_refusals(tmp_path, monkeypatch):
    from threatfeedme import pusher_unifi as pu
    db = Database(str(tmp_path / "t.db"))
    for i in (1, 2, 3):
        _seed_high(db, f"203.0.113.{i}", score=0.9)
    db.add_never_block("203.0.113.3", "ip", reason="our own box")
    monkeypatch.setenv("UNIFI_USER", "svc")
    monkeypatch.setenv("UNIFI_PASSWORD", "pw")
    session = FakeSession()
    monkeypatch.setattr(pu.UniFiPusher, "from_config",
                        classmethod(lambda cls, config, db=None: UniFiPusher(
                            session=session, host="192.0.2.1", tier="high",
                            group_prefix="tfm", max_per_group=10)))
    summary = pu.push_to_unifi(db, {"integrations": {"unifi": {"enabled": True, "host": "192.0.2.1"}}})
    assert summary["never_block_refused"] == 1
    assert summary["entries"] == 2
    pushed = set()
    for g in session.groups.values():
        pushed |= set(g.get("group_members") or [])
    assert "203.0.113.3" not in pushed
    assert {"203.0.113.1", "203.0.113.2"} <= pushed


# ---------------- CRUD + API ----------------

def test_db_crud_roundtrip(tmp_path):
    db = Database(str(tmp_path / "t.db"))
    db.add_never_block("203.0.113.7", "ip", reason="x", added_by="operator")
    entries = db.get_never_block()
    assert [e.value for e in entries] == ["203.0.113.7"]
    assert entries[0].kind == "ip" and entries[0].added_by == "operator"
    # re-adding updates rather than duplicating
    db.add_never_block("203.0.113.7", "ip", reason="y")
    assert len(db.get_never_block()) == 1
    assert db.get_never_block()[0].reason == "y"
    assert db.remove_never_block("203.0.113.7") is True
    assert db.remove_never_block("203.0.113.7") is False


# The CRUD endpoints run through the same require_auth + csrf_check as the
# whitelist (proven globally in test_csrf_subprocess), so here we drive the
# router functions directly against a temp DB — no TestClient, no module
# reload. core's singletons resolve via module __getattr__, so patching
# core.__dict__ (not setattr, which reads the lazy value first) swaps them
# without ever touching the repo's real config or ./data.
def _wire_core(monkeypatch, db):
    from threatfeedme import core, pipeline
    monkeypatch.setitem(core.__dict__, "db", db)
    monkeypatch.setitem(core.__dict__, "config", {})
    monkeypatch.setattr(pipeline, "export_tiers_async", lambda db, config: None)


def test_router_add_list_remove_and_enforce(tmp_path, monkeypatch):
    from threatfeedme.routers import never_block as nb
    from threatfeedme.schemas import NeverBlockRequest
    db = Database(str(tmp_path / "t.db"))
    _wire_core(monkeypatch, db)

    r = nb.add_never_block(NeverBlockRequest(value="*.EXAMPLE.com", reason="trusted vendor"),
                           None, None)
    assert r["success"] is True
    listed = nb.list_never_block(None)
    assert any(e.value == "*.example.com" and e.kind == "domain" for e in listed)
    # stored canonical, and now enforced through the shared matcher
    assert db.get_never_block_matcher().matches("app.example.com")

    d = nb.remove_never_block("*.example.com", None, None)
    assert d["success"] is True
    assert not db.get_never_block_matcher().matches("app.example.com")


def test_router_rejects_junk_value(tmp_path, monkeypatch):
    from fastapi import HTTPException
    from threatfeedme.routers import never_block as nb
    from threatfeedme.schemas import NeverBlockRequest
    db = Database(str(tmp_path / "t.db"))
    _wire_core(monkeypatch, db)
    with pytest.raises(HTTPException) as ei:
        nb.add_never_block(NeverBlockRequest(value="not a value!!"), None, None)
    assert ei.value.status_code == 400


def test_router_remove_unknown_is_404(tmp_path, monkeypatch):
    from fastapi import HTTPException
    from threatfeedme.routers import never_block as nb
    db = Database(str(tmp_path / "t.db"))
    _wire_core(monkeypatch, db)
    with pytest.raises(HTTPException) as ei:
        nb.remove_never_block("203.0.113.99", None, None)
    assert ei.value.status_code == 404


def test_router_registers_all_three_verbs():
    from threatfeedme.routers import never_block as nb
    paths = {r.path for r in nb.router.routes}
    methods = set()
    for r in nb.router.routes:
        methods |= set(r.methods)
    assert paths == {"/api/never-block"}
    assert {"GET", "POST", "DELETE"} <= methods
