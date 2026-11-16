"""The UniFi push must not make a gateway block shared CDN addresses.

A UniFi domain list is enforced by the addresses its names resolve to. Most
phishing domains sit behind a CDN proxy, so pushing them blocked the CDN's
shared addresses and every unrelated site on them (2026-11-16: 543 of 870
pushed High domains resolved into one CDN's ranges). Three fixes are pinned
here: shared CDN ranges are part of the IP safety floor, a domain goes to
the gateway only when every address it resolves to would be allowed on an
IP list, and switching the domain arm off empties its lists.

Offline: every lookup is a fake passed in or patched on the module.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from threatfeedme import pusher_unifi as pu
from threatfeedme import resolved_guard as rg
from threatfeedme.database import Database
from threatfeedme.pusher_unifi import ENV_PASSWORD, ENV_USER, UniFiPusher
from threatfeedme.safety import SHARED_EDGE, SafetyFilter

from test_unifi import FakeSession

# One address inside the shipped shared-edge ranges, and one plain public
# address no floor covers.
EDGE_V4 = "104.16.0.1"
EDGE_V6 = "2606:4700::1"
PLAIN = "5.6.7.8"


def _lookups(table, calls=None):
    """A fake resolver: name -> addresses, [] for anything unknown."""
    def lookup(name):
        if calls is not None:
            calls.append(name)
        return list(table.get(name, []))
    return lookup


def _judge(address):
    return SafetyFilter().address_reason(address)


@pytest.fixture
def db(tmp_path):
    return Database(str(tmp_path / "t.db"))


def _domains(db, names, score=0.9):
    for i, name in enumerate(names):
        db.add_indicator(name, "f1", {}, kind="domain")
        db.set_indicator_score(name, score - i * 0.01, "high")


def _pusher(session=None, **kw):
    kw.setdefault("host", "192.168.1.1")
    kw.setdefault("tier", "high")
    kw.setdefault("group_prefix", "tfm")
    return UniFiPusher(session=session or FakeSession(), **kw)


# ---------------- the IP floor ----------------

def test_shared_edge_addresses_are_refused_on_ip_lists():
    # A feed listing a CDN edge address names a site behind the proxy;
    # blocking the address blocks everyone else on it.
    f = SafetyFilter()
    assert "protected public infrastructure" in f.excluded_reason(EDGE_V4)
    assert "protected public infrastructure" in f.excluded_reason(EDGE_V6)
    assert f.excluded_reason("172.67.201.147") is not None
    assert f.excluded_reason(PLAIN) is None


def test_a_range_touching_shared_edge_is_refused():
    # Overlap, not containment: a wider block that swallows part of the
    # edge space is as harmful as an address inside it.
    f = SafetyFilter()
    assert f.excluded_reason("104.0.0.0/11") is not None      # contains 104.16.0.0/13
    assert f.excluded_reason("104.16.5.0/24") is not None     # inside it
    assert f.excluded_reason("104.32.0.0/16") is None         # next door


def test_shared_edge_follows_the_protect_known_good_switch():
    f = SafetyFilter(protect_known_good=False)
    assert f.excluded_reason(EDGE_V4) is None


def test_operator_known_good_accepts_ranges():
    # safety.known_good used to take single addresses only; a CIDR was
    # silently dropped, so an operator could not protect another CDN.
    f = SafetyFilter(known_good=["185.1.0.0/16", "2.2.2.2"])
    assert f.excluded_reason("185.1.1.1") is not None
    assert f.excluded_reason("2.2.2.2") is not None
    assert f.excluded_reason("2.2.2.3") is None


def test_existing_resolver_protection_still_names_the_address():
    assert SafetyFilter().excluded_reason("8.8.8.8") == \
        "protected public infrastructure (8.8.8.8)"
    assert SafetyFilter().excluded_reason("8.8.8.0/24") is not None


def test_shared_edge_list_parses_and_is_public():
    import ipaddress
    nets = [ipaddress.ip_network(n) for n in SHARED_EDGE]
    assert len(nets) == len(set(nets)) and all(not n.is_private for n in nets)


def test_stored_edge_addresses_are_purged_retroactively(db):
    # Rows stored before the floor existed must leave on the next refresh,
    # not linger until they age out.
    db.add_indicator(EDGE_V4, "f1", {})
    db.add_indicator(PLAIN, "f1", {})
    reasons = db.purge_unsafe_indicators(SafetyFilter())
    assert sum(reasons.values()) == 1
    assert db.get_indicator(EDGE_V4) is None
    assert db.get_indicator(PLAIN) is not None


def test_address_reason_refuses_what_it_cannot_parse():
    f = SafetyFilter()
    assert f.address_reason("not-an-address") == "not an IP address"
    assert f.address_reason("fe80::1%eth0") is not None        # link-local, zone stripped
    assert f.address_reason("127.0.0.1") is not None           # a sinkhole answer
    assert f.address_reason(PLAIN) is None


# ---------------- resolved_guard.screen ----------------

def test_screen_sorts_names_by_what_they_resolve_to():
    table = {"on-cdn.example.io": [EDGE_V4], "own-host.example.io": [PLAIN],
             "mixed.example.io": [PLAIN, EDGE_V6], "sinkholed.example.io": ["0.0.0.0"]}
    names = ["on-cdn.example.io", "own-host.example.io", "mixed.example.io",
             "dead.example.io", "sinkholed.example.io"]
    verdicts = rg.screen(names, 10, _judge, lookup=_lookups(table))
    # A placeholder-only answer is a DNS filter talking, counted apart
    # (tests/test_unifi_dns_filter.py).
    assert [v for v, _ in verdicts] == [rg.PROTECTED, rg.OK, rg.PROTECTED,
                                        rg.UNRESOLVED, rg.FILTERED]
    # The detail names the address, so an operator can see why.
    assert verdicts[0][1].startswith(EDGE_V4 + ":")
    assert verdicts[2][1].startswith(EDGE_V6 + ":")     # one bad address is enough


def test_screen_stops_looking_once_the_cap_is_met():
    # Names past the cap are cut whatever they resolve to, so they cost no
    # lookups (a Medium tier is tens of thousands of names).
    names = [f"n{i}.example.io" for i in range(rg.CHUNK * 3)]
    calls = []
    verdicts = rg.screen(names, 5, _judge,
                         lookup=_lookups({n: [PLAIN] for n in names}, calls))
    assert [v for v, _ in verdicts[:5]] == [rg.OK] * 5
    assert all(v == rg.UNEXAMINED for v, _ in verdicts[5:])
    assert len(calls) <= rg.CHUNK


def test_screen_answers_from_cache_and_refreshes_after_ttl():
    now = [1000.0]
    calls = []
    lookup = _lookups({"a.example.io": [PLAIN]}, calls)
    kw = dict(lookup=lookup, clock=lambda: now[0])
    assert rg.screen(["a.example.io"], 1, _judge, **kw)[0][0] == rg.OK
    assert rg.screen(["a.example.io"], 1, _judge, **kw)[0][0] == rg.OK
    assert calls == ["a.example.io"]                     # second answer was cached
    now[0] += rg.TTL_RESOLVED + 1
    rg.screen(["a.example.io"], 1, _judge, **kw)
    assert calls == ["a.example.io", "a.example.io"]     # stale answers are re-read


def test_a_cached_answer_is_judged_again_each_time():
    # Addresses are cached, not verdicts: a never-block or known-good entry
    # added later applies on the next push, not after the TTL.
    lookup = _lookups({"a.example.io": [PLAIN]})
    assert rg.screen(["a.example.io"], 1, lambda a: None, lookup=lookup)[0][0] == rg.OK
    verdict, detail = rg.screen(["a.example.io"], 1, lambda a: "operator said no",
                                lookup=lookup)[0]
    assert verdict == rg.PROTECTED and "operator said no" in detail


def test_screen_without_resolve_never_looks_anything_up():
    calls = []
    verdicts = rg.screen(["a.example.io"], 1, _judge, resolve=False,
                         lookup=_lookups({"a.example.io": [PLAIN]}, calls))
    assert verdicts == [(rg.UNCHECKED, "")] and calls == []


def test_screen_fails_closed_when_the_budget_is_spent():
    # No time left means no lookups; unknown names are held back, not pushed
    # unchecked.
    calls = []
    verdicts = rg.screen(["a.example.io"], 1, _judge, budget=0,
                         lookup=_lookups({"a.example.io": [PLAIN]}, calls))
    assert verdicts == [(rg.UNCHECKED, "")] and calls == []


def test_a_lookup_that_raises_leaves_the_name_unchecked():
    # No answer is not "does not resolve": the name is held back this push
    # and asked again on the next, with nothing cached in between.
    def boom(name):
        raise RuntimeError("resolver exploded")
    assert rg.screen(["a.example.io"], 1, _judge, lookup=boom)[0][0] == rg.UNCHECKED
    assert rg.screen(["a.example.io"], 1, _judge,
                     lookup=_lookups({"a.example.io": [PLAIN]}))[0][0] == rg.OK


def test_system_lookup_reads_addresses_and_swallows_resolver_errors(monkeypatch):
    import socket

    def fake_getaddrinfo(name, port, type=0):
        if name == "dead.example.io":
            raise socket.gaierror("no such host")
        return [(socket.AF_INET, type, 6, "", (PLAIN, 0)),
                (socket.AF_INET, type, 6, "", (PLAIN, 0)),
                (socket.AF_INET6, type, 6, "", ("fe80::1%eth0", 0, 0, 3))]
    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    assert rg.system_lookup("live.example.io") == [PLAIN, "fe80::1"]
    assert rg.system_lookup("dead.example.io") == []


def test_the_suite_never_resolves_for_real():
    # conftest points the seam at a fake for every test.
    assert rg.__dict__["_lookup"] is not rg.system_lookup


# ---------------- the domain arm ----------------

def test_domain_selection_holds_back_cdn_fronted_and_dead_names(db, monkeypatch):
    names = ["on-cdn.example.io", "own-host.example.io", "dead.example.io",
             "also-cdn.example.io", "second-host.example.io"]
    _domains(db, names)
    monkeypatch.setitem(pu.resolved_guard.__dict__, "_lookup", _lookups({
        "on-cdn.example.io": [EDGE_V4], "also-cdn.example.io": ["172.67.1.1"],
        "own-host.example.io": [PLAIN], "second-host.example.io": ["5.6.7.9"]}))
    sel = _pusher(domain_tier="high").select(db, "domain", "high")
    assert sel.values == ["own-host.example.io", "second-host.example.io"]
    assert sel.protected_count == 2 and sel.unresolved_count == 1
    assert sel.unchecked_count == 0
    # Held-back names are not "withheld at cap": they are counted apart.
    assert sel.total == 2 and sel.withheld == []
    assert [v for v, _ in sel.protected] == ["on-cdn.example.io", "also-cdn.example.io"]


def test_domain_selection_honours_never_block_on_resolved_addresses(db, monkeypatch):
    # The operator's veto holds however the block would arrive: a listed
    # domain resolving to a never-block address must not reach the gateway.
    _domains(db, ["points-at-office.example.io", "own-host.example.io"])
    db.add_never_block("7.7.7.0/24", "ip", reason="office")
    monkeypatch.setitem(pu.resolved_guard.__dict__, "_lookup", _lookups({
        "points-at-office.example.io": ["7.7.7.9"],
        "own-host.example.io": ["5.6.8.1"]}))
    sel = _pusher(domain_tier="high").select(db, "domain", "high")
    assert sel.values == ["own-host.example.io"]
    assert sel.protected == [("points-at-office.example.io",
                              "7.7.7.9: on the never-block list")]


def test_a_listed_domain_cannot_aim_the_gateway_at_the_lan(db, monkeypatch):
    # Whoever controls a listed domain controls its DNS. Pointed at a LAN
    # address or a public resolver, the gateway would block that instead.
    _domains(db, ["rebind.example.io", "dns-killer.example.io"])
    monkeypatch.setitem(pu.resolved_guard.__dict__, "_lookup", _lookups({
        "rebind.example.io": ["192.168.1.1"], "dns-killer.example.io": ["8.8.8.8"]}))
    sel = _pusher(domain_tier="high").select(db, "domain", "high")
    assert sel.values == [] and sel.protected_count == 2


def test_coverage_view_reads_the_cache_and_starts_no_lookups(db, monkeypatch):
    # The coverage endpoint is a GET: it reports what the last push
    # resolved and calls everything else unchecked.
    _domains(db, ["on-cdn.example.io", "own-host.example.io"])
    calls = []
    monkeypatch.setitem(pu.resolved_guard.__dict__, "_lookup", _lookups({
        "on-cdn.example.io": [EDGE_V4], "own-host.example.io": [PLAIN]}, calls))
    p = _pusher(domain_tier="high")
    cold = p.select(db, "domain", "high", resolve=False)
    assert cold.values == [] and cold.unchecked_count == 2 and calls == []
    p.select(db, "domain", "high")                       # a push resolves
    seen = len(calls)
    warm = p.select(db, "domain", "high", resolve=False)
    assert warm.values == ["own-host.example.io"] and warm.protected_count == 1
    assert len(calls) == seen


def test_ip_selection_does_no_lookups(db, monkeypatch):
    db.add_indicator("5.6.7.1", "f1", {})
    db.set_indicator_score("5.6.7.1", 0.9, "high")
    calls = []
    monkeypatch.setitem(pu.resolved_guard.__dict__, "_lookup", _lookups({}, calls))
    assert _pusher().select(db, "ip", "high").values == ["5.6.7.1"]
    assert calls == []


def test_cap_counts_only_names_that_pass(db, monkeypatch):
    # The cap is filled with names that can be enforced; a held-back name
    # must not take a slot from one that can.
    names = ["cdn-1.example.io", "host-1.example.io", "cdn-2.example.io",
             "host-2.example.io", "host-3.example.io"]
    _domains(db, names)
    table = {n: [EDGE_V4] if n.startswith("cdn") else [PLAIN] for n in names}
    monkeypatch.setitem(pu.resolved_guard.__dict__, "_lookup", _lookups(table))
    p = _pusher(domain_tier="high", max_entries=2)
    sel = p._select(db, "domain", "high", None)
    assert sel.values == ["host-1.example.io", "host-2.example.io"]
    assert sel.total == 3 and sel.withheld == ["host-3.example.io"]


def _configured_push(db, monkeypatch, session, **kw):
    monkeypatch.setenv(ENV_USER, "svc")
    monkeypatch.setenv(ENV_PASSWORD, "pw")
    monkeypatch.setattr(pu.UniFiPusher, "from_config",
                        classmethod(lambda cls, config, db=None: _pusher(session, **kw)))
    return pu.push_to_unifi(db, {"integrations": {"unifi": {
        "enabled": True, "host": "192.168.1.1"}}})


def test_push_writes_only_checked_domains_and_reports_the_rest(db, monkeypatch):
    _domains(db, ["on-cdn.example.io", "own-host.example.io", "dead.example.io"])
    monkeypatch.setitem(pu.resolved_guard.__dict__, "_lookup", _lookups({
        "on-cdn.example.io": [EDGE_V4], "own-host.example.io": [PLAIN]}))
    session = FakeSession()
    summary = _configured_push(db, monkeypatch, session, domain_tier="high")
    lists = {g["name"]: g["group_members"] for g in session.groups.values()}
    assert lists["tfm-dom-high-1"] == ["own-host.example.io"]
    d = summary["domains"]
    assert d["entries"] == 1 and d["address_withheld"] == 1
    assert d["unresolved_withheld"] == 1 and "unchecked_withheld" not in d
    assert d["withheld"] == 0                      # nothing was cut at the cap


def test_a_domain_that_moves_behind_a_cdn_is_withdrawn(db, monkeypatch):
    _domains(db, ["mover.example.io"])
    table = {"mover.example.io": [PLAIN]}
    monkeypatch.setitem(pu.resolved_guard.__dict__, "_lookup", _lookups(table))
    session = FakeSession()
    _configured_push(db, monkeypatch, session, domain_tier="high")
    by_name = lambda: {g["name"]: g["group_members"] for g in session.groups.values()}
    assert by_name()["tfm-dom-high-1"] == ["mover.example.io"]
    table["mover.example.io"] = [EDGE_V4]
    pu.resolved_guard.clear_cache()               # as if the answer's TTL had passed
    _configured_push(db, monkeypatch, session, domain_tier="high")
    assert by_name()["tfm-dom-high-1"] == []


def test_switching_the_domain_arm_off_empties_its_lists(db, monkeypatch):
    # Off used to mean "stop visiting": the last list stayed on the gateway,
    # enforced, and the only way out was the gateway's own UI.
    db.add_indicator("5.6.7.1", "f1", {})
    db.set_indicator_score("5.6.7.1", 0.9, "high")
    session = FakeSession(groups=[
        {"_id": "d1", "name": "tfm-dom-high-1", "group_type": "domain-group",
         "group_members": ["old-a.example.io", "old-b.example.io"]},
        {"_id": "d2", "name": "tfm-dom-medium-1", "group_type": "domain-group",
         "group_members": ["old-c.example.io"]},
        {"_id": "d3", "name": "someone-elses-list", "group_type": "domain-group",
         "group_members": ["keep.example.io"]},
        {"_id": "a1", "name": "tfm-dom-looking-address-group", "group_type": "address-group",
         "group_members": ["5.6.7.200"]},
    ])
    summary = _configured_push(db, monkeypatch, session, domain_tier="")
    assert session.groups["d1"]["group_members"] == []
    assert session.groups["d2"]["group_members"] == []
    assert session.groups["d3"]["group_members"] == ["keep.example.io"]
    assert summary["domains_withdrawn"] == 2 and "domains" not in summary
    assert "domain_error" not in summary
    # Idempotent: nothing left to empty, nothing written, nothing reported.
    writes_before = sum(1 for c in session.calls if c[0] == "PUT")
    again = _configured_push(db, monkeypatch, session, domain_tier="")
    assert "domains_withdrawn" not in again
    assert sum(1 for c in session.calls if c[0] == "PUT") == writes_before


def test_domain_arm_off_adds_no_gateway_calls_when_nothing_to_empty(db, monkeypatch):
    # Most installs never used the domain arm; they must not pay for it.
    db.add_indicator("5.6.7.1", "f1", {})
    db.set_indicator_score("5.6.7.1", 0.9, "high")
    session = FakeSession()
    _configured_push(db, monkeypatch, session, domain_tier="")
    gets = [c for c in session.calls if c[0] == "GET" and c[1].endswith("/rest/firewallgroup")]
    assert len(gets) == 1                          # the IP sync's own listing, reused


def test_a_failed_address_check_is_a_domain_error_not_a_failed_push(db, monkeypatch):
    db.add_indicator("5.6.7.1", "f1", {})
    db.set_indicator_score("5.6.7.1", 0.9, "high")
    _domains(db, ["own-host.example.io"])

    def broken(*a, **kw):
        raise RuntimeError("screen blew up")
    monkeypatch.setitem(pu.resolved_guard.__dict__, "screen", broken)
    session = FakeSession()
    summary = _configured_push(db, monkeypatch, session, domain_tier="high")
    assert summary["entries"] == 1                 # the IP arm still landed
    assert "screen blew up" in summary["domain_error"]
    assert not any(g["group_type"] == "domain-group" for g in session.groups.values())
