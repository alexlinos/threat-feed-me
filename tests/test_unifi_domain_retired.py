"""The UniFi domain push is retired; what is left is cleaning up after it.

From 2.1 to 2.7.4 the push could also write a domain tier into a Domain-type
network list. A gateway enforces such a list by the addresses its names
resolve to, so one listed name on shared hosting blocked every other site on
that address: a code host (2.6.3), a CDN (2.7.3), a static-site host (the
day after 2.7.4). Each round added a guard; the premise was the fault.

Pinned here:

  * nothing a setting, an old config or an old browser tab can say makes the
    push write a domain again;
  * a list that arm left on a gateway is neutralised on the next push, with
    ONE reserved name, because a real gateway refuses an empty domain list
    (the 2.7.3 "off empties the list" only ever worked against a fake that
    accepted one);
  * that clean-up is idempotent, costs no gateway call when there is nothing
    to do, never touches the operator's own lists, and cannot fail the IP
    push or leak the gateway's address into the dashboard.
"""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from threatfeedme import pusher_unifi as pu
from threatfeedme.database import Database
from threatfeedme.pusher_unifi import (DOMAIN_PLACEHOLDER, ENV_PASSWORD, ENV_USER,
                                       UniFiPusher)

from test_unifi import FakeSession


@pytest.fixture(autouse=True)
def _gateway_login(monkeypatch):
    monkeypatch.setenv(ENV_USER, "svc")
    monkeypatch.setenv(ENV_PASSWORD, "pw")


def _group(gid, name, members, group_type="domain-group"):
    return {"_id": gid, "name": name, "group_type": group_type,
            "group_members": list(members)}


@pytest.fixture
def db(tmp_path):
    database = Database(str(tmp_path / "t.db"))
    database.add_indicator("203.0.113.9", "f1", {})
    database.set_indicator_score("203.0.113.9", 0.9, "high")
    for i, name in enumerate(("evil-a.example.io", "evil-b.example.io")):
        database.add_indicator(name, "f1", {}, kind="domain")
        database.set_indicator_score(name, 0.9 - i * 0.01, "high")
    return database


def _push(db, monkeypatch, session, settings=None):
    """A push through the real config path: from_config -> from_block."""
    monkeypatch.setenv(ENV_USER, "svc")
    monkeypatch.setenv(ENV_PASSWORD, "pw")
    monkeypatch.setattr(pu.requests, "Session", lambda: session)
    block = {"enabled": True, "host": "192.168.1.1", "group_prefix": "tfm"}
    block.update(settings or {})
    return pu.push_to_unifi(db, {"integrations": {"unifi": block}})


def _lists(session):
    return {g["name"]: g["group_members"] for g in session.groups.values()}


def _writes(session):
    return [c for c in session.calls if c[0] in ("POST", "PUT") and "firewallgroup" in c[1]]


# ---------------- the placeholder ----------------

def test_the_placeholder_can_never_resolve():
    # .invalid is reserved (RFC 6761): no resolver answers for it, so a list
    # holding only this name matches no address.
    assert DOMAIN_PLACEHOLDER.endswith(".invalid")
    from threatfeedme.domains import reserved_reason
    assert reserved_reason(DOMAIN_PLACEHOLDER)      # the app itself would never serve it


def test_the_fake_gateway_refuses_an_empty_domain_list_like_a_real_one():
    session = FakeSession(groups=[_group("d1", "tfm-dom-high-1", ["a.example.io"])])
    p = UniFiPusher(host="192.168.1.1", group_prefix="tfm", session=session)
    p.login()
    body = dict(session.groups["d1"], group_members=[])
    with pytest.raises(Exception):
        p._api("PUT", "/rest/firewallgroup/d1", json=body)
    assert session.groups["d1"]["group_members"] == ["a.example.io"]
    # An empty ADDRESS group is fine, as on hardware.
    session.groups["a1"] = _group("a1", "tfm-low-1", ["198.51.100.1"], "address-group")
    p._api("PUT", "/rest/firewallgroup/a1", json=dict(session.groups["a1"], group_members=[]))
    assert session.groups["a1"]["group_members"] == []


# ---------------- nothing pushes a domain ----------------

@pytest.mark.parametrize("settings", [
    {},
    {"domain_tier": "high"},
    {"domain_tier": "medium", "domain_check_resolver": "cloudflare"},
    {"domain_tier": "high", "domain_policy_id": "pol-dom"},
])
def test_no_setting_makes_the_push_write_a_domain(db, monkeypatch, settings):
    session = FakeSession()
    summary = _push(db, monkeypatch, session, settings)
    assert summary["entries"] == 1 and "domains" not in summary
    assert _lists(session) == {"tfm-high-1": ["203.0.113.9"]}
    assert all(g["group_type"] == "address-group" for g in session.groups.values())
    assert "domain_error" not in summary and "domains_withdrawn" not in summary


def test_the_pusher_has_no_domain_arm_left():
    p = UniFiPusher(host="192.168.1.1")
    for gone in ("domain_tier", "check_resolver", "domain_policy_id", "collect_domains"):
        assert not hasattr(p, gone)
    with pytest.raises(TypeError):
        UniFiPusher(host="192.168.1.1", domain_tier="high")
    # An old settings block that still names it builds a plain IP pusher.
    assert UniFiPusher.from_block({"host": "192.168.1.1", "domain_tier": "high",
                                   "domain_check_resolver": "google"}) is not None


def test_the_address_check_module_is_gone():
    # It made DNS lookups for every listed name; with the domain push retired
    # nothing in the app resolves an indicator.
    import importlib
    with pytest.raises(ImportError):
        importlib.import_module("threatfeedme.resolved_guard")


# ---------------- cleaning up a gateway that ran it ----------------

def test_a_leftover_domain_list_is_neutralised_on_the_next_push(db, monkeypatch):
    session = FakeSession(groups=[
        _group("d1", "tfm-dom-high-1", ["phish.example.io", "pages-site.example.io"]),
    ])
    summary = _push(db, monkeypatch, session, {"domain_tier": "high"})
    assert _lists(session)["tfm-dom-high-1"] == [DOMAIN_PLACEHOLDER]
    assert summary["domains_withdrawn"] == 1 and "domain_error" not in summary
    assert summary["entries"] == 1                       # the IP push is untouched
    # Still there, same id: the operator's policy keeps a valid reference.
    assert session.groups["d1"]["name"] == "tfm-dom-high-1"


def test_every_tier_and_shard_the_old_arm_wrote_is_cleared(db, monkeypatch):
    session = FakeSession(groups=[
        _group("d1", "tfm-dom-high-1", ["a.example.io"]),
        _group("d2", "tfm-dom-medium-1", ["b.example.io"]),
        _group("d3", "tfm-dom-medium-2", ["c.example.io"]),
        _group("d4", "tfm-dom-medium-3", [DOMAIN_PLACEHOLDER]),   # already neutral
    ])
    summary = _push(db, monkeypatch, session)
    lists = _lists(session)
    assert all(lists[name] == [DOMAIN_PLACEHOLDER] for name in lists if "-dom-" in name)
    assert summary["domains_withdrawn"] == 3


def test_clean_up_is_idempotent_and_free_when_there_is_nothing_to_do(db, monkeypatch):
    session = FakeSession(groups=[_group("d1", "tfm-dom-high-1", ["a.example.io"])])
    _push(db, monkeypatch, session)
    session.calls.clear()
    again = _push(db, monkeypatch, session)
    assert "domains_withdrawn" not in again and "domain_error" not in again
    assert _writes(session) == []                        # IP group unchanged, list already neutral
    assert len([c for c in session.calls if c[0] == "GET"]) == 1   # one listing, shared


def test_clean_up_leaves_other_peoples_lists_alone(db, monkeypatch):
    session = FakeSession(groups=[
        _group("o1", "my-own-domains", ["intranet.example.net"]),
        _group("o2", "other-dom-high-1", ["x.example.io"]),            # another prefix
        _group("o3", "tfm-dom-notes", ["198.51.100.7"], "address-group"),  # our name, not a domain list
    ])
    summary = _push(db, monkeypatch, session)
    lists = _lists(session)
    assert lists["my-own-domains"] == ["intranet.example.net"]
    assert lists["other-dom-high-1"] == ["x.example.io"]
    assert "domains_withdrawn" not in summary
    # The IP arm's stale-group rule still applies to an address group in its
    # own namespace, as before: emptied, which an address group allows.
    assert lists["tfm-dom-notes"] == []


def test_a_failed_clean_up_does_not_fail_the_ip_push_or_name_the_gateway(db, monkeypatch):
    session = FakeSession(groups=[_group("d1", "tfm-dom-high-1", ["a.example.io"])])
    real = session.request

    def refuse_domain_writes(method, url, headers=None, timeout=None, json=None):
        if method == "PUT" and (json or {}).get("group_type") == "domain-group":
            raise RuntimeError(f"400 Client Error for url: {url}")
        return real(method, url, headers=headers, timeout=timeout, json=json)
    session.request = refuse_domain_writes
    summary = _push(db, monkeypatch, session)
    assert summary["entries"] == 1
    assert summary["domain_error"] == "could not clear the retired domain lists on the gateway"
    # The dashboard shows this text: no URL, no gateway address.
    assert "192.168.1.1" not in json.dumps(summary["domain_error"])
    assert json.loads(db.get_setting(pu.LAST_PUSH_KEY))["error"] is None


def test_withdraw_without_a_prior_listing_reads_the_gateway_itself():
    session = FakeSession(groups=[_group("d1", "tfm-dom-high-1", ["a.example.io"])])
    p = UniFiPusher(host="192.168.1.1", group_prefix="tfm", session=session)
    p.login()
    assert p.withdraw("domain-group", "dom-") == 1
    assert session.groups["d1"]["group_members"] == [DOMAIN_PLACEHOLDER]
    assert p.withdraw("domain-group", "dom-") == 0


def test_stale_detection_never_empties_a_domain_list(monkeypatch):
    # sync()'s stale rule empties groups of its own type that the current
    # tier no longer uses. Asked about domain groups, it must write the
    # placeholder too, or it would send the request a gateway refuses.
    session = FakeSession(groups=[_group("d1", "tfm-dom-high-1", ["a.example.io"])])
    p = UniFiPusher(host="192.168.1.1", group_prefix="tfm", session=session, tier="high")
    p.login()
    p.sync(["b.example.io"], label="dom-medium", group_type="domain-group")
    assert session.groups["d1"]["group_members"] == [DOMAIN_PLACEHOLDER]
