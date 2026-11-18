"""Shared CDN addresses never reach an IP list.

A feed that lists a CDN's shared proxy address is naming one site behind it;
blocking the address blocks every other site there. Measured 2026-11-16: 893
addresses inside one CDN's published ranges sat on an Everything IP list.
Those ranges are part of the IP safety floor, checked by overlap, and rows
stored before the floor existed are purged on the next refresh.

(The UniFi domain push this file also used to cover was retired; see
tests/test_unifi_domain_retired.py.)
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from threatfeedme.database import Database
from threatfeedme.safety import SHARED_EDGE, SafetyFilter

# One address inside the shipped shared-edge ranges, and one plain public
# address no floor covers.
EDGE_V4 = "104.16.0.1"
EDGE_V6 = "2606:4700::1"
PLAIN = "5.6.7.8"


@pytest.fixture
def db(tmp_path):
    return Database(str(tmp_path / "t.db"))


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


