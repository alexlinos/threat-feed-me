"""Safety-filter hardening (v2.4.19): supernets, the prefix floor, and the
retroactive sweep. The filter's promise is that a poisoned upstream can never
make a firewall block its own network — these pin the gaps review found."""
import pytest

from threatfeedme.database import Database
from threatfeedme.safety import SafetyFilter


@pytest.fixture
def f():
    return SafetyFilter()


@pytest.mark.parametrize("cidr", [
    "10.0.0.0/7",      # half RFC1918, half public: is_private was False
    "172.16.0.0/11",   # contains all of 172.16.0.0/12
    "192.168.0.0/15",  # contains all of 192.168.0.0/16
    "127.0.0.0/7",     # loopback supernet
    "169.254.0.0/15",  # link-local supernet
    "100.64.0.0/9",    # CGNAT supernet
    "224.0.0.0/3",     # multicast + reserved
    "0.0.0.0/1",       # half the internet, includes "this network"
])
def test_supernets_touching_special_space_are_refused(f, cidr):
    assert f.excluded_reason(cidr), cidr


def test_wide_public_netblock_hits_the_prefix_floor(f):
    # an eighth of IPv4 that touches no private space — still an outage
    reason = f.excluded_reason("64.0.0.0/3")
    assert reason and "too wide" in reason


def test_real_wide_netblocks_still_pass(f):
    # the widest legitimate entries measured on the live corpus are /12
    # (Spamhaus DROP hijacked blocks); the default floor must keep them
    assert f.excluded_reason("42.128.0.0/12") is None
    assert f.excluded_reason("45.95.168.0/22") is None
    assert f.excluded_reason("185.220.101.7") is None


def test_prefix_floor_is_configurable_and_can_be_disabled():
    strict = SafetyFilter.from_config({"safety": {"min_prefix_ipv4": 16}})
    assert strict.excluded_reason("42.128.0.0/12")
    off = SafetyFilter.from_config({"safety": {"min_prefix_ipv4": 0}})
    assert off.excluded_reason("64.0.0.0/3") is None
    # disabling the floor must not disable the special-space check
    assert off.excluded_reason("10.0.0.0/7")


def test_ipv6_special_space(f):
    assert f.excluded_reason("::ffff:10.0.0.1")     # v4-mapped private
    assert f.excluded_reason("fd00::/8")            # unique-local
    assert f.excluded_reason("64:ff9b::1")          # NAT64
    assert f.excluded_reason("2001:db8::/32")       # documentation
    assert f.excluded_reason("2a00:1450:4001::/48") is None


def test_stored_value_reason_uses_the_served_cidr(f):
    # the store keeps only the network address; the CIDR is what's served
    assert f.stored_value_reason("10.0.0.0", "ip", cidr="10.0.0.0/7")
    assert f.stored_value_reason("42.128.0.0", "ip", cidr="42.128.0.0/12") is None
    assert f.stored_value_reason("185.220.101.7", "ip") is None


def test_stored_value_reason_domains():
    f = SafetyFilter(known_good_domains=["acme-internal.com"])
    assert f.stored_value_reason("mail.acme-internal.com", "domain")
    assert f.stored_value_reason("updates.microsoft.com", "domain")
    assert f.stored_value_reason("evil-login.top", "domain") is None


def test_sweep_removes_rows_the_filter_now_refuses(tmp_path):
    db = Database(str(tmp_path / "t.db"))
    # rows stored before the fix (the old filter let this supernet through)
    db.add_indicators_bulk([("10.0.0.0", {"cidr": "10.0.0.0/7"}),
                            ("42.128.0.0", {"cidr": "42.128.0.0/12"}),
                            ("185.220.101.7", {})], source="poisoned")
    db.add_indicators_bulk([("mail.acme-internal.com", {}),
                            ("evil-login.top", {})], source="dom", kind="domain")
    safety = SafetyFilter(known_good_domains=["acme-internal.com"])

    removed = db.purge_unsafe_indicators(safety, chunk=1)

    assert sum(removed.values()) == 2
    assert db.get_indicator("10.0.0.0") is None
    assert db.get_indicator("mail.acme-internal.com") is None
    for keep in ("42.128.0.0", "185.220.101.7", "evil-login.top"):
        assert db.get_indicator(keep) is not None, keep
    # FK cascade cleared the swept rows' attribution
    with db._cursor() as cur:
        n = cur.execute("SELECT COUNT(*) FROM indicator_sources").fetchone()[0]
    assert n == 3


def test_sweep_is_a_noop_on_a_clean_store(tmp_path):
    db = Database(str(tmp_path / "t.db"))
    db.add_indicators_bulk([("185.220.101.7", {})], source="x")
    assert db.purge_unsafe_indicators(SafetyFilter()) == {}
