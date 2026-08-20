"""
Focused tests for the threat feed aggregator, covering the parsing, scoring,
CIDR-overlap, whitelist, and export behavior most prone to regressions.
"""
import csv
import json
import os
import sqlite3
import sys
from datetime import datetime, timezone, timedelta

import pytest
import requests

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from threatfeedme.database import Database
from threatfeedme.exporter import firewall_value, is_included
from threatfeedme.pipeline import _export_tier
from threatfeedme import pipeline
from threatfeedme.feed_ingestor import FeedIngestor
from threatfeedme.models import (ConfidenceTier, FeedSource, FeedType, ThreatIndicator, ALL_FEEDS,
                    REASON_FALSE_POSITIVE, REASON_RISK_ACCEPTED)
from threatfeedme.scorer import ConfidenceScorer, fp_penalty_factor


CONFIG = {
    "feeds": [
        {"name": "custom_honeypot", "weight": 0.7},
        {"name": "spamhaus_drop", "weight": 0.95},
        {"name": "abuse_ch_malware", "weight": 0.9},
    ],
    "scoring": {
        # These tests exercise the fixed-threshold math; the effective-votes
        # engine has its own section (see "effective-votes tiering" below).
        "tiering": {"method": "legacy"},
        "source_weight": 0.45,
        "reputation_weight": 0.33,
        "recency_weight": 0.22,
        "decay_half_life_hours": 72,
        "high_confidence": {"min_sources": 3, "min_score": 0.75},
        "medium_confidence": {"min_sources": 2, "min_score": 0.5},
    },
}


@pytest.fixture
def db(tmp_path):
    return Database(str(tmp_path / "test.db"))


# ---------------------------------------------------------------- parsing ----

def test_parser_preserves_real_cidr(db, tmp_path):
    """CIDR blocks keep their true prefix instead of a guessed /24."""
    feed_file = tmp_path / "netblocks.txt"
    feed_file.write_text("# comment\n192.168.0.0/16\n10.0.0.5\n")
    feed = FeedSource(
        name="spamhaus_drop", url=str(feed_file), feed_type=FeedType.SPAM,
        weight=0.95, update_interval=3600, local_file=True,
    )
    entries = FeedIngestor(db).fetch_feed(feed)
    by_ip = {e["ip"]: e for e in entries}
    assert by_ip["192.168.0.0"]["cidr"] == "192.168.0.0/16"
    assert by_ip["10.0.0.5"]["cidr"] is None


# --------------------------------------------------------------- scoring ----

def test_weights_are_normalized():
    """Even non-normalized configured weights sum to 1.0 at runtime."""
    scorer = ConfidenceScorer(None, {"scoring": {
        "source_weight": 4, "reputation_weight": 3, "recency_weight": 3}})
    assert pytest.approx(sum(scorer.weights.values()), abs=1e-9) == 1.0


def test_reputation_weight_comes_from_config():
    scorer = ConfidenceScorer(None, CONFIG)
    assert scorer.source_weights["custom_honeypot"] == 0.7
    assert scorer.source_weights["spamhaus_drop"] == 0.95


def test_ip_over_cidr_overlap_uses_real_prefix(db):
    """An IP inside a stored /16 gains the reporting feed via exact match."""
    db.add_indicator("172.16.0.0", "spamhaus_drop", {"cidr": "172.16.0.0/16"})
    db.add_indicator("172.16.5.5", "custom_honeypot", {})

    scorer = ConfidenceScorer(db, CONFIG)
    netblocks = scorer._load_netblock_sources()
    assert "spamhaus_drop" in scorer._netblock_sources_for("172.16.5.5", netblocks)
    # An address outside the block must not match.
    assert scorer._netblock_sources_for("192.0.2.1", netblocks) == set()


def test_netblock_overlap_credits_any_feed(db):
    """CIDR-overlap corroboration is not Spamhaus-specific: an IP inside a
    netblock reported by any feed gains that feed as a source."""
    db.add_indicator("203.0.113.0", "emerging_threats_block", {"cidr": "203.0.113.0/24"})
    db.add_indicator("203.0.113.77", "custom_honeypot", {})
    ConfidenceScorer(db, CONFIG).recalculate_all_scores()
    # Second source via the /24 -> promoted to medium.
    assert db.get_indicator("203.0.113.77").tier == ConfidenceTier.MEDIUM


def test_require_threat_intel_gates_high_tier():
    """With require_threat_intel on, custom/manual-only corroboration tops out
    at medium; one curated external feed among the sources unlocks high."""
    cfg = {
        "feeds": [
            {"name": "hp1", "weight": 0.9, "feed_type": "custom"},
            {"name": "hp2", "weight": 0.9, "feed_type": "custom"},
            {"name": "hp3", "weight": 0.9, "feed_type": "custom"},
            {"name": "et", "weight": 0.9, "feed_type": "threat_intel"},
        ],
        "scoring": {
            **CONFIG["scoring"],
            "high_confidence": {"min_sources": 3, "min_score": 0.75,
                                "require_threat_intel": True},
        },
    }
    scorer = ConfidenceScorer(None, cfg)
    assert scorer._determine_tier(0.9, 3, ["hp1", "hp2", "hp3"]) == ConfidenceTier.MEDIUM
    assert scorer._determine_tier(0.9, 3, ["hp1", "hp2", "et"]) == ConfidenceTier.HIGH
    # 'manual' and unknown sources never satisfy the gate.
    assert scorer._determine_tier(0.9, 3, ["hp1", "hp2", "manual"]) == ConfidenceTier.MEDIUM
    # Gate off (or absent) -> old behavior.
    scorer_off = ConfidenceScorer(None, CONFIG)
    assert scorer_off._determine_tier(0.9, 3, ["hp1", "hp2", "hp3"]) == ConfidenceTier.HIGH


def test_recalculate_persists_scores(db):
    db.add_indicator("203.0.113.7", "abuse_ch_malware", {})
    count = ConfidenceScorer(db, CONFIG).recalculate_all_scores()
    assert count == 1
    assert db.get_indicator("203.0.113.7").confidence_score > 0


# ------------------------------------------------------------- whitelist ----

def test_whitelist_excludes_and_expires(db):
    db.add_indicator("198.51.100.1", "abuse_ch_malware", {})
    db.add_to_whitelist("198.51.100.1", "false positive", "alex")
    assert "198.51.100.1" in db.get_whitelisted_ips()

    # An already-expired entry is not returned.
    db.add_to_whitelist(
        "198.51.100.2", "temp", "alex",
        expires_at=datetime.now(timezone.utc) - timedelta(hours=1),
    )
    assert "198.51.100.2" not in db.get_whitelisted_ips()


def test_per_feed_whitelist_reduces_but_keeps(db):
    """Whitelisting one feed drops that source but keeps the IP if others report it."""
    db.add_indicator("203.0.113.9", "cins_army", {})
    db.add_indicator("203.0.113.9", "custom_honeypot", {})
    ConfidenceScorer(db, CONFIG).recalculate_all_scores()
    assert db.get_indicator("203.0.113.9").tier == ConfidenceTier.MEDIUM

    db.add_to_whitelist("203.0.113.9", "noisy", "alex", feed_name="cins_army")
    ConfidenceScorer(db, CONFIG).recalculate_all_scores()
    assert db.get_indicator("203.0.113.9").tier == ConfidenceTier.LOW
    # Only cins is globally whitelisted-scoped, so the IP is NOT globally excluded.
    assert "203.0.113.9" not in db.get_whitelisted_ips()
    assert is_included(db.get_indicator("203.0.113.9"), db.get_whitelist_map())


def test_cidr_whitelist_suppresses_contained_ip(db):
    """A GLOBAL CIDR whitelist excludes every IP it contains, but nothing outside."""
    inside = ThreatIndicator(
        ip="10.1.2.3", sources=["cins_army"],
        first_seen=datetime.now(timezone.utc), last_seen=datetime.now(timezone.utc),
        confidence_score=0.5, tier=ConfidenceTier.LOW, metadata={},
    )
    outside = ThreatIndicator(
        ip="11.0.0.1", sources=["cins_army"],
        first_seen=datetime.now(timezone.utc), last_seen=datetime.now(timezone.utc),
        confidence_score=0.5, tier=ConfidenceTier.LOW, metadata={},
    )
    db.add_to_whitelist("10.0.0.0/8", "internal range", "alex", feed_name=ALL_FEEDS)
    wl_map = db.get_whitelist_map()

    from threatfeedme.models import effective_sources
    assert effective_sources("10.1.2.3", ["cins_army"], wl_map) is None
    assert not is_included(inside, wl_map)
    # An address outside the CIDR is untouched.
    assert effective_sources("11.0.0.1", ["cins_army"], wl_map) == ["cins_army"]
    assert is_included(outside, wl_map)


def test_per_feed_cidr_whitelist_scope(db):
    """A CIDR scoped to one feed removes only that feed from a contained IP."""
    db.add_to_whitelist("45.66.0.0/16", "noisy for cins", "alex", feed_name="cins_army")
    wl_map = db.get_whitelist_map()

    from threatfeedme.models import effective_sources
    surviving = effective_sources("45.66.230.5", ["cins_army", "custom_honeypot"], wl_map)
    assert surviving == ["custom_honeypot"]  # cins removed, other feed survives
    # An IP outside the /16 keeps every source.
    assert effective_sources("45.67.0.1", ["cins_army", "custom_honeypot"], wl_map) == \
        ["cins_army", "custom_honeypot"]


def test_host_whitelist_entry_stays_exact_only(db):
    """A bare host / explicit /32 must not act as a containing CIDR rule."""
    db.add_to_whitelist("10.0.0.5", "one host", "alex", feed_name=ALL_FEEDS)
    wl_map = db.get_whitelist_map()
    # A /32 produces no CIDR rule, so a neighbor is not swept up.
    from threatfeedme.models import effective_sources
    assert effective_sources("10.0.0.5", ["cins_army"], wl_map) is None
    assert effective_sources("10.0.0.6", ["cins_army"], wl_map) == ["cins_army"]


def test_whitelist_matcher_behaves_as_dict(db):
    """WhitelistMatcher must still support .get(ip) and == comparison."""
    db.add_to_whitelist("203.0.113.9", "a", "alex", feed_name="cins_army")
    wl_map = db.get_whitelist_map()
    assert wl_map.get("203.0.113.9") == {"cins_army"}
    assert wl_map.get("no.such.ip") is None


def test_query_indicators_excludes_cidr_whitelisted(db):
    """An IP inside a globally-whitelisted CIDR is dropped from the rows."""
    db.add_indicator("45.66.230.5", "cins_army", {})
    db.add_indicator("45.67.0.1", "cins_army", {})
    db.add_to_whitelist("45.66.0.0/16", "internal", "alex", feed_name=ALL_FEEDS)
    ips = [r["ip"] for r in db.query_indicators()["rows"]]
    assert "45.66.230.5" not in ips  # contained by the whitelisted CIDR
    assert "45.67.0.1" in ips        # outside the CIDR, still listed


def test_global_whitelist_excludes_everywhere(db):
    db.add_indicator("203.0.113.9", "cins_army", {})
    db.add_to_whitelist("203.0.113.9", "ours", "alex", feed_name=ALL_FEEDS)
    assert "203.0.113.9" in db.get_whitelisted_ips()
    assert not is_included(db.get_indicator("203.0.113.9"), db.get_whitelist_map())


def test_remove_specific_scope(db):
    db.add_indicator("203.0.113.9", "cins_army", {})
    db.add_to_whitelist("203.0.113.9", "a", "alex", feed_name="cins_army")
    db.add_to_whitelist("203.0.113.9", "b", "alex", feed_name=ALL_FEEDS)
    db.remove_from_whitelist("203.0.113.9", feed_name=ALL_FEEDS)
    scopes = db.get_whitelist_map().get("203.0.113.9")
    assert scopes == {"cins_army"}  # only the global scope was removed


def test_feed_source_crud(db):
    db.add_feed(FeedSource(name="f1", url="http://x/y.txt", feed_type=FeedType.MALWARE, weight=0.8))
    assert db.get_feed_source("f1").weight == 0.8
    assert "f1" in [f.name for f in db.get_feed_sources()]

    db.set_feed_enabled("f1", False)
    assert db.get_feed_source("f1").enabled is False
    assert "f1" not in [f.name for f in db.get_feed_sources(enabled_only=True)]

    assert db.remove_feed("f1") is True
    assert db.get_feed_source("f1") is None


def test_seed_feeds_is_idempotent(db):
    cfg = {"feeds": [{"name": "s1", "url": "http://a/b.txt", "weight": 0.9, "feed_type": "malware"}]}
    assert db.seed_feeds_from_config(cfg) == 1
    assert db.seed_feeds_from_config(cfg) == 0  # already seeded -> no-op


def test_settings_roundtrip(db):
    assert db.get_setting("k", "default") == "default"
    db.set_setting("k", "v")
    assert db.get_setting("k") == "v"


def test_default_install_seeds_clean_feed_set(db):
    """Out-of-the-box contract: the shipped config.yaml seeds the free keyless
    feeds enabled, and the ones needing setup (keys/URLs/sample data) disabled,
    so a fresh install is all-green with no configuration."""
    import yaml
    cfg_path = os.path.join(os.path.dirname(__file__), "..", "config.yaml")
    cfg = yaml.safe_load(open(cfg_path, encoding="utf-8"))
    db.seed_feeds_from_config(cfg)

    enabled = {f.name for f in db.get_feed_sources(enabled_only=True)}
    disabled = {f.name for f in db.get_feed_sources() if not f.enabled}

    # These must be live and keyless on a fresh install.
    for name in ["emerging_threats_compromised", "emerging_threats_block",
                 "cins_army", "blocklist_de", "bbcan177",
                 "talos_snort", "dshield_block", "spamhaus_drop", "greensnow",
                 "dataplane_sshpwauth", "bruteforceblocker", "turris_greylist",
                 "binarydefense", "threatfox_mirror", "abuseipdb_s100_3d"]:
        assert name in enabled, f"{name} should be enabled out of the box"

    # These require setup and must ship disabled (no error rows out of box).
    for name in ["alienVault_otx", "custom_honeypot",
                 "honeydb_bad_hosts", "honeydb_mydata"]:
        assert name in disabled, f"{name} should be disabled by default"
    # PhishTank was removed: it publishes phishing URLs, not attacker IPs, so
    # it must not reappear in the seed lineup.
    assert "phishTank" not in enabled | disabled
    # Feodo and SSLBL were removed 2026-08 (abuse.ch key-walled the legacy
    # text exports and they froze); they must not reappear either.
    assert "abuse_ch_feodo" not in enabled | disabled
    assert "abuse_ch_sslbl" not in enabled | disabled


def test_restore_default_feeds_merges_without_clobber(db):
    cfg = {"feeds": [
        {"name": "a", "url": "http://a/x.txt", "weight": 0.9},
        {"name": "b", "url": "http://b/x.txt", "weight": 0.8},
    ]}
    db.seed_feeds_from_config(cfg)
    # User removes one and customizes the other.
    db.remove_feed("a")
    db.add_feed(FeedSource(name="b", url="http://b/custom.txt", weight=0.5))
    added = db.restore_default_feeds(cfg)
    assert added == ["a"]  # only the missing default came back
    assert db.get_feed_source("b").url == "http://b/custom.txt"  # customization kept


# ------------------------------------------------- default-feed upgrade sync ----

def test_sync_adds_new_defaults_and_preserves_user_data(db):
    """App update: a new default feed appears in the shipped config. Sync adds
    it to an existing DB without touching indicators, whitelist, or scores —
    updating must never require wiping the database."""
    v1 = {"feeds": [{"name": "a", "url": "http://a/x.txt"}]}
    db.seed_feeds_from_config(v1)
    db.add_indicator("203.0.113.5", "a", {"cidr": "203.0.113.0/24"})
    db.add_to_whitelist("198.51.100.9", "mail relay", "alex")

    v2 = {"feeds": [{"name": "a", "url": "http://a/x.txt"},
                    {"name": "new_default", "url": "http://n/y.txt"}]}
    actions = db.sync_default_feeds(v2)
    assert actions["added"] == ["new_default"]
    assert actions["updated"] == []
    # Accumulated state survives (the multi-day rolling DShield case).
    assert db.get_indicator("203.0.113.5") is not None
    assert "198.51.100.9" in db.get_whitelisted_ips()


def test_sync_updates_untouched_default(db):
    """A default the user never customized follows shipped changes (e.g. the
    upstream URL moved)."""
    db.seed_feeds_from_config({"feeds": [{"name": "a", "url": "http://a/old.txt"}]})
    actions = db.sync_default_feeds({"feeds": [{"name": "a", "url": "http://a/new.txt"}]})
    assert actions["updated"] == ["a"]
    assert db.get_feed_source("a").url == "http://a/new.txt"
    # Idempotent: a second sync with the same config changes nothing.
    again = db.sync_default_feeds({"feeds": [{"name": "a", "url": "http://a/new.txt"}]})
    assert again["updated"] == [] and again["added"] == []


def test_sync_never_clobbers_customized_feed(db):
    """A dashboard add/override (the only way an operator can change a feed's
    URL) nulls seed_fingerprint and exempts the row from plumbing sync —
    deliberate URL overrides are never clobbered."""
    db.seed_feeds_from_config({"feeds": [{"name": "a", "url": "http://a/x.txt"}]})
    db.add_feed(FeedSource(name="a", url="http://a/mine.txt", weight=0.4))
    actions = db.sync_default_feeds({"feeds": [{"name": "a", "url": "http://a/moved.txt"}]})
    assert actions["updated"] == []
    feed = db.get_feed_source("a")
    assert feed.url == "http://a/mine.txt" and feed.weight == 0.4


def test_sync_enabled_toggle_counts_as_customization(db):
    """Preferences are never synced: a disabled toggle sticks across updates,
    and a shipped update_interval change does not apply to existing rows."""
    db.seed_feeds_from_config({"feeds": [{"name": "a", "url": "http://a/x.txt"}]})
    db.set_feed_enabled("a", False)
    db.sync_default_feeds({"feeds": [{"name": "a", "url": "http://a/x.txt",
                                      "update_interval": 60}]})
    feed = db.get_feed_source("a")
    assert feed.enabled is False and feed.update_interval == 3600


def test_sync_respects_deletion_tombstones(db):
    """A default the operator deleted stays deleted across updates; only the
    explicit restore-defaults action (or re-adding) brings it back."""
    db.seed_feeds_from_config({"feeds": [{"name": "a", "url": "http://a/x.txt"}]})
    db.remove_feed("a")
    actions = db.sync_default_feeds({"feeds": [{"name": "a", "url": "http://a/x.txt"}]})
    assert actions["skipped_deleted"] == ["a"] and db.get_feed_source("a") is None
    # Explicit restore clears the tombstone...
    assert db.restore_default_feeds({"feeds": [{"name": "a", "url": "http://a/x.txt"}]}) == ["a"]
    # ...so subsequent syncs treat it as a live default again.
    assert db.sync_default_feeds(
        {"feeds": [{"name": "a", "url": "http://a/x.txt"}]})["skipped_deleted"] == []


# ------------------------------------------------------- feed telemetry ----

ECHO_SIZE = 30  # comfortably over telemetry.MIN_REDUNDANT_SIZE


def _telemetry_db(db):
    """Three feeds: 'solo' reports uniquely, 'echo_a'/'echo_b' report exactly
    the same IPs as each other (the aggregator-of-aggregators case)."""
    for name in ("solo", "echo_a", "echo_b"):
        db.add_feed(FeedSource(name=name, url=f"http://{name}/x.txt",
                               feed_type=FeedType.THREAT_INTEL, weight=1.0))
    db.add_indicator("203.0.113.1", "solo", {})
    db.add_indicator("203.0.113.2", "solo", {})
    db.add_indicator("203.0.113.3", "solo", {})
    for i in range(ECHO_SIZE):
        ip = f"198.51.100.{i}"
        db.add_indicator(ip, "echo_a", {})
        db.add_indicator(ip, "echo_b", {})
    return db


def test_exclusive_counts_identify_unique_contribution(db):
    _telemetry_db(db)
    excl = db.get_feed_exclusive_counts()
    assert excl.get("solo") == 3          # nothing else reports these
    assert excl.get("echo_a", 0) == 0     # every IP is corroborated by echo_b
    assert excl.get("echo_b", 0) == 0


def test_overlap_detects_redundant_feed_pairs(db):
    from threatfeedme.telemetry import feed_telemetry
    _telemetry_db(db)
    t = feed_telemetry(db)
    pairs = {(p["a"], p["b"]): p["n"] for p in t["overlap"]}
    assert pairs.get(("echo_a", "echo_b")) == ECHO_SIZE
    # solo shares nothing, so it must not appear in any pair.
    assert not any("solo" in (p["a"], p["b"]) for p in t["overlap"])
    # ...and the redundancy callout flags the echo pair at 100%.
    assert [(p["a"], p["b"], p["pct"]) for p in t["redundant_pairs"]] == \
        [("echo_a", "echo_b", 100)]


def test_has_overlap_true_when_feeds_share_indicators(db):
    """The overlap map should render only when some pair actually shares
    indicators — a grid full of zeros is noise."""
    from threatfeedme.telemetry import feed_telemetry
    _telemetry_db(db)   # echo_a/echo_b share ECHO_SIZE IPs
    assert feed_telemetry(db)["has_overlap"] is True


def test_has_overlap_false_when_no_indicators_shared(db):
    """Two feeds that report disjoint sets must not render the overlap map."""
    from threatfeedme.telemetry import feed_telemetry
    db.add_feed(FeedSource(name="a", url="http://a/x.txt",
                           feed_type=FeedType.THREAT_INTEL, weight=1.0))
    db.add_feed(FeedSource(name="b", url="http://b/x.txt",
                           feed_type=FeedType.THREAT_INTEL, weight=1.0))
    db.add_indicator("203.0.113.1", "a", {})
    db.add_indicator("203.0.113.2", "a", {})
    db.add_indicator("203.0.113.3", "b", {})
    db.add_indicator("203.0.113.4", "b", {})
    assert feed_telemetry(db)["has_overlap"] is False


def test_twin_is_recorded_on_the_smaller_feed(db):
    """Containment is directional: if a small feed sits inside a big one, the
    small feed is the redundant one — the chip belongs on it, not on the big
    feed that still carries plenty of its own."""
    from threatfeedme.telemetry import feed_telemetry, MIN_REDUNDANT_SIZE
    for name in ("big", "small"):
        db.add_feed(FeedSource(name=name, url=f"http://{name}/x.txt",
                               feed_type=FeedType.THREAT_INTEL, weight=1.0))
    shared = [f"203.0.113.{i}" for i in range(MIN_REDUNDANT_SIZE + 5)]
    for ip in shared:
        db.add_indicator(ip, "big", {})
        db.add_indicator(ip, "small", {})
    for i in range(200):  # 'big' has plenty the small feed lacks
        db.add_indicator(f"198.51.{i // 256}.{i % 256}", "big", {})

    rows = {r["name"]: r for r in feed_telemetry(db)["rows"]}
    assert rows["small"]["twin"]["name"] == "big"
    assert rows["small"]["twin"]["pct"] == 100
    assert rows["big"]["twin"] is None


def test_tiny_feeds_are_not_flagged_redundant(db):
    """A feed with a handful of indicators is trivially 'contained' in a big
    one; flagging it would bury the real redundancies (abuse.ch Feodo's
    recommended list is routinely a single IP)."""
    from threatfeedme.telemetry import feed_telemetry
    for name in ("big", "tiny"):
        db.add_feed(FeedSource(name=name, url=f"http://{name}/x.txt",
                               feed_type=FeedType.THREAT_INTEL, weight=1.0))
    db.add_indicator("203.0.113.9", "big", {})
    db.add_indicator("203.0.113.9", "tiny", {})   # 100% of tiny, but tiny is 1
    for i in range(100):
        db.add_indicator(f"198.51.{i // 256}.{i % 256}", "big", {})

    t = feed_telemetry(db)
    assert t["redundant_pairs"] == []
    assert {r["name"]: r["twin"] for r in t["rows"]}["tiny"] is None


def test_first_report_window_excludes_older_indicators(db):
    """A feed added recently must not be credited for indicators that predate
    it — the window keeps 'first to report' fair across install dates."""
    _telemetry_db(db)
    with db._cursor() as cur:  # age everything solo reported
        cur.execute("UPDATE indicator_sources SET reported_at = '2020-01-01T00:00:00+00:00' "
                    "WHERE source_name = 'solo'")
    recent = db.get_feed_first_report_counts(since="2026-01-01T00:00:00+00:00")
    assert recent.get("solo", 0) == 0
    assert db.get_feed_first_report_counts().get("solo") == 3  # all-time still counts them


def test_telemetry_rows_rank_by_exclusive_contribution(db):
    from threatfeedme.telemetry import feed_telemetry
    _telemetry_db(db)
    rows = feed_telemetry(db)["rows"]
    assert rows[0]["name"] == "solo"
    assert rows[0]["exclusive"] == 3 and rows[0]["exclusive_pct"] == 100
    echo = next(r for r in rows if r["name"] == "echo_a")
    assert echo["exclusive"] == 0 and echo["exclusive_pct"] == 0


def test_telemetry_health_flags_stale_and_failed_feeds(db):
    from threatfeedme.telemetry import feed_telemetry
    _telemetry_db(db)
    db.update_feed_stats("solo", 3, "success")
    db.update_feed_stats("echo_a", 0, "error", error_message="boom")
    _set_last_update(db, "echo_b", "2020-01-01T00:00:00+00:00")
    db.update_feed_stats("echo_b", 2, "success")
    _set_last_update(db, "echo_b", "2020-01-01T00:00:00+00:00")

    health = {r["name"]: r["health"] for r in feed_telemetry(db)["rows"]}
    assert health["echo_a"]["state"] == "error"
    assert health["echo_b"]["state"] == "stale"
    assert health["solo"]["state"] in ("ok", "no new")  # ran now, freshness varies


def test_purge_orphaned_feedback_self_heals_stale_penalties(db):
    """FP attributions must not outlive the whitelist entry that justified
    them. Rows stranded by the old tier-scoped-removal bug are cleared at
    startup; live ones (entry still present) are kept."""
    db.add_indicator("203.0.113.31", "cins_army", {})
    db.add_indicator("203.0.113.32", "cins_army", {})
    # One with a surviving whitelist entry, one orphaned.
    db.add_to_whitelist("203.0.113.31", "fp", "alex")
    db.record_false_positive("203.0.113.31", ["cins_army"])
    db.record_false_positive("203.0.113.32", ["cins_army"])
    assert db.get_feed_fp_counts()["cins_army"] == 2

    assert db.purge_orphaned_feedback() == 1
    assert db.get_feed_fp_counts()["cins_army"] == 1
    entries = db.get_feed_false_positives("cins_army")
    assert [e["ip"] for e in entries] == ["203.0.113.31"]
    assert entries[0]["whitelisted"] is True
    # Idempotent.
    assert db.purge_orphaned_feedback() == 0


def test_clear_feed_feedback_restores_reputation(db):
    from threatfeedme.scorer import ConfidenceScorer, DEFAULT_SOURCE_WEIGHT
    for i in range(10):
        db.add_indicator(f"7.7.7.{i}", "cins_army", {})
    db.record_false_positive("7.7.7.0", ["cins_army"])
    db.record_false_positive("7.7.7.1", ["cins_army"])
    assert ConfidenceScorer(db, CONFIG).source_weights["cins_army"] < DEFAULT_SOURCE_WEIGHT

    assert db.clear_feed_feedback("cins_army") == 2
    assert db.get_feed_fp_counts() == {}
    scorer = ConfidenceScorer(db, CONFIG)
    assert scorer.source_weights.get("cins_army", DEFAULT_SOURCE_WEIGHT) == DEFAULT_SOURCE_WEIGHT


def test_sync_treats_pre_upgrade_rows_as_customized(db):
    """Rows from databases that predate fingerprints (NULL) are never
    auto-updated — conservative default for unknown provenance."""
    db.seed_feeds_from_config({"feeds": [{"name": "a", "url": "http://a/x.txt"}]})
    with db._cursor() as cur:
        cur.execute("UPDATE feeds SET seed_fingerprint = NULL WHERE name = 'a'")
    actions = db.sync_default_feeds({"feeds": [{"name": "a", "url": "http://a/moved.txt"}]})
    assert actions["updated"] == []
    assert db.get_feed_source("a").url == "http://a/x.txt"


def test_query_indicators_search_and_paginate(db):
    for i in range(5):
        db.add_indicator(f"10.0.0.{i}", "cins_army", {})
    db.add_indicator("8.8.8.8", "cins_army", {})
    res = db.query_indicators(q="10.0.0", limit=2, offset=0)
    assert res["total"] == 5 and len(res["rows"]) == 2
    assert all(r["ip"].startswith("10.0.0") for r in res["rows"])


def test_query_indicators_excludes_globally_whitelisted(db):
    db.add_indicator("9.9.9.9", "cins_army", {})
    db.add_to_whitelist("9.9.9.9", "removed", "alex")  # global by default
    ips = [r["ip"] for r in db.query_indicators()["rows"]]
    assert "9.9.9.9" not in ips


def test_query_indicators_total_matches_rows_under_global_cidr(db):
    """A global CIDR whitelist subtracts its hidden IPs from `total` too."""
    for i in range(4):
        db.add_indicator(f"203.0.113.{i}", "cins_army", {})   # hidden by CIDR
    for i in range(3):
        db.add_indicator(f"198.51.100.{i}", "cins_army", {})  # visible
    db.add_to_whitelist("203.0.113.0/24", "internal", "alex", feed_name=ALL_FEEDS)

    res = db.query_indicators(limit=100)
    assert res["total"] == 3 == len(res["rows"])
    ips = {r["ip"] for r in res["rows"]}
    assert ips == {"198.51.100.0", "198.51.100.1", "198.51.100.2"}


def test_query_indicators_pagination_under_global_cidr(db):
    """Pages stay full, non-overlapping, and complete when a CIDR hides rows."""
    for i in range(10):
        db.add_indicator(f"203.0.113.{i}", "cins_army", {})   # hidden by CIDR
    for i in range(5):
        db.add_indicator(f"198.51.100.{i}", "cins_army", {})  # 5 survivors
    db.add_to_whitelist("203.0.113.0/24", "internal", "alex", feed_name=ALL_FEEDS)

    p1 = db.query_indicators(limit=2, offset=0)
    p2 = db.query_indicators(limit=2, offset=2)
    p3 = db.query_indicators(limit=2, offset=4)
    assert p1["total"] == p2["total"] == p3["total"] == 5
    assert len(p1["rows"]) == 2 and len(p2["rows"]) == 2  # no short pages
    assert len(p3["rows"]) == 1                            # last, partial page
    seen = [r["ip"] for r in p1["rows"] + p2["rows"] + p3["rows"]]
    assert len(seen) == len(set(seen))  # no overlap between pages
    assert set(seen) == {f"198.51.100.{i}" for i in range(5)}


def test_query_indicators_exact_whitelist_total_stays_exact(db):
    """Fast path: an exact-only global whitelist is excluded in SQL, total exact."""
    for i in range(4):
        db.add_indicator(f"198.51.100.{i}", "cins_army", {})
    db.add_to_whitelist("198.51.100.0", "ours", "alex", feed_name=ALL_FEEDS)

    res = db.query_indicators(limit=100)
    assert res["total"] == 3 == len(res["rows"])
    assert "198.51.100.0" not in {r["ip"] for r in res["rows"]}


def test_query_indicators_include_whitelisted_shows_cidr_hidden(db):
    """include_whitelisted=True returns even the CIDR-hidden IPs."""
    for i in range(3):
        db.add_indicator(f"203.0.113.{i}", "cins_army", {})
    db.add_indicator("198.51.100.1", "cins_army", {})
    db.add_to_whitelist("203.0.113.0/24", "internal", "alex", feed_name=ALL_FEEDS)

    res = db.query_indicators(include_whitelisted=True, limit=100)
    assert res["total"] == 4 == len(res["rows"])
    assert "203.0.113.0" in {r["ip"] for r in res["rows"]}


def test_query_indicators_search_with_global_cidr(db):
    """`total` reflects both the q= filter and the CIDR whitelist together."""
    for i in range(4):
        db.add_indicator(f"203.0.113.{i}", "cins_army", {})   # match q, hidden
    for i in range(2):
        db.add_indicator(f"203.0.200.{i}", "cins_army", {})   # match q, visible
    db.add_indicator("8.8.8.8", "cins_army", {})              # no q match
    db.add_to_whitelist("203.0.113.0/24", "internal", "alex", feed_name=ALL_FEEDS)

    res = db.query_indicators(q="203.0", limit=100)
    assert res["total"] == 2 == len(res["rows"])
    assert {r["ip"] for r in res["rows"]} == {"203.0.200.0", "203.0.200.1"}


def test_query_indicators_per_feed_cidr_does_not_hide(db):
    """A CIDR whitelisted for only one feed must not hide rows from this view."""
    db.add_indicator("45.66.230.5", "cins_army", {})
    db.add_to_whitelist("45.66.0.0/16", "noisy for cins", "alex",
                        feed_name="cins_army")

    res = db.query_indicators(limit=100)
    assert res["total"] == 1 == len(res["rows"])
    assert res["rows"][0]["ip"] == "45.66.230.5"


def test_delete_indicator(db):
    db.add_indicator("7.7.7.7", "cins_army", {})
    assert db.delete_indicator("7.7.7.7") is True
    assert db.get_indicator("7.7.7.7") is None


# ------------------------------------------------------------- backups ----

def test_backup_creates_usable_snapshot(db, tmp_path):
    db.add_indicator("45.10.20.30", "cins_army", {})
    dest = str(tmp_path / "backups")
    path = db.backup_database(dest, keep=7)
    assert os.path.exists(path)
    # The snapshot is a real SQLite DB with the data.
    snap = Database(path)
    assert snap.get_indicator("45.10.20.30") is not None


def test_backup_prunes_to_keep(db, tmp_path):
    dest = tmp_path / "backups"
    dest.mkdir()
    # Pre-seed 5 fake, timestamp-named backups; keep=2 should leave the newest 2.
    names = [f"threat_feeds-2026070{i}T000000Z.db" for i in range(1, 6)]
    for n in names:
        (dest / n).write_text("x")
    db._prune_backups(str(dest), keep=2)
    remaining = sorted(p.name for p in dest.iterdir())
    assert remaining == names[-2:]


# ------------------------------------------------ FP feedback → scoring ----

def test_fp_penalty_factor_math():
    assert fp_penalty_factor(0, 1000) == 1.0        # no FPs -> no penalty
    assert fp_penalty_factor(10, 1000) == pytest.approx(0.9)   # 1% -> 0.9
    assert fp_penalty_factor(50, 1000) == pytest.approx(0.5)   # 5% -> 0.5
    assert fp_penalty_factor(200, 1000) == 0.2      # 20% -> floored at 0.2
    assert fp_penalty_factor(5, 0) == 1.0           # unknown denominator -> safe


def test_false_positive_downweights_feed_reputation(db):
    # A feed reports 10 IPs; 2 get flagged as false positives -> 20% rate.
    for i in range(10):
        db.add_indicator(f"6.6.6.{i}", "cins_army", {})
    db.record_false_positive("6.6.6.0", ["cins_army"])
    db.record_false_positive("6.6.6.1", ["cins_army"])

    from threatfeedme.scorer import DEFAULT_SOURCE_WEIGHT
    penalized = ConfidenceScorer(db, CONFIG).source_weights["cins_army"]
    assert penalized < DEFAULT_SOURCE_WEIGHT
    assert db.get_feed_fp_counts()["cins_army"] == 2


def test_risk_accepted_does_not_penalize(db):
    # get_feed_fp_counts only counts recorded false positives; risk-accepted
    # whitelisting records no feedback, so the feed keeps its reputation.
    from threatfeedme.scorer import DEFAULT_SOURCE_WEIGHT
    db.add_indicator("6.6.6.9", "cins_army", {})
    # (No record_false_positive call for a risk-accepted decision.)
    assert db.get_feed_fp_counts() == {}
    # No penalty applied -> the source keeps the uniform default reputation.
    scorer = ConfidenceScorer(db, CONFIG)
    assert scorer.source_weights.get("cins_army", DEFAULT_SOURCE_WEIGHT) \
        == DEFAULT_SOURCE_WEIGHT


def test_clear_feedback_restores_reputation(db):
    db.add_indicator("6.6.6.5", "cins_army", {})
    db.record_false_positive("6.6.6.5", ["cins_army"])
    assert db.get_feed_fp_counts().get("cins_army") == 1
    db.clear_feedback("6.6.6.5")
    assert db.get_feed_fp_counts() == {}


def test_clear_feedback_scoped_preserves_other_feeds(db):
    """Clearing one feed's feedback for an IP must not wipe another feed's."""
    db.record_false_positive("6.6.6.7", ["feed_a", "feed_b"])
    assert db.get_feed_fp_counts() == {"feed_a": 1, "feed_b": 1}
    db.clear_feedback("6.6.6.7", feed_name="feed_a")
    counts = db.get_feed_fp_counts()
    assert "feed_a" not in counts
    assert counts.get("feed_b") == 1  # feed_b penalty preserved


# ------------------------------------------------- safety guardrails ----

def test_safety_filter_blocks_private_and_known_good():
    from threatfeedme.safety import SafetyFilter
    f = SafetyFilter(drop_private_reserved=True, protect_known_good=True)
    assert f.excluded_reason("10.0.0.1")           # RFC1918
    assert f.excluded_reason("192.168.1.1")        # RFC1918
    assert f.excluded_reason("172.16.5.5")         # RFC1918
    assert f.excluded_reason("127.0.0.1")          # loopback
    assert f.excluded_reason("169.254.1.1")        # link-local
    assert f.excluded_reason("100.64.1.1")         # CGNAT (not is_private on 3.11)
    assert f.excluded_reason("224.0.0.1")          # multicast
    assert "infrastructure" in f.excluded_reason("8.8.8.8")   # known-good
    assert f.excluded_reason("1.1.1.1")            # known-good
    assert f.excluded_reason("8.8.8.0/24")         # CIDR containing known-good
    assert f.excluded_reason("45.77.88.99") is None  # ordinary global IP passes


def test_safety_filter_toggles_off():
    from threatfeedme.safety import SafetyFilter
    f = SafetyFilter(drop_private_reserved=False, protect_known_good=False)
    assert f.excluded_reason("10.0.0.1") is None
    assert f.excluded_reason("8.8.8.8") is None


def test_ingest_applies_safety_filter(db, tmp_path):
    from threatfeedme.feed_ingestor import FeedIngestor
    from threatfeedme.safety import SafetyFilter
    feed_file = tmp_path / "mixed.txt"
    feed_file.write_text("10.0.0.1\n8.8.8.8\n192.168.0.0/16\n45.77.88.99\n")
    feed = FeedSource(name="mixed", url=str(feed_file), feed_type=FeedType.CUSTOM,
                      weight=0.6, local_file=True)
    ing = FeedIngestor(db, safety=SafetyFilter())
    stored = ing.ingest_feed(feed)
    assert stored == 1  # only the ordinary global IP survives
    assert db.get_indicator("45.77.88.99") is not None
    assert db.get_indicator("10.0.0.1") is None
    assert db.get_indicator("8.8.8.8") is None


def test_pipeline_refresh_local_feed(db, tmp_path):
    """End-to-end refresh over a local-file feed: ingest -> score -> export."""
    from threatfeedme import pipeline
    feed_file = tmp_path / "ips.txt"
    feed_file.write_text("# comment\n5.5.5.5\n6.6.6.6\n")
    db.add_feed(FeedSource(name="local_test", url=str(feed_file),
                           feed_type=FeedType.CUSTOM, weight=0.6, local_file=True))

    cfg = {"scoring": CONFIG["scoring"],
           "output": {"base_dir": str(tmp_path / "out"), "formats": ["text"]}}
    results = pipeline.run_refresh(db, cfg)

    assert results["local_test"]["status"] == "success"
    assert db.get_indicator("5.5.5.5") is not None
    assert (tmp_path / "out" / "low_confidence_ips.text").exists()


def test_legacy_whitelist_is_migrated(tmp_path):
    """A pre-scope whitelist table is upgraded, entries become global (ALL_FEEDS)."""
    dbp = str(tmp_path / "legacy.db")
    conn = sqlite3.connect(dbp)
    conn.executescript(
        "CREATE TABLE whitelist (id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT UNIQUE NOT NULL,"
        " reason TEXT NOT NULL, added_by TEXT NOT NULL, added_at TEXT NOT NULL, expires_at TEXT);"
        " INSERT INTO whitelist (ip, reason, added_by, added_at)"
        " VALUES ('10.0.0.1','legacy','bob','2026-01-01T00:00:00');"
    )
    conn.commit()
    conn.close()

    db = Database(dbp)  # runs migration on open
    entries = db.get_whitelist()
    assert len(entries) == 1
    assert entries[0].ip == "10.0.0.1"
    assert entries[0].feed_name == ALL_FEEDS

    # Re-opening (a second process/init) must not crash or double-migrate.
    db2 = Database(dbp)
    assert len(db2.get_whitelist()) == 1


def test_legacy_db_gets_reported_at_migration(tmp_path):
    """A database whose indicator_sources predates reported_at gains the
    column on open, so ingest and the telemetry queries work against it.

    Defensive: every released version has shipped reported_at in the CREATE
    TABLE (since v1.0.0), so no real upgrade path hits this. It guards
    hand-built or hand-repaired databases and keeps the migration block
    uniform with the other additive column adds.
    """
    dbp = str(tmp_path / "legacy.db")
    conn = sqlite3.connect(dbp)
    conn.executescript(
        "CREATE TABLE indicators (id INTEGER PRIMARY KEY AUTOINCREMENT,"
        " ip TEXT UNIQUE NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,"
        " confidence_score REAL DEFAULT 0.0, tier TEXT DEFAULT 'low', metadata TEXT DEFAULT '{}');"
        " CREATE TABLE indicator_sources (id INTEGER PRIMARY KEY AUTOINCREMENT,"
        " indicator_id INTEGER NOT NULL, source_name TEXT NOT NULL,"
        " UNIQUE(indicator_id, source_name));"
    )
    conn.execute("INSERT INTO indicators (ip, first_seen, last_seen) VALUES ('203.0.113.1','2026-01-01','2026-01-01')")
    conn.commit()
    conn.close()

    db = Database(dbp)  # must ALTER TABLE to add reported_at

    # The ingest path that fills reported_at must work on the migrated table.
    db.add_indicator("203.0.113.2", "talos_snort", {})

    # Telemetry queries must work against the migrated column.
    # The pre-existing row has NULL reported_at, so it is excluded from the
    # freshness window (NULL >= ? is false); only the newly-ingested one counts.
    new = db.get_feed_new_counts("2026-01-01T00:00:00+00:00")
    assert new.get("talos_snort", 0) == 1

    # Re-opening (a second process/init) must not crash or double-migrate.
    db2 = Database(dbp)
    db2.add_indicator("203.0.113.3", "talos_snort", {})
    assert db2.get_feed_new_counts("2026-01-01T00:00:00+00:00").get("talos_snort", 0) == 2


# ---------------------------------------------------------------- export ----

def test_csv_export_quotes_multiple_sources(db, tmp_path):
    """Multi-source rows must not spill into extra CSV columns."""
    db.add_indicator("192.0.2.50", "abuse_ch_malware", {})
    db.add_indicator("192.0.2.50", "custom_honeypot", {})
    ConfidenceScorer(db, CONFIG).recalculate_all_scores()

    path = _export_tier(db, ConfidenceTier.LOW, str(tmp_path / "out"), "csv")
    with open(path, newline="") as f:
        rows = list(csv.reader(f))
    header, *data = rows
    assert len(header) == 6
    # Every data row has exactly the same column count as the header.
    assert all(len(r) == 6 for r in data)


def test_json_export_reports_actual_tier(db, tmp_path):
    db.add_indicator("192.0.2.60", "abuse_ch_malware", {})
    ConfidenceScorer(db, CONFIG).recalculate_all_scores()
    path = _export_tier(db, ConfidenceTier.LOW, str(tmp_path / "out"), "json")
    data = json.loads(open(path).read())
    assert data["tier"] == "low"


# ------------------------------------------------------- firewall values ----

def _indicator(ip, meta):
    now = datetime.now(timezone.utc)
    return ThreatIndicator(
        ip=ip, sources=["spamhaus_drop"], first_seen=now, last_seen=now,
        confidence_score=0.5, tier=ConfidenceTier.LOW, metadata=meta,
    )


def test_firewall_value_prefers_cidr():
    """A netblock must be blocked as its CIDR, not the bare network address."""
    assert firewall_value(_indicator("45.66.230.0", {"cidr": "45.66.230.0/24"})) == "45.66.230.0/24"
    assert firewall_value(_indicator("203.0.113.7", {})) == "203.0.113.7"


def test_text_export_emits_cidr(db, tmp_path):
    db.add_indicator("45.66.230.0", "spamhaus_drop", {"cidr": "45.66.230.0/24"})
    ConfidenceScorer(db, CONFIG).recalculate_all_scores()
    path = _export_tier(db, ConfidenceTier.LOW, str(tmp_path / "out"), "text")
    lines = open(path).read().split()
    assert "45.66.230.0/24" in lines
    assert "45.66.230.0" not in lines  # bare network address must not appear


# --------------------------------------------------- feed removal / purge ----

def _set_last_seen(db, ip, iso):
    """Test helper: force an indicator's last_seen to a fixed ISO timestamp."""
    conn = sqlite3.connect(db.db_path)
    try:
        conn.execute("UPDATE indicators SET last_seen = ? WHERE ip = ?", (iso, ip))
        conn.commit()
    finally:
        conn.close()


def test_remove_feed_purges_orphaned_indicator(db):
    # An IP reported ONLY by the removed feed is deleted.
    db.add_feed(FeedSource(name="custom_honeypot", url="x", feed_type=FeedType.CUSTOM,
                           weight=0.7, update_interval=3600, local_file=True))
    db.add_indicator("203.0.113.50", "custom_honeypot", {})
    assert db.remove_feed("custom_honeypot") is True
    assert db.get_indicator("203.0.113.50") is None


def test_remove_feed_keeps_multi_source_indicator(db):
    # An IP also reported by another feed survives, minus the removed source.
    db.add_feed(FeedSource(name="custom_honeypot", url="x", feed_type=FeedType.CUSTOM,
                           weight=0.7, update_interval=3600, local_file=True))
    db.add_indicator("203.0.113.51", "custom_honeypot", {})
    db.add_indicator("203.0.113.51", "spamhaus_drop", {})
    assert db.remove_feed("custom_honeypot") is True
    surviving = db.get_indicator("203.0.113.51")
    assert surviving is not None
    assert "custom_honeypot" not in surviving.sources
    assert "spamhaus_drop" in surviving.sources
    # The orphaned source attribution is gone from the reporting counts.
    assert "custom_honeypot" not in db.get_feed_report_counts()


def test_remove_feed_clears_feed_feedback(db):
    db.add_indicator("203.0.113.52", "custom_honeypot", {})
    db.record_false_positive("203.0.113.52", ["custom_honeypot"])
    assert db.get_feed_fp_counts().get("custom_honeypot", 0) == 1
    db.remove_feed("custom_honeypot")
    assert db.get_feed_fp_counts().get("custom_honeypot", 0) == 0


def test_remove_feed_missing_returns_false(db):
    assert db.remove_feed("never_existed") is False


def test_purge_stale_indicators_deletes_old_keeps_recent(db):
    db.add_indicator("203.0.113.60", "spamhaus_drop", {})  # old
    db.add_indicator("203.0.113.61", "spamhaus_drop", {})  # recent (now)
    old_iso = (datetime.now(timezone.utc) - timedelta(days=90)).isoformat()
    _set_last_seen(db, "203.0.113.60", old_iso)

    deleted = db.purge_stale_indicators(30)
    assert deleted == 1
    assert db.get_indicator("203.0.113.60") is None
    assert db.get_indicator("203.0.113.61") is not None


def test_purge_stale_indicators_disabled_when_zero(db):
    db.add_indicator("203.0.113.62", "spamhaus_drop", {})
    old_iso = (datetime.now(timezone.utc) - timedelta(days=90)).isoformat()
    _set_last_seen(db, "203.0.113.62", old_iso)
    assert db.purge_stale_indicators(0) == 0
    assert db.get_indicator("203.0.113.62") is not None


def test_purge_stale_indicators_keeps_whitelisted(db):
    # A stale but operator-whitelisted IP must survive purge when the
    # whitelist map is passed; a stale non-whitelisted one is still purged.
    db.add_indicator("203.0.113.63", "spamhaus_drop", {})
    db.add_indicator("203.0.113.64", "spamhaus_drop", {})
    old_iso = (datetime.now(timezone.utc) - timedelta(days=90)).isoformat()
    _set_last_seen(db, "203.0.113.63", old_iso)
    _set_last_seen(db, "203.0.113.64", old_iso)
    db.add_to_whitelist("203.0.113.63", "ours", "alex")

    deleted = db.purge_stale_indicators(30, db.get_whitelist_map())
    assert deleted == 1
    assert db.get_indicator("203.0.113.63") is not None  # whitelisted: kept
    assert db.get_indicator("203.0.113.64") is None       # not whitelisted: purged


def test_purge_stale_indicators_keeps_feed_scoped_whitelist(db):
    # A feed-scoped whitelist entry also protects the IP's row from purge.
    db.add_indicator("203.0.113.65", "spamhaus_drop", {})
    old_iso = (datetime.now(timezone.utc) - timedelta(days=90)).isoformat()
    _set_last_seen(db, "203.0.113.65", old_iso)
    db.add_to_whitelist("203.0.113.65", "noisy", "alex", feed_name="spamhaus_drop")
    db.purge_stale_indicators(30, db.get_whitelist_map())
    assert db.get_indicator("203.0.113.65") is not None


def test_prune_sightings_drops_old_keeps_recent(db):
    # The churn log is ring-pruned so it can't grow without bound.
    old = (datetime.now(timezone.utc) - timedelta(days=40)).isoformat()
    recent = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    db.append_sightings("spamhaus_drop", {"203.0.113.70": True}, old)
    db.append_sightings("spamhaus_drop", {"203.0.113.70": True}, recent)
    assert db.prune_sightings(30) == 1
    conn = sqlite3.connect(db.db_path)
    try:
        ticks = [r[0] for r in conn.execute("SELECT tick FROM sightings").fetchall()]
    finally:
        conn.close()
    assert ticks == [recent]


def test_prune_sightings_disabled_when_zero(db):
    old = (datetime.now(timezone.utc) - timedelta(days=40)).isoformat()
    db.append_sightings("spamhaus_drop", {"203.0.113.71": True}, old)
    assert db.prune_sightings(0) == 0


def test_detect_leaves_left_and_returned(db):
    # A present throughout; B left-then-returned; C left. left=[C], returned=[B],
    # and A (continuously present) must be in neither.
    now = datetime.now(timezone.utc)
    t1 = (now - timedelta(days=3)).isoformat()
    t2 = (now - timedelta(days=2)).isoformat()
    t3 = (now - timedelta(days=1)).isoformat()
    db.append_sightings("S", {"A": True, "B": True, "C": True}, t1)
    db.append_sightings("S", {"A": True, "C": True}, t2)          # B absent
    db.append_sightings("S", {"A": True, "B": True}, t3)          # B back, C absent
    r = db.detect_leaves("S", 30)
    assert sorted(r["left"]) == ["C"]
    assert sorted(r["returned"]) == ["B"]
    assert "A" not in r["left"] and "A" not in r["returned"]


def test_detect_leaves_single_snapshot_has_no_churn(db):
    t1 = datetime.now(timezone.utc).isoformat()
    db.append_sightings("S", {"A": True, "B": True}, t1)
    r = db.detect_leaves("S", 30)
    assert r["left"] == [] and r["returned"] == []


def test_detect_leaves_first_appearance_is_not_a_return(db):
    # An ip newly seen (absent earlier only because it hadn't appeared yet) is
    # not a return, and being in the latest snapshot it hasn't left.
    now = datetime.now(timezone.utc)
    t1 = (now - timedelta(days=3)).isoformat()
    t2 = (now - timedelta(days=2)).isoformat()
    db.append_sightings("S", {"A": True}, t1)
    db.append_sightings("S", {"A": True, "X": True}, t2)
    r = db.detect_leaves("S", 30)
    assert "X" not in r["returned"]
    assert "X" not in r["left"]


def test_detect_leaves_return_outside_window_excluded(db):
    # B leaves and returns, but the return is older than the window.
    now = datetime.now(timezone.utc)
    t1 = (now - timedelta(days=60)).isoformat()
    t2 = (now - timedelta(days=55)).isoformat()
    t3 = (now - timedelta(days=50)).isoformat()
    db.append_sightings("S", {"A": True, "B": True}, t1)
    db.append_sightings("S", {"A": True}, t2)                     # B absent
    db.append_sightings("S", {"A": True, "B": True}, t3)          # B back, but 50d ago
    r = db.detect_leaves("S", 30)
    assert "B" not in r["returned"]        # return is outside the 30d window
    assert r["left"] == []                  # B present at latest snapshot


def test_corpus_change_key_moves_on_add_and_fp(db):
    k0 = db.corpus_change_key()
    db.add_indicator("203.0.113.90", "cins_army", {})
    k1 = db.corpus_change_key()
    assert k1 != k0                         # indicator + source attribution added
    db.record_false_positive("203.0.113.90", ["cins_army"])
    k2 = db.corpus_change_key()
    assert k2 != k1                         # feed_feedback row added


def test_run_refresh_skips_rescore_when_unchanged(db, monkeypatch):
    # A no-op refresh (nothing changed since the last rescore) must not run the
    # full recalculate/export.
    monkeypatch.setattr(pipeline, "fetch_feeds", lambda *a, **k: {})
    monkeypatch.setattr(pipeline, "export_tiers", lambda *a, **k: {})
    calls = []
    monkeypatch.setattr(pipeline, "recalculate", lambda *a, **k: calls.append(1) or 0)
    db.add_indicator("203.0.113.91", "spamhaus_drop", {})
    pipeline.run_refresh(db, CONFIG)        # change vs stored(None) -> rescore
    pipeline.run_refresh(db, CONFIG)        # nothing changed -> skip
    assert calls == [1]


def test_run_refresh_rescores_after_fp_between_refreshes(db, monkeypatch):
    # An FP flagged BETWEEN refreshes (it only re-exports in the app) must still
    # force the next refresh to rescore — the whole reason the key is compared
    # against the last-rescore value, not this refresh's start.
    monkeypatch.setattr(pipeline, "fetch_feeds", lambda *a, **k: {})
    monkeypatch.setattr(pipeline, "export_tiers", lambda *a, **k: {})
    calls = []
    monkeypatch.setattr(pipeline, "recalculate", lambda *a, **k: calls.append(1) or 0)
    db.add_indicator("203.0.113.92", "cins_army", {})
    pipeline.run_refresh(db, CONFIG)        # rescore #1
    pipeline.run_refresh(db, CONFIG)        # skip (unchanged)
    assert len(calls) == 1
    db.record_false_positive("203.0.113.92", ["cins_army"])
    pipeline.run_refresh(db, CONFIG)        # feed_feedback changed -> rescore #2
    assert len(calls) == 2


def test_purge_keeps_old_manual_indicator(db):
    # An operator-curated manual entry must survive retention even when stale.
    db.add_indicator("203.0.113.70", "manual", {})
    old_iso = (datetime.now(timezone.utc) - timedelta(days=90)).isoformat()
    _set_last_seen(db, "203.0.113.70", old_iso)

    assert db.purge_stale_indicators(30) == 0
    assert db.get_indicator("203.0.113.70") is not None


def test_purge_deletes_old_feed_indicator_but_keeps_manual(db):
    # Side-by-side: same old last_seen, only the feed-sourced one is purged.
    db.add_indicator("203.0.113.71", "spamhaus_drop", {})  # feed source -> purged
    db.add_indicator("203.0.113.72", "manual", {})         # manual -> exempt
    old_iso = (datetime.now(timezone.utc) - timedelta(days=90)).isoformat()
    _set_last_seen(db, "203.0.113.71", old_iso)
    _set_last_seen(db, "203.0.113.72", old_iso)

    assert db.purge_stale_indicators(30) == 1
    assert db.get_indicator("203.0.113.71") is None
    assert db.get_indicator("203.0.113.72") is not None


def test_purge_keeps_manual_even_with_additional_feed_source(db):
    # An IP reported by a feed AND curated manually keeps the manual exemption.
    db.add_indicator("203.0.113.73", "spamhaus_drop", {})
    db.add_indicator("203.0.113.73", "manual", {})
    old_iso = (datetime.now(timezone.utc) - timedelta(days=90)).isoformat()
    _set_last_seen(db, "203.0.113.73", old_iso)

    assert db.purge_stale_indicators(30) == 0
    assert db.get_indicator("203.0.113.73") is not None


def test_purge_stale_indicators_deletes_beyond_retention_days(db):
    """An indicator older than max_age_days is purged even with an empty
    whitelist map (no whitelisted IPs to protect)."""
    db.add_indicator("203.0.113.77", "spamhaus_drop", {})
    old_iso = (datetime.now(timezone.utc) - timedelta(days=15)).isoformat()
    _set_last_seen(db, "203.0.113.77", old_iso)
    wl_map = db.get_whitelist_map()
    deleted = db.purge_stale_indicators(14, whitelist_map=wl_map)
    assert deleted == 1
    assert db.get_indicator("203.0.113.77") is None


def test_purge_stale_indicators_keeps_whitelisted_indicator(db):
    """A whitelisted indicator must survive retention eviction even when its
    last_seen is far older than the retention window."""
    db.add_indicator("203.0.113.77", "spamhaus_drop", {})
    db.add_to_whitelist("203.0.113.77", "internal host", "admin")
    db.add_indicator("203.0.113.78", "spamhaus_drop", {})  # NOT whitelisted
    old_iso = (datetime.now(timezone.utc) - timedelta(days=15)).isoformat()
    _set_last_seen(db, "203.0.113.77", old_iso)
    _set_last_seen(db, "203.0.113.78", old_iso)
    wl_map = db.get_whitelist_map()
    deleted = db.purge_stale_indicators(14, whitelist_map=wl_map)
    assert deleted == 1, "only the non-whitelisted indicator should be purged"
    assert db.get_indicator("203.0.113.77") is not None, "whitelisted IP survives"
    assert db.get_indicator("203.0.113.78") is None, "non-whitelisted IP is gone"


# ------------------------------------------ per-feed scheduler due-check ----

def _set_last_update(db, feed_name, iso):
    """Test helper: force a feed_stats row's last_update to a fixed ISO time."""
    conn = sqlite3.connect(db.db_path)
    try:
        conn.execute("UPDATE feed_stats SET last_update = ? WHERE feed_name = ?",
                     (iso, feed_name))
        conn.commit()
    finally:
        conn.close()


def test_due_feeds_never_fetched_is_due(db):
    from threatfeedme import pipeline
    db.add_feed(FeedSource(name="cins_army", url="http://x/y.txt", weight=0.85,
                           update_interval=3600))
    # No feed_stats row yet -> due regardless of interval.
    assert pipeline.due_feeds(db, default_interval_seconds=3600) == ["cins_army"]


def test_due_feeds_old_last_update_is_due(db):
    from threatfeedme import pipeline
    db.add_feed(FeedSource(name="emerging_threats_compromised", url="http://x/y.txt",
                           weight=0.9, update_interval=43200))  # 12h cadence
    db.update_feed_stats("emerging_threats_compromised", 5, "success")
    # Last update 13h ago > 12h interval -> due.
    old = (datetime.now(timezone.utc) - timedelta(hours=13)).isoformat()
    _set_last_update(db, "emerging_threats_compromised", old)
    assert "emerging_threats_compromised" in pipeline.due_feeds(db, 3600)


def test_due_feeds_recently_updated_not_due(db):
    from threatfeedme import pipeline
    db.add_feed(FeedSource(name="emerging_threats_compromised", url="http://x/y.txt",
                           weight=0.9, update_interval=43200))  # 12h cadence
    db.update_feed_stats("emerging_threats_compromised", 5, "success")
    # Updated 1h ago, well within the 12h interval -> NOT due.
    recent = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    _set_last_update(db, "emerging_threats_compromised", recent)
    assert pipeline.due_feeds(db, 3600) == []


def test_due_feeds_zero_interval_uses_default(db):
    from threatfeedme import pipeline
    db.add_feed(FeedSource(name="custom_honeypot", url="http://x/y.txt", weight=0.7,
                           update_interval=0))  # falls back to default
    db.update_feed_stats("custom_honeypot", 1, "success")
    # 30 min since update. With a 60-min default it's NOT due...
    updated = (datetime.now(timezone.utc) - timedelta(minutes=30)).isoformat()
    _set_last_update(db, "custom_honeypot", updated)
    assert pipeline.due_feeds(db, default_interval_seconds=3600) == []
    # ...but with a 10-min default the same age IS due.
    assert pipeline.due_feeds(db, default_interval_seconds=600) == ["custom_honeypot"]


def test_due_feeds_ignores_disabled_feeds(db):
    from threatfeedme import pipeline
    db.add_feed(FeedSource(name="cins_army", url="http://x/y.txt", weight=0.85,
                           update_interval=3600, enabled=False))
    # Disabled feed is never returned even though it has never been fetched.
    assert pipeline.due_feeds(db, 3600) == []


def test_due_feeds_unparseable_last_update_is_due(db):
    from threatfeedme import pipeline
    db.add_feed(FeedSource(name="cins_army", url="http://x/y.txt", weight=0.85,
                           update_interval=43200))
    db.update_feed_stats("cins_army", 5, "success")
    _set_last_update(db, "cins_army", "not-a-timestamp")
    assert pipeline.due_feeds(db, 3600) == ["cins_army"]


# ---------------------------------------- conditional GET / retry-backoff ----

class _FakeResponse:
    """Minimal stand-in for requests.Response (status, headers, body)."""

    def __init__(self, status_code=200, headers=None, text=""):
        self.status_code = status_code
        self.headers = headers or {}
        self.text = text
        self.encoding = "utf-8"

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.exceptions.HTTPError(f"HTTP {self.status_code}")

    def close(self):
        pass

    def iter_content(self, chunk_size=65536, decode_unicode=False):
        """Yield the body as a single chunk so callers using streaming work."""
        if self.text:
            yield self.text.encode(self.encoding or "utf-8")


def _http_feed(name="http_feed"):
    return FeedSource(name=name, url="http://feeds.example/list.txt",
                      feed_type=FeedType.CUSTOM, weight=0.6, update_interval=3600)


def _stub_get(monkeypatch, responses):
    """Script requests.get with a fixed response sequence; an Exception item
    is raised instead of returned. Returns the recorded calls (url, headers)."""
    calls = []
    seq = iter(responses)

    def fake_get(url, headers=None, timeout=None, **kwargs):
        calls.append({"url": url, "headers": dict(headers or {})})
        item = next(seq)
        if isinstance(item, Exception):
            raise item
        return item

    monkeypatch.setattr("threatfeedme.feed_ingestor.requests.get", fake_get)
    return calls


def _stub_sleep(monkeypatch):
    """Capture retry-backoff delays instead of actually sleeping."""
    delays = []
    monkeypatch.setattr("threatfeedme.feed_ingestor._sleep", delays.append)
    return delays


def test_200_validators_stored_and_sent_on_next_fetch(db, monkeypatch):
    calls = _stub_get(monkeypatch, [
        _FakeResponse(200, {"ETag": '"v1"',
                            "Last-Modified": "Mon, 01 Jun 2026 00:00:00 GMT"},
                      "1.2.3.4\n"),
        _FakeResponse(200, {"ETag": '"v2"'}, "1.2.3.4\n"),
    ])
    feed = _http_feed()
    ing = FeedIngestor(db)

    assert ing.ingest_feed(feed) == 1
    # First request is unconditional (nothing stored yet).
    assert "If-None-Match" not in calls[0]["headers"]
    assert "If-Modified-Since" not in calls[0]["headers"]
    assert db.get_feed_http_cache(feed.name) == \
        ('"v1"', "Mon, 01 Jun 2026 00:00:00 GMT")

    ing.ingest_feed(feed)
    # Second request offers the stored validators.
    assert calls[1]["headers"]["If-None-Match"] == '"v1"'
    assert calls[1]["headers"]["If-Modified-Since"] == "Mon, 01 Jun 2026 00:00:00 GMT"
    # The second 200 carried only an ETag -> Last-Modified is cleared.
    assert db.get_feed_http_cache(feed.name) == ('"v2"', None)


def test_304_skips_ingest_and_survives_retention(db, monkeypatch):
    _stub_get(monkeypatch, [
        _FakeResponse(200, {"ETag": '"v1"'}, "1.2.3.4\n5.6.7.8\n"),
        _FakeResponse(304),
    ])
    feed = _http_feed()
    ing = FeedIngestor(db)
    assert ing.ingest_feed(feed) == 2

    # Age the indicators past retention, then refetch: the 304 must bump
    # last_seen so the purge that runs right after fetching keeps them.
    old_iso = (datetime.now(timezone.utc) - timedelta(days=90)).isoformat()
    _set_last_seen(db, "1.2.3.4", old_iso)
    _set_last_seen(db, "5.6.7.8", old_iso)

    assert ing.ingest_feed(feed) == 2  # previous count carried forward, not 0

    stats = {s.feed_name: s for s in db.get_feed_stats()}
    assert stats[feed.name].status == "success"
    assert stats[feed.name].total_indicators == 2
    # Stored validators survive the 304 (not clobbered).
    assert db.get_feed_http_cache(feed.name) == ('"v1"', None)

    assert db.purge_stale_indicators(30) == 0
    assert db.get_indicator("1.2.3.4") is not None
    assert db.get_indicator("5.6.7.8") is not None


def test_200_without_validators_clears_stored_ones(db, monkeypatch):
    calls = _stub_get(monkeypatch, [
        _FakeResponse(200, {"ETag": '"v1"'}, "1.2.3.4\n"),
        _FakeResponse(200, {}, "1.2.3.4\n"),
        _FakeResponse(200, {}, "1.2.3.4\n"),
    ])
    feed = _http_feed()
    ing = FeedIngestor(db)
    ing.ingest_feed(feed)
    ing.ingest_feed(feed)  # 200 with no validators -> stored ones erased
    assert db.get_feed_http_cache(feed.name) == (None, None)
    ing.ingest_feed(feed)  # so the next request must be unconditional
    assert "If-None-Match" not in calls[2]["headers"]
    assert "If-Modified-Since" not in calls[2]["headers"]


def test_retry_recovers_from_transient_failures(db, monkeypatch):
    delays = _stub_sleep(monkeypatch)
    calls = _stub_get(monkeypatch, [
        _FakeResponse(500),
        requests.exceptions.Timeout("timed out"),
        _FakeResponse(200, {}, "1.2.3.4\n"),
    ])
    assert FeedIngestor(db).ingest_feed(_http_feed()) == 1
    assert len(calls) == 3
    assert delays == [2, 4]  # backoff between the three attempts


def test_client_error_fails_immediately_without_retry(db, monkeypatch):
    delays = _stub_sleep(monkeypatch)
    calls = _stub_get(monkeypatch, [_FakeResponse(404)])
    feed = _http_feed()
    with pytest.raises(requests.exceptions.HTTPError):
        FeedIngestor(db).ingest_feed(feed)
    assert len(calls) == 1
    assert delays == []
    # The existing error handling is untouched by the retry machinery.
    stats = {s.feed_name: s for s in db.get_feed_stats()}
    assert stats[feed.name].status == "error"


def test_persistent_5xx_exhausts_retries_then_raises(db, monkeypatch):
    delays = _stub_sleep(monkeypatch)
    calls = _stub_get(monkeypatch, [_FakeResponse(503)] * 3)
    with pytest.raises(requests.exceptions.HTTPError):
        FeedIngestor(db).ingest_feed(_http_feed())
    assert len(calls) == 3
    assert delays == [2, 4]


# ------------------------------------------------------------- SSRF guard ----

def test_private_feed_url_is_rejected(db, monkeypatch):
    """A feed whose host resolves to a private address is refused before any
    network request is made."""
    monkeypatch.setattr("threatfeedme.feed_ingestor._host_addresses",
                        lambda host: ["10.0.0.5"])
    calls = _stub_get(monkeypatch, [_FakeResponse(200, {}, "1.2.3.4\n")])
    with pytest.raises(RuntimeError, match="non-public address"):
        FeedIngestor(db).ingest_feed(_http_feed())
    assert calls == []


def test_private_feed_url_allowed_when_opted_in(db, monkeypatch):
    monkeypatch.setattr("threatfeedme.feed_ingestor._host_addresses",
                        lambda host: ["10.0.0.5"])
    _stub_get(monkeypatch, [_FakeResponse(200, {}, "1.2.3.4\n")])
    ing = FeedIngestor(db, allow_private_urls=True)
    assert ing.ingest_feed(_http_feed()) == 1


def test_redirect_to_private_address_is_rejected(db, monkeypatch):
    """The guard applies to every redirect hop, not just the original URL."""
    resolved = {"feeds.example": ["8.8.8.8"], "internal.example": ["192.168.1.1"]}
    monkeypatch.setattr("threatfeedme.feed_ingestor._host_addresses",
                        lambda host: resolved[host])
    calls = _stub_get(monkeypatch, [
        _FakeResponse(302, {"Location": "http://internal.example/x.txt"}),
    ])
    with pytest.raises(RuntimeError, match="non-public address"):
        FeedIngestor(db).ingest_feed(_http_feed())
    assert len(calls) == 1  # first hop was fetched, the private hop was not


def test_public_redirect_is_followed(db, monkeypatch):
    calls = _stub_get(monkeypatch, [
        _FakeResponse(301, {"Location": "http://feeds.example/moved.txt"}),
        _FakeResponse(200, {}, "1.2.3.4\n"),
    ])
    assert FeedIngestor(db).ingest_feed(_http_feed()) == 1
    assert calls[1]["url"] == "http://feeds.example/moved.txt"


# ------------------------------------------------------- DShield scraper ----

def test_dshield_scraper_rewrites_ranges_to_cidr(db, monkeypatch):
    """block.txt start/end/mask rows become real CIDRs (not two bare IPs)."""
    raw = (
        "# DShield.org Recommended Block List\n"
        "203.0.113.0\t203.0.113.255\t24\t342\tSOMENET\tUS\tabuse@example.com\n"
        "198.51.100.0\t198.51.100.255\t24\t100\tOTHERNET\tUS\tNone\n"
        "not\ta\tvalid\trow\n"
    )
    _stub_get(monkeypatch, [_FakeResponse(200, {}, raw)])
    feed = FeedSource(name="dshield_block", url="http://feeds.example/block.txt",
                      feed_type=FeedType.THREAT_INTEL, weight=1.0,
                      update_interval=3600, scraper="dshield_block")
    entries = FeedIngestor(db).fetch_feed(feed)
    by_ip = {e["ip"]: e for e in entries}
    assert by_ip["203.0.113.0"]["cidr"] == "203.0.113.0/24"
    assert by_ip["198.51.100.0"]["cidr"] == "198.51.100.0/24"
    # The end-of-range addresses must NOT appear as separate bare IPs.
    assert "203.0.113.255" not in by_ip and len(by_ip) == 2


def test_drb_ra_scraper_extracts_domain_column(db, monkeypatch):
    """drb-ra '#domain,ioc' CSV: domains ingest, descriptions don't."""
    raw = (
        "#domain,ioc\n"
        "aaa.ad4min.com,Possible Cobalt Strike C2 Domain\n"
        "c2.evil.example,Possible Cobalt Strike C2 Fronted Domain\n"
        "\n"
    )
    _stub_get(monkeypatch, [_FakeResponse(200, {}, raw)])
    feed = FeedSource(name="drb_ra_c2", url="http://feeds.example/c2.csv",
                      feed_type=FeedType.THREAT_INTEL, weight=1.0,
                      update_interval=3600, scraper="drb_ra_domains",
                      indicator_kind="domain")
    entries = FeedIngestor(db).fetch_feed(feed)
    values = {e["ip"] for e in entries}
    assert values == {"aaa.ad4min.com", "c2.evil.example"}
    assert all(e.get("kind") == "domain" for e in entries)


def test_phishtank_scraper_extracts_url_hosts(db, monkeypatch):
    """PhishTank CSV: the url column's HOST ingests; the header row and quoted
    commas inside a URL don't break parsing."""
    raw = (
        "phish_id,url,phish_detail_url,submission_time\n"
        "9508326,https://facture-92481.com/index.php,http://phishtank.example/9508326,2026-08-20\n"
        '9508327,"https://evil.example/pay,me/now",http://phishtank.example/9508327,2026-08-20\n'
    )
    _stub_get(monkeypatch, [_FakeResponse(200, {}, raw)])
    feed = FeedSource(name="phishtank_online_valid", url="http://feeds.example/pt.csv",
                      feed_type=FeedType.PHISHING, weight=1.0,
                      update_interval=3600, scraper="phishtank_urls",
                      indicator_kind="domain")
    entries = FeedIngestor(db).fetch_feed(feed)
    values = {e["ip"] for e in entries}
    assert values == {"facture-92481.com", "evil.example"}
    # detail-page hosts (column 2) must never leak into the corpus
    assert not any("phishtank.example" in v for v in values)


# ------------------------------------------------------- OTX pulses scraper ----

import ipaddress
from threatfeedme.feed_ingestor import NOT_MODIFIED


def _otx_feed():
    return FeedSource(name="alienVault_otx",
                      url="https://otx.alienvault.com/api/v1/pulses/subscribed/?limit=50",
                      feed_type=FeedType.THREAT_INTEL, weight=1.0,
                      update_interval=3600, requires_auth=True,
                      auth_env="OTX_API_KEY", auth_header="X-OTX-API-KEY",
                      scraper="otx_pulses")


def _pulse_page(indicator_sets, next_url=None):
    """Build one OTX pulses/subscribed JSON page from a list of indicator lists."""
    pulses = [{"id": f"p{i}", "name": f"pulse{i}",
               "indicators": [{"indicator": v, "type": t} for v, t in inds]}
              for i, inds in enumerate(indicator_sets)]
    page = {"results": pulses, "count": len(pulses)}
    if next_url:
        page["next"] = next_url
    else:
        page["next"] = None
    return json.dumps(page)


def test_otx_pulses_single_page_extracts_ipv4_only(db, monkeypatch):
    """IPv4 indicator values are kept; IPv6/hostname/domain/URL/hash are dropped."""
    monkeypatch.setenv("OTX_API_KEY", "test-key-123")
    body = _pulse_page([
        [("1.1.1.1", "IPv4"), ("2.2.2.2", "IPv4"),
         ("2001:db8::1", "IPv6"), ("evil.com", "hostname"),
         ("https://x/y", "URL"), ("aa11bb", "FileHash-SHA1")],
        [("1.1.1.1", "IPv4")],  # duplicate across pulses must collapse
    ])
    _stub_get(monkeypatch, [_FakeResponse(200, {}, body)])
    feed = _otx_feed()
    entries = FeedIngestor(db).fetch_feed(feed)
    ips = sorted(e["ip"] for e in entries)
    assert ips == ["1.1.1.1", "2.2.2.2"]
    # no IPv6/hostname/URL/hash leaked in
    assert all(ipaddress.ip_address(ip).version == 4 for ip in ips)


def test_otx_pulses_paginates_via_next(db, monkeypatch):
    """Page 2 is fetched from page 1's `next` URL; IPs from both pages ingested."""
    monkeypatch.setenv("OTX_API_KEY", "test-key-123")
    page1 = _pulse_page([[("1.1.1.1", "IPv4")]], next_url="https://otx.alienvault.com/api/v1/pulses/subscribed/?limit=50&page=2")
    page2 = _pulse_page([[("2.2.2.2", "IPv4")]])
    calls = _stub_get(monkeypatch, [
        _FakeResponse(200, {}, page1),
        _FakeResponse(200, {}, page2),
    ])
    feed = _otx_feed()
    entries = FeedIngestor(db).fetch_feed(feed)
    ips = sorted(e["ip"] for e in entries)
    assert ips == ["1.1.1.1", "2.2.2.2"]
    assert calls[1]["url"] == "https://otx.alienvault.com/api/v1/pulses/subscribed/?limit=50&page=2"


def test_otx_pulses_pagination_cap_stops(db, monkeypatch):
    """The page cap prevents following `next` beyond the bounded iterations."""
    monkeypatch.setenv("OTX_API_KEY", "test-key-123")
    # Patch the module global by string path so the scraper's __globals__ sees it.
    monkeypatch.setattr("threatfeedme.feed_ingestor._OTX_MAX_PAGES", 1)
    # page1 -> next page2 -> next page3; with cap=1 only pages 1 and 2 are fetched.
    page1 = _pulse_page([[("1.1.1.1", "IPv4")]], next_url="https://otx.alienvault.com/api/v1/pulses/subscribed/?limit=50&page=2")
    page2 = _pulse_page([[("2.2.2.2", "IPv4")]], next_url="https://otx.alienvault.com/api/v1/pulses/subscribed/?limit=50&page=3")
    page3 = _pulse_page([[("3.3.3.3", "IPv4")]])
    calls = _stub_get(monkeypatch, [_FakeResponse(200, {}, page1), _FakeResponse(200, {}, page2), _FakeResponse(200, {}, page3)])
    feed = _otx_feed()
    entries = FeedIngestor(db).fetch_feed(feed)
    # cap=1: the scraper ingests page 1 and stops before ever pulling page 2
    # (it never fetches a page it wouldn't process on a later iteration).
    assert sorted(e["ip"] for e in entries) == ["1.1.1.1"]
    assert len(calls) == 1  # pages 2 and 3 never fetched


def test_otx_pulses_empty_results_is_rejected(db, monkeypatch):
    """An empty pulses response is a failed scrape, not a silent healthy 0."""
    monkeypatch.setenv("OTX_API_KEY", "test-key-123")
    body = json.dumps({"results": [], "count": 0, "next": None})
    _stub_get(monkeypatch, [_FakeResponse(200, {}, body)])
    feed = _otx_feed()
    with pytest.raises(RuntimeError, match="returned no indicators"):
        FeedIngestor(db).fetch_feed(feed)


def test_otx_pulses_malformed_json_raises(db, monkeypatch):
    """A non-JSON 200 body fails immediately (no retry — a bad body won't fix itself)."""
    monkeypatch.setenv("OTX_API_KEY", "test-key-123")
    calls = _stub_get(monkeypatch, [_FakeResponse(200, {}, "not json at all")])
    delays = _stub_sleep(monkeypatch)
    feed = _otx_feed()
    with pytest.raises(RuntimeError, match="JSON parse failed"):
        FeedIngestor(db).fetch_feed(feed)
    assert len(calls) == 1
    assert delays == []  # JSON error is not retried


def test_otx_pulses_sends_auth_header_on_every_page(db, monkeypatch):
    """X-OTX-API-KEY must be present on page 1 and every paginated page."""
    monkeypatch.setenv("OTX_API_KEY", "test-key-123")
    page1 = _pulse_page([[("1.1.1.1", "IPv4")]], next_url="https://otx.alienvault.com/api/v1/pulses/subscribed/?limit=50&page=2")
    page2 = _pulse_page([[("2.2.2.2", "IPv4")]])
    calls = _stub_get(monkeypatch, [_FakeResponse(200, {}, page1), _FakeResponse(200, {}, page2)])
    feed = _otx_feed()
    FeedIngestor(db).fetch_feed(feed)
    assert calls[0]["headers"]["X-OTX-API-KEY"] == "test-key-123"
    assert calls[1]["headers"]["X-OTX-API-KEY"] == "test-key-123"


def test_otx_pulses_304_short_circuits_before_pagination(db, monkeypatch):
    """A 304 from the feed URL returns NOT_MODIFIED without fetching pages."""
    monkeypatch.setenv("OTX_API_KEY", "test-key-123")
    calls = _stub_get(monkeypatch, [_FakeResponse(304)])
    feed = _otx_feed()
    assert FeedIngestor(db).fetch_feed(feed) is NOT_MODIFIED
    assert len(calls) == 1


def test_local_file_feed_bypasses_http_machinery(db, tmp_path, monkeypatch):
    def _never(*args, **kwargs):
        raise AssertionError("HTTP machinery must not run for local-file feeds")

    monkeypatch.setattr("threatfeedme.feed_ingestor.requests.get", _never)
    monkeypatch.setattr("threatfeedme.feed_ingestor._sleep", _never)
    feed_file = tmp_path / "local.txt"
    feed_file.write_text("1.2.3.4\n")
    feed = FeedSource(name="local", url=str(feed_file), feed_type=FeedType.CUSTOM,
                      weight=0.6, local_file=True)
    assert FeedIngestor(db).ingest_feed(feed) == 1
    assert db.get_feed_http_cache("local") == (None, None)


def test_ingest_failure_after_200_does_not_cache_validators(db, monkeypatch):
    """A crash mid-ingest must not persist the new ETag -- otherwise the next
    refresh would 304 against content that was never stored."""
    calls = _stub_get(monkeypatch, [
        _FakeResponse(200, {"ETag": '"v1"'}, "1.2.3.4\n"),
        _FakeResponse(200, {"ETag": '"v1"'}, "1.2.3.4\n"),
    ])
    feed = _http_feed()
    ing = FeedIngestor(db)

    real_add = db.add_indicators_bulk
    state = {"fail": True}

    def flaky_add(*args, **kwargs):
        if state["fail"]:
            raise sqlite3.OperationalError("database is locked")
        return real_add(*args, **kwargs)

    monkeypatch.setattr(db, "add_indicators_bulk", flaky_add)
    with pytest.raises(sqlite3.OperationalError):
        ing.ingest_feed(feed)
    assert db.get_feed_http_cache(feed.name) == (None, None)

    # The retry after the failed run is unconditional and ingests in full.
    state["fail"] = False
    assert ing.ingest_feed(feed) == 1
    assert "If-None-Match" not in calls[1]["headers"]
    assert db.get_feed_http_cache(feed.name) == ('"v1"', None)


def test_304_after_error_run_reports_live_count(db, monkeypatch):
    """The 304 total must come from the live rows, not the error run's 0."""
    _stub_sleep(monkeypatch)
    _stub_get(monkeypatch, [
        _FakeResponse(200, {"ETag": '"v1"'}, "1.2.3.4\n5.6.7.8\n"),
        _FakeResponse(503), _FakeResponse(503), _FakeResponse(503),
        _FakeResponse(304),
    ])
    feed = _http_feed()
    ing = FeedIngestor(db)
    assert ing.ingest_feed(feed) == 2
    with pytest.raises(requests.exceptions.HTTPError):
        ing.ingest_feed(feed)  # error run records total_indicators = 0

    assert ing.ingest_feed(feed) == 2
    stats = {s.feed_name: s for s in db.get_feed_stats()}
    assert stats[feed.name].status == "success"
    assert stats[feed.name].total_indicators == 2


def test_304_with_no_live_indicators_forces_full_refetch(db, monkeypatch):
    """When retention already purged everything a feed contributed, a 304
    cannot restore it -- the validators are dropped and the content
    re-downloaded unconditionally within the same ingest call."""
    calls = _stub_get(monkeypatch, [
        _FakeResponse(200, {"ETag": '"v1"'}, "1.2.3.4\n"),
        _FakeResponse(304),
        _FakeResponse(200, {"ETag": '"v2"'}, "1.2.3.4\n5.6.7.8\n"),
    ])
    feed = _http_feed()
    ing = FeedIngestor(db)
    assert ing.ingest_feed(feed) == 1
    # Simulate the retention sweep having removed the feed's indicators.
    db.delete_indicator("1.2.3.4")

    assert ing.ingest_feed(feed) == 2
    # The forced second request within the same call was unconditional.
    assert "If-None-Match" not in calls[2]["headers"]
    assert db.get_indicator("1.2.3.4") is not None
    assert db.get_indicator("5.6.7.8") is not None
    assert db.get_feed_http_cache(feed.name) == ('"v2"', None)
    stats = {s.feed_name: s for s in db.get_feed_stats()}
    assert stats[feed.name].status == "success"
    assert stats[feed.name].total_indicators == 2


def test_feed_url_change_clears_validators(db, monkeypatch):
    """Editing a feed's URL invalidates the old validators -- a stale
    If-Modified-Since against different content could 304 forever."""
    _stub_get(monkeypatch, [
        _FakeResponse(200, {"ETag": '"v1"'}, "1.2.3.4\n"),
    ])
    feed = _http_feed()
    db.add_feed(feed)
    FeedIngestor(db).ingest_feed(feed)
    assert db.get_feed_http_cache(feed.name) == ('"v1"', None)

    # Re-adding with the same URL keeps the validators...
    db.add_feed(feed)
    assert db.get_feed_http_cache(feed.name) == ('"v1"', None)
    # ...but a URL change clears them.
    db.add_feed(FeedSource(name=feed.name, url="http://feeds.example/other.txt",
                           feed_type=FeedType.CUSTOM, weight=0.6, update_interval=3600))
    assert db.get_feed_http_cache(feed.name) == (None, None)


def test_remove_feed_clears_validators(db, monkeypatch):
    """A re-added same-name feed must not inherit the removed feed's validators."""
    _stub_get(monkeypatch, [
        _FakeResponse(200, {"ETag": '"v1"'}, "1.2.3.4\n"),
    ])
    feed = _http_feed()
    db.add_feed(feed)
    FeedIngestor(db).ingest_feed(feed)
    assert db.get_feed_http_cache(feed.name) == ('"v1"', None)

    assert db.remove_feed(feed.name) is True
    assert db.get_feed_http_cache(feed.name) == (None, None)


def test_feed_stats_http_cache_migration(tmp_path):
    """A pre-validator feed_stats table gains the etag/last_modified columns."""
    dbp = str(tmp_path / "legacy_stats.db")
    conn = sqlite3.connect(dbp)
    conn.executescript(
        "CREATE TABLE feed_stats (id INTEGER PRIMARY KEY AUTOINCREMENT,"
        " feed_name TEXT NOT NULL, total_indicators INTEGER DEFAULT 0,"
        " last_update TEXT NOT NULL, status TEXT NOT NULL, error_message TEXT);"
        " INSERT INTO feed_stats (feed_name, total_indicators, last_update, status)"
        " VALUES ('cins_army', 7, '2026-01-01T00:00:00', 'success');"
    )
    conn.commit()
    conn.close()

    db = Database(dbp)  # runs migration on open
    assert db.get_feed_http_cache("cins_army") == (None, None)
    db.set_feed_http_cache("cins_army", '"e1"', "Mon, 01 Jun 2026 00:00:00 GMT")
    assert db.get_feed_http_cache("cins_army") == \
        ('"e1"', "Mon, 01 Jun 2026 00:00:00 GMT")
    # Existing stats survive the migration untouched.
    stats = {s.feed_name: s for s in db.get_feed_stats()}
    assert stats["cins_army"].total_indicators == 7


# ==============================================================================
# Talos Snort.org scraper tests
# ==============================================================================

_MOCK_TALOS_TERMS_HTML = """\
<!DOCTYPE html>
<html><head><meta charset="utf-8"></head>
<body>
<form action="/downloads/ip-block-list/accept-terms" accept-terms class="button_to">
  <input name="authenticity_token" id="authenticity_token" value="csrf_token_abc123" type="hidden">
  <button type="submit" class="button primary">Accept</button>
</form>
</body>
</html>"""

_TALOS_MOCK_IPS = """\
1.2.3.4
5.6.7.8
9.10.11.12
13.14.15.16"""


def test_talos_scraper_dispatch(monkeypatch, db):
    """FeedIngestor.fetch_feed routes to the registered scraper (not _fetch_url)
    when feed.scraper is set, and returns the parsed indicators."""
    calls = {}

    def fake_scraper(self, feed):
        calls["scraped"] = feed.name
        return _TALOS_MOCK_IPS

    def boom(self, feed):
        raise AssertionError("_fetch_url must not be called for a scraper feed")

    monkeypatch.setitem(FeedIngestor._SCRAPERS, "talos_snort", fake_scraper)
    monkeypatch.setattr(FeedIngestor, "_fetch_url", boom)

    feed = FeedSource(
        name="talos_snort",
        url="https://snort.org/downloads/ip-block-list/terms",
        feed_type=FeedType.THREAT_INTEL,
        weight=0.95,
        scraper="talos_snort",
    )
    entries = FeedIngestor(db).fetch_feed(feed)
    assert calls.get("scraped") == "talos_snort"
    assert {e["ip"] for e in entries} == {"1.2.3.4", "5.6.7.8", "9.10.11.12", "13.14.15.16"}


def test_talos_scraper_end_to_end_ingest(monkeypatch, db):
    """ingest_feed stores scraped indicators and records success with the count."""
    monkeypatch.setitem(
        FeedIngestor._SCRAPERS, "talos_snort", lambda self, feed: _TALOS_MOCK_IPS
    )
    feed = FeedSource(
        name="talos_snort", url="https://snort.org/x", feed_type=FeedType.THREAT_INTEL,
        weight=0.95, scraper="talos_snort",
    )
    count = FeedIngestor(db).ingest_feed(feed)
    assert count == 4
    assert db.get_indicator("1.2.3.4") is not None
    stats = {s.feed_name: s for s in db.get_feed_stats()}
    assert stats["talos_snort"].status == "success"
    assert stats["talos_snort"].total_indicators == 4


def test_talos_garbage_200_is_rejected(monkeypatch, db):
    """A scraper HTTP 200 that is not the IP list (e.g. an error/terms page)
    yields zero indicators and must be treated as a failed fetch, not a healthy
    empty feed — otherwise retention silently drains the stored IPs."""
    monkeypatch.setitem(
        FeedIngestor._SCRAPERS,
        "talos_snort",
        lambda self, feed: "<html><body>Access denied</body></html>",
    )
    feed = FeedSource(
        name="talos_snort", url="https://snort.org/x", feed_type=FeedType.THREAT_INTEL,
        weight=0.95, scraper="talos_snort",
    )
    ingestor = FeedIngestor(db)
    with pytest.raises(RuntimeError, match="returned no indicators"):
        ingestor.fetch_feed(feed)
    # ingest_feed should surface the failure as an errored feed, not success/0.
    with pytest.raises(RuntimeError):
        ingestor.ingest_feed(feed)
    stats = {s.feed_name: s for s in db.get_feed_stats()}
    assert stats["talos_snort"].status == "error"


def test_talos_scraper_no_scraper_raises(db):
    """fetch_feed raises RuntimeError when the named scraper is not registered."""
    feed = FeedSource(
        name="fake_scraper_feed",
        url="https://example.com/",
        feed_type=FeedType.THREAT_INTEL,
        scraper="nonexistent_scraper",
    )
    ingestor = FeedIngestor(db)
    with pytest.raises(RuntimeError, match="Scraper 'nonexistent_scraper' not registered"):
        ingestor.fetch_feed(feed)


def test_talos_token_extraction():
    """_scrape_talos extracts the CSRF authenticity_token from the terms page."""
    from threatfeedme.feed_ingestor import _TALOS_TOKEN_RE, _TALOS_TOKEN_RE_FALLBACK

    # Primary regex (anchored inside accept-terms form)
    m = _TALOS_TOKEN_RE.search(_MOCK_TALOS_TERMS_HTML)
    assert m is not None, "Primary regex should match the token"
    assert m.group(1) == "csrf_token_abc123"

    # Fallback regex (loose, scans entire page)
    m = _TALOS_TOKEN_RE_FALLBACK.search(_MOCK_TALOS_TERMS_HTML)
    assert m is not None, "Fallback regex should also match"
    assert m.group(1) == "csrf_token_abc123"


def test_talos_token_extraction_no_form():
    """Both regexes return None when there is no authenticity_token on the page."""
    from threatfeedme.feed_ingestor import _TALOS_TOKEN_RE, _TALOS_TOKEN_RE_FALLBACK

    blank_page = "<html><body>no form here</body></html>"
    assert _TALOS_TOKEN_RE.search(blank_page) is None
    assert _TALOS_TOKEN_RE_FALLBACK.search(blank_page) is None


def test_talos_token_extraction_fallback_works():
    """Fallback regex matches a token outside the accept-terms form block."""
    from threatfeedme.feed_ingestor import _TALOS_TOKEN_RE, _TALOS_TOKEN_RE_FALLBACK

    # A page where the token appears before any accept-terms marker
    html = '''<form><input name="authenticity_token" value="fallback_token"></form>'''
    # Primary should fail (no accept-terms anchor)
    assert _TALOS_TOKEN_RE.search(html) is None
    # Fallback should succeed
    m = _TALOS_TOKEN_RE_FALLBACK.search(html)
    assert m is not None
    assert m.group(1) == "fallback_token"


def test_talos_cloudflare_ua_present():
    """The scraper uses a Chrome 126 User-Agent to bypass Cloudflare."""
    from threatfeedme.feed_ingestor import _TALOS_UA
    assert "Chrome/126" in _TALOS_UA
    assert "Windows NT 10.0" in _TALOS_UA


def test_talos_full_scrape_flow(monkeypatch, db):
    """End-to-end test: mock the terms page GET and accept-terms POST, then
    verify the scraper returns the raw IP list."""
    import requests
    from threatfeedme.feed_ingestor import _scrape_talos, _TALOS_TERMS_URL, _TALOS_ACCEPT_URL, _TALOS_UA

    class MockSession:
        def __init__(self):
            self.headers = {"User-Agent": _TALOS_UA}

        def get(self, url, **kwargs):
            assert url == _TALOS_TERMS_URL
            class Resp:
                text = _MOCK_TALOS_TERMS_HTML
                status_code = 200
                def raise_for_status(self): pass
            return Resp()

        def post(self, url, data, **kwargs):
            assert url == _TALOS_ACCEPT_URL
            assert data["authenticity_token"] == "csrf_token_abc123"
            assert data["commit"] == "Accept"
            class Resp:
                text = _TALOS_MOCK_IPS
                status_code = 200
                headers = {"content-type": "text/plain"}
                def raise_for_status(self): pass
            return Resp()

    # Inject the mock session
    monkeypatch.setattr("requests.Session", lambda: MockSession())

    feed = FeedSource(
        name="talos_snort",
        url=_TALOS_TERMS_URL,
        feed_type=FeedType.THREAT_INTEL,
        scraper="talos_snort",
    )
    ingestor = FeedIngestor(db)
    content = _scrape_talos(ingestor, feed)
    # The scraper strip()s the response text, so compare against stripped
    assert content == _TALOS_MOCK_IPS.strip()


def test_talos_terms_page_get_failure(monkeypatch, db):
    """Scraper raises when the terms page GET fails."""
    import requests
    from threatfeedme.feed_ingestor import _scrape_talos, _TALOS_TERMS_URL

    class MockSession:
        def __init__(self):
            self.headers = {}
        def get(self, url, **kwargs):
            raise requests.exceptions.ConnectionError("connection refused")
        def post(self, *a, **kw):
            raise RuntimeError("should not be called")

    monkeypatch.setattr("requests.Session", lambda: MockSession())
    feed = FeedSource(
        name="talos_snort",
        url=_TALOS_TERMS_URL,
        feed_type=FeedType.THREAT_INTEL,
        scraper="talos_snort",
    )
    ingestor = FeedIngestor(db)
    with pytest.raises(requests.exceptions.ConnectionError):
        _scrape_talos(ingestor, feed)


def test_talos_missing_token_raises(monkeypatch, db):
    """Scraper raises RuntimeError when the authenticity_token is not found."""
    import requests
    from threatfeedme.feed_ingestor import _scrape_talos, _TALOS_TERMS_URL

    class MockSession:
        def __init__(self):
            self.headers = {}
        def get(self, url, **kwargs):
            class Resp:
                text = "<html><body>no token here</body></html>"
                status_code = 200
                def raise_for_status(self): pass
            return Resp()
        def post(self, *a, **kw):
            raise RuntimeError("should not be called")

    monkeypatch.setattr("requests.Session", lambda: MockSession())
    feed = FeedSource(
        name="talos_snort",
        url=_TALOS_TERMS_URL,
        feed_type=FeedType.THREAT_INTEL,
        scraper="talos_snort",
    )
    ingestor = FeedIngestor(db)
    with pytest.raises(RuntimeError, match="could not find authenticity_token"):
        _scrape_talos(ingestor, feed)


def test_talos_accept_post_failure(monkeypatch, db):
    """Scraper raises when the accept-terms POST fails."""
    import requests
    from threatfeedme.feed_ingestor import _scrape_talos, _TALOS_TERMS_URL, _TALOS_ACCEPT_URL

    class MockSession:
        def __init__(self):
            self.headers = {}
        def get(self, url, **kwargs):
            class Resp:
                text = _MOCK_TALOS_TERMS_HTML
                status_code = 200
                def raise_for_status(self): pass
            return Resp()
        def post(self, url, data, **kwargs):
            raise requests.exceptions.Timeout("post timed out")

    monkeypatch.setattr("requests.Session", lambda: MockSession())
    feed = FeedSource(
        name="talos_snort",
        url=_TALOS_TERMS_URL,
        feed_type=FeedType.THREAT_INTEL,
        scraper="talos_snort",
    )
    ingestor = FeedIngestor(db)
    with pytest.raises(requests.exceptions.Timeout):
        _scrape_talos(ingestor, feed)


def test_talos_scrape_returns_raw_body(monkeypatch, db):
    """_scrape_talos returns the accept-terms response body verbatim (stripped);
    parsing/validation happens downstream in fetch_feed/ingest_feed."""
    import requests
    from threatfeedme.feed_ingestor import _scrape_talos, _TALOS_TERMS_URL

    class MockSession:
        def __init__(self):
            self.headers = {}
        def get(self, url, **kwargs):
            class Resp:
                text = _MOCK_TALOS_TERMS_HTML
                status_code = 200
                def raise_for_status(self): pass
            return Resp()
        def post(self, url, data, **kwargs):
            class Resp:
                text = "1.2.3.4\n"  # single IP, real newline
                status_code = 200
                headers = {"content-type": "text/plain"}
                def raise_for_status(self): pass
            return Resp()

    monkeypatch.setattr("requests.Session", lambda: MockSession())
    feed = FeedSource(
        name="talos_snort",
        url=_TALOS_TERMS_URL,
        feed_type=FeedType.THREAT_INTEL,
        scraper="talos_snort",
    )
    assert _scrape_talos(FeedIngestor(db), feed) == "1.2.3.4"


# ------------------------------------------------------------------- geo ----
# The packed /16 -> country table is the one place a silent wrong answer is
# plausible: a bad offset mislabels countries with no error anywhere.

def _build_geo_table(mapping, tmp_path):
    """Write a real .geo1 file mapping {/16 index: iso} using the shipped
    generator, so these tests exercise the actual format both ways."""
    from threatfeedme.geo.generate import generate
    from threatfeedme.geo.countries import known_codes
    out = tmp_path / "t.geo1"
    generate(mapping, set(known_codes()), out=out)
    return out


def test_geo_table_roundtrip_maps_ips_to_countries(tmp_path):
    from threatfeedme.geo.data import CountryBuckets
    # 8.8.0.0/16 -> US, 5.45.0.0/16 -> RU
    path = _build_geo_table({(8 << 8) | 8: "US", (5 << 8) | 45: "RU"}, tmp_path)
    b = CountryBuckets.load(path)
    assert b.country_for_ip_str("8.8.8.8") == "US"
    assert b.country_for_ip_str("8.8.255.254") == "US"   # same /16
    assert b.country_for_ip_str("5.45.1.2") == "RU"
    assert b.country_for_ip_str("9.9.9.9") == "ZZ"       # unmapped
    assert b.country_for_ip_str("not-an-ip") == "ZZ"


def test_geo_table_rejects_corrupt_files(tmp_path):
    """A truncated or foreign file must raise, not silently serve garbage."""
    from threatfeedme.geo.data import CountryBuckets
    good = _build_geo_table({0: "US"}, tmp_path).read_bytes()

    with pytest.raises(ValueError):
        CountryBuckets(b"tiny")
    with pytest.raises(ValueError):                       # bad magic
        CountryBuckets(b"XXXX" + good[4:])
    with pytest.raises(ValueError):                       # unsupported version
        CountryBuckets(good[:4] + b"\x63\x00" + good[6:])
    with pytest.raises(ValueError):                       # truncated buckets
        CountryBuckets(good[:-64])
    missing = tmp_path / "nope.geo1"
    with pytest.raises(FileNotFoundError):
        CountryBuckets.load(missing)


def test_country_counts_buckets_indicators(db, tmp_path, monkeypatch):
    """country_counts() groups stored indicators by country and is read-only."""
    from threatfeedme.geo import data as geo_data
    path = _build_geo_table({(8 << 8) | 8: "US", (5 << 8) | 45: "RU"}, tmp_path)
    monkeypatch.setattr(geo_data, "_DEFAULT", path)

    for ip in ("8.8.8.8", "8.8.4.4", "5.45.1.1"):
        db.add_indicator(ip, "cins_army", {})
    db.add_indicator("9.9.9.9", "cins_army", {})   # unmapped -> ZZ

    counts = dict(db.country_counts())
    assert counts["US"] == 2 and counts["RU"] == 1 and counts["ZZ"] == 1
    assert len(db.get_all_indicators()) == 4       # aggregation stored nothing


def test_country_counts_empty_when_table_missing(db, tmp_path, monkeypatch):
    """No geo table is a degraded feature, not a 500 on the dashboard."""
    from threatfeedme.geo import data as geo_data
    monkeypatch.setattr(geo_data, "_DEFAULT", tmp_path / "absent.geo1")
    db.add_indicator("8.8.8.8", "cins_army", {})
    assert db.country_counts() == []


def test_dbip_parser_awards_each_16_to_its_dominant_country(tmp_path):
    """DB-IP ranges can straddle /16s; the /16 goes to whoever covers most of
    it. This is the CC-BY source path the shipped table is built from."""
    from threatfeedme.geo.generate import _parse_dbip
    csv = tmp_path / "dbip.csv"
    csv.write_text(
        "1.1.0.0,1.1.0.99,GB\n"       # 100 addresses of 1.1.0.0/16
        "1.1.0.100,1.1.255.255,TH\n"  # the rest of it -> TH should win
        "2.2.0.0,2.2.255.255,DE\n"
        "2001:db8::,2001:db8::ffff,FR\n",  # IPv6 row must be skipped
        encoding="utf-8")
    table = _parse_dbip(str(csv))
    assert table[(1 << 8) | 1] == "TH"
    assert table[(2 << 8) | 2] == "DE"


def test_world_map_paths_ship_and_are_wellformed():
    """The dashboard choropleth needs the generated path file; a missing or
    malformed one silently degrades the map to a bar list."""
    import json
    from pathlib import Path
    import threatfeedme
    p = Path(threatfeedme.__file__).parent / "static" / "world-paths.json"
    assert p.exists(), "world-paths.json not generated"
    doc = json.loads(p.read_text(encoding="utf-8"))
    paths, names = doc["paths"], doc["names"]
    assert len(paths) > 150                       # ~174 countries at 110m
    for iso in ("US", "CN", "RU", "BR", "DE"):
        assert iso in paths and paths[iso].startswith("M") and paths[iso].endswith("Z")
        assert names[iso]
    # Keep the payload small: it is fetched by the browser on panel expand.
    assert p.stat().st_size < 150 * 1024, "map data has grown too heavy"


def test_map_generator_projects_and_simplifies(tmp_path):
    from threatfeedme.geo.generate_map import build, WIDTH, HEIGHT
    import json
    # A square around the prime meridian/equator plus a speck that must be
    # dropped for being smaller than MIN_AREA.
    geo = {"features": [
        {"properties": {"ISO_A2": "AA", "NAME": "Alphaland"},
         "geometry": {"type": "Polygon", "coordinates": [[
             [-10, 10], [10, 10], [10, -10], [-10, -10], [-10, 10]]]}},
        {"properties": {"ISO_A2": "-99", "NAME": "Disputed"},
         "geometry": {"type": "Polygon", "coordinates": [[
             [0, 0], [1, 0], [1, 1], [0, 0]]]}},
        {"properties": {"ISO_A2": "BB", "NAME": "Speck"},
         "geometry": {"type": "Polygon", "coordinates": [[
             [0, 0], [0.01, 0], [0.01, 0.01], [0, 0]]]}},
    ]}
    src = tmp_path / "w.geojson"
    src.write_text(json.dumps(geo), encoding="utf-8")
    out = tmp_path / "w.json"
    build(str(src), out=out)
    doc = json.loads(out.read_text(encoding="utf-8"))

    assert "AA" in doc["paths"] and doc["names"]["AA"] == "Alphaland"
    assert "BB" not in doc["paths"]        # speck dropped
    assert not any(k.startswith("-") for k in doc["paths"])  # no ISO -99 entity
    # Longitude 0 must land at the horizontal centre of the viewBox.
    xs = [float(t.split()[0]) for t in doc["paths"]["AA"].lstrip("M").rstrip("Z").split("L")]
    assert min(xs) < WIDTH / 2 < max(xs)
    assert all(0 <= x <= WIDTH for x in xs)


# ------------------------------------------------------------ bulk ingest ----

def test_bulk_insert_matches_add_indicator_semantics(db):
    """Bulk path stores the same rows/sources a per-row loop would."""
    n = db.add_indicators_bulk(
        [("203.0.113.1", {"feed_type": "threat_intel"}),
         ("203.0.113.2", {"cidr": "203.0.113.0/24"})],
        source="feed_a",
    )
    assert n == 2
    ind = db.get_indicator("203.0.113.2")
    assert ind.sources == ["feed_a"]
    assert ind.metadata["cidr"] == "203.0.113.0/24"
    assert ind.first_seen == ind.last_seen


def test_bulk_upsert_preserves_first_seen_and_merges_metadata(db):
    db.add_indicator("203.0.113.9", "feed_a", {"old_key": "kept"})
    first_seen = db.get_indicator("203.0.113.9").first_seen
    db.add_indicators_bulk([("203.0.113.9", {"new_key": "added"})], source="feed_b")
    ind = db.get_indicator("203.0.113.9")
    assert ind.first_seen == first_seen
    assert ind.metadata["old_key"] == "kept" and ind.metadata["new_key"] == "added"
    assert sorted(ind.sources) == ["feed_a", "feed_b"]
    # No duplicate indicator row was created by the upsert.
    with db._cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM indicators WHERE ip = ?", ("203.0.113.9",))
        assert cur.fetchone()[0] == 1


def test_bulk_duplicate_source_reports_ignored(db):
    """Re-ingesting the same feed doesn't duplicate indicator_sources rows."""
    db.add_indicators_bulk([("198.51.100.7", {})], source="feed_a")
    db.add_indicators_bulk([("198.51.100.7", {})], source="feed_a")
    assert db.get_indicator("198.51.100.7").sources == ["feed_a"]


def test_bulk_chunking_crosses_commit_boundary(db, monkeypatch):
    """Rows on both sides of a chunk commit all land."""
    monkeypatch.setattr(Database, "BULK_CHUNK", 3)
    rows = [(f"203.0.113.{i}", {}) for i in range(1, 9)]  # 8 rows, chunk=3
    assert db.add_indicators_bulk(rows, source="feed_a") == 8
    with db._cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM indicators")
        assert cur.fetchone()[0] == 8
        cur.execute("SELECT COUNT(*) FROM indicator_sources WHERE source_name = 'feed_a'")
        assert cur.fetchone()[0] == 8


def test_bulk_empty_rows_no_op(db):
    assert db.add_indicators_bulk([], source="feed_a") == 0


def test_ingest_uses_bulk_path(db, tmp_path):
    """End-to-end: a local-file feed lands via the bulk writer."""
    feed_file = tmp_path / "list.txt"
    # Real public addresses: the safety filter drops reserved ranges (which
    # includes TEST-NET), so 10/8 is the only row that should be excluded.
    feed_file.write_text("45.13.2.9\n91.92.242.236\n10.0.0.1\n")
    feed = FeedSource(name="bulk_feed", url=str(feed_file), feed_type=FeedType.THREAT_INTEL,
                      weight=1.0, update_interval=3600, local_file=True)
    from threatfeedme.safety import SafetyFilter
    ingestor = FeedIngestor(db, safety=SafetyFilter(drop_private_reserved=True))
    count = ingestor.ingest_feed(feed)
    assert count == 2
    assert db.get_indicator("45.13.2.9").sources == ["bulk_feed"]
    assert db.get_indicator("10.0.0.1") is None


# ------------------------------------------------- effective-votes tiering ----

EV_CONFIG = {
    "feeds": [],
    "scoring": {
        "tiering": {"method": "effective_votes",
                    "medium_floor": 1.1, "high_floor": 2.0},
        "high_confidence": {"require_threat_intel": False},
    },
}


def _seed_disjoint(db, feed, ips):
    for ip in ips:
        db.add_indicator(ip, feed, {"feed_type": "threat_intel"})


def test_effective_votes_discounts_twin_feeds(db):
    """Two feeds reporting identical populations are one witness, not two."""
    for i in range(1, 11):
        db.add_indicator(f"45.13.2.{i}", "echo_a", {})
        db.add_indicator(f"45.13.2.{i}", "echo_b", {})
    scorer = ConfidenceScorer(db, EV_CONFIG)
    assert scorer._effective_votes(["echo_a", "echo_b"]) == pytest.approx(1.0)


def test_effective_votes_full_credit_for_disjoint_feeds(db):
    _seed_disjoint(db, "feed_a", [f"45.13.2.{i}" for i in range(1, 11)])
    _seed_disjoint(db, "feed_b", [f"91.92.242.{i}" for i in range(1, 11)])
    scorer = ConfidenceScorer(db, EV_CONFIG)
    assert scorer._effective_votes(["feed_a", "feed_b"]) == pytest.approx(2.0)


def test_effective_votes_partial_overlap(db):
    """50% overlap with an already-counted feed = half a vote."""
    _seed_disjoint(db, "big", [f"45.13.2.{i}" for i in range(1, 21)])       # 20 IPs
    _seed_disjoint(db, "half", [f"45.13.2.{i}" for i in range(1, 6)]        # 5 shared
                   + [f"91.92.242.{i}" for i in range(1, 6)])               # 5 unique
    scorer = ConfidenceScorer(db, EV_CONFIG)
    # overlap = 5 / min(20, 10) = 0.5; big counts first (larger)
    assert scorer._effective_votes(["big", "half"]) == pytest.approx(1.5)


def test_tier_from_votes_floors_are_strict(db):
    """Exactly two independent witnesses is medium, not high — high needs
    strictly more than the floor."""
    scorer = ConfidenceScorer(db, EV_CONFIG)
    t = scorer._tier_from_votes
    assert t(1.0, ["a"], 1.1, 2.0) == ConfidenceTier.LOW
    assert t(1.5, ["a", "b"], 1.1, 2.0) == ConfidenceTier.MEDIUM
    assert t(2.0, ["a", "b"], 1.1, 2.0) == ConfidenceTier.MEDIUM
    assert t(2.4, ["a", "b", "c"], 1.1, 2.0) == ConfidenceTier.HIGH
    assert t(9.0, [], 1.1, 2.0) == ConfidenceTier.LOW  # no evidence


def test_tier_from_votes_keeps_threat_intel_gate(db):
    cfg = {"feeds": [{"name": "curated", "feed_type": "threat_intel"}],
           "scoring": {"tiering": {"method": "effective_votes"},
                       "high_confidence": {"require_threat_intel": True}}}
    scorer = ConfidenceScorer(db, cfg)
    # 3 independent votes but all custom/unknown -> capped at medium
    assert scorer._tier_from_votes(3.0, ["up1", "up2", "up3"], 1.1, 2.0) \
        == ConfidenceTier.MEDIUM
    assert scorer._tier_from_votes(3.0, ["curated", "up2", "up3"], 1.1, 2.0) \
        == ConfidenceTier.HIGH


def test_domain_witness_gate_uses_effective_votes_not_raw_count(db):
    """The domain witness gate keys on EFFECTIVE (overlap-discounted) votes,
    not the raw distinct-source count. high_b is set high (10) so only the gate
    can produce HIGH — isolating its behavior from the k-means boundary."""
    scorer = ConfidenceScorer(db, EV_CONFIG)
    t = scorer._tier_from_votes
    # 3 effective independent witnesses -> gate forces HIGH despite high_b=10
    assert t(3.0, ["a", "b", "c"], 1.1, 10.0, kind='domain') == ConfidenceTier.HIGH
    # 3 DISTINCT source names but effectively ~1 witness (correlated/echoes):
    # the old raw-count gate wrongly promoted this; the votes gate must not.
    assert t(1.0, ["a", "b", "c"], 1.1, 10.0, kind='domain') == ConfidenceTier.LOW
    # just under the witness threshold -> falls through to the boundary logic
    assert t(2.9, ["a", "b", "c"], 1.1, 10.0, kind='domain') == ConfidenceTier.MEDIUM


def test_domain_witness_gate_is_domain_only(db):
    """The gate applies to domains, not IPs: an IP with 3 effective votes under
    a high break stays MEDIUM (no gate), while the same domain goes HIGH."""
    scorer = ConfidenceScorer(db, EV_CONFIG)
    assert scorer._tier_from_votes(3.0, ["a", "b", "c"], 1.1, 10.0, kind='ip') \
        == ConfidenceTier.MEDIUM
    assert scorer._tier_from_votes(3.0, ["a", "b", "c"], 1.1, 10.0, kind='domain') \
        == ConfidenceTier.HIGH


def test_domain_authoritative_feed_forces_high(db):
    """Provenance-first domain HIGH: one designated authoritative source is
    enough, regardless of votes or the k-means boundary."""
    cfg = {"feeds": [{"name": "urlhaus_hostfile", "feed_type": "threat_intel"}],
           "scoring": {"tiering": {"method": "effective_votes"},
                       "high_confidence": {
                           "authoritative_domain_feeds": ["urlhaus_hostfile"]}}}
    scorer = ConfidenceScorer(db, cfg)
    t = scorer._tier_from_votes
    # single authoritative source, ~1 vote, break far above -> HIGH
    assert t(1.0, ["urlhaus_hostfile"], 1.1, 10.0, kind='domain') == ConfidenceTier.HIGH
    # same evidence, non-authoritative feed -> falls through to boundary (LOW)
    assert t(1.0, ["openphish_community"], 1.1, 10.0, kind='domain') == ConfidenceTier.LOW
    # authoritative among others still trips it
    assert t(1.5, ["openphish_community", "urlhaus_hostfile"], 1.1, 10.0,
             kind='domain') == ConfidenceTier.HIGH


def test_domain_authoritative_is_domain_only_and_optional(db):
    """The provenance gate never applies to IPs, and an empty/absent list
    leaves tiering untouched."""
    cfg = {"feeds": [{"name": "urlhaus_hostfile", "feed_type": "threat_intel"}],
           "scoring": {"tiering": {"method": "effective_votes"},
                       "high_confidence": {
                           "authoritative_domain_feeds": ["urlhaus_hostfile"]}}}
    scorer = ConfidenceScorer(db, cfg)
    assert scorer._tier_from_votes(1.0, ["urlhaus_hostfile"], 1.1, 10.0, kind='ip') \
        == ConfidenceTier.LOW
    bare = ConfidenceScorer(db, EV_CONFIG)  # no authoritative list configured
    assert bare._tier_from_votes(1.0, ["urlhaus_hostfile"], 1.1, 10.0, kind='domain') \
        == ConfidenceTier.LOW


def test_domain_authoritative_honors_require_threat_intel(db):
    """A custom-typed feed marked authoritative cannot force HIGH while
    require_threat_intel is on — the intel gate outranks the designation."""
    cfg = {"feeds": [{"name": "my_upload", "feed_type": "custom"}],
           "scoring": {"tiering": {"method": "effective_votes"},
                       "high_confidence": {
                           "require_threat_intel": True,
                           "authoritative_domain_feeds": ["my_upload"]}}}
    scorer = ConfidenceScorer(db, cfg)
    assert scorer._tier_from_votes(1.0, ["my_upload"], 1.1, 10.0, kind='domain') \
        == ConfidenceTier.LOW


def test_domain_witness_gate_honors_require_threat_intel(db):
    """With require_threat_intel, three effective witnesses that are all
    custom/unknown do NOT trip the gate; one curated source among them does."""
    cfg = {"feeds": [{"name": "curated", "feed_type": "threat_intel"}],
           "scoring": {"tiering": {"method": "effective_votes"},
                       "high_confidence": {"require_threat_intel": True,
                                           "min_domain_sources": 3}}}
    scorer = ConfidenceScorer(db, cfg)
    assert scorer._tier_from_votes(3.0, ["up1", "up2", "up3"], 1.1, 10.0, kind='domain') \
        == ConfidenceTier.MEDIUM
    assert scorer._tier_from_votes(3.0, ["curated", "up2", "up3"], 1.1, 10.0, kind='domain') \
        == ConfidenceTier.HIGH


def test_natural_breaks_degenerate_population_uses_floors(db):
    scorer = ConfidenceScorer(db, EV_CONFIG)
    assert scorer._natural_breaks([]) == (1.1, 2.0)
    assert scorer._natural_breaks([1.0] * 500) == (1.1, 2.0)   # uniform
    assert scorer._natural_breaks([1.0, 2.0, 3.0]) == (1.1, 2.0)  # tiny


def test_natural_breaks_finds_three_lumps(db):
    scorer = ConfidenceScorer(db, EV_CONFIG)
    votes = [1.0] * 300 + [2.0] * 100 + [3.5] * 30
    med_b, high_b = scorer._natural_breaks(votes)
    assert 1.1 <= med_b < 2.0 < high_b < 3.5
    # boundaries actually separate the lumps
    assert sum(1 for v in votes if v > high_b) == 30
    assert sum(1 for v in votes if med_b < v <= high_b) == 100


def test_natural_breaks_never_below_floors(db):
    scorer = ConfidenceScorer(db, EV_CONFIG)
    # all mass squeezed low -> k-means breaks would sit below the floors
    votes = [0.2] * 100 + [0.4] * 100 + [0.9] * 100
    med_b, high_b = scorer._natural_breaks(votes)
    assert med_b >= 1.1 and high_b >= 2.0


def test_recalculate_persists_votes_and_breaks(db):
    """Full rescore stores effective_votes per indicator and the tier
    boundaries in settings; correlated feeds don't reach high."""
    # echo pair: same 60 IPs (100% overlap), third feed disjoint
    for i in range(1, 61):
        ip = f"45.13.{i // 250}.{i % 250 or 1}"
        db.add_indicator(ip, "echo_a", {"feed_type": "threat_intel"})
        db.add_indicator(ip, "echo_b", {"feed_type": "threat_intel"})
    scorer = ConfidenceScorer(db, EV_CONFIG)
    scorer.recalculate_all_scores()
    with db._cursor() as cur:
        cur.execute("SELECT effective_votes, tier FROM indicators LIMIT 1")
        votes, tier = cur.fetchone()
    assert votes == pytest.approx(1.0)   # echo pair = one witness
    assert tier == "low"                 # 1.0 not > medium floor 1.1
    assert db.get_setting(scorer.TIER_BREAKS_KEY) is not None


def test_single_ip_score_uses_stored_breaks(db):
    """calculate_score on one IP honors the boundaries the last full
    rescore stored (population context a single IP can't compute)."""
    import json as _json
    _seed_disjoint(db, "feed_a", [f"45.13.2.{i}" for i in range(1, 11)])
    _seed_disjoint(db, "feed_b", [f"91.92.242.{i}" for i in range(1, 11)])
    db.add_indicator("203.0.113.9", "feed_a", {})
    db.add_indicator("203.0.113.9", "feed_b", {})
    scorer = ConfidenceScorer(db, EV_CONFIG)
    # votes for the shared IP ~ 2.0 (feeds nearly disjoint); with a stored
    # medium break above that, it must come back LOW, not medium
    db.set_setting(scorer.TIER_BREAKS_KEY, _json.dumps({"medium": 2.5, "high": 4.0}))
    _score, tier = scorer.calculate_score("203.0.113.9")
    assert tier == ConfidenceTier.LOW
    db.set_setting(scorer.TIER_BREAKS_KEY, _json.dumps({"medium": 1.1, "high": 4.0}))
    _score, tier = scorer.calculate_score("203.0.113.9")
    assert tier == ConfidenceTier.MEDIUM


def test_legacy_method_preserves_fixed_gates(db):
    """method: legacy keeps the old count/score thresholds byte-for-byte."""
    db.add_indicator("203.0.113.9", "a", {})
    db.add_indicator("203.0.113.9", "b", {})
    db.add_indicator("203.0.113.9", "c", {})
    scorer = ConfidenceScorer(db, CONFIG)   # CONFIG pins method: legacy
    _score, tier = scorer.calculate_score("203.0.113.9")
    assert tier == ConfidenceTier.HIGH      # 3 sources, fresh -> high


def test_package_version_matches_pyproject():
    """__version__ sat at 1.1.0 for seven releases because nothing checked it;
    the footer now displays it, so drift would mislead operators verifying an
    upgrade. CI's tag gate compares pyproject; this ties __init__ to it."""
    import tomllib
    from threatfeedme import __version__
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    with open(os.path.join(root, "pyproject.toml"), "rb") as f:
        assert tomllib.load(f)["project"]["version"] == __version__


# ------------------------------------------- plumbing sync + env loading ----

def test_sync_fixes_plumbing_of_enabled_default(db):
    """The OTX weekend bug: an opt-in feed must receive shipped plumbing
    fixes (url/scraper) even after the operator enabled it and it ran —
    enabling is a preference, not a plumbing edit. Preferences survive."""
    db.seed_feeds_from_config({"feeds": [
        {"name": "otx", "url": "http://otx/old-export", "requires_auth": True,
         "auth_env": "OTX_API_KEY", "enabled": False},
    ]})
    db.set_feed_enabled("otx", True)   # operator opts in (old gate froze this)
    actions = db.sync_default_feeds({"feeds": [
        {"name": "otx", "url": "http://otx/new-pulses", "requires_auth": True,
         "auth_env": "OTX_API_KEY", "scraper": "otx_pulses", "enabled": False},
    ]})
    assert actions["updated"] == ["otx"]
    feed = db.get_feed_source("otx")
    assert feed.url == "http://otx/new-pulses" and feed.scraper == "otx_pulses"
    assert feed.enabled is True   # the operator's opt-in survives the fix


def test_sync_plumbing_update_is_idempotent(db):
    db.seed_feeds_from_config({"feeds": [{"name": "a", "url": "http://a/old"}]})
    cfg = {"feeds": [{"name": "a", "url": "http://a/new"}]}
    assert db.sync_default_feeds(cfg)["updated"] == ["a"]
    assert db.sync_default_feeds(cfg)["updated"] == []


def test_load_env_file_fills_empty_env_var(tmp_path, monkeypatch):
    """compose's `VAR=${VAR:-}` mappings inject EMPTY env vars for anything
    the host doesn't define; those must not shadow a dashboard-saved key on
    the data volume (the key silently vanished on every restart)."""
    from threatfeedme.core import load_env_file
    envfile = tmp_path / ".env"
    envfile.write_text("OTX_API_KEY=real-key-123\nOTHER=from-file\n")
    monkeypatch.setenv("OTX_API_KEY", "")            # present but empty
    monkeypatch.setenv("OTHER", "operator-wins")     # real operator value
    load_env_file(str(envfile))
    assert os.environ["OTX_API_KEY"] == "real-key-123"   # filled
    assert os.environ["OTHER"] == "operator-wins"        # not overridden


# --------------------------------------------------- HoneyDB scraper ----

class _FakeHoneyDBResponse:
    def __init__(self, body):
        self.text = body
        self.status_code = 200
    def raise_for_status(self):
        pass


def _honeydb_feed(name="honeydb_bad_hosts", url="https://honeydb.io/api/bad-hosts"):
    return FeedSource(name=name, url=url, feed_type=FeedType.THREAT_INTEL,
                      weight=1.0, update_interval=3600, requires_auth=True,
                      auth_env="HONEYDB_API_ID,HONEYDB_API_KEY", scraper="honeydb")


def test_honeydb_scraper_sends_both_headers_and_flattens(db, monkeypatch):
    monkeypatch.setenv("HONEYDB_API_ID", "id-123")
    monkeypatch.setenv("HONEYDB_API_KEY", "key-456")
    seen = {}

    def fake_get(url, headers):
        seen["url"], seen["headers"] = url, headers
        return _FakeHoneyDBResponse(
            '[{"remote_host": "45.13.2.9", "count": "4"},'
            ' {"remote_host": "91.92.242.236", "count": "1"}]')

    ing = FeedIngestor(db)
    monkeypatch.setattr(ing, "_get_with_retries", fake_get)
    parsed = ing.fetch_feed(_honeydb_feed())
    assert seen["headers"] == {"X-HoneyDb-ApiId": "id-123",
                               "X-HoneyDb-ApiKey": "key-456"}
    assert sorted(e["ip"] for e in parsed) == ["45.13.2.9", "91.92.242.236"]


def test_honeydb_scraper_names_missing_credentials(db, monkeypatch):
    monkeypatch.delenv("HONEYDB_API_ID", raising=False)
    monkeypatch.setenv("HONEYDB_API_KEY", "key-456")
    ing = FeedIngestor(db)
    with pytest.raises(RuntimeError, match="HONEYDB_API_ID"):
        ing.fetch_feed(_honeydb_feed())


def test_honeydb_empty_window_is_not_an_error(db, monkeypatch):
    """/mydata is legitimately empty when your sensors saw no attacks in the
    last 24h — that must read as 'no new data', never as a failed scrape
    (the zero-indicator guard would otherwise error and, over time, let
    retention drain the feed's stored IPs)."""
    from threatfeedme.feed_ingestor import NOT_MODIFIED
    monkeypatch.setenv("HONEYDB_API_ID", "id-123")
    monkeypatch.setenv("HONEYDB_API_KEY", "key-456")
    ing = FeedIngestor(db)
    monkeypatch.setattr(ing, "_get_with_retries",
                        lambda url, headers: _FakeHoneyDBResponse("[]"))
    assert ing.fetch_feed(_honeydb_feed("honeydb_mydata")) is NOT_MODIFIED


def test_honeydb_rejects_non_list_response(db, monkeypatch):
    monkeypatch.setenv("HONEYDB_API_ID", "id-123")
    monkeypatch.setenv("HONEYDB_API_KEY", "key-456")
    ing = FeedIngestor(db)
    monkeypatch.setattr(ing, "_get_with_retries",
                        lambda url, headers: _FakeHoneyDBResponse('{"status": "error"}'))
    with pytest.raises(RuntimeError, match="response shape"):
        ing.fetch_feed(_honeydb_feed())


# ------------------------------------------------------ 429 retry policy ----

class _CodeResponse:
    def __init__(self, code, headers=None):
        self.status_code = code
        self.headers = headers or {}
        self.closed = False
    def close(self):
        self.closed = True
    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.exceptions.HTTPError(f"{self.status_code}")


def test_429_is_retried_honoring_retry_after(db, monkeypatch):
    """GitHub raw rate-limits per source IP and a refresh burst trips it
    (live-observed: hagezi 429'd hourly on prod). 429 is 'try again later',
    not a permanent client error — retry it, honoring Retry-After."""
    import threatfeedme.feed_ingestor as fi
    sleeps = []
    monkeypatch.setattr(fi, "_sleep", lambda s: sleeps.append(s))
    responses = [_CodeResponse(429, {"Retry-After": "7"}), _CodeResponse(200)]
    ing = FeedIngestor(db)
    monkeypatch.setattr(ing, "_get_following_redirects",
                        lambda url, headers: responses.pop(0))
    r = ing._get_with_retries("https://example.com/feed.txt", {})
    assert r.status_code == 200
    assert sleeps == [7]          # Retry-After honored, not the default backoff


def test_429_retry_after_is_capped_and_final_attempt_raises(db, monkeypatch):
    import threatfeedme.feed_ingestor as fi
    sleeps = []
    monkeypatch.setattr(fi, "_sleep", lambda s: sleeps.append(s))
    responses = [_CodeResponse(429, {"Retry-After": "99999"}),
                 _CodeResponse(429), _CodeResponse(429)]
    ing = FeedIngestor(db)
    monkeypatch.setattr(ing, "_get_following_redirects",
                        lambda url, headers: responses.pop(0))
    with pytest.raises(requests.exceptions.HTTPError):
        ing._get_with_retries("https://example.com/feed.txt", {})
    # hostile Retry-After capped; missing header falls back to backoff
    assert sleeps[0] == fi._RETRY_AFTER_CAP
    assert len(sleeps) == 2       # no sleep after the final failing attempt


# ------------------------------------------------------------ sightings ----


def test_sightings_appended_per_tick(db):
    """Sightings table records per-source per-tick presence in batch."""
    tick = "2026-08-18T00:00:00Z"
    present_map = {"203.0.113.77": True, "198.51.100.1": True}
    count = db.append_sightings("honeydb_mydata", present_map, tick)
    assert count == 2

    # Verify rows landed
    with db._cursor() as cur:
        cur.execute(
            "SELECT COUNT(*) FROM sightings WHERE source_name=? AND tick=?",
            ("honeydb_mydata", tick),
        )
        assert cur.fetchone()[0] == 2

    # UNIQUE(source_name, ip, tick): re-insert with same tick replaces
    db.append_sightings("honeydb_mydata", {"203.0.113.77": True}, tick)
    with db._cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM sightings")
        assert cur.fetchone()[0] == 2  # still 2

    # Different tick adds new rows
    tick2 = "2026-08-18T01:00:00Z"
    db.append_sightings("honeydb_mydata", {"203.0.113.77": True}, tick2)
    with db._cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM sightings")
        assert cur.fetchone()[0] == 3

    # Empty map is a no-op
    assert db.append_sightings("honeydb_mydata", {}, tick2) == 0


def test_other_4xx_still_fails_immediately(db, monkeypatch):
    import threatfeedme.feed_ingestor as fi
    monkeypatch.setattr(fi, "_sleep", lambda s: pytest.fail("must not retry 404"))
    ing = FeedIngestor(db)
    monkeypatch.setattr(ing, "_get_following_redirects",
                        lambda url, headers: _CodeResponse(404))
    assert ing._get_with_retries("https://example.com/x.txt", {}).status_code == 404
