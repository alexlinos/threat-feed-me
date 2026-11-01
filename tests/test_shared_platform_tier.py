"""Shared-hosting infrastructure must never earn force-HIGH on one curator's word.

Prod incident 2026-10-31: urlhaus_keyed reported `github.com`,
`raw.githubusercontent.com` and `codeload.github.com` — URLhaus names the
payload HOST, and malware hosts payloads on GitHub. Provenance force-HIGH put
those on the pushed domain tier, UniFi resolved them to GitHub's serving IPs
and blackholed GitHub for the whole LAN. The guard denies force-HIGH for
shared platforms; independent corroboration still earns HIGH.
"""
import pytest

from threatfeedme.database import Database
from threatfeedme.models import ConfidenceTier
from threatfeedme.scorer import (
    ConfidenceScorer, DEFAULT_SHARED_PLATFORMS, resolve_shared_platforms,
    shared_platform_for,
)

FEEDS = [{"name": "urlhaus_keyed", "feed_type": "threat_intel"}]


@pytest.fixture
def db(tmp_path):
    return Database(str(tmp_path / "shared-platform.db"))


def _scorer(db, high_confidence=None):
    hc = high_confidence if high_confidence is not None else {
        "authoritative_domain_feeds": ["urlhaus_keyed"]}
    cfg = {
        "feeds": [dict(f) for f in FEEDS],
        "scoring": {"tiering": {"method": "effective_votes"},
                    "high_confidence": hc}}
    # Authority is granted by provenance: the stored feed row must match the
    # configured one, exactly as at app startup, or force-HIGH is never
    # granted and the baseline tests would pass for the wrong reason.
    for f in cfg["feeds"]:
        f.setdefault("url", "https://%s.example/recent.csv" % f["name"])
    db.seed_feeds_from_config(cfg)
    return ConfidenceScorer(db, cfg)


def test_shared_platform_denies_force_high(db):
    """The exact prod case: one authoritative vote must not block GitHub."""
    t = _scorer(db)._tier_from_votes
    for value in ("raw.githubusercontent.com", "github.com",
                  "codeload.github.com", "donutsmp-mod.github.io"):
        assert t(1.0, ["urlhaus_keyed"], 1.1, 10.0, kind="domain",
                 value=value) == ConfidenceTier.LOW, value


def test_cloud_stores_and_paste_lockers_are_shared(db):
    """The 2026-11-01 sweep found 22 pub-<hash>.r2.dev buckets in prod HIGH.

    Each bucket belongs to one attacker, but every bucket resolves to
    Cloudflare's shared edge, so a hostname block becomes a Cloudflare block.
    Measured against the live keyed export: 105,580 of 121,677 URLs (86.8%)
    sit on platforms in this list, so coverage here is the difference between
    blocking a locker and blocking the internet's file hosting.
    """
    t = _scorer(db)._tier_from_votes
    for value in ("pub-0462440f54f44b9fb3474df61e32d6ba.r2.dev",
                  "commondatastorage.googleapis.com", "drive.google.com",
                  "mega.nz", "t.me", "paste.ee"):
        assert t(1.0, ["urlhaus_keyed"], 1.1, 10.0, kind="domain",
                 value=value) == ConfidenceTier.LOW, value


def test_shared_platform_for_names_the_platform():
    """The matcher returns the entry it hit, which is what the tag stores."""
    assert shared_platform_for("raw.githubusercontent.com") == "githubusercontent.com"
    assert shared_platform_for(
        "pub-0462440f54f44b9fb3474df61e32d6ba.r2.dev") == "r2.dev"
    assert shared_platform_for("EVIL-GitHub.COM") is None
    assert shared_platform_for("github.com.evil.tld") is None
    assert shared_platform_for("   ") is None
    assert shared_platform_for(None) is None
    assert shared_platform_for("github.com", platforms=("example.com",)) is None


def test_resolver_default_override_and_disable():
    """One reader for the config key, so ingest and scoring cannot diverge."""
    assert resolve_shared_platforms({}) is DEFAULT_SHARED_PLATFORMS
    assert resolve_shared_platforms(None) is DEFAULT_SHARED_PLATFORMS
    cfg = {"scoring": {"high_confidence": {
        "shared_platform_domains": [" GitHub.com ", ".gitlab.com", ""]}}}
    assert resolve_shared_platforms(cfg) == ("github.com", "gitlab.com")
    off = {"scoring": {"high_confidence": {"shared_platform_domains": []}}}
    assert resolve_shared_platforms(off) == ()


def test_ingest_tags_shared_platform_rows(db):
    """A demoted domain must say why, or it looks like the feed went quiet."""
    from threatfeedme.feed_ingestor import FeedIngestor
    rm = FeedIngestor(db=db, shared_platforms=("github.com", "r2.dev")).row_metadata
    assert rm({"ip": "github.com"}, "github.com", "domain") == {
        "shared_platform": "github.com"}
    assert rm({"ip": "x.r2.dev"}, "x.r2.dev", "domain") == {"shared_platform": "r2.dev"}
    assert rm({"ip": "evil.example"}, "evil.example", "domain") == {}
    assert rm({"ip": "github.com"}, "github.com", "ip") == {}
    assert rm({"ip": "1.2.3.4", "cidr": "1.2.3.0/24"}, "1.2.3.0/24", "ip") == {
        "cidr": "1.2.3.0/24"}
    # The tag must not crowd out the one key scoring actually reads.
    assert rm({"ip": "x.r2.dev", "cidr": "x.r2.dev"}, "x.r2.dev", "domain") == {
        "cidr": "x.r2.dev", "shared_platform": "r2.dev"}


def test_guard_and_ingest_share_one_matcher(db):
    """Two consumers, one rule: they cannot drift apart by construction."""
    s = _scorer(db)
    for value in ("github.com", "pub-1.r2.dev", "evil-github.com",
                  "malware.example-bad.tld", ""):
        assert s._is_shared_platform(value) == (
            shared_platform_for(value, s.shared_platforms) is not None), value


def test_ordinary_domain_still_gets_force_high(db):
    """The guard is scoped to shared platforms, not a blanket cap."""
    assert _scorer(db)._tier_from_votes(
        1.0, ["urlhaus_keyed"], 1.1, 10.0, kind="domain",
        value="malware-delivery.example-bad.tld") == ConfidenceTier.HIGH


def test_lookalike_suffixes_are_not_shared(db):
    """A suffix match must be a real subdomain boundary."""
    s = _scorer(db)
    assert s._is_shared_platform("evil-github.com") is False
    assert s._is_shared_platform("github.com.evil.tld") is False
    assert s._is_shared_platform("vercel.app.evil.tld") is False
    assert s._is_shared_platform("github.com") is True
    assert s._is_shared_platform("RAW.GitHubusercontent.COM") is True
    assert s._is_shared_platform("github.com.") is True
    assert s._is_shared_platform("") is False
    assert s._is_shared_platform(None) is False


def test_independent_witnesses_still_earn_high_for_shared(db):
    """Guard removes force-HIGH only; corroboration remains a path to HIGH."""
    assert _scorer(db)._tier_from_votes(
        3.0, ["urlhaus_keyed", "phishing_army", "openphish_community"],
        1.1, 10.0, kind="domain",
        value="raw.githubusercontent.com") == ConfidenceTier.HIGH


def test_ips_untouched_by_the_guard(db):
    assert _scorer(db)._tier_from_votes(
        1.0, ["urlhaus_keyed"], 1.1, 10.0, kind="ip",
        value="203.0.113.9") == ConfidenceTier.LOW


def test_config_overrides_and_disables_the_guard(db):
    """Operator config wins: an empty list disables, a custom list replaces."""
    off = _scorer(db, {"authoritative_domain_feeds": ["urlhaus_keyed"],
                       "shared_platform_domains": []})
    assert off._tier_from_votes(1.0, ["urlhaus_keyed"], 1.1, 10.0, kind="domain",
                                value="github.com") == ConfidenceTier.HIGH
    custom = _scorer(db, {"authoritative_domain_feeds": ["urlhaus_keyed"],
                          "shared_platform_domains": ["Evil.Example"]})
    assert custom._is_shared_platform("github.com") is False
    assert custom._is_shared_platform("payload.evil.example") is True


def test_callers_pass_the_value(db):
    """A guard nobody feeds is a guard nobody has: the rescore call sites must
    pass the indicator value, or shared platforms silently keep force-HIGH."""
    import inspect
    from threatfeedme import scorer as mod
    body = inspect.getsource(mod.ConfidenceScorer)
    assert "value=indicator.ip" in body
    assert "value=ip" in body
