"""
v2.0 domain-intel path: parser normalization, safety floor, kind-separated
serving (URLs + on-disk exports), and the TLD panel data.

The one regression that must never happen (D2): an IP feed URL emitting a
domain — a FortiGate address feed fed a hostname errors the whole import.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from threatfeedme.domains import normalize_domain, is_valid_domain, reserved_reason
from threatfeedme.feed_ingestor import parse_domain_feed_content
from threatfeedme.safety import SafetyFilter


# ==================== domains.py: normalization ====================

def test_normalize_lowercases_and_strips_trailing_dot():
    assert normalize_domain("EVIL.Example.COM.") == "evil.example.com"


def test_normalize_rejects_ips_and_cidrs_and_junk():
    assert normalize_domain("203.0.113.7") is None
    assert normalize_domain("203.0.113.0/24") is None
    assert normalize_domain("no-dot") is None
    assert normalize_domain("") is None
    assert normalize_domain("host:8080") is None
    assert normalize_domain("a..b.com") is None


def test_normalize_rejects_leading_trailing_hyphen_labels():
    # RFC 952/1123: every label must start and end with an alphanumeric.
    # A leading/trailing hyphen on a non-first label must never slip past
    # IDNA/UTS46 and land in the corpus as a "domain".
    assert normalize_domain("example.-com") is None        # TLD starts with '-'
    assert normalize_domain("evil.-example.com") is None    # label starts with '-'
    assert normalize_domain("sub-.example.com") is None     # label ends with '-'
    assert normalize_domain("example-.com") is None
    assert normalize_domain("evil.example.com") == "evil.example.com"


def test_normalize_idna_encodes_unicode_to_punycode():
    # Unicode and punycode spellings must collapse to the same stored value.
    uni = normalize_domain("bücher.example.com")
    assert uni == "xn--bcher-kva.example.com"
    assert normalize_domain("xn--bcher-kva.example.com") == uni


def test_normalize_enforces_dns_length_limits():
    assert normalize_domain(("a" * 64) + ".com") is None       # label > 63
    long_name = ".".join(["a" * 60] * 5)                        # name > 253
    assert normalize_domain(long_name) is None


def test_reserved_reason_flags_special_use_tlds():
    for d in ("host.test", "phish.example", "x.invalid", "svc.localhost",
              "printer.local", "market.onion"):
        assert reserved_reason(d), d
    assert reserved_reason("evil.example.com") is None  # .com, not .example


def test_is_valid_domain_only_accepts_canonical():
    assert is_valid_domain("evil.example.com")
    assert not is_valid_domain("EVIL.example.com")  # not canonical


# ==================== parser: parse_domain_feed_content ====================

def test_parser_hosts_file_format():
    content = (
        "# urlhaus hostfile\n"
        "0.0.0.0 malware-one.example.com\n"
        "127.0.0.1 malware-two.example.com\n"
    )
    got = {e["ip"] for e in parse_domain_feed_content(content)}
    assert got == {"malware-one.example.com", "malware-two.example.com"}
    assert all(e["kind"] == "domain" for e in parse_domain_feed_content(content))


def test_parser_plain_domain_lines_skip_ips_and_comments():
    content = (
        "; joewein style comment\n"
        "spam-domain.example.com\n"
        "203.0.113.9\n"          # bare IP line: never a domain indicator
        "198.51.100.0/24\n"      # CIDR line: never a domain indicator
    )
    got = {e["ip"] for e in parse_domain_feed_content(content)}
    assert got == {"spam-domain.example.com"}


def test_parser_url_lines_keep_host_strip_port_userinfo_www():
    content = (
        "https://www.phish-one.example.com/login\n"
        "http://phish-two.example.com:8080/x?y=z\n"
        "http://user:pass@phish-three.example.com/a\n"
        "http://203.0.113.44/kit.zip\n"   # IP-hosted URL: not a domain
    )
    got = {e["ip"] for e in parse_domain_feed_content(content)}
    assert got == {"phish-one.example.com", "phish-two.example.com",
                   "phish-three.example.com"}


def test_parser_dedupes_unicode_and_punycode_spellings():
    content = "bücher.evil-example.com\nxn--bcher-kva.evil-example.com\n"
    entries = parse_domain_feed_content(content)
    assert len(entries) == 1
    assert entries[0]["ip"] == "xn--bcher-kva.evil-example.com"


# ==================== safety: the domain floor (D4) ====================

def test_safety_rejects_reserved_tlds():
    s = SafetyFilter()
    assert s.excluded_reason("something.test")
    assert s.excluded_reason("intranet.local")
    assert s.excluded_reason("evil-but-real.example.com") is None


def test_safety_protects_core_known_good_and_subdomains():
    s = SafetyFilter()
    assert s.excluded_reason("microsoft.com")
    assert s.excluded_reason("update.microsoft.com")
    assert s.excluded_reason("deep.cdn.windowsupdate.com")
    # ...but lookalikes are NOT protected: suffix match requires a label edge.
    assert s.excluded_reason("evilmicrosoft.com") is None
    assert s.excluded_reason("microsoft.com.phish.example.net") is None


def test_safety_operator_domains_from_config():
    s = SafetyFilter.from_config({"safety": {"known_good_domains": ["MyOrg.Example.ORG"]}})
    assert s.excluded_reason("myorg.example.org")
    assert s.excluded_reason("mail.myorg.example.org")


def test_safety_domain_toggles_off():
    s = SafetyFilter(drop_private_reserved=False, protect_known_good=False)
    assert s.excluded_reason("something.test") is None
    assert s.excluded_reason("update.microsoft.com") is None


def test_safety_non_domain_non_ip_left_for_other_validation():
    assert SafetyFilter().excluded_reason("not a domain at all") is None


# ==================== serving: kind-separated URLs and exports ====================

@pytest.fixture(scope="module")
def client(tmp_path_factory):
    work = tmp_path_factory.mktemp("domains")
    db_path = str(work / "t.db").replace("\\", "/")
    out_dir = str(work / "output").replace("\\", "/")
    cfg_path = work / "config.yaml"
    cfg_path.write_text(
        "database:\n"
        f"  path: {db_path}\n"
        f"output: {{base_dir: {out_dir}, formats: [text, csv, json]}}\n"
        "feeds:\n"
        "  - {name: ipfeed, url: 'https://example.com/ips.txt', feed_type: threat_intel}\n"
        "  - {name: domfeed_a, url: 'https://example.com/a.txt', feed_type: threat_intel, indicator_kind: domain}\n"
        "  - {name: domfeed_b, url: 'https://example.com/b.txt', feed_type: threat_intel, indicator_kind: domain}\n"
        "  - {name: domfeed_c, url: 'https://example.com/c.txt', feed_type: threat_intel, indicator_kind: domain}\n"
        "safety: {drop_private_reserved: false, protect_known_good: true}\n"
        "dashboard: {auth_required: false}\n"
    )
    os.environ["CONFIG_PATH"] = str(cfg_path)
    # The CSRF module (runs earlier, alphabetically) re-imports the app with
    # auth ENABLED and auth.py caches that in module globals — purge and
    # re-import so this module's auth_required:false config takes effect.
    for m in list(sys.modules.keys()):
        if m == "threatfeedme" or m.startswith("threatfeedme."):
            sys.modules.pop(m, None)

    import yaml
    from threatfeedme import core
    core.reset()
    core.init(str(cfg_path))

    from threatfeedme.database import Database
    from threatfeedme.scorer import ConfidenceScorer

    db = Database(db_path)
    db.add_indicator("203.0.113.7", "ipfeed", {})
    # Three independent domain feeds agree -> the domain lands high-tier.
    for feed in ("domfeed_a", "domfeed_b", "domfeed_c"):
        db.add_indicator("tri-source.example.net", feed, {}, kind="domain")
    db.add_indicator("solo.example.net", "domfeed_a", {}, kind="domain")
    db.add_indicator("wl.example.net", "domfeed_a", {}, kind="domain")
    db.add_to_whitelist("wl.example.net", "false positive", "alex")
    ConfidenceScorer(db, yaml.safe_load(cfg_path.read_text())).recalculate_all_scores()
    # Pin tiers explicitly: these tests exercise cumulative kind-separated
    # serving, not the vote-tiering thresholds (the scorer has its own tests —
    # and a 3-feed fully-overlapping micro-corpus tiers everything low anyway).
    db.set_indicator_score("tri-source.example.net", 0.9, "high")
    db.set_indicator_score("solo.example.net", 0.2, "low")

    from starlette.testclient import TestClient
    from threatfeedme import dashboard
    return TestClient(dashboard.app, headers={"X-Requested-With": "XMLHttpRequest"})


def test_domain_feed_txt_serves_domains(client):
    r = client.get("/feeds/domains/all.txt")
    assert r.status_code == 200
    assert "tri-source.example.net" in r.text
    assert "solo.example.net" in r.text


def test_ip_feed_never_emits_a_domain(client):
    # THE regression test (D2).
    for tier in ("high", "medium", "low", "all"):
        body = client.get(f"/feeds/{tier}.txt").text
        assert "example.net" not in body, f"domain leaked into IP feed {tier}"
    assert "203.0.113.7" in client.get("/feeds/all.txt").text


def test_domain_feed_never_emits_an_ip(client):
    for tier in ("high", "medium", "low", "all"):
        body = client.get(f"/feeds/domains/{tier}.txt").text
        assert "203.0.113.7" not in body, f"IP leaked into domain feed {tier}"


def test_domain_feed_excludes_whitelisted(client):
    assert "wl.example.net" not in client.get("/feeds/domains/all.txt").text


def test_domain_feed_tiers_are_cumulative(client):
    # tri-source (3 independent feeds) must be in every cumulative tier file.
    for tier in ("high", "medium", "low", "all"):
        assert "tri-source.example.net" in client.get(f"/feeds/domains/{tier}.txt").text
    # single-source domain: low/all only.
    assert "solo.example.net" not in client.get("/feeds/domains/high.txt").text
    assert "solo.example.net" in client.get("/feeds/domains/all.txt").text


def test_domain_feed_csv_and_json(client):
    csv_body = client.get("/feeds/domains/all.csv").text
    assert "tri-source.example.net" in csv_body
    j = client.get("/feeds/domains/all.json").json()
    assert j["feed"] == "domains/all"
    values = {i["value"] for i in j["indicators"]}
    assert "tri-source.example.net" in values
    assert "203.0.113.7" not in values


def test_domain_feed_unknown_tier_404(client):
    assert client.get("/feeds/domains/bogus.txt").status_code == 404


def test_tld_endpoint_counts_last_label(client):
    r = client.get("/api/domains/tlds")
    assert r.status_code == 200
    data = dict((tld, n) for tld, n in r.json()["data"])
    # All corpus domains end in .net — and "net" must be the counted label,
    # not "example.net" (the first-dot INSTR bug this endpoint replaced).
    assert data.get("net", 0) >= 2
    assert not any("." in tld for tld in data)


def test_exports_split_by_kind(client):
    from threatfeedme import core, pipeline
    results = pipeline.export_tiers(core.db, core.config)
    ips_file = results["text"]["low"]
    dom_file = results["text"]["low_domains"]
    assert ips_file.endswith("low_confidence_ips.text")
    assert dom_file.endswith("low_confidence_domains.text")
    with open(ips_file) as f:
        ips_body = f.read()
    with open(dom_file) as f:
        dom_body = f.read()
    assert "203.0.113.7" in ips_body and "example.net" not in ips_body
    assert "tri-source.example.net" in dom_body and "203.0.113.7" not in dom_body
    assert "wl.example.net" not in dom_body  # whitelist applies to exports too


def test_export_stats_per_kind(client):
    from threatfeedme import core, pipeline
    stats = pipeline.get_export_stats(core.db)
    assert stats["total_unique_ips"] == 1
    assert stats["total_unique_domains"] == 2  # wl.example.net excluded
    assert stats["high_domain_count"] == 1     # tri-source only


# ==================== adversarial-review regressions ====================

def test_normalize_preserves_idna2008_deviation_characters():
    """faß.de and fass.de are SEPARATELY registrable (.de, since 2010) and
    browsers resolve faß.de as xn--fa-hia.de. The stdlib IDNA2003 codec
    casefolds ß→ss, which would store (and block!) the innocent fass.de
    while the actual threat never entered the corpus."""
    assert normalize_domain("faß.de") == "xn--fa-hia.de"
    assert normalize_domain("fass.de") == "fass.de"


def test_normalize_maps_unicode_dot_separators():
    assert normalize_domain("evil。example-uni.com") == "evil.example-uni.com"
    assert normalize_domain("update．microsoft．com") == "update.microsoft.com"
    assert normalize_domain("microsoft.com。") == "microsoft.com"
    # ...which means the safety floor holds for those spellings too.
    assert SafetyFilter().excluded_reason("update．microsoft．com")


def test_normalize_rejects_invalid_punycode_and_numeric_tlds():
    assert normalize_domain("xn--zzzzzzzz.com") is None   # undecodable alabel
    # All-numeric TLDs cannot exist in DNS; these shapes also pass both
    # parsers otherwise (leading-zero octets aren't IPs to ipaddress).
    assert normalize_domain("1.2.3.4.5") is None
    assert normalize_domain("01.2.3.4") is None
    assert normalize_domain("012.034.056.078") is None


def test_parser_multi_hostname_hosts_lines():
    got = {e["ip"] for e in parse_domain_feed_content(
        "0.0.0.0 multi-a.example.com multi-b.example.com\n")}
    assert got == {"multi-a.example.com", "multi-b.example.com"}


def test_parser_bom_and_inline_comments_and_embedded_quads():
    content = (
        "﻿0.0.0.0 bom-first.example.com\n"
        "inline-comment.example.com # seen 2026-08\n"
        "semi-comment.example.com ; spam\n"
        "10.0.0.1.nip.example.io\n"   # embeds a dotted quad; real infra shape
    )
    got = {e["ip"] for e in parse_domain_feed_content(content)}
    assert got == {"bom-first.example.com", "inline-comment.example.com",
                   "semi-comment.example.com", "10.0.0.1.nip.example.io"}


def test_parser_www_stripped_consistently_across_arms():
    content = (
        "https://www.split-id.example.com/login\n"
        "www.split-id.example.com\n"
        "0.0.0.0 www.split-id.example.com\n"
    )
    entries = parse_domain_feed_content(content)
    assert len(entries) == 1
    assert entries[0]["ip"] == "split-id.example.com"


def test_ip_parser_rejects_uncanonical_addresses():
    from threatfeedme.feed_ingestor import parse_feed_content
    got = {e["ip"] for e in parse_feed_content("01.2.3.4\n203.0.113.9\n")}
    # Leading-zero octets aren't parseable by ipaddress, so serving them
    # would error a strict firewall address import (D2).
    assert got == {"203.0.113.9"}


def test_bulk_upsert_never_flips_kind(tmp_path):
    """A value stored under one kind stays that kind, matching
    add_indicator: an ambiguous value reported by feeds of both kinds must
    not ping-pong between /feeds/* and /feeds/domains/*."""
    from threatfeedme.database import Database
    db = Database(str(tmp_path / "t.db"))
    db.add_indicator("stable.example.io", "domfeed", {}, kind="domain")
    db.add_indicators_bulk([("stable.example.io", {})], source="ipfeed", kind="ip")
    assert db.get_indicator("stable.example.io").kind == "domain"


def test_source_counts_per_kind(tmp_path):
    from threatfeedme.database import Database
    db = Database(str(tmp_path / "t.db"))
    db.add_indicator("203.0.113.1", "mixed_feed", {}, kind="ip")
    db.add_indicator("kindsplit.example.io", "mixed_feed", {}, kind="domain")
    assert db.get_source_counts()["mixed_feed"] == 2
    assert db.get_source_counts(kind="ip")["mixed_feed"] == 1
    assert db.get_source_counts(kind="domain")["mixed_feed"] == 1


def test_feed_source_rejects_unknown_kind():
    import pytest as _pytest
    from threatfeedme.models import FeedSource
    with _pytest.raises(Exception):
        FeedSource(name="x", url="https://example.com/x.txt", indicator_kind="domains")


def test_health_disabled_beats_stale():
    """A feed disabled after it has run must report 'disabled' (muted), not
    'stale' — a deliberately-off feed pinning itself above healthy rows in
    the problems-float sort forever was the bug."""
    from datetime import datetime, timedelta, timezone
    from threatfeedme.telemetry import _health
    from threatfeedme.models import FeedSource, FeedStats
    feed = FeedSource(name="off", url="https://example.com/x.txt",
                      update_interval=3600, enabled=False)
    stat = FeedStats(feed_name="off", total_indicators=10, status="success",
                     last_update=datetime.now(timezone.utc) - timedelta(days=3))
    h = _health(feed, stat, new_count=0)
    assert h["state"] == "disabled" and h["level"] == "muted"


# ==================== feed persistence: indicator_kind round-trip ====================

def test_feed_kind_survives_db_round_trip(tmp_path):
    """indicator_kind must survive add_feed -> get_feed_source: the ingest
    pipeline reads feeds from the DB, so a kind dropped at this layer means
    every domain feed silently degrades to the IP parser (the bug that
    shipped: the column existed but no write/read path touched it)."""
    from threatfeedme.database import Database
    from threatfeedme.models import FeedSource
    db = Database(str(tmp_path / "t.db"))
    db.add_feed(FeedSource(name="domfeed", url="https://example.com/d.txt",
                           indicator_kind="domain"))
    assert db.get_feed_source("domfeed").indicator_kind == "domain"
    assert db.get_feed_source("domfeed") in db.get_feed_sources()


def test_seed_and_sync_carry_kind_and_heal_wrong_rows(tmp_path):
    """Seeding writes the declared kind; sync_default_feeds treats kind as
    PLUMBING, so a database whose domain feeds were seeded as 'ip' (any DB
    created before the kind column was wired through) self-heals on the
    next startup."""
    from threatfeedme.database import Database
    from threatfeedme.models import FeedSource
    cfg = {"feeds": [{"name": "hagezi", "url": "https://example.com/ti.txt",
                      "feed_type": "threat_intel", "indicator_kind": "domain"}]}
    db = Database(str(tmp_path / "t.db"))
    db.seed_feeds_from_config(cfg)
    assert db.get_feed_source("hagezi").indicator_kind == "domain"
    # Simulate the pre-fix state: same feed stored as kind 'ip' with seed
    # provenance. Sync must correct the kind without touching preferences.
    with db._cursor() as cur:
        cur.execute("UPDATE feeds SET indicator_kind = 'ip', enabled = 0 WHERE name = 'hagezi'")
    assert db.get_feed_source("hagezi").indicator_kind == "ip"
    actions = db.sync_default_feeds(cfg)
    assert "hagezi" in actions["updated"]
    healed = db.get_feed_source("hagezi")
    assert healed.indicator_kind == "domain"
    assert healed.enabled is False  # preference untouched by the heal


# ==================== whitelist: domain matcher (D6) ====================

def test_matcher_wildcard_covers_apex_and_subdomains():
    from threatfeedme.models import WhitelistMatcher, ALL_FEEDS
    m = WhitelistMatcher({"*.corp.example.org": {ALL_FEEDS}})
    m.add_cidr_rules_from_keys()
    assert ALL_FEEDS in m.scoped_feeds("corp.example.org")
    assert ALL_FEEDS in m.scoped_feeds("mail.corp.example.org")
    assert ALL_FEEDS in m.scoped_feeds("a.b.corp.example.org")
    # Label-edge only: a lookalike never matches.
    assert m.scoped_feeds("evilcorp.example.org") == set()
    # And IPs never hit domain wildcards.
    assert m.scoped_feeds("203.0.113.1") == set()


def test_matcher_exact_domain_and_feed_scope():
    from threatfeedme.models import WhitelistMatcher, effective_sources
    m = WhitelistMatcher({"fp.example.org": {"domfeed_a"}})
    m.add_cidr_rules_from_keys()
    # Feed-scoped: only that feed's report is suppressed.
    assert effective_sources("fp.example.org", ["domfeed_a", "domfeed_b"], m) == ["domfeed_b"]
    assert effective_sources("other.example.org", ["domfeed_a"], m) == ["domfeed_a"]


def test_whitelist_api_accepts_exact_domain(client):
    r = client.post("/api/whitelist", json={
        "ip": "SOLO.example.NET.", "reason_code": "false_positive",
        "reason": "test", "added_by": "test",
    })
    assert r.status_code == 200 and r.json()["success"], r.text
    # Normalized key, excluded from serving immediately.
    assert "solo.example.net" not in client.get("/feeds/domains/all.txt").text
    r = client.request("DELETE", "/api/whitelist", params={"ip": "solo.example.net"})
    assert r.status_code == 200
    assert "solo.example.net" in client.get("/feeds/domains/all.txt").text


def test_whitelist_api_accepts_wildcard(client):
    r = client.post("/api/whitelist", json={
        "ip": "*.tri-source.example.net", "reason_code": "internal_asset",
        "reason": "test", "added_by": "test",
    })
    assert r.status_code == 200 and r.json()["success"], r.text
    # The apex indicator is suppressed by its own wildcard (apex + subdomains).
    assert "tri-source.example.net" not in client.get("/feeds/domains/all.txt").text
    r = client.request("DELETE", "/api/whitelist", params={"ip": "*.tri-source.example.net"})
    assert r.status_code == 200
    assert "tri-source.example.net" in client.get("/feeds/domains/all.txt").text


def test_whitelist_api_rejects_junk(client):
    r = client.post("/api/whitelist", json={
        "ip": "<script>alert(1)</script>", "reason_code": "other",
        "reason": "x", "added_by": "x",
    })
    assert r.status_code == 400


def test_whitelist_api_rejects_bogus_tier_scope(client):
    r = client.post("/api/whitelist", json={
        "ip": "203.0.113.200", "reason_code": "other",
        "reason": "x", "added_by": "x", "feed_name": "tier:hgih",
    })
    assert r.status_code == 400


def test_whitelist_delete_accepts_uncanonical_spelling(client):
    r = client.post("/api/whitelist", json={
        "ip": "*.Wildcard-Del.example.ORG.", "reason_code": "other",
        "reason": "x", "added_by": "x",
    })
    assert r.status_code == 200 and r.json()["success"], r.text
    # Delete by the ORIGINAL (un-normalized) spelling must find the
    # canonical stored key.
    r = client.request("DELETE", "/api/whitelist",
                       params={"ip": "*.Wildcard-Del.example.ORG."})
    assert r.status_code == 200, r.text


def test_wildcard_add_does_not_clear_anchor_fp_blame(client):
    from threatfeedme import core
    # FP-whitelist the apex: feeds get blamed.
    r = client.post("/api/whitelist", json={
        "ip": "solo.example.net", "reason_code": "false_positive",
        "reason": "fp", "added_by": "t",
    })
    assert r.status_code == 200 and r.json()["success"], r.text
    assert core.db.get_feed_fp_counts().get("domfeed_a", 0) == 1
    # Adding a RANGE entry sharing the anchor must not clear that blame.
    r = client.post("/api/whitelist", json={
        "ip": "*.solo.example.net", "reason_code": "internal_asset",
        "reason": "range", "added_by": "t",
    })
    assert r.status_code == 200 and r.json()["success"], r.text
    assert core.db.get_feed_fp_counts().get("domfeed_a", 0) == 1, \
        "range add silently cleared the anchor's FP attribution"
    # Cleanup: removing the FP entry withdraws the blame.
    client.request("DELETE", "/api/whitelist", params={"ip": "*.solo.example.net"})
    client.request("DELETE", "/api/whitelist", params={"ip": "solo.example.net"})
    assert core.db.get_feed_fp_counts().get("domfeed_a", 0) == 0


def test_query_indicators_with_global_wildcard(client):
    """The global-range slow path must stay CORRECT (perf is why it was
    rewritten: one wildcard used to materialize the full table with a
    correlated subquery per row on every dashboard search keystroke)."""
    from threatfeedme import core
    r = client.post("/api/whitelist", json={
        "ip": "*.tri-source.example.net", "reason_code": "internal_asset",
        "reason": "x", "added_by": "x",
    })
    assert r.status_code == 200 and r.json()["success"], r.text
    try:
        result = core.db.query_indicators(limit=100)
        values = {row["ip"] for row in result["rows"]}
        assert "tri-source.example.net" not in values
        assert "solo.example.net" in values
        assert result["total"] == len(values)
    finally:
        client.request("DELETE", "/api/whitelist",
                       params={"ip": "*.tri-source.example.net"})


def test_tld_counts_exclude_whitelisted_domains(client):
    from threatfeedme import core
    # wl.example.net is globally whitelisted in the fixture; a same-TLD
    # domain that isn't whitelisted keeps counting.
    data = dict(core.db.get_domain_tld_counts())
    total_net = data.get("net", 0)
    with core.db._cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM indicators WHERE kind='domain' AND ip LIKE '%.net'")
        raw_net = cur.fetchone()[0]
    assert total_net == raw_net - 1  # exactly the whitelisted one missing


# ==================== manual indicator add: domains ====================

def test_manual_add_domain_gets_domain_kind(client):
    r = client.post("/api/indicators", json={"ip": "manually-added.example.org"})
    assert r.status_code == 200 and r.json()["success"], r.text
    assert "manually-added.example.org" in client.get("/feeds/domains/all.txt").text
    # Kind separation holds for manual adds too.
    assert "manually-added.example.org" not in client.get("/feeds/all.txt").text
    client.request("DELETE", "/api/indicators/manually-added.example.org")


def test_manual_add_wildcard_rejected(client):
    r = client.post("/api/indicators", json={"ip": "*.example.org"})
    assert r.status_code == 400


def test_manual_add_known_good_domain_refused(client):
    r = client.post("/api/indicators", json={"ip": "update.microsoft.com"})
    assert r.status_code == 400
    assert "protected" in r.json()["detail"]


def test_manual_add_reserved_tld_refused(client):
    # This fixture runs with drop_private_reserved OFF (TEST-NET IPs), so
    # reserved-TLD rejection is toggle-tested in the SafetyFilter unit tests;
    # here we only assert the known-good floor holds through the API.
    r = client.post("/api/indicators", json={"ip": "gmail.com"})
    assert r.status_code == 400
