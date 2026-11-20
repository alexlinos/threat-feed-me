"""Regression tests for security, correctness, and ML fixes from the 2.7.5 review.

Strictly offline; uses RFC 5737/2606 documentation ranges only.
"""
import os
import json
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock

import pytest
from fastapi import HTTPException

from threatfeedme import (
    applications,
    auth,
    catalog_sync,
    core,
    crowdsec,
    feed_ingestor as fi,
    middleware as mw,
    predictor,
    pusher_unifi,
    stix_ingest,
    train_predictor as tp,
    vendor_catalog,
)
from threatfeedme.database import Database
from threatfeedme.geo.data import CountryBuckets
from threatfeedme.models import FeedSource, FeedType
from threatfeedme.routers import feeds as feeds_router
from threatfeedme.routers import integrations as int_router
from threatfeedme.routers import system as sys_router
from threatfeedme.scorer import ConfidenceScorer


@pytest.fixture
def db(tmp_path):
    return Database(str(tmp_path / "hardening.db"))


# ---- 1. Remote catalog security & URL-change reset --------------------------

def test_catalog_rejects_local_file_entries(db):
    cfg = {"feeds": [{"name": "alpha", "url": "https://feeds.example.org/a.txt"}]}
    db.seed_feeds_from_config(cfg)
    evil = [
        {"name": "alpha", "url": "/etc/hosts", "local_file": True},
        {"name": "leak", "url": "/etc/passwd", "local_file": True},
        {"name": "bad_scheme", "url": "file:///etc/passwd"},
    ]
    cleaned = catalog_sync._keys_shipped_only(evil, cfg)
    assert cleaned == []
    # Defense-in-depth inside Database.sync_catalog_feeds too.
    db.sync_catalog_feeds(evil, auto_add=True)
    assert db.get_feed_source("alpha").local_file is False
    assert db.get_feed_source("alpha").url == "https://feeds.example.org/a.txt"
    assert db.get_feed_source("leak") is None
    assert db.get_feed_source("bad_scheme") is None


def test_catalog_http_get_arms_connect_time_ssrf_guard(monkeypatch):
    seen_guard = []

    class FakeResp:
        status_code = 200
        headers = {}
        encoding = "utf-8"

        def iter_content(self, chunk_size=65536, decode_unicode=False):
            yield b"catalog_version: 1\nfeeds: []\n"

        def close(self):
            pass

    def spy_get(url, **kwargs):
        seen_guard.append(getattr(fi._ssrf_guard, "active", False))
        return FakeResp()

    monkeypatch.setattr(catalog_sync.requests, "get", spy_get)
    monkeypatch.setattr(catalog_sync, "_require_public_url", lambda url: None)
    catalog_sync.http_get_text("https://raw.githubusercontent.com/alexlinos/threat-feed-me/main/feed_catalog.yaml")
    assert seen_guard == [True]
    assert getattr(fi._ssrf_guard, "active", False) is False


def test_catalog_redirect_without_location_fails_immediately(monkeypatch):
    calls = []

    class FakeRedirect:
        status_code = 302
        headers = {}

        def close(self):
            pass

    def fake_get(url, **kw):
        calls.append(url)
        return FakeRedirect()

    monkeypatch.setattr(catalog_sync.requests, "get", fake_get)
    monkeypatch.setattr(catalog_sync, "_require_public_url", lambda url: None)
    with pytest.raises(catalog_sync.CatalogError, match="Location"):
        catalog_sync.http_get_text("https://raw.githubusercontent.com/alexlinos/threat-feed-me/main/feed_catalog.yaml")
    assert len(calls) == 1


def test_catalog_dismiss_refuses_active_non_pending_feed(db, monkeypatch):
    db.add_feed(FeedSource(name="live_feed", url="https://feeds.example.org/live.txt"))
    monkeypatch.setitem(core.__dict__, "db", db)
    with pytest.raises(HTTPException) as exc:
        sys_router.catalog_pending_dismiss("live_feed", _=True, _csrf=True)
    assert exc.value.status_code == 404
    assert db.get_feed_source("live_feed") is not None


def test_sync_url_change_resets_validators_and_source_state(db):
    old_cfg = {"feeds": [{"name": "alpha", "url": "https://feeds.example.org/v1.txt"}]}
    db.seed_feeds_from_config(old_cfg)
    db.update_feed_stats("alpha", 1, "success")
    db.set_feed_http_cache("alpha", '"etag-v1"', "Mon, 01 Jan 2026 00:00:00 GMT")
    db.update_source_sightings("alpha", {"198.51.100.1"}, "2026-01-01T00:00:00+00:00")

    new_cfg = {"feeds": [{"name": "alpha", "url": "https://feeds.example.org/v2.txt"}]}
    db.sync_default_feeds(new_cfg)
    assert db.get_feed_http_cache("alpha") == (None, None)
    with db._cursor() as cur:
        assert cur.execute("SELECT COUNT(*) FROM source_state WHERE source_name = 'alpha'").fetchone()[0] == 0


# ---- 2. SSRF, redaction, redirects & IPv6 parser ----------------------------

@pytest.mark.parametrize("addr", [
    "64:ff9b::169.254.169.254",  # NAT64 metadata
    "224.0.0.1",                 # IPv4 multicast
    "ff02::1",                   # IPv6 multicast
    "::ffff:127.0.0.1",          # IPv4-mapped loopback
    "100.64.0.1",                # CGNAT
])
def test_ssrf_guard_rejects_nat64_multicast_and_mapped(addr):
    with pytest.raises(fi.UnsafeURLError):
        fi._assert_public("rebind.example", [addr])


def test_url_embedded_secret_with_special_chars_is_redacted(db, monkeypatch):
    monkeypatch.setenv("URLHAUS_AUTH_KEY", "abc+def/ghi=123")
    ing = fi.FeedIngestor(
        db,
        key_policy=fi.KeyPolicy([{"name": "uh", "url": "https://urlhaus-api.abuse.ch/v2/{auth_key}/x",
                                  "auth_env": "URLHAUS_AUTH_KEY"}]),
    )
    feed = FeedSource(name="uh", url="https://urlhaus-api.abuse.ch/v2/{auth_key}/x",
                      auth_env="URLHAUS_AUTH_KEY")
    resolved, secrets = ing._resolved_auth_url(feed)
    assert "abc%2Bdef%2Fghi%3D123" in resolved
    scrubbed = fi._redact(f"HTTPSConnectionPool: failed for {resolved}", secrets)
    assert "abc+def" not in scrubbed
    assert "abc%2Bdef" not in scrubbed
    assert "[redacted]" in scrubbed
    # Userinfo also scrubbed
    assert "secret" not in fi._redact("failed https://alice:secret@tip.example.org/taxii2/")


def test_redirect_scheme_downgrade_refused_for_url_key(db, monkeypatch):
    class Redir:
        status_code = 302
        headers = {"Location": "http://urlhaus-api.abuse.ch/v2/key/recent.csv"}

        def close(self):
            pass

    monkeypatch.setattr(fi.requests, "get", lambda *a, **k: Redir())
    ing = fi.FeedIngestor(db, allow_private_urls=True)
    with pytest.raises(RuntimeError, match="never travels off its host"):
        ing._get_following_redirects(
            "https://urlhaus-api.abuse.ch/v2/key/recent.csv",
            {},
            secrets=("key",),
            allowed_host="urlhaus-api.abuse.ch",
        )


def test_parse_feed_content_ipv6_bom_and_inline_comments():
    text = (
        "\ufeff# header 198.51.100.99\n"
        "198.51.100.1 # mirror 198.51.100.2\n"
        "203.0.113.0/24 ; SBL 198.51.100.3\n"
        "2001:4860:4860::8888\n"
        "2606:4700:4700::/48\n"
    )
    parsed = {e["ip"]: e for e in fi.parse_feed_content(text)}
    assert "198.51.100.1" in parsed
    assert "198.51.100.2" not in parsed
    assert "198.51.100.3" not in parsed
    assert "198.51.100.99" not in parsed
    assert parsed["203.0.113.0"]["cidr"] == "203.0.113.0/24"
    assert "2001:4860:4860::8888" in parsed
    assert parsed["2606:4700:4700::"]["cidr"] == "2606:4700:4700::/48"


def test_negative_retry_after_clamps_to_zero(db, monkeypatch):
    sleeps = []
    monkeypatch.setattr(fi, "_sleep", lambda d: sleeps.append(d))
    responses = iter([
        Mock(status_code=429, headers={"Retry-After": "-10"}, close=lambda: None),
        Mock(status_code=200, headers={}, close=lambda: None),
    ])
    ing = fi.FeedIngestor(db, allow_private_urls=True)
    monkeypatch.setattr(ing, "_get_following_redirects", lambda *a, **k: next(responses))
    resp = ing._get_with_retries("https://feeds.example.org/a.txt", {})
    assert resp.status_code == 200
    assert sleeps == [0]


def test_read_local_file_enforces_byte_cap(db, tmp_path, monkeypatch):
    p = tmp_path / "big.txt"
    p.write_bytes(b"a" * 2048)
    monkeypatch.setattr(fi, "_MAX_FETCH_BYTES", 1024)
    ing = fi.FeedIngestor(db)
    with pytest.raises(fi.ResponseTooLargeError):
        ing._read_local_file(str(p))


# ---- 3. Integrations security -----------------------------------------------

def test_unifi_default_session_ignores_env_proxies_and_refuses_redirect(monkeypatch):
    monkeypatch.setenv("UNIFI_USER", "svc")
    monkeypatch.setenv("UNIFI_PASSWORD", "pw")
    p = pusher_unifi.UniFiPusher(host="192.0.2.10", verify_ssl=True)
    assert p.session.trust_env is False

    class RedirResp:
        status_code = 307
        is_redirect = True
        headers = {"location": "https://evil.example/steal"}

    monkeypatch.setattr(p.session, "post", lambda *a, **kw: RedirResp())
    with pytest.raises(RuntimeError, match="redirect"):
        p.login()


def test_crowdsec_scheme_downgrade_and_tls_disable_clear_credentials(db, tmp_path, monkeypatch):
    monkeypatch.setitem(core.__dict__, "db", db)
    monkeypatch.setitem(core.__dict__, "config", {})
    monkeypatch.setattr(core, "env_file", lambda: str(tmp_path / ".env"))
    db.set_setting(crowdsec.SETTINGS_KEY, json.dumps({
        "lapi_url": "https://lapi.example.net:8080", "verify_ssl": True
    }))
    monkeypatch.setenv(crowdsec.ENV_MACHINE_PASSWORD, "secret-pw")
    res = int_router.crowdsec_save(
        int_router.CrowdSecSettingsRequest(lapi_url="http://lapi.example.net:8080"),
        _=True, _csrf=True,
    )
    assert res["credentials_cleared"] is True
    assert crowdsec.ENV_MACHINE_PASSWORD not in os.environ

    # Also clear when verify_ssl flips True -> False
    db.set_setting(crowdsec.SETTINGS_KEY, json.dumps({
        "lapi_url": "https://lapi.example.net:8080", "verify_ssl": True
    }))
    monkeypatch.setenv(crowdsec.ENV_BOUNCER_KEY, "bouncer-secret")
    res2 = int_router.crowdsec_save(
        int_router.CrowdSecSettingsRequest(verify_ssl=False),
        _=True, _csrf=True,
    )
    assert res2["credentials_cleared"] is True
    assert crowdsec.ENV_BOUNCER_KEY not in os.environ


def test_integration_credentials_reject_oversized_and_non_ascii(tmp_path, monkeypatch):
    monkeypatch.setattr(core, "env_file", lambda: str(tmp_path / ".env"))
    with pytest.raises(HTTPException) as e1:
        int_router.unifi_credentials(
            int_router.UniFiCredentialsRequest(username="a" * 5000, password="pw"),
            _=True, _csrf=True,
        )
    assert e1.value.status_code == 400
    with pytest.raises(HTTPException) as e2:
        int_router.crowdsec_credentials(
            int_router.CrowdSecCredentialsRequest(bouncer_key="héllo"),
            _=True, _csrf=True,
        )
    assert e2.value.status_code == 400
    assert not (tmp_path / ".env").exists()


# ---- 4. Vendor catalog & application lists ----------------------------------

def test_vendor_catalog_rejects_path_traversal_and_protects_custom_slug(db):
    base = "https://factory.example/catalog/"
    manifest = {
        "generated_at": "2026-11-20T00:00:00Z",
        "lists": [
            {"slug": "good-list", "name": "Good", "vendor": "V",
             "url": base + "good-list.txt", "entries": 1, "bytes": 10},
            {"slug": "traversal-list", "name": "Bad", "vendor": "V",
             "url": base + "../../other/evil.txt", "entries": 1, "bytes": 10},
        ],
    }
    cleaned = vendor_catalog._clean(manifest, base)
    assert [e["slug"] for e in cleaned["lists"]] == ["good-list"]

    # Operator owns a custom list with the same slug: toggling catalog OFF must not disable it.
    db.set_setting(vendor_catalog.CATALOG_URL_SETTING, base + "catalog.json")
    db.add_application_list("good-list", "https://operator.example/custom.txt",
                            "list", "", 3600, 8, 20, 50.0)
    vendor_catalog._cache.update(at=0.0, doc=None, error=None, next_try=0.0)

    class FakeResp:
        status_code = 200
        headers = {}
        def raise_for_status(self): pass
        def iter_content(self, chunk_size=65536, decode_unicode=False):
            yield json.dumps(manifest).encode()
        def close(self): pass

    with pytest.raises(vendor_catalog.NameTakenError):
        vendor_catalog.set_enabled(db, "good-list", False, get=lambda *a, **k: FakeResp())
    assert db.get_application_list("good-list")["enabled"] == 1


def test_delete_application_list_returns_true_without_pending(db):
    db.add_application_list("sample-list", "https://vendor.example/list.txt",
                            "list", "", 3600, 8, 20, 50.0)
    assert db.delete_application_list("sample-list") is True
    assert db.delete_application_list("sample-list") is False


def test_applications_guard_dedupe_and_bool_extraction():
    ok, _ = applications.guard_entry("https://.example.com/path")
    assert ok is False
    deduped = applications.select_entries(["192.0.2.1", "192.0.2.1/32"], hosts=True)
    assert deduped == ["192.0.2.1"]
    extracted = applications.extract_json_paths({"items": [True, False, "192.0.2.1", 42]}, "items[]")
    assert extracted == ["192.0.2.1", "42"]


# ---- 5. Functional, scorer, STIX, geo, ML & middleware fixes ----------------

def test_delete_upload_file_handles_oserror_without_nameerror(tmp_path, monkeypatch):
    monkeypatch.setitem(core.__dict__, "UPLOAD_DIR", os.path.realpath(str(tmp_path)))
    p = tmp_path / "custom.txt"
    p.write_text("198.51.100.1\n")
    monkeypatch.setattr(os, "remove", lambda _: (_ for _ in ()).throw(PermissionError("locked")))
    feed = FeedSource(name="custom", url=str(p), local_file=True)
    feeds_router._delete_upload_file(feed)  # must not raise NameError


def test_served_counts_matches_walk_with_never_block(db):
    db.add_indicators_bulk([("198.51.100.1", {}), ("198.51.100.2", {})], source="feed_a")
    db.add_never_block("198.51.100.1", "ip", reason="critical")
    wl_map = db.get_whitelist_map()
    assert sys_router._served_counts(db, wl_map) == sys_router._served_counts_walk(db, wl_map)


def test_whitelist_expires_at_normalized_to_utc(db):
    tz_plus5 = timezone(timedelta(hours=5))
    # Already expired in UTC (now - 10 min), expressed in +05:00 whose raw ISO string is > UTC now!
    expired_local = (datetime.now(timezone.utc) - timedelta(minutes=10)).astimezone(tz_plus5)
    db.add_to_whitelist("198.51.100.9", "temp", "tester", expires_at=expired_local)
    assert "198.51.100.9" not in db.get_whitelisted_ips()


def test_scorer_clamps_raised_floors_and_fails_closed_on_db_error(db):
    db.add_indicators_bulk([("198.51.100.1", {})], source="f1")
    db.add_indicators_bulk([("198.51.100.1", {})], source="f2")
    s1 = ConfidenceScorer(db, {"scoring": {"tiering": {"medium_floor": 1.1, "high_floor": 2.0}}})
    s1.recalculate_all_scores()
    # Raise high_floor without changing distribution: stored breaks must clamp up
    s2 = ConfidenceScorer(db, {"scoring": {"tiering": {"medium_floor": 1.5, "high_floor": 3.5}}})
    med_b, high_b = s2._breaks_for_votes([2.0], kind="ip")
    assert med_b >= 1.5 and high_b >= 3.5

    class BrokenDB:
        def get_feed_sources(self):
            raise RuntimeError("locked")
        def get_feed_fp_counts(self):
            return {}
        def get_feed_report_counts(self):
            return {}

    s_broken = ConfidenceScorer(BrokenDB(), {
        "scoring": {"high_confidence": {"authoritative_domain_feeds": ["openphish"]}},
        "feeds": [{"name": "openphish", "url": "https://openphish.com/feed.txt"}],
    })
    assert s_broken.authoritative_sources == set()


def test_stix_modified_semantic_comparison_and_trailing_op():
    objs = [
        {"type": "indicator", "id": "indicator--1", "modified": "2026-01-01T12:00:00Z",
         "pattern_type": "stix", "pattern": "[ipv4-addr:value = '198.51.100.1']"},
        {"type": "indicator", "id": "indicator--1", "modified": "2026-01-01T12:00:00.500Z",
         "revoked": True, "pattern_type": "stix",
         "pattern": "[ipv4-addr:value = '198.51.100.1']"},
        {"type": "indicator", "id": "indicator--2", "modified": "2026-01-01T12:00:00Z",
         "pattern_type": "stix", "pattern": "[ipv4-addr:value = '198.51.100.2' AND]"},
    ]
    vals, stats = stix_ingest.indicator_values(objs, "ip")
    assert vals == []
    assert stats["revoked"] == 1
    assert stats["conditional"] == 1


def test_geo_returns_zz_for_ipv6():
    buckets = CountryBuckets.load()
    assert buckets.country_for_ip_str("2001:4860:4860::8888") == "ZZ"
    assert buckets.country_for_ip(int(__import__("ipaddress").ip_address("2606:4700::1"))) == "ZZ"


def test_predictor_score_many_empty_and_consec_churn_reset(db):
    p = predictor.Predictor(db, {"predictor": {"enabled": False}})
    assert p.score_many([]) == {}

    base = datetime(2026, 8, 1, tzinfo=timezone.utc)
    sentinel = "192.0.2.254"
    ip = "198.51.100.7"
    db.add_indicator(ip, "talos")
    db.update_source_sightings("talos", {sentinel}, base.isoformat())
    # Cycle 1: qualifying 8h leave -> return (churn=1, streak=1)
    # Cycle 2: sub-floor 2h leave -> return (breaks streak -> 0)
    # Cycle 3: qualifying 8h leave -> return (churn=2, streak=1 -> max_streak=1)
    events = [
        (0, True), (1, False), (9, True),
        (10, False), (12, True),
        (13, False), (21, True),
    ]
    for h, present in events:
        cur = {sentinel, ip} if present else {sentinel}
        db.update_source_sightings("talos", cur, (base + timedelta(hours=h)).isoformat())
    fb = predictor.FeatureBuilder(db, now=base + timedelta(hours=24))
    vec = dict(zip(predictor.FEATURE_NAMES, fb.build(ip)))
    assert vec["churn_count"] == 2.0
    assert vec["max_consec_churn"] == 1.0


def test_train_predictor_excludes_right_censored_tail(db):
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    sentinel = "192.0.2.254"
    ip = "198.51.100.55"
    db.add_indicator(ip, "talos")
    db.update_source_sightings("talos", {sentinel}, base.isoformat())
    # 10 days of history, 24h horizon -> last snapshot must be <= t_max - 24h
    for day in range(1, 11):
        t_leave = base + timedelta(days=day)
        t_ret = t_leave + timedelta(hours=8)
        db.update_source_sightings("talos", {sentinel}, t_leave.isoformat())
        db.update_source_sightings("talos", {sentinel, ip}, t_ret.isoformat())
    _, _, _, snaps = tp.build_dataset(db, {"retention": {"churn_log_exclude": []}},
                                      horizon_h=24, snapshot_h=24)
    t_max = base + timedelta(days=10, hours=8)
    assert snaps
    assert snaps[-1][0] <= t_max - timedelta(hours=24)


def test_host_check_exempts_bare_taxii2_and_rejects_malformed_v6_host():
    assert "/taxii2" in mw._EXEMPT_PATHS
    assert mw.host_of_header("[::1]trailing") == "[::1]trailing"
    assert not mw.always_allowed(mw.host_of_header("[::1]trailing"))


# ---- Structural review fixes -----------------------------------------------

def test_cidr_whitelist_overlap_host_and_subnet_exclude_netblock(db):
    """A whitelisted host IP or sub-CIDR overlapping a CIDR indicator must
    suppress that CIDR indicator across row_included, scorer, query_indicators,
    and _served_counts (with full walk parity)."""
    from threatfeedme.exporter import is_included, row_included
    from threatfeedme.models import ALL_FEEDS, ConfidenceTier, ThreatIndicator
    from threatfeedme.routers.system import _served_counts, _served_counts_walk
    from threatfeedme.scorer import ConfidenceScorer

    # Netblock indicator 203.0.113.0/24 stored as network addr + metadata.cidr
    db.add_indicator("203.0.113.0", "spamhaus_drop", {"cidr": "203.0.113.0/24"})
    db.set_indicator_score("203.0.113.0", 0.9, "high")
    # Disjoint netblock 198.51.100.0/24
    db.add_indicator("198.51.100.0", "spamhaus_drop", {"cidr": "198.51.100.0/24"})
    db.set_indicator_score("198.51.100.0", 0.9, "high")

    # 1) Host IP inside 203.0.113.0/24 globally whitelisted
    db.add_to_whitelist("203.0.113.5", "our gateway", "op", feed_name=ALL_FEEDS)
    wl = db.get_whitelist_map()
    assert not row_included("203.0.113.0", ["spamhaus_drop"], wl, cidr="203.0.113.0/24")
    assert row_included("198.51.100.0", ["spamhaus_drop"], wl, cidr="198.51.100.0/24")

    # Scorer agrees
    scorer = ConfidenceScorer(db, {"scoring": {"tier_method": "legacy"}})
    ind = db.get_indicator("203.0.113.0")
    assert not is_included(ind, wl)
    _, _, surviving = scorer._evidence(ind, {}, wl)
    assert surviving is None

    # Fast path and exact walk agree on _served_counts
    assert _served_counts(db, wl) == _served_counts_walk(db, wl)
    served, _ = _served_counts(db, wl)
    assert served["ip"]["high"] == 1

    # 2) Sub-CIDR 198.51.100.128/25 (does not contain .0) scoped to tier:high
    db.add_to_whitelist("198.51.100.128/25", "subnet", "op", feed_name="tier:high")
    wl2 = db.get_whitelist_map()
    assert not row_included("198.51.100.0", ["spamhaus_drop"], wl2,
                            tier=ConfidenceTier.HIGH, cidr="198.51.100.0/24")
    assert row_included("198.51.100.0", ["spamhaus_drop"], wl2,
                        tier=ConfidenceTier.MEDIUM, cidr="198.51.100.0/24")
    assert _served_counts(db, wl2) == _served_counts_walk(db, wl2)

    # 3) Global sub-CIDR 198.51.100.128/25 excludes 198.51.100.0/24 from query_indicators
    db.add_to_whitelist("198.51.100.128/25", "subnet all", "op", feed_name=ALL_FEEDS)
    q = db.query_indicators()
    assert q["total"] == 0 and q["rows"] == []


def test_urlhaus_keyed_requires_auth_no_extra_header(db, monkeypatch):
    """urlhaus_keyed declares requires_auth: true in both config.yaml and
    feed_catalog.yaml, keeps URL-path auth (no Authorization header leak),
    and catalog sync never auto-enables it."""
    import pathlib
    import yaml
    from threatfeedme.credentials import KeyPolicy

    root = pathlib.Path(__file__).resolve().parent.parent
    cfg = yaml.safe_load((root / "config.yaml").read_text(encoding="utf-8"))
    cat = yaml.safe_load((root / "feed_catalog.yaml").read_text(encoding="utf-8"))
    cfg_entry = next(f for f in cfg["feeds"] if f["name"] == "urlhaus_keyed")
    cat_entry = next(f for f in cat["feeds"] if f["name"] == "urlhaus_keyed")
    assert cfg_entry["requires_auth"] is True
    assert cat_entry["requires_auth"] is True

    captured = {}

    class _Resp:
        status_code = 200
        headers = {}
        encoding = "utf-8"

        def iter_content(self, chunk_size=65536, decode_unicode=False):
            yield b"# id,url\n1,http://bad.example/a\n"

        def close(self):
            pass

        def raise_for_status(self):
            pass

    def fake_get(url, **kwargs):
        captured["url"] = url
        captured["headers"] = dict(kwargs.get("headers") or {})
        return _Resp()

    monkeypatch.setenv("URLHAUS_AUTH_KEY", "synthetic-key-xyz")
    monkeypatch.setattr(fi.requests, "get", fake_get)
    feed = FeedSource(**dict(cfg_entry, enabled=True))
    ing = fi.FeedIngestor(db, key_policy=KeyPolicy(cfg["feeds"]))
    out = ing._fetch_url(feed)
    assert "bad.example" in out
    assert "synthetic-key-xyz" in captured["url"]
    assert "Authorization" not in captured["headers"]


def test_unifi_pusher_mounts_single_socket_cert_pin_adapter(monkeypatch):
    """Real UniFi sessions with verify_ssl=False and a pinned cert mount
    _PinnedCertAdapter with urllib3 assert_fingerprint."""
    from threatfeedme import pusher_unifi as pu

    pin = "ab" * 32
    p = pu.UniFiPusher("192.0.2.1", verify_ssl=False, cert_sha256=pin)
    try:
        adapter = p.session.get_adapter("https://192.0.2.1")
        assert isinstance(adapter, pu._PinnedCertAdapter)
        assert adapter.poolmanager.connection_pool_kw["assert_fingerprint"] == pin
        assert adapter.poolmanager.connection_pool_kw["assert_hostname"] is False
    finally:
        p.session.close()

    # With verify_ssl=True, standard CA verification is used (no pin adapter)
    p_ca = pu.UniFiPusher("192.0.2.1", verify_ssl=True, cert_sha256=pin)
    try:
        adapter_ca = p_ca.session.get_adapter("https://192.0.2.1")
        assert not isinstance(adapter_ca, pu._PinnedCertAdapter)
    finally:
        p_ca.session.close()

    # Fingerprint mismatch SSLError during login translates to a clear RuntimeError
    import requests as _requests

    class _MismatchSession:
        verify = False
        def post(self, *a, **kw):
            raise _requests.exceptions.SSLError("Fingerprints did not match. Expected \"aa\", got \"bb\"")

    monkeypatch.setenv(pu.ENV_USER, "svc")
    monkeypatch.setenv(pu.ENV_PASSWORD, "pw")
    monkeypatch.setattr(pu, "cert_fingerprint", lambda host, timeout=20: pin)
    p_err = pu.UniFiPusher("192.0.2.1", verify_ssl=False, cert_sha256=pin, session=_MismatchSession())
    with pytest.raises(RuntimeError, match="certificate changed"):
        p_err.login()


def test_redundant_sqlite_indexes_dropped_and_autoindexes_used(db):
    """idx_sources_indicator and idx_whitelist_ip are dropped while SQLite
    autoindexes from UNIQUE constraints still serve lookups."""
    with db._cursor() as cur:
        indexes = {
            r[0] for r in cur.execute(
                "SELECT name FROM sqlite_master WHERE type = 'index'"
            ).fetchall()
        }
        assert "idx_sources_indicator" not in indexes
        assert "idx_whitelist_ip" not in indexes

        plan_src = " ".join(
            str(r["detail"]) for r in cur.execute(
                "EXPLAIN QUERY PLAN SELECT source_name FROM indicator_sources WHERE indicator_id = ?", (1,)
            ).fetchall()
        )
        plan_wl = " ".join(
            str(r["detail"]) for r in cur.execute(
                "EXPLAIN QUERY PLAN SELECT feed_name FROM whitelist WHERE ip = ?", ("203.0.113.1",)
            ).fetchall()
        )
        assert "sqlite_autoindex_indicator_sources_1" in plan_src
        assert "sqlite_autoindex_whitelist_1" in plan_wl
