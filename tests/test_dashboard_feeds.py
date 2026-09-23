"""
Tests for the firewall-facing feed endpoints served by the dashboard.

The dashboard binds its database at import time from CONFIG_PATH, so the config
and a populated database are created before `dashboard` is imported.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    work = tmp_path_factory.mktemp("dash")
    db_path = str(work / "t.db").replace("\\", "/")
    cfg_path = work / "config.yaml"
    cfg_path.write_text(
        "database:\n"
        f"  path: {db_path}\n"
        "scoring:\n"
        "  source_weight: 0.45\n"
        "  reputation_weight: 0.33\n"
        "  recency_weight: 0.22\n"
        "  high_confidence: {min_sources: 3, min_score: 0.75}\n"
        "  medium_confidence: {min_sources: 2, min_score: 0.5}\n"
        "feeds:\n"
        "  - {name: spamhaus_drop, url: 'https://example.com/drop.txt', feed_type: spam, weight: 0.95}\n"
        "  - {name: custom_honeypot, url: './sample_honeypot_ips.txt', feed_type: custom, weight: 0.7, local_file: true}\n"
        # drop_private off so TEST-NET sample IPs (203.0.113.x etc., which are
        # is_private on Python 3.11) work in tests; known-good protection on.
        "safety: {drop_private_reserved: false, protect_known_good: true}\n"
        "dashboard: {auth_required: false}\n"
    )
    os.environ["CONFIG_PATH"] = str(cfg_path)

    from threatfeedme.database import Database
    from threatfeedme.scorer import ConfidenceScorer
    import yaml

    db = Database(db_path)
    db.add_indicator("45.66.230.0", "spamhaus_drop", {"cidr": "45.66.230.0/24"})
    db.add_indicator("45.66.230.99", "custom_honeypot", {})  # inside the /24
    db.add_indicator("198.51.100.5", "custom_honeypot", {})  # will be whitelisted
    db.add_to_whitelist("198.51.100.5", "mail relay", "alex")
    ConfidenceScorer(db, yaml.safe_load(cfg_path.read_text())).recalculate_all_scores()

    from starlette.testclient import TestClient
    from threatfeedme import core
    # Initialize core from THIS fixture's config explicitly. Relying on the
    # first lazy access broke when any earlier test had already touched core:
    # every test here then ran against that other DB.
    core.reset()
    core.init(str(cfg_path))
    from threatfeedme import dashboard

    # CSRF is enforced on all mutating endpoints regardless of auth, so the
    # client sends the same header the dashboard JS (apiFetch) always sets.
    return TestClient(dashboard.app, headers={"X-Requested-With": "XMLHttpRequest"})


def test_txt_feed_is_plaintext(client):
    r = client.get("/feeds/all.txt")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/plain")


def test_feed_emits_cidr_not_bare_network(client):
    body = client.get("/feeds/all.txt").text
    assert "45.66.230.0/24" in body
    assert "\n45.66.230.0\n" not in body


def test_feed_excludes_whitelisted(client):
    assert "198.51.100.5" not in client.get("/feeds/all.txt").text


def test_cidr_overlap_promotes_to_medium(client):
    # The honeypot IP inside the Spamhaus /24 gains a second source -> medium.
    assert "45.66.230.99" in client.get("/feeds/medium.txt").text


def test_unknown_feed_returns_404(client):
    assert client.get("/feeds/bogus.txt").status_code == 404


def test_homepage_shows_paste_url(client):
    body = client.get("/").text
    assert "Firewall feed URLs" in body
    assert "/feeds/medium.txt" in body


def _fake_request(headers=None, scheme="http", hostname="127.0.0.1", port=8080):
    """Minimal stand-in for a Starlette Request for _feed_base()."""
    from types import SimpleNamespace
    from starlette.datastructures import Headers
    return SimpleNamespace(
        headers=Headers(headers or {}),
        url=SimpleNamespace(scheme=scheme, hostname=hostname, port=port),
    )


def test_feed_base_does_not_double_port():
    # The Host header carries the port; _feed_base must not append it again.
    from threatfeedme.feed_helpers import _feed_base
    base = _feed_base(_fake_request(headers={"Host": "192.168.1.50:8080"}))
    assert base == "http://192.168.1.50:8080"
    assert ":8080:8080" not in base


def test_feed_base_loopback_swapped_for_lan_ip(monkeypatch):
    # A loopback host is unreachable from the firewall; it must be swapped out.
    # _lan_ip is stubbed: this tests the swap, not the test machine's network
    # (it used to fail on any host whose hostname didn't resolve).
    from threatfeedme import feed_helpers
    monkeypatch.setattr(feed_helpers, "_lan_ip", lambda: "192.168.1.50")
    for loopback in ("127.0.0.1:8080", "localhost:8080", "0.0.0.0:8080"):
        base = feed_helpers._feed_base(_fake_request(headers={"Host": loopback}))
        assert base == "http://192.168.1.50:8080", loopback


def test_lan_ip_prefers_the_default_route_source(monkeypatch):
    # hostname lookup alone returned 127.0.0.1 where the hostname doesn't
    # resolve; the route's source address answers without DNS
    from threatfeedme import feed_helpers

    class _Sock:
        def __init__(self, *a): pass
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def connect(self, addr): pass
        def getsockname(self): return ("10.20.30.40", 54321)

    monkeypatch.setattr(feed_helpers.socket, "socket", _Sock)
    monkeypatch.setattr(feed_helpers.socket, "getaddrinfo",
                        lambda *a, **k: (_ for _ in ()).throw(OSError("no dns")))
    assert feed_helpers._lan_ip() == "10.20.30.40"


def test_lan_ip_last_resort_is_loopback(monkeypatch):
    from threatfeedme import feed_helpers

    def _no_socket(*a):
        raise OSError("no route")

    monkeypatch.setattr(feed_helpers.socket, "socket", _no_socket)
    monkeypatch.setattr(feed_helpers.socket, "getaddrinfo",
                        lambda *a, **k: (_ for _ in ()).throw(OSError("no dns")))
    assert feed_helpers._lan_ip() == "127.0.0.1"


def test_feed_base_honors_reverse_proxy_without_port():
    # Behind an HTTPS proxy on 443, no port should appear in the URL.
    from threatfeedme.feed_helpers import _feed_base
    base = _feed_base(_fake_request(
        headers={"X-Forwarded-Proto": "https", "X-Forwarded-Host": "feeds.example.org"},
    ))
    assert base == "https://feeds.example.org"


def test_indicators_page_has_whitelist_form_with_tier_scope(client):
    body = client.get("/indicators").text
    assert 'id="wl-feed"' in body
    assert "All tiers" in body
    for tier_option in ("tier:high", "tier:medium", "tier:low"):
        assert tier_option in body  # tier scopes replace per-feed scopes


def test_dashboard_is_not_a_wall_of_ips(client):
    """The landing page answers 'what is this doing for me' — feed URLs and
    feed health. The 50k-row indicator list and whitelist live on their own
    page, reachable from the nav and the lookup box."""
    body = client.get("/").text
    assert "Firewall feed URLs" in body
    assert 'href="/indicators"' in body          # nav link
    assert 'id="lookup-ip"' in body              # single-IP lookup, not a list
    assert 'id="ind-body"' not in body           # indicator table gone
    assert 'id="wl-feed"' not in body            # whitelist form gone
    assert "<details" in body                    # firewall instructions collapsed


def test_feeds_table_carries_telemetry_inline(client):
    """Telemetry lives inside the feeds table — no separate intelligence
    section competing with the feed management surface."""
    body = client.get("/").text
    assert "Feed intelligence" not in body      # merged away
    assert 'class="feeds"' in body
    for col in ("Unique", "First 7d", "New 24h", "Status"):
        assert col in body
    assert "Overlap map" in body                # heatmap behind a disclosure
    # Wide tables scroll inside their own container, not the page.
    assert 'class="table-scroll"' in body


def test_telemetry_api_reports_contribution_and_health(client):
    j = client.get("/api/telemetry").json()
    assert {"rows", "overlap", "redundant_pairs"} <= set(j)
    by_name = {r["name"]: r for r in j["rows"]}
    # The fixture seeds spamhaus_drop + custom_honeypot with overlapping data.
    assert "spamhaus_drop" in by_name
    row = by_name["spamhaus_drop"]
    assert {"indicators", "exclusive", "exclusive_pct", "first_reports",
            "new", "health"} <= set(row)
    assert row["health"]["state"] in {"ok", "no new", "stale", "error",
                                      "never run", "disabled", "unknown"}


def test_indicators_page_prefills_search_from_query(client):
    """The dashboard lookup box deep-links here with ?q=<ip>."""
    body = client.get("/indicators?q=203.0.113.7").text
    assert 'id="ind-body"' in body
    assert 'value="203.0.113.7"' in body


def test_fp_review_and_clear_one(client):
    """The FP badge's modal lists a feed's flagged IPs and can forgive one,
    leaving the whitelist entry (and the feed exclusion) in place."""
    from threatfeedme import dashboard
    db = dashboard.db
    db.add_indicator("203.0.113.211", "spamhaus_drop", {})
    client.post("/api/whitelist", json={
        "ip": "203.0.113.211", "reason_code": "false_positive",
    })
    j = client.get("/api/feeds/spamhaus_drop/false-positives").json()
    assert j["count"] >= 1
    entry = next(e for e in j["entries"] if e["ip"] == "203.0.113.211")
    assert entry["whitelisted"] is True  # still whitelisted -> not orphaned

    r = client.delete("/api/feeds/spamhaus_drop/false-positives?ip=203.0.113.211")
    assert r.status_code == 200 and r.json()["cleared"] == 1
    assert db.get_feed_fp_counts().get("spamhaus_drop", 0) == 0
    # Forgiving the feed does NOT un-whitelist the IP.
    assert "203.0.113.211" in db.get_whitelisted_ips()
    client.delete("/api/whitelist?ip=203.0.113.211")


def test_fp_clear_all_for_feed(client):
    from threatfeedme import dashboard
    db = dashboard.db
    for ip in ("203.0.113.212", "203.0.113.213"):
        db.add_indicator(ip, "custom_honeypot", {})
        client.post("/api/whitelist", json={"ip": ip, "reason_code": "false_positive"})
    assert db.get_feed_fp_counts().get("custom_honeypot", 0) == 2
    r = client.delete("/api/feeds/custom_honeypot/false-positives")
    assert r.status_code == 200 and r.json()["cleared"] == 2
    assert db.get_feed_fp_counts().get("custom_honeypot", 0) == 0
    for ip in ("203.0.113.212", "203.0.113.213"):
        client.delete("/api/whitelist?ip=" + ip)


def test_fp_endpoints_404_for_unknown_feed(client):
    assert client.get("/api/feeds/nope/false-positives").status_code == 404
    assert client.delete("/api/feeds/nope/false-positives").status_code == 404


def test_tier_scoped_fp_feedback_cleared_on_remove(client):
    """Regression: a tier-scoped FP blames every reporting feed; removing the
    whitelist entry must clear that feedback (clearing by the literal
    'tier:...' scope matches nothing and left the FP penalty stuck)."""
    from threatfeedme import dashboard
    db = dashboard.db
    db.add_indicator("198.51.100.77", "spamhaus_drop", {})
    r = client.post("/api/whitelist", json={
        "ip": "198.51.100.77", "feed_name": "tier:high",
        "reason_code": "false_positive",
    })
    assert r.status_code == 200 and r.json()["success"] is True, r.text
    assert db.get_feed_fp_counts().get("spamhaus_drop", 0) >= 1

    r = client.delete("/api/whitelist?ip=198.51.100.77&feed=tier:high")
    assert r.status_code == 200, r.text
    assert db.get_feed_fp_counts().get("spamhaus_drop", 0) == 0


def test_tier_scoped_entry_excludes_from_that_tier_only(client):
    """A tier:medium entry hides the IP from medium.txt but not all.txt."""
    from threatfeedme import dashboard
    db = dashboard.db
    # 45.66.230.99 is medium in this fixture (honeypot IP inside spamhaus /24).
    assert "45.66.230.99" in client.get("/feeds/medium.txt").text
    r = client.post("/api/whitelist", json={
        "ip": "45.66.230.99", "feed_name": "tier:medium", "reason_code": "other",
    })
    assert r.status_code == 200 and r.json()["success"] is True, r.text
    try:
        assert "45.66.230.99" not in client.get("/feeds/medium.txt").text
        assert "45.66.230.99" in client.get("/feeds/all.txt").text
    finally:
        client.delete("/api/whitelist?ip=45.66.230.99&feed=tier:medium")


def test_feed_source_api_crud(client):
    r = client.post("/api/feeds", json={
        "name": "my_custom", "url": "https://example.com/f.txt",
        "feed_type": "custom", "weight": 0.6,
    })
    assert r.status_code == 200 and r.json()["success"] is True
    assert "my_custom" in [f["name"] for f in client.get("/api/feed-sources").json()]

    assert client.post("/api/feeds/my_custom/enabled?enabled=false").status_code == 200
    assert client.delete("/api/feeds/my_custom").status_code == 200
    assert client.delete("/api/feeds/my_custom").status_code == 404  # already gone


def test_upload_custom_list_creates_local_feed(client):
    from threatfeedme import dashboard
    content = b"# my list\n8.8.8.8\n1.2.3.0/24\n"
    r = client.post("/api/feeds/upload",
                    data={"name": "my_upload", "weight": "0.7"},
                    files={"file": ("list.txt", content, "text/plain")})
    assert r.status_code == 200, r.text
    assert "2 indicators" in r.json()["message"]

    feed = {f["name"]: f for f in client.get("/api/feed-sources").json()}["my_upload"]
    assert feed["local_file"] is True
    # Stored file must live inside the uploads directory (boundary check).
    assert dashboard._is_within_uploads(feed["url"])
    assert os.path.realpath(feed["url"]).startswith(os.path.realpath(dashboard.UPLOAD_DIR))


def test_upload_path_traversal_is_contained(client):
    from threatfeedme import dashboard
    r = client.post("/api/feeds/upload",
                    data={"name": "../../etc/evil"},
                    files={"file": ("x.txt", b"9.9.9.9\n", "text/plain")})
    assert r.status_code == 200, r.text
    feed = {f["name"]: f for f in client.get("/api/feed-sources").json()}.get(
        r.json()["message"].split("'")[1])
    # Whatever the slug, the file cannot escape the uploads directory.
    assert dashboard._is_within_uploads(feed["url"])
    assert ".." not in os.path.relpath(feed["url"], dashboard.UPLOAD_DIR)


def test_upload_rejects_binary(client):
    r = client.post("/api/feeds/upload", data={"name": "bin"},
                    files={"file": ("x.bin", b"\x00\x01\x02 8.8.8.8", "application/octet-stream")})
    assert r.status_code == 415


def test_upload_rejects_no_indicators(client):
    r = client.post("/api/feeds/upload", data={"name": "empty"},
                    files={"file": ("x.txt", b"just some words, no ips\n", "text/plain")})
    assert r.status_code == 422


def test_upload_rejects_non_utf8(client):
    # Invalid UTF-8 (lone 0xFF bytes, no null byte) must be rejected, not
    # silently mangled and stored.
    r = client.post("/api/feeds/upload", data={"name": "latin"},
                    files={"file": ("x.txt", b"8.8.8.8 \xff\xfe bad bytes", "text/plain")})
    assert r.status_code == 415


def test_indicator_delete_removes_and_whitelists(client):
    from threatfeedme import dashboard
    client.post("/api/indicators", json={"ip": "198.19.7.7"})
    assert client.delete("/api/indicators/198.19.7.7").status_code == 200
    assert dashboard.db.get_indicator("198.19.7.7") is None
    # Removal globally whitelists so a refresh won't bring it back.
    assert "198.19.7.7" in dashboard.db.get_whitelisted_ips()


def test_upload_rejects_oversize(client):
    big = (b"8.8.8.8\n" * (dashboard_max() // 8 + 1000))
    r = client.post("/api/feeds/upload", data={"name": "big"},
                    files={"file": ("x.txt", big, "text/plain")})
    assert r.status_code == 413


def dashboard_max():
    from threatfeedme import dashboard
    return dashboard.MAX_UPLOAD_BYTES


def test_adding_an_existing_feed_name_needs_explicit_overwrite(client):
    feed = {"name": "dup_feed", "url": "https://example.com/a.txt", "feed_type": "custom"}
    assert client.post("/api/feeds", json=feed).status_code == 200
    # same name, different URL: refused, the original is untouched
    r = client.post("/api/feeds", json={**feed, "url": "https://example.com/b.txt"})
    assert r.status_code == 409 and "already exists" in r.json()["detail"]
    urls = {f["name"]: f["url"] for f in client.get("/api/feed-sources").json()}
    assert urls["dup_feed"] == "https://example.com/a.txt"
    r = client.post("/api/feeds", json={**feed, "url": "https://example.com/b.txt",
                                        "overwrite": True})
    assert r.status_code == 200
    urls = {f["name"]: f["url"] for f in client.get("/api/feed-sources").json()}
    assert urls["dup_feed"] == "https://example.com/b.txt"
    client.delete("/api/feeds/dup_feed")


def test_adding_a_feed_that_points_inside_the_network_is_refused(client, monkeypatch):
    from threatfeedme import feed_ingestor
    monkeypatch.setattr(feed_ingestor, "_host_addresses", lambda h: ["169.254.169.254"])
    r = client.post("/api/feeds", json={"name": "metadata", "feed_type": "custom",
                                        "url": "http://metadata.example/latest"})
    assert r.status_code == 400 and "non-public" in r.json()["detail"]
    assert "metadata" not in [f["name"] for f in client.get("/api/feed-sources").json()]


def test_an_upload_cannot_take_over_a_remote_feeds_name(client):
    client.post("/api/feeds", json={"name": "remote_one", "feed_type": "custom",
                                    "url": "https://example.com/r.txt"})
    r = client.post("/api/feeds/upload", data={"name": "remote_one"},
                    files={"file": ("l.txt", b"198.51.100.7\n", "text/plain")})
    assert r.status_code == 409
    # re-uploading your OWN list under its name is how it gets updated
    for body in (b"198.51.100.7\n", b"198.51.100.8\n"):
        r = client.post("/api/feeds/upload", data={"name": "my_upload"},
                        files={"file": ("l.txt", body, "text/plain")})
        assert r.status_code == 200, r.text
    client.delete("/api/feeds/remote_one")
    client.delete("/api/feeds/my_upload")


def test_whitelist_errors_are_http_errors_not_200_false(client, monkeypatch):
    from threatfeedme import core
    r = client.post("/api/whitelist", json={"ip": "198.51.100.77", "reason_code": "other",
                                            "expires_at": "next tuesday"})
    assert r.status_code == 400 and "expires_at" in r.json()["detail"]

    def boom(*a, **k):
        raise RuntimeError("disk I/O error at /secret/path")
    monkeypatch.setattr(core.db, "add_to_whitelist", boom)
    r = client.post("/api/whitelist", json={"ip": "198.51.100.77", "reason_code": "other"})
    assert r.status_code == 500 and "/secret/path" not in r.text


def test_the_matrix_says_whether_a_firewall_is_polling(client):
    import re
    from threatfeedme import dashboard, polls
    client.get("/feeds/high.txt", headers={"User-Agent": "FortiGate (FortiOS 7.4)"})
    body = client.get("/").text
    assert re.search(r"polled (just now|\d+m ago) by FortiGate", body)
    assert "not polled yet" in body                  # the cells nothing fetched
    entry = polls.snapshot(dashboard.db)["high.txt"]
    assert set(entry) == {"at", "count", "agent"}    # no client address stored


def test_poll_keys_come_from_routes_not_raw_paths(client):
    from threatfeedme import dashboard, polls
    client.get("/feeds/nope.txt")                     # 404: unknown feed, not recorded
    client.get("/feeds/domains/medium.json", headers={"User-Agent": "x\x01y"})
    snap = polls.snapshot(dashboard.db)
    assert "nope.txt" not in snap and snap["domains/medium.json"]["agent"] == "xy"


def test_system_panel_shows_operational_facts(client):
    body = client.get("/").text
    for text in ("System</b>", "Last backup", "Vote grace", "Predictor", "/taxii2/"):
        assert text in body, text


def test_local_file_feed_outside_uploads_is_rejected(client):
    # Adding a local-file feed pointing at an arbitrary path must be blocked.
    r = client.post("/api/feeds", json={
        "name": "evil", "url": "/etc/passwd", "feed_type": "custom",
        "local_file": True,
    })
    assert r.status_code == 400


def test_settings_api_roundtrip(client):
    assert client.get("/api/settings").json()["refresh_interval_minutes"] == 60
    assert client.post("/api/settings", json={"refresh_interval_minutes": 30}).status_code == 200
    assert client.get("/api/settings").json()["refresh_interval_minutes"] == 30
    assert client.post("/api/settings", json={"refresh_interval_minutes": 0}).status_code == 400


def test_restore_defaults_api(client):
    # Remove a seeded default, then restore it via the API.
    assert client.delete("/api/feeds/spamhaus_drop").status_code == 200
    r = client.post("/api/feeds/restore-defaults")
    assert r.status_code == 200
    assert "spamhaus_drop" in r.json()["added"]
    assert "spamhaus_drop" in [f["name"] for f in client.get("/api/feed-sources").json()]


def test_indicator_add_view_remove(client):
    # Add a manual indicator.
    assert client.post("/api/indicators", json={"ip": "203.0.113.45"}).status_code == 200
    # It shows up in the merged view (searchable).
    found = client.get("/api/indicators?q=203.0.113.45").json()
    assert found["total"] >= 1
    assert any(r["ip"] == "203.0.113.45" for r in found["indicators"])
    # Remove it -> excluded from the view and globally whitelisted.
    assert client.delete("/api/indicators/203.0.113.45").status_code == 200
    after = client.get("/api/indicators?q=203.0.113.45").json()
    assert not any(r["ip"] == "203.0.113.45" for r in after["indicators"])
    assert "203.0.113.45" in {e["ip"] for e in client.get("/api/whitelist").json()}


def test_indicator_add_cidr_and_reject_invalid(client):
    assert client.post("/api/indicators", json={"ip": "198.18.0.0/24"}).status_code == 200
    assert any(r["value"] == "198.18.0.0/24"
               for r in client.get("/api/indicators?q=198.18.0.0").json()["indicators"])
    assert client.post("/api/indicators", json={"ip": "not-an-ip"}).status_code == 400


def test_indicator_detail_shows_sources(client):
    client.post("/api/indicators", json={"ip": "203.0.113.77"})
    j = client.get("/api/indicators/203.0.113.77").json()
    assert j["ip"] == "203.0.113.77"
    assert "manual" in j["sources"]


def test_false_positive_whitelist_blames_feed(client):
    from threatfeedme import dashboard
    # Seed an indicator reported by a specific feed, then whitelist it as a
    # false positive scoped to that feed.
    dashboard.db.add_indicator("45.33.0.9", "custom_honeypot", {})
    r = client.post("/api/whitelist", json={
        "ip": "45.33.0.9", "feed_name": "custom_honeypot",
        "reason_code": "false_positive", "reason": "not malicious",
    })
    assert r.status_code == 200 and r.json()["success"] is True
    assert dashboard.db.get_feed_fp_counts().get("custom_honeypot", 0) >= 1
    # Removing the whitelist entry withdraws the feedback.
    client.delete("/api/whitelist?ip=45.33.0.9&feed=custom_honeypot")
    assert dashboard.db.get_feed_fp_counts().get("custom_honeypot", 0) == 0


def test_risk_accepted_whitelist_records_no_feedback(client):
    from threatfeedme import dashboard
    dashboard.db.add_indicator("45.33.0.10", "custom_honeypot", {})
    client.post("/api/whitelist", json={
        "ip": "45.33.0.10", "feed_name": "custom_honeypot",
        "reason_code": "risk_accepted",
    })
    assert dashboard.db.get_feed_fp_counts().get("custom_honeypot", 0) == 0


def test_invalid_reason_code_rejected(client):
    r = client.post("/api/whitelist", json={"ip": "45.9.9.9", "reason_code": "bogus"})
    assert r.status_code == 400


def test_manual_add_rejects_known_good(client):
    # 8.8.8.8 must never be addable (protect_known_good on in the fixture).
    r = client.post("/api/indicators", json={"ip": "8.8.8.8"})
    assert r.status_code == 400
    assert "infrastructure" in r.json()["detail"]
    # An ordinary global IP is fine.
    assert client.post("/api/indicators", json={"ip": "45.77.88.99"}).status_code == 200


def test_feed_name_and_url_validation(client):
    # Bad name (would be an XSS vector if rendered).
    bad = client.post("/api/feeds", json={"name": "<script>", "url": "https://x/y.txt"})
    assert bad.status_code == 400
    # Non-http scheme rejected for remote feeds.
    scheme = client.post("/api/feeds", json={"name": "evil", "url": "file:///etc/passwd"})
    assert scheme.status_code == 400


def test_whitelist_free_text_is_html_escaped(client):
    # added_by is free text; a script payload must be escaped, not rendered raw.
    client.post("/api/whitelist", json={
        "ip": "45.11.22.33", "reason_code": "other",
        "added_by": "<script>alert(1)</script>",
    })
    body = client.get("/indicators").text  # whitelist table moved off the dashboard
    assert "<script>alert(1)</script>" not in body
    assert "&lt;script&gt;" in body


def test_whitelist_invalid_ip_rejected(client):
    r = client.post("/api/whitelist", json={"ip": "not-an-ip", "reason_code": "other"})
    assert r.status_code == 400


def test_cidr_whitelist_records_no_unattributable_feedback(client):
    from threatfeedme import dashboard
    # Whitelisting a CIDR as a false positive must NOT create feed feedback
    # (it has no single reporting indicator to attribute), but must still
    # suppress the range.
    dashboard.db.add_indicator("77.90.1.5", "custom_honeypot", {})
    before = dict(dashboard.db.get_feed_fp_counts())
    r = client.post("/api/whitelist", json={
        "ip": "77.90.1.0/24", "feed_name": "custom_honeypot",
        "reason_code": "false_positive",
    })
    assert r.status_code == 200
    assert dashboard.db.get_feed_fp_counts() == before  # no new FP attribution
    assert "77.90.1.5" not in client.get("/feeds/all.txt").text  # still suppressed


def test_whitelist_cidr_suppresses_contained_ip_end_to_end(client):
    from threatfeedme import dashboard
    # An indicator inside a range, then whitelist the whole range via the API.
    dashboard.db.add_indicator("77.88.99.10", "custom_honeypot", {})
    dashboard.db.set_indicator_score("77.88.99.10", 0.6, "low")
    assert "77.88.99.10" in client.get("/feeds/all.txt").text
    r = client.post("/api/whitelist", json={"ip": "77.88.99.0/24", "reason_code": "other"})
    assert r.status_code == 200
    # Stored with its prefix so the matcher builds a CIDR rule...
    assert any(e["ip"] == "77.88.99.0/24" for e in client.get("/api/whitelist").json())
    # ...and the contained IP drops out of the served feed.
    assert "77.88.99.10" not in client.get("/feeds/all.txt").text


def test_api_key_set_status_clear_and_never_echoed(client):
    """Dashboard-saved API keys: written to the data-volume .env, exported to
    the process env immediately, reported only as configured true/false."""
    from threatfeedme import core
    var = "TFM_FEED_TEST_KEYED"
    r = client.post("/api/feeds", json={
        "name": "keyed_feed", "url": "https://example.com/keyed.txt",
        "feed_type": "threat_intel", "requires_auth": True,
        "auth_env": var, "auth_header": "X-API-KEY",
    })
    assert r.status_code == 200, r.text
    try:
        # Not configured yet.
        j = client.get("/api/feeds/keyed_feed/api-key").json()
        assert j == {"auth_env": var, "configured": False,
                     "vars": [{"name": var, "configured": False}]}

        # Set: persisted to .env AND applied to os.environ without restart.
        r = client.post("/api/feeds/keyed_feed/api-key", json={"api_key": "s3cret-token"})
        assert r.status_code == 200 and r.json()["configured"] is True
        assert os.environ.get(var) == "s3cret-token"
        assert f"{var}=s3cret-token" in open(core.env_file(), encoding="utf-8").read()

        # Status never echoes the key value.
        j = client.get("/api/feeds/keyed_feed/api-key").json()
        assert j["configured"] is True
        assert "s3cret" not in str(j)

        # Empty key clears both the file entry and the env var.
        r = client.post("/api/feeds/keyed_feed/api-key", json={"api_key": ""})
        assert r.json()["configured"] is False
        assert var not in open(core.env_file(), encoding="utf-8").read()
        assert var not in os.environ

        # A feed without auth_env cannot take a key.
        r = client.post("/api/feeds/spamhaus_drop/api-key", json={"api_key": "x"})
        assert r.status_code == 400
    finally:
        os.environ.pop(var, None)
        client.delete("/api/feeds/keyed_feed")


def test_load_env_file_never_overrides_real_env(tmp_path, monkeypatch):
    from threatfeedme import core
    p = tmp_path / ".env"
    p.write_text("A_TEST_VAR=fromfile\nB_TEST_VAR=filevalue\n# comment\nnot a kv line\n")
    monkeypatch.setenv("A_TEST_VAR", "fromenv")
    monkeypatch.delenv("B_TEST_VAR", raising=False)
    try:
        core.load_env_file(str(p))
        assert os.environ["A_TEST_VAR"] == "fromenv"   # real env wins
        assert os.environ["B_TEST_VAR"] == "filevalue"  # file fills the gap
    finally:
        os.environ.pop("B_TEST_VAR", None)


def test_refresh_guards(client):
    from threatfeedme import dashboard
    # Unknown feed -> 404 (no refresh started).
    assert client.post("/api/refresh?feed=does_not_exist").status_code == 404
    # Already-running -> 409.
    dashboard._refresh_state["running"] = True
    try:
        assert client.post("/api/refresh").status_code == 409
    finally:
        dashboard._refresh_state["running"] = False


def test_refresh_status_shows_running_immediately(client, monkeypatch):
    """The first status poll after POST /api/refresh must already report
    running=True — the dashboard polls right away, and if the flag were set
    inside the worker thread the UI would declare 'Refresh complete' and
    reload while the fetch was still starting."""
    import threading
    import time
    from threatfeedme import scheduler

    release = threading.Event()

    def slow_refresh(*args, **kwargs):
        release.wait(5)
        return {}

    monkeypatch.setattr(scheduler.pipeline, "run_refresh", slow_refresh)
    r = client.post("/api/refresh")
    assert r.status_code == 200
    try:
        assert client.get("/api/refresh/status").json()["running"] is True
    finally:
        release.set()
    # And it flips back to False once the worker finishes.
    deadline = time.time() + 5
    while client.get("/api/refresh/status").json()["running"]:
        assert time.time() < deadline, "refresh never finished"
        time.sleep(0.05)


def test_api_add_and_remove_scoped_whitelist(client):
    # Add a per-feed whitelist entry via the API.
    r = client.post("/api/whitelist", json={
        "ip": "192.0.2.200", "reason": "test", "added_by": "pytest",
        "feed_name": "custom_honeypot",
    })
    assert r.status_code == 200 and r.json()["success"] is True

    entries = {(e["ip"], e["feed_name"]) for e in client.get("/api/whitelist").json()}
    assert ("192.0.2.200", "custom_honeypot") in entries

    # Removing a different scope should 404 (nothing to remove there)...
    assert client.delete("/api/whitelist?ip=192.0.2.200&feed=*").status_code == 404
    # ...but removing the correct scope succeeds.
    assert client.delete("/api/whitelist?ip=192.0.2.200&feed=custom_honeypot").status_code == 200


def test_manual_backup_endpoint(client):
    from threatfeedme import dashboard; import os
    r = client.post("/api/backup")
    assert r.status_code == 200
    path = r.json()["path"]
    assert os.path.exists(path)
    # Backup lands next to the (temp) DB, not in the repo.
    assert os.path.realpath(path).startswith(os.path.realpath(os.path.dirname(dashboard.db_path)))


def test_cidr_whitelist_entry_can_be_removed(client):
    # A CIDR whitelist entry (slash in the value) must be removable — the reason
    # the endpoint takes ip as a query param rather than a path segment.
    r = client.post("/api/whitelist", json={"ip": "203.0.113.0/24", "reason_code": "other"})
    assert r.status_code == 200
    assert any(e["ip"] == "203.0.113.0/24" for e in client.get("/api/whitelist").json())
    d = client.delete("/api/whitelist?ip=203.0.113.0/24&feed=*")
    assert d.status_code == 200
    assert not any(e["ip"] == "203.0.113.0/24" for e in client.get("/api/whitelist").json())


def test_delete_feed_purges_its_indicator_data(client):
    from threatfeedme import dashboard
    # A feed whose sole indicator is reported only by it.
    client.post("/api/feeds", json={
        "name": "purge_me", "url": "https://example.com/p.txt",
        "feed_type": "custom", "weight": 0.6,
    })
    dashboard.db.add_indicator("203.0.113.201", "purge_me", {})
    assert dashboard.db.get_indicator("203.0.113.201") is not None

    assert client.delete("/api/feeds/purge_me").status_code == 200
    # Orphaned indicator and its source attribution are purged.
    assert dashboard.db.get_indicator("203.0.113.201") is None
    assert "purge_me" not in dashboard.db.get_feed_report_counts()


# NOTE: keep this above the CSRF section — its fixture re-imports the
# whole package against a different database, so a later
# `from threatfeedme import dashboard` no longer matches `client`.
def test_indicator_apis_expose_effective_votes(client):
    # The module fixture is shared and earlier tests mutate it (whitelists,
    # extra sources change the measured overlaps), so seed dedicated feeds
    # this test alone uses: two mostly-disjoint sets sharing one IP, giving
    # that IP a deterministic ~1.83 votes (1 + (1 - 1/6 overlap)).
    from threatfeedme import dashboard
    for i in range(1, 6):
        dashboard.db.add_indicator(f"45.140.17.{i}", "ev_probe_a", {})
        dashboard.db.add_indicator(f"45.140.18.{i}", "ev_probe_b", {})
    dashboard.db.add_indicator("45.140.19.9", "ev_probe_a", {})
    dashboard.db.add_indicator("45.140.19.9", "ev_probe_b", {})
    assert client.post("/api/recalculate-scores").status_code == 200

    # Paginated list: every row carries the field for the dashboard table.
    rows = client.get("/api/indicators?limit=200").json()["indicators"]
    assert rows and all("effective_votes" in r for r in rows)
    assert all(r["effective_votes"] is not None for r in rows)

    # Single-IP detail exposes the same number the list shows; the probe IP
    # reported by both (mostly disjoint) feeds lands near two full votes.
    j = client.get("/api/indicators/45.140.19.9").json()
    assert j["effective_votes"] == pytest.approx(1.83, abs=0.01)
    by_ip = {r["ip"]: r for r in rows}
    assert by_ip["45.140.19.9"]["effective_votes"] == j["effective_votes"]


def test_feeds_are_cumulative_high_subset_of_medium(client):
    """A firewall polling one URL must get every indicator at or above that
    confidence: high ⊆ medium ⊆ low. Regression test for the exclusive-bucket
    serving that silently dropped the highest-confidence IPs from the
    recommended medium feed."""
    high = set(client.get("/feeds/high.txt").text.split())
    med = set(client.get("/feeds/medium.txt").text.split())
    low = set(client.get("/feeds/low.txt").text.split())
    assert high <= med <= low
    # The fixture guarantees a medium-tier indicator exists, so medium must
    # be a strict superset of high somewhere in the lifecycle of this module.
    assert med  # non-empty


def test_matrix_recommends_medium(client):
    """The docs always recommended Medium; the matrix badge said High. One
    Recommended badge, on the Medium row."""
    import re
    body = client.get("/").text
    assert body.count('class="rec">Recommended<') == 1
    row = re.search(r'mx-tier mx-(\w+)">\s*<span class="mx-label">[^<]*</span>\s*'
                    r'<span class="rec">Recommended', body)
    assert row and row.group(1) == "medium"


def test_footer_shows_running_version(client):
    from threatfeedme import __version__
    body = client.get("/").text
    assert f"v{__version__}" in body


def test_matrix_cells_show_served_counts(client):
    """The matrix cells answer "what does my firewall get" — they must match
    the cumulative feed files, not the exclusive tier distribution. (The v1
    stat-tile row is retired in v2.0; counts live inline in the feed matrix,
    one column per indicator kind.)"""
    body = client.get("/").text
    assert "Domain feeds" in body                 # the kind columns render
    assert "/feeds/domains/medium.txt" in body    # domain URLs in the matrix
    med_served = len([l for l in client.get("/feeds/medium.txt").text.splitlines() if l.strip()])
    assert f'{med_served:,}' in body      # medium IP cell == medium.txt size


def test_low_card_hidden_but_url_stays_live(client):
    """low == all under cumulative serving: one "Everything" card on the
    dashboard, but the low.txt URL keeps working for firewalls already
    polling it."""
    body = client.get("/").text
    assert "Everything" in body
    assert "/feeds/low.txt" not in body       # card gone
    assert client.get("/feeds/low.txt").status_code == 200  # alias lives


def test_multivar_api_key_set_status_and_gate(client, monkeypatch):
    """Multi-credential feeds (comma-separated auth_env, e.g. HoneyDB's
    id+key pair): status reports each var, POST accepts a {VAR: value} map,
    the plain api_key field is rejected (ambiguous), and undeclared vars
    are refused so the endpoint can't become a generic env editor."""
    from threatfeedme import dashboard
    from threatfeedme.models import FeedSource, FeedType
    monkeypatch.delenv("TFM_FEED_HD_TEST_ID", raising=False)
    monkeypatch.delenv("TFM_FEED_HD_TEST_KEY", raising=False)
    dashboard.db.add_feed(FeedSource(
        name="multikey_feed", url="https://example.com/api", weight=1.0,
        feed_type=FeedType.THREAT_INTEL, update_interval=3600,
        requires_auth=True, auth_env="TFM_FEED_HD_TEST_ID,TFM_FEED_HD_TEST_KEY", enabled=False))
    try:
        j = client.get("/api/feeds/multikey_feed/api-key").json()
        assert j["configured"] is False
        assert [v["name"] for v in j["vars"]] == ["TFM_FEED_HD_TEST_ID", "TFM_FEED_HD_TEST_KEY"]

        # plain api_key is ambiguous for a two-var feed
        r = client.post("/api/feeds/multikey_feed/api-key", json={"api_key": "x"})
        assert r.status_code == 400

        # undeclared var names are refused
        r = client.post("/api/feeds/multikey_feed/api-key",
                        json={"keys": {"PATH": "evil"}})
        assert r.status_code == 400

        # setting both configures the feed; values are never echoed back
        r = client.post("/api/feeds/multikey_feed/api-key",
                        json={"keys": {"TFM_FEED_HD_TEST_ID": "id-1", "TFM_FEED_HD_TEST_KEY": "k-2"}})
        assert r.status_code == 200 and r.json()["configured"] is True
        assert "id-1" not in r.text and "k-2" not in r.text
        assert os.environ["TFM_FEED_HD_TEST_ID"] == "id-1"

        # partial credentials -> not configured (badge must not lie)
        r = client.post("/api/feeds/multikey_feed/api-key",
                        json={"keys": {"TFM_FEED_HD_TEST_KEY": ""}})
        assert r.json()["configured"] is False
    finally:
        client.delete("/api/feeds/multikey_feed")
        for v in ("TFM_FEED_HD_TEST_ID", "TFM_FEED_HD_TEST_KEY"):
            os.environ.pop(v, None)


# NOTE: tests that reach the DB via `dashboard.db` must stay ABOVE the tests
# that reload the threatfeedme modules (the csrf fixtures): after a reload,
# `dashboard.db` is the new modules' DB while `client` still serves the old.

@pytest.mark.parametrize("secret", ["UNIFI_PASSWORD", "DASHBOARD_PASSWORD", "HTTPS_PROXY"])
def test_add_feed_refuses_someone_elses_secret_as_its_key(client, secret):
    """auth_env names the variable whose VALUE is sent as the feed's key, so a
    feed pointed at an attacker's server with auth_env=UNIFI_PASSWORD used to
    hand over the gateway password on the next refresh (review 2026-09-22)."""
    r = client.post("/api/feeds", json={
        "name": "exfil_feed", "url": "https://attacker.example/x.txt",
        "feed_type": "threat_intel", "requires_auth": True,
        "auth_env": secret, "auth_header": "X-Leak",
    })
    assert r.status_code == 400, r.text
    assert "TFM_FEED_" in r.json()["detail"]
    assert client.get("/api/feeds/exfil_feed/api-key").status_code == 404


def test_api_key_endpoint_refuses_a_stored_process_knob(client):
    """A feed stored before the rule with auth_env=HTTPS_PROXY must not turn
    the key endpoint into a proxy injection for every outbound request."""
    from threatfeedme import dashboard
    from threatfeedme.models import FeedSource, FeedType
    os.environ.pop("HTTPS_PROXY", None)
    dashboard.db.add_feed(FeedSource(
        name="legacy_bad_feed", url="https://example.com/x", weight=1.0,
        feed_type=FeedType.THREAT_INTEL, update_interval=3600,
        requires_auth=True, auth_env="HTTPS_PROXY", enabled=False))
    try:
        r = client.post("/api/feeds/legacy_bad_feed/api-key",
                        json={"api_key": "http://attacker:3128"})
        assert r.status_code == 400
        assert "HTTPS_PROXY" not in os.environ
    finally:
        client.delete("/api/feeds/legacy_bad_feed")
        os.environ.pop("HTTPS_PROXY", None)


def test_host_check_api_lock_and_unlock(client):
    """Report-only -> lock to the seen names -> enforcing; the host the
    request arrived on is always kept, so locking can't lock out the page."""
    from threatfeedme import middleware as mw
    mw._seen.clear(); mw.invalidate_allowlist_cache()
    try:
        client.get("/api/stats")                       # arrives as "testserver"
        s = client.get("/api/host-check").json()
        assert s["mode"] == "report-only"
        assert "testserver" in [e["host"] for e in s["seen"]]

        r = client.post("/api/host-check", json={"allowed": ["threatfeedme.tnh.local"]})
        assert r.status_code == 200
        s = r.json()
        assert s["mode"] == "enforcing"
        assert s["configured"] == ["testserver", "threatfeedme.tnh.local"]

        assert client.get("/api/stats", headers={"host": "attacker.example"}).status_code == 400
        # feeds stay open to any Host, even while enforcing
        assert client.get("/feeds/high.txt", headers={"host": "attacker.example"}).status_code == 200

        assert client.post("/api/host-check", json={"allowed": ["bad_name!"]}).status_code == 400
    finally:
        client.post("/api/host-check", json={"allowed": []})   # back to report-only
        mw._seen.clear(); mw.invalidate_allowlist_cache()
    assert client.get("/api/host-check").json()["mode"] == "report-only"


def test_feed_etag_304_and_limit_over_http(client):
    """Firewalls re-polling an unchanged list get a 304; ?limit=N serves the
    top N by score (for entry-capped firewalls)."""
    r = client.get("/feeds/all.txt")
    assert r.status_code == 200 and r.headers["etag"]
    again = client.get("/feeds/all.txt", headers={"if-none-match": r.headers["etag"]})
    assert again.status_code == 304 and again.content == b""
    top1 = client.get("/feeds/all.txt?limit=1")
    assert top1.text.splitlines() == r.text.splitlines()[:1]
    assert client.get("/feeds/all.txt?limit=0").status_code == 422
    assert client.get("/feeds/all.csv?limit=1").text.count("\n") == 2   # header + 1
    doc = client.get("/feeds/all.json?limit=1").json()
    assert doc["total_count"] == 1 and len(doc["indicators"]) == 1


def test_ops_pulse_row(client):
    """The pulse row answers health/freshness/velocity/overrides at a glance
    and must NOT duplicate matrix sizes. UniFi card renders only when the
    push integration is configured (it isn't, in this fixture)."""
    body = client.get("/").text
    for label in ("Feeds healthy", "Last refresh", "New in 24h", "Overrides"):
        assert label in body
    assert "UniFi push" not in body           # hidden unless configured
    # fixture has one whitelist entry -> the zero-state line must NOT show
    assert "human judgment applied" in body
    assert "pure feed consensus" not in body


def test_pulse_never_run_is_pending_then_a_problem(client, monkeypatch):
    """A feed with no successful fetch used to count as healthy. Before any
    refresh finishes it is pending; after one, it is a problem."""
    from threatfeedme import scheduler
    monkeypatch.setitem(scheduler._refresh_state, "last_finished", None)
    body = client.get("/").text
    assert "awaiting first fetch" in body and "all feeds reporting" not in body
    monkeypatch.setitem(scheduler._refresh_state, "last_finished",
                        "2026-01-01T00:00:00+00:00")
    body = client.get("/").text
    assert "problem:" in body and "awaiting first fetch" not in body


def test_new_in_24h_counts_each_indicator_once(tmp_path):
    from threatfeedme.database import Database
    db = Database(str(tmp_path / "n.db"))
    for feed in ("feed_a", "feed_b", "feed_c"):          # one ip, three feeds
        db.add_indicators_bulk([("198.51.100.9", {})], source=feed)
    db.add_indicators_bulk([("evil.example.net", {})], source="feed_d", kind="domain")
    assert db.get_new_indicator_counts("2000-01-01T00:00:00+00:00") == {"ip": 1, "domain": 1}
    assert db.get_new_indicator_counts("2999-01-01T00:00:00+00:00") == {}


def test_matrix_count_fast_path_matches_walk(client):
    """The dashboard's SQL fast path and the exact full walk must agree for
    every non-CIDR/non-wildcard whitelist shape (global, tier-scoped,
    feed-scoped, and missing-row entries)."""
    from threatfeedme import dashboard
    from threatfeedme.routers.system import _served_counts, _served_counts_walk
    db = dashboard.db
    db.add_indicator("198.18.40.1", "spamhaus_drop", {})
    db.add_indicator("198.18.40.2", "spamhaus_drop", {})
    db.add_indicator("198.18.40.2", "custom_honeypot", {})
    client.post("/api/whitelist", json={"ip": "198.18.40.1", "feed_name": "*",
                                        "reason_code": "other", "reason": "t"})
    client.post("/api/whitelist", json={"ip": "198.18.40.2", "feed_name": "tier:high",
                                        "reason_code": "other", "reason": "t"})
    client.post("/api/whitelist", json={"ip": "203.0.113.250", "feed_name": "*",
                                        "reason_code": "other", "reason": "no such row"})
    try:
        wl_map = db.get_whitelist_map()
        # The shared fixture accumulates CIDR rules from other tests; strip
        # range rules so BOTH paths see the same exact-only rule set and the
        # fast path activates (its precondition).
        wl_map.cidr_rules = []
        wl_map.wildcard_rules = []
        fast = _served_counts(db, wl_map)
        walk = _served_counts_walk(db, wl_map)
        assert fast == walk
    finally:
        for ip, feed in (("198.18.40.1", "*"), ("198.18.40.2", "tier:high"),
                         ("203.0.113.250", "*")):
            client.delete(f"/api/whitelist?ip={ip}&feed={feed}")


def test_refresh_pulse_card_is_live_updatable(client):
    """The Last-refresh card carries stable ids + the interval so client JS
    can keep it honest while the page sits open (a tab opened during
    container startup once showed 'first fetch pending' for a day)."""
    body = client.get("/").text
    assert 'id="pulse-refresh"' in body
    assert 'id="pulse-refresh-n"' in body
    assert 'data-interval-min=' in body


# ==================== CSRF protection tests ====================


@pytest.fixture(scope="module")
def csrf_client(tmp_path_factory):
    """A test client with Basic auth enabled so CSRF checks are active."""
    work = tmp_path_factory.mktemp("csrf")
    db_path = str(work / "t.db").replace("\\", "/")
    cfg_path = work / "csrf_config.yaml"
    cfg_path.write_text(
        "database:\n"
        f"  path: {db_path}\n"
        "scoring:\n"
        "  source_weight: 0.45\n"
        "  reputation_weight: 0.33\n"
        "  recency_weight: 0.22\n"
        "  high_confidence: {min_sources: 3, min_score: 0.75}\n"
        "feeds:\n"
        "  - {name: spamhaus_drop, url: 'https://example.com/drop.txt', feed_type: spam, weight: 0.95}\n"
        "safety: {drop_private_reserved: false, protect_known_good: true}\n"
        "dashboard: {auth_required: true}\n"
    )
    # Restored at teardown: leaking the credentials into os.environ made every
    # LATER module-reloading fixture (test_domains, test_unifi) come up with
    # auth on, since setting both credentials now enables auth.
    saved = {v: os.environ.get(v) for v in ("DASHBOARD_USER", "DASHBOARD_PASSWORD")}
    os.environ["CONFIG_PATH"] = str(cfg_path)
    os.environ["DASHBOARD_USER"] = "admin"
    os.environ["DASHBOARD_PASSWORD"] = "testpass"

    # Force re-import of all project modules so the new env vars take effect.
    for m in list(sys.modules.keys()):
        if m == "threatfeedme" or m.startswith("threatfeedme."):
            sys.modules.pop(m, None)

    from starlette.testclient import TestClient
    from threatfeedme import dashboard

    try:
        yield TestClient(dashboard.app)
    finally:
        for var, value in saved.items():
            if value is None:
                os.environ.pop(var, None)
            else:
                os.environ[var] = value


def _auth_headers():
    """Base64-encoded admin:testpass for Basic auth."""
    import base64
    token = base64.b64encode(b"admin:testpass").decode("ascii")
    return {"Authorization": f"Basic {token}"}


def test_csrf_allowed_with_header(csrf_client):
    """A mutating POST with X-Requested-With header passes CSRF check."""
    headers = _auth_headers()
    headers["X-Requested-With"] = "XMLHttpRequest"
    r = csrf_client.post("/api/whitelist", json={
        "ip": "203.0.113.99", "reason_code": "other",
    }, headers=headers)
    assert r.status_code == 200, r.text


def test_csrf_rejected_without_header():
    """A mutating POST without X-Requested-With is blocked (403) -- clean subprocess."""
    import subprocess, sys
    r = subprocess.run([sys.executable, "tests/test_csrf_subprocess.py"],
                       capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, f"subprocess failed:\n{r.stderr}\n{r.stdout}"
    assert "PASS test_csrf_rejected_without_header" in r.stdout


def test_csrf_rejected_delete_without_header():
    """A mutating DELETE without X-Requested-With is blocked (403) -- clean subprocess."""
    import subprocess, sys
    r = subprocess.run([sys.executable, "tests/test_csrf_subprocess.py"],
                       capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, f"subprocess failed:\n{r.stderr}\n{r.stdout}"
    assert "PASS test_csrf_rejected_delete_without_header" in r.stdout


def test_csrf_rejected_invalid_header_value():
    """Wrong header value is also blocked -- clean subprocess."""
    import subprocess, sys
    r = subprocess.run([sys.executable, "tests/test_csrf_subprocess.py"],
                       capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, f"subprocess failed:\n{r.stderr}\n{r.stdout}"
    assert "PASS test_csrf_rejected_invalid_header_value" in r.stdout


def test_csrf_read_endpoints_not_blocked(csrf_client):
    """GET /api/* read endpoints must still work without CSRF header."""
    r = csrf_client.get("/api/stats", headers=_auth_headers())
    assert r.status_code == 200


def test_csrf_feed_endpoints_not_blocked(csrf_client):
    """Public feed URLs are unauthenticated and must not be blocked by CSRF."""
    r = csrf_client.get("/feeds/all.txt")
    assert r.status_code == 200


def test_csrf_enforced_even_when_auth_off(client):
    """CSRF is enforced unconditionally: a no-auth LAN dashboard is ambient
    authority, so cross-site POSTs must still be rejected."""
    r = client.post("/api/whitelist", json={
        "ip": "203.0.113.200", "reason_code": "other",
    }, headers={"X-Requested-With": "not-the-dashboard"})
    assert r.status_code == 403
    assert "CSRF" in r.json().get("detail", "")


def test_healthz_is_cheap_and_unauthenticated(client):
    """The container healthcheck target: must answer without auth headers and
    without streaming the corpus (the old /feeds/all.txt probe timed out at
    large corpus sizes, marking healthy deployments permanently unhealthy)."""
    r = client.get("/healthz", headers={})
    assert r.status_code == 200
    assert r.json() == {"ok": True}
