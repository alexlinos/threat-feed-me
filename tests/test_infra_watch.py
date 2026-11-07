"""Offline tests for scripts/infra_watch.py (repo rule: no network in tests).

Covers the pure parts the CI job depends on: each vendor normalizer, the
diff/alert logic, and the poisoned-file prefix guard. Fixtures are minimal
shapes of the real vendor documents using documentation ranges.
"""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import infra_watch as iw


def _source(name="t"):
    return iw.Source(name, lambda: None, lambda d: set())


# --- normalizers -----------------------------------------------------------

def test_normalize_aws():
    data = {
        "ipv4_prefixes": [{"ip_prefix": "192.0.2.0/24", "region": "us-east-1", "service": "EC2"}],
        "ipv6_prefixes": [{"ipv6_prefix": "2001:db8::/40", "region": "us-east-1", "service": "S3"}],
    }
    assert iw.normalize_aws(data) == {
        "v4|us-east-1|EC2|192.0.2.0/24",
        "v6|us-east-1|S3|2001:db8::/40",
    }


def test_normalize_m365_splits_ips_and_urls():
    data = [
        {"serviceArea": "Exchange", "category": "Optimize",
         "ips": ["192.0.2.1", "192.0.2.2"], "urls": ["mail.example.net"]},
        {"serviceArea": "Teams", "category": "Allow", "ips": [], "urls": []},
    ]
    out = iw.normalize_m365(data)
    assert "ip|Exchange|Optimize|192.0.2.1" in out
    assert "url|Exchange|Optimize|mail.example.net" in out
    assert len(out) == 3


def test_normalize_gcp_skips_missing_prefixes():
    data = {"prefixes": [
        {"scope": "us-central1", "service": "Google Cloud", "ipv4Prefix": "192.0.2.0/24"},
        {"scope": "global", "service": "Google APIs", "ipv6Prefix": "2001:db8::/32"},
        {"scope": "empty"},
    ]}
    assert iw.normalize_gcp(data) == {"v4|us-central1|Google Cloud|192.0.2.0/24",
                                      "v6|global|Google APIs|2001:db8::/32"}


def test_normalize_azure_handles_properties_nesting():
    data = {"values": [
        {"properties": {"name": "AzureFrontDoor.Frontend", "regionName": "US",
                        "addressPrefixes": ["192.0.2.0/27", "198.51.100.0/27"]}},
        {"name": "OldShape", "region": "", "addressPrefixes": ["203.0.113.0/24"]},
    ]}
    out = iw.normalize_azure(data)
    assert "cidr|AzureFrontDoor.Frontend|US|192.0.2.0/27" in out
    assert "cidr|OldShape|Global|203.0.113.0/24" in out


def test_normalize_azure_live_shape_keeps_tag_name():
    # The real ServiceTags shape: the tag name sits on the value and the
    # prefixes inside properties. Reading the name out of properties (the
    # old code) yielded "" for every entry, which made per-tag catalog
    # slicing impossible (issue #28).
    data = {"values": [
        {"name": "Storage.EastUS", "id": "/subscriptions/x",
         "properties": {"region": "eastus", "platform": "Azure",
                        "addressPrefixes": ["192.0.2.0/27"]}},
        {"name": "Sql", "properties": {"region": "",
                                        "addressPrefixes": ["198.51.100.0/27"]}},
    ]}
    out = iw.normalize_azure(data)
    assert "cidr|Storage.EastUS|eastus|192.0.2.0/27" in out
    assert "cidr|Sql|Global|198.51.100.0/27" in out


def test_normalize_adobe_extracts_domains_and_drops_junk():
    text = """
    - *.adobe.com
    - lm.licenses.adobe.com
    - https://cc-api-data.adobe.io/some/path
    - wss://speech.platform.bing.com
    - firebase*.googleapis.com
    - network-endpoints.html and app.js are page furniture
    - s3.amazonaws.com/tron-ffc-icons-prod/
    """
    out = iw.normalize_adobe(text)
    assert "domain|||*.adobe.com" in out
    assert "domain|||lm.licenses.adobe.com" in out
    assert "domain|||cc-api-data.adobe.io" in out
    assert "domain|||speech.platform.bing.com" in out
    assert "domain|||s3.amazonaws.com" in out
    assert not any("firebase" in e and "*" in e.split("|")[-1][1:] for e in out)
    # The mid-string wildcard's parent must not leak in as a broader entry.
    assert "domain|||googleapis.com" not in out
    assert not any(e.endswith(".html") or e.endswith(".js") for e in out)


def test_adobe_source_is_optional():
    src = next(s for s in iw.SOURCES if s.name == "adobe_endpoints")
    assert src.optional is True
    assert all(not s.optional for s in iw.SOURCES if s.name != "adobe_endpoints")


def _fake_adobe_get(monkeypatch, page, files):
    fetched = []

    def get(url, headers=None):
        fetched.append(url)
        if url == iw.ADOBE_PAGE_URL:
            return page.encode()
        return files[url].encode()
    monkeypatch.setattr(iw, "get", get)
    return fetched


def test_adobe_uses_only_the_linked_file_on_an_adobe_host(monkeypatch):
    page = ('<a href="https://cdn.other.example/endpoints-allowlist.txt">mirror</a>'
            '<a href="https://www.adobe.com/files/endpoints-allowlist-2026.txt">file</a>'
            '<script src="https://assets.tracker.example/x.js"></script>')
    good = "https://www.adobe.com/files/endpoints-allowlist-2026.txt"
    fetched = _fake_adobe_get(monkeypatch, page, {good: "*.adobe.com\n"})
    assert iw.fetch_adobe() == "*.adobe.com\n"
    assert fetched == [iw.ADOBE_PAGE_URL, good]       # the foreign mirror is never fetched


def test_adobe_without_a_linked_file_fails_instead_of_mining_the_page(monkeypatch):
    # The page's own hosts (CDN, scripts, analytics) must never become entries
    # on a list firewalls allow.
    page = '<p>*.adobe.com</p><script src="https://assets.tracker.example/x.js"></script>'
    _fake_adobe_get(monkeypatch, page, {})
    with pytest.raises(ValueError):
        iw.fetch_adobe()


def test_normalize_cloudflare_dict_of_lists():
    data = {"result": {"ipv4_cidrs": ["192.0.2.0/24"], "ipv6_cidrs": ["2001:db8::/48"]}}
    assert iw.normalize_cloudflare(data) == {"v4|192.0.2.0/24", "v6|2001:db8::/48"}


def test_normalize_github_meta_limits_keys():
    data = {"hooks": ["192.0.2.0/24"], "runner": ["198.51.100.0/25"],
            "git": ["203.0.113.0/24"], "web": ["not-an-ip.example.net"]}
    out = iw.normalize_github_meta(data)
    assert "meta|hooks|192.0.2.0/24" in out
    assert "meta|runner|198.51.100.0/25" in out
    assert "meta|git|203.0.113.0/24" not in out


# --- diffing and guards ----------------------------------------------------

def test_first_run_seeds_baseline_without_alert():
    row = iw.evaluate(_source(), None, {"v4|a|b|192.0.2.0/24"}, 10, 8, 20)
    assert row["baseline"] and not row["alert"] and row["added"] == 1


def test_small_change_no_alert_large_change_alerts():
    base = {f"v4|r|s|192.0.2.{i}/32" for i in range(100)}
    row = iw.evaluate(_source(), base, base | {"v4|r|s|198.51.100.9/32"}, 10, 8, 20)
    assert not row["alert"] and row["added"] == 1
    grown = base | {f"v4|r|s|198.51.100.{i}/32" for i in range(20)}
    row = iw.evaluate(_source(), base, grown, 10, 8, 20)
    assert row["alert"] and "10" in row["alert_reasons"][0]


def test_poisoned_wide_cidr_alerts_below_volume_threshold():
    base = {"v4|r|s|192.0.2.0/24", "v6|r|s|2001:db8::/32"}
    poisoned = base | {"v4|r|s|10.0.0.0/4"}  # one new entry, but far too wide
    row = iw.evaluate(_source(), base, poisoned, 10, 8, 20)
    assert row["alert"]
    assert any("IPv4 prefix wider" in r for r in row["alert_reasons"])


def test_non_cidr_entries_do_not_break_prefix_scan():
    # M365/GitHub lists carry URLs and hostnames; parsing must skip them.
    assert iw.min_prefixes({"url|a|b|x.example.net", "v4|a|b|192.0.2.0/24"}) == (24, 999)


def test_load_previous_corrupt_snapshot_returns_none(tmp_path):
    (tmp_path / "t.json").write_text("{not json", encoding="utf-8")
    assert iw.load_previous(tmp_path, "t") is None
    (tmp_path / "t.json").write_text(json.dumps({"entries": ["a", "b"]}))
    assert iw.load_previous(tmp_path, "t") == {"a", "b"}
