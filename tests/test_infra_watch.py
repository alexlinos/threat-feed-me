"""Offline tests for scripts/infra_watch.py (repo rule: no network in tests).

Covers the pure parts the CI job depends on: each vendor normalizer, the
diff/alert logic, and the poisoned-file prefix guard. Fixtures are minimal
shapes of the real vendor documents using documentation ranges.
"""

import json
import sys
from pathlib import Path

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
