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
    # The shape of AWS's own ip-ranges.json, top-level keys included: IPv4
    # under "prefixes", IPv6 under "ipv6_prefixes". This fixture used to say
    # "ipv4_prefixes", the same wrong key the code read, so the test passed
    # while every published AWS list held no IPv4 range at all.
    data = {
        "syncToken": "0", "createDate": "2026-01-01-00-00-00",
        "prefixes": [{"ip_prefix": "192.0.2.0/24", "region": "us-east-1",
                      "service": "EC2", "network_border_group": "us-east-1"}],
        "ipv6_prefixes": [{"ipv6_prefix": "2001:db8::/40", "region": "us-east-1",
                           "service": "S3", "network_border_group": "us-east-1"}],
    }
    assert iw.normalize_aws(data) == {
        "v4|us-east-1|EC2|192.0.2.0/24",
        "v6|us-east-1|S3|2001:db8::/40",
    }


@pytest.mark.parametrize("missing", ["prefixes", "ipv6_prefixes"])
def test_normalize_aws_refuses_a_file_missing_a_family(missing):
    """A renamed key must fail the fetch, not publish half the ranges."""
    data = {
        "prefixes": [{"ip_prefix": "192.0.2.0/24", "region": "r", "service": "EC2"}],
        "ipv6_prefixes": [{"ipv6_prefix": "2001:db8::/40", "region": "r", "service": "S3"}],
    }
    del data[missing]
    with pytest.raises(ValueError):
        iw.normalize_aws(data)


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


def test_source_that_parses_to_nothing_fails_and_keeps_its_snapshot(tmp_path, monkeypatch):
    # A vendor changing its file shape normalizes to an empty set. Taken as
    # "everything removed" it would overwrite the snapshot and publish
    # emptied lists; it must count as a failed fetch instead.
    old = json.dumps({"entries": ["v4|192.0.2.0/24"]})
    (tmp_path / "t.json").write_text(old, encoding="utf-8")
    monkeypatch.setattr(iw, "SOURCES", [iw.Source("t", lambda: {"new": "shape"}, lambda d: set())])
    assert iw.main(["--snapshots", str(tmp_path), "--update"]) == 2
    assert (tmp_path / "t.json").read_text(encoding="utf-8") == old


def test_alert_holds_only_alerting_source_and_accept_alert_advances_it(tmp_path, monkeypatch):
    """One vendor alerting must hold only its snapshot while healthy vendors
    still update; --accept-alert advances the held baseline and exits 0."""
    good_old = json.dumps({"entries": [f"v4|r|s|192.0.2.{i}/32" for i in range(20)],
                           "fetched_at": "2026-01-01T00:00:00Z", "source": "good"})
    bad_old = json.dumps({"entries": [f"v4|r|s|198.51.100.{i}/32" for i in range(10)],
                          "fetched_at": "2026-01-01T00:00:00Z", "source": "bad"})
    same_old = json.dumps({"entries": ["v4|r|s|203.0.113.0/24"],
                           "fetched_at": "2026-01-01T00:00:00Z", "source": "same"})
    (tmp_path / "good.json").write_text(good_old, encoding="utf-8")
    (tmp_path / "bad.json").write_text(bad_old, encoding="utf-8")
    (tmp_path / "same.json").write_text(same_old, encoding="utf-8")

    good_new = {f"v4|r|s|192.0.2.{i}/32" for i in range(21)}          # +5%, ok
    bad_new = {f"v4|r|s|198.51.100.{i}/32" for i in range(20)}        # +100%, ALERT
    same_new = {"v4|r|s|203.0.113.0/24"}                              # 0%, unchanged
    monkeypatch.setattr(iw, "SOURCES", [
        iw.Source("good", lambda: good_new, lambda d: d),
        iw.Source("bad", lambda: bad_new, lambda d: d),
        iw.Source("same", lambda: same_new, lambda d: d),
    ])

    assert iw.main(["--snapshots", str(tmp_path), "--update"]) == 1
    assert set(json.loads((tmp_path / "good.json").read_text())["entries"]) == good_new
    assert (tmp_path / "bad.json").read_text(encoding="utf-8") == bad_old
    # Unchanged source must not be rewritten just to bump fetched_at.
    assert (tmp_path / "same.json").read_text(encoding="utf-8") == same_old

    # Explicit operator acceptance advances the held snapshot cleanly.
    assert iw.main(["--snapshots", str(tmp_path), "--update", "--accept-alert"]) == 0
    assert set(json.loads((tmp_path / "bad.json").read_text())["entries"]) == bad_new


def test_github_meta_uses_token_and_get_retries_transient_503(monkeypatch):
    seen_headers = []

    class _Raw:
        def __init__(self, data):
            self._data = data
        def read(self, n=-1, decode_content=True):
            return self._data

    class _Resp:
        def __init__(self, status, data=b"{}"):
            self.status_code = status
            self.raw = _Raw(data)
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False
        def raise_for_status(self):
            if self.status_code >= 400:
                raise iw.requests.HTTPError(f"{self.status_code}")

    responses = iter([_Resp(503), _Resp(200, b'{"web": ["192.0.2.0/24"]}')])
    monkeypatch.setattr(iw, "_sleep", lambda s: None)
    monkeypatch.setenv("GITHUB_TOKEN", "synthetic-gh-token")

    def fake_get(url, headers=None, **kw):
        seen_headers.append(dict(headers or {}))
        return next(responses)

    monkeypatch.setattr(iw.requests, "get", fake_get)
    data = iw.fetch_github_meta()
    assert data == {"web": ["192.0.2.0/24"]}
    assert len(seen_headers) == 2
    assert seen_headers[0]["Authorization"] == "Bearer synthetic-gh-token"


def test_normalize_zoom_atlassian_okta_fastly_oci_do_stripe():
    import pytest

    # Zoom
    assert iw.normalize_zoom({
        "meetings": "# comment\n192.0.2.0/24\nbad-line\n",
        "phone": "198.51.100.0/25\n",
    }) == {"zoom|meetings|192.0.2.0/24", "zoom|phone|198.51.100.0/25"}

    # Atlassian
    assert iw.normalize_atlassian({"items": [
        {"cidr": "203.0.113.0/24", "product": ["jira", "confluence"], "direction": ["egress"]},
    ]}) == {
        "atlassian|jira|egress|203.0.113.0/24",
        "atlassian|confluence|egress|203.0.113.0/24",
    }

    # Okta
    assert iw.normalize_okta({
        "us_cell_1": {"ip_ranges": ["192.0.2.1/32"]},
        "emea_workflow_cell_2": {"ip_ranges": ["198.51.100.2/32"]},
        "preview_pam_cell_1": {"ip_ranges": ["203.0.113.3/32"]},
    }) == {
        "okta|us|core|192.0.2.1/32",
        "okta|emea|workflows|198.51.100.2/32",
        "okta|preview|pam|203.0.113.3/32",
    }

    # Fastly (requires both v4 and v6 families, matching AWS discipline)
    assert iw.normalize_fastly({
        "addresses": ["192.0.2.0/24"],
        "ipv6_addresses": ["2001:db8::/32"],
    }) == {"v4|192.0.2.0/24", "v6|2001:db8::/32"}
    with pytest.raises(ValueError, match="no v4"):
        iw.normalize_fastly({"addresses": [], "ipv6_addresses": ["2001:db8::/32"]})

    # OCI
    assert iw.normalize_oci({"regions": [
        {"region": "us-ashburn-1", "cidrs": [
            {"cidr": "192.0.2.0/24", "tags": ["OCI", "OBJECT_STORAGE"]},
        ]},
    ]}) == {
        "oci|us-ashburn-1|OCI|192.0.2.0/24",
        "oci|us-ashburn-1|OBJECT_STORAGE|192.0.2.0/24",
    }

    # DigitalOcean geofeed CSV
    assert iw.normalize_digitalocean(
        "# header\n198.51.100.0/24,US,US-NY,New York,10001\nnot-a-cidr,XX\n"
    ) == {"do|US|198.51.100.0/24"}

    # Stripe
    assert iw.normalize_stripe({
        "api": "203.0.113.10\n",
        "webhooks": "203.0.113.20\n",
    }) == {"stripe|api|203.0.113.10", "stripe|webhooks|203.0.113.20"}
