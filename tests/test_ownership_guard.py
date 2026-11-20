"""Offline tests for the must-not-block IP ownership guard (issue #18).

Verifies all acceptance criteria and factory slicing:
  1. A High address in the must-not-block set cannot reach the pushed UniFi or
     CrowdSec group, while rentable cloud tenant compute stays blockable.
  2. Operator-extensible via config (`extra_ranges`) and explicit override
     (`allow_ranges` / `allow_vendors`) logs a warning and permits the address.
  3. Push summaries report `ownership_refused` and `ownership_refused_by_vendor`.
  4. Factory builder (`scripts/build_catalog.py`) subtracts `gcp_cloud` from
     `gcp_goog` and excludes rentable compute (`EC2`, `AMAZON`, `actions`).
"""
import json
import logging
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import build_catalog as bc
from threatfeedme import crowdsec, ownership_guard as og, pusher_unifi as pu, scheduler
from threatfeedme.database import Database


@pytest.fixture
def db(tmp_path):
    return Database(str(tmp_path / "og-test.db"))


def _write_snap(snaps: Path, name: str, entries: list[str]) -> None:
    (snaps / f"{name}.json").write_text(
        json.dumps({"source": name, "entries": entries}), encoding="utf-8"
    )


def test_build_ownership_guard_subtracts_gcp_cloud_and_excludes_rentable_compute(tmp_path):
    snaps = tmp_path / "snaps"
    snaps.mkdir()
    out = tmp_path / "cat"
    out.mkdir()

    # gcp_goog covers 192.0.2.0/24; gcp_cloud covers upper half 192.0.2.128/25
    # -> google_frontends must protect ONLY 192.0.2.0/25, leaving tenant compute blockable!
    _write_snap(snaps, "gcp_goog", ["v4|global|Google|192.0.2.0/24"])
    _write_snap(snaps, "gcp_cloud", ["v4|us-east1|GCP|192.0.2.128/25"])
    _write_snap(snaps, "cloudflare_ips", ["v4|198.51.100.0/25"])
    _write_snap(snaps, "m365_endpoints", [
        "ip|Exchange|Optimize|203.0.113.0/26",
        "url|Exchange|Optimize|outlook.office365.com",
    ])
    _write_snap(snaps, "aws_ip_ranges", [
        "v4|GLOBAL|CLOUDFRONT|198.51.100.128/26",
        "v4|us-east-1|EC2|198.51.100.192/26",
        "v4|us-east-1|AMAZON|198.51.100.192/26",
    ])
    _write_snap(snaps, "github_meta", [
        "meta|web|203.0.113.64/26",
        "meta|actions|203.0.113.128/26",
        "meta|runner|203.0.113.192/26",
    ])

    out_file = out / "ownership_guard.json"
    doc = bc.build_ownership_guard(snaps, "2026-11-20T00:00:00Z", out_path=out_file)
    assert out_file.exists()
    vendors = doc["vendors"]
    assert vendors["google_frontends"] == ["192.0.2.0/25"]
    assert vendors["cloudflare"] == ["198.51.100.0/25"]
    assert vendors["m365"] == ["203.0.113.0/26"]
    assert vendors["aws_cloudfront"] == ["198.51.100.128/26"]
    assert vendors["github_frontends"] == ["203.0.113.64/26"]

    # Idempotence: second build with same snapshots preserves generated_at
    doc2 = bc.build_ownership_guard(snaps, "2026-11-21T00:00:00Z", out_path=out_file)
    assert doc2["generated_at"] == "2026-11-20T00:00:00Z"


def test_unifi_high_address_in_must_not_block_is_refused_and_reported(db):
    """Issue #18 AC1 & AC3: a High address in a must-not-block range cannot
    reach the pushed UniFi group, and the push summary reports count + vendor."""
    bundle = {
        "schema_version": 1,
        "vendors": {
            "m365": ["203.0.113.0/26"],
            "google_frontends": ["192.0.2.0/25"],
        },
    }
    og.refresh_ownership_guard(db, {}, fetch=lambda u: json.dumps(bundle))

    # Seed High indicators: 1 M365 frontend, 1 Google frontend, 1 GCP compute (blockable),
    # 1 normal attacker IP, 1 baked DNS resolver (8.8.8.8)
    for ip in ("203.0.113.10", "192.0.2.10", "192.0.2.200", "198.51.100.50", "8.8.8.8"):
        db.add_indicator(ip, "feed_a")
        db.set_indicator_score(ip, 0.95, "high")

    cfg = {"integrations": {"unifi": {"enabled": True, "host": "192.0.2.1", "tier": "high"}}}
    pusher = pu.UniFiPusher.from_config(cfg, db=db)
    sel = pusher.select(db, "ip", "high")

    # Protected addresses absent; tenant compute + normal attacker kept
    assert "203.0.113.10" not in sel.values
    assert "192.0.2.10" not in sel.values
    assert "8.8.8.8" not in sel.values
    assert "192.0.2.200" in sel.values
    assert "198.51.100.50" in sel.values

    # Summary reports refusal counts and vendor breakdown
    assert sel.ownership_refused_count == 3
    assert sel.ownership_refused_by_vendor == {
        "dns_resolvers": 1,
        "google_frontends": 1,
        "m365": 1,
    }
    summary = {"entries": len(sel.values)}
    pu._add_coverage(summary, sel)
    assert summary["ownership_refused"] == 3
    assert summary["ownership_refused_by_vendor"]["m365"] == 1


def test_operator_extra_ranges_and_explicit_allow_override_logs_warning(db, caplog):
    """Issue #18 AC2: operator-extensible via extra_ranges, and explicit allow
    overrides permit the address with a logged warning."""
    db.add_indicator("198.51.100.10", "feed_a")
    db.set_indicator_score("198.51.100.10", 0.95, "high")
    db.add_indicator("198.51.100.20", "feed_a")
    db.set_indicator_score("198.51.100.20", 0.95, "high")

    cfg = {
        "safety": {
            "ownership_guard": {
                "remote_enabled": False,
                "extra_ranges": [{"cidr": "198.51.100.0/24", "vendor": "corp_saas"}],
                "allow_ranges": ["198.51.100.20/32"],
            }
        },
        "integrations": {"unifi": {"enabled": True, "host": "192.0.2.1", "tier": "high"}},
    }
    pusher = pu.UniFiPusher.from_config(cfg, db=db)
    with caplog.at_level(logging.WARNING, logger="threatfeedme.ownership_guard"):
        sel = pusher.select(db, "ip", "high")

    assert "198.51.100.10" not in sel.values
    assert "198.51.100.20" in sel.values
    assert sel.ownership_refused_by_vendor == {"corp_saas": 1}
    assert any("explicit allow_ranges override" in rec.message for rec in caplog.records)


def test_crowdsec_push_enforces_ownership_guard_and_reports_refusals(db):
    bundle = {"schema_version": 1, "vendors": {"m365": ["203.0.113.0/26"]}}
    og.refresh_ownership_guard(db, {}, fetch=lambda u: json.dumps(bundle))
    db.add_indicator("203.0.113.5", "feed_a")
    db.set_indicator_score("203.0.113.5", 0.9, "high")
    db.add_indicator("198.51.100.5", "feed_a")
    db.set_indicator_score("198.51.100.5", 0.9, "high")

    guard = og.OwnershipGuard.from_config({}, db=db)
    pusher = crowdsec.CrowdSecPusher("https://lapi.example.net:8080", tier="high",
                                     ownership_guard=guard)
    vals = pusher.collect(db)
    assert vals == ["198.51.100.5"]
    assert pusher.last_ownership_refused == 1
    assert pusher.last_ownership_refused_by_vendor == {"m365": 1}


def test_fail_closed_and_wide_prefix_rejection(db):
    # Fail closed when configured and no remote bundle is cached yet
    guard = og.OwnershipGuard.from_config(
        {"safety": {"ownership_guard": {"fail_closed_on_missing_cache": True}}},
        db=db,
    )
    with pytest.raises(RuntimeError, match="failed closed"):
        guard.check_ready()

    # Overly wide prefix in remote bundle is rejected without corrupting state
    poisoned = json.dumps({"schema_version": 1, "vendors": {"evil": ["0.0.0.0/1"]}})
    res = og.refresh_ownership_guard(db, {}, fetch=lambda u: poisoned)
    assert res["status"] == "error"
    assert db.get_setting(og.GUARD_DOC_KEY) is None


def test_scheduler_ownership_guard_poll_respects_interval(db, monkeypatch):
    import importlib
    live_og = importlib.import_module("threatfeedme.ownership_guard")
    live_sched = importlib.import_module("threatfeedme.scheduler")
    calls = []
    monkeypatch.setattr(
        live_og, "refresh_ownership_guard",
        lambda d, c: (calls.append(1), {"status": "synced"})[1],
    )
    live_sched._maybe_ownership_guard_poll(db=db, config={})
    live_sched._maybe_ownership_guard_poll(db=db, config={})
    assert len(calls) == 1


def test_bundle_covering_too_much_of_ipv4_is_refused_and_the_last_one_kept(db):
    """Each prefix passing the /8 floor is not enough: a few hundred valid
    ranges can cover everything, and a guard that matches everything empties
    every pushed list without an error."""
    good = {"schema_version": 1, "vendors": {"m365": ["203.0.113.0/26"]}}
    assert og.refresh_ownership_guard(db, {}, fetch=lambda u: json.dumps(good))["status"] == "synced"

    wide = {"schema_version": 1,
            "vendors": {"evil": [f"{n}.0.0.0/8" for n in range(1, 9)]}}   # 8 x /8 = 3.1%
    res = og.refresh_ownership_guard(db, {}, fetch=lambda u: json.dumps(wide))
    assert res["status"] == "error"
    assert "limit" in res["reason"]
    # the last good bundle is still the one in force
    guard = og.OwnershipGuard.from_config({}, db=db)
    assert guard.match("203.0.113.5") == "m365"
    assert guard.match("198.51.100.77") is None


def test_coverage_counts_overlapping_ranges_once():
    assert og.v4_coverage(["192.0.2.0/24", "192.0.2.0/25", "2001:db8::/32", "junk"]) == 256


def test_factory_and_app_share_one_coverage_limit():
    assert bc._GUARD_MAX_V4_COVERAGE == og.MAX_V4_COVERAGE


def test_factory_keeps_the_published_bundle_when_a_build_is_too_wide(tmp_path, capsys):
    snaps = tmp_path / "snaps"
    snaps.mkdir()
    out_file = tmp_path / "ownership_guard.json"
    _write_snap(snaps, "cloudflare_ips", ["v4|198.51.100.0/25"])
    first = bc.build_ownership_guard(snaps, "2026-11-20T00:00:00Z", out_path=out_file)
    published = out_file.read_text(encoding="utf-8")

    _write_snap(snaps, "cloudflare_ips", [f"v4|{n}.0.0.0/8" for n in range(1, 9)])
    again = bc.build_ownership_guard(snaps, "2026-11-21T00:00:00Z", out_path=out_file)
    assert out_file.read_text(encoding="utf-8") == published
    assert again["vendors"] == first["vendors"]
    assert "keeping the published bundle" in capsys.readouterr().err


def test_status_says_when_only_the_built_in_ranges_are_in_force(db):
    s = og.status(db, {})
    assert s["enabled"] and s["remote_enabled"] and not s["bundle_loaded"]
    assert s["vendors"] == ["cloudflare", "dns_resolvers"]
    assert s["fetch_failed"] is False

    og.refresh_ownership_guard(db, {}, fetch=lambda u: "not json")
    assert og.status(db, {})["fetch_failed"] is True

    bundle = {"schema_version": 1, "vendors": {"m365": ["203.0.113.0/26"]}}
    og.refresh_ownership_guard(db, {}, fetch=lambda u: json.dumps(bundle))
    s = og.status(db, {})
    assert s["bundle_loaded"] and "m365" in s["vendors"] and not s["fetch_failed"]
    # no error text ever leaves the module through status
    assert set(s) == {"enabled", "remote_enabled", "bundle_loaded", "vendors",
                      "fetched_at", "fetch_failed"}

    off = og.status(db, {"safety": {"ownership_guard": {"enabled": False}}})
    assert off["enabled"] is False


def test_preview_uses_the_operators_guard_settings(db, monkeypatch):
    """The coverage preview must agree with the push: a guard the operator
    switched off, or a range they allowed, applies to both."""
    from threatfeedme.routers import integrations as integ
    core = integ.core           # the copy the router itself reads
    db.add_indicator("8.8.8.8", "feed_a")
    db.set_indicator_score("8.8.8.8", 0.95, "high")
    monkeypatch.setitem(core.__dict__, "db", db)

    monkeypatch.setitem(core.__dict__, "config", {})
    on = integ.unifi_withheld(kind="ip", tier="high", _=True)
    assert on["entries"] == 0
    assert on["ownership_refused_count"] == 1
    assert on["ownership_refused_by_vendor"] == {"dns_resolvers": 1}

    monkeypatch.setitem(core.__dict__, "config",
                        {"safety": {"ownership_guard": {"enabled": False}}})
    off = integ.unifi_withheld(kind="ip", tier="high", _=True)
    assert off["entries"] == 1 and off["ownership_refused_count"] == 0
