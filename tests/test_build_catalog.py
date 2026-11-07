"""Catalog builder (issue #28): slicing the infra-watch snapshots into
finished lists + the manifest, offline against fixture snapshots.

The load-bearing rules under test: per-service/per-area/per-tag slicing
(never one vendor blob), Azure entries without a tag name are skipped
rather than shipped as a blob, and non-address material in GitHub meta
never becomes a list entry.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import build_catalog as bc


def _snapshots(tmp_path, data: dict[str, list[str]]) -> Path:
    d = tmp_path / "snapshots"
    d.mkdir()
    for name, entries in data.items():
        (d / f"{name}.json").write_text(
            json.dumps({"source": name, "entries": sorted(entries)}),
            encoding="utf-8")
    return d


def _build(tmp_path, data):
    snaps = _snapshots(tmp_path, data)
    out = tmp_path / "catalog"
    manifest = bc.build(snaps, out, "https://factory.example/", "2026-11-07T00:00:00Z")
    return manifest, out


def test_aws_slices_per_service(tmp_path):
    manifest, out = _build(tmp_path, {"aws_ip_ranges": [
        "v4|us-east-1|EC2|192.0.2.0/24", "v6|GLOBAL|S3|2001:db8::/40",
        "v4|GLOBAL|S3|198.51.100.0/24"]})
    by_slug = {m["slug"]: m for m in manifest["lists"]}
    assert set(by_slug) == {"aws-ec2", "aws-s3"}
    assert by_slug["aws-s3"]["entries"] == 2
    assert by_slug["aws-ec2"]["url"] == \
        "https://factory.example/catalog/aws-ec2.txt"
    assert (out / "aws-ec2.txt").read_text() == "192.0.2.0/24\n"


def test_m365_slices_per_area_and_form_and_cloud(tmp_path):
    manifest, _ = _build(tmp_path, {
        "m365_endpoints": ["ip|Exchange|Optimize|192.0.2.5",
                           "url|Exchange|Optimize|outlook.office.com",
                           "url|Common|Allow|*.office.com"],
        "m365_gcc_high": ["ip|Common|Allow|198.51.100.9"]})
    slugs = {m["slug"] for m in manifest["lists"]}
    assert slugs == {"m365-exchange-ips", "m365-exchange-urls",
                     "m365-common-urls", "m365-gcchigh-common-ips"}


def test_azure_slices_per_tag_and_skips_unnamed(tmp_path):
    manifest, out = _build(tmp_path, {"azure_service_tags": [
        "cidr|Storage.EastUS|eastus|192.0.2.0/27",
        "cidr|Sql||198.51.100.0/27",
        "cidr||Global|203.0.113.0/24",          # pre-fix snapshot shape
    ]})
    slugs = {m["slug"] for m in manifest["lists"]}
    assert slugs == {"azure-storage-eastus", "azure-sql"}
    assert not (out / "azure.txt").exists()     # never one Azure blob


def test_github_meta_drops_non_addresses(tmp_path):
    manifest, _ = _build(tmp_path, {"github_meta": [
        "meta|api|192.0.2.0/24", "meta|api|not-an-address",
        "meta|pages|198.51.100.0/24"]})
    by_slug = {m["slug"]: m for m in manifest["lists"]}
    assert by_slug["github-api"]["entries"] == 1
    assert by_slug["github-pages"]["entries"] == 1


def test_single_list_sources(tmp_path):
    manifest, _ = _build(tmp_path, {
        "gcp_goog": ["v4|||192.0.2.0/24"],
        "gcp_cloud": ["v4|us-east1|Google Cloud|198.51.100.0/24"],
        "cloudflare_ips": ["v4|203.0.113.0/24"],
        "adobe_endpoints": ["domain|||*.adobe.com", "domain|||cc.adobe.io"]})
    slugs = {m["slug"] for m in manifest["lists"]}
    assert slugs == {"google-workspace", "gcp-cloud", "cloudflare", "adobe"}
    adobe = next(m for m in manifest["lists"] if m["slug"] == "adobe")
    assert adobe["vendor"] == "Adobe" and adobe["entries"] == 2


def test_manifest_counts_match_files(tmp_path):
    manifest, out = _build(tmp_path, {
        "aws_ip_ranges": ["v4|GLOBAL|EC2|192.0.2.0/24",
                          "v4|GLOBAL|EC2|192.0.2.0/24"]})  # dup collapses
    (entry,) = manifest["lists"]
    body = (out / "aws-ec2.txt").read_bytes()
    assert entry["entries"] == 1 and entry["bytes"] == len(body)


def test_rebuild_with_unchanged_snapshots_rewrites_nothing(tmp_path):
    # Regression: a fresh generated_at every run changed catalog.json
    # daily even when no list did, and the workflow's commit step pushed
    # a no-op snapshot commit. An unchanged rebuild must leave the whole
    # output tree byte-identical, stamp included.
    data = {"aws_ip_ranges": ["v4|us-east-1|EC2|192.0.2.0/24"]}
    manifest, out = _build(tmp_path, data)
    before = {p.name: p.read_bytes() for p in out.iterdir()}
    snaps = tmp_path / "snapshots"
    again = bc.build(snaps, out, "https://factory.example/",
                     "2026-11-08T00:00:00Z")
    assert {p.name: p.read_bytes() for p in out.iterdir()} == before
    assert again["generated_at"] == manifest["generated_at"]

    # A real change still rewrites the manifest, with the new stamp.
    (snaps / "aws_ip_ranges.json").write_text(json.dumps(
        {"source": "aws_ip_ranges",
         "entries": ["v4|us-east-1|EC2|192.0.2.0/24",
                     "v4|us-east-1|EC2|198.51.100.0/24"]}), encoding="utf-8")
    changed = bc.build(snaps, out, "https://factory.example/",
                       "2026-11-08T00:00:00Z")
    assert changed["generated_at"] == "2026-11-08T00:00:00Z"
    assert json.loads((out / "catalog.json").read_text())["generated_at"] == \
        "2026-11-08T00:00:00Z"
