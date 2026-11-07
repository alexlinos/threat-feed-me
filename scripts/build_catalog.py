#!/usr/bin/env python3
"""Build the application-list catalog from the infra-watch snapshots.

The factory half of issue #28. infra_watch.py already fetches and
canonicalizes every vendor file into snapshot entry sets on the
``infra-snapshots`` branch; this script does the slicing the clients must
never do: it groups those canonical entries into finished, served-shape
lists (one plain list per catalog entry) and writes a small manifest,
``catalog.json``, describing them. The app renders the catalog from the
manifest alone and downloads a list's data only when the operator toggles
that list on, per the build-placement decision (heavy building happens
here, in GitHub Actions; clients verify, cache and serve).

Input entries are the canonical strings infra_watch writes
(``kind|dim|dim|value``). Output, under ``--out``:

  * ``<slug>.txt`` per catalog list: sorted unique entry values, one per
    line, exactly what a slice 1 "list" source serves after the guard.
  * ``catalog.json``: {generated_at, lists: [{slug, name, vendor,
    description, format, entries, bytes, url}]}. ``url`` is --base-url
    joined with the file name.

Slicers are pure functions over the snapshot entry lists so tests can
exercise them offline against fixtures (repo rule: no network in tests).
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
import time
from pathlib import Path
from typing import Callable, Iterable

DEFAULT_BASE_URL = ("https://raw.githubusercontent.com/alexlinos/"
                    "threat-feed-me/infra-snapshots/")

# A catalog list: (vendor, display name, one-line description, entries)
CatalogList = tuple[str, str, str, list[str]]


def slugify(text: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return slug[:64].strip("-")


def _value(entry: str) -> str:
    return entry.split("|")[-1]


# --------------------------------------------------------------------------
# Slicers: canonical snapshot entries -> {slug: CatalogList}
# --------------------------------------------------------------------------

def slice_aws(entries: list[str]) -> dict[str, CatalogList]:
    by_service: dict[str, list[str]] = {}
    for e in entries:
        parts = e.split("|")
        if len(parts) != 4:
            continue
        by_service.setdefault(parts[2], []).append(parts[3])
    out = {}
    for service, prefixes in sorted(by_service.items()):
        slug = "aws-" + slugify(service)
        out[slug] = ("AWS", f"AWS {service.replace('_', ' ').title()}",
                     f"Amazon Web Services {service} ranges, all regions.",
                     prefixes)
    return out


# source name -> (cloud label, slug prefix)
_M365_CLOUDS = {
    "m365_endpoints": ("Worldwide", "m365"),
    "m365_gcc_high": ("US Gov GCC High", "m365-gcchigh"),
    "m365_dod": ("US Gov DoD", "m365-dod"),
    "m365_china": ("21Vianet (China)", "m365-china"),
}


def slice_m365(source: str, entries: list[str]) -> dict[str, CatalogList]:
    cloud, prefix = _M365_CLOUDS[source]
    groups: dict[tuple[str, str], list[str]] = {}
    for e in entries:
        parts = e.split("|")
        if len(parts) != 4:
            continue
        kind, area, _cat, value = parts
        groups.setdefault((area, kind), []).append(value)
    out = {}
    for (area, kind), values in sorted(groups.items()):
        form = "ips" if kind == "ip" else "urls"
        slug = f"{prefix}-{slugify(area)}-{form}"
        out[slug] = (
            "Microsoft 365",
            f"Microsoft 365 {cloud} {area} {'IPs' if kind == 'ip' else 'URLs'}",
            f"{area} endpoints for Microsoft 365 {cloud}: "
            + ("IP ranges." if kind == "ip" else "URLs and domains."),
            values)
    return out


def slice_azure(entries: list[str]) -> tuple[dict[str, CatalogList], int]:
    """Per-tag lists. Entries whose tag name is empty come from snapshots
    written before the normalizer fix; they cannot be sliced honestly, so
    they are skipped (and counted for the build log), never shipped as one
    giant undifferentiated Azure list."""
    by_tag: dict[str, list[str]] = {}
    skipped = 0
    for e in entries:
        parts = e.split("|")
        if len(parts) != 4:
            continue
        tag = parts[1]
        if not tag:
            skipped += 1
            continue
        by_tag.setdefault(tag, []).append(parts[3])
    out = {}
    for tag, prefixes in sorted(by_tag.items()):
        slug = "azure-" + slugify(tag)
        out[slug] = ("Microsoft Azure", f"Azure {tag}",
                     f"Azure service tag {tag} address prefixes.", prefixes)
    return out, skipped


def slice_single(slug: str, vendor: str, name: str, description: str,
                 entries: Iterable[str]) -> dict[str, CatalogList]:
    return {slug: (vendor, name, description, [_value(e) for e in entries])}


def slice_github_meta(entries: list[str]) -> dict[str, CatalogList]:
    by_key: dict[str, list[str]] = {}
    for e in entries:
        parts = e.split("|")
        if len(parts) != 3:
            continue
        value = parts[2]
        try:
            ipaddress.ip_network(value, strict=False)
        except ValueError:
            continue  # meta also carries non-address values; not list material
        by_key.setdefault(parts[1], []).append(value)
    return {f"github-{slugify(key)}":
            ("GitHub", f"GitHub {key}",
             f"GitHub {key} address ranges from the GitHub meta API.", values)
            for key, values in sorted(by_key.items())}


SLICERS: dict[str, Callable[[list[str]], dict[str, CatalogList]]] = {
    "aws_ip_ranges": slice_aws,
    "gcp_cloud": lambda e: slice_single(
        "gcp-cloud", "Google Cloud", "Google Cloud ranges",
        "Google Cloud customer and service ranges, all regions.", e),
    "gcp_goog": lambda e: slice_single(
        "google-workspace", "Google", "Google Workspace",
        "Google front-end ranges used by Gmail, Drive, Meet and the other "
        "Workspace apps.", e),
    "cloudflare_ips": lambda e: slice_single(
        "cloudflare", "Cloudflare", "Cloudflare ranges",
        "Cloudflare edge network ranges.", e),
    "github_meta": slice_github_meta,
    "adobe_endpoints": lambda e: slice_single(
        "adobe", "Adobe", "Adobe apps and services",
        "Creative Cloud and Acrobat network endpoints (domains) from "
        "Adobe's published endpoints list.", e),
}


# --------------------------------------------------------------------------
# Build
# --------------------------------------------------------------------------

def load_snapshot(snapshots_dir: Path, source: str) -> list[str] | None:
    path = snapshots_dir / f"{source}.json"
    if not path.exists():
        return None
    try:
        return list(json.loads(path.read_text(encoding="utf-8"))["entries"])
    except (ValueError, KeyError, OSError):
        return None


def _write_if_changed(path: Path, body: str) -> None:
    """Write only on a real change, so an unchanged rebuild leaves the
    output tree byte-identical and a commit step sees no diff."""
    try:
        if path.read_text(encoding="utf-8") == body:
            return
    except OSError:
        pass
    path.write_text(body, encoding="utf-8", newline="\n")


def _existing_manifest(path: Path) -> dict:
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
        return doc if isinstance(doc, dict) else {}
    except (ValueError, OSError):
        return {}


def build(snapshots_dir: Path, out_dir: Path, base_url: str,
          generated_at: str) -> dict:
    """Slice every known snapshot into catalog files + the manifest.
    Returns the manifest dict; files are written under out_dir."""
    catalog: dict[str, CatalogList] = {}
    warnings: list[str] = []

    for source in sorted(set(SLICERS) | set(_M365_CLOUDS)
                         | {"azure_service_tags"}):
        entries = load_snapshot(snapshots_dir, source)
        if entries is None:
            warnings.append(f"{source}: no snapshot, skipped")
            continue
        if source in _M365_CLOUDS:
            produced = slice_m365(source, entries)
        elif source == "azure_service_tags":
            produced, skipped = slice_azure(entries)
            if skipped:
                warnings.append(
                    f"azure_service_tags: {skipped} entries have no tag "
                    "name (pre-fix snapshot) and were not catalogued")
        else:
            produced = SLICERS[source](entries)
        for slug, item in produced.items():
            if slug in catalog:
                warnings.append(f"{slug}: produced twice, keeping first")
                continue
            catalog[slug] = item

    out_dir.mkdir(parents=True, exist_ok=True)
    manifest_lists = []
    for slug in sorted(catalog):
        vendor, name, description, values = catalog[slug]
        values = sorted(set(values))
        body = "".join(v + "\n" for v in values)
        _write_if_changed(out_dir / f"{slug}.txt", body)
        manifest_lists.append({
            "slug": slug, "name": name, "vendor": vendor,
            "description": description, "format": "list",
            "entries": len(values), "bytes": len(body.encode("utf-8")),
            "url": base_url.rstrip("/") + f"/catalog/{slug}.txt",
        })
    manifest_lists.sort(key=lambda m: (m["vendor"], m["name"]))
    # The stamp alone must not dirty the output: with a fresh generated_at
    # every run, catalog.json changes daily even when no list did, and the
    # workflow's commit step pushes a no-op snapshot commit. When the lists
    # are unchanged, keep the previous manifest, stamp included.
    previous = _existing_manifest(out_dir / "catalog.json")
    if previous.get("lists") == manifest_lists:
        manifest = {"generated_at": previous.get("generated_at") or generated_at,
                    "lists": manifest_lists}
    else:
        manifest = {"generated_at": generated_at, "lists": manifest_lists}
        _write_if_changed(out_dir / "catalog.json",
                          json.dumps(manifest, indent=1) + "\n")
    for w in warnings:
        print(f"WARN {w}", file=sys.stderr)
    return manifest


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--snapshots", default="snapshots",
                    help="directory holding infra-watch <source>.json files")
    ap.add_argument("--out", default="catalog",
                    help="directory to write <slug>.txt files and catalog.json")
    ap.add_argument("--base-url", default=DEFAULT_BASE_URL,
                    help="public base the manifest URLs are built from")
    args = ap.parse_args(argv)
    generated_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    manifest = build(Path(args.snapshots), Path(args.out), args.base_url,
                     generated_at)
    total = sum(m["entries"] for m in manifest["lists"])
    print(f"catalog: {len(manifest['lists'])} lists, {total} entries total")
    for m in manifest["lists"]:
        print(f"  {m['slug']}: {m['entries']} entries, {m['bytes']} bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
