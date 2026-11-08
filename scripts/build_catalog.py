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
    line, exactly what a slice 1 "list" source serves after the guard. A
    file whose list is no longer produced is deleted, so an install that
    had it switched on reports an error instead of serving it frozen.
  * ``catalog.json``: {generated_at, vendors: {name: {description, docs}},
    lists: [{slug, name, vendor, group, description, format, entries,
    bytes, url}]}. ``url`` is --base-url joined with the file name;
    ``group`` is the tab a list sits under on the Applications page
    (Microsoft's endpoint categories; a vendor with one view has one group
    or none); ``docs`` links each vendor's own documentation on what to
    allow.

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

# A catalog list: (vendor, display name, one-line description, entries, group)
CatalogList = tuple[str, str, str, list[str], str]

ALL_REGIONS = "All regions"
ALL_CATEGORIES = "All categories"
M365_CATEGORIES = ("Optimize", "Allow", "Default")

_RENTABLE = (" These ranges also host other customers' workloads, so allowing"
             " them lets anything running there through.")
_M365_TEXT = ("Microsoft sorts these endpoints into three categories: Optimize,"
              " Allow and Default. Most sites want All categories, which"
              " combines the three.")
_GOOGLE_DOCS = "https://support.google.com/a/answer/10026322"
_M365_DOCS = "https://learn.microsoft.com/microsoft-365/enterprise/"

# Vendor -> (description, the vendor's own page on what to allow).
VENDORS: dict[str, tuple[str, str]] = {
    "AWS": ("Amazon Web Services address ranges per service, across all regions."
            " AMAZON and EC2 are rentable space." + _RENTABLE,
            "https://docs.aws.amazon.com/vpc/latest/userguide/aws-ip-ranges.html"),
    "Microsoft Azure": ("Azure service tags, one list per service across all"
                        " regions. AzureCloud is all of Azure's public space."
                        + _RENTABLE,
                        "https://learn.microsoft.com/azure/virtual-network/service-tags-overview"),
    "Microsoft 365 Worldwide": (_M365_TEXT, _M365_DOCS + "urls-and-ip-address-ranges"),
    "Microsoft 365 US Gov GCC High": (
        _M365_TEXT, _M365_DOCS + "microsoft-365-u-s-government-gcc-high-endpoints"),
    "Microsoft 365 US Gov DoD": (
        _M365_TEXT, _M365_DOCS + "microsoft-365-u-s-government-dod-endpoints"),
    "Microsoft 365 China (21Vianet)": (
        _M365_TEXT, _M365_DOCS + "urls-and-ip-address-ranges-21vianet"),
    "Google": ("Google's own front ends: Gmail, Drive, Meet and the other"
               " Workspace apps, kept apart from Google Cloud.", _GOOGLE_DOCS),
    "Google Cloud": ("Google Cloud customer and service ranges, all regions."
                     + _RENTABLE, _GOOGLE_DOCS),
    "Cloudflare": ("Cloudflare's edge network ranges." + _RENTABLE,
                   "https://www.cloudflare.com/ips/"),
    "GitHub": ("GitHub's address ranges per service, from the GitHub meta API.",
               "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/about-githubs-ip-addresses"),
    "Adobe": ("Domains Adobe lists for Creative Cloud, Acrobat and Document Cloud.",
              "https://helpx.adobe.com/enterprise/kb/network-endpoints.html"),
}


def slugify(text: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return slug[:64].strip("-")


def _value(entry: str) -> str:
    return entry.split("|")[-1]


# --------------------------------------------------------------------------
# Slicers: canonical snapshot entries -> {slug: CatalogList}
# --------------------------------------------------------------------------

def _aws_name(service: str) -> str:
    return service.replace("_", " ").title()


def slice_aws(entries: list[str]) -> dict[str, CatalogList]:
    """Per service across all regions. Per service and region was 347 more
    lists from one snapshot; left out until someone needs a region (maintainer,
    2026-11-07), like Azure's regional tags."""
    by_service: dict[str, list[str]] = {}
    for e in entries:
        parts = e.split("|")
        if len(parts) != 4:
            continue
        by_service.setdefault(parts[2], []).append(parts[3])
    return {"aws-" + slugify(service): (
                "AWS", f"AWS {_aws_name(service)}",
                f"Amazon Web Services {service} ranges, all regions.", prefixes, ALL_REGIONS)
            for service, prefixes in sorted(by_service.items())}


# source name -> (vendor, slug prefix)
_M365_CLOUDS = {
    "m365_endpoints": ("Microsoft 365 Worldwide", "m365"),
    "m365_gcc_high": ("Microsoft 365 US Gov GCC High", "m365-gcchigh"),
    "m365_dod": ("Microsoft 365 US Gov DoD", "m365-dod"),
    "m365_china": ("Microsoft 365 China (21Vianet)", "m365-china"),
}
_M365_AREAS = {"Exchange": "Exchange Online",
               "SharePoint": "SharePoint Online and OneDrive",
               "Skype": "Microsoft Teams",
               "Common": "Microsoft 365 Common and Office Online"}


def slice_m365(source: str, entries: list[str]) -> dict[str, CatalogList]:
    """Per service area and form (IPs vs URLs), once with every category
    and once per category. The all-categories slugs are the 2.7 ones."""
    vendor, prefix = _M365_CLOUDS[source]
    groups: dict[tuple[str, str, str], list[str]] = {}
    for e in entries:
        parts = e.split("|")
        if len(parts) != 4:
            continue
        kind, area, cat, value = parts
        groups.setdefault((area, kind, ""), []).append(value)
        if cat in M365_CATEGORIES:
            groups.setdefault((area, kind, cat), []).append(value)
    out = {}
    for (area, kind, cat), values in sorted(groups.items()):
        form = "ips" if kind == "ip" else "urls"
        label = _M365_AREAS.get(area, area)
        what = "IPs" if kind == "ip" else "URLs"
        slug = f"{prefix}-{slugify(area)}-{form}" + (f"-{slugify(cat)}" if cat else "")
        out[slug] = (
            vendor, f"{label} {what}" + (f" ({cat})" if cat else ""),
            f"{label} endpoints"
            + (f" in Microsoft's {cat} category" if cat else ", every category")
            + (": IP ranges." if kind == "ip" else ": URLs and domains."),
            values, cat or ALL_CATEGORIES)
    return out


def slice_azure(entries: list[str]) -> tuple[dict[str, CatalogList], int, int]:
    """One list per service tag across all regions (Storage, AzureCloud):
    about a hundred. Regional tags (Storage.EastUS) are skipped and counted:
    they are some 2,900 more, which would multiply the published files,
    the manifest and the page for a need nobody has asked for yet; the
    global tag already covers every region. Entries whose tag name is empty
    come from snapshots written before the normalizer fix; they cannot be
    sliced honestly, so they are skipped too, never shipped as one giant
    undifferentiated Azure list. Returns (lists, unnamed, regional)."""
    by_tag: dict[str, list[str]] = {}
    unnamed = regional = 0
    for e in entries:
        parts = e.split("|")
        if len(parts) != 4:
            continue
        tag = parts[1]
        if not tag:
            unnamed += 1
            continue
        if "." in tag:
            regional += 1
            continue
        by_tag.setdefault(tag, []).append(parts[3])
    out = {}
    for tag, prefixes in sorted(by_tag.items()):
        out["azure-" + slugify(tag)] = (
            "Microsoft Azure", f"Azure {tag}",
            f"Azure service tag {tag} address prefixes, all regions.", prefixes,
            ALL_REGIONS)
    return out, unnamed, regional


def slice_single(slug: str, vendor: str, name: str, description: str,
                 entries: Iterable[str]) -> dict[str, CatalogList]:
    return {slug: (vendor, name, description, [_value(e) for e in entries], "")}


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
             f"GitHub {key} address ranges from the GitHub meta API.", values, "")
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
            produced, unnamed, regional = slice_azure(entries)
            if unnamed:
                warnings.append(
                    f"azure_service_tags: {unnamed} entries have no tag "
                    "name (pre-fix snapshot) and were not catalogued")
            if regional:
                print(f"azure_service_tags: {regional} regional-tag entries left "
                      "to their all-regions tags", file=sys.stderr)
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
        vendor, name, description, values, group = catalog[slug]
        values = sorted(set(values))
        body = "".join(v + "\n" for v in values)
        _write_if_changed(out_dir / f"{slug}.txt", body)
        manifest_lists.append({
            "slug": slug, "name": name, "vendor": vendor, "group": group,
            "description": description, "format": "list",
            "entries": len(values), "bytes": len(body.encode("utf-8")),
            "url": base_url.rstrip("/") + f"/catalog/{slug}.txt",
        })
    manifest_lists.sort(key=lambda m: (m["vendor"], m["group"], m["name"]))
    vendors = {v: {"description": VENDORS[v][0], "docs": VENDORS[v][1]}
               for v in sorted({m["vendor"] for m in manifest_lists}) if v in VENDORS}

    # Retired lists: delete their files so installs that had one switched on
    # get an error, not a silently frozen allow-list. Never when nothing was
    # produced (every snapshot missing must not wipe the published catalog).
    if manifest_lists:
        for stale in out_dir.glob("*.txt"):
            if stale.stem not in catalog:
                stale.unlink()
                warnings.append(f"{stale.stem}: no longer produced, file removed")

    # The stamp alone must not dirty the output: with a fresh generated_at
    # every run, catalog.json changes daily even when no list did, and the
    # workflow's commit step pushes a no-op snapshot commit. When the lists
    # are unchanged, keep the previous manifest, stamp included.
    previous = _existing_manifest(out_dir / "catalog.json")
    if previous.get("lists") == manifest_lists and previous.get("vendors") == vendors:
        manifest = {"generated_at": previous.get("generated_at") or generated_at,
                    "vendors": vendors, "lists": manifest_lists}
    else:
        manifest = {"generated_at": generated_at, "vendors": vendors,
                    "lists": manifest_lists}
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
