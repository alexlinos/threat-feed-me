#!/usr/bin/env python3
"""Track upstream changes to the application-list sources.

Fetches every vendor infrastructure list the application catalog is built
from (AWS, Microsoft 365, Google Cloud, Google, Azure service
tags, Cloudflare, GitHub meta), normalizes each to a sorted set of canonical
entry strings, and diffs against the snapshots kept on the ``infra-snapshots``
orphan branch. The CI workflow runs this daily, commits new snapshots, and
opens an alert issue when a change is big enough to matter or looks hostile
(a CIDR suddenly wider than the 2.6 prefix floor allows).

Why in CI rather than in the app: scripts/build_catalog.py slices these
snapshots into the catalog every install reads, and a poisoned vendor file
should page the maintainer, not silently pass through a production change
guard.

Parsers are pure functions over already-parsed JSON so the test suite can
exercise them offline against fixtures (repo rule: no network in tests).

Exit codes: 0 = ok, 1 = alert-worthy change, 2 = at least one fetch failed
or parsed to nothing (the last good snapshot is kept).
"""

from __future__ import annotations

import argparse
import ipaddress
from typing import Any, Callable
import json
import os
import re
import sys
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

import requests

USER_AGENT = "threat-feed-me-infra-watch/1.0 (+https://github.com/alexlinos/threat-feed-me)"
FETCH_TIMEOUT = 60
MAX_BYTES = 32 * 1024 * 1024  # vendor files are < 1 MB; cap hostile/looped bodies
_MAX_RETRIES = 3
_RETRYABLE_STATUS = {429, 500, 502, 503, 504}
_sleep = time.sleep

# Alert thresholds (overridable on the CLI). The prefix floors mirror the
# 2.6 application-list safety rules: a v4 prefix never wider than /8, v6
# never wider than /20. Watching a floor one step above the hard limit
# gives early warning of vendor mistakes or a poisoned file.
DEFAULT_CHANGE_PCT = 10.0       # alert when +/- entries exceed this share
DEFAULT_V4_FLOOR_ALERT = 8      # alert if any v4 prefix is narrower than /8
DEFAULT_V6_FLOOR_ALERT = 20     # alert if any v6 prefix is narrower than /20


# --------------------------------------------------------------------------
# Fetchers (thin; network only through get_json/get_text)
# --------------------------------------------------------------------------

def get(url: str, headers: dict | None = None) -> bytes:
    last_exc: Exception | None = None
    for attempt in range(1, _MAX_RETRIES + 1):
        try:
            with requests.get(
                url,
                headers={"User-Agent": USER_AGENT, **(headers or {})},
                timeout=FETCH_TIMEOUT,
                stream=True,
            ) as resp:
                if resp.status_code in _RETRYABLE_STATUS and attempt < _MAX_RETRIES:
                    _sleep(2 ** (attempt - 1))
                    continue
                resp.raise_for_status()
                body = resp.raw.read(MAX_BYTES + 1, decode_content=True)
                if len(body) > MAX_BYTES:
                    raise ValueError(f"response over {MAX_BYTES} bytes: {url}")
                return body
        except requests.RequestException as exc:
            last_exc = exc
            if attempt < _MAX_RETRIES:
                _sleep(2 ** (attempt - 1))
                continue
            raise
    raise last_exc or RuntimeError(f"failed to fetch {url}")


def get_json(url: str, headers: dict | None = None):
    return json.loads(get(url, headers).decode("utf-8", errors="replace"))


def fetch_aws():
    return get_json("https://ip-ranges.amazonaws.com/ip-ranges.json")


def fetch_m365_instance(instance: str):
    # The endpoints API wants a per-request GUID; a per-run GUID keeps
    # vendor-side request logging honest without identifying anyone.
    guid = str(uuid.uuid4())
    url = f"https://endpoints.office.com/endpoints/{instance}?clientrequestid=" + guid
    return get_json(url, headers={"X-MSEdge-ClientID": guid})


def fetch_m365():
    return fetch_m365_instance("Worldwide")


def fetch_gcp_cloud():
    return get_json("https://www.gstatic.com/ipranges/cloud.json")


def fetch_gcp_goog():
    return get_json("https://www.gstatic.com/ipranges/goog.json")


AZURE_DETAILS_URL = "https://www.microsoft.com/en-us/download/details.aspx?id=56519"
# The blob URL rotates weekly; the details page is the only keyless way to
# find the current one. Match the public ServiceTags JSON blob specifically.
AZURE_BLOB_RE = re.compile(
    r"https://download\.microsoft\.com/[^\s\"'<>]+ServiceTags_Public[^\s\"'<>]*\.json")


def fetch_azure():
    page = get(AZURE_DETAILS_URL).decode("utf-8", errors="replace")
    candidates = sorted(set(AZURE_BLOB_RE.findall(page)))
    if not candidates:
        raise ValueError("no ServiceTags_Public blob link found on the Azure details page")
    return get_json(candidates[-1])  # date-stamped names sort newest-last


def fetch_cloudflare():
    return get_json("https://api.cloudflare.com/client/v4/ips")


def fetch_github_meta():
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    headers = {"Authorization": f"Bearer {token}"} if token else None
    return get_json("https://api.github.com/meta", headers=headers)


ZOOM_FILES = {
    "meetings": "https://assets.zoom.us/docs/ipranges/ZoomMeetings.txt",
    "phone": "https://assets.zoom.us/docs/ipranges/ZoomPhone.txt",
    "crc": "https://assets.zoom.us/docs/ipranges/ZoomCRC.txt",
    "contact_center": "https://assets.zoom.us/docs/ipranges/ZoomCC.txt",
    "cdn": "https://assets.zoom.us/docs/ipranges/ZoomCDN.txt",
}


def fetch_zoom():
    return {
        service: get(url).decode("utf-8", errors="replace")
        for service, url in ZOOM_FILES.items()
    }


def fetch_atlassian():
    return get_json("https://ip-ranges.atlassian.com/")


def fetch_okta():
    return get_json("https://s3.amazonaws.com/okta-ip-ranges/ip_ranges.json")


def fetch_fastly():
    return get_json("https://api.fastly.com/public-ip-list")


def fetch_oci():
    return get_json("https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json")


def fetch_digitalocean():
    return get("https://digitalocean.com/geo/google.csv").decode("utf-8", errors="replace")


STRIPE_FILES = {
    "api": "https://stripe.com/files/ips/ips_api.txt",
    "webhooks": "https://stripe.com/files/ips/ips_webhooks.txt",
}


def fetch_stripe():
    return {
        service: get(url).decode("utf-8", errors="replace")
        for service, url in STRIPE_FILES.items()
    }


# --------------------------------------------------------------------------
# Normalizers: parsed JSON -> set of canonical "kind|a|b" entry strings
# --------------------------------------------------------------------------

def normalize_aws(data: dict) -> set[str]:
    # AWS names the two families differently: IPv4 is "prefixes" (entries
    # keyed ip_prefix), IPv6 is "ipv6_prefixes" (entries keyed ipv6_prefix).
    # This read "ipv4_prefixes" from the day the catalog shipped until
    # 2.7.7, a key that does not exist, so every published AWS list was
    # IPv6-only and nothing failed. A family that parses to nothing is now
    # a failed fetch: the snapshot is kept and the run turns red.
    out = set()
    for key, field, kind in (("prefixes", "ip_prefix", "v4"),
                             ("ipv6_prefixes", "ipv6_prefix", "v6")):
        rows = data.get(key) or []
        if not rows:
            raise ValueError(f"AWS ranges: no {kind} entries under '{key}'")
        for p in rows:
            out.add(f"{kind}|{p.get('region','')}|{p.get('service','')}|{p[field]}")
    return out


def normalize_m365(data: list) -> set[str]:
    out = set()
    for ep in data:
        area = ep.get("serviceArea", "")
        cat = ep.get("category", "")
        for ip in ep.get("ips", []):
            out.add(f"ip|{area}|{cat}|{ip}")
        for url in ep.get("urls", []):
            out.add(f"url|{area}|{cat}|{url}")
    return out


def normalize_gcp(data: dict) -> set[str]:
    # Live shape (2026-11): {"prefixes": [{"ipv4Prefix", "service", "scope"}...]}
    out = set()
    for r in data.get("prefixes", []):
        scope = r.get("scope", "")
        service = r.get("service", "")
        for key in ("ipv4Prefix", "ipv6Prefix"):
            if r.get(key):
                kind = "v4" if key == "ipv4Prefix" else "v6"
                out.add(f"{kind}|{scope}|{service}|{r[key]}")
    return out


def normalize_azure(data: dict) -> set[str]:
    out = set()
    for pl in data.get("values", []):
        # Live shape: {"name": "Storage.EastUS", "properties": {"region": ...,
        # "addressPrefixes": [...]}}. The tag name lives on the value, NOT
        # inside properties; reading it from properties yielded "" for every
        # entry and made per-tag slicing impossible (found while building
        # the application catalog, issue #28).
        props = pl.get("properties", pl)
        name = pl.get("name") or props.get("name", "")
        region = props.get("regionName") or props.get("region") or "Global"
        for prefix in props.get("addressPrefixes", []):
            out.add(f"cidr|{name}|{region}|{prefix}")
    return out


def normalize_cloudflare(data: dict) -> set[str]:
    # Live shape: {"result": {"ipv4_cidrs": [...], "ipv6_cidrs": [...]}}
    out = set()
    result = data.get("result", {})
    for key, kind in (("ipv4_cidrs", "v4"), ("ipv6_cidrs", "v6")):
        for cidr in result.get(key, []):
            out.add(f"{kind}|{cidr}")
    return out


# Only these /meta keys are list material (runner addresses move the most).
GITHUB_META_KEYS = ("hooks", "web", "api", "ssh", "importer", "packages",
                    "runner", "pages", "actions", "dependabot", "backup")


def normalize_github_meta(data: dict) -> set[str]:
    out = set()
    for key in GITHUB_META_KEYS:
        for value in data.get(key, []):
            if isinstance(value, str):
                out.add(f"meta|{key}|{value}")
    return out


def _valid_ip_or_cidr(raw: str) -> str | None:
    token = (raw or "").strip()
    if not token or token.startswith("#"):
        return None
    try:
        net = ipaddress.ip_network(token, strict=False)
    except ValueError:
        return None
    return str(net.network_address) if "/" not in token else str(net)


def normalize_zoom(data: dict) -> set[str]:
    # {service: plain-text CIDR lines}
    out = set()
    for service, text in (data or {}).items():
        if not isinstance(text, str):
            continue
        for line in text.splitlines():
            val = _valid_ip_or_cidr(line)
            if val:
                out.add(f"zoom|{service}|{val}")
    return out


def normalize_atlassian(data: dict) -> set[str]:
    # Live shape: {"items": [{"cidr": "...", "product": [...], "direction": [...]}]}
    out = set()
    for item in (data or {}).get("items", []):
        if not isinstance(item, dict):
            continue
        cidr = _valid_ip_or_cidr(item.get("cidr", ""))
        if not cidr:
            continue
        products = item.get("product") or ["general"]
        directions = item.get("direction") or ["both"]
        for prod in products:
            for direction in directions:
                out.add(f"atlassian|{prod}|{direction}|{cidr}")
    return out


_OKTA_CELL_RE = re.compile(r"^([a-z]+?)(?:_(pam|workflow))?_cell_\d+$", re.IGNORECASE)


def normalize_okta(data: dict) -> set[str]:
    # Live shape: {"us_cell_1": {"ip_ranges": ["192.0.2.1/32", ...]}, ...}
    out = set()
    for cell, payload in (data or {}).items():
        if not isinstance(payload, dict):
            continue
        m = _OKTA_CELL_RE.match(str(cell))
        if m:
            region = m.group(1).lower()
            svc_raw = (m.group(2) or "core").lower()
            service = "workflows" if svc_raw == "workflow" else svc_raw
        else:
            region = str(cell).split("_", 1)[0].lower() or "other"
            service = "core"
        for raw in payload.get("ip_ranges", []):
            val = _valid_ip_or_cidr(str(raw))
            if val:
                out.add(f"okta|{region}|{service}|{val}")
    return out


def normalize_fastly(data: dict) -> set[str]:
    # Live shape: {"addresses": [...], "ipv6_addresses": [...]}
    out = set()
    for key, kind in (("addresses", "v4"), ("ipv6_addresses", "v6")):
        rows = (data or {}).get(key) or []
        if not rows:
            raise ValueError(f"Fastly ranges: no {kind} entries under '{key}'")
        for raw in rows:
            val = _valid_ip_or_cidr(str(raw))
            if val:
                out.add(f"{kind}|{val}")
    return out


def normalize_oci(data: dict) -> set[str]:
    # Live shape: {"regions": [{"region": "...", "cidrs": [{"cidr": "...", "tags": [...]}]}]}
    out = set()
    for reg in (data or {}).get("regions", []):
        if not isinstance(reg, dict):
            continue
        region = str(reg.get("region") or "global")
        for row in reg.get("cidrs", []):
            if not isinstance(row, dict):
                continue
            cidr = _valid_ip_or_cidr(str(row.get("cidr") or ""))
            if not cidr:
                continue
            tags = row.get("tags") or ["OCI"]
            for tag in tags:
                out.add(f"oci|{region}|{tag}|{cidr}")
    return out


def normalize_digitalocean(data: str) -> set[str]:
    # Live shape: geofeed CSV "cidr,country,region,city,postal"
    out = set()
    for line in (data or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(",")
        cidr = _valid_ip_or_cidr(parts[0])
        if not cidr:
            continue
        country = (parts[1].strip().upper() if len(parts) > 1 and parts[1].strip() else "ZZ")
        out.add(f"do|{country}|{cidr}")
    return out


def normalize_stripe(data: dict) -> set[str]:
    # {service: plain-text IP lines}
    out = set()
    for service, text in (data or {}).items():
        if not isinstance(text, str):
            continue
        for line in text.splitlines():
            val = _valid_ip_or_cidr(line)
            if val:
                out.add(f"stripe|{service}|{val}")
    return out


@dataclass
class Source:
    name: str
    fetch: Callable[[], Any]      # () -> parsed JSON
    normalize: Callable[[Any], set[str]]  # (parsed) -> set[str]
    note: str = ""
    data: Any = field(default=None, repr=False)


SOURCES = [
    Source("aws_ip_ranges", fetch_aws, normalize_aws),
    Source("m365_endpoints", fetch_m365, normalize_m365),
    Source("m365_gcc_high", lambda: fetch_m365_instance("USGovGCCHigh"),
           normalize_m365, note="sovereign cloud instance"),
    Source("m365_dod", lambda: fetch_m365_instance("USGovDoD"),
           normalize_m365, note="sovereign cloud instance"),
    Source("m365_china", lambda: fetch_m365_instance("China"),
           normalize_m365, note="sovereign cloud instance (21Vianet)"),
    Source("gcp_cloud", fetch_gcp_cloud, normalize_gcp),
    Source("gcp_goog", fetch_gcp_goog, normalize_gcp),
    Source("azure_service_tags", fetch_azure, normalize_azure,
           note="blob URL found via the download page weekly"),
    Source("cloudflare_ips", fetch_cloudflare, normalize_cloudflare),
    Source("github_meta", fetch_github_meta, normalize_github_meta),
    Source("zoom_ips", fetch_zoom, normalize_zoom),
    Source("atlassian_ips", fetch_atlassian, normalize_atlassian),
    Source("okta_ips", fetch_okta, normalize_okta),
    Source("fastly_ips", fetch_fastly, normalize_fastly),
    Source("oci_ips", fetch_oci, normalize_oci),
    Source("digitalocean_ips", fetch_digitalocean, normalize_digitalocean),
    Source("stripe_ips", fetch_stripe, normalize_stripe),
]


# --------------------------------------------------------------------------
# Diffing and guards
# --------------------------------------------------------------------------

def snapshot_path(snapshots_dir: Path, name: str) -> Path:
    return snapshots_dir / f"{name}.json"


def load_previous(snapshots_dir: Path, name: str) -> set[str] | None:
    path = snapshot_path(snapshots_dir, name)
    if not path.exists():
        return None
    try:
        return set(json.loads(path.read_text(encoding="utf-8"))["entries"])
    except (ValueError, KeyError, OSError):
        return None  # corrupt snapshot: treat as no baseline, reseed silently


def min_prefixes(entries: set[str]) -> tuple[int, int]:
    """Narrowest (smallest prefixlen) v4 and v6 CIDR seen, 128/999 if none.

    A CIDR in a vendor file that is suddenly wider than the floors is the
    fingerprint of a poisoned or broken source, so it alerts independently
    of the change volume.
    """
    v4, v6 = 128, 999
    for e in entries:
        cidr = e.split("|")[-1]
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        if net.version == 4:
            v4 = min(v4, net.prefixlen)
        else:
            v6 = min(v6, net.prefixlen)
    return v4, v6


def evaluate(source: Source, previous: set[str] | None, current: set[str],
             change_pct: float, v4_floor: int, v6_floor: int) -> dict:
    """Compare one source against its baseline; return the report row."""
    row = {"status": "ok", "count": len(current), "baseline": previous is None}
    if previous is None:
        row.update(added=len(current), removed=0, pct_change=100.0, alert=False)
        return row  # first run seeds the baseline; not an event
    added = current - previous
    removed = previous - current
    denom = max(len(previous), 1)
    pct = 100.0 * (len(added) + len(removed)) / denom
    row.update(added=len(added), removed=len(removed),
               added_sample=sorted(added)[:5], removed_sample=sorted(removed)[:5])
    reasons = []
    if pct > change_pct:
        reasons.append(f"changed {pct:.1f}% of entries (threshold {change_pct:g}%)")
    v4, v6 = min_prefixes(current)
    if v4 < v4_floor:
        reasons.append(f"IPv4 prefix wider than /{v4_floor} (narrowest /{v4})")
    if v6 < v6_floor:
        reasons.append(f"IPv6 prefix wider than /{v6_floor} (narrowest /{v6})")
    row["pct_change"] = round(pct, 2)
    row["min_v4_prefix"] = None if v4 == 128 else v4
    row["min_v6_prefix"] = None if v6 == 999 else v6
    row["alert"] = bool(reasons)
    row["alert_reasons"] = reasons
    return row


def render_report(results: dict[str, dict], fetched_at: str) -> str:
    lines = [f"# Infra list watch — {fetched_at}", ""]
    lines.append("| source | entries | +added | -removed | %change | status |")
    lines.append("|---|---|---|---|---|---|")
    for name, r in results.items():
        status = r["status"]
        if r["status"] == "ok" and r.get("alert"):
            status = "ALERT: " + "; ".join(r["alert_reasons"])
        elif r.get("baseline"):
            status = "baseline seeded"
        lines.append(f"| {name} | {r.get('count','-')} | {r.get('added','-')} "
                     f"| {r.get('removed','-')} | {r.get('pct_change','-')} | {status} |")
    for name, r in results.items():
        if r.get("added_sample") or r.get("removed_sample"):
            lines.append("")
            lines.append(f"## {name}")
            for label, key in (("added", "added_sample"), ("removed", "removed_sample")):
                for e in r.get(key, []):
                    lines.append(f"- {label}: `{e}`")
    lines.append("")
    return "\n".join(lines)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--snapshots", default="snapshots",
                    help="directory holding <source>.json baselines")
    ap.add_argument("--update", action="store_true",
                    help="write new snapshots and report.md into --snapshots")
    ap.add_argument("--only", action="append", default=None,
                    help="run just this source (repeatable); local debugging")
    ap.add_argument("--change-pct", type=float, default=DEFAULT_CHANGE_PCT)
    ap.add_argument("--v4-floor", type=int, default=DEFAULT_V4_FLOOR_ALERT)
    ap.add_argument("--v6-floor", type=int, default=DEFAULT_V6_FLOOR_ALERT)
    ap.add_argument("--accept-alert", action="store_true",
                    help="write alerting sources as the new baseline instead of holding them")
    args = ap.parse_args(argv)

    snapshots_dir = Path(args.snapshots)
    snapshots_dir.mkdir(parents=True, exist_ok=True)
    sources = [s for s in SOURCES if not args.only or s.name in args.only]

    results: dict[str, dict] = {}
    fetch_failed = False
    for src in sources:
        try:
            src.data = src.fetch()
            entries = src.normalize(src.data)
            if not entries:
                # A vendor changing its file shape parses to nothing; taking
                # that as "everything removed" would publish emptied lists.
                raise ValueError("no entries parsed")
        except (requests.RequestException, ValueError, KeyError, TypeError) as exc:
            fetch_failed = True
            results[src.name] = {"status": f"fetch failed: {exc}", "count": None,
                                 "alert": False, "baseline": False}
            print(f"FAIL {src.name}: {exc}", file=sys.stderr)
            continue
        previous = load_previous(snapshots_dir, src.name)
        r = evaluate(src, previous, entries,
                     args.change_pct, args.v4_floor, args.v6_floor)
        results[src.name] = r
        # Hold alerting sources at their last-good snapshot unless explicitly
        # accepted (--accept-alert), so a suspicious swing on one vendor does
        # not freeze updates for the other healthy vendors. Also skip rewriting
        # unchanged snapshots (azure_service_tags.json is >6 MB) so daily no-op
        # runs don't churn git with timestamp-only diffs.
        should_write = (
            args.update
            and (not r.get("alert") or args.accept_alert)
            and (previous is None or entries != previous)
        )
        if should_write:
            payload = {"source": src.name, "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                       "entries": sorted(entries)}
            snapshot_path(snapshots_dir, src.name).write_text(
                json.dumps(payload, indent=1, sort_keys=True) + "\n", encoding="utf-8")
        print(f"{src.name}: {r.get('count')} entries, +{r.get('added', 0)} "
              f"-{r.get('removed', 0)} ({r.get('pct_change', 0)}%) "
              f"{'ALERT' if r.get('alert') else 'ok'}")

    fetched_at = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime())
    report = render_report(results, fetched_at)
    print("\n" + report)
    if args.update:
        (snapshots_dir / "report.md").write_text(report, encoding="utf-8")
        (snapshots_dir / "report.json").write_text(
            json.dumps({"fetched_at": fetched_at, "sources": results}, indent=1) + "\n",
            encoding="utf-8")

    if fetch_failed:
        return 2
    if any(r.get("alert") for r in results.values()) and not args.accept_alert:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
