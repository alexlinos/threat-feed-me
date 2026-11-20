"""Must-not-block IP ownership guard (issue #18).

Refuses to push High/selected IP addresses or CIDRs that overlap vendor-operated
shared infrastructure (public DNS resolvers, Cloudflare edge, Google Workspace /
Search frontends, Microsoft 365 Worldwide, AWS CloudFront, GitHub frontends,
and operator-added networks) while deliberately leaving rentable cloud tenant
compute (GCP Compute, AWS EC2/AMAZON, Azure tenant space, GitHub Actions)
blockable.

Zero live DNS or WHOIS calls at push time: the guard runs entirely in memory
from a baked baseline (DNS resolvers + Cloudflare edge) merged with a daily
cached bundle (``catalog/ownership_guard.json`` published on the
``infra-snapshots`` branch by ``scripts/build_catalog.py``) plus operator
extensions and overrides from ``config.yaml``.
"""
from __future__ import annotations

from bisect import bisect_right
from datetime import datetime, timezone
import ipaddress
import json
import logging
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import urljoin, urlsplit

import requests

from threatfeedme.feed_ingestor import (
    ResponseTooLargeError,
    UnsafeURLError,
    _FETCH_TIMEOUT,
    _read_capped_bytes,
    _require_public_url,
    guarded_get,
)
from threatfeedme.safety import KNOWN_GOOD, SHARED_EDGE

logger = logging.getLogger(__name__)

DEFAULT_GUARD_URL = (
    "https://raw.githubusercontent.com/alexlinos/"
    "threat-feed-me/infra-snapshots/catalog/ownership_guard.json"
)

# SQLite settings keys (same persistence model as catalog_sync).
GUARD_DOC_KEY = "ownership_guard_doc"
GUARD_FETCHED_KEY = "ownership_guard_fetched_at"
GUARD_ERROR_KEY = "ownership_guard_last_error"

_MAX_GUARD_BYTES = 2 * 1024 * 1024
_MAX_GUARD_REDIRECTS = 5
_ALLOWED_REDIRECT_SUFFIX = "githubusercontent.com"
_MIN_V4_PREFIX = 8
_MIN_V6_PREFIX = 20
# The most IPv4 space one bundle may protect. The per-prefix floor above
# stops a single absurd range, not a few hundred plausible ones: 256 valid
# /8s cover every address, and a guard that matches everything empties
# every install's pushed lists without one error. Built from the vendors'
# files on 2026-11-20 the bundle covered 8.9 million addresses (0.21% of
# IPv4), about 12 million once CloudFront's IPv4 ranges are in it; 2% is
# several times that and still far from "everything". A bundle over the cap
# is refused whole and the last good one stays in use. IPv6 has no cap:
# its space is too large for a share of it to mean anything, and the /20
# floor is what bounds a range there.
MAX_V4_COVERAGE = (2 ** 32) // 50

# Always-on baked floor so air-gapped installs and fresh boots before the first
# remote refresh still protect core DNS resolvers and Cloudflare shared edge.
BAKED_VENDORS: Dict[str, Tuple[str, ...]] = {
    "dns_resolvers": tuple(KNOWN_GOOD),
    "cloudflare": tuple(SHARED_EDGE),
}


class OwnershipGuardError(Exception):
    """Remote ownership-guard fetch or parse error (never fatal on refresh)."""


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _host_of(url: str) -> str:
    return (urlsplit(url).hostname or "").lower()


def _is_allowed_redirect(current: str, next_host: str) -> bool:
    if not next_host:
        return False
    if next_host == _host_of(current):
        return True
    return (
        next_host.endswith("." + _ALLOWED_REDIRECT_SUFFIX)
        or next_host == _ALLOWED_REDIRECT_SUFFIX
    )


def guard_config(config: Optional[Dict]) -> Dict:
    """Resolve `safety.ownership_guard` with safe defaults."""
    safety = (config or {}).get("safety")
    raw = (safety.get("ownership_guard") if isinstance(safety, dict) else None)
    cfg = dict(raw) if isinstance(raw, dict) else {}
    cfg.setdefault("enabled", True)
    cfg.setdefault("remote_enabled", True)
    cfg.setdefault("url", DEFAULT_GUARD_URL)
    cfg.setdefault("interval_hours", 24)
    cfg.setdefault("fail_closed_on_missing_cache", False)
    cfg.setdefault("extra_ranges", [])
    cfg.setdefault("allow_ranges", [])
    cfg.setdefault("allow_vendors", [])
    return cfg


def http_get_text(url: str) -> str:
    """Fetch ownership_guard.json over public HTTPS under the connect-time SSRF
    guard, with a 2 MB streaming cap and same-CDN redirect policy."""
    if not url.lower().startswith("https://"):
        raise OwnershipGuardError(f"ownership guard URL must be https:// (got {url!r})")
    resp = None
    current = url
    try:
        for _ in range(_MAX_GUARD_REDIRECTS + 1):
            _require_public_url(current)
            resp = guarded_get(
                current,
                allow_private=False,
                get=requests.get,
                timeout=_FETCH_TIMEOUT,
                allow_redirects=False,
            )
            if resp.status_code in (301, 302, 303, 307, 308):
                loc = (resp.headers.get("location") or "").strip()
                resp.close()
                resp = None
                if not loc:
                    raise OwnershipGuardError("ownership guard redirect missing Location header")
                next_url = urljoin(current, loc)
                if not next_url.lower().startswith("https://"):
                    raise OwnershipGuardError("ownership guard redirect left TLS")
                if not _is_allowed_redirect(current, _host_of(next_url)):
                    raise OwnershipGuardError(
                        f"ownership guard redirect to '{_host_of(next_url)}' refused"
                    )
                current = next_url
                continue
            if resp.status_code != 200:
                raise OwnershipGuardError(f"ownership guard fetch got HTTP {resp.status_code}")
            try:
                raw = _read_capped_bytes(
                    resp, "ownership_guard", max_bytes=_MAX_GUARD_BYTES
                )
            except ResponseTooLargeError:
                raise OwnershipGuardError("ownership guard bundle exceeded 2 MB cap") from None
            return raw.decode(resp.encoding or "utf-8", errors="replace")
        raise OwnershipGuardError("ownership guard exceeded redirect limit")
    except OwnershipGuardError:
        raise
    except UnsafeURLError as e:
        raise OwnershipGuardError(str(e)) from None
    except requests.RequestException as e:
        raise OwnershipGuardError(f"ownership guard fetch failed: {type(e).__name__}") from None
    finally:
        if resp is not None:
            try:
                resp.close()
            except Exception:
                pass


def parse_guard_doc(text: str) -> Dict[str, List[str]]:
    """Validate and extract `{vendor: [cidr, ...]}` from ownership_guard.json.

    Refuses malformed JSON, wrong schema_version, empty vendor maps, or any
    prefix wider than /8 (IPv4) or /20 (IPv6) so a poisoned bundle can never
    blank out a push."""
    try:
        doc = json.loads(text)
    except ValueError as e:
        raise OwnershipGuardError(f"ownership guard JSON is malformed: {e}") from None
    if not isinstance(doc, dict) or doc.get("schema_version") != 1:
        raise OwnershipGuardError("ownership guard bundle must be a JSON object with schema_version=1")
    vendors_raw = doc.get("vendors")
    if not isinstance(vendors_raw, dict) or not vendors_raw:
        raise OwnershipGuardError("ownership guard bundle has no vendors map")
    cleaned: Dict[str, List[str]] = {}
    for vendor, cidrs in vendors_raw.items():
        vname = str(vendor or "").strip()
        if not vname or not isinstance(cidrs, list):
            continue
        valid_cidrs: List[str] = []
        for item in cidrs:
            try:
                net = ipaddress.ip_network(str(item).strip(), strict=False)
            except ValueError:
                continue
            floor = _MIN_V4_PREFIX if net.version == 4 else _MIN_V6_PREFIX
            if net.prefixlen < floor:
                raise OwnershipGuardError(
                    f"ownership guard vendor '{vname}' contains overly wide prefix {net}"
                )
            valid_cidrs.append(str(net))
        if valid_cidrs:
            cleaned[vname] = valid_cidrs
    if not cleaned:
        raise OwnershipGuardError("ownership guard bundle contained no valid prefixes")
    covered = v4_coverage(c for cidrs in cleaned.values() for c in cidrs)
    if covered > MAX_V4_COVERAGE:
        raise OwnershipGuardError(
            f"ownership guard bundle covers {covered:,} IPv4 addresses, over the "
            f"{MAX_V4_COVERAGE:,} limit; refusing it")
    return cleaned


def v4_coverage(cidrs: Iterable[str]) -> int:
    """How many IPv4 addresses a set of ranges covers, overlaps counted once."""
    nets = []
    for c in cidrs:
        try:
            net = ipaddress.ip_network(str(c).strip(), strict=False)
        except ValueError:
            continue
        if net.version == 4:
            nets.append(net)
    return sum(n.num_addresses for n in ipaddress.collapse_addresses(nets))


def refresh_ownership_guard(
    db, config: Optional[Dict], fetch: Optional[Callable[[str], str]] = None
) -> Dict:
    """Fetch and cache the remote ownership_guard.json bundle in SQLite.

    Never raises and never destroys an existing cached bundle on failure."""
    cfg = guard_config(config)
    if not cfg.get("enabled", True) or not cfg.get("remote_enabled", True):
        return {"status": "disabled"}
    url = str(cfg.get("url") or DEFAULT_GUARD_URL)
    fetch_fn = fetch or http_get_text
    try:
        text = fetch_fn(url)
        vendors = parse_guard_doc(text)
    except Exception as e:
        if db is not None:
            try:
                db.set_setting(GUARD_ERROR_KEY, f"{_utcnow_iso()}: {e}")
            except Exception:
                pass
        logger.warning("[ownership_guard] keeping last-known bundle (%s): %s", url, e)
        return {"status": "error", "reason": str(e)}

    if db is not None:
        db.set_setting(GUARD_DOC_KEY, json.dumps({"schema_version": 1, "vendors": vendors}))
        db.set_setting(GUARD_FETCHED_KEY, _utcnow_iso())
        db.delete_setting(GUARD_ERROR_KEY)
    total = sum(len(v) for v in vendors.values())
    logger.info(
        "[ownership_guard] refreshed bundle: %d vendors, %d prefixes",
        len(vendors),
        total,
    )
    return {"status": "synced", "vendors": len(vendors), "prefixes": total}


def status(db, config: Optional[Dict]) -> Dict:
    """What the guard is working from right now, for the Integrations page.
    The built-in ranges are only DNS resolvers and Cloudflare; everything
    else arrives in the fetched bundle, and an operator reading the docs
    would otherwise assume it is in force when it has never been fetched.
    Never raises, and carries no error text: only whether the last fetch
    failed."""
    out = {"enabled": False, "remote_enabled": False, "bundle_loaded": False,
           "vendors": [], "fetched_at": "", "fetch_failed": False}
    try:
        cfg = guard_config(config)
        guard = OwnershipGuard.from_config(config, db=db)
        out.update(enabled=guard.enabled,
                   remote_enabled=bool(cfg.get("remote_enabled", True)),
                   bundle_loaded=guard.remote_loaded,
                   vendors=sorted(guard.vendor_counts))
        if db is not None:
            out["fetched_at"] = db.get_setting(GUARD_FETCHED_KEY) or ""
            out["fetch_failed"] = bool(db.get_setting(GUARD_ERROR_KEY))
    except Exception:
        logger.exception("[ownership_guard] could not read the guard's state")
    return out


def _parse_range_bounds(value: str) -> Optional[Tuple[int, int, int]]:
    """Return `(version, lo, hi)` for an IP or CIDR string, else None."""
    try:
        net = ipaddress.ip_network(str(value).strip(), strict=False)
    except ValueError:
        return None
    return net.version, int(net.network_address), int(net.broadcast_address)


class _IntervalIndex:
    """Sorted integer interval index with prefix max_hi for fast overlap queries."""

    __slots__ = ("_starts", "_entries", "_max_hi")

    def __init__(self, entries: Iterable[Tuple[int, int, str]]):
        sorted_entries = sorted(entries, key=lambda item: (item[0], item[1]))
        self._entries: List[Tuple[int, int, str]] = sorted_entries
        self._starts: List[int] = [e[0] for e in sorted_entries]
        max_hi: List[int] = []
        running = -1
        for _lo, hi, _label in sorted_entries:
            if hi > running:
                running = hi
            max_hi.append(running)
        self._max_hi: List[int] = max_hi

    def find_overlap(self, lo: int, hi: int) -> Optional[str]:
        """Return the label of the first interval overlapping `[lo, hi]`, else None."""
        idx = bisect_right(self._starts, hi) - 1
        while idx >= 0 and self._max_hi[idx] >= lo:
            e_lo, e_hi, label = self._entries[idx]
            if e_lo <= hi and lo <= e_hi:
                return label
            idx -= 1
        return None

    def __len__(self) -> int:
        return len(self._entries)


class OwnershipGuard:
    """In-memory must-not-block IP ownership matcher with explicit overrides."""

    def __init__(
        self,
        vendors: Dict[str, Sequence[str]],
        *,
        enabled: bool = True,
        allow_ranges: Sequence[str] = (),
        allow_vendors: Sequence[str] = (),
        remote_loaded: bool = False,
        fail_closed_on_missing_cache: bool = False,
        remote_enabled: bool = True,
    ):
        self.enabled = bool(enabled)
        self.remote_loaded = bool(remote_loaded)
        self.fail_closed_on_missing_cache = bool(fail_closed_on_missing_cache)
        self.remote_enabled = bool(remote_enabled)
        self._logged_overrides: set = set()

        allowed_v = {str(v).strip().lower() for v in (allow_vendors or ()) if str(v).strip()}
        if self.enabled and allowed_v:
            logger.warning(
                "[ownership_guard] explicit allow_vendors override active for: %s",
                ", ".join(sorted(allowed_v)),
            )

        by_ver: Dict[int, List[Tuple[int, int, str]]] = {4: [], 6: []}
        self.vendor_counts: Dict[str, int] = {}
        for vendor, cidrs in (vendors or {}).items():
            vname = str(vendor).strip()
            if not vname or vname.lower() in allowed_v:
                continue
            added = 0
            for raw in cidrs or ():
                parsed = _parse_range_bounds(raw)
                if parsed is None:
                    continue
                ver, lo, hi = parsed
                by_ver[ver].append((lo, hi, vname))
                added += 1
            if added:
                self.vendor_counts[vname] = self.vendor_counts.get(vname, 0) + added
        self._protected = {4: _IntervalIndex(by_ver[4]), 6: _IntervalIndex(by_ver[6])}

        allow_by_ver: Dict[int, List[Tuple[int, int, str]]] = {4: [], 6: []}
        for raw in allow_ranges or ():
            parsed = _parse_range_bounds(raw)
            if parsed is None:
                continue
            ver, lo, hi = parsed
            allow_by_ver[ver].append((lo, hi, str(raw).strip()))
        self._allowed = {
            4: _IntervalIndex(allow_by_ver[4]),
            6: _IntervalIndex(allow_by_ver[6]),
        }

    @classmethod
    def from_config(cls, config: Optional[Dict], db=None) -> "OwnershipGuard":
        """Build an OwnershipGuard from baked defaults + cached DB bundle + config."""
        cfg = guard_config(config)
        vendors: Dict[str, List[str]] = {
            k: list(v) for k, v in BAKED_VENDORS.items()
        }
        remote_loaded = False
        if db is not None and cfg.get("remote_enabled", True):
            try:
                raw_doc = db.get_setting(GUARD_DOC_KEY)
                if raw_doc:
                    remote_vendors = parse_guard_doc(raw_doc)
                    for vname, cidrs in remote_vendors.items():
                        vendors[vname] = list(cidrs)
                    remote_loaded = True
            except Exception as e:
                logger.warning("[ownership_guard] ignoring unreadable cached bundle: %s", e)

        for entry in cfg.get("extra_ranges") or ():
            if isinstance(entry, dict):
                cidr = str(entry.get("cidr") or entry.get("range") or "").strip()
                vname = str(entry.get("vendor") or entry.get("label") or "operator").strip()
            else:
                cidr = str(entry or "").strip()
                vname = "operator"
            if cidr:
                vendors.setdefault(vname or "operator", []).append(cidr)

        return cls(
            vendors,
            enabled=bool(cfg.get("enabled", True)),
            allow_ranges=cfg.get("allow_ranges") or (),
            allow_vendors=cfg.get("allow_vendors") or (),
            remote_loaded=remote_loaded,
            fail_closed_on_missing_cache=bool(cfg.get("fail_closed_on_missing_cache", False)),
            remote_enabled=bool(cfg.get("remote_enabled", True)),
        )

    def check_ready(self) -> None:
        """Fail closed when the operator requires a cached remote bundle before
        pushing and none has been loaded yet."""
        if (
            self.enabled
            and self.fail_closed_on_missing_cache
            and self.remote_enabled
            and not self.remote_loaded
        ):
            raise RuntimeError(
                "ownership guard failed closed: no remote ownership bundle is cached yet "
                "(wait for the daily refresh or set safety.ownership_guard.fail_closed_on_missing_cache: false)"
            )

    def match(self, value: str) -> Optional[str]:
        """Return the protected vendor name if `value` (IP or CIDR) must not be
        blocked, or None if it may be emitted. Logs a warning when an explicit
        `allow_ranges` override permits an otherwise protected address."""
        if not self.enabled:
            return None
        parsed = _parse_range_bounds(value)
        if parsed is None:
            return None
        ver, lo, hi = parsed
        vendor = self._protected[ver].find_overlap(lo, hi)
        if vendor is None:
            return None
        override = self._allowed[ver].find_overlap(lo, hi)
        if override is not None:
            key = (value, vendor, override)
            if key not in self._logged_overrides:
                self._logged_overrides.add(key)
                logger.warning(
                    "[ownership_guard] allowing %s despite protected vendor '%s' "
                    "(explicit allow_ranges override '%s')",
                    value,
                    vendor,
                    override,
                )
            return None
        return vendor
