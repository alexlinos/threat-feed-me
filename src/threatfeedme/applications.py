"""Application lists (2.6 slice 1): vendor allow-lists, kept out of intel.

Policy, not intel. These lists exist so a firewall can ALLOW or exempt
traffic (Microsoft 365, cloud ranges, SaaS egress pinning). They never enter
the indicator corpus, the vote engine, overlap telemetry, the churn log or
the predictor — corroboration means nothing for a vendor's own ranges, and
false-positive feedback inverts when the entry is known-good by definition.
The separation is enforced structurally: own tables, own serving routes
(/lists/*), own dashboard view, and this module is the only writer.

The safety rules are deliberately NOT the threat-list ones. The known-good
output filter must not run here (it would strip the entries, which *are*
known-good infrastructure). What runs instead, at every emission:

  * prefix floor: no IPv4 prefix wider than a configurable /8, no IPv6
    wider than /20 — the anti-`0.0.0.0/0` rule from the 2.6 design;
  * bogon / private / special-use address rejection;
  * the change guard: a refresh that moves more than a threshold share of
    a list is held for operator approval, never served silently.

Fetches arm the same connect-time SSRF guard the feed ingestor uses
(private-address policy, safety.allow_private_feed_urls), because these
URLs are operator-supplied and must obey the same rule as any feed URL.
See fetch(): the guard is thread-local and does nothing unless armed.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import re
import time
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests

from threatfeedme.domains import is_valid_domain
from threatfeedme.feed_ingestor import (ResponseTooLargeError, UnsafeURLError,
                                        _read_capped_bytes, guarded_get)
from threatfeedme.safety import _SPECIAL_V4, _SPECIAL_V6

logger = logging.getLogger(__name__)

USER_AGENT = "threat-feed-me (application list fetch)"

# Prefix floors and the change guard, per the 2.6 design constraints. The
# floors are configurable per list; these are the shipped defaults.
DEFAULT_V4_FLOOR = 8
DEFAULT_V6_FLOOR = 20
DEFAULT_CHANGE_PCT = 50.0
DEFAULT_UPDATE_INTERVAL = 21600  # 6h: vendor files move slowly, ETags make idle polls free

# Caps that bound what one malicious or broken vendor file can cost.
MAX_BODY_BYTES = 32 * 1024 * 1024
MAX_ENTRIES = 500_000
MAX_ENTRY_LEN = 512
HISTORY_RETENTION_DAYS = 30
HISTORY_KEEP_ROWS = 200          # age-independent floor, so audit never blanks
DIFF_SAMPLE_CAP = 500            # per side, in the stored diff

_CONTROL_CHARS = re.compile(r"[\x00-\x20\x7f\u202a-\u202e\u2066-\u2069\u200e\u200f]")
_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$")


def valid_name(name: str) -> bool:
    """List names land in URLs (/lists/<name>.txt) and must be inert there."""
    return bool(_NAME_RE.match(name or ""))


# --------------------------------------------------------------------------
# Entry validation (the emission gate)
# --------------------------------------------------------------------------

# RFC5737/3849 documentation ranges: ipaddress marks them private ("not
# globally reachable"), but for an allow-list they are harmless stand-ins —
# operators test with them and the repo's fixtures use them.
# Excluding them from the special-use rule keeps the gate honest without
# failing on samples that can never carry real traffic.
_DOCUMENTATION_NETS = tuple(ipaddress.ip_network(n) for n in (
    "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32"))


def _net_ok(net: ipaddress.IPv4Network | ipaddress.IPv6Network,
            v4_floor: int, v6_floor: int) -> Tuple[bool, str]:
    if net.version == 4 and net.prefixlen < v4_floor:
        return False, f"IPv4 prefix wider than /{v4_floor}"
    if net.version == 6 and net.prefixlen < v6_floor:
        return False, f"IPv6 prefix wider than /{v6_floor}"
    if any(net.subnet_of(d) for d in _DOCUMENTATION_NETS
           if d.version == net.version):
        return True, ""
    # An allow-list entry in special-use space is a bug or a poison attempt:
    # an allow for your own network is firewall config, not something a
    # served list should carry. Overlap, not containment, is the rule, as
    # in safety.py: is_private on a NETWORK needs both ends private, so a
    # supernet straddling it (172.0.0.0/8 holds 172.16.0.0/12) passed the
    # is_* tests alone in 2.7.0. Those stay for the rest of reserved space.
    for special in (_SPECIAL_V4 if net.version == 4 else _SPECIAL_V6):
        if net.overlaps(special):
            return False, f"special-use address space (overlaps {special})"
    if (net.is_private or net.is_loopback or net.is_link_local
            or net.is_multicast or net.is_reserved or net.is_unspecified):
        return False, "special-use address space"
    return True, ""


def guard_entry(entry: str, v4_floor: int = DEFAULT_V4_FLOOR,
                v6_floor: int = DEFAULT_V6_FLOOR) -> Tuple[bool, str]:
    """Accept an entry only if it is inert policy data. Returns (ok, reason).

    Accepted shapes: IP, CIDR, domain, *.wildcard, and http(s) URLs (the
    M365 shape). Anything network-shaped goes through the prefix floor and
    the special-use check; anything host-shaped through the domain rules.
    """
    if not entry or len(entry) > MAX_ENTRY_LEN or _CONTROL_CHARS.search(entry):
        return False, "empty, oversized or contains control characters"
    if "://" in entry:
        try:
            parsed = urlparse(entry)
        except ValueError:
            return False, "unparseable URL"
        if parsed.scheme not in ("http", "https"):
            return False, "URL scheme is not http(s)"
        host = (parsed.hostname or "").lower().rstrip(".")
        if not host:
            return False, "URL has no host"
        return guard_entry(host.lstrip("*."), v4_floor, v6_floor) \
            if not host.startswith("*") else _domain_ok(host)
    if entry.startswith("*."):
        return _domain_ok(entry)
    try:
        net = ipaddress.ip_network(entry, strict=False)
    except ValueError:
        # Not a network; a single IP comes back here as host/32 would, so
        # it is either a bare IP (handled above) or a host name.
        return _domain_ok(entry)
    return _net_ok(net, v4_floor, v6_floor)


def _domain_ok(host: str) -> Tuple[bool, str]:
    bare = host[2:] if host.startswith("*.") else host
    if bare.count("*") > 1 or (host.startswith("*") and not host.startswith("*.")):
        return False, "malformed wildcard"
    if is_valid_domain(bare):
        return True, ""
    # A bare IPv4 slipped past ip_network (e.g. a malformed octet string);
    # anything that is neither a valid domain nor an IP is junk.
    return False, "not an IP, CIDR, domain, wildcard or URL"


def filter_entries(entries: List[str], v4_floor: int, v6_floor: int
                   ) -> Tuple[List[str], List[Tuple[str, str]]]:
    """The emission gate: (accepted sorted-unique, [(entry, reason) rejected])."""
    ok: set = set()
    rejected: List[Tuple[str, str]] = []
    for e in entries:
        good, reason = guard_entry(e.strip(), v4_floor, v6_floor)
        if good:
            ok.add(e.strip())
        else:
            rejected.append((e[:MAX_ENTRY_LEN], reason))
        if len(ok) > MAX_ENTRIES:
            raise ValueError(f"list exceeds {MAX_ENTRIES} entries")
    return sorted(ok), rejected


# --------------------------------------------------------------------------
# Source parsing: plain list or JSON + filter expression
# --------------------------------------------------------------------------

def extract_json_paths(data: Any, expr: str) -> List[str]:
    """A JSONPath subset: ``$.a.b[*].c`` -> list of leaf strings.

    Deliberately small — enough that most vendor files are configuration,
    not code (the 2.6 engine decision). Dots descend, ``[*]`` expands one
    level, a leaf may be a string, a number, or a list of strings. Anything
    richer belongs in a dedicated fetcher, not in a parser a vendor file
    can steer.
    """
    if expr.startswith("$."):
        expr = expr[2:]
    elif expr.startswith("$"):
        expr = expr[1:]
    out: List[str] = []
    nodes: List[Any] = [data]
    for token in expr.split("."):
        if not token:
            continue
        key, _, index = token.partition("[")
        expand = index == "*]"
        nxt: List[Any] = []
        for node in nodes:
            if isinstance(node, dict) and key in node:
                nxt.append(node[key])
        if not nxt:
            raise ValueError(f"filter expression found nothing at '{key}'")
        if expand:
            expanded: List[Any] = []
            for node in nxt:
                if isinstance(node, list):
                    expanded.extend(node)
                else:
                    expanded.append(node)
            nxt = expanded
        nodes = nxt
    for node in nodes:
        if isinstance(node, str):
            out.append(node)
        elif isinstance(node, (int, float)):
            out.append(str(node))
        elif isinstance(node, list):
            for item in node:
                if isinstance(item, (str, int, float)):
                    out.append(str(item))
    return out


def parse_body(body: str, fmt: str, filter_expr: str) -> List[str]:
    """Raw response body -> raw entry strings, before the guard."""
    if fmt == "json":
        data = json.loads(body)
        if not filter_expr:
            raise ValueError("JSON lists need a filter expression")
        return extract_json_paths(data, filter_expr)
    lines: List[str] = []
    for line in body.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            lines.append(line)
    return lines


def fetch(url: str, etag: Optional[str] = None,
          get: Callable = requests.get,
          allow_private: bool = False) -> Tuple[Optional[str], Optional[str]]:
    """Conditional GET. Returns (body, new_etag), or (None, etag) on 304.

    SSRF policy, same as a feed fetch (safety.allow_private_feed_urls),
    through feed_ingestor.guarded_get: the connect-time guard armed for the
    request, env proxies off, the body streamed under a running byte cap.
    2.7.0 called requests.get directly and assumed a process-wide guard;
    the guard is thread-local and only armed on request, so list URLs could
    read cloud metadata or any LAN host.
    """
    headers = {"User-Agent": USER_AGENT}
    if etag:
        headers["If-None-Match"] = etag
    resp = guarded_get(url, allow_private=allow_private, get=get,
                       headers=headers, timeout=60)
    try:
        resp.raise_for_status()
        if resp.status_code == 304:
            return None, etag
        raw = _read_capped_bytes(resp, url, MAX_BODY_BYTES)
    finally:
        resp.close()
    return raw.decode("utf-8", errors="replace"), resp.headers.get("ETag")


# --------------------------------------------------------------------------
# Refresh: fetch -> guard -> change guard -> store or hold
# --------------------------------------------------------------------------

def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _stamp_epoch(stamp: str) -> float:
    """Epoch seconds for a stored timestamp.

    The database stamps rows with ``_utcnow_iso()`` (offset form, e.g.
    ``2026-11-06T13:45:52.050315+00:00``); a ``Z`` suffix and naive stamps
    are read as UTC too. Parsing must accept what the writer emits: a
    format mismatch here makes every list look permanently due.
    """
    from datetime import datetime, timezone
    text = stamp.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def refresh_list(db, name: str, get: Callable = requests.get,
                 allow_private: bool = False) -> Dict[str, Any]:
    """One list, one poll. Never raises for a vendor error: the per-list
    status is what the dashboard shows, and one dead vendor must not stop
    the scheduler pass. `get` is injectable for tests (repo rule: offline).
    """
    row = db.get_application_list(name)
    if row is None:
        raise ValueError(f"unknown list '{name}'")
    summary: Dict[str, Any] = {"name": name, "outcome": "ok"}
    try:
        body, new_etag = fetch(row["source_url"], row.get("http_etag"), get=get,
                               allow_private=allow_private)
        if body is None:
            db.set_application_list_state(name, status="not-modified")
            summary["outcome"] = "not-modified"
            return summary
        raw = parse_body(body, row["format"], row.get("filter_expr") or "")
        accepted, rejected = filter_entries(raw, row["min_v4_prefix"], row["min_v6_prefix"])
        current = set(db.get_entries(name))
        added = set(accepted) - current
        removed = current - set(accepted)
        pct = 100.0 * (len(added) + len(removed)) / max(len(current), 1)
        summary.update(count=len(accepted), added=len(added), removed=len(removed),
                       rejected=len(rejected), pct=round(pct, 2))
        if current and pct > row["change_threshold_pct"]:
            # Change guard: hold the refresh, keep serving the last approved
            # version. "Hold and ask" beats "serve and discover".
            db.add_pending(name, accepted,
                           [{"e": e} for e in sorted(added)][:DIFF_SAMPLE_CAP],
                           [{"e": e} for e in sorted(removed)][:DIFF_SAMPLE_CAP],
                           reason=(f"refresh moves {pct:.1f}% of the list "
                                   f"(threshold {row['change_threshold_pct']:g}%)"),
                           added_count=len(added), removed_count=len(removed))
            db.set_application_list_state(name, status=f"held: {pct:.1f}% change",
                                          etag=new_etag)
            summary["outcome"] = "held"
            return summary
        db.replace_entries(name, accepted, len(added), len(removed),
                           sorted(added)[:DIFF_SAMPLE_CAP], sorted(removed)[:DIFF_SAMPLE_CAP])
        db.set_application_list_state(name, status="ok", etag=new_etag)
        if rejected:
            sample = "; ".join(f"{e}: {r}" for e, r in rejected[:5])
            summary["status_note"] = f"{len(rejected)} rejected ({sample})"
            db.set_application_list_state(name, status=f"ok ({len(rejected)} rejected)")
        return summary
    # An SSRF refusal or an oversized body is a per-list status like any
    # other vendor error, not a 500. Other RuntimeErrors are bugs and stay
    # loud.
    except (requests.RequestException, ValueError, KeyError, TypeError, OSError,
            UnsafeURLError, ResponseTooLargeError) as exc:
        logger.warning("[applications] refresh of %s failed: %s", name, exc)
        db.set_application_list_state(name, status=f"error: {str(exc)[:200]}")
        summary.update(outcome="error", error=str(exc)[:300])
        return summary


def refresh_due(db, allow_private: bool = False) -> List[Dict[str, Any]]:
    """Scheduler pass: refresh every enabled list whose interval elapsed.
    Sequential by design — these are a handful of vendor URLs and the ETag
    path costs one request each; a pool would just add a way to hammer a
    vendor on a clock bug."""
    summaries = []
    for row in db.get_application_lists(enabled_only=True):
        interval = int(row["update_interval"] or DEFAULT_UPDATE_INTERVAL)
        last = row.get("last_refresh_at")
        if last:
            try:
                if time.time() - _stamp_epoch(last) < interval:
                    continue
            except ValueError:
                pass  # unparseable stamp: treat as due
        try:
            summaries.append(refresh_list(db, row["name"], allow_private=allow_private))
        except Exception as exc:  # a broken row must not end the pass
            logger.warning("[applications] %s: %s", row["name"], exc)
    db.prune_application_history(HISTORY_RETENTION_DAYS, HISTORY_KEEP_ROWS)
    return summaries
