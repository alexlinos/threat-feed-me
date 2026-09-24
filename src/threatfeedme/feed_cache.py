"""
Lean, cached rendering of the firewall-facing feed URLs (/feeds/*).

Why (review 2026-09-22): every poll used to materialize the whole tier as
ThreatIndicator objects (plus a json.loads of each row's metadata) before
writing a byte. A /feeds/low.txt poll over ~560k IPs peaked around 1.6 GB and
took ~15 s, anyone on the LAN could trigger it, and two overlapping polls
could exceed the container's 3 GB cap. Now:

  * rows stream from the DB as plain tuples (Database.iter_served_rows);
  * .txt — the format firewalls poll — is built once per data version into a
    compact bytes body with line offsets, then reused: repeat polls cost a
    fingerprint query, return an ETag, and honour If-None-Match (304);
  * .csv / .json stream straight from the cursor in constant memory;
  * ?limit=N serves the top N by score (the list is score-ordered). That is
    what lets a firewall with an entry cap — ~131k on mid-range FortiGates —
    keep the strongest entries instead of an arbitrary slice, and it is where
    the recurrence predictor's within-tier ordering finally changes what a
    capped firewall blocks.

Same entries, same formats, same score order as the old renderer (txt and CSV
byte-identical under that order). Two deliberate differences: ties in score
are now ordered by value — the old SQL left them in unspecified order, and a
deterministic tie-break is what keeps ?limit=N stable between polls instead
of flickering entries in and out of a capped firewall's list — and the JSON's
total_count follows the indicators array (a streamed body can't know the count
first; key order carries no meaning in JSON; the on-disk export always did
this). Measured on 300k IPs: build peak 772 MB -> 12 MB, 9.2 s -> 3.5 s, and
a repeat poll of an unchanged list 8 ms.
"""
import csv
import hashlib
import io
import json
import threading
from array import array
from datetime import datetime, timezone
from typing import Dict, Iterator, Optional, Tuple

from threatfeedme.exporter import row_included
from threatfeedme.models import ConfidenceTier, CUMULATIVE_TIERS

SERVE_STAMP_KEY = "serve_stamp"

# Output feed name -> (stored tiers served, tier whose scoped whitelist
# entries apply). Cumulative: medium serves high+medium; low and all serve
# everything ("all" honours tier:low scopes, exactly as before).
_FEEDS = {
    "high": (CUMULATIVE_TIERS[ConfidenceTier.HIGH], ConfidenceTier.HIGH),
    "medium": (CUMULATIVE_TIERS[ConfidenceTier.MEDIUM], ConfidenceTier.MEDIUM),
    "low": (CUMULATIVE_TIERS[ConfidenceTier.LOW], ConfidenceTier.LOW),
    "all": (tuple(ConfidenceTier), ConfidenceTier.LOW),
}


def _dt_str(raw):
    """The old CSV wrote str(datetime) (space-separated); keep it identical."""
    try:
        return str(datetime.fromisoformat(raw))
    except (TypeError, ValueError):
        return raw


def _dt_iso(raw):
    """The old JSON wrote datetime.isoformat(); keep it identical."""
    try:
        return datetime.fromisoformat(raw).isoformat()
    except (TypeError, ValueError):
        return raw


def iter_rows(db, name: str, kind: str, limit: Optional[int] = None) -> Iterator[tuple]:
    """Whitelist-filtered served rows for one feed URL, score order, <= limit."""
    tiers, scope = _FEEDS[name]
    wl_map = db.get_whitelist_map()
    served = 0
    for row in db.iter_served_rows(kind, tiers):
        if limit is not None and served >= limit:
            return
        if row_included(row[0], row[2], wl_map, tier=scope):
            served += 1
            yield row


def _value(row) -> str:
    return row[1] or row[0]      # firewall_value: the netblock if there is one


# ---- .txt: built once per data version, then reused -------------------------

class _TxtEntry:
    __slots__ = ("version", "body", "offsets", "etag")

    def __init__(self, version, body, offsets, etag):
        self.version, self.body, self.offsets, self.etag = version, body, offsets, etag


_txt: Dict[Tuple[str, str], _TxtEntry] = {}
_locks: Dict[Tuple[str, str], threading.Lock] = {}
_locks_guard = threading.Lock()


def _lock_for(key) -> threading.Lock:
    with _locks_guard:
        return _locks.setdefault(key, threading.Lock())


def _build_txt(db, name: str, kind: str, version: str) -> _TxtEntry:
    buf = io.BytesIO()
    offsets = array("Q", [0])        # offsets[i] = byte offset after i lines
    for row in iter_rows(db, name, kind):
        buf.write(_value(row).encode() + b"\n")
        offsets.append(buf.tell())
    # stable across restarts (hash() is salted per process)
    digest = hashlib.sha1(f"{kind}:{name}:{version}".encode()).hexdigest()[:16]
    etag = f'"{digest}"'
    return _TxtEntry(version, buf.getvalue(), offsets, etag)


def txt(db, name: str, kind: str, limit: Optional[int] = None) -> Tuple[bytes, str]:
    """The .txt body (optionally the top `limit` lines) and its ETag.
    Single-flight per URL: concurrent polls wait for one build, never
    run their own."""
    key = (kind, name)
    version = db.serve_fingerprint()
    entry = _txt.get(key)
    if entry is None or entry.version != version:
        with _lock_for(key):
            entry = _txt.get(key)
            if entry is None or entry.version != version:
                entry = _build_txt(db, name, kind, version)
                _txt[key] = entry
    if limit is None or limit >= len(entry.offsets) - 1:
        return entry.body, entry.etag
    return entry.body[:entry.offsets[limit]], entry.etag[:-1] + f"-top{limit}\""


def invalidate() -> None:
    _txt.clear()


def mark_scores_changed(db) -> None:
    """Called after a rescore: tiers/scores changed in place, which row counts
    can't see. Bumps the stamp that serve_fingerprint reads."""
    db.set_setting(SERVE_STAMP_KEY, datetime.now(timezone.utc).isoformat())


# ---- .csv / .json: streamed straight from the cursor -------------------------

def stream_csv(db, name: str, kind: str, limit: Optional[int] = None) -> Iterator[bytes]:
    out = io.StringIO()
    writer = csv.writer(out)
    # The first column is the indicator value; the header keeps the historical
    # name "ip" for both kinds so existing SIEM column mappings don't break.
    writer.writerow(["ip", "confidence_score", "tier", "first_seen", "last_seen", "sources"])
    n = 0
    for row in iter_rows(db, name, kind, limit):
        writer.writerow([_value(row), row[3], row[4], _dt_str(row[5]), _dt_str(row[6]),
                         ";".join(row[2])])
        n += 1
        if n % 2000 == 0:
            yield out.getvalue().encode()
            out.seek(0); out.truncate()
    yield out.getvalue().encode()


def stream_json(db, name: str, kind: str, limit: Optional[int] = None) -> Iterator[bytes]:
    # Compact separators + ensure_ascii=False: exactly what Starlette's
    # JSONResponse rendered before, so the values and bytes match.
    def dump(v):
        return json.dumps(v, ensure_ascii=False, separators=(",", ":")).encode()

    feed = name if kind == "ip" else f"domains/{name}"
    yield (b'{"feed":' + dump(feed) + b',"generated_at":' +
           dump(datetime.now(timezone.utc).isoformat()) + b',"indicators":[')
    n = 0
    chunk = []
    for row in iter_rows(db, name, kind, limit):
        chunk.append((b"," if n else b"") + dump({
            "value": _value(row), "ip": row[0], "confidence_score": row[3],
            "tier": row[4], "sources": row[2], "last_seen": _dt_iso(row[6]),
        }))
        n += 1
        if len(chunk) >= 1000:
            yield b"".join(chunk); chunk = []
    yield b"".join(chunk) + b'],"total_count":' + str(n).encode() + b"}"
