"""
Read-only TAXII 2.1 server (v2.5.0): the served tiers as STIX 2.1 Indicators,
so a SIEM or TIP (Microsoft Sentinel, QRadar, Splunk, MISP, OpenCTI) can
subscribe the way MineMeld's TAXII output let them.

Six collections, one per served feed: {High, Medium, Everything} x {IPs,
Domains}. Content is exactly what the matching /feeds URL serves (same tiers,
same whitelist and tier-scoped rules via exporter.row_included); only the
wire format differs. Unauthenticated and read-only, like /feeds: machine
consumers poll it, and the content is treated as non-secret.

Ordering and paging follow the spec's "date added": an indicator's date added
is its last_seen (when a feed last re-affirmed it), so a client polling with
added_after receives everything still being reported since its last poll,
and each object's valid_until (last_seen + VALID_DAYS) lets the client expire
what stops being reported. Paging is a keyset over (last_seen, value) carried
in an opaque `next` token, stable while a refresh rewrites rows.

No stix2 dependency: the objects are small, and the image stays lean.
"""
import base64
import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple

from threatfeedme.exporter import row_included
from threatfeedme.models import CUMULATIVE_TIERS, ConfidenceTier

TAXII_MEDIA = "application/taxii+json;version=2.1"
STIX_MEDIA = "application/stix+json;version=2.1"

# Namespace for deterministic ids: the same indicator keeps the same STIX id
# across polls (and across installs), so clients update it in place instead
# of accumulating duplicates. The OASIS validator notes these are not UUIDv4
# (a SHOULD for SDOs); deterministic ids are the deliberate trade-off.
_NS = uuid.UUID("5b1f6a58-7d3e-4c1e-9d59-0f3a3e2c7b11")

DEFAULT_LIMIT = 1000
MAX_LIMIT = 10000
VALID_DAYS = 7

_TIERS = {
    "high": (CUMULATIVE_TIERS[ConfidenceTier.HIGH], ConfidenceTier.HIGH, "High confidence"),
    "medium": (CUMULATIVE_TIERS[ConfidenceTier.MEDIUM], ConfidenceTier.MEDIUM,
               "Medium confidence (includes High)"),
    "all": (tuple(ConfidenceTier), ConfidenceTier.LOW, "Everything"),
}
_KINDS = {"ip": "IP addresses and netblocks", "domain": "Domains"}


def _collection_id(kind: str, tier: str) -> str:
    return str(uuid.uuid5(_NS, f"collection:{kind}:{tier}"))


COLLECTIONS: Dict[str, Tuple[str, str]] = {
    _collection_id(k, t): (k, t) for k in _KINDS for t in _TIERS}


def collection_info(cid: str) -> Dict:
    kind, tier = COLLECTIONS[cid]
    return {
        "id": cid,
        "title": f"threat-feed-me: {_KINDS[kind]}, {_TIERS[tier][2]}",
        "description": (f"The /feeds/{'domains/' if kind == 'domain' else ''}{tier}.txt list "
                        "as STIX 2.1 Indicators: overlap-discounted corroboration across "
                        "independent feeds, whitelist applied."),
        "can_read": True,
        "can_write": False,
        "media_types": [STIX_MEDIA],
    }


def stix_time(raw) -> Optional[str]:
    """Stored ISO timestamp -> STIX timestamp (UTC, millisecond, 'Z')."""
    try:
        dt = datetime.fromisoformat(str(raw))
    except (TypeError, ValueError):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def parse_added_after(raw: str) -> str:
    """A client's added_after -> the stored-timestamp form it is compared
    against. Raises ValueError on anything that is not a timestamp."""
    dt = datetime.fromisoformat(raw.strip().replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat()


def _pattern(kind: str, value: str) -> str:
    esc = value.replace("\\", "\\\\").replace("'", "\\'")
    if kind == "domain":
        obj = "domain-name"
    else:
        obj = "ipv6-addr" if ":" in value else "ipv4-addr"
    return f"[{obj}:value = '{esc}']"


def indicator(kind: str, row) -> Optional[Dict]:
    ip, cidr, sources, score, tier, first, last = row
    value = cidr or ip
    created, modified = stix_time(first), stix_time(last)
    if not created or not modified:
        return None
    if modified < created:          # a re-added row; STIX requires modified >= created
        modified = created
    try:
        until = datetime.fromisoformat(str(last)).astimezone(timezone.utc) + timedelta(days=VALID_DAYS)
        valid_until = stix_time(until.isoformat())
    except (TypeError, ValueError):
        valid_until = None
    feeds = sorted(sources)
    obj = {
        "type": "indicator",
        "spec_version": "2.1",
        "id": f"indicator--{uuid.uuid5(_NS, f'{kind}:{value}')}",
        "created": created,
        "modified": modified,
        "name": value,
        "description": (f"threat-feed-me {tier}-confidence indicator, reported by "
                        f"{len(feeds)} feed{'s' if len(feeds) != 1 else ''}"
                        + (f": {', '.join(feeds)}" if feeds else "")
                        + ". Confidence is overlap-discounted corroboration across "
                          "independent feeds."),
        "indicator_types": ["malicious-activity"],
        "pattern": _pattern(kind, value),
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": created,
        "confidence": max(0, min(100, int(round((score or 0) * 100)))),
        # Tier and reporting feeds as labels (an open vocabulary SIEMs index),
        # not x_ custom properties, which STIX 2.1 wants formalized as
        # extensions (validator warning 401).
        "labels": [f"threat-feed-me:{tier}"] + [f"source:{f}" for f in feeds],
    }
    if valid_until and valid_until > created:
        obj["valid_until"] = valid_until
    return obj


def encode_next(key: Tuple[str, str]) -> str:
    return base64.urlsafe_b64encode(json.dumps(list(key)).encode()).decode().rstrip("=")


def decode_next(token: str) -> Tuple[str, str]:
    """Raises ValueError on a token this server did not issue."""
    pad = "=" * (-len(token) % 4)
    key = json.loads(base64.urlsafe_b64decode(token + pad))
    if (not isinstance(key, list) or len(key) != 2
            or not all(isinstance(k, str) and len(k) <= 300 for k in key)):
        raise ValueError("bad next token")
    return key[0], key[1]


def page(db, cid: str, added_after: Optional[str] = None,
         next_token: Optional[str] = None, limit: int = DEFAULT_LIMIT):
    """One page of a collection: (objects, date_added list, more, next_token).
    Raises ValueError for a malformed next / added_after."""
    kind, tier_name = COLLECTIONS[cid]
    tiers, scope, _label = _TIERS[tier_name]
    limit = max(1, min(MAX_LIMIT, int(limit)))
    if next_token:
        after = decode_next(next_token)
    elif added_after:
        after = (parse_added_after(added_after), "\uffff")   # strictly after that instant
    else:
        after = None
    wl = db.get_whitelist_map()
    objects: List[Dict] = []
    added: List[str] = []
    last_key = None
    more = False
    for row in db.iter_served_rows_by_added(kind, tiers, after=after):
        if len(objects) >= limit:
            more = True
            break
        last_key = (row[6], row[0])
        if not row_included(row[0], row[2], wl, tier=scope):
            continue
        obj = indicator(kind, row)
        if obj is None:
            continue
        objects.append(obj)
        added.append(obj["modified"])
    return objects, added, more, (encode_next(last_key) if more and last_key else None)
