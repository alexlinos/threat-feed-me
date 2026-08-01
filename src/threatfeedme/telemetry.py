"""Feed telemetry: which feeds are actually earning their keep.

The scoring engine already penalizes feeds that produce false positives, but
that signal is invisible until someone flags something and reactive by
definition. This module makes feed value *observable*: how much each feed
contributes that nothing else does, how often it sees a threat first, whether
it is still fresh, and how independent its agreement with other feeds really
is.

Everything here is derived from data already on disk (see the FEED TELEMETRY
section of database.py) — there is no history table to accumulate and no cold
start on a fresh install.
"""
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from threatfeedme.database import Database

# A feed is "first-to-report"-scored over this window. An all-time count would
# unfairly favour whichever feeds were installed longest.
FIRST_REPORT_WINDOW_DAYS = 7
# Freshness window for the churn column.
NEW_WINDOW_HOURS = 24
# A feed is stale once it has gone this multiple of its own update_interval
# without a successful run (a permanently-304ing or silently-dead source).
STALE_INTERVAL_MULTIPLE = 3
# Overlap at or above this fraction of the smaller feed means the two are
# substantially the same list — their agreement is not independent evidence.
REDUNDANT_OVERLAP = 0.9


def _iso_ago(**kwargs) -> str:
    return (datetime.now(timezone.utc) - timedelta(**kwargs)).isoformat()


def _parse(ts) -> Optional[datetime]:
    """Coerce a timestamp to an aware UTC datetime.

    FeedStats.last_update is typed `datetime` (Pydantic parses the stored ISO
    string), but the same field arrives as a raw string from other callers —
    accept both rather than silently reporting every feed as 'unknown'.
    """
    if not ts:
        return None
    if isinstance(ts, datetime):
        dt = ts
    else:
        try:
            dt = datetime.fromisoformat(ts)
        except (ValueError, TypeError):
            return None
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt


def _health(feed, stat, new_count: int) -> Dict[str, Any]:
    """Classify a feed's operational state.

    The failure that actually bites is not a feed ballooning — it is a feed
    quietly dying while the dashboard still shows last week's green 'success'.
    """
    if stat is None or not stat.last_update:
        return {"state": "never run", "level": "muted",
                "detail": "no successful fetch yet"}
    if stat.status != "success":
        return {"state": "error", "level": "bad",
                "detail": stat.error_message or "last run failed"}

    last = _parse(stat.last_update)
    if last is None:
        return {"state": "unknown", "level": "muted", "detail": "unparseable last run"}
    age_s = (datetime.now(timezone.utc) - last).total_seconds()
    interval = feed.update_interval if (feed.update_interval or 0) > 0 else 3600
    if age_s > interval * STALE_INTERVAL_MULTIPLE:
        hours = int(age_s // 3600)
        return {"state": "stale", "level": "warn",
                "detail": f"no successful run in {hours}h (interval {interval // 3600 or 1}h)"}
    if not feed.enabled:
        return {"state": "disabled", "level": "muted", "detail": "not fetched"}
    if new_count == 0:
        return {"state": "no new", "level": "warn",
                "detail": f"nothing new in {NEW_WINDOW_HOURS}h — list may be static"}
    return {"state": "ok", "level": "good", "detail": "fetching and contributing"}


def feed_telemetry(db: Database) -> Dict[str, Any]:
    """Per-feed contribution and health, plus notable feed pairs.

    Returns rows sorted by exclusive contribution: the feeds you would miss
    most if you removed them come first.
    """
    feeds = {f.name: f for f in db.get_feed_sources()}
    stats = {s.feed_name: s for s in db.get_feed_stats()}
    reported = db.get_feed_report_counts()
    exclusive = db.get_feed_exclusive_counts()
    firsts = db.get_feed_first_report_counts(
        since=_iso_ago(days=FIRST_REPORT_WINDOW_DAYS))
    new = db.get_feed_new_counts(since=_iso_ago(hours=NEW_WINDOW_HOURS))
    overlap = db.get_feed_overlap()

    rows = []
    for name, feed in feeds.items():
        total = reported.get(name, 0)
        excl = exclusive.get(name, 0)
        rows.append({
            "name": name,
            "enabled": feed.enabled,
            "indicators": total,
            "exclusive": excl,
            # Share of this feed's own reports that no other feed corroborates.
            "exclusive_pct": round(excl / total * 100) if total else 0,
            "first_reports": firsts.get(name, 0),
            "new": new.get(name, 0),
            "health": _health(feed, stats.get(name), new.get(name, 0)),
        })
    rows.sort(key=lambda r: (-r["exclusive"], -r["indicators"], r["name"]))

    # Pairs whose overlap is large relative to the smaller feed: agreement
    # between these is close to a single source voting twice.
    redundant = []
    for pair in overlap:
        smaller = min(reported.get(pair["a"], 0), reported.get(pair["b"], 0))
        if not smaller:
            continue
        frac = pair["n"] / smaller
        if frac >= REDUNDANT_OVERLAP:
            redundant.append({**pair, "pct": round(frac * 100)})
    redundant.sort(key=lambda p: -p["pct"])

    return {
        "rows": rows,
        "overlap": sorted(overlap, key=lambda p: -p["n"]),
        "redundant_pairs": redundant,
        "first_report_window_days": FIRST_REPORT_WINDOW_DAYS,
        "new_window_hours": NEW_WINDOW_HOURS,
    }
