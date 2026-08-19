"""Shared ingestion -> scoring -> export pipeline.

Used by both the CLI (main.py) and the dashboard's manual/scheduled refresh so
they behave identically. Feed sources are read from the database (the runtime
source of truth), not directly from config.
"""
import logging
import os
import threading
from datetime import datetime, timezone
from typing import Dict, List, Optional

from threatfeedme.database import Database
from threatfeedme.feed_ingestor import FeedIngestor
from threatfeedme.scorer import ConfidenceScorer
from threatfeedme.safety import SafetyFilter
from threatfeedme.exporter import _write_text, _write_csv, _write_json, is_included
from threatfeedme.models import ConfidenceTier, CUMULATIVE_TIERS

logger = logging.getLogger(__name__)


# ---- Pipeline helpers ----

def scorer_config(db: Database, config: Dict) -> Dict:
    """Build the scorer's config, sourcing per-feed reputation weights from the
    database feeds (which may differ from the seed config after edits)."""
    return {
        'scoring': config.get('scoring', {}),
        'feeds': [
            {'name': f.name, 'weight': f.weight}
            for f in db.get_feed_sources()
        ],
    }


def due_feeds(db: Database, default_interval_seconds: int) -> List[str]:
    """Names of enabled feeds that are currently due for a refresh."""
    last_updates = db.get_feed_last_updates()
    now = datetime.now(timezone.utc)
    due: List[str] = []
    for feed in db.get_feed_sources(enabled_only=True):
        interval = feed.update_interval if (feed.update_interval or 0) > 0 else default_interval_seconds
        raw = last_updates.get(feed.name)
        if not raw:
            due.append(feed.name)
            continue
        try:
            last = datetime.fromisoformat(raw)
        except (ValueError, TypeError):
            due.append(feed.name)
            continue
        if last.tzinfo is None:
            last = last.replace(tzinfo=timezone.utc)
        if (now - last).total_seconds() >= interval:
            due.append(feed.name)
    return due


def fetch_feeds(db: Database, config: Dict, only: Optional[List[str]] = None) -> Dict:
    """Fetch and ingest enabled feeds (optionally a subset by name)."""
    safety_cfg = config.get('safety', {}) or {}
    ingestor = FeedIngestor(
        db,
        safety=SafetyFilter.from_config(config),
        allow_private_urls=bool(safety_cfg.get('allow_private_feed_urls', False)),
    )
    feeds = db.get_feed_sources(enabled_only=True)
    if only is not None:
        wanted = set(only)
        feeds = [f for f in feeds if f.name in wanted]

    results = {}
    for feed in feeds:
        try:
            count = ingestor.ingest_feed(feed)
            results[feed.name] = {'status': 'success', 'count': count}
            logger.info(f"[ok] {feed.name}: {count} indicators")
        except Exception as e:
            results[feed.name] = {'status': 'error', 'error': str(e)}
            logger.error(f"[fail] {feed.name}: {e}")
    return results


def recalculate(db: Database, config: Dict) -> int:
    """Recalculate confidence scores for all indicators."""
    scorer = ConfidenceScorer(db, scorer_config(db, config))
    return scorer.recalculate_all_scores()


# ---- Export (inlined from the Exporter class) ----

def _export_tier(db: Database, tier: ConfidenceTier, output_dir: str,
                 format: str = "text", kind: str = "ip") -> str:
    """Export a single confidence-tier file (cumulative: the medium file
    contains every high- or medium-tier indicator). Returns filepath.

    One file per kind: the historical *_confidence_ips files stay IP-only
    (a FortiGate address import errors on a hostname), domains get their own
    *_confidence_domains files."""
    # Generator end to end: rows stream from SQLite through the whitelist
    # filter into the file writer without ever materializing the tier.
    wl_map = db.get_whitelist_map()
    indicators = (i for i in db.iter_indicators_by_tiers(CUMULATIVE_TIERS[tier], kind=kind)
                  if is_included(i, wl_map, tier=tier))

    suffix = "ips" if kind == "ip" else "domains"
    filename = f"{tier.value}_confidence_{suffix}.{format}"
    filepath = os.path.join(output_dir, filename)
    os.makedirs(output_dir, exist_ok=True)

    if format == "text":
        _write_text(indicators, filepath)
    elif format == "csv":
        _write_csv(indicators, filepath)
    elif format == "json":
        _write_json(indicators, tier, filepath)
    else:
        raise ValueError(f"Unsupported format: {format}")
    return filepath


# Background export machinery: whitelist/feedback endpoints must not pay for
# a full tier-file rebuild inside the request (3 formats x 4 cumulative tiers
# = 12 full-table loads — the UI froze for the duration). The LIVE feed URLs
# don't need the files at all (the whitelist matcher applies at serve time);
# only the on-disk exports do, and those can lag by a second.
#
# One worker at a time; a change landing mid-export sets the dirty flag so
# the worker runs once more and the files always reflect the last change.
_export_dirty = threading.Event()
_export_state_lock = threading.Lock()
_export_running = False


def export_tiers_async(db: Database, config: Dict) -> None:
    """Schedule export_tiers on a daemon thread, coalescing bursts."""
    global _export_running
    _export_dirty.set()
    with _export_state_lock:
        if _export_running:
            return  # active worker will observe the dirty flag and rerun
        _export_running = True

    def _run():
        global _export_running
        try:
            while _export_dirty.is_set():
                _export_dirty.clear()
                try:
                    export_tiers(db, config)
                except Exception:
                    logger.exception("background tier export failed")
                # A whitelist change must reach a configured UniFi gateway
                # too — "this block is hurting us, stop NOW" can't wait for
                # the next refresh cycle. Gated on push_ready (enabled +
                # host + credentials all non-empty) so deployments without
                # UniFi skip this entirely; diff-aware, so a no-op push is
                # one login and one read. Same coalescing as the exports.
                try:
                    from threatfeedme.pusher_unifi import push_ready, push_to_unifi
                    if push_ready(db, config):
                        push_to_unifi(db, config)
                except Exception:
                    logger.exception("[unifi] push after whitelist/export change failed")
        finally:
            with _export_state_lock:
                _export_running = False
            # A change that landed exactly as the loop exited would be lost;
            # re-schedule so its export still happens.
            if _export_dirty.is_set():
                export_tiers_async(db, config)

    threading.Thread(target=_run, name="tier-export", daemon=True).start()


def export_tiers(db: Database, config: Dict) -> Dict:
    """Export all tiers to every configured format, one file set per kind
    (*_confidence_ips.* and *_confidence_domains.*)."""
    output_dir = config.get('output', {}).get('base_dir', './output')
    formats = config.get('output', {}).get('formats', ['text'])
    results = {}
    for fmt in formats:
        tier_results = {}
        for tier in ConfidenceTier:
            tier_results[tier.value] = _export_tier(db, tier, output_dir, format=fmt, kind="ip")
            tier_results[f"{tier.value}_domains"] = _export_tier(
                db, tier, output_dir, format=fmt, kind="domain")
        results[fmt] = tier_results
    return results


def get_export_stats(db: Database) -> Dict:
    """Get statistics about exported data, per kind. The historical unsuffixed
    keys stay IP-only (they describe the *_confidence_ips files)."""
    stats = {}
    wl_map = db.get_whitelist_map()
    for tier in ConfidenceTier:
        # Cumulative, matching the exported files (low_count == everything).
        stats[f"{tier.value}_count"] = sum(
            1 for i in db.iter_indicators_by_tiers(CUMULATIVE_TIERS[tier], kind="ip")
            if is_included(i, wl_map))
        stats[f"{tier.value}_domain_count"] = sum(
            1 for i in db.iter_indicators_by_tiers(CUMULATIVE_TIERS[tier], kind="domain")
            if is_included(i, wl_map))
    stats["total_unique_ips"] = stats.get("low_count", 0)
    stats["total_unique_domains"] = stats.get("low_domain_count", 0)
    stats["whitelisted_count"] = len(db.get_whitelist())
    return stats


# ---- Retention ----

RETENTION_MAX_AGE_KEY = "retention_max_age_days"
DEFAULT_RETENTION_DAYS = 7  # fallback if neither the DB setting nor config sets it


def retention_max_age_days(db: Database, config: Dict) -> int:
    """Effective retention window in days.

    A runtime DB setting (editable from the dashboard) takes precedence; the
    config's ``retention.max_age_days`` is the seed default. Returns 0 to mean
    "keep forever" (purge disabled). Invalid values fall back to the default.
    """
    val = db.get_setting(RETENTION_MAX_AGE_KEY)
    if val is None or val == "":
        val = (config.get('retention', {}) or {}).get('max_age_days', DEFAULT_RETENTION_DAYS)
    try:
        return max(0, int(val))
    except (ValueError, TypeError):
        return DEFAULT_RETENTION_DAYS


# ---- Full refresh ----

def run_refresh(db: Database, config: Dict, only: Optional[List[str]] = None) -> Dict:
    """Full refresh: fetch -> score -> export -> push. Returns per-feed fetch
    results."""
    fetched = fetch_feeds(db, config, only=only)
    tick = datetime.now(timezone.utc).isoformat()
    # Churn ground truth: snapshot each successfully-refreshed source's
    # current indicator set into the sightings log, one batch per source per
    # tick. A source that errored/skipped this tick is left out — its prior
    # tick rows make the leave observable without writing False rows (an ip
    # present at tick N with no row at N+1 is the leave). The Sightings
    # UNIQUE(source_name, ip, tick) key is why re-inserting the same tick
    # replaces; leave-then-return is the predictor's training signal.
    for name, res in fetched.items():
        if res.get("status") != "success":
            continue
        ips = db.get_source_ips(name)
        if ips:
            db.append_sightings(name, {ip: True for ip in ips}, tick)
    max_age_days = retention_max_age_days(db, config)
    if max_age_days > 0:
        purged = db.purge_stale_indicators(max_age_days)
        logger.info(f"[retention] purged {purged} stale indicators (> {max_age_days}d)")
    recalculate(db, config)
    export_tiers(db, config)
    # Push integrations (UniFi has no poll-a-URL feature, so we push instead).
    # Guarded: an unreachable gateway must never break the refresh — the
    # served block lists are already updated at this point either way.
    # push_ready gates on the integration variables being set and non-empty,
    # so unconfigured deployments skip the attempt silently.
    try:
        from threatfeedme.pusher_unifi import push_ready, push_to_unifi
        if push_ready(db, config):
            push_to_unifi(db, config)
    except Exception:
        logger.exception("[unifi] push failed (refresh itself succeeded)")
    return fetched
