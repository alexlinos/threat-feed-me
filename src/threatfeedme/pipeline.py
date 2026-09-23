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

from threatfeedme import jobs
from threatfeedme.database import Database, MEMBERSHIP_STAMP_KEY
from threatfeedme.feed_ingestor import FeedIngestor
from threatfeedme.scorer import ConfidenceScorer, current_votes_enabled, vote_grace_days
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
        # predictor block must ride along: the scorer gates its
        # predictor_weight on predictor.enabled (Task 8)
        'predictor': config.get('predictor', {}),
        'feeds': [
            {'name': f.name, 'weight': f.weight}
            for f in db.get_feed_sources()
        ],
        # The CONFIGURED feed URLs: the trust anchor domain authority is
        # verified against (scorer.authoritative_sources). 'feeds' above is
        # rebuilt from the DB and carries no URL, so without this every
        # authoritative feed failed verification and live domain HIGH would
        # have silently emptied (caught before release, v2.5.0).
        'config_feed_urls': {f.get('name'): f.get('url')
                             for f in config.get('feeds', []) or [] if isinstance(f, dict)},
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


def fetch_feeds(db: Database, config: Dict, only: Optional[List[str]] = None,
                collect_values: Optional[Dict] = None) -> Dict:
    """Fetch and ingest enabled feeds (optionally a subset by name).

    `collect_values`, when given, is filled with {feed_name: set(values)} for
    every feed whose fetch fully succeeded with fresh content (not-modified
    and errored feeds leave no entry) — the churn log's clean-snapshot input.
    Kept out of the returned results dict on purpose: that dict is stored as
    refresh status and serialized to the dashboard, where a half-million-value
    set has no business being."""
    safety_cfg = config.get('safety', {}) or {}
    from threatfeedme.credentials import KeyPolicy
    ingestor = FeedIngestor(
        db,
        safety=SafetyFilter.from_config(config),
        allow_private_urls=bool(safety_cfg.get('allow_private_feed_urls', False)),
        key_policy=KeyPolicy.from_config(config),
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
    if collect_values is not None:
        collect_values.update(ingestor.ingested_values)
    return results


def recalculate(db: Database, config: Dict) -> int:
    """Recalculate confidence scores for all indicators. Serialized with every
    other heavy writer (jobs.write_lock): a request-triggered rescore waits
    for a running one instead of racing it with stale reads."""
    with jobs.write_lock:
        # The grace lives in source_left's contents, so expire it first:
        # otherwise a recalc between refreshes scores last hour's grace.
        db.prune_left_memberships(vote_grace_days(config))
        scorer = ConfidenceScorer(db, scorer_config(db, config))
        count = scorer.recalculate_all_scores()
        # Tiers and scores changed in place — invisible to row counts — so tell
        # the feed cache its bodies are stale (feed_cache.serve_fingerprint).
        from threatfeedme.feed_cache import mark_scores_changed
        mark_scores_changed(db)
        return count


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
    with jobs.write_lock:   # never interleave with a rescore rewriting tiers
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

# Settings key holding the scoring-input fingerprint (scoring_input_key) as of
# the last rescore, so run_refresh can skip the full recompute when nothing
# that affects scores/tiers has changed. Stored in the DB so it is
# per-deployment and survives restarts.
_RESCORE_KEY = "last_scored_corpus_key"

# Stamped by the offline predict pass when it writes fresh predictive_scores,
# so the next refresh rescores and actually consumes them.
PREDICT_STAMP_KEY = "predict_pass_stamp"


def scoring_input_key(db: Database, config: Dict) -> str:
    """Fingerprint of EVERYTHING that changes scores or tiers.

    The gate used to key on three row counts alone, so these changes never
    rescored until some unrelated corpus change happened to come along
    (review 2026-09-22): a scoring-config edit (the documented "force a
    recalc" gotcha), a feed weight or enabled toggle, a whitelist change, and
    fresh predict-pass scores. The corpus part stays cheap counts; the rest is
    small (config block, a ~30-row catalog, the whitelist) and is hashed."""
    import hashlib
    import json as _json
    from threatfeedme.scorer import predictor_live

    pcfg = (config.get('predictor') or {})
    model_path = pcfg.get('model_path', 'data/predictor_model.txt')
    try:
        model_mtime = os.path.getmtime(model_path) if predictor_live(config) else None
    except OSError:
        model_mtime = None
    catalog = sorted((f.name, bool(f.enabled), float(f.weight), f.feed_type.value)
                     for f in db.get_feed_sources())
    whitelist = sorted((w.ip, w.feed_name, w.reason_code, str(w.expires_at))
                       for w in db.get_whitelist())
    blob = _json.dumps({
        "scoring": config.get('scoring') or {},
        "predictor": {"enabled": bool(pcfg.get('enabled')), "model_mtime": model_mtime},
        "catalog": catalog,
        "whitelist": whitelist,
        "predict_stamp": db.get_setting(PREDICT_STAMP_KEY),
        # With current-listing votes a leave removes a vote without touching
        # any attribution row. Only then: some feed churns almost every
        # refresh, so folding it in unconditionally would disable the gate.
        "membership": (db.get_setting(MEMBERSHIP_STAMP_KEY)
                       if current_votes_enabled(config) else None),
    }, sort_keys=True, default=str)
    digest = hashlib.sha256(blob.encode()).hexdigest()[:16]
    return ",".join(str(n) for n in db.corpus_change_key()) + ":" + digest


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

def churn_log_exclude(config: Dict) -> set:
    """Feed names whose churn transitions should NOT be written to `sightings`.

    Set via `retention.churn_log_exclude` in config. For wholesale-rotating
    feeds — the list rewrites nearly every refresh, so a "leave" says nothing
    about the IP's behavior — logging churn costs disk and poisons the
    predictor's positive class. Live-measured on the deploy DB: cins_army
    wrote 74% of all transitions and accounted for 51% of churn "positives"
    while its 'stayed' population was 5 of 91k (pure rotation). Source state
    still syncs for excluded feeds, so re-enabling later diffs cleanly.
    """
    names = (config.get('retention', {}) or {}).get('churn_log_exclude', []) or []
    return {str(n) for n in names}


# Shrink guard. A plain feed that serves an HTML error page, an empty body, or
# a truncated file still parses "successfully" — to a handful of stray matches
# or nothing — and diffing that against its membership records a MASS LEAVE,
# then a mass return when the feed recovers. Past the 6h gap floor those are
# exactly the leave->return labels the predictor learns from. A collapse below
# _COLLAPSE_FRACTION of a membership of at least _COLLAPSE_MIN_PRIOR is held
# back from the churn log; if it persists _COLLAPSE_ACCEPT_AFTER fetches in a
# row it is accepted as the feed's real new size, so a genuine permanent
# shrink can't freeze the state forever.
_COLLAPSE_FRACTION = 0.05
_COLLAPSE_MIN_PRIOR = 100
_COLLAPSE_ACCEPT_AFTER = 3


def _collapsed_fetch(db: Database, name: str, n_values: int) -> bool:
    key = f"shrink_guard:{name}"
    prior = db.source_state_count(name)
    if prior >= _COLLAPSE_MIN_PRIOR and n_values < _COLLAPSE_FRACTION * prior:
        streak = int(db.get_setting(key) or 0) + 1
        if streak < _COLLAPSE_ACCEPT_AFTER:
            db.set_setting(key, str(streak))
            logger.warning(
                f"[churn] {name}: list collapsed {prior} -> {n_values} "
                f"({streak}/{_COLLAPSE_ACCEPT_AFTER}); treating as a bad fetch, "
                f"churn NOT recorded")
            return True
        logger.warning(f"[churn] {name}: collapse persisted {streak} fetches; "
                       f"accepting {n_values} as its real size")
    if db.get_setting(key) not in (None, "", "0"):
        db.set_setting(key, "0")
    return False


def run_refresh(db: Database, config: Dict, only: Optional[List[str]] = None) -> Dict:
    """Full refresh: fetch -> score -> export -> push. Returns per-feed fetch
    results."""
    fetched_values: Dict = {}
    fetched = fetch_feeds(db, config, only=only, collect_values=fetched_values)
    # Network fetching stays outside the write lock (a slow feed must never
    # block a rescore or a whitelist export); everything from here rewrites
    # scoring state, so it runs serialized with the other heavy writers.
    with jobs.write_lock:
        return _after_fetch(db, config, fetched, fetched_values)


def _after_fetch(db: Database, config: Dict, fetched: Dict, fetched_values: Dict) -> Dict:
    """run_refresh's post-fetch phase (caller holds jobs.write_lock)."""
    tick = datetime.now(timezone.utc).isoformat()
    # Churn ground truth, transition format: diff each cleanly-fetched
    # source's ACTUAL ingested values against its last snapshot and record
    # only arrivals/leaves (see Database.update_source_sightings — an
    # unchanged refetch writes nothing). Only feeds present in fetched_values
    # had a complete fresh parse; errored and not-modified feeds are absent,
    # so a partial refresh can never fake a mass-leave. Diffing the fetched
    # values (not indicator_sources, which is add-only attribution) is what
    # makes leaves observable at all — attribution never shrinks.
    for name, values in fetched_values.items():
        if fetched.get(name, {}).get("status") != "success":
            continue
        if _collapsed_fetch(db, name, len(values)):
            fetched[name]["warning"] = (
                "list collapsed to %d entries; churn not recorded" % len(values))
            continue
        stats = db.update_source_sightings(
            name, values, tick, record=name not in churn_log_exclude(config))
        if stats["arrived"] or stats["left"]:
            logger.info(f"[churn] {name}: +{stats['arrived']} arrived, "
                        f"-{stats['left']} left")
    max_age_days = retention_max_age_days(db, config)
    # Ring-prune the churn log so sightings can't grow without bound (one row
    # per source per ip per tick). Keep well beyond the indicator retention
    # window so a leave-then-return WITHIN that window stays observable; floor
    # at 30d so a disabled/short retention still leaves usable churn history.
    db.prune_sightings(max(2 * max_age_days, 30) if max_age_days > 0 else 30)
    # Expire drops past the vote grace BEFORE the gate key is read: an expiry
    # is a vote change with no attribution change, and must force the rescore.
    db.prune_left_memberships(vote_grace_days(config))
    # Re-apply the safety filter to what is already stored: a filter fix or a
    # new operator known-good entry must take effect now, not when the rows age
    # out. A non-empty sweep changes the corpus key, so it forces the rescore.
    try:
        from threatfeedme.safety import SafetyFilter
        unsafe = db.purge_unsafe_indicators(SafetyFilter.from_config(config))
        if unsafe:
            logger.warning(f"[safety] removed stored indicators the filter now refuses: {unsafe}")
    except Exception:
        logger.exception("[safety] retroactive sweep failed (refresh continues)")
    if max_age_days > 0:
        # Pass the whitelist map so operator-whitelisted IPs are never aged
        # out — whitelist is operator intent, not feed state.
        purged = db.purge_stale_indicators(max_age_days, db.get_whitelist_map())
        logger.info(f"[retention] purged {purged} stale indicators (> {max_age_days}d)")
    # Gate the expensive full-corpus rescore + export + push on an actual
    # change to scoring inputs since the LAST rescore. A fast feed coming due
    # (openphish 15m, dshield 30m) otherwise drags a ~90s recompute of the
    # whole corpus every time, even when it refetched byte-identical content.
    # The key is compared against the value stored at the last rescore rather
    # than this refresh's start, so a change made between refreshes (e.g. an FP
    # flag, which only re-exports) still forces the rescore it needs.
    # Tradeoff: pure age-decay drift between real changes isn't reapplied until
    # the next change; the roster changes often enough to keep this current.
    key = scoring_input_key(db, config)
    if key == db.get_setting(_RESCORE_KEY):
        logger.info("[refresh] no scoring-relevant change; skipped rescore/export/push")
        return fetched
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
    db.set_setting(_RESCORE_KEY, key)
    return fetched
