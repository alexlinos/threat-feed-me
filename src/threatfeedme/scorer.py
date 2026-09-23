"""
Confidence Scoring Engine - Calculate and assign confidence tiers
"""
import bisect
import logging
import math
import ipaddress
import json
import os
from datetime import datetime, timezone
from typing import List, Dict, Optional

from threatfeedme.models import ThreatIndicator, ConfidenceTier, FeedType, effective_sources
from threatfeedme.database import Database, CURRENT_ATTRIBUTION_SQL

logger = logging.getLogger(__name__)


def predictor_live(config: Dict) -> bool:
    """The recurrence factor is live only when enabled AND a trained model
    file exists. The model is produced offline (train_predictor, tools
    container); until one exists every predictive_score is absent, so a
    non-zero weight would only renormalize the real factors down."""
    pcfg = (config or {}).get('predictor', {}) or {}
    if not pcfg.get('enabled', False):
        return False
    return os.path.exists(pcfg.get('model_path', 'data/predictor_model.txt'))


def _differs(update, previous, eps: float = 1e-6) -> bool:
    """Whether a rescore result (score, tier, votes, ip) changes what is
    stored (score, tier, votes). Never-scored rows (votes None) always count.

    eps is set by what a score is USED for, not float precision: recency
    decays continuously, so every row's score drifts a hair between any two
    rescores — even milliseconds apart — and at 1e-9 every row counted as
    changed, defeating the point. Scores are shown to 2-3 decimals and order
    the served list; drift under 1e-6 is invisible to both. A tier or vote
    change is always written, and the error can't accumulate: the next
    rescore compares against the stored value, so drift past eps is written."""
    score, tier, votes, _ip = update
    old_score, old_tier, old_votes = previous
    if tier != old_tier or old_votes is None or old_score is None:
        return True
    return abs(score - old_score) > eps or abs(votes - old_votes) > eps


# False-positive penalty tuning. A feed's reputation weight is multiplied by
# max(FP_MIN_FACTOR, 1 - FP_PENALTY_K * fp_rate), where fp_rate is the fraction
# of the feed's reported IPs that users flagged as false positives. At K=10, a
# 5% FP rate halves the feed's reputation and an 8%+ rate floors it.
FP_PENALTY_K = 10.0
FP_MIN_FACTOR = 0.2
# A feed at or below this penalty factor is surfaced as "degraded" in the UI.
FP_DEGRADED_FACTOR = 0.6


def fp_penalty_factor(fp_count: int, reported_count: int,
                      k: float = FP_PENALTY_K, floor: float = FP_MIN_FACTOR) -> float:
    """Reputation multiplier for a feed given its false-positive rate."""
    if not reported_count or fp_count <= 0:
        return 1.0
    rate = fp_count / reported_count
    return max(floor, 1.0 - k * rate)


# Every source starts at the same reputation. Reputation is earned, not
# assumed: the false-positive penalty below lowers a feed's weight from user
# feedback, and an operator can pin a per-feed weight in config/the dashboard
# if they have a measured reason to.
DEFAULT_SOURCE_WEIGHT = 1.0


class ConfidenceScorer:
    def __init__(self, db: Database, config: Dict):
        self.db = db
        self.config = config

        # Normalize the component weights so the final score always spans the
        # full 0.0-1.0 range even if the configured values do not sum to 1.0.
        scoring = config.get('scoring', {})
        raw_weights = {
            'source': scoring.get('source_weight', 0.45),
            'reputation': scoring.get('reputation_weight', 0.33),
            'recency': scoring.get('recency_weight', 0.22),
            # Recurrence-predictor factor (Task 8). Normalized WITH the other
            # components so it can never outweigh feed corroboration, and
            # forced to 0 unless the predictor is live: enabled AND a model
            # file exists. A stale predictive_score from a previously-enabled
            # run must not keep steering scores after the switch is thrown
            # off, and an install that has never trained a model must not pay
            # the renormalization (every score scaled down ~9%) for a factor
            # that contributes nothing — which is what the shipped
            # enabled:true did to every fresh install before v2.4.19. The value
            # is read from indicator metadata, never recomputed here: scoring
            # must not depend on lightgbm; it only checks the file is there.
            'predictor': (scoring.get('predictor_weight', 0.0)
                          if predictor_live(config) else 0.0),
        }
        total = sum(raw_weights.values()) or 1.0
        self.weights = {k: v / total for k, v in raw_weights.items()}

        # Tiering method. 'effective_votes' (default) discounts each source's
        # vote by its measured overlap with sources already counted, then
        # finds the tier boundaries from the vote distribution itself
        # (natural breaks), never below the configured floors. 'legacy'
        # restores the fixed source-count/score gates.
        tiering = scoring.get('tiering') or {}
        self.tier_method = str(tiering.get('method', 'effective_votes'))
        self.medium_floor = float(tiering.get('medium_floor', 1.1))
        self.high_floor = float(tiering.get('high_floor', 2.0))
        # Overlap ratios and per-source sizes are loaded once per rescore
        # (and lazily for single-IP scoring); (a, b) keys are stored both ways.
        self._overlap = None
        self._source_sizes = {}
        # Opt-in: votes come from what feeds list NOW, not everything they
        # ever listed (database.CURRENT_ATTRIBUTION_SQL). Overlap ratios stay
        # on attribution history either way: they estimate how correlated two
        # PUBLISHERS are, and the retention window is a far larger sample of
        # that than a single snapshot. Off by default: measured on the prod
        # snapshot (2026-09-22) a hard cut took IP HIGH 36.8k -> 5.0k and
        # domain HIGH 1,241 -> 366, because most feeds publish short windows
        # (honeydb 24h, abuseipdb 3d) and most of today's corroboration is two
        # feeds seeing an IP days apart. Pending a maintainer decision.
        self.current_votes = bool(scoring.get('votes_require_current_listing', False))

        # Reputation weights are driven by config/DB (via pipeline.scorer_config)
        # so adding a feed never requires editing this module; sources without
        # an explicit weight get the uniform default.
        self.source_weights = {}
        for feed in config.get('feeds', []):
            name = feed.get('name')
            weight = feed.get('weight')
            if name and weight is not None:
                self.source_weights[name] = weight

        # Feed type per source, used by the high-tier require_threat_intel
        # gate. Config seeds the map; the DB (authoritative for runtime-added
        # feeds) overrides it. The 'manual' pseudo-source and unknown sources
        # stay unmapped and never satisfy the gate.
        self.source_types = {}
        for feed in config.get('feeds', []):
            if feed.get('name') and feed.get('feed_type'):
                self.source_types[feed['name']] = str(feed['feed_type'])
        # Disabled feeds cast no vote. Disabling a feed only stops FETCHING
        # it; its attributions stay in indicator_sources, so before v2.4.19 a
        # disabled (often: disabled-because-noisy) feed kept corroborating its
        # IPs into Medium/High indefinitely. Its IPs now score as if it never
        # reported them — gone from the higher tiers at the next rescore — and
        # retention ages out whatever it alone listed.
        self.disabled_sources = set()
        # Domain authority (force-HIGH on one feed's word) is granted by
        # PROVENANCE, not by name. It used to key on the feed name alone, so a
        # custom upload named "urlhaus_hostfile", or the real one re-pointed at
        # another URL, inherited force-HIGH for every domain it listed (review
        # 2026-09-22). The operator's config is the trust anchor: a configured
        # authoritative feed counts only while its stored row still matches the
        # same-named feed in config.feeds — same URL, and not an upload.
        auth_cfg = set(((scoring.get('high_confidence') or {})
                        .get('authoritative_domain_feeds')) or [])
        # pipeline.scorer_config passes the configured URLs explicitly (its
        # 'feeds' list is rebuilt from the DB, without URLs); direct callers
        # pass a config whose 'feeds' carry them.
        config_urls = config.get('config_feed_urls') or {
            f.get('name'): f.get('url')
            for f in config.get('feeds', []) or [] if isinstance(f, dict)}
        self.authoritative_sources = set(auth_cfg)   # no DB (unit tests): trust config
        if self.db is not None:
            try:
                verified = set()
                for feed in self.db.get_feed_sources():
                    self.source_types[feed.name] = feed.feed_type.value
                    if not feed.enabled:
                        self.disabled_sources.add(feed.name)
                    if (feed.name in auth_cfg and not feed.local_file
                            and config_urls.get(feed.name) == feed.url):
                        verified.add(feed.name)
                for name in sorted(auth_cfg - verified):
                    logger.warning(
                        f"[score] {name} is listed as authoritative but its stored "
                        f"feed no longer matches the configured one (URL changed, "
                        f"an upload, or not configured); it gets no force-HIGH")
                self.authoritative_sources = verified
            except Exception:
                logger.exception("[score] could not load the feed roster; "
                                 "feed types and enabled state unknown this rescore")

        # Apply the false-positive penalty: feeds users have flagged as noisy
        # get their reputation reduced, so their IPs score lower and fall out
        # of the higher-confidence firewall feeds. self.feed_penalty records the
        # factor per feed for display. Skipped when no DB (unit tests).
        self.feed_penalty = {}
        if self.db is not None:
            try:
                fp_counts = self.db.get_feed_fp_counts()
                report_counts = self.db.get_feed_report_counts()
                for name in set(self.source_weights) | set(fp_counts):
                    factor = fp_penalty_factor(fp_counts.get(name, 0),
                                               report_counts.get(name, 0))
                    self.feed_penalty[name] = factor
                    if factor < 1.0:
                        self.source_weights[name] = (
                            self.source_weights.get(name, DEFAULT_SOURCE_WEIGHT) * factor
                        )
            except Exception:
                # Never let feedback bookkeeping break scoring — but say so:
                # losing the penalties silently hands FP-degraded feeds their
                # full weight (and authority) back.
                logger.exception("[score] false-positive penalties unavailable; "
                                 "scoring WITHOUT feed reputation this rescore")
                self.feed_penalty = {}

    # ==================== PUBLIC API ====================

    def calculate_score(self, ip: str) -> tuple[float, ConfidenceTier]:
        """Calculate confidence score and tier for a single IP.

        Tier boundaries come from the last full rescore (persisted in
        settings); before any rescore has run, the configured floors apply.
        """
        indicator = self.db.get_indicator(ip, current_sources=self.current_votes)
        if not indicator:
            return 0.0, ConfidenceTier.LOW

        netblocks = self._load_netblock_sources()
        score, votes, sources = self._evidence(
            indicator, netblocks, self.db.get_whitelist_map())
        if self.tier_method == 'legacy':
            tier = self._determine_tier(score, len(sources or []), sources)
        else:
            med_b, high_b = self._stored_breaks(kind=indicator.kind)
            tier = self._tier_from_votes(votes, sources, med_b, high_b)
        return score, tier

    def recalculate_all_scores(self) -> int:
        """Recalculate scores for all indicators.

        Data is loaded once. With effective-votes tiering this is a two-pass
        computation: evidence for every indicator first, then tier boundaries
        from the resulting vote distribution (natural breaks over the floors),
        then tiers. Only rows whose score, tier or votes actually changed are
        written, in short chunked transactions (_write_changes).
        """
        whitelist_map = self.db.get_whitelist_map()
        netblocks = self._load_netblock_sources()

        # Stream the table and keep only the per-indicator evidence tuple —
        # holding the full model list AND an evidence list roughly doubled
        # the largest allocation in the process, which starved 2 GB hosts
        # (small Synology/NAS deployments) during the hourly rescore.
        evidence = []
        previous = []   # (score, tier, votes) as stored, aligned with evidence
        count = 0
        for indicator in self.db.iter_indicators_by_tiers(
                tuple(ConfidenceTier), current_sources=self.current_votes):
            count += 1
            score, votes, sources = self._evidence(indicator, netblocks, whitelist_map)
            evidence.append((indicator.ip, score, votes, sources, indicator.kind))
            previous.append((indicator.confidence_score, indicator.tier.value,
                             indicator.effective_votes))

        if self.tier_method == 'legacy':
            updates = [
                (score, self._determine_tier(score, len(sources or []), sources).value,
                 votes, ip)
                for ip, score, votes, sources, _kind in evidence
            ]
        else:
            # Tier boundaries are computed PER KIND. Domain vote distributions
            # differ wildly from IP ones; shared breaks would let one
            # population silently set the other's tier lines. Split the vote
            # populations and persist two break pairs (tier_breaks /
            # tier_breaks_domains) so each kind's tiers stay its own.
            ip_votes = [votes for _ip, _s, votes, sources, kind in evidence
                        if kind == 'ip' and sources]
            dom_votes = [votes for _ip, _s, votes, sources, kind in evidence
                        if kind == 'domain' and sources]
            ip_med, ip_high = self.medium_floor, self.high_floor
            dom_med, dom_high = self.medium_floor, self.high_floor
            # A kind with no population keeps (or never gains) its stored
            # breaks: persisting floor breaks for an EMPTY kind would mark it
            # "already tiered" (the dashboard's Processing gate reads exactly
            # this key) before a single indicator of that kind ever scored.
            if ip_votes:
                ip_med, ip_high = self._breaks_for_votes(ip_votes, kind='ip')
                self._persist_breaks(ip_med, ip_high, kind='ip')
            if dom_votes:
                dom_med, dom_high = self._breaks_for_votes(dom_votes, kind='domain')
                self._persist_breaks(dom_med, dom_high, kind='domain')
            # Unknown/future kind values fall to the IP breaks — the same
            # fallback the dashboard's counting uses — rather than silently
            # adopting domain boundaries.
            updates = [
                (score,
                 self._tier_from_votes(
                     votes, sources,
                     dom_med if kind == 'domain' else ip_med,
                     dom_high if kind == 'domain' else ip_high,
                     kind).value,
                 votes, ip)
                for ip, score, votes, sources, kind in evidence
            ]

        changed = [u for u, prev in zip(updates, previous) if _differs(u, prev)]
        self._write_changes(changed)
        logger.info(f"[score] rescored {count} indicators; {len(changed)} changed")
        return count

    # Rows per write transaction, and how long one waits on a busy writer.
    _WRITE_CHUNK = 5000
    _WRITE_BUSY_TIMEOUT_MS = 120000

    def _write_changes(self, changed) -> None:
        """Write rescore results in short transactions. This used to be ONE
        executemany over every row — 10-20 s at ~760k indicators — which held
        SQLite's single writer lock past the 5 s busy_timeout, so any other
        writer (an API edit, the offline predict pass) could fail with
        "database is locked" (review 2026-09-22). Most rows don't move between
        rescores, so writing only the changed ones also shrinks the work."""
        for i in range(0, len(changed), self._WRITE_CHUNK):
            with self.db._cursor() as cur:
                cur.execute(f"PRAGMA busy_timeout = {self._WRITE_BUSY_TIMEOUT_MS}")
                cur.executemany(
                    "UPDATE indicators SET confidence_score = ?, tier = ?, "
                    "effective_votes = ? WHERE ip = ?",
                    changed[i:i + self._WRITE_CHUNK],
                )

    # ==================== SCORING INTERNALS ====================

    def _evidence(
        self, indicator: ThreatIndicator, netblocks, whitelist_map: Dict
    ) -> tuple[float, float, Optional[List[str]]]:
        """Compute (score, effective_votes, surviving_sources) for an
        indicator given precomputed netblocks (from _load_netblock_sources)
        and the whitelist scoping map. Tier is decided by the caller — with
        effective-votes tiering it needs the whole population's vote
        distribution, which no single indicator can know."""
        # Apply whitelist scoping: drop globally-whitelisted IPs entirely and
        # remove any per-feed-whitelisted sources.
        eff = effective_sources(indicator.ip, indicator.sources, whitelist_map)
        if eff is None:
            return 0.0, 0.0, None
        sources = [s for s in eff if s not in self.disabled_sources]
        # CIDR-aware when given a WhitelistMatcher; plain dict falls back to
        # exact match. Used below to skip re-adding a netblock source that has
        # been whitelisted for this IP.
        if hasattr(whitelist_map, "scoped_feeds"):
            scoped = whitelist_map.scoped_feeds(indicator.ip)
        else:
            scoped = whitelist_map.get(indicator.ip, set())

        # IP-over-CIDR overlap: an IP inside a netblock reported by another
        # feed gains that feed as a corroborating source, using the netblock's
        # real prefix rather than a guess. Sources whitelisted for this IP are
        # not re-added. Sorted so source order (and anything derived from it)
        # stays deterministic.
        for src in sorted(self._netblock_sources_for(indicator.ip, netblocks)):
            if (src not in sources and src not in scoped
                    and src not in self.disabled_sources):
                sources.append(src)

        # No surviving sources means no evidence -> lowest confidence.
        if not sources:
            return 0.0, 0.0, []

        votes = self._effective_votes(sources)

        # The source component of the score follows the same de-correlated
        # evidence measure the tiers use (legacy keeps the raw count).
        if self.tier_method == 'legacy':
            source_score = self._calculate_source_score(sources)
        else:
            source_score = min(votes * 0.25, 1.0)
        reputation_score = self._calculate_reputation_score(sources)
        recency_score = self._calculate_recency_score(indicator.last_seen)
        # Predictor factor: the stored probability from a prior predict pass
        # (metadata.predictive_score, written by Predictor.predict_and_store).
        # Missing/None/invalid contributes exactly 0, and with the weight
        # normalized in __init__ this can never outrank corroboration; tiers
        # come from effective votes, so this shifts score within a tier, not
        # the tier itself. That composition is what keeps an FP-degraded
        # feed's IPs from riding the predictor back up the ranking.
        raw_ps = (indicator.metadata or {}).get("predictive_score")
        predictor_score = 0.0
        if raw_ps is not None:
            try:
                v = float(raw_ps)
            except (TypeError, ValueError):
                v = 0.0
            # NaN passes min/max comparisons untouched (and json.loads
            # accepts bare NaN), so it must be trapped explicitly
            if math.isfinite(v):
                predictor_score = min(max(v, 0.0), 1.0)

        total_score = (
            source_score * self.weights['source']
            + reputation_score * self.weights['reputation']
            + recency_score * self.weights['recency']
            + predictor_score * self.weights['predictor']
        )

        return total_score, votes, sources

    # ---- Effective-votes tiering ----
    #
    # A raw source count treats every feed as an independent witness, but
    # public feeds aggregate each other and share reporter communities, so
    # adding feeds inflates counts without adding evidence. Instead each
    # source's vote is discounted by its measured overlap with sources
    # already counted: the first (largest) source is a full vote, and a
    # source that 100%-overlaps an already-counted one adds nothing. The
    # overlap ratios come from the live database — the same data behind the
    # dashboard's overlap heatmap — so the discount tracks reality as feeds
    # drift, with no hand-tuned correlation constants.

    def _load_overlap(self) -> Dict:
        """Pairwise overlap ratios |A∩B|/min(|A|,|B|), cached per scorer
        instance (one instance per rescore). Failure degrades to no
        discounting, i.e. votes == raw source count."""
        if self._overlap is not None:
            return self._overlap
        try:
            sizes = self.db.get_source_counts()
            pairs = self.db.get_feed_overlap()
        except Exception:
            # Fail-safe but LOUD: with no overlap data every source counts as
            # an independent witness, so correlated feeds inflate votes and
            # tiers across the board. Silently doing that is the one outcome
            # a scoring engine must never hide.
            logger.exception("[score] feed overlap unavailable; votes fall back "
                             "to RAW source counts this rescore (tiers inflated)")
            self._overlap = {}
            return self._overlap
        self._source_sizes = sizes
        ov = {}
        for p in pairs:
            smaller = min(sizes.get(p['a'], 0), sizes.get(p['b'], 0))
            if smaller:
                r = min(1.0, p['n'] / smaller)
                ov[(p['a'], p['b'])] = ov[(p['b'], p['a'])] = r
        self._overlap = ov
        return ov

    def _effective_votes(self, sources: List[str]) -> float:
        """Overlap-discounted vote count. Greedy, largest source first (the
        biggest feed anchors; each later source is discounted by its highest
        overlap with anything already counted). Deterministic: ties broken
        by name."""
        overlap = self._load_overlap()
        votes, counted = 0.0, []
        for s in sorted(sources, key=lambda s: (-self._source_sizes.get(s, 0), s)):
            discount = max((overlap.get((s, c), 0.0) for c in counted), default=0.0)
            votes += max(0.0, 1.0 - discount)
            counted.append(s)
        return votes

    TIER_BREAKS_KEY = 'tier_breaks'
    TIER_BREAKS_KEY_DOMAINS = 'tier_breaks_domains'
    TIER_FINGERPRINT_KEY = 'tier_breaks_fingerprint'
    TIER_FINGERPRINT_KEY_DOMAINS = 'tier_breaks_fingerprint_domains'

    def _breaks_for_votes(self, votes: List[float], kind: str = 'ip') -> tuple[float, float]:
        """Tier boundaries, held stable between rescores unless the vote
        distribution actually moves.

        Because tier is the firewall block gate, hourly k-means recomputation
        would silently re-bucket live indicators as feeds age in/out. We reuse
        the persisted breaks unless (a) the vote distribution has shifted past
        a threshold (quantile fingerprint drift) or (b) the feed roster
        changed (source-count fingerprint). Only then re-run k-means. The
        configured floors remain hard minimums in all paths.

        `kind` selects which stored break/fingerprint pair is read and
        written ('ip' -> tier_breaks, 'domain' -> tier_breaks_domains) so each
        kind's boundaries stay its own.
        """
        # First rescore (no stored fingerprint): compute and persist.
        fingerprint = self._load_fingerprint(kind=kind)
        if fingerprint is None:
            med_b, high_b = self._natural_breaks(votes)
            self._persist_fingerprint(votes, kind=kind)
            return med_b, high_b

        if self._fingerprint_moved(votes, fingerprint, kind=kind):
            med_b, high_b = self._natural_breaks(votes)
            self._persist_fingerprint(votes, kind=kind)
            return med_b, high_b

        # Distribution unchanged -> keep the stable boundaries.
        return self._stored_breaks(kind=kind)

    def _load_fingerprint(self, kind: str = 'ip') -> Optional[dict]:
        key = self.TIER_FINGERPRINT_KEY_DOMAINS if kind == 'domain' \
            else self.TIER_FINGERPRINT_KEY
        try:
            raw = self.db.get_setting(key)
            if raw:
                j = json.loads(raw)
                if 'votes' in j and 'sources' in j:
                    return j
        except Exception:
            pass
        return None

    def _persist_fingerprint(self, votes: List[float], kind: str = 'ip') -> None:
        key = self.TIER_FINGERPRINT_KEY_DOMAINS if kind == 'domain' \
            else self.TIER_FINGERPRINT_KEY
        try:
            self.db.set_setting(
                key,
                json.dumps({'votes': self._fingerprint(votes),
                            'sources': self._source_fingerprint(kind)}),
            )
        except Exception:
            # never let bookkeeping break a rescore
            logger.warning("[score] could not persist the %s roster fingerprint", kind,
                           exc_info=True)

    def _fingerprint(self, votes: List[float]) -> List[float]:
        """Quantile snapshot of the vote distribution (deciles). Stable,
        order-independent, robust to outliers — a cheap summary of the whole
        population."""
        vals = sorted(v for v in votes if v > 0)
        if not vals:
            return []
        qs = [0.0, 0.1, 0.25, 0.5, 0.75, 0.9, 0.99, 1.0]
        return [vals[min(len(vals) - 1, int(q * (len(vals) - 1)))] for q in qs]

    def _source_fingerprint(self, kind: str = 'ip') -> Dict[str, int]:
        """Roster fingerprint for one kind: {feed_name: attribution count}
        over indicators OF THAT KIND only.

        Two properties matter here. Per-kind: the shared whole-roster
        snapshot let routine IP-feed churn force a DOMAIN break recompute
        (and vice versa) — the exact cross-kind re-bucketing D3's split
        exists to prevent. Tolerant compare (see _fingerprint_moved): the
        old exact-count string equality tripped on every single-indicator
        change, so the "held stable between rescores" guarantee never
        actually held on a live system."""
        try:
            return {n: int(c) for n, c in self.db.get_source_counts(kind=kind).items()}
        except Exception:
            return {}

    def _fingerprint_moved(self, votes: List[float], fingerprint: dict,
                           kind: str = 'ip') -> bool:
        """True when the current vote distribution differs from the stored one
        past a relative threshold, or the feed roster materially changed
        (feed added/removed, or any feed resized >25%)."""
        new = self._fingerprint(votes)
        old = fingerprint.get('votes') or []
        if len(new) != len(old):
            return True
        for n, o in zip(new, old):
            # Relative drift: any decile moving >25% (floor at 1.0) triggers
            # a recompute. Absolute cap keeps tiny distributions from flapping.
            denom = max(abs(o), 1.0)
            if abs(n - o) / denom > 0.25:
                return True
        old_sources = fingerprint.get('sources')
        if not isinstance(old_sources, dict):
            # Legacy format (pre-per-kind list of "name=count" strings):
            # recompute once, after which the dict format is stored.
            return True
        new_sources = self._source_fingerprint(kind)
        if set(old_sources) != set(new_sources):
            return True  # feed added or removed
        for name, n in new_sources.items():
            o = old_sources.get(name, 0)
            if abs(n - o) / max(o, 1) > 0.25:
                return True  # materially resized, not routine churn
        return False

    def _natural_breaks(self, votes: List[float]) -> tuple[float, float]:
        """Find the medium/high tier boundaries from the vote distribution:
        1-D k-means (k=3, deterministic quantile init) over all indicators
        with evidence; boundaries are the midpoints between adjacent cluster
        centroids. The configured floors are hard minimums — a boundary is
        never placed below them — and they alone apply when the population
        is too small or too uniform to cluster."""
        vals = sorted(v for v in votes if v > 0)
        if len(vals) < 50 or len(set(vals)) < 3:
            return self.medium_floor, self.high_floor

        prefix = [0.0]
        for v in vals:
            prefix.append(prefix[-1] + v)

        def seg_mean(i: int, j: int) -> float:
            return (prefix[j] - prefix[i]) / (j - i)

        c = [vals[len(vals) // 6], vals[len(vals) // 2], vals[(5 * len(vals)) // 6]]
        if not (c[0] < c[1] < c[2]):
            d = sorted(set(vals))
            c = [d[0], d[len(d) // 2], d[-1]]
        for _ in range(100):
            i1 = bisect.bisect_right(vals, (c[0] + c[1]) / 2)
            i2 = bisect.bisect_right(vals, (c[1] + c[2]) / 2)
            i1 = max(1, min(i1, len(vals) - 2))
            i2 = max(i1 + 1, min(i2, len(vals) - 1))
            nc = [seg_mean(0, i1), seg_mean(i1, i2), seg_mean(i2, len(vals))]
            if nc == c:
                break
            c = nc

        c.sort()
        med_b = max((c[0] + c[1]) / 2, self.medium_floor)
        high_b = max((c[1] + c[2]) / 2, self.high_floor, med_b + 1e-9)
        return med_b, high_b

    def _tier_from_votes(self, votes: float, sources: Optional[List[str]],
                         med_b: float, high_b: float,
                         kind: str = 'ip') -> ConfidenceTier:
        """Tier from effective votes: strictly above the boundary. The high
        tier keeps the require_threat_intel gate — an IP known only from
        custom/manual data tops out at medium no matter how many votes.

        Domain HIGH is provenance-first: a domain reported by a feed the
        operator designated authoritative (scoring.high_confidence.
        authoritative_domain_feeds) is HIGH on that feed's word alone.
        Curated domain blocklists aren't independent witnesses the way IP
        scanner feeds are — aggregators republish each other, so the
        overlap-discounted vote count collapses real consensus toward one
        witness and (measured on prod) NO domain clears the vote boundary.
        Who reported it is the honest confidence signal for domains; a
        tier-scoped whitelist entry remains the per-domain escape hatch.

        Authority is revocable by evidence: an authoritative feed whose
        false-positive penalty factor has fallen below FP_DEGRADED_FACTOR —
        the same threshold that shows the "degraded" badge on the dashboard —
        loses its force-HIGH privilege until the flags are cleared and the
        factor recovers. This keys on the FP penalty, not the configured
        weight, so an operator-pinned low base weight never silently strips
        authority. It extends the self-healing FP loop to the provenance
        path: tiers are pure vote math and ignore reputation, so without
        this a flagged authoritative feed would keep forcing HIGH.

        Secondary domain witness gate: >= min_domain_sources EFFECTIVE
        (overlap-discounted) witnesses also earns HIGH — genuinely
        independent corroboration counts even without an authoritative
        source. Both gates honor require_threat_intel.
        """
        if not sources:
            return ConfidenceTier.LOW
        high_cfg = self.config.get('scoring', {}).get('high_confidence', {})
        high_require_intel = bool(high_cfg.get('require_threat_intel', False))
        intel_ok = (not high_require_intel) or self._has_intel_source(sources)
        if kind == 'domain':
            auth_feeds = self.authoritative_sources   # provenance-verified names
            if intel_ok and auth_feeds and any(
                    s in auth_feeds
                    and self.feed_penalty.get(s, 1.0) >= FP_DEGRADED_FACTOR
                    for s in sources):
                return ConfidenceTier.HIGH
            min_witnesses = float(high_cfg.get('min_domain_sources', 3))
            if votes >= min_witnesses and intel_ok:
                return ConfidenceTier.HIGH
        if votes > high_b and intel_ok:
            return ConfidenceTier.HIGH
        if votes > med_b:
            return ConfidenceTier.MEDIUM
        return ConfidenceTier.LOW

    def _persist_breaks(self, med_b: float, high_b: float, kind: str = 'ip') -> None:
        key = self.TIER_BREAKS_KEY_DOMAINS if kind == 'domain' \
            else self.TIER_BREAKS_KEY
        try:
            self.db.set_setting(key, json.dumps({'medium': med_b, 'high': high_b}))
        except Exception:
            # never let bookkeeping break a rescore; single-IP scoring falls
            # back to the floors until a persist succeeds
            logger.warning("[score] could not persist %s tier breaks", kind, exc_info=True)

    def _stored_breaks(self, kind: str = 'ip') -> tuple[float, float]:
        """Boundaries persisted by the last full rescore; floors before any
        rescore has run (fresh database)."""
        key = self.TIER_BREAKS_KEY_DOMAINS if kind == 'domain' \
            else self.TIER_BREAKS_KEY
        try:
            raw = self.db.get_setting(key)
            if raw:
                j = json.loads(raw)
                return float(j['medium']), float(j['high'])
        except Exception:
            logger.warning("[score] stored %s tier breaks unreadable; using the floors",
                           kind, exc_info=True)
        return self.medium_floor, self.high_floor

    def _load_netblock_sources(self):
        """Map every stored netblock (any feed, real CIDR from indicator
        metadata) to the set of feeds that reported it, once per run.

        Returns (buckets, wide): buckets keys IPv4 first octet -> list of
        (network, sources) so the per-indicator containment check only scans
        netblocks that could possibly contain the IP; networks broader than
        /8 and IPv6 land in the small catch-all list checked for every IP.
        """
        # A netblock's corroboration follows the same current-listing rule as
        # a direct vote, or a dropped /24 would keep voting for every IP in it.
        current = f" AND {CURRENT_ATTRIBUTION_SQL}" if self.current_votes else ""
        with self.db._cursor() as cur:
            cur.execute(
                "SELECT i.ip, i.metadata, s.source_name "
                "FROM indicators i "
                "JOIN indicator_sources s ON i.id = s.indicator_id "
                f"""WHERE i.metadata LIKE '%"cidr"%'{current}"""
            )
            rows = cur.fetchall()

        nets: Dict = {}
        for row in rows:
            try:
                cidr = json.loads(row['metadata']).get('cidr')
            except (ValueError, TypeError):
                continue
            if not cidr:
                continue
            try:
                net = ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                continue
            nets.setdefault(net, set()).add(row['source_name'])

        buckets: Dict = {}
        wide = []
        for net, srcs in nets.items():
            if net.version == 4 and net.prefixlen >= 8:
                buckets.setdefault(int(net.network_address) >> 24, []).append((net, srcs))
            else:
                wide.append((net, srcs))
        return buckets, wide

    @staticmethod
    def _netblock_sources_for(ip_str: str, netblocks) -> set:
        """Union of the sources of every stored netblock containing ip_str."""
        buckets, wide = netblocks
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return set()
        candidates = wide
        if ip.version == 4:
            candidates = candidates + buckets.get(int(ip) >> 24, [])
        found = set()
        for net, srcs in candidates:
            if ip in net:
                found |= srcs
        return found

    def _calculate_source_score(self, sources: List[str]) -> float:
        """Score based on number of sources (diminishing returns, max at 4+)."""
        if not sources:
            return 0.0
        return min(len(sources) * 0.25, 1.0)

    def _calculate_reputation_score(self, sources: List[str]) -> float:
        """Average reputation weight across the reporting sources."""
        if not sources:
            return 0.0
        weights = [self.source_weights.get(s, DEFAULT_SOURCE_WEIGHT) for s in sources]
        return sum(weights) / len(weights)

    def _calculate_recency_score(self, last_seen) -> float:
        """Exponential decay based on how recently the indicator was seen."""
        try:
            if isinstance(last_seen, datetime):
                last_seen_dt = last_seen
            else:
                last_seen_dt = datetime.fromisoformat(last_seen)
        except (ValueError, TypeError):
            return 0.5  # Default if parsing fails

        # Compare in UTC; tolerate both naive and aware timestamps.
        now = datetime.now(timezone.utc)
        if last_seen_dt.tzinfo is None:
            last_seen_dt = last_seen_dt.replace(tzinfo=timezone.utc)

        hours_ago = (now - last_seen_dt).total_seconds() / 3600
        half_life = self.config.get('scoring', {}).get('decay_half_life_hours', 72)
        return math.pow(0.5, hours_ago / half_life)

    def _has_intel_source(self, sources: Optional[List[str]]) -> bool:
        """True if any reporting source is a curated external feed — any feed
        type except 'custom'. Custom uploads, local lists, the 'manual'
        pseudo-source, and unknown sources do not count, so an IP known only
        from user-supplied data cannot satisfy require_threat_intel."""
        if sources is None:
            return True  # callers without source detail skip the gate
        return any(
            self.source_types.get(s) not in (None, FeedType.CUSTOM.value)
            for s in sources
        )

    def _determine_tier(self, score: float, source_count: int,
                        sources: Optional[List[str]] = None) -> ConfidenceTier:
        """Determine confidence tier based on score, source count, and (for
        the high tier's require_threat_intel gate) which feeds reported it."""
        scoring = self.config.get('scoring', {})
        high_config = scoring.get('high_confidence', {})
        medium_config = scoring.get('medium_confidence', {})

        high_min_sources = high_config.get('min_sources', 3)
        high_min_score = high_config.get('min_score', 0.75)
        high_require_intel = bool(high_config.get('require_threat_intel', False))
        medium_min_sources = medium_config.get('min_sources', 2)
        medium_min_score = medium_config.get('min_score', 0.5)

        if (source_count >= high_min_sources and score >= high_min_score
                and (not high_require_intel or self._has_intel_source(sources))):
            return ConfidenceTier.HIGH
        if source_count >= medium_min_sources and score >= medium_min_score:
            return ConfidenceTier.MEDIUM
        return ConfidenceTier.LOW
