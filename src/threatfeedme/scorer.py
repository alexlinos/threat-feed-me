"""
Confidence Scoring Engine - Calculate and assign confidence tiers
"""
import math
import ipaddress
import json
from datetime import datetime, timezone
from typing import List, Dict, Optional

from threatfeedme.models import ThreatIndicator, ConfidenceTier, FeedType, effective_sources
from threatfeedme.database import Database


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
        }
        total = sum(raw_weights.values()) or 1.0
        self.weights = {k: v / total for k, v in raw_weights.items()}

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
        if self.db is not None:
            try:
                for feed in self.db.get_feed_sources():
                    self.source_types[feed.name] = feed.feed_type.value
            except Exception:
                pass  # never let feed bookkeeping break scoring

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
                # Never let feedback bookkeeping break scoring.
                self.feed_penalty = {}

    # ==================== PUBLIC API ====================

    def calculate_score(self, ip: str) -> tuple[float, ConfidenceTier]:
        """Calculate confidence score and tier for a single IP."""
        indicator = self.db.get_indicator(ip)
        if not indicator:
            return 0.0, ConfidenceTier.LOW

        netblocks = self._load_netblock_sources()
        return self._compute(indicator, netblocks, self.db.get_whitelist_map())

    def recalculate_all_scores(self) -> int:
        """Recalculate scores for all indicators.

        Data is loaded once and written back in a single transaction, avoiding
        the previous per-indicator reconnect and full netblock rescan.
        """
        indicators = self.db.get_all_indicators()
        whitelist_map = self.db.get_whitelist_map()
        netblocks = self._load_netblock_sources()

        updates = []
        for indicator in indicators:
            score, tier = self._compute(indicator, netblocks, whitelist_map)
            updates.append((score, tier.value, indicator.ip))

        if updates:
            conn = self.db._get_connection()
            try:
                conn.executemany(
                    "UPDATE indicators SET confidence_score = ?, tier = ? WHERE ip = ?",
                    updates,
                )
                conn.commit()
            finally:
                conn.close()

        return len(indicators)

    # ==================== SCORING INTERNALS ====================

    def _compute(
        self, indicator: ThreatIndicator, netblocks, whitelist_map: Dict
    ) -> tuple[float, ConfidenceTier]:
        """Compute (score, tier) for an indicator given precomputed netblocks
        (from _load_netblock_sources) and the whitelist scoping map."""
        # Apply whitelist scoping: drop globally-whitelisted IPs entirely and
        # remove any per-feed-whitelisted sources.
        eff = effective_sources(indicator.ip, indicator.sources, whitelist_map)
        if eff is None:
            return 0.0, ConfidenceTier.LOW
        sources = eff
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
            if src not in sources and src not in scoped:
                sources.append(src)

        # No surviving sources means no evidence -> lowest confidence.
        if not sources:
            return 0.0, ConfidenceTier.LOW

        source_count = len(sources)

        source_score = self._calculate_source_score(sources)
        reputation_score = self._calculate_reputation_score(sources)
        recency_score = self._calculate_recency_score(indicator.last_seen)

        total_score = (
            source_score * self.weights['source']
            + reputation_score * self.weights['reputation']
            + recency_score * self.weights['recency']
        )

        tier = self._determine_tier(total_score, source_count, sources)
        return total_score, tier

    def _load_netblock_sources(self):
        """Map every stored netblock (any feed, real CIDR from indicator
        metadata) to the set of feeds that reported it, once per run.

        Returns (buckets, wide): buckets keys IPv4 first octet -> list of
        (network, sources) so the per-indicator containment check only scans
        netblocks that could possibly contain the IP; networks broader than
        /8 and IPv6 land in the small catch-all list checked for every IP.
        """
        with self.db._cursor() as cur:
            cur.execute(
                """
                SELECT i.ip, i.metadata, s.source_name
                FROM indicators i
                JOIN indicator_sources s ON i.id = s.indicator_id
                WHERE i.metadata LIKE '%"cidr"%'
                """
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
