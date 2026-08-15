"""
Threat Feed Me! - Core Data Models
"""
import ipaddress
from pydantic import BaseModel, ConfigDict, field_validator
from typing import Optional, List, Dict, Any, Set, Tuple
from datetime import datetime
from enum import Enum


# Sentinel feed name meaning "all feeds" for a whitelist entry. A whitelist
# entry scoped to ALL_FEEDS excludes the IP everywhere; an entry scoped to a
# specific feed name only suppresses that feed's report of the IP.
ALL_FEEDS = "*"

# Why an IP was whitelisted. Only FALSE_POSITIVE feeds back into feed scoring
# (it means the feed was wrong); the others mean the feed was right but the org
# is choosing not to block, so the feed is not penalized.
REASON_FALSE_POSITIVE = "false_positive"
REASON_RISK_ACCEPTED = "risk_accepted"
REASON_INTERNAL_ASSET = "internal_asset"
REASON_OTHER = "other"
WHITELIST_REASONS = {
    REASON_FALSE_POSITIVE: "False positive (feed was wrong — lowers feed score)",
    REASON_RISK_ACCEPTED: "Risk accepted (known-bad but allowed)",
    REASON_INTERNAL_ASSET: "Internal/known asset",
    REASON_OTHER: "Other",
}


class WhitelistMatcher(dict):
    """Whitelist scoping map: exact indicator value (str) -> set(feed_names).

    Subclasses ``dict`` so existing callers/tests that treat the whitelist map
    as a plain dict (``.get(ip)``, ``in``, ``==`` comparison, iteration) keep
    working unchanged. On top of the exact map it also holds parsed range
    rules, one flavour per indicator kind:

      - CIDR rules ("10.0.0.0/8") suppress every IP the network contains,
        mirroring the containment the Spamhaus overlap path already does. A
        bare host or an explicit /32 (or /128) stays an exact entry only.
      - Wildcard domain rules ("*.example.com") suppress the apex domain and
        every subdomain — the D6 domain analogue of a CIDR (a phishing kit
        rotates hostnames under one domain the way a botnet rotates IPs
        inside one netblock).
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Parsed CIDR rules: list of (ip_network, set(feed_names)). Built only
        # from entries that are real networks with a non-host prefix.
        self.cidr_rules: List[Tuple[Any, Set[str]]] = []
        # Wildcard domain rules: list of (apex_domain, set(feed_names)),
        # built from "*.apex" keys. Matching is label-edge suffix match.
        self.wildcard_rules: List[Tuple[str, Set[str]]] = []

    def add_cidr_rules_from_keys(self) -> None:
        """(Re)build CIDR and wildcard-domain rules from the current keys.

        An entry is treated as a CIDR rule when its stored value parses as a
        network whose prefix is shorter than a single host (so a plain host or
        a /32 // /128 is left as an exact match only), and as a wildcard rule
        when it starts with "*."."""
        rules: List[Tuple[Any, Set[str]]] = []
        wildcards: List[Tuple[str, Set[str]]] = []
        for key, feeds in self.items():
            if key.startswith("*."):
                apex = key[2:]
                if apex:
                    wildcards.append((apex, set(feeds)))
                continue
            if "/" not in key:
                continue
            try:
                net = ipaddress.ip_network(key, strict=False)
            except ValueError:
                continue
            if net.prefixlen >= net.max_prefixlen:
                continue  # a /32 or /128 is a single host -> exact only
            rules.append((net, set(feeds)))
        self.cidr_rules = rules
        self.wildcard_rules = wildcards

    def scoped_feeds(self, value: str) -> Set[str]:
        """Feeds whitelisting ``value`` (an IP or a domain): the exact match
        plus any containing CIDR rule (IPs) or wildcard rule (domains).

        Returns the union of every matching rule's feed set; empty set if
        nothing matches."""
        exact = self.get(value)
        scoped: Set[str] = set(exact) if exact else set()
        if self.cidr_rules or self.wildcard_rules:
            try:
                addr = ipaddress.ip_address(value)
            except ValueError:
                addr = None
            if addr is not None:
                for net, feeds in self.cidr_rules:
                    if addr.version == net.version and addr in net:
                        scoped |= feeds
            else:
                # Not an IP -> match domain wildcards. "*.example.com" covers
                # example.com itself and any depth of subdomain (label-edge
                # match, so notexample.com never matches).
                for apex, feeds in self.wildcard_rules:
                    if value == apex or value.endswith('.' + apex):
                        scoped |= feeds
        return scoped


def effective_sources(
    ip: str, sources: List[str], whitelist_map: Dict[str, Set[str]]
) -> Optional[List[str]]:
    """Apply whitelist scoping to an indicator's sources.

    Returns:
      - None  if the IP is globally whitelisted (ALL_FEEDS) -> exclude entirely.
      - the surviving sources otherwise (possibly empty if every reporting feed
        has been whitelisted for this IP, which callers treat as "no evidence").

    Uses CIDR-aware scoping when given a WhitelistMatcher; a plain dict falls
    back to exact-string matching (so legacy callers keep working).
    """
    if hasattr(whitelist_map, "scoped_feeds"):
        scoped = whitelist_map.scoped_feeds(ip)
    else:
        scoped = whitelist_map.get(ip) or set()
    if not scoped:
        return list(sources)
    # Guard: scoped_feeds() must never return None — if it did, the ALL_FEEDS
    # check below would raise TypeError.
    if scoped is None:
        return list(sources)
    if ALL_FEEDS in scoped:
        return None
    return [s for s in sources if s not in scoped]


class FeedType(str, Enum):
    MALWARE = "malware"
    SPAM = "spam"
    PHISHING = "phishing"
    THREAT_INTEL = "threat_intel"
    CUSTOM = "custom"


class ConfidenceTier(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


# Served feeds are cumulative thresholds, not exclusive buckets: an operator
# polling medium.txt must get every high-confidence IP too (the docs have
# always promised "medium = corroborated OR BETTER"). Maps each output feed
# to the indicator tiers it contains.
CUMULATIVE_TIERS = {
    ConfidenceTier.HIGH: (ConfidenceTier.HIGH,),
    ConfidenceTier.MEDIUM: (ConfidenceTier.HIGH, ConfidenceTier.MEDIUM),
    ConfidenceTier.LOW: (ConfidenceTier.HIGH, ConfidenceTier.MEDIUM,
                         ConfidenceTier.LOW),
}


class FeedSource(BaseModel):
    name: str
    url: str
    feed_type: FeedType = FeedType.CUSTOM
    weight: float = 1.0  # equal starting reputation; FP feedback earns it down
    update_interval: int = 3600  # seconds
    requires_auth: bool = False
    local_file: bool = False
    # When requires_auth is True, the API key is read from this environment
    # variable and sent in this header. Keys are never stored in config/code.
    auth_env: Optional[str] = None
    auth_header: str = "Authorization"
    # Custom scraper name for feeds that need special fetch logic (e.g. Talos
    # Snort.org terms form). When set, fetch_feed uses the named scraper instead
    # of a plain HTTP GET.
    scraper: Optional[str] = None
    # Disabled feeds are kept but skipped during ingestion.
    enabled: bool = True
    # Kind of indicator this feed produces: 'ip' (default, includes CIDRs) or
    # 'domain'. Feeds DECLARE their kind; domain extraction only runs for
    # domain feeds. Never sniff domains out of IP feeds.
    indicator_kind: str = "ip"

    @field_validator('indicator_kind')
    @classmethod
    def _kind_must_be_known(cls, v):
        # Rejecting at the model catches config typos (indicator_kind:
        # domains) on the seed/sync paths too, not just the API: a junk kind
        # stored on rows would be invisible to every kind-filtered feed URL
        # while still counted by the dashboard.
        if v not in ("ip", "domain"):
            raise ValueError("indicator_kind must be 'ip' or 'domain'")
        return v

    # Allow "type" in YAML to map to "feed_type"
    model_config = ConfigDict(populate_by_name=True)


class ThreatIndicator(BaseModel):
    ip: str
    sources: List[str]  # List of feed names that reported this IP
    first_seen: datetime
    last_seen: datetime
    confidence_score: float
    tier: ConfidenceTier
    metadata: Dict[str, Any] = {}
    # Overlap-discounted independent-witness count from the last rescore
    # (None until one has run). Includes netblock-derived votes, so it can
    # exceed len(sources) — this is what explains an IP's tier.
    effective_votes: Optional[float] = None
    # Kind of indicator: 'ip' (default, includes CIDRs) or 'domain'.
    kind: str = "ip"

    model_config = ConfigDict(from_attributes=True)


class WhitelistEntry(BaseModel):
    ip: str
    reason: str
    added_by: str
    added_at: datetime
    expires_at: Optional[datetime] = None
    # ALL_FEEDS ("*") = whitelisted from every feed; otherwise a specific feed.
    feed_name: str = ALL_FEEDS
    # One of WHITELIST_REASONS; only false_positive affects feed scoring.
    reason_code: str = REASON_OTHER


class FeedStats(BaseModel):
    feed_name: str
    total_indicators: int
    last_update: datetime
    status: str  # success, error, skipped
    error_message: Optional[str] = None


class AggregationResult(BaseModel):
    total_unique_ips: int
    high_confidence_count: int
    medium_confidence_count: int
    low_confidence_count: int
    whitelisted_count: int
    feeds_processed: int
    processing_time_seconds: float
