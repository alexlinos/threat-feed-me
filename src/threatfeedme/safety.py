"""
Safety guards so a non-expert operator can't accidentally feed their firewall
something harmful — internal/reserved space, or well-known good infrastructure.

Applied at the write boundaries (feed ingestion and manual "add indicator"),
never at the low-level store, and fully toggleable from config.yaml. Every
refresh also re-applies it retroactively to what is already stored
(Database.purge_unsafe_indicators), so a filter fix or a new operator
known-good entry takes effect within one refresh instead of waiting for the
offending rows to age out.
"""
import ipaddress
from typing import Optional, Dict, List

from threatfeedme.domains import normalize_domain, reserved_reason


# Well-known benign public infrastructure that should never end up on a block
# list (blocking these would break DNS/connectivity for the whole org). Public
# recursive DNS resolvers are the classic footgun ("why did I just add 8.8.8.8").
KNOWN_GOOD = [
    "8.8.8.8", "8.8.4.4",              # Google Public DNS
    "1.1.1.1", "1.0.0.1",              # Cloudflare DNS
    "9.9.9.9", "149.112.112.112",      # Quad9
    "208.67.222.222", "208.67.220.220",  # OpenDNS
    "4.2.2.1", "4.2.2.2",              # Level3
]

# The domain analogue of KNOWN_GOOD: infrastructure whose DNS-layer blocking
# takes down OS updates, TLS revocation checks, or the org's mail — no matter
# what a feed says (compromised pages ON these platforms belong in a URL/
# email-layer product, not a DNS blocklist; D4). An entry protects itself and
# every subdomain. Deliberately small and curated — a top-N popularity list
# would smuggle in thousands of unreviewed names (and top-N sites are exactly
# what phishing kits abuse).
KNOWN_GOOD_DOMAINS = [
    # OS + browser update channels: blocking these bricks patching.
    "microsoft.com", "windowsupdate.com", "windows.com", "windows.net",
    "apple.com", "icloud.com",
    "google.com", "gstatic.com", "googleapis.com", "android.com",
    "mozilla.org", "ubuntu.com", "debian.org",
    # CDN backbones: half the web's assets resolve through these.
    "akamai.net", "akamaiedge.net", "akamaihd.net",
    "cloudfront.net", "cloudflare.com", "fastly.net",
    "amazonaws.com", "azureedge.net", "azure.com",
    # Mail infrastructure: silently eating the org's mail is the worst
    # failure mode of all (nobody notices until something was missed).
    "gmail.com", "googlemail.com", "outlook.com", "live.com",
    "office.com", "office365.com", "protection.outlook.com",
]

# IANA special-purpose address registries (RFC 6890 and successors), as an
# explicit list checked by OVERLAP. ipaddress's is_private on a *network* is
# true only when both its first and last address are private, so a supernet
# straddling private and public space (10.0.0.0/7, 172.16.0.0/11,
# 192.168.0.0/15) used to pass — one poisoned upstream line would have made a
# firewall block its own LAN (found in review 2026-09-22). Overlap, not
# containment, is the rule: any entry touching this space is refused.
_SPECIAL_V4 = [ipaddress.ip_network(n) for n in (
    "0.0.0.0/8",        # "this network"
    "10.0.0.0/8",       # RFC 1918
    "100.64.0.0/10",    # RFC 6598 shared/CGNAT
    "127.0.0.0/8",      # loopback
    "169.254.0.0/16",   # link-local
    "172.16.0.0/12",    # RFC 1918
    "192.0.0.0/24",     # IETF protocol assignments
    "192.0.2.0/24",     # TEST-NET-1
    "192.88.99.0/24",   # deprecated 6to4 relay anycast
    "192.168.0.0/16",   # RFC 1918
    "198.18.0.0/15",    # benchmarking
    "198.51.100.0/24",  # TEST-NET-2
    "203.0.113.0/24",   # TEST-NET-3
    "224.0.0.0/4",      # multicast
    "240.0.0.0/4",      # reserved + limited broadcast
)]
_SPECIAL_V6 = [ipaddress.ip_network(n) for n in (
    "::/128", "::1/128",          # unspecified, loopback
    "::ffff:0:0/96",              # IPv4-mapped (would smuggle v4 private space)
    "64:ff9b::/96", "64:ff9b:1::/48",  # NAT64 — blocking breaks v6-only clients
    "100::/64",                   # discard-only
    "2001::/23",                  # IETF protocol assignments (incl. Teredo)
    "2001:db8::/32",              # documentation
    "2002::/16",                  # 6to4
    "fc00::/7",                   # unique-local
    "fe80::/10",                  # link-local
    "ff00::/8",                   # multicast
)]

# Widest netblock a block list may carry. A poisoned upstream serving
# 64.0.0.0/3 is an eighth of IPv4, a self-inflicted outage even though it
# touches no private space. Measured on the live corpus (2026-09-22) the widest
# LEGITIMATE entries are /12 (Spamhaus DROP hijacked blocks, bbcan177, ET) —
# a /16 floor would have silently dropped real protection — so the default
# refuses /0-/9 and keeps a margin under real data. 0 disables.
DEFAULT_MIN_PREFIX_V4 = 10
DEFAULT_MIN_PREFIX_V6 = 24


class SafetyFilter:
    def __init__(self, drop_private_reserved: bool = True,
                 protect_known_good: bool = True,
                 known_good: Optional[List[str]] = None,
                 known_good_domains: Optional[List[str]] = None,
                 min_prefix_v4: int = DEFAULT_MIN_PREFIX_V4,
                 min_prefix_v6: int = DEFAULT_MIN_PREFIX_V6):
        self.drop_private_reserved = drop_private_reserved
        self.protect_known_good = protect_known_good
        self.min_prefix_v4 = int(min_prefix_v4 or 0)
        self.min_prefix_v6 = int(min_prefix_v6 or 0)
        names = list(KNOWN_GOOD) + list(known_good or [])
        self._known_good = []
        for g in names:
            try:
                self._known_good.append(ipaddress.ip_address(g))
            except ValueError:
                continue
        # Canonicalized domain floor: the shipped core list plus the operator's
        # own domains from config (safety.known_good_domains — their mail
        # server, their SaaS tenant). Entries that don't normalize are dropped
        # rather than silently matching nothing.
        self._known_good_domains = []
        for g in list(KNOWN_GOOD_DOMAINS) + list(known_good_domains or []):
            canon = normalize_domain(g)
            if canon:
                self._known_good_domains.append(canon)

    @classmethod
    def from_config(cls, config: Dict) -> "SafetyFilter":
        s = (config or {}).get("safety", {}) or {}
        return cls(
            drop_private_reserved=s.get("drop_private_reserved", True),
            protect_known_good=s.get("protect_known_good", True),
            known_good=s.get("known_good"),
            known_good_domains=s.get("known_good_domains"),
            min_prefix_v4=s.get("min_prefix_ipv4", DEFAULT_MIN_PREFIX_V4),
            min_prefix_v6=s.get("min_prefix_ipv6", DEFAULT_MIN_PREFIX_V6),
        )

    def excluded_reason(self, value: str) -> Optional[str]:
        """Return a human-readable reason if this IP/CIDR/domain must not be
        blocked, else None. Values that are neither are left for other
        validation to handle."""
        try:
            net = ipaddress.ip_network(value, strict=False)
        except ValueError:
            return self._domain_excluded_reason(value)
        return self._net_excluded_reason(net)

    def _net_excluded_reason(self, net) -> Optional[str]:
        if self.protect_known_good:
            for g in self._known_good:
                if g in net:
                    return f"protected public infrastructure ({g})"

        if self.drop_private_reserved:
            for special in (_SPECIAL_V4 if net.version == 4 else _SPECIAL_V6):
                if net.overlaps(special):
                    return f"private / reserved / bogon address (overlaps {special})"

        floor = self.min_prefix_v4 if net.version == 4 else self.min_prefix_v6
        if floor and net.prefixlen < floor:
            return f"netblock too wide (/{net.prefixlen}; minimum /{floor})"

        return None

    def stored_value_reason(self, value: str, kind: str,
                            cidr: Optional[str] = None) -> Optional[str]:
        """excluded_reason for a value ALREADY in the store, used by the
        retroactive sweep. Stored domains are canonical already, so this skips
        the IDNA re-normalization that dominates excluded_reason's cost on a
        ~200k-domain corpus; IPs are checked on their served CIDR when one
        exists (the stored value is only the network address)."""
        if kind == "domain":
            if self.drop_private_reserved:
                reason = reserved_reason(value)
                if reason:
                    return reason
            if self.protect_known_good:
                for g in self._known_good_domains:
                    if value == g or value.endswith('.' + g):
                        return f"protected known-good domain ({g})"
            return None
        try:
            net = ipaddress.ip_network(cidr or value, strict=False)
        except ValueError:
            return None
        return self._net_excluded_reason(net)

    def _domain_excluded_reason(self, value: str) -> Optional[str]:
        """Domain arm of excluded_reason, same toggles as the IP arm:
        drop_private_reserved governs special-use TLDs (the domain analogue of
        bogon space), protect_known_good governs the known-good floor. The
        floor matches the domain itself and any subdomain — blocking
        cdn.updates.microsoft.com is as destructive as blocking the apex."""
        domain = normalize_domain(value)
        if domain is None:
            return None  # not a domain either; other validation handles it

        if self.drop_private_reserved:
            reason = reserved_reason(domain)
            if reason:
                return reason

        if self.protect_known_good:
            for g in self._known_good_domains:
                if domain == g or domain.endswith('.' + g):
                    return f"protected known-good domain ({g})"

        return None
