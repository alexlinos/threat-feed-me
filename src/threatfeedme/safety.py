"""
Safety guards so a non-expert operator can't accidentally feed their firewall
something harmful — internal/reserved space, or well-known good infrastructure.

Applied at the write boundaries (feed ingestion and manual "add indicator"),
never at the low-level store, and fully toggleable from config.yaml.
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

_CGNAT = ipaddress.ip_network("100.64.0.0/10")  # RFC 6598, not flagged is_private on 3.11


class SafetyFilter:
    def __init__(self, drop_private_reserved: bool = True,
                 protect_known_good: bool = True,
                 known_good: Optional[List[str]] = None,
                 known_good_domains: Optional[List[str]] = None):
        self.drop_private_reserved = drop_private_reserved
        self.protect_known_good = protect_known_good
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
        )

    def excluded_reason(self, value: str) -> Optional[str]:
        """Return a human-readable reason if this IP/CIDR/domain must not be
        blocked, else None. Values that are neither are left for other
        validation to handle."""
        try:
            net = ipaddress.ip_network(value, strict=False)
        except ValueError:
            return self._domain_excluded_reason(value)

        if self.protect_known_good:
            for g in self._known_good:
                if g in net:
                    return f"protected public infrastructure ({g})"

        if self.drop_private_reserved:
            if (net.is_private or net.is_loopback or net.is_link_local
                    or net.is_multicast or net.is_reserved or net.is_unspecified
                    or net.overlaps(_CGNAT)):
                return "private / reserved / bogon address"

        return None

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
