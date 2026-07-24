"""
Safety guards so a non-expert operator can't accidentally feed their firewall
something harmful — internal/reserved space, or well-known good infrastructure.

Applied at the write boundaries (feed ingestion and manual "add indicator"),
never at the low-level store, and fully toggleable from config.yaml.
"""
import ipaddress
from typing import Optional, Dict, List


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

_CGNAT = ipaddress.ip_network("100.64.0.0/10")  # RFC 6598, not flagged is_private on 3.11


class SafetyFilter:
    def __init__(self, drop_private_reserved: bool = True,
                 protect_known_good: bool = True,
                 known_good: Optional[List[str]] = None):
        self.drop_private_reserved = drop_private_reserved
        self.protect_known_good = protect_known_good
        names = list(KNOWN_GOOD) + list(known_good or [])
        self._known_good = []
        for g in names:
            try:
                self._known_good.append(ipaddress.ip_address(g))
            except ValueError:
                continue

    @classmethod
    def from_config(cls, config: Dict) -> "SafetyFilter":
        s = (config or {}).get("safety", {}) or {}
        return cls(
            drop_private_reserved=s.get("drop_private_reserved", True),
            protect_known_good=s.get("protect_known_good", True),
            known_good=s.get("known_good"),
        )

    def excluded_reason(self, value: str) -> Optional[str]:
        """Return a human-readable reason if this IP/CIDR must not be blocked,
        else None. Non-IP values are left for other validation to handle."""
        try:
            net = ipaddress.ip_network(value, strict=False)
        except ValueError:
            return None

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
