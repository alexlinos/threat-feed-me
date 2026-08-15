"""
Shared feed/indicator helpers used by the routers: the tier-feed catalogue,
feed-URL construction, live whitelist-scoped indicator queries, and IP/CIDR
normalization.
"""
import ipaddress
import socket
from typing import List, Optional, Tuple, Union

from fastapi import Request

from threatfeedme import core
from threatfeedme.domains import normalize_domain
from threatfeedme.exporter import is_included
from threatfeedme.models import ConfidenceTier, CUMULATIVE_TIERS, ThreatIndicator

# ==================== FEED HELPERS ====================
# Ordered so the UI renders strongest-first; "recommended" flags the default
# most operators should point their firewall at.
TIER_FEEDS = [
    {
        "key": "high",
        "label": "High Confidence",
        "description": "More than two independent sources agree (overlap-discounted)",
        "recommended": True,
    },
    {
        "key": "medium",
        "label": "Medium Confidence",
        "description": "Corroborated by more than one independent source; includes high",
        "recommended": False,
    },
    {
        # With cumulative serving, low == all. The URL stays live (firewalls
        # may poll it) but the dashboard shows a single "Everything" card.
        "key": "low",
        "label": "Low Confidence",
        "description": "Alias of the everything feed",
        "recommended": False,
        "hidden": True,
    },
    {
        "key": "all",
        "label": "Everything",
        "description": "Every indicator with any evidence: low.txt serves the same list",
        "recommended": False,
    },
]

_FEEDS_BY_NAME = {f["key"]: f for f in TIER_FEEDS}


def _feed_base(request: Request, tier_key: str = "") -> str:
    """Build the base feed URL for a tier, respecting X-Forwarded-Proto/Proto
    so a reverse proxy (FortiGate, nginx) preserves HTTPS in the link the
    dashboard hands to the operator.

    Returns just the scheme://host[:port] — the caller/template adds the
    /feeds/... path."""
    scheme = request.headers.get("X-Forwarded-Proto") or request.headers.get("Proto") or request.url.scheme
    # The Host / X-Forwarded-Host header already carries the port the client
    # reached us on, so split it out rather than re-appending request.url.port
    # (which would double it, e.g. "host:8080:8080").
    host_hdr = request.headers.get("X-Forwarded-Host") or request.headers.get("Host")
    if host_hdr:
        hostname, _, port = host_hdr.partition(":")
    else:
        hostname = request.url.hostname or "localhost"
        port = str(request.url.port or "")
    # A loopback/wildcard host is unreachable from the firewall polling the URL;
    # swap in this server's LAN IP so the operator can paste it as-is.
    if hostname in ("localhost", "127.0.0.1", "0.0.0.0", "::1", "::"):
        hostname = _lan_ip()
    if port and port not in ("80", "443"):
        return f"{scheme}://{hostname}:{port}"
    return f"{scheme}://{hostname}"


def _indicators_for(tier=None, kind: str = "ip"):
    """Live indicator query with whitelist applied (global excludes dropped).

    Accepts None (all indicators), a ConfidenceTier enum, or a string tier
    key ("high", "medium", "low", "all") for callers that pass the URL path
    parameter directly. "all" returns every indicator regardless of tier.

    `kind` filters the population ('ip' or 'domain') so the IP feed URLs
    never emit a domain and the domain feed URLs never emit an IP — a
    FortiGate address feed fed a hostname errors the whole import, so the
    two kinds must never bleed into each other's files.
    Returns ThreatIndicator objects so downstream callers (export, feed
    construction) have structured data instead of raw dicts.
    """
    wl_map = core.db.get_whitelist_map()
    if tier is None or tier == "all":
        indicators = core.db.get_indicators_by_kind(kind)
        return [i for i in indicators if is_included(i, wl_map)]
    tier_enum = ConfidenceTier(tier) if isinstance(tier, str) else tier
    # Cumulative: medium.txt serves high + medium, low.txt serves everything —
    # a firewall polling one URL must get every indicator at or above that
    # confidence. Tier-scoped whitelist exclusions still key off the OUTPUT
    # feed (tier=tier_enum), so "exclude from medium" hides an indicator from
    # medium.txt regardless of which tier it carries.
    indicators = core.db.get_indicators_by_kind_and_tiers(kind, CUMULATIVE_TIERS[tier_enum])
    return [i for i in indicators if is_included(i, wl_map, tier=tier_enum)]


def _lan_ip() -> str:
    """Best-effort LAN-facing IP of this host. Returns 127.0.0.1 when the
    hostname resolves to nothing useful (Docker, no network, etc.)."""
    try:
        hostname = socket.gethostname()
        addrs = socket.getaddrinfo(hostname, None, family=socket.AF_INET)
        for addr in addrs:
            ip = addr[4][0]
            if ip.startswith("127.") or ip == "::1":
                continue
            return ip
    except (socket.gaierror, OSError):
        pass
    return "127.0.0.1"


def _normalize_indicator(value: str):
    """Normalize an indicator value: IP, CIDR, domain, or wildcard domain.
    Returns (stored, pattern_or_None).

    `stored` is the canonical single-indicator value (IP address, network
    address, or punycode domain). `pattern` is non-None when the value names
    a RANGE rather than one indicator — the full CIDR, or the "*.apex"
    wildcard — which is what gets stored as a whitelist key and why callers
    skip single-indicator rescoring for it. Raises ValueError if the value is
    none of the four shapes.
    """
    v = value.strip()
    if not v:
        raise ValueError("empty value")
    if "/" in v:
        network = ipaddress.ip_network(v, strict=False)
        return (str(network.network_address), str(network))
    try:
        return (str(ipaddress.ip_address(v)), None)
    except ValueError:
        pass
    wildcard = v.startswith("*.")
    domain = normalize_domain(v[2:] if wildcard else v)
    if domain is None:
        raise ValueError(f"not an IP, CIDR, or domain: {value!r}")
    return (domain, f"*.{domain}" if wildcard else None)


def _value_kind(stored: str) -> str:
    """Indicator kind of a normalized single value: 'ip' or 'domain'."""
    try:
        ipaddress.ip_address(stored)
        return "ip"
    except ValueError:
        return "domain"
