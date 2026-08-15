"""
Domain syntax: validation and normalization shared by the feed parser, the
safety filter, and the whitelist.

Kept dependency-free on purpose (D4: no Tranco/public-suffix-list dependency)
— everything here is syntax and IANA special-use registry knowledge, not
reputation. Policy (what to *refuse* to block) lives in safety.py.
"""
import ipaddress
import re
from typing import Optional

# A plausible DNS name: LDH labels, at least one dot. Deliberately ASCII-only;
# unicode names are IDNA-encoded to punycode BEFORE this check so both
# spellings of the same domain dedupe to one indicator.
_DOMAIN_RE = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9-]+)+$')

# Special-use TLDs that can never be a real-world threat indicator: blocking
# them is either meaningless (they don't resolve in public DNS) or harmful
# (.localhost/.local break loopback and mDNS). RFC 6761 (test, localhost,
# invalid, example), RFC 6762 (local), RFC 7686 (onion).
RESERVED_TLDS = frozenset({"test", "example", "invalid", "localhost", "local", "onion"})

# DNS length limits (RFC 1035): 253 visible chars for the full name, 63 per label.
_MAX_DOMAIN_LEN = 253
_MAX_LABEL_LEN = 63


def normalize_domain(value: str) -> Optional[str]:
    """Canonicalize a domain: lowercase, trailing-dot stripped, unicode
    IDNA-encoded to punycode. Returns None when the value is not a plausible
    public DNS name (no dot, an IP address, bad labels, over-long).

    Normalization runs BEFORE dedupe/storage so `bücher.example` and
    `xn--bcher-kva.example` collapse into one indicator.
    """
    v = (value or "").strip().rstrip('.').lower()
    if not v or '.' not in v or '/' in v or ':' in v:
        return None
    if any(ord(c) > 127 for c in v):
        try:
            v = v.encode('idna').decode('ascii')
        except UnicodeError:
            return None
    if len(v) > _MAX_DOMAIN_LEN or any(len(l) > _MAX_LABEL_LEN for l in v.split('.')):
        return None
    try:
        ipaddress.ip_address(v)
        return None  # an IP is never a domain indicator
    except ValueError:
        pass
    if not _DOMAIN_RE.match(v):
        return None
    return v


def is_valid_domain(value: str) -> bool:
    """True when value is already a canonical, plausible domain."""
    return normalize_domain(value) == value


def reserved_reason(domain: str) -> Optional[str]:
    """Why a (canonical) domain can never be blocked, or None if it can.
    Bare TLDs never reach here (normalize_domain requires a dot), so this
    only guards the special-use registry."""
    tld = domain.rpartition('.')[2]
    if tld in RESERVED_TLDS:
        return f"reserved / special-use TLD (.{tld})"
    return None
