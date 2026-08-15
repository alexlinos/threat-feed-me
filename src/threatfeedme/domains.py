"""
Domain syntax: validation and normalization shared by the feed parser, the
safety filter, and the whitelist.

Kept dependency-light on purpose (D4: no Tranco/public-suffix-list dependency)
— everything here is syntax and IANA special-use registry knowledge, not
reputation. Policy (what to *refuse* to block) lives in safety.py.
"""
import ipaddress
import re
from typing import Optional

# IDNA2008 + UTS46 (already in the tree as a requests dependency, now pinned
# directly). NOT the stdlib 'idna' codec: that one is IDNA2003, whose nameprep
# casefolds deviation characters — ß→ss turns faß.de into fass.de, storing
# (and blocking!) an innocent bystander while the actual threat domain
# xn--fa-hia.de never enters the corpus. UTS46 non-transitional (the modern
# browser behaviour) keeps the two apart.
import idna as _idna

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

# Trailing label separators to strip: ASCII dot plus the unicode dot forms
# UTS46 maps to '.' (ideographic/fullwidth/halfwidth full stops). Interior
# occurrences are handled by the UTS46 remap itself.
_DOT_CHARS = '.。．｡'


def normalize_domain(value: str) -> Optional[str]:
    """Canonicalize a domain: lowercase, trailing-dot stripped, unicode
    IDNA-encoded to punycode (UTS46, non-transitional). Returns None when the
    value is not a plausible public DNS name (no dot, an IP address, an
    all-numeric TLD, bad labels, invalid punycode, over-long).

    Normalization runs BEFORE dedupe/storage so `bücher.example` and
    `xn--bcher-kva.example` collapse into one indicator.
    """
    v = (value or "").strip().rstrip(_DOT_CHARS).lower()
    if not v or '/' in v or ':' in v:
        return None
    if any(ord(c) > 127 for c in v):
        # Unicode form -> punycode. UTS46 also maps unicode dot separators
        # (evil。com) to ASCII dots along the way.
        try:
            v = _idna.encode(v, uts46=True).decode('ascii')
        except (UnicodeError, ValueError):
            return None
    elif 'xn--' in v:
        # Already-punycode input: validate it actually decodes. Unvalidated
        # xn-- junk (xn--zzzzzzz.com) would otherwise be stored and served.
        try:
            _idna.encode(v, uts46=True)
        except (UnicodeError, ValueError):
            return None
    if '.' not in v:
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
    # An all-numeric TLD cannot exist in DNS (RFC 3696). Rejecting it here
    # kills the whole ambiguous-shape class (1.2.3.4.5, 01.2.3.4, ...) that
    # would otherwise be stored as "domains" and served to DNS filters —
    # including IP typos from the manual-add box.
    if v.rpartition('.')[2].isdigit():
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
