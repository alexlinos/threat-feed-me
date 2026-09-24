"""
Reading STIX 2.1 from a TAXII 2.1 collection (v2.5.0): the parsing half.

threat-feed-me SERVES TAXII (taxii.py); this is the other direction, so a
MISP, OpenCTI or commercial TAXII server can be a feed. The fetch half lives
in feed_ingestor (the `taxii21` scraper) so it inherits the SSRF guard, the
capped reads and the credential policy. Everything here is pure: objects in,
indicator values out.

What is read, and why so little:
  * Only `indicator` objects. Bare observables (ipv4-addr, domain-name SCOs)
    are context in most collections (a victim, an analyst's workstation, a
    sinkhole) and blocking them is how a TIP export takes down a customer.
  * Only STIX patterns that say "this value", nothing conditional. An
    observation like `[ipv4-addr:value = '1.2.3.4' AND
    network-traffic:dst_port = 443]` means "that IP on 443"; extracting the
    IP would block far more than the author asserted, so any value joined
    by AND to another condition is skipped (counted, never guessed). OR
    lists are flattened; so are OR-joined observations. ISSUBSET on an IP
    value is a CIDR. Qualifiers (WITHIN, START/STOP, REPEATS) and
    FOLLOWEDBY make the indicator conditional in time, so they are skipped.
  * The MISP shape `[network-traffic:dst_ref.type = 'ipv4-addr' AND
    network-traffic:dst_ref.value = '1.2.3.4']` is common and means just the
    IP: a `*_ref.type` assertion is a type annotation, not a condition, so
    it is dropped before the AND check.
  * Revoked indicators, ones past `valid_until`, and ones typed `benign` are
    left out, so an indicator leaves the feed when its source withdraws it.

Every value is still untrusted: the normal feed parser validates each one
(ipaddress / IDNA) and the output safety filter runs after that.
"""
import re
from datetime import datetime, timezone
from typing import Dict, Iterable, List, Optional, Tuple

# Paths whose value is an indicator, by the feed kind that may take them.
_IP_PATHS = {"ipv4-addr:value", "ipv6-addr:value",
             "network-traffic:dst_ref.value", "network-traffic:src_ref.value"}
_DOMAIN_PATHS = {"domain-name:value", "url:value"}
_TYPE_ASSERTION = re.compile(r"^[a-z0-9-]+:[a-z_]+_ref\.type$")

_MAX_PATTERN = 20_000          # a pattern longer than this is not an indicator
_TOKEN = re.compile(r"""
    (?P<ws>\s+)
  | (?P<str>'(?:\\.|[^'\\])*')
  | (?P<lb>\[) | (?P<rb>\]) | (?P<lp>\() | (?P<rp>\))
  | (?P<op><=|>=|!=|=|<|>)
  | (?P<word>[A-Za-z0-9_\-:.*]+)
""", re.VERBOSE)


class _Skip(Exception):
    """This pattern is valid STIX we deliberately don't turn into a block."""


def _tokens(pattern: str) -> List[Tuple[str, str]]:
    out, pos = [], 0
    while pos < len(pattern):
        m = _TOKEN.match(pattern, pos)
        if not m:
            raise _Skip("unsupported character")
        pos = m.end()
        kind = m.lastgroup
        if kind != "ws":
            out.append((kind, m.group(kind)))
    return out


def _unquote(s: str) -> str:
    return re.sub(r"\\(.)", r"\1", s[1:-1])


def _observation(tokens: List[Tuple[str, str]]) -> List[Tuple[str, str]]:
    """Comparisons inside one [ ... ]: returns [(path, value)] or raises _Skip.

    AND binds tighter than OR (STIX 2.1 pattern grammar), so the comparisons
    split into OR-separated AND-chains. A chain asserts a value outright only
    if, after dropping `*_ref.type` annotations, exactly one value comparison
    is left; a chain with two (IP AND port) is conditional and skipped, and
    the others still count (A OR (B AND C) matches A on its own). Parentheses
    are accepted only around pure OR lists, where flattening is exact."""
    has_parens = any(k in ("lp", "rp") for k, _ in tokens)
    toks = [t for t in tokens if t[0] not in ("lp", "rp")]
    chains, chain, i = [], [], 0
    saw_and = False
    while i < len(toks):
        if len(toks) - i < 3:
            raise _Skip("truncated comparison")
        (k1, path), (k2, op), (k3, lit) = toks[i], toks[i + 1], toks[i + 2]
        if k1 != "word" or k3 != "str":
            raise _Skip("not a simple comparison")
        if k2 == "op" and op == "=":
            chain.append((path, "=", _unquote(lit)))
        elif k2 == "word" and op.upper() == "ISSUBSET":
            chain.append((path, "ISSUBSET", _unquote(lit)))
        else:
            raise _Skip(f"operator {op!r}")
        i += 3
        if i < len(toks):
            k, word = toks[i]
            word = word.upper() if k == "word" else word
            if word == "OR":
                chains.append(chain)
                chain = []
            elif word == "AND":
                saw_and = True
            else:
                raise _Skip("unexpected token")
            i += 1
    chains.append(chain)
    if has_parens and saw_and:
        raise _Skip("grouped AND")
    out, conditional = [], 0
    for ch in chains:
        values = [(p, op, v) for p, op, v in ch if not (_TYPE_ASSERTION.match(p) and op == "=")]
        if len(values) != 1:
            conditional += bool(values)
            continue
        p, op, v = values[0]
        if op == "=" or p in _IP_PATHS:
            out.append((p, v))
    if not out:
        raise _Skip("value is conditional (AND)" if conditional else "no value comparison")
    return out


def pattern_values(pattern: str) -> List[Tuple[str, str]]:
    """(path, value) pairs a STIX pattern asserts outright; _Skip otherwise."""
    if not pattern or len(pattern) > _MAX_PATTERN:
        raise _Skip("empty or oversized pattern")
    toks = _tokens(pattern)
    values, i = [], 0
    while i < len(toks):
        if toks[i][0] != "lb":
            raise _Skip("expected an observation")
        depth, j = 0, i
        while j < len(toks):
            if toks[j][0] == "lb":
                depth += 1
            elif toks[j][0] == "rb":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        if j >= len(toks):
            raise _Skip("unbalanced brackets")
        values.extend(_observation(toks[i + 1:j]))
        i = j + 1
        if i < len(toks):
            k, word = toks[i]
            if k != "word" or word.upper() != "OR":
                # AND / FOLLOWEDBY between observations, or a qualifier
                # (WITHIN, START, STOP, REPEATS): conditional, not a block.
                raise _Skip(f"{word} between observations")
            i += 1
    return values


def _parse_time(value) -> Optional[datetime]:
    if not isinstance(value, str):
        return None
    try:
        t = datetime.fromisoformat(value)   # 3.11+ accepts a trailing Z
    except ValueError:
        return None
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)


def indicator_values(objects: Iterable[dict], kind: str,
                     now: Optional[datetime] = None) -> Tuple[List[str], Dict[str, int]]:
    """Values of the given kind ('ip' / 'domain') asserted by the CURRENT
    indicators among `objects`, plus counts of what was skipped and why.
    When one indicator id appears in several versions, the latest wins."""
    now = now or datetime.now(timezone.utc)
    wanted = _IP_PATHS if kind == "ip" else _DOMAIN_PATHS
    latest: Dict[str, dict] = {}
    for obj in objects:
        if not isinstance(obj, dict) or obj.get("type") != "indicator":
            continue
        oid = str(obj.get("id") or "")
        prev = latest.get(oid)
        if prev is None or str(obj.get("modified") or "") >= str(prev.get("modified") or ""):
            latest[oid] = obj
    out, seen = [], set()
    stats = {"indicators": 0, "revoked": 0, "expired": 0, "benign": 0,
             "not_stix": 0, "conditional": 0, "other_kind": 0}
    for obj in latest.values():
        stats["indicators"] += 1
        if obj.get("revoked") is True:
            stats["revoked"] += 1
            continue
        until = _parse_time(obj.get("valid_until"))
        if until is not None and until <= now:
            stats["expired"] += 1
            continue
        types = obj.get("indicator_types") or []
        if isinstance(types, list) and "benign" in types:
            stats["benign"] += 1
            continue
        if obj.get("pattern_type", "stix") != "stix":
            stats["not_stix"] += 1
            continue
        try:
            pairs = pattern_values(str(obj.get("pattern") or ""))
        except _Skip:
            stats["conditional"] += 1
            continue
        took = False
        for path, value in pairs:
            if path in wanted and value and value not in seen:
                seen.add(value)
                out.append(value)
                took = True
        if not took:
            stats["other_kind"] += 1
    return out, stats
