"""
Address check for domain lists that a gateway enforces by resolved address.

A UniFi domain list in a firewall policy is not a DNS filter: the gateway
blocks the ADDRESSES the listed names resolve to. Most phishing domains sit
behind a CDN proxy, so "block evil.example" becomes "block one of the CDN's
shared addresses" and every unrelated site on that address goes down with
it. Measured on a live High tier the day this was written: 543 of 870 pushed
domains resolved into one CDN's proxy ranges, 953 distinct shared addresses.
The name-based shared-platform guard (scorer.DEFAULT_SHARED_PLATFORMS)
cannot see this; the domains carry their own names.

So before a domain goes to such a gateway it must pass the IP list's own
rule: every address it resolves to has to be one the safety filter would
let onto an IP list. A name is held back when

  * any address is protected (shared CDN edge, public resolvers, the
    operator's known-good and never-block entries) or private / reserved
    (a listed domain whose owner pointed it at a LAN address to make the
    gateway block it),
  * every address is a placeholder (0.0.0.0, loopback, the documentation
    ranges): the answer of a DNS filter that already blocks the name, which
    says nothing about where the name really lives. Measured the day 2.7.3
    rolled: both installs resolved through a gateway whose own filter
    answered 95% of the listed names with its block-page address, and the
    check read that as "reserved address". Still held back (the real
    addresses are unknown), but counted apart so the panel can say why,
  * it does not resolve (blocking a dead name protects nobody; it is picked
    up again once it resolves), or
  * it could not be checked inside the time budget (fail closed; the cache
    fills across pushes, so a large tier converges instead of stalling one).

Limits, stated plainly: the gateway resolves the name itself, later, and may
get a different answer; a listed domain's owner can still point it at any
unprotected public address. This check removes the collateral we can see,
it does not make address-level enforcement of a domain list safe.

The lookups use the system resolver unless the operator picks a public one
(PUBLIC_RESOLVERS, DNS over HTTPS): behind a filtering resolver that is the
only way to see real addresses, and it sends the names being checked to that
provider, so it is off until chosen. These are the only DNS queries the app
makes for indicator values (PRIVACY.md). Nothing connects to the addresses.
"""
import concurrent.futures as cf
import ipaddress
import json
import logging
import socket
import threading
import time
from typing import Callable, Dict, List, Optional, Sequence, Tuple

logger = logging.getLogger(__name__)

OK = "ok"                    # resolved, every address unprotected
PROTECTED = "protected"      # an address the IP filter refuses
FILTERED = "filtered"        # placeholder addresses only: a DNS filter's answer
UNRESOLVED = "unresolved"    # no address
UNCHECKED = "unchecked"      # no answer inside the budget; held back this push
UNEXAMINED = "unexamined"    # past the cap: never needed a verdict

# A resolved answer is re-read every couple of hours so a domain that moves
# behind a CDN is withdrawn soon; a dead name is the slow lookup, so its
# answer is kept longer (the cost is only a delay before it is pushed).
TTL_RESOLVED = 2 * 3600
TTL_UNRESOLVED = 6 * 3600
MAX_CACHE = 400_000
DEFAULT_BUDGET = 90.0        # seconds of lookups per screening
WORKERS = 32
CHUNK = 256

# (source, name) -> (expires, addresses). Addresses, not verdicts: a new
# known-good or never-block entry applies on the next push without waiting
# for the TTL. Keyed by source so switching resolver never reuses the other
# one's answers (a filter's placeholder would outlive the switch by hours).
SYSTEM = "system"
_cache: Dict[Tuple[str, str], Tuple[float, Tuple[str, ...]]] = {}
_cache_lock = threading.Lock()

# What a filtering resolver answers with in place of the real record: the
# unspecified and loopback addresses (most hosts-file style filters) and the
# documentation ranges (a UniFi gateway's block page sits in 203.0.113.0/24).
# None of them is ever a real site's address.
_PLACEHOLDER_NETS = tuple(ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "127.0.0.0/8", "192.0.2.0/24", "198.51.100.0/24",
    "203.0.113.0/24", "::/128", "::1/128", "2001:db8::/32"))


def is_placeholder(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(str(address).split('%', 1)[0])
    except ValueError:
        return False
    return any(ip.version == net.version and ip in net
               for net in _PLACEHOLDER_NETS)


def system_lookup(name: str) -> List[str]:
    """Every address `name` resolves to through the system resolver; [] when
    it does not resolve. The one place this module touches the network."""
    try:
        infos = socket.getaddrinfo(name, None, type=socket.SOCK_STREAM)
    except (OSError, UnicodeError):          # gaierror is an OSError
        return []
    return sorted({str(info[4][0]).split('%', 1)[0] for info in infos})


# The seam: screen() reads this name at call time, and the test suite points
# it at a fake for every test (a unit test must never reach real DNS).
_lookup = system_lookup


def _cached(key: Tuple[str, str], now: float) -> Optional[Tuple[str, ...]]:
    hit = _cache.get(key)
    if hit is None or hit[0] <= now:
        return None
    return hit[1]


def _store(key: Tuple[str, str], addresses: Sequence[str], now: float) -> None:
    ttl = TTL_RESOLVED if addresses else TTL_UNRESOLVED
    with _cache_lock:
        if len(_cache) >= MAX_CACHE:
            for key in [k for k, v in _cache.items() if v[0] <= now]:
                del _cache[key]
            if len(_cache) >= MAX_CACHE:
                _cache.clear()
        _cache[key] = (now + ttl, tuple(addresses))


def clear_cache() -> None:
    with _cache_lock:
        _cache.clear()


def _resolve_one(key: Tuple[str, str], lookup: Callable[[str], List[str]],
                 clock: Callable[[], float]) -> None:
    try:
        addresses = lookup(key[1])
    except Exception:
        # No answer is not "does not resolve": nothing is cached, the name is
        # UNCHECKED this push and asked again on the next. A lookup reports a
        # dead name by returning [], as system_lookup does.
        return
    _store(key, addresses, clock())


def screen(names: Sequence[str], cap: int,
           judge: Callable[[str], Optional[str]], *,
           resolve: bool = True, budget: float = DEFAULT_BUDGET,
           lookup: Optional[Callable[[str], List[str]]] = None,
           clock: Callable[[], float] = time.monotonic,
           source: str = SYSTEM,
           ) -> List[Tuple[str, str]]:
    """One (verdict, detail) per name, in order.

    `names` is strongest first. Names are examined until `cap` of them are
    OK; the rest are UNEXAMINED (they would be cut at the cap whatever their
    addresses). `judge(address)` returns why an address must not be blocked,
    or None. With `resolve` false nothing is looked up: verdicts come from
    the cache and unknown names are UNCHECKED (the read-only coverage view).
    `source` names the resolver the answers come from; each has its own
    cache. A `lookup` that raises leaves the name UNCHECKED.
    """
    lookup = lookup or _lookup
    verdicts: List[Tuple[str, str]] = []
    deadline = clock() + max(0.0, budget)
    ok = 0
    pool: Optional[cf.ThreadPoolExecutor] = None
    try:
        for start in range(0, len(names), CHUNK):
            if ok >= cap:
                break
            chunk = names[start:start + CHUNK]
            now = clock()
            if resolve and now < deadline:
                missing = [n for n in chunk
                           if _cached((source, n), now) is None]
                if missing:
                    if pool is None:
                        pool = cf.ThreadPoolExecutor(
                            max_workers=WORKERS, thread_name_prefix="tfm-dns")
                    futures = [pool.submit(_resolve_one, (source, n), lookup,
                                           clock) for n in missing]
                    # A lookup still running at the deadline is not waited
                    # for; it lands in the cache for the next push.
                    cf.wait(futures, timeout=max(0.0, deadline - clock()))
            now = clock()
            for name in chunk:
                if ok >= cap:
                    verdicts.append((UNEXAMINED, ""))
                    continue
                addresses = _cached((source, name), now)
                if addresses is None:
                    verdicts.append((UNCHECKED, ""))
                elif not addresses:
                    verdicts.append((UNRESOLVED, ""))
                elif all(is_placeholder(a) for a in addresses):
                    verdicts.append((FILTERED, addresses[0]))
                else:
                    for address in addresses:
                        reason = judge(address)
                        if reason:
                            verdicts.append((PROTECTED, f"{address}: {reason}"))
                            break
                    else:
                        verdicts.append((OK, ""))
                        ok += 1
    finally:
        if pool is not None:
            pool.shutdown(wait=False, cancel_futures=True)
    verdicts.extend([(UNEXAMINED, "")] * (len(names) - len(verdicts)))
    return verdicts


# ---- Public resolver (opt-in) -------------------------------------------------
# DNS over HTTPS, JSON form. A closed list: the operator picks a name, never a
# URL, so this is not one more place a typed address gets fetched. Both
# providers answer unfiltered. The requests still go through the feed SSRF
# guard (guarded_get) and a capped read, like every other fetch.
PUBLIC_RESOLVERS = {
    "cloudflare": "https://cloudflare-dns.com/dns-query",
    "google": "https://dns.google/resolve",
}
_DOH_TIMEOUT = (5, 8)            # connect, read
_DOH_MAX_BYTES = 64 * 1024
_DOH_MAX_RECORDS = 64
# After this many failures in a row the resolver is taken as down for the
# rest of the screening: 800 names must not each wait out a timeout.
_DOH_TRIP = 24
_RR_A, _RR_AAAA = 1, 28
_RCODE_OK, _RCODE_SERVFAIL, _RCODE_NXDOMAIN, _RCODE_REFUSED = 0, 2, 3, 5


class LookupFailed(RuntimeError):
    """The resolver gave no usable answer. Distinct from "does not resolve"."""


_sessions = threading.local()


def _session():
    session = getattr(_sessions, "session", None)
    if session is None:
        import requests
        session = _sessions.session = requests.Session()
    return session


def doh_query(url: str, name: str, rtype: str, allow_private: bool) -> dict:
    """One DNS-JSON query: the only place the public path touches the
    network."""
    from threatfeedme import feed_ingestor
    response = feed_ingestor.guarded_get(
        url, allow_private=allow_private, get=_session().get,
        params={"name": name, "type": rtype},
        headers={"Accept": "application/dns-json"},
        timeout=_DOH_TIMEOUT, allow_redirects=False)
    try:
        if response.status_code != 200:
            raise LookupFailed(f"HTTP {response.status_code}")
        body = feed_ingestor._read_capped_bytes(
            response, "public resolver", _DOH_MAX_BYTES)
    finally:
        response.close()
    document = json.loads(body)
    if not isinstance(document, dict):
        raise LookupFailed("not a DNS JSON answer")
    return document


# The seam, as _lookup is for the system resolver: PublicLookup reads this
# name at call time and the test suite points it at a fake for every test.
_query = doh_query


def _answer_addresses(document: dict) -> List[str]:
    """The A/AAAA addresses in a DNS-JSON answer. The body is remote input:
    anything that does not parse as an address is dropped."""
    status = document.get("Status")
    # What the system resolver reports as not resolving. REFUSED is the
    # name's own servers turning the question away (a lame delegation): one
    # public resolver passes it on as 5 where the other says SERVFAIL for the
    # same names. A provider refusing US answers with an HTTP error instead.
    if status in (_RCODE_NXDOMAIN, _RCODE_SERVFAIL, _RCODE_REFUSED):
        return []
    if status != _RCODE_OK:
        raise LookupFailed(f"DNS status {status!r}")
    answers = document.get("Answer")
    found: List[str] = []
    for record in (answers if isinstance(answers, list) else [])[:_DOH_MAX_RECORDS]:
        if not isinstance(record, dict) or record.get("type") not in (_RR_A, _RR_AAAA):
            continue
        try:
            found.append(str(ipaddress.ip_address(str(record.get("data", "")).strip())))
        except ValueError:
            continue
    return found


class PublicLookup:
    """`lookup` for screen() that asks a public resolver. Raises LookupFailed
    when it gets no usable answer (the name stays unchecked); `failed` and
    `down` tell the caller what to report afterwards."""

    def __init__(self, resolver: str, allow_private: bool = False):
        if resolver not in PUBLIC_RESOLVERS:
            raise ValueError(f"unknown resolver {resolver!r}")
        self.resolver = resolver
        self.url = PUBLIC_RESOLVERS[resolver]
        self.allow_private = allow_private
        self.failed = 0
        self._streak = 0
        self._lock = threading.Lock()

    @property
    def down(self) -> bool:
        return self._streak >= _DOH_TRIP

    def __call__(self, name: str) -> List[str]:
        if self.down:
            raise LookupFailed("public resolver is not answering")
        try:
            found = set()
            for rtype in ("A", "AAAA"):
                found.update(_answer_addresses(
                    _query(self.url, name, rtype, self.allow_private)))
        except Exception as e:
            with self._lock:
                self.failed += 1
                self._streak += 1
            raise LookupFailed(type(e).__name__) from e
        with self._lock:
            self._streak = 0
        return sorted(found)
