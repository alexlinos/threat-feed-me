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
    (a sinkhole answer, or a listed domain whose owner pointed it at a LAN
    address to make the gateway block it),
  * it does not resolve (blocking a dead name protects nobody; it is picked
    up again once it resolves), or
  * it could not be checked inside the time budget (fail closed; the cache
    fills across pushes, so a large tier converges instead of stalling one).

Limits, stated plainly: the gateway resolves the name itself, later, and may
get a different answer; a listed domain's owner can still point it at any
unprotected public address. This check removes the collateral we can see,
it does not make address-level enforcement of a domain list safe.

The lookups use the system resolver and are the only DNS queries the app
makes for indicator values (PRIVACY.md). Nothing connects to the addresses.
"""
import concurrent.futures as cf
import logging
import socket
import threading
import time
from typing import Callable, Dict, List, Optional, Sequence, Tuple

logger = logging.getLogger(__name__)

OK = "ok"                    # resolved, every address unprotected
PROTECTED = "protected"      # an address the IP filter refuses
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

# name -> (expires, addresses). Addresses, not verdicts: a new known-good or
# never-block entry applies on the next push without waiting for the TTL.
_cache: Dict[str, Tuple[float, Tuple[str, ...]]] = {}
_cache_lock = threading.Lock()


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


def _cached(name: str, now: float) -> Optional[Tuple[str, ...]]:
    hit = _cache.get(name)
    if hit is None or hit[0] <= now:
        return None
    return hit[1]


def _store(name: str, addresses: Sequence[str], now: float) -> None:
    ttl = TTL_RESOLVED if addresses else TTL_UNRESOLVED
    with _cache_lock:
        if len(_cache) >= MAX_CACHE:
            for key in [k for k, v in _cache.items() if v[0] <= now]:
                del _cache[key]
            if len(_cache) >= MAX_CACHE:
                _cache.clear()
        _cache[name] = (now + ttl, tuple(addresses))


def clear_cache() -> None:
    with _cache_lock:
        _cache.clear()


def _resolve_one(name: str, lookup: Callable[[str], List[str]],
                 clock: Callable[[], float]) -> None:
    try:
        addresses = lookup(name)
    except Exception:
        addresses = []
    _store(name, addresses, clock())


def screen(names: Sequence[str], cap: int,
           judge: Callable[[str], Optional[str]], *,
           resolve: bool = True, budget: float = DEFAULT_BUDGET,
           lookup: Optional[Callable[[str], List[str]]] = None,
           clock: Callable[[], float] = time.monotonic,
           ) -> List[Tuple[str, str]]:
    """One (verdict, detail) per name, in order.

    `names` is strongest first. Names are examined until `cap` of them are
    OK; the rest are UNEXAMINED (they would be cut at the cap whatever their
    addresses). `judge(address)` returns why an address must not be blocked,
    or None. With `resolve` false nothing is looked up: verdicts come from
    the cache and unknown names are UNCHECKED (the read-only coverage view).
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
                missing = [n for n in chunk if _cached(n, now) is None]
                if missing:
                    if pool is None:
                        pool = cf.ThreadPoolExecutor(
                            max_workers=WORKERS, thread_name_prefix="tfm-dns")
                    futures = [pool.submit(_resolve_one, n, lookup, clock)
                               for n in missing]
                    # A lookup still running at the deadline is not waited
                    # for; it lands in the cache for the next push.
                    cf.wait(futures, timeout=max(0.0, deadline - clock()))
            now = clock()
            for name in chunk:
                if ok >= cap:
                    verdicts.append((UNEXAMINED, ""))
                    continue
                addresses = _cached(name, now)
                if addresses is None:
                    verdicts.append((UNCHECKED, ""))
                elif not addresses:
                    verdicts.append((UNRESOLVED, ""))
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
