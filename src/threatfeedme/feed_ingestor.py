"""
Feed Ingestion Engine - Fetch, normalize, and ingest threat feeds
"""
import csv
import io
import os
import re
import socket
import time
import ipaddress
import json
from datetime import datetime, timezone
from typing import List, Dict, Optional, Tuple, Union
from urllib.parse import urljoin, urlsplit
import logging

import requests

# Maximum bytes to accept from a single feed HTTP fetch. Beyond this the
# connection is closed and the response is treated as an error to prevent
# memory exhaustion from a multi-GB feed response.
_MAX_FETCH_BYTES = 50 * 1024 * 1024  # 50 MB

from threatfeedme.domains import normalize_domain
from threatfeedme.models import FeedSource, FeedType
from threatfeedme.database import Database

logger = logging.getLogger(__name__)

# Retry policy for transient HTTP failures (5xx, timeouts, connection errors).
# _sleep is a module attribute so tests can stub out the real backoff delays.
_MAX_ATTEMPTS = 3
_BACKOFF_SECONDS = (2, 4)
# Cap honored Retry-After values so a hostile server can't pin the
# refresh thread for hours with one header.
_RETRY_AFTER_CAP = 120
_sleep = time.sleep

# Redirects are followed manually (not by requests) so that every hop — not
# just the URL the operator typed — passes the SSRF guard below.
_MAX_REDIRECTS = 5
_REDIRECT_STATUSES = {301, 302, 303, 307, 308}


def _host_addresses(host: str) -> List[str]:
    """Resolve a hostname to all its addresses. Module-level so tests can stub
    it out instead of doing real DNS lookups."""
    return [info[4][0] for info in socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)]


def _require_public_url(url: str) -> None:
    """SSRF guard: reject a URL whose host is (or resolves to) a non-public
    address. Feed URLs can be added at runtime from the dashboard, so without
    this an operator-facing page could be pointed at cloud metadata services
    or internal hosts and use the stored fetch errors as a port-scan oracle."""
    host = urlsplit(url).hostname
    if not host:
        raise RuntimeError(f"feed URL has no host: {url!r}")
    try:
        addresses = _host_addresses(host)
    except socket.gaierror as e:
        # A resolution failure is retryable, like any other connection error.
        raise requests.exceptions.ConnectionError(
            f"could not resolve feed host '{host}': {e}"
        )
    for addr in addresses:
        ip = ipaddress.ip_address(addr.split('%', 1)[0])
        if not ip.is_global:
            raise RuntimeError(
                f"feed URL host '{host}' resolves to non-public address {ip}; "
                "refusing to fetch (set safety.allow_private_feed_urls: true "
                "to permit internal feed URLs)"
            )


class _NotModified:
    """Sentinel type for a 304 response: the feed's content is unchanged and
    the previously ingested indicators remain valid."""

NOT_MODIFIED = _NotModified()

# IPv4 address; the CIDR variant additionally captures the prefix length.
_IP_PATTERN = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
_CIDR_PATTERN = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/\d{1,2}\b'

# Hosts-file line: a sinkhole address then one OR MORE hostnames (multi-
# hostname lines are valid hosts syntax and common in compacted blocklists).
_HOSTS_FILE_RE = re.compile(r'^(?:0\.0\.0\.0|127\.0\.0\.1|::1)\s+(.+)$', re.IGNORECASE)
# URL whose host we keep (openphish style). Captures the full authority;
# userinfo/port are stripped below before validation.
_URL_RE = re.compile(r'^https?://([^/\s]+)', re.IGNORECASE)


def _url_host(authority: str) -> str:
    """Bare hostname from a URL authority: drop user:pass@ and :port. A feed
    entry like http://evil.example:8080/x must yield evil.example, not be
    dropped because the port fails domain validation."""
    host = authority.rpartition('@')[2]
    return host.partition(':')[0]


def parse_domain_feed_content(content: str) -> List[Dict]:
    """Parse domain feed content: hosts-file lines (urlhaus style), plain
    domain-per-line lists, or URLs whose host we keep (openphish; the full
    host, not the registrable domain — blocking login.evil.weebly.com must
    not take down the whole hosting platform).

    Returns ['ip': domain, 'kind': 'domain'] dicts, deduped within the feed
    AFTER normalize_domain (lowercase, IDNA to punycode), so the unicode and
    punycode spellings of one domain collapse to one indicator. IPs, CIDRs,
    and comments are never treated as domains — normalize_domain rejects
    them (including all-numeric-TLD shapes like 1.2.3.4.5), so no separate
    IP-pattern guard is needed and domains that merely EMBED a dotted quad
    (10.0.0.1.nip.io — real phishing infrastructure) still ingest.
    """
    indicators: Dict[str, Dict] = {}

    def _add(candidate: str) -> None:
        domain = normalize_domain(candidate)
        if not domain:
            return
        # One host, one identity: URL lists prefix www. spam onto the same
        # hosts that plain lists carry bare, splitting votes across two rows.
        # Strip it everywhere (only when a registrable name remains, so a
        # literal www.com is left alone).
        if domain.startswith('www.') and domain.count('.') >= 2:
            domain = domain[4:]
        indicators.setdefault(domain, {'ip': domain, 'kind': 'domain'})

    # A UTF-8 BOM survives .strip() (U+FEFF is not whitespace) and breaks the
    # ^-anchored regexes on the first line.
    for line in content.lstrip('﻿').split('\n'):
        line = line.strip()
        if not line or line.startswith('#') or line.startswith(';'):
            continue
        # Inline comments: domains can never contain '#' or ';', so truncate.
        line = line.split('#')[0].split(';')[0].strip()
        if not line:
            continue
        hosts = _HOSTS_FILE_RE.match(line)
        if hosts:
            for token in hosts.group(1).split():
                _add(token)
            continue
        url = _URL_RE.match(line)
        if url:
            _add(_url_host(url.group(1).lower()))
            continue
        # Plain domain-per-line (first token, so trailing annotations on
        # loosely-formatted lists don't cost the indicator).
        _add(line.split()[0])
    return list(indicators.values())


def parse_feed_content(content: str) -> List[Dict]:
    """Parse feed content and extract IPs and netblocks.

    Netblocks retain their real CIDR notation so downstream overlap detection is
    exact rather than a /16-/20-/24 guess. Module-level so callers (e.g. upload
    validation) can reuse it without a Database.
    """
    # Keyed by stored indicator value so duplicates within one feed collapse.
    indicators: Dict[str, Dict] = {}

    for line in content.split('\n'):
        line = line.strip()

        # Skip comments and empty lines
        if not line or line.startswith('#') or line.startswith(';'):
            continue

        cidr_matches = re.findall(_CIDR_PATTERN, line)
        if cidr_matches:
            for cidr in cidr_matches:
                try:
                    network = ipaddress.ip_network(cidr, strict=False)
                except ValueError:
                    continue
                # Store the network address as the indicator but keep the
                # canonical CIDR (with real prefix) for exact matching.
                net_addr = str(network.network_address)
                indicators[net_addr] = {'ip': net_addr, 'cidr': str(network)}
        else:
            for found_ip in re.findall(_IP_PATTERN, line):
                # Validate + canonicalize: the regex alone admits shapes
                # ipaddress rejects (leading-zero octets like 01.2.3.4), and
                # serving such a string on the IP-only URLs errors a strict
                # firewall address import — the exact D2 failure. The CIDR
                # branch above already gets this via ip_network().
                try:
                    canon = str(ipaddress.ip_address(found_ip))
                except ValueError:
                    continue
                # Do not let a bare IP overwrite a netblock's CIDR metadata.
                indicators.setdefault(canon, {'ip': canon, 'cidr': None})

    return list(indicators.values())


class FeedIngestor:
    # Scraper registry: scraper name -> callable(self, feed) -> str content
    _SCRAPERS = {}

    @classmethod
    def register_scraper(cls, name: str):
        """Decorator to register a scraper function."""
        def wrapper(fn):
            cls._SCRAPERS[name] = fn
            return fn
        return wrapper

    def __init__(self, db: Database, safety=None, allow_private_urls: bool = False):
        self.db = db
        # Optional SafetyFilter; when set, private/reserved/known-good entries
        # are skipped at ingest so they never reach outputs.
        self.safety = safety
        # Opt-out for the SSRF guard, for deployments that legitimately fetch
        # feeds from internal servers (e.g. an on-prem honeypot).
        self.allow_private_urls = allow_private_urls
        # Validators from the most recent HTTP 200, held here until the whole
        # ingest succeeds. Persisting them any earlier would let the next
        # refresh 304 against content that was never stored (e.g. a crash
        # mid-ingest). None means "nothing to persist" (local file or 304);
        # (None, None) means "clear the stored validators".
        self._pending_validators: Optional[Tuple[Optional[str], Optional[str]]] = None
        # Per-feed values from each COMPLETE ingest this ingestor performed,
        # keyed by feed name — the churn log diffs these against source_state
        # (see Database.update_source_sightings). A not-modified or failed
        # fetch deliberately leaves no entry: no clean snapshot, no diff, so a
        # partial refresh can never fake a mass-leave. Post-safety-filter, so
        # the log tracks what actually entered the corpus.
        self.ingested_values: Dict[str, Set[str]] = {}

    def fetch_feed(self, feed: FeedSource) -> Union[List[Dict], _NotModified]:
        """Fetch indicators from a feed source.

        Returns a list of dicts: {'ip': str, 'cidr': Optional[str]}. For
        netblocks the network address is stored as 'ip' and the full CIDR
        (e.g. '1.2.0.0/16') is preserved in 'cidr' so the scorer can perform
        accurate membership checks instead of guessing the prefix length.

        HTTP feeds are fetched conditionally; when the server answers 304 the
        NOT_MODIFIED sentinel is returned instead of a list.

        Feeds with a custom scraper (feed.scraper) use registered scraper logic
        instead of a plain HTTP GET.
        """
        logger.info(f"Fetching feed: {feed.name}")

        self._pending_validators = None
        try:
            if feed.scraper:
                scraper_fn = self._SCRAPERS.get(feed.scraper)
                if not scraper_fn:
                    raise RuntimeError(
                        f"Scraper '{feed.scraper}' not registered for feed '{feed.name}'"
                    )
                content = scraper_fn(self, feed)
                if content is NOT_MODIFIED:
                    return NOT_MODIFIED
            elif feed.local_file:
                content = self._read_local_file(feed.url)
            else:
                content = self._fetch_url(feed)
                if content is NOT_MODIFIED:
                    return NOT_MODIFIED
        except Exception as e:
            logger.error(f"Failed to fetch {feed.name}: {e}")
            raise

        parsed = self._parse_feed_content(content, kind=feed.indicator_kind)
        # A scraper feed that yields zero indicators means the scrape returned
        # something other than the block list (e.g. an HTTP 200 error/terms
        # page, a Cloudflare interstitial). Treat that as a failure rather than
        # a healthy empty feed — otherwise the run is marked 'success' with 0
        # indicators and the retention sweep silently drains the feed's stored
        # IPs (their last_seen never gets refreshed).
        if feed.scraper and not parsed:
            raise RuntimeError(
                f"Scraper '{feed.scraper}' for feed '{feed.name}' returned no "
                f"indicators ({len(content)} bytes) — treating as a failed fetch"
            )
        return parsed

    def _fetch_url(self, feed: FeedSource) -> Union[str, _NotModified]:
        """Fetch raw feed content from a URL, applying auth if required.

        Sends the validators from the last full download so an unchanged feed
        can answer 304 (returned as NOT_MODIFIED) instead of shipping the full
        list again. Transient failures are retried by _get_with_retries."""
        headers = {'User-Agent': 'ThreatFeedMe/1.0'}

        # Inject an API key from the environment when the feed requires auth.
        # Keys are never hardcoded; the env var and header name come from config.
        # auth_env may be a comma-separated list (multi-credential APIs like
        # HoneyDB); those feeds must use a scraper that builds its own headers
        # — the generic path can only map ONE var onto auth_header, so here it
        # just verifies the credentials exist and names any that are missing.
        if feed.requires_auth:
            env_vars = [v.strip() for v in (feed.auth_env or '').split(',') if v.strip()]
            missing = [v for v in env_vars if not os.environ.get(v)]
            if not env_vars or missing:
                raise RuntimeError(
                    f"Feed '{feed.name}' requires auth but env var(s) "
                    f"'{', '.join(missing) or feed.auth_env}' not set"
                )
            if len(env_vars) == 1:
                headers[feed.auth_header] = os.environ[env_vars[0]]

        etag, last_modified = self.db.get_feed_http_cache(feed.name)
        if etag:
            headers['If-None-Match'] = etag
        if last_modified:
            headers['If-Modified-Since'] = last_modified

        response = self._get_with_retries(feed.url, headers)
        if response.status_code == 304:
            return NOT_MODIFIED
        response.raise_for_status()

        # Stream the response body with a running byte counter to prevent
        # memory exhaustion from a multi-GB feed.
        total = 0
        chunks = []
        for chunk in response.iter_content(chunk_size=65536, decode_unicode=False):
            total += len(chunk)
            if total > _MAX_FETCH_BYTES:
                response.close()
                raise RuntimeError(
                    f"Feed '{feed.name}' response exceeded {_MAX_FETCH_BYTES // (1024*1024)} MB "
                    f"({total // (1024*1024)} MB received) — download aborted"
                )
            chunks.append(chunk)
        content = b''.join(chunks).decode(response.encoding or 'utf-8', errors='replace')

        # Stash this download's validators; ingest_feed persists them only
        # after the whole ingest succeeds. A 200 without validators stashes
        # (None, None) so any stored ones get cleared: sending stale
        # validators could yield a 304 for content we never ingested.
        self._pending_validators = (
            response.headers.get('ETag'),
            response.headers.get('Last-Modified'),
        )
        return content

    def _get_with_retries(self, url: str, headers: Dict[str, str]) -> requests.Response:
        """GET with up to _MAX_ATTEMPTS attempts on transient failures.

        5xx responses, timeouts, connection errors, and 429 are retried;
        other client errors (4xx) fail immediately since repeating them
        cannot succeed and just hammers the feed operator. 429 is the one
        client error that is explicitly "try again later" — GitHub raw
        rate-limits per source IP, and a refresh burst across several
        raw.githubusercontent-hosted feeds trips it (live-observed on prod:
        hagezi 429'd hourly while the same URL fetched fine elsewhere). Its
        Retry-After header is honored, capped so a hostile server can't
        pin the refresh thread. The final attempt's failure propagates
        unchanged so callers' error handling stays the same."""
        for attempt in range(1, _MAX_ATTEMPTS + 1):
            retry_after = None
            try:
                response = self._get_following_redirects(url, headers)
            except (requests.exceptions.Timeout, requests.exceptions.ConnectionError):
                if attempt == _MAX_ATTEMPTS:
                    raise
            else:
                if response.status_code == 429:
                    if attempt == _MAX_ATTEMPTS:
                        response.raise_for_status()
                    try:
                        retry_after = min(int(response.headers.get('Retry-After', '')),
                                          _RETRY_AFTER_CAP)
                    except (ValueError, TypeError):
                        retry_after = None
                    response.close()
                elif response.status_code < 500:
                    return response
                elif attempt == _MAX_ATTEMPTS:
                    response.raise_for_status()
                else:
                    # Release the discarded 5xx response's pooled connection
                    # before retrying.
                    response.close()

            delay = retry_after if retry_after is not None else \
                _BACKOFF_SECONDS[min(attempt, len(_BACKOFF_SECONDS)) - 1]
            logger.warning(
                f"Transient failure fetching {url} "
                f"(attempt {attempt}/{_MAX_ATTEMPTS}); retrying in {delay}s"
            )
            _sleep(delay)

        # Defensive: every path above returns or raises on the final attempt.
        raise RuntimeError(f"retry loop exited without a response for {url}")

    def _get_following_redirects(self, url: str, headers: Dict[str, str]) -> requests.Response:
        """Single GET, following redirects manually so every hop passes the
        SSRF guard (requests' automatic redirects would only let us check the
        first URL)."""
        for _ in range(_MAX_REDIRECTS + 1):
            if not self.allow_private_urls:
                _require_public_url(url)
            response = requests.get(url, headers=headers, timeout=30,
                                    stream=True, allow_redirects=False)
            if response.status_code in _REDIRECT_STATUSES:
                location = response.headers.get('Location')
                response.close()
                if not location:
                    raise RuntimeError(f"redirect without a Location header fetching {url}")
                url = urljoin(url, location)
                continue
            return response
        raise RuntimeError(f"too many redirects fetching {url}")

    def _read_local_file(self, path: str) -> str:
        """Read raw content from a local file. Explicit UTF-8 (mirroring the
        HTTP path's decode) — the locale default on Windows is cp1252, which
        reads a UTF-8 domain list as mojibake that then IDNA-encodes into a
        WRONG punycode domain."""
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            return f.read()

    def _parse_feed_content(self, content: str, kind: str = "ip") -> List[Dict]:
        """Instance shim around the module-level parser, dispatching by kind.

        Domain feeds go through parse_domain_feed_content (hosts-file/domain/
        URL extraction); IP feeds (the default) keep the historical path.
        The feed declares its kind; the caller passes it through.
        """
        if kind == "domain":
            return parse_domain_feed_content(content)
        return parse_feed_content(content)

    def ingest_feed(self, feed: FeedSource) -> int:
        """Fetch and ingest all indicators from a feed"""
        try:
            entries = self.fetch_feed(feed)

            if entries is NOT_MODIFIED:
                # Upstream content is unchanged, so re-parsing is skipped --
                # but last_seen must still advance: run_refresh purges by
                # last_seen right after fetching, so untouched indicators
                # would age out of retention even though the feed still
                # serves them.
                touched = self.db.touch_feed_indicators(feed.name)
                if touched:
                    logger.info(
                        f"{feed.name}: not modified ({touched} indicators kept current)"
                    )
                    # Report the live indicator count; 'unchanged' is not
                    # 'zero', and a preceding error run may have recorded 0.
                    self.db.update_feed_stats(
                        feed_name=feed.name,
                        total_indicators=touched,
                        status='success',
                    )
                    return touched
                # 304 but nothing live: retention already purged everything
                # this feed contributed (e.g. it sat disabled or erroring past
                # max_age), and a 304 can never restore it. Drop the stored
                # validators and re-download once, unconditionally.
                logger.info(
                    f"{feed.name}: not modified but no live indicators; re-fetching in full"
                )
                self.db.set_feed_http_cache(feed.name, None, None)
                entries = self.fetch_feed(feed)
                if entries is NOT_MODIFIED:
                    # A compliant server cannot 304 an unconditional request;
                    # treat it as an empty feed rather than looping.
                    entries = []

            logger.info(f"Fetched {len(entries)} indicators from {feed.name}")

            now = datetime.now(timezone.utc).isoformat()
            skipped = 0
            # Filter in Python, write in one bulk call: per-row add_indicator()
            # commits per IP, which wedged the refresh on 90k-row feeds.
            rows = []
            for entry in entries:
                value = entry.get('cidr') or entry['ip']
                # Drop internal/reserved/known-good addresses before storing.
                if self.safety and self.safety.excluded_reason(value):
                    skipped += 1
                    continue

                metadata = {
                    'feed_type': feed.feed_type.value,
                    'feed_weight': feed.weight,
                    'fetched_at': now,
                }
                if entry.get('cidr'):
                    metadata['cidr'] = entry['cidr']

                rows.append((entry['ip'], metadata))

            count = self.db.add_indicators_bulk(rows, source=feed.name, kind=feed.indicator_kind)
            # Full parse succeeded: this IS the source's current membership.
            # (The not-modified path returns earlier and records nothing —
            # unchanged content means no transitions by definition.)
            self.ingested_values[feed.name] = {r[0] for r in rows}

            if skipped:
                logger.info(f"{feed.name}: skipped {skipped} private/reserved/known-good entries")

            self.db.update_feed_stats(
                feed_name=feed.name,
                total_indicators=count,
                status='success',
            )

            # Persist the response validators only now, after the ingest fully
            # succeeded: caching them any earlier would let the next refresh
            # 304 against content that was never stored.
            if self._pending_validators is not None:
                self.db.set_feed_http_cache(feed.name, *self._pending_validators)

            return count

        except Exception as e:
            self.db.update_feed_stats(
                feed_name=feed.name,
                total_indicators=0,
                status='error',
                error_message=str(e),
            )
            raise


# =============================================================================
# Talos Snort.org IP block list scraper
# =============================================================================
#
# Snort.org gates its IP block list behind a one-click terms-acceptance form
# protected by a Rails CSRF authenticity_token. The scraper:
#   1. GETs the terms page with a browser User-Agent (Cloudflare 403s the
#      default UA).
#   2. Scrapes the CSRF token from the HTML.
#   3. POSTs to accept-terms; the response body IS the raw IP list.
#   4. Returns the raw text (NOT_MODIFIED not supported — Snort.org doesn't
#      provide ETags/Last-Modified for this endpoint).
#
# The scraper is registered under "talos_snort" and wired to any feed whose
# config sets `scraper: talos_snort`.

_TALOS_TERMS_URL = "https://snort.org/downloads/ip-block-list/terms"
_TALOS_ACCEPT_URL = "https://snort.org/downloads/ip-block-list/accept-terms"
_TALOS_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/126.0.0.0 Safari/537.36"
)
_TALOS_TIMEOUT = 30

# Regex for the CSRF authenticity_token. The markup has an id= attribute
# between name= and value=, so a naive name="authenticity_token" value="..."
# fails. The anchored regex first tries within the accept-terms form block;
# a fallback scans the entire page.
_TALOS_TOKEN_RE = re.compile(
    r'accept-terms"[\s\S]*?name="authenticity_token"[^>]*?value="([^"]+)"',
    re.DOTALL,
)
_TALOS_TOKEN_RE_FALLBACK = re.compile(
    r'name="authenticity_token"[^>]*?value="([^"]+)"',
)


def _scrape_talos(self: FeedIngestor, feed: FeedSource) -> str:
    """Scrape the Snort.org IP block list via the terms-acceptance form.

    Returns the raw IP list text. Raises on failure (no fallback to stale
    data — the caller's exception handler logs and marks the feed errored).
    """
    logger.info(f"Talos scraper: fetching terms page for {feed.name}")

    # Step 1: GET the terms page with a browser UA to pass Cloudflare.
    session = requests.Session()
    session.headers["User-Agent"] = _TALOS_UA
    try:
        resp = session.get(_TALOS_TERMS_URL, timeout=_TALOS_TIMEOUT)
        resp.raise_for_status()
    except Exception as e:
        logger.error(f"Talos scraper: terms page GET failed: {e}")
        raise

    # Step 2: extract the CSRF authenticity_token.
    token = None
    m = _TALOS_TOKEN_RE.search(resp.text)
    if m:
        token = m.group(1)
    else:
        m = _TALOS_TOKEN_RE_FALLBACK.search(resp.text)
        if m:
            token = m.group(1)
    if not token:
        raise RuntimeError(
            f"Talos scraper: could not find authenticity_token in terms page "
            f"(content length={len(resp.text)}, "
            f"'accept-terms' found={'accept-terms' in resp.text})"
        )

    logger.info(
        f"Talos scraper: extracted authenticity_token "
        f"(length={len(token)}), posting accept-terms"
    )

    # Step 3: POST accept-terms with the token; the response body IS the list.
    try:
        post_resp = session.post(
            _TALOS_ACCEPT_URL,
            data={"authenticity_token": token, "commit": "Accept"},
            timeout=_TALOS_TIMEOUT,
        )
        post_resp.raise_for_status()
    except Exception as e:
        logger.error(f"Talos scraper: accept-terms POST failed: {e}")
        raise

    body = post_resp.text.strip()
    logger.info(
        f"Talos scraper: got {len(body)} bytes from accept-terms "
        f"(content-type: {post_resp.headers.get('content-type', 'unknown')})"
    )
    return body


# Register the scraper so fetch_feed can dispatch to it.
FeedIngestor.register_scraper("talos_snort")(_scrape_talos)


# =============================================================================
# DShield (SANS ISC) recommended block list
# =============================================================================
#
# block.txt rows are tab-separated "start<TAB>end<TAB>mask<TAB>..." with the
# prefix length as a bare number (no slash), e.g.:
#   203.0.113.0	203.0.113.255	24	342	SOMENET	US	abuse@example.com
# The generic parser would ingest the start AND end addresses as two bare
# IPs and lose the netblock, so this scraper rewrites each row to CIDR
# ("203.0.113.0/24") before parsing. Fetching still goes through _fetch_url,
# so conditional GET, retries, size caps, and the SSRF guard all apply.

def _scrape_dshield_block(self: FeedIngestor, feed: FeedSource):
    content = self._fetch_url(feed)
    if content is NOT_MODIFIED:
        return NOT_MODIFIED
    lines = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        parts = line.split('\t')
        if len(parts) >= 3 and parts[2].strip().isdigit():
            lines.append(f"{parts[0].strip()}/{parts[2].strip()}")
    return "\n".join(lines)


FeedIngestor.register_scraper("dshield_block")(_scrape_dshield_block)


# -----------------------------------------------------------------------------
# AlienVault OTX subscribed-pulses scraper (JSON feed)
#
# The OTX /indicators/export endpoint is broken upstream (504/hangs), so this
# feed pulls IPv4 indicators from the working /pulses/subscribed endpoint,
# which returns JSON:
#   {"results": [{..., "indicators": [{"indicator": "...", "type": "IPv4"}, ...]}],
#    "count": N, "next": "<url or null>"}
# Each pulse's `indicators` is an array of {indicator, type}; we keep only
# type=="IPv4" and flatten them back into the same one-IP-per-line text the
# generic parser expects, so the rest of the pipeline needs no changes.
_OTX_MAX_PAGES = 20  # guard against a runaway `next` chain


def _scrape_otx_pulses(self: FeedIngestor, feed: FeedSource):
    content = self._fetch_url(feed)
    if content is NOT_MODIFIED:
        return NOT_MODIFIED
    try:
        page = json.loads(content)
    except ValueError:
        raise RuntimeError(f"{feed.name}: OTX pulses JSON parse failed")

    lines = []
    for _ in range(_OTX_MAX_PAGES):
        for pulse in page.get('results') or []:
            for indicator in pulse.get('indicators') or []:
                if indicator.get('type') == 'IPv4':
                    value = str(indicator.get('indicator') or '').strip()
                    if value:
                        lines.append(value)
        next_url = page.get('next')
        if not next_url:
            break

        # Cap the pages we ingest: never pull a page we won't process on a
        # later iteration (avoids a wasted rate-limited call).
        if _ == _OTX_MAX_PAGES - 1:
            break

        # Fetch the next page with the same auth the feed requires.
        headers = {}
        if feed.requires_auth:
            api_key = os.environ.get(feed.auth_env) if feed.auth_env else None
            if not api_key:
                raise RuntimeError(
                    f"{feed.name}: requires auth but env var "
                    f"'{feed.auth_env}' is not set"
                )
            headers[feed.auth_header] = api_key
        response = self._get_with_retries(next_url, headers)
        response.raise_for_status()
        try:
            page = json.loads(response.text)
        except ValueError:
            raise RuntimeError(f"{feed.name}: OTX pulses JSON parse failed")

    return "\n".join(lines)


FeedIngestor.register_scraper("otx_pulses")(_scrape_otx_pulses)


# HoneyDB bad-hosts scraper (JSON feed)
#
# HoneyDB authenticates with TWO headers (X-HoneyDb-ApiId + X-HoneyDb-ApiKey),
# which the generic single-var auth path can't express, so this scraper builds
# its own headers from two env vars. Serves both shipped feeds: /bad-hosts
# (community, rolling 24h window — retention accumulates the union across
# fetches) and /bad-hosts/mydata (only sensors this account operates).
# Response: JSON array of {"remote_host": "<ip>", ...}; unknown shapes are
# handled leniently so an upstream field rename degrades, not breaks.
_HONEYDB_ENV_ID = "HONEYDB_API_ID"
_HONEYDB_ENV_KEY = "HONEYDB_API_KEY"


def _scrape_honeydb(self: FeedIngestor, feed: FeedSource):
    api_id = os.environ.get(_HONEYDB_ENV_ID)
    api_key = os.environ.get(_HONEYDB_ENV_KEY)
    missing = [name for name, val in ((_HONEYDB_ENV_ID, api_id),
                                      (_HONEYDB_ENV_KEY, api_key)) if not val]
    if missing:
        raise RuntimeError(
            f"{feed.name}: requires HoneyDB credentials; missing env var(s): "
            f"{', '.join(missing)} (set both via the dashboard's Set key button)"
        )
    headers = {"X-HoneyDb-ApiId": api_id, "X-HoneyDb-ApiKey": api_key}
    response = self._get_with_retries(feed.url, headers)
    response.raise_for_status()
    try:
        data = json.loads(response.text)
    except ValueError:
        raise RuntimeError(f"{feed.name}: HoneyDB JSON parse failed")
    if not isinstance(data, list):
        raise RuntimeError(f"{feed.name}: unexpected HoneyDB response shape")

    # A valid-but-empty window is normal for /mydata (your sensors saw no
    # attacks in the last 24h). NOT_MODIFIED keeps previously ingested
    # indicators alive instead of tripping the zero-indicator scraper guard.
    if not data:
        logger.info(f"{feed.name}: HoneyDB window empty; keeping prior indicators")
        return NOT_MODIFIED

    lines = []
    for entry in data:
        if isinstance(entry, dict):
            value = entry.get('remote_host') or entry.get('ip') or entry.get('host')
        else:
            value = entry
        value = str(value or '').strip()
        if value:
            lines.append(value)
    return "\n".join(lines)


FeedIngestor.register_scraper("honeydb")(_scrape_honeydb)


# =============================================================================
# CSV-column scrapers (drb-ra C2 domains, PhishTank online-valid)
# =============================================================================
#
# The domain parser wants domain/URL/hosts-file lines; a CSV row like
# "evil.example,Possible Cobalt Strike C2 Domain" fails domain validation on
# the comma (deliberately — never loosen the validator for a feed's framing).
# These scrapers reduce a CSV to one column of plain values and hand the
# result to the normal parser. Fetching goes through _fetch_url, so
# conditional GET, retries, size caps, and the SSRF guard all apply.

def _scrape_csv_column(self: FeedIngestor, feed: FeedSource, column: int):
    content = self._fetch_url(feed)
    if content is NOT_MODIFIED:
        return NOT_MODIFIED
    out = []
    # csv module (not str.split): PhishTank quotes fields, and a quoted URL
    # may legally contain commas.
    for row in csv.reader(io.StringIO(content)):
        if not row or row[0].lstrip().startswith('#'):
            continue  # drb-ra's "#domain,ioc" header
        if len(row) <= column:
            continue
        value = row[column].strip()
        if not value or value.lower() in ('domain', 'url'):
            continue  # PhishTank's unquoted "phish_id,url,..." header row
        out.append(value)
    return "\n".join(out)


def _scrape_drb_ra_domains(self: FeedIngestor, feed: FeedSource):
    """drb-ra C2IntelFeeds: '#domain,ioc' — the domain is column 0."""
    return _scrape_csv_column(self, feed, 0)


def _scrape_phishtank_urls(self: FeedIngestor, feed: FeedSource):
    """PhishTank online-valid.csv: 'phish_id,url,...' — the URL is column 1;
    the URL parser keeps the full host (see parse_domain_feed_content)."""
    return _scrape_csv_column(self, feed, 1)


FeedIngestor.register_scraper("drb_ra_domains")(_scrape_drb_ra_domains)
FeedIngestor.register_scraper("phishtank_urls")(_scrape_phishtank_urls)
