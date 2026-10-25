"""Remote feed catalog (issue #9): the live roster lives in the GitHub repo.

Baseline feeds keep shipping inside the image (a fresh air-gapped install
gets the baked ``config.yaml feeds:`` exactly as before). ON TOP of that,
the app periodically fetches ``feed_catalog.yaml`` from this repo and runs
the same add/update/tombstone sync over its ``feeds:`` list that
``sync_default_feeds`` runs over the baked config — plumbing-follows-the-ship
for sync-provenance rows, preferences-are-sacred otherwise, operator
deletions never resurrected. Roster maintenance becomes a commit to a file:
no image rebuild, and deprecations actually reach existing installs.

Safety rails (non-negotiable, all exercised in tests/test_catalog.py):

* **Never destructive.** Any fetch/parse failure — including a 200 with an
  empty ``feeds:`` list — keeps the last state: one warning log line, the
  last-good ``catalog_version`` retained, a ``catalog_last_error`` stamp.
* **Monotonic version.** A catalog whose ``catalog_version`` is not strictly
  greater than the stored one changes nothing, so replaying an old commit
  (or a URL flipped to a stale mirror) can never downgrade the roster.
* **Supply chain.** Default source is this repo's raw.githubusercontent.com
  URL over TLS; ``catalog.url`` is overridable for mirrors, but only
  public HTTPS is fetched (SSRF guard reused from the feed fetch path) and
  redirects are followed only within the githubusercontent hosts. Changing
  ``catalog.url`` to a third party means trusting them to define what the
  firewall blocks.
* **Auto-add policy.** ``catalog.auto_add`` (settings-page toggle, default
  ON). OFF: new entries land *pending* (disabled, unfetched, unscored) for
  one-click Add, and Dismiss tombstones them via ``deleted_feeds``. Entries
  that need a key ship disabled regardless of the toggle — auto-add never
  enables a feed that cannot work without a key.

The fetch reuses the ingestor's discipline (imported, not copied):
``_MAX_FETCH_BYTES`` capped reads, no env proxies, and the SSRF guard.
"""
import logging
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlsplit

import requests
import yaml

from threatfeedme.feed_ingestor import (_FETCH_TIMEOUT, _NO_PROXIES,
                                        _read_capped, _require_public_url)

logger = logging.getLogger(__name__)

# The default trust anchor: this repo's raw content, main branch, pinned
# path. The file is added by the maintainer as roster entries are ratified;
# until then every install simply logs one warning line and keeps its
# baked baseline roster (that is the offline path, and it is a tested one).
DEFAULT_CATALOG_URL = ("https://raw.githubusercontent.com/alexlinos/"
                       "threat-feed-me/main/feed_catalog.yaml")

# settings-table keys (persisted like every other runtime setting).
CATALOG_VERSION_KEY = "catalog_version"
CATALOG_FETCHED_KEY = "catalog_last_fetch_at"
CATALOG_ERROR_KEY = "catalog_last_error"
CATALOG_AUTO_ADD_KEY = "catalog_auto_add"

# One redirect chain, but only ever inside the CDN that serves GitHub raw
# content — a catalog fetch must not be walked onto an arbitrary host.
_MAX_CATALOG_REDIRECTS = 5
_ALLOWED_REDIRECT_SUFFIX = "githubusercontent.com"

# A roster is human-sized; the ingestor's 50 MB feed cap is the hard ceiling
# (imported above), this is the sane one that rejects a wrong URL (say, an
# image or a data dump) long before the memory ceiling matters.
_SOFT_MAX_CATALOG_BYTES = 1024 * 1024


class CatalogError(Exception):
    """Any catalog fetch/parse/validation failure. Never fatal upstream:
    the sync keeps the last state on one warning line."""


def _as_mapping(section: str, value) -> dict:
    """A config mapping, or {} for absent/null; any other shape is a
    malformed block logged once and defaulted (same discipline as the
    scheduler's config guard: a bad block must never break a loop)."""
    if value is None:
        return {}
    if isinstance(value, dict):
        return value
    logger.warning("[catalog] 'catalog' config is not a mapping (%s); using defaults",
                   type(value).__name__)
    return {}


def catalog_config(config: Dict) -> dict:
    """The catalog block with defaults applied: enabled ON, repo-pinned URL,
    auto_add ON (the DB setting, once saved, wins over the config value)."""
    cfg = dict(_as_mapping('catalog', (config or {}).get('catalog')))
    cfg.setdefault('enabled', True)
    cfg.setdefault('url', DEFAULT_CATALOG_URL)
    cfg.setdefault('auto_add', True)
    cfg.setdefault('interval_hours', 24)
    return cfg


def resolve_auto_add(db, config: Dict) -> bool:
    """The effective auto-add policy: the persisted settings toggle wins
    (surfaced on the dashboard settings panel, persists across restarts);
    before it has ever been saved, the config.yaml value is the default."""
    raw = None
    try:
        raw = db.get_setting(CATALOG_AUTO_ADD_KEY)
    except Exception:
        raw = None
    if raw is None:
        return bool(catalog_config(config).get('auto_add', True))
    return str(raw).strip().lower() in ("1", "true", "yes", "on")


def _host_of(url: str) -> str:
    return (urlsplit(url).hostname or "").lower()


def _is_allowed_redirect(current: str, next_host: str) -> bool:
    """Follow a redirect only while it stays on GitHub's raw-content CDN —
    or, for a self-hosted mirror URL, on the same host it started on. This
    is the 'no redirect-following onto non-githubusercontent hosts' rule."""
    if not next_host:
        return False
    if next_host == _host_of(current):
        return True
    return next_host.endswith("." + _ALLOWED_REDIRECT_SUFFIX) or \
        next_host == _ALLOWED_REDIRECT_SUFFIX


def http_get_text(url: str) -> str:
    """Fetch catalog text. Public HTTPS only (the feed path's SSRF guard),
    no env proxies, capped streamed read, manual same-CDN redirects.
    Module-level so tests can replace the seam instead of the network."""
    if not url.lower().startswith("https://"):
        raise CatalogError(f"catalog URL must be https:// (got scheme from {url!r})")
    resp = None
    current = url
    try:
        for _hop in range(_MAX_CATALOG_REDIRECTS + 1):
            _require_public_url(current)   # SSRF guard, reused from the feed fetch
            resp = requests.get(current, stream=True, timeout=_FETCH_TIMEOUT,
                                allow_redirects=False, proxies=_NO_PROXIES)
            if resp.status_code in (301, 302, 303, 307, 308):
                loc = resp.headers.get("location", "")
                next_url = urljoin(current, loc)
                resp.close()
                if not next_url.lower().startswith("https://"):
                    raise CatalogError("catalog redirect left TLS; keeping last state")
                if not _is_allowed_redirect(current, _host_of(next_url)):
                    raise CatalogError(
                        f"catalog redirect to non-githubusercontent host "
                        f"'{_host_of(next_url)}' refused")
                current = next_url
                continue
            if resp.status_code != 200:
                raise CatalogError(f"catalog fetch got HTTP {resp.status_code}")
            text = _read_capped(resp, "feed_catalog")
            if len(text.encode("utf-8", errors="replace")) > _SOFT_MAX_CATALOG_BYTES:
                raise CatalogError("catalog document is implausibly large (>1 MB)")
            return text
        raise CatalogError("catalog exceeded the redirect limit")
    except CatalogError:
        raise
    except requests.RequestException as e:
        raise CatalogError(f"catalog fetch failed: {type(e).__name__}") from None
    finally:
        if resp is not None:
            try:
                resp.close()
            except Exception:
                pass


def parse_catalog(text: str) -> Tuple[int, List[Dict]]:
    """Parse and validate the document; raise CatalogError on anything a
    hostile or half-written file could smuggle past us.

    The roster must be complete-by-shape: a dict, an integer
    ``catalog_version``, and a NON-EMPTY list of dict entries with at least
    name+url each. A 200 with empty feeds is indistinguishable from a wipe,
    so it is rejected here, before any state is touched."""
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as e:
        raise CatalogError(f"catalog YAML is malformed: {type(e).__name__}") from None
    if not isinstance(doc, dict):
        raise CatalogError(f"catalog must be a YAML mapping (got {type(doc).__name__})")
    version = doc.get("catalog_version")
    # bool is an int subclass; True is not a version number.
    if isinstance(version, bool) or not isinstance(version, int) or version < 0:
        raise CatalogError("catalog_version must be a non-negative integer")
    feeds = doc.get("feeds")
    if not isinstance(feeds, list) or not feeds:
        raise CatalogError("catalog 'feeds' must be a non-empty list "
                           "(an empty roster is rejected, never applied)")
    valid = [f for f in feeds if isinstance(f, dict) and f.get("name") and f.get("url")]
    if not valid:
        raise CatalogError("catalog contains no well-formed feed entries "
                           "(each needs at least name and url)")
    return version, valid


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def sync_catalog(db, config: Dict, fetch: Optional[Callable[[str], str]] = None,
                 *, force: bool = False) -> Dict:
    """Fetch, gate, and apply the remote catalog. NEVER raises and NEVER
    destructive: every failure path is one warning log, a
    ``catalog_last_error`` stamp, and the roster exactly as it was.

    Returns a result dict for the scheduler/API log:
      status: disabled | skipped | error | stale | synced
    """
    cfg = catalog_config(config)
    result: Dict = {"status": "skipped", "reason": ""}
    if not cfg.get("enabled", True):
        result.update(status="disabled", reason="catalog.enabled is false")
        return result
    url = str(cfg.get("url") or DEFAULT_CATALOG_URL)
    fetch = fetch or http_get_text

    try:
        text = fetch(url)
        version, feeds = parse_catalog(text)
    except Exception as e:
        # The whole never-destructive rail in one line: keep last state.
        db.set_setting(CATALOG_ERROR_KEY, f"{_utcnow_iso()}: {e}")
        logger.warning("[catalog] keeping last-known roster (%s), version %s: %s",
                       url, db.get_setting(CATALOG_VERSION_KEY) or "unknown", e)
        result.update(status="error", reason=str(e))
        return result

    stored = db.get_setting(CATALOG_VERSION_KEY)
    if stored is not None:
        try:
            stored_int = int(stored)
        except (ValueError, TypeError):
            # A corrupt stamp is not a licence to apply anything: refuse
            # until an operator clears it (there is no legitimate way this
            # key ever holds a non-int — only this module writes it).
            db.set_setting(CATALOG_ERROR_KEY,
                           f"{_utcnow_iso()}: stored catalog_version is unreadable ({stored!r})")
            logger.warning("[catalog] stored catalog_version %r is unreadable; "
                           "refusing to sync (clear settings key '%s' to recover)",
                           stored, CATALOG_VERSION_KEY)
            result.update(status="error", reason="unreadable stored catalog_version")
            return result
        # Strictly increasing, always: replay of an old commit or a URL
        # flipped to a stale mirror must change nothing. `force` skips the
        # gate only for a same-version re-sync of the same document (an
        # operator pressing "check now" must not re-apply plumbing on every
        # poll); a LOWER version is still refused outright.
        if version < stored_int:
            logger.warning("[catalog] version %s is older than applied version %s; "
                           "keeping last state", version, stored_int)
            result.update(status="stale", reason=f"{version} < {stored_int}",
                          catalog_version=version)
            return result
        if version == stored_int and not force:
            result.update(status="skipped", reason="version unchanged",
                          catalog_version=version)
            return result

    auto_add = resolve_auto_add(db, config)
    actions = db.sync_catalog_feeds(feeds, auto_add=auto_add)

    db.set_setting(CATALOG_VERSION_KEY, str(version))
    db.set_setting(CATALOG_FETCHED_KEY, _utcnow_iso())
    db.delete_setting(CATALOG_ERROR_KEY)
    logger.info("[catalog] applied version %s (auto_add=%s): +%s added, +%s pending, "
                "%s updated, %s stay deleted", version, auto_add,
                len(actions["added"]), len(actions["pending"]),
                len(actions["updated"]), len(actions["skipped_deleted"]))
    result.update(status="synced", catalog_version=version, auto_add=auto_add, **actions)
    return result
