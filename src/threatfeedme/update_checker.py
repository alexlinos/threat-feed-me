"""Update checker: notification-only "a newer release exists" (issue #10).

The app runs from a floating image and deployments drift silently; the
operator should see "you are behind, the release page is here" without
visiting GitHub. Notification ONLY, never auto-update: pulling and
restarting on a remote verdict is a supply-chain and availability risk (a
bad image bricks the blocklist pipeline unsupervised). A human runs the
pull.

Every failure mode is silent BY DESIGN (timeout, DNS, refused connection,
403 rate-limit, 404, 5xx, unparseable JSON, garbage tag): the result is
indistinguishable from "no update" — no exception escapes, no error-level
log, update_available stays false. An update checker that nags on airplane
mode is worse than none.

Why this fetch is not behind the feed SSRF guard: the URL is the local
operator's config.yaml (same trust class as ``database.path`` or
``integrations.unifi.host``), never a dashboard-supplied value, and the
default is a fixed constant. The response body is read for exactly one
field — ``tag_name`` — which is kept only if it survives the strict
three-segment numeric guard the publish workflow enforces; nothing else
is parsed or stored, and the release link is built from constant bases
plus the validated tag, never from response data.

Rate limits: the unauthenticated GitHub Releases API answers 60 req/h per
source IP; the 24 h cadence (and the persisted ``update_last_check`` stamp,
written on every ATTEMPT — a failed check earns the same rest as a
successful one, so a down network is retried daily, not every scheduler
tick) keeps one install at ~1 req/day.
"""
import logging
import re
from datetime import datetime, timedelta, timezone

import requests

logger = logging.getLogger(__name__)

RELEASES_URL = "https://api.github.com/repos/alexlinos/threat-feed-me/releases/latest"
# Constant bases only: the link shown in the footer is these plus the
# regex-validated tag, never a URL field from the API response.
RELEASE_HTML_BASE = "https://github.com/alexlinos/threat-feed-me"
RELEASE_PAGE_BASE = RELEASE_HTML_BASE + "/releases/tag/"

# Persisted through the existing settings mechanism (db.get/set_setting),
# same as last_backup_at: survives restarts, paces the scheduler.
LAST_CHECK_KEY = "update_last_check"
LATEST_VERSION_KEY = "update_latest_version"
AVAILABLE_KEY = "update_available"

CHECK_INTERVAL_HOURS = 24.0
FETCH_TIMEOUT_S = 10.0
_USER_AGENT = "ThreatFeedMe/update-checker"

# Same guard as the publish workflow (docker-publish.yml): whole string,
# exactly three numeric segments. Tags are stripped of a leading 'v'
# before matching — GitHub releases conventionally carry one.
_TAG_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")


def _http_get(url: str, timeout: float):
    """Network seam (2.5.7 lesson: anything that opens a socket needs an
    injectable seam so no unit test can ever reach the network). Tests
    patch this function; production is the only caller of requests.get."""
    return requests.get(url, timeout=timeout, allow_redirects=True,
                        headers={"User-Agent": _USER_AGENT,
                                 "Accept": "application/vnd.github+json"})


def updates_config(config) -> dict:
    """The ``updates:`` config block, or {} for absent/null/malformed —
    a bad shape never raises (same discipline as scheduler._config_mapping:
    a malformed block must not break anything else)."""
    cfg = (config or {}).get("updates") if isinstance(config, dict) else None
    return cfg if isinstance(cfg, dict) else {}


def updates_enabled(config) -> bool:
    """On by default (one unauthenticated GET/day leaks essentially nothing
    beyond the fact an install polled; air-gapped installs get a silent
    no-op). Opt out with ``updates.enabled: false``."""
    value = updates_config(config).get("enabled", True)
    if isinstance(value, str):
        return value.strip().lower() not in ("false", "0", "no", "off")
    return bool(value)


def _clean_tag(tag):
    """A tag normalised to N.N.N, or None. This is the garbage filter:
    'v1.2.3' -> '1.2.3'; 'release-7', '1.2', '1.2.3.4', '2.6.0-rc1', None,
    or any non-string -> None."""
    if not isinstance(tag, str):
        return None
    tag = tag.strip()
    if tag[:1] in ("v", "V"):
        tag = tag[1:]
    return tag if _TAG_RE.match(tag) else None


def _as_tuple(tag: str):
    return tuple(int(p) for p in tag.split("."))  # tag is pre-validated


def is_newer(candidate, current) -> bool:
    """Strict numeric-tuple compare after the shared guard. Anything the
    guard rejects (including a weird dev 'current') compares as NOT newer:
    silence is the safe answer."""
    c = _clean_tag(candidate)
    cur = _clean_tag(current)
    if c is None or cur is None:
        return False
    return _as_tuple(c) > _as_tuple(cur)


def _now_iso(now) -> str:
    return (now or datetime.now(timezone.utc)).isoformat()


def check_for_updates(db, config=None, now=None):
    """One release check: GET the configured releases endpoint, keep the
    tag only if it passes the guard, persist the state through settings,
    and log ONE INFO line when a newer version is first seen (nothing
    per-cycle). NEVER raises: every failure leaves update_available false
    and logs nothing at INFO or above. Returns the update_state dict on a
    successful check, None otherwise."""
    cfg = updates_config(config)
    url = cfg.get("url") or RELEASES_URL
    try:
        timeout = float(cfg.get("timeout_seconds", FETCH_TIMEOUT_S))
    except (TypeError, ValueError):
        timeout = FETCH_TIMEOUT_S
    ts = _now_iso(now)
    try:
        try:
            resp = _http_get(url, timeout)
        finally:
            # Stamped on every ATTEMPT, success or not (see the module
            # docstring): this is what paces the scheduler and keeps a down
            # network from being retried every tick.
            db.set_setting(LAST_CHECK_KEY, ts)
        if getattr(resp, "status_code", None) != 200:
            # 403 (rate limit — X-RateLimit-* only explains WHY, there is
            # nothing to tell the operator), 404, 5xx: silent.
            return None
        payload = resp.json()  # raises on garbage; caught below
        tag = _clean_tag(payload.get("tag_name") if isinstance(payload, dict) else None)
        if tag is None:
            return None  # missing or unparseable tag: silent, stays false
        was = db.get_setting(AVAILABLE_KEY)
        newer = is_newer(tag, _current_version())
        db.set_setting(LATEST_VERSION_KEY, tag)
        db.set_setting(AVAILABLE_KEY, "1" if newer else "0")
        if newer and was != "1":
            # The single INFO line: when a newer release is FIRST seen.
            logger.info("Update available: v%s (running v%s) — %s",
                        tag, _current_version(), RELEASE_PAGE_BASE + tag)
        return update_state(db, config)
    except Exception:
        # Timeout, DNS, refused connection, garbage JSON, even a Database
        # that raises: no exception escapes an update check, and no error
        # log — an unavailable network is not the operator's problem.
        return None


def run_due_check(db, config=None, now=None):
    """The scheduler's entry point: check only when enabled and the
    interval has elapsed since the last ATTEMPT. Zero outbound calls when
    disabled or not yet due."""
    if not updates_enabled(config):
        return None
    last = None
    try:
        last = db.get_setting(LAST_CHECK_KEY)
    except Exception:
        pass  # unreadable state -> check now (the check itself can't raise)
    if last:
        try:
            hours = float(updates_config(config).get("interval_hours", CHECK_INTERVAL_HOURS))
        except (TypeError, ValueError):
            hours = CHECK_INTERVAL_HOURS
        if hours <= 0:
            hours = CHECK_INTERVAL_HOURS
        try:
            dt = datetime.fromisoformat(str(last))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            if (now or datetime.now(timezone.utc)) - dt < timedelta(hours=hours):
                return None
        except (TypeError, ValueError):
            pass  # unparseable stamp -> check now
    return check_for_updates(db, config, now=now)


def _current_version() -> str:
    from threatfeedme import __version__
    return __version__


def update_state(db, config=None) -> dict:
    """Read-only view for the dashboard (footer badge) and the System
    panel. 'available' is re-derived from the stored tag against the
    RUNNING version, never trusted from settings: an upgrade that lands
    without a fresh check clears the badge by itself."""
    latest = None
    available = False
    checked_at = None
    try:
        latest = _clean_tag(db.get_setting(LATEST_VERSION_KEY))
        checked_at = db.get_setting(LAST_CHECK_KEY)
    except Exception:
        pass
    if latest is not None:
        available = is_newer(latest, _current_version())
    release_url = (RELEASE_PAGE_BASE + latest) if (available and latest) else None
    return {"available": available,
            "current": _current_version(),
            "latest": latest,
            "release_url": release_url,
            "checked_at": checked_at,
            "releases_url": RELEASE_HTML_BASE + "/releases"}
