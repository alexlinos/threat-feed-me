"""
CrowdSec integration, both directions (v2.5.0).

PUSH (publish): after each refresh the configured IP tier is written into the
operator's own CrowdSec Local API as ban decisions, so every CrowdSec bouncer
they already run (nginx, Traefik, HAProxy, Cloudflare, iptables/nftables, ...)
enforces threat-feed-me's lists with no per-device setup. Uses a MACHINE login
(`cscli machines add threatfeedme --password ...`), the same API
`cscli decisions import` uses: one alert per chunk carrying the decisions.

Replacement without an enforcement gap: every push is a GENERATION with its
own scenario name (threatfeedme/<tier>@<stamp>). The new generation is posted
completely, and only then is the previous one expired (DELETE /v1/decisions
?scenario=<previous>, which bouncers see as deletions on their next stream
pull). Live-verified against CrowdSec 1.8.1: origin and scenario survive the
round trip, delete-by-scenario is exact, 40k decisions post in ~1.5 s.

Decisions carry a duration (default 24h) and the push re-runs at least every
half-duration even when nothing changed, so a threat-feed-me that dies stops
blocking within a day instead of forever, and one that lives never lapses. A
generation orphaned by a crash expires the same way.

PULL (consume): the crowdsec_lapi scraper reads the same LAPI as a BOUNCER
(`cscli bouncers add threatfeedme`) and turns its decisions into feeds, split
by origin so each is its own witness: crowdsec_local (the operator's own
detections + manual bans), crowdsec_community (the community blocklist, CAPI)
and crowdsec_lists (subscribed blocklists). Decisions threat-feed-me pushed
itself are excluded server-side AND client-side: a pushed IP read back as a
vote would be threat-feed-me corroborating itself.

Security model (mirrors the UniFi gateway): the LAPI is a LAN host the
operator configures from the authenticated dashboard, so it is exempt from the
feed SSRF guard for exactly these calls, and the three credentials
(CROWDSEC_MACHINE_ID / CROWDSEC_MACHINE_PASSWORD / CROWDSEC_BOUNCER_KEY) are
bound to it: never sent anywhere else, no redirects followed, cleared when the
host changes, write-only through the API, never echoed or logged. No feed can
name them as its auth_env (credentials.KeyPolicy refuses unshipped names).

Failures here never break a refresh; the caller wraps and logs.
"""
import hashlib
import json
import logging
import os
import re
from datetime import datetime, timezone
from typing import Dict, List, Optional
from urllib.parse import urlsplit

import requests

from threatfeedme.exporter import firewall_value, is_included
from threatfeedme.models import ConfidenceTier, CUMULATIVE_TIERS

logger = logging.getLogger(__name__)

ENV_MACHINE_ID = "CROWDSEC_MACHINE_ID"
ENV_MACHINE_PASSWORD = "CROWDSEC_MACHINE_PASSWORD"
ENV_BOUNCER_KEY = "CROWDSEC_BOUNCER_KEY"
CREDENTIAL_VARS = (ENV_MACHINE_ID, ENV_MACHINE_PASSWORD, ENV_BOUNCER_KEY)

SETTINGS_KEY = "crowdsec_integration"
LAST_PUSH_KEY = "crowdsec_last_push"

# Everything threat-feed-me writes into CrowdSec carries this origin and a
# scenario under this prefix; the pull side filters on both.
ORIGIN = "threatfeedme"
SCENARIO_PREFIX = "threatfeedme/"

_VALID_TIERS = ("high", "medium", "low")
DEFAULT_TIER = "medium"          # the product's recommended tier
DEFAULT_DURATION_H = 24
_MIN_DURATION_H, _MAX_DURATION_H = 2, 24 * 7
DEFAULT_MAX_ENTRIES = 200_000    # bouncers handle this; a runaway tier doesn't
_CHUNK = 10_000                  # decisions per alert (one POST each)
_TIMEOUT = 60

# scheme://host[:port] only. The LAPI's paths are fixed; a pasted path would
# otherwise retarget authenticated calls.
_LAPI_RE = re.compile(r'^https?://[A-Za-z0-9.\-]+(:\d{1,5})?/?$|^https?://\[[0-9A-Fa-f:.]+\](:\d{1,5})?/?$')
# Console Raw IP List integration ids are interpolated into a URL path.
_CONSOLE_ID_RE = re.compile(r'^[A-Za-z0-9_-]{1,64}$')
CONSOLE_CONTENT_URL = "https://admin.api.crowdsec.net/v1/integrations/{id}/content"


# ---- settings -----------------------------------------------------------------

def effective_block(db, config: Dict) -> Dict:
    """Dashboard-saved settings over the config.yaml seed block, field by field
    (the UniFi precedence model)."""
    block = dict(((config or {}).get('integrations', {}) or {}).get('crowdsec', {}) or {})
    if db is not None:
        try:
            raw = db.get_setting(SETTINGS_KEY)
            if raw:
                stored = json.loads(raw)
                if isinstance(stored, dict):
                    block.update(stored)
        except Exception:
            pass
    return block


def normalize_lapi_url(url: str) -> str:
    """'' or a validated scheme://host[:port] with no trailing slash. Raises
    ValueError on anything with a path, query, credentials or bad port."""
    url = (url or "").strip()
    if not url:
        return ""
    if not _LAPI_RE.match(url):
        raise ValueError("LAPI URL must be http(s)://host[:port] with no path")
    parts = urlsplit(url)
    if parts.port is not None and not 0 < parts.port < 65536:
        raise ValueError("LAPI port out of range")
    return url.rstrip('/')


def lapi_url(db, config: Dict) -> str:
    try:
        return normalize_lapi_url(effective_block(db, config).get('lapi_url', ''))
    except ValueError:
        return ""


def console_integration_id(db, config: Dict) -> str:
    v = str(effective_block(db, config).get('console_integration_id') or '').strip()
    return v if _CONSOLE_ID_RE.match(v) else ""


def duration_hours(block: Dict) -> int:
    try:
        h = int(block.get('duration_hours', DEFAULT_DURATION_H))
    except (TypeError, ValueError):
        h = DEFAULT_DURATION_H
    return max(_MIN_DURATION_H, min(_MAX_DURATION_H, h))


def _session(verify: bool = True) -> requests.Session:
    s = requests.Session()
    s.verify = verify
    s.trust_env = False     # never route LAN credentials through an env proxy
    return s


def _check(r: requests.Response, what: str) -> requests.Response:
    if r.is_redirect or 300 <= r.status_code < 400:
        # Credentials go to the configured LAPI only; a redirect is refused,
        # never followed.
        raise RuntimeError(f"CrowdSec {what}: LAPI answered a redirect; refusing to follow")
    r.raise_for_status()
    return r


# ---- push ---------------------------------------------------------------------

class CrowdSecPusher:
    def __init__(self, lapi: str, tier: str = DEFAULT_TIER,
                 duration_h: int = DEFAULT_DURATION_H,
                 max_entries: int = DEFAULT_MAX_ENTRIES,
                 verify_ssl: bool = True, session=None):
        self.lapi = normalize_lapi_url(lapi)
        self.tier = tier if tier in _VALID_TIERS else DEFAULT_TIER
        self.duration_h = max(_MIN_DURATION_H, min(_MAX_DURATION_H, int(duration_h)))
        self.max_entries = max(1, int(max_entries))
        self.session = session if session is not None else _session(verify_ssl)
        self._token: Optional[str] = None

    @classmethod
    def from_block(cls, block: Dict, session=None) -> Optional["CrowdSecPusher"]:
        """None without a LAPI URL (enabled flag NOT consulted: Test must work
        before the operator enables)."""
        try:
            url = normalize_lapi_url(block.get('lapi_url', ''))
        except ValueError:
            return None
        if not url:
            return None
        return cls(url, tier=block.get('tier', DEFAULT_TIER),
                   duration_h=duration_hours(block),
                   max_entries=block.get('max_entries', DEFAULT_MAX_ENTRIES),
                   verify_ssl=bool(block.get('verify_ssl', True)), session=session)

    @staticmethod
    def credentials_configured() -> bool:
        return bool(os.environ.get(ENV_MACHINE_ID)) and bool(os.environ.get(ENV_MACHINE_PASSWORD))

    def login(self) -> None:
        mid, pw = os.environ.get(ENV_MACHINE_ID), os.environ.get(ENV_MACHINE_PASSWORD)
        if not mid or not pw:
            raise RuntimeError(f"CrowdSec push needs {ENV_MACHINE_ID} / {ENV_MACHINE_PASSWORD} "
                               "(set them in the dashboard's CrowdSec panel)")
        r = _check(self.session.post(f"{self.lapi}/v1/watchers/login",
                                     json={"machine_id": mid, "password": pw, "scenarios": []},
                                     timeout=_TIMEOUT, allow_redirects=False), "login")
        self._token = (r.json() or {}).get("token")
        if not self._token:
            raise RuntimeError("CrowdSec login: no token in the LAPI's answer")

    def _auth(self) -> Dict[str, str]:
        return {"Authorization": f"Bearer {self._token}"}

    def test_connection(self) -> Dict:
        """Login only: proves URL + machine credentials. No writes."""
        self.login()
        return {"ok": True}

    def collect(self, db) -> List[str]:
        """The tier's IP/CIDR values, whitelist-applied, strongest first."""
        tier = ConfidenceTier(self.tier)
        wl = db.get_whitelist_map()
        values = [firewall_value(i)
                  for i in db.iter_indicators_by_tiers(CUMULATIVE_TIERS[tier], kind='ip')
                  if is_included(i, wl, tier=tier)]
        if len(values) > self.max_entries:
            logger.warning("[crowdsec] %s tier has %d entries; pushing the strongest %d "
                           "(max_entries)", self.tier, len(values), self.max_entries)
            values = values[:self.max_entries]
        return values

    def _alert(self, scenario: str, chunk: List[str], now: str) -> Dict:
        # Field set mirrors `cscli decisions import` (every field the LAPI's
        # Alert model marks required).
        return {
            "scenario": scenario, "scenario_hash": "", "scenario_version": "",
            "message": f"threat-feed-me {self.tier} tier ({len(chunk)} entries)",
            "events_count": len(chunk), "start_at": now, "stop_at": now,
            "capacity": 0, "leakspeed": "", "simulated": False, "events": [],
            "source": {"scope": "threatfeedme", "value": self.tier},
            "decisions": [{
                "origin": ORIGIN, "type": "ban",
                "scope": "Range" if "/" in v else "Ip", "value": v,
                "duration": f"{self.duration_h}h", "scenario": scenario,
            } for v in chunk],
        }

    def post_generation(self, values: List[str], scenario: str) -> None:
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        for i in range(0, len(values), _CHUNK):
            _check(self.session.post(f"{self.lapi}/v1/alerts", headers=self._auth(),
                                     json=[self._alert(scenario, values[i:i + _CHUNK], now)],
                                     timeout=_TIMEOUT, allow_redirects=False), "push")

    def expire(self, scenario: str) -> int:
        r = _check(self.session.delete(f"{self.lapi}/v1/decisions", headers=self._auth(),
                                       params={"scenario": scenario},
                                       timeout=_TIMEOUT, allow_redirects=False), "expire")
        try:
            return int((r.json() or {}).get("nbDeleted") or 0)
        except (ValueError, TypeError):
            return 0


def _last(db) -> Dict:
    try:
        raw = db.get_setting(LAST_PUSH_KEY)
        return json.loads(raw) if raw else {}
    except Exception:
        return {}


def _record(db, **outcome) -> None:
    try:
        prev = _last(db)
        prev.update(outcome)
        prev["at"] = datetime.now(timezone.utc).isoformat()
        db.set_setting(LAST_PUSH_KEY, json.dumps(prev))
    except Exception:
        pass


def push_ready(db, config: Dict) -> bool:
    block = effective_block(db, config)
    return (bool(block.get('enabled')) and bool(lapi_url(db, config))
            and CrowdSecPusher.credentials_configured())


def push_to_crowdsec(db, config: Dict, force: bool = False, session=None) -> Optional[Dict]:
    """Publish the configured tier as a new generation, then expire the last
    one. A no-op (returns {"skipped": ...}) when the list is unchanged and the
    live generation is younger than half its duration. None when disabled.
    Raises on failure (callers wrap it); the outcome is recorded either way."""
    from threatfeedme import jobs
    with jobs.write_lock:
        block = effective_block(db, config)
        if not block.get('enabled'):
            return None
        pusher = CrowdSecPusher.from_block(block, session=session)
        if pusher is None:
            return None
        values = pusher.collect(db)
        digest = hashlib.sha256("\n".join(values).encode()).hexdigest()[:16]
        last = _last(db)
        # the generation bouncers are enforcing now (kept across failed pushes)
        prev_scenario = last.get("live_scenario")
        age_h = None
        if last.get("pushed_at"):
            try:
                age_h = (datetime.now(timezone.utc)
                         - datetime.fromisoformat(last["pushed_at"])).total_seconds() / 3600
            except (ValueError, TypeError):
                age_h = None
        if (not force and last.get("digest") == digest and last.get("tier") == pusher.tier
                and age_h is not None and age_h < pusher.duration_h / 2
                and not last.get("error")):
            return {"skipped": "unchanged", "entries": len(values)}
        # Microsecond stamp, and never the live generation's name: two pushes
        # in one second (Push now twice, a whitelist push landing on a refresh)
        # used to reuse the name, so the "previous" generation was never
        # expired and its decisions doubled (caught by the live test).
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        scenario = f"{SCENARIO_PREFIX}{pusher.tier}@{stamp}"
        if scenario == prev_scenario:
            scenario += "b"
        try:
            pusher.login()
            pusher.post_generation(values, scenario)
        except Exception as e:
            # The previous generation is still whole and live; drop the
            # partial new one rather than leave it half-posted.
            try:
                if pusher._token:
                    pusher.expire(scenario)
            except Exception:
                pass
            _record(db, error=str(e))
            raise
        expired = 0
        if prev_scenario and prev_scenario != scenario:
            try:
                expired = pusher.expire(prev_scenario)
            except Exception as e:
                # Harmless: the old generation times out by its duration.
                logger.warning("[crowdsec] could not expire %s (it times out on its own): %s",
                               prev_scenario, e)
        summary = {"entries": len(values), "tier": pusher.tier, "scenario": scenario,
                   "expired_previous": expired, "duration_h": pusher.duration_h}
        _record(db, error=None, live_scenario=scenario, digest=digest,
                tier=pusher.tier, pushed_at=datetime.now(timezone.utc).isoformat(),
                summary=summary)
        logger.info("[crowdsec] published %d %s-tier decisions as %s (expired %d from the "
                    "previous generation)", len(values), pusher.tier, scenario, expired)
        return summary


# ---- pull ---------------------------------------------------------------------

def decision_values(decisions) -> List[str]:
    """Ban values from a /v1/decisions answer (a JSON list, or null when empty),
    minus anything threat-feed-me published itself. Hostile input: shapes are
    checked, not trusted; the ingest parser validates every value after."""
    out: List[str] = []
    if not isinstance(decisions, list):
        return out
    for d in decisions:
        if not isinstance(d, dict):
            continue
        if str(d.get("type") or "").lower() != "ban":
            continue
        if d.get("origin") == ORIGIN or str(d.get("scenario") or "").startswith(SCENARIO_PREFIX):
            continue
        if str(d.get("scope") or "").lower() not in ("ip", "range"):
            continue
        value = str(d.get("value") or "").strip()
        if value:
            out.append(value)
    return out
