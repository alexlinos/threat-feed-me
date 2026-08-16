"""
UniFi (UDM / UDM Pro / UDM SE / Cloud Gateway) firewall-group pusher.

UniFi OS has no "poll an external blocklist URL" feature (a years-old open
feature request), so the FortiGate-style serve-a-URL model can't reach it.
This module inverts the flow: after each refresh, the configured tier's
IP/CIDR set is PUSHED into named UniFi firewall groups via the gateway's
local Network API. The operator references those groups ONCE in a drop rule
(Firewall & Security -> rule -> source/destination = the threatfeedme
groups); membership then updates itself every refresh.

Design constraints, learned from the community's scar tissue:
  - Firewall groups cap out around ~10k members on UniFi OS, so the set is
    CHUNKED across groups named {prefix}-{tier}-1..N (default 5k/group) and
    the default tier is medium — never "Everything" (100k+ would wedge
    provisioning).
  - Stale chunk groups are EMPTIED, not deleted: UniFi refuses to delete a
    group referenced by a firewall rule, and an empty group matches nothing.
  - Credentials come from UNIFI_USER / UNIFI_PASSWORD env vars only (the
    data-volume .env works), never from config. Use a dedicated local-only
    admin restricted to the Network app.
  - UDM certs are self-signed, so verify_ssl defaults false (config can
    enable it for gateways with real certs).
  - IPv4 only: UniFi's "address-group" type is v4; the handful of v6
    indicators are skipped and counted in the log line.

Failures here must never break a refresh — the caller wraps the push and
logs; the block lists keep serving either way.
"""
import json
import logging
import os
from datetime import datetime, timezone
from typing import Dict, List, Optional

import requests

from threatfeedme.exporter import firewall_value, is_included
from threatfeedme.models import ConfidenceTier, CUMULATIVE_TIERS

logger = logging.getLogger(__name__)

ENV_USER = "UNIFI_USER"
ENV_PASSWORD = "UNIFI_PASSWORD"

# Runtime settings (saved from the dashboard's Integrations panel) override
# the config.yaml seed block field-by-field, same precedence model as the
# refresh interval. Last push outcome is recorded for the panel's status line.
SETTINGS_KEY = "unifi_integration"
LAST_PUSH_KEY = "unifi_last_push"

# Chunk size stays well under the ~10k member cap community reports; the
# total cap keeps a misconfigured tier=low from shoving 100k+ entries at a
# home gateway. Values stream in confidence order, so a truncation keeps
# the strongest indicators and the log says exactly what was dropped.
DEFAULT_MAX_PER_GROUP = 5000
DEFAULT_MAX_ENTRIES = 50000
_VALID_TIERS = ("high", "medium", "low")


class UniFiPusher:
    def __init__(self, host: str, site: str = "default", tier: str = "high",
                 group_prefix: str = "threatfeedme", verify_ssl: bool = False,
                 max_entries: int = DEFAULT_MAX_ENTRIES,
                 max_per_group: int = DEFAULT_MAX_PER_GROUP,
                 domain_tier: str = "",
                 timeout: int = 20, session=None):
        host = (host or "").strip().rstrip('/')
        if host and not host.lower().startswith(('http://', 'https://')):
            host = 'https://' + host
        self.host = host
        self.site = site or "default"
        # High is the default for a push target: a home gateway wants the
        # cleanest list, and high fits in one group. Operators opt UP to
        # medium consciously.
        self.tier = tier if tier in _VALID_TIERS else "high"
        if tier not in _VALID_TIERS:
            logger.warning("[unifi] unknown tier %r; using high", tier)
        # Domain arm (optional, OFF by default): maintains Domain-type
        # network lists ({prefix}-dom-{tier}-1..N) through the SAME
        # firewall-group API as the IP arm — group_type 'domain-group'.
        # Available on base firmware (no CyberSecure), and consumed the same
        # way as the IP lists: the operator creates a policy referencing
        # them. Empty string = don't push domains.
        self.domain_tier = domain_tier if domain_tier in _VALID_TIERS else ""
        if domain_tier and domain_tier not in _VALID_TIERS:
            logger.warning("[unifi] unknown domain_tier %r; domain push off", domain_tier)
        self.group_prefix = group_prefix or "threatfeedme"
        self.max_entries = max(1, int(max_entries))
        self.max_per_group = max(1, int(max_per_group))
        self.timeout = timeout
        self.session = session if session is not None else requests.Session()
        self.session.verify = verify_ssl
        if not verify_ssl:
            # Self-signed UDM cert: silence the per-request nag, we said so once.
            try:
                import urllib3
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            except Exception:
                pass
        self._csrf: Optional[str] = None

    @classmethod
    def from_block(cls, cfg: Dict) -> Optional["UniFiPusher"]:
        """Build from a settings block (enabled flag NOT consulted — the
        dashboard's Test button must work before the operator commits to
        enabling). None when no host is configured."""
        if not (cfg or {}).get('host'):
            return None
        return cls(
            host=cfg['host'],
            site=cfg.get('site', 'default'),
            tier=cfg.get('tier', 'high'),
            group_prefix=cfg.get('group_prefix', 'threatfeedme'),
            verify_ssl=bool(cfg.get('verify_ssl', False)),
            max_entries=cfg.get('max_entries', DEFAULT_MAX_ENTRIES),
            max_per_group=cfg.get('max_per_group', DEFAULT_MAX_PER_GROUP),
            domain_tier=cfg.get('domain_tier', ''),
        )

    @classmethod
    def from_config(cls, config: Dict, db=None) -> Optional["UniFiPusher"]:
        """Build from the effective settings; None if disabled or hostless."""
        cfg = effective_block(db, config)
        if not cfg.get('enabled'):
            return None
        return cls.from_block(cfg)

    # ---------------- UniFi OS API plumbing ----------------

    def credentials_configured(self) -> bool:
        return bool(os.environ.get(ENV_USER)) and bool(os.environ.get(ENV_PASSWORD))

    def test_connection(self) -> Dict:
        """Login and READ the firewall groups — no writes. The dashboard's
        Test button, so the operator can verify host/credentials before
        enabling the push."""
        self.login()
        groups = self._api('GET', '/rest/firewallgroup')
        ours = [g.get('name') for g in groups
                if (g.get('name') or '').startswith(f"{self.group_prefix}-")]
        return {"ok": True, "groups_total": len(groups), "our_groups": sorted(ours)}

    def login(self) -> None:
        user = os.environ.get(ENV_USER)
        password = os.environ.get(ENV_PASSWORD)
        if not user or not password:
            raise RuntimeError(
                f"UniFi push enabled but {ENV_USER} / {ENV_PASSWORD} are not set "
                "(add them to the data volume's .env or the environment)")
        r = self.session.post(f"{self.host}/api/auth/login",
                              json={"username": user, "password": password},
                              timeout=self.timeout)
        r.raise_for_status()
        # UniFi OS hands the CSRF token back as a response header; mutating
        # Network-app calls must echo it.
        self._csrf = r.headers.get('x-csrf-token') or r.headers.get('X-CSRF-Token')

    def _request(self, method: str, url: str, **kwargs):
        headers = {'X-CSRF-Token': self._csrf} if self._csrf else {}
        r = self.session.request(method, url, headers=headers,
                                 timeout=self.timeout, **kwargs)
        # The token rotates on some responses; always keep the freshest.
        rotated = r.headers.get('x-csrf-token')
        if rotated:
            self._csrf = rotated
        r.raise_for_status()
        return r

    def _api(self, method: str, path: str, **kwargs) -> List[Dict]:
        """Legacy Network API (/api/s/{site}/...): {'meta':…, 'data':[...]}."""
        r = self._request(method, f"{self.host}/proxy/network/api/s/{self.site}{path}", **kwargs)
        try:
            return (r.json() or {}).get('data', [])
        except ValueError:
            return []


    # ---------------- Collection & sync ----------------

    def collect(self, db) -> List[str]:
        """The tier's IPv4/CIDR values, whitelist-applied, confidence-ordered
        (so a truncation keeps the strongest indicators)."""
        tier_enum = ConfidenceTier(self.tier)
        wl_map = db.get_whitelist_map()
        values: List[str] = []
        skipped_v6 = 0
        for ind in db.iter_indicators_by_tiers(CUMULATIVE_TIERS[tier_enum], kind='ip'):
            if not is_included(ind, wl_map, tier=tier_enum):
                continue
            value = firewall_value(ind)
            if ':' in value:  # UniFi address-groups are IPv4-only
                skipped_v6 += 1
                continue
            values.append(value)
        if skipped_v6:
            logger.info("[unifi] skipped %d IPv6 indicators (address-group is v4-only)",
                        skipped_v6)
        if len(values) > self.max_entries:
            # ASCII only: Windows consoles default to cp1252.
            logger.warning(
                "[unifi] %s tier has %d entries; pushing the strongest %d "
                "(max_entries) - consider a higher tier, or raise the cap",
                self.tier, len(values), self.max_entries)
            values = values[:self.max_entries]
        return values

    def collect_domains(self, db) -> List[str]:
        """The domain tier's values, whitelist-applied, confidence-ordered,
        capped like the IP arm (a content-filter list is compiled on the
        gateway; unbounded lists are how UDMs get slow)."""
        tier_enum = ConfidenceTier(self.domain_tier)
        wl_map = db.get_whitelist_map()
        values: List[str] = []
        for ind in db.iter_indicators_by_tiers(CUMULATIVE_TIERS[tier_enum], kind='domain'):
            if not is_included(ind, wl_map, tier=tier_enum):
                continue
            values.append(ind.ip)
        if len(values) > self.max_entries:
            logger.warning(
                "[unifi] %s domain tier has %d entries; pushing the strongest %d "
                "(max_entries) - consider a higher tier, or raise the cap",
                self.domain_tier, len(values), self.max_entries)
            values = values[:self.max_entries]
        return values

    def sync(self, values: List[str], label: str = None,
             group_type: str = "address-group") -> Dict:
        """Reconcile the chunk groups named {prefix}-{label}-1..N (of one
        group_type) with `values`. Creates missing groups, updates changed
        ones, leaves identical ones alone, and EMPTIES stale groups (a group
        referenced by a rule/policy can't be deleted; an empty group matches
        nothing).

        Both arms share this: the IP arm labels groups {prefix}-{tier}
        (address-group), the domain arm {prefix}-dom-{tier} (domain-group —
        the Domain-type Network List on current firmware, same API). Stale
        detection is scoped to the arm's OWN group_type, so the IP pass can
        never empty the domain lists and vice versa, while still covering
        both shrinkage and tier switches within an arm."""
        label = label or self.tier
        chunks = [values[i:i + self.max_per_group]
                  for i in range(0, len(values), self.max_per_group)] or [[]]
        groups = {g.get('name'): g for g in self._api('GET', '/rest/firewallgroup')}

        created = updated = unchanged = emptied = 0
        current = {f"{self.group_prefix}-{label}-{i}" for i in range(1, len(chunks) + 1)}
        for idx, chunk in enumerate(chunks, 1):
            name = f"{self.group_prefix}-{label}-{idx}"
            existing = groups.get(name)
            if existing is None:
                self._api('POST', '/rest/firewallgroup', json={
                    "name": name,
                    "group_type": group_type,
                    "group_members": chunk,
                })
                created += 1
            elif list(existing.get('group_members') or []) != chunk:
                body = dict(existing)
                body['group_members'] = chunk
                self._api('PUT', f"/rest/firewallgroup/{existing['_id']}", json=body)
                updated += 1
            else:
                unchanged += 1

        marker = f"{self.group_prefix}-"
        for name, g in groups.items():
            if g.get('group_type') != group_type:
                continue  # the other arm's groups are not ours to touch
            if not (name or "").startswith(marker) or name in current:
                continue
            if g.get('group_members') or []:
                body = dict(g)
                body['group_members'] = []
                self._api('PUT', f"/rest/firewallgroup/{g['_id']}", json=body)
                emptied += 1

        return {"entries": len(values), "groups": len(chunks), "created": created,
                "updated": updated, "unchanged": unchanged, "emptied": emptied}


def effective_block(db, config: Dict) -> Dict:
    """The integration's effective settings: dashboard-saved values (a JSON
    settings row) override the config.yaml seed block field-by-field — the
    same precedence model as the refresh interval, so the product promise
    ("manage it from the dashboard, no config editing") holds here too."""
    block = dict(((config or {}).get('integrations', {}) or {}).get('unifi', {}) or {})
    if db is not None:
        try:
            raw = db.get_setting(SETTINGS_KEY)
            if raw:
                stored = json.loads(raw)
                if isinstance(stored, dict):
                    block.update(stored)
        except Exception:
            pass  # unreadable runtime settings degrade to the config seed
    return block


def record_push_outcome(db, summary: Optional[Dict] = None, error: str = None) -> None:
    """Persist the last push outcome for the dashboard's status line."""
    try:
        db.set_setting(LAST_PUSH_KEY, json.dumps({
            "at": datetime.now(timezone.utc).isoformat(),
            "summary": summary,
            "error": error,
        }))
    except Exception:
        pass  # status bookkeeping must never break a push/refresh


def push_ready(db, config: Dict) -> bool:
    """Cheap pre-flight: integration enabled, host set, and BOTH credential
    variables non-empty. High-frequency callers (the whitelist-triggered
    background export worker) gate on this so unconfigured deployments —
    the overwhelming majority — skip the push without a login attempt or a
    line of error noise."""
    block = effective_block(db, config)
    return (bool(block.get('enabled')) and bool(block.get('host'))
            and bool(os.environ.get(ENV_USER))
            and bool(os.environ.get(ENV_PASSWORD)))


def push_to_unifi(db, config: Dict) -> Optional[Dict]:
    """Push the configured tier into UniFi firewall groups. Returns the sync
    summary, or None when the integration is disabled. Raises on failure —
    the refresh pipeline wraps this so a push error never breaks a refresh.
    Outcomes (success AND failure) are recorded for the dashboard."""
    pusher = UniFiPusher.from_config(config, db=db)
    if pusher is None:
        return None
    try:
        pusher.login()
        values = pusher.collect(db)
        summary = pusher.sync(values)
    except Exception as e:
        record_push_outcome(db, error=str(e))
        raise
    logger.info(
        "[unifi] pushed %d entries into %d group(s) [%s-%s-*]: "
        "%d created, %d updated, %d unchanged, %d emptied",
        summary["entries"], summary["groups"], pusher.group_prefix, pusher.tier,
        summary["created"], summary["updated"], summary["unchanged"], summary["emptied"])
    # Domain arm: optional, and isolated — a domain-list failure must not
    # roll back or hide the IP push that just succeeded. Its error is
    # carried in the summary instead.
    if pusher.domain_tier:
        try:
            summary["domains"] = pusher.sync(
                pusher.collect_domains(db),
                label=f"dom-{pusher.domain_tier}",
                group_type="domain-group")
            d = summary["domains"]
            logger.info(
                "[unifi] domain push: %d domains into %d list(s) [%s-dom-%s-*]: "
                "%d created, %d updated, %d unchanged, %d emptied",
                d["entries"], d["groups"], pusher.group_prefix, pusher.domain_tier,
                d["created"], d["updated"], d["unchanged"], d["emptied"])
        except Exception as e:
            summary["domain_error"] = str(e)
            logger.error("[unifi] domain push failed (IP push succeeded): %s", e)
    record_push_outcome(db, summary=summary)
    return summary
