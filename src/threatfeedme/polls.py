"""
"Is my firewall actually polling?" (v2.5.0).

Records, per served feed URL (and per TAXII collection), when it was last
fetched, how often, and the client's User-Agent, so the dashboard can show
"last polled 3m ago by FortiGate" beside each URL. An operator who pasted a
URL into a firewall otherwise has no way to tell from here whether the
firewall ever fetched it (a typo'd URL fails silently on most firewalls).

Deliberately minimal: time, count and a truncated User-Agent. No client IP
is stored (the web server's access log already has it, under the operator's
own log retention). Held in memory and persisted to one settings row at most
once a minute, so a busy poller costs nothing per request.
"""
import json
import threading
import time
from datetime import datetime, timezone
from typing import Dict

SETTINGS_KEY = "feed_polls"
_FLUSH_EVERY_S = 60
_MAX_PATHS = 64          # bounded: paths come from our own routes only
_AGENT_LEN = 80

_lock = threading.Lock()
_polls: Dict[str, Dict] = {}
_loaded = False
_last_flush = 0.0


def _clean_agent(ua: str) -> str:
    ua = "".join(c for c in (ua or "") if 32 <= ord(c) < 127)
    return ua[:_AGENT_LEN]


def _load(db) -> None:
    global _loaded
    if _loaded:
        return
    _loaded = True
    try:
        raw = db.get_setting(SETTINGS_KEY)
        stored = json.loads(raw) if raw else {}
        if isinstance(stored, dict):
            for k, v in list(stored.items())[:_MAX_PATHS]:
                if isinstance(v, dict):
                    _polls[str(k)] = v
    except Exception:
        pass


def record(db, key: str, user_agent: str) -> None:
    """Note one poll of `key` (a route-derived label, never raw client input)."""
    global _last_flush
    now = datetime.now(timezone.utc).isoformat()
    with _lock:
        _load(db)
        entry = _polls.get(key)
        if entry is None:
            if len(_polls) >= _MAX_PATHS:
                return
            entry = _polls[key] = {"count": 0}
        entry["at"] = now
        entry["count"] = int(entry.get("count", 0)) + 1
        entry["agent"] = _clean_agent(user_agent)
        due = time.monotonic() - _last_flush >= _FLUSH_EVERY_S
        if due:
            _last_flush = time.monotonic()
            snapshot = json.dumps(_polls)
    if due:
        try:
            db.set_setting(SETTINGS_KEY, snapshot)
        except Exception:
            pass     # bookkeeping must never fail a feed poll


def snapshot(db) -> Dict[str, Dict]:
    with _lock:
        _load(db)
        return {k: dict(v) for k, v in _polls.items()}


def age_minutes(entry: Dict) -> int:
    try:
        at = datetime.fromisoformat(entry["at"])
        return max(0, int((datetime.now(timezone.utc) - at).total_seconds() // 60))
    except (KeyError, TypeError, ValueError):
        return -1


def agent_label(agent: str) -> str:
    """A short, human name for common pollers; otherwise the UA's first token."""
    a = (agent or "").lower()
    # FortiOS external-resource connectors send "curl/7.58.0" unless the
    # connector sets its own (`set user-agent`), seen on prod right after the
    # 2.5.0 roll. A real curl 7.58 (Ubuntu 18.04) reads as FortiGate too;
    # the tooltip shows the raw string, so the operator can tell.
    if a == "curl/7.58.0":
        return "FortiGate"
    for needle, name in (("fortigate", "FortiGate"), ("fortios", "FortiGate"),
                         ("pan-os", "Palo Alto"), ("paloalto", "Palo Alto"),
                         ("pfblocker", "pfBlockerNG"), ("pfsense", "pfSense"),
                         ("opnsense", "OPNsense"), ("sophos", "Sophos"),
                         ("sonicwall", "SonicWall"), ("checkpoint", "Check Point"),
                         ("pi-hole", "Pi-hole"), ("pihole", "Pi-hole"), ("adguard", "AdGuard"),
                         ("taxii2-client", "TAXII client"), ("curl", "curl"), ("wget", "wget"),
                         ("mozilla", "a browser")):
        if needle in a:
            return name
    return (agent or "unknown").split("/")[0][:24] or "unknown"
