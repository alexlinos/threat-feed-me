"""
Simple web dashboard for Threat Feed Me!

The dashboard's primary job is to hand an operator a URL they can paste
straight into their firewall's external threat-feed / block-list configuration
(FortiGate External Connector, pfSense/pfBlockerNG, Palo Alto EDL, etc.). Those
feed URLs are served as plain text, one IP or CIDR per line, and are always
generated live from the database with the whitelist applied.

This module is a thin compatibility shim: the application now lives in
`app.py` (assembly), `core.py` (config/db singletons — lazy initialised),
`auth.py`, `scheduler.py`, and the `routers/` package. Importing `dashboard`
re-exports the FastAPI `app` so `uvicorn dashboard:app` works unchanged, plus
lazy-proxies the core singletons for test compatibility.
"""
import uvicorn

from threatfeedme.app import app
from threatfeedme.auth import require_auth
from threatfeedme.scheduler import (
    DEFAULT_REFRESH_MINUTES,
    REFRESH_INTERVAL_KEY,
    LAST_BACKUP_KEY,
    _backup_cfg,
    _do_refresh,
    _maybe_backup,
    _refresh_interval_minutes,
    _refresh_state,
    _run_backup,
    _scheduler_loop,
    _scheduler_stop,
)
from threatfeedme.routers.feeds import MAX_UPLOAD_BYTES, _is_within_uploads, _safe_upload_path
from threatfeedme.feed_helpers import TIER_FEEDS, _FEEDS_BY_NAME, _feed_base, _indicators_for, _lan_ip, _normalize_indicator
from threatfeedme.schemas import (
    FeedRequest,
    IndicatorRequest,
    SettingsRequest,
    WhitelistRequest,
    WhitelistResponse,
)

# Lazy proxy to core singletons for backward compat (tests use
# dashboard.db.add_indicator(...), dashboard.UPLOAD_DIR, etc.)
from threatfeedme import core as _core_mod
_core_accessed = False


def __getattr__(name):
    """Proxy attribute access to core for backward-compat re-exports.

    Tests and legacy code that do `from dashboard import config, db, UPLOAD_DIR`
    or `dashboard.db.add_indicator(...)` get the live core singleton.
    """
    _CORE_ATTRS = {
        'config': 'config',
        'db': 'db',
        'db_path': 'db_path',
        'UPLOAD_DIR': 'UPLOAD_DIR',
        'SAFETY': 'SAFETY',
        'templates': 'templates',
        'load_config': 'load_config',
    }
    if name in _CORE_ATTRS:
        return getattr(_core_mod, _CORE_ATTRS[name])
    raise AttributeError(f"module 'dashboard' has no attribute '{name}'")


if __name__ == "__main__":
    cfg = _core_mod.config.get('dashboard', {})
    host = cfg.get('host', '127.0.0.1')
    port = cfg.get('port', 8080)
    uvicorn.run(app, host=host, port=port)
