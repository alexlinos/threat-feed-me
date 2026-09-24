"""
Test-facing shim over the app. Production loads `threatfeedme.app:app`
(main.py --serve, uvicorn); tests import this module for `dashboard.app`,
a few route helpers, and `dashboard.db` / `dashboard.config`, which resolve
to the LIVE core singletons on every access (core initializes lazily, and
some suites purge and re-import threatfeedme).
"""
from threatfeedme import core as _core
from threatfeedme.app import app  # noqa: F401
from threatfeedme.routers.feeds import MAX_UPLOAD_BYTES, _is_within_uploads  # noqa: F401
from threatfeedme.scheduler import _refresh_state  # noqa: F401

_CORE_ATTRS = ("config", "db", "db_path", "UPLOAD_DIR")


def __getattr__(name):
    if name in _CORE_ATTRS:
        return getattr(_core, name)
    raise AttributeError(f"module 'dashboard' has no attribute '{name}'")
