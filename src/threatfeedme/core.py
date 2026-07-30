"""
Shared application singletons: configuration, database, upload directory,
safety filter, and templates.

Everything here was originally constructed at import time (from the CONFIG_PATH
environment variable) so that `import dashboard` — or any module in the app —
binds to the same config/database without needing the server to start. That
pattern is retained for backward compatibility, but the actual singletons are
now lazy-initialized on first access. Every consumer — routers included —
resolves these values through the module (`core.db`, `core.config`, ...) at call
time rather than binding them at import, so `core.init(config_path)` and
`core.reset()` are reflected app-wide. Tests or alternate entry points can
therefore swap in a different database/config without subprocess isolation.

Lifespan (app.py) explicitly warms the singletons so the server path is
unchanged.
"""
import logging
import os

import yaml
from fastapi.templating import Jinja2Templates

from threatfeedme.database import Database
from threatfeedme.safety import SafetyFilter

logger = logging.getLogger(__name__)

# Internal state: None until first access or explicit init().
_config = None
_db = None
_db_path = None
_upload_dir = None
_safety = None
_templates = None
_initialized = False


def load_config(config_path: str = "config.yaml") -> dict:
    """Load configuration from YAML, falling back to sane defaults."""
    try:
        with open(config_path, 'r') as f:
            return yaml.safe_load(f) or {}
    except FileNotFoundError:
        return {}


def _resolve_db_path(cfg: dict) -> str:
    return cfg.get('database', {}).get('path', './data/threatfeedme.db')


def env_file() -> str:
    """Path of the runtime .env file: next to the database, so API keys saved
    from the dashboard persist on the Docker data volume."""
    _ensure()
    return os.path.join(os.path.dirname(_db_path) or ".", ".env")


def load_env_file(path: str) -> None:
    """Load KEY=value lines into os.environ WITHOUT overriding variables that
    are already set — a key passed via real environment (compose, shell)
    always wins over the dashboard-saved file. Missing file is fine."""
    try:
        with open(path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    except (FileNotFoundError, OSError):
        return
    for line in lines:
        line = line.strip()
        if not line or line.startswith('#') or '=' not in line:
            continue
        key, _, value = line.partition('=')
        key = key.strip()
        if key and key not in os.environ:
            os.environ[key] = value.strip()


def init(config_path: str = None):
    """Explicitly initialise (or re-initialise) all singletons.

    Called by the FastAPI lifespan on startup, and by tests that need a clean
    state. When config_path is None, the CONFIG_PATH env var (or default
    'config.yaml') is used.
    """
    global _config, _db, _db_path, _upload_dir, _safety, _templates, _initialized

    path = config_path if config_path is not None else os.environ.get("CONFIG_PATH", "config.yaml")
    _config = load_config(path)
    _db_path = _resolve_db_path(_config)
    _db = Database(_db_path)

    # API keys saved from the dashboard live in a .env next to the database;
    # load them now so feeds with auth_env work after a restart. Variables
    # already present in the real environment are never overridden.
    load_env_file(os.path.join(os.path.dirname(_db_path) or ".", ".env"))

    # Directory for uploaded custom lists (alongside the database).
    os.makedirs(os.path.join(os.path.dirname(_db_path) or ".", "uploads"), exist_ok=True)
    # realpath (not abspath) so symlinked components are resolved for containment.
    _upload_dir = os.path.realpath(os.path.join(os.path.dirname(_db_path) or ".", "uploads"))

    # Seed feed sources from config on first run; the DB is authoritative for
    # user state after that. On every startup, merge changes to the SHIPPED
    # defaults (new feeds, updated URLs) into the DB without touching user
    # customizations, deletions, or accumulated data — so updating the app
    # never requires wiping the database.
    _db.seed_feeds_from_config(_config)
    sync = _db.sync_default_feeds(_config)
    if sync["added"] or sync["updated"]:
        logger.info(
            "Default feed sync: added %s; updated %s",
            ", ".join(sync["added"]) or "none",
            ", ".join(sync["updated"]) or "none",
        )

    # Safety guard for manual adds (config-toggleable; see config.yaml `safety`).
    _safety = SafetyFilter.from_config(_config)

    # Jinja2 templates (autoescaping on for .html — the structural XSS defence).
    # Anchored to this module's directory so it works regardless of CWD.
    _templates = Jinja2Templates(directory=os.path.join(os.path.dirname(__file__), "templates"))

    _initialized = True


def _ensure():
    """Lazy-init on first call if init() was never called explicitly.

    This preserves the original import-time behaviour: importing `core` triggers
    init from the environment, but the work happens on first attribute access
    rather than at module import time.
    """
    if not _initialized:
        init()


def __getattr__(name):
    """Lazy access to singleton globals.

    `from core import config, db` triggers __getattr__ for 'config' and 'db',
    which calls _ensure() and returns the internal variable.
    """
    _SINGLETONS = {
        'config': lambda: _config,
        'db': lambda: _db,
        'db_path': lambda: _db_path,
        'UPLOAD_DIR': lambda: _upload_dir,
        'SAFETY': lambda: _safety,
        'templates': lambda: _templates,
    }
    if name in _SINGLETONS:
        _ensure()
        val = _SINGLETONS[name]()
        if val is None:
            raise RuntimeError(f"core.{name} accessed before initialisation — "
                               "call core.init() or import core before using it")
        return val
    raise AttributeError(f"module 'core' has no attribute '{name}'")


def reset():
    """Reset all singletons to None (for test cleanup).

    After calling reset(), the next attribute access re-initialises from the
    environment — or call init(config_path) for a specific configuration.
    """
    global _config, _db, _db_path, _upload_dir, _safety, _templates, _initialized
    _config = None
    _db = None
    _db_path = None
    _upload_dir = None
    _safety = None
    _templates = None
    _initialized = False
