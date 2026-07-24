"""
Background refresh scheduling and automatic database backups.

A single lock ensures only one refresh (manual or scheduled) runs at a time;
`_refresh_state` is the shared status dict the API routes report and the
scheduler updates.

All singletons are accessed lazily on first call rather than at import time,
so tests that need a different config/database can reset core and re-init
without needing subprocess isolation.
"""
import logging
import os
import threading
from datetime import datetime, timezone
from typing import Optional, List

from threatfeedme import pipeline
from threatfeedme import core

logger = logging.getLogger(__name__)

# Default auto-refresh cadence (minutes) if none has been set.
DEFAULT_REFRESH_MINUTES = 60
REFRESH_INTERVAL_KEY = "refresh_interval_minutes"

LAST_BACKUP_KEY = "last_backup_at"


def _refresh_interval_minutes() -> int:
    try:
        return max(1, int(core.db.get_setting(REFRESH_INTERVAL_KEY, DEFAULT_REFRESH_MINUTES)))
    except (ValueError, TypeError):
        return DEFAULT_REFRESH_MINUTES


def _backup_cfg() -> dict:
    """Backup settings with sane defaults; dir defaults next to the database."""
    cfg = dict(core.config.get('database', {}).get('backup', {}) or {})
    cfg.setdefault('dir', os.path.join(os.path.dirname(core.db_path) or '.', 'backups'))
    cfg.setdefault('keep', 7)
    cfg.setdefault('interval_hours', 24)
    cfg.setdefault('enabled', True)
    return cfg


def _run_backup() -> str:
    """Take a backup now and record the timestamp. Returns the backup path."""
    cfg = _backup_cfg()
    path = core.db.backup_database(cfg['dir'], keep=int(cfg['keep']))
    core.db.set_setting(LAST_BACKUP_KEY, datetime.now(timezone.utc).isoformat())
    return path


def _maybe_backup() -> None:
    """Run an automatic backup if enabled and the interval has elapsed."""
    cfg = _backup_cfg()
    if not cfg.get('enabled'):
        return
    last = core.db.get_setting(LAST_BACKUP_KEY)
    if last:
        try:
            elapsed = (datetime.now(timezone.utc) - datetime.fromisoformat(last)).total_seconds()
            if elapsed < float(cfg['interval_hours']) * 3600:
                return
        except (ValueError, TypeError):
            pass  # unparseable -> back up now
    try:
        path = _run_backup()
        logger.info(f"[backup] wrote {path}")
    except Exception as e:
        logger.error(f"[backup] failed: {e}")


# ==================== REFRESH STATE & SCHEDULER ====================
# A single lock ensures only one refresh (manual or scheduled) runs at a time.
_refresh_lock = threading.Lock()
_refresh_state = {"running": False, "last_finished": None, "last_result": None, "last_error": None}
_scheduler_stop = threading.Event()


def _run_refresh_holding_lock(only: Optional[List[str]] = None) -> None:
    """Body of one refresh. The caller must already hold _refresh_lock and
    have set running=True; both are released/cleared here."""
    try:
        result = pipeline.run_refresh(core.db, core.config, only=only)
        _refresh_state["last_result"] = result
        _refresh_state["last_error"] = None
    except Exception as e:  # keep the scheduler/endpoint alive on failure
        _refresh_state["last_error"] = str(e)
        logger.error(f"Refresh failed: {e}")
    finally:
        _refresh_state["running"] = False
        _refresh_state["last_finished"] = datetime.now(timezone.utc).isoformat()
        _refresh_lock.release()


def _do_refresh(only: Optional[List[str]] = None) -> bool:
    """Run one refresh if none is in progress. Returns False if already busy."""
    if not _refresh_lock.acquire(blocking=False):
        return False
    _refresh_state["running"] = True
    _run_refresh_holding_lock(only)
    return True


def start_refresh_async(only: Optional[List[str]] = None) -> bool:
    """Start a refresh in a background thread; False if one is already running.

    The lock is acquired and running=True is set synchronously, BEFORE the
    thread spawns: the dashboard polls /api/refresh/status immediately after
    triggering, and if the flag were set inside the thread the first poll
    could see running=False and declare the refresh complete while it was
    still starting."""
    if not _refresh_lock.acquire(blocking=False):
        return False
    _refresh_state["running"] = True
    threading.Thread(target=_run_refresh_holding_lock, args=(only,), daemon=True).start()
    return True


def _scheduler_loop():
    """Background loop: on each short tick, refresh only the feeds that are due
    per their individual update_interval (Emerging Threats every 12h, hourly
    feeds every hour, etc.) instead of polling everything on one global clock.

    The dashboard's global auto-refresh setting (REFRESH_INTERVAL_KEY) acts as
    the DEFAULT interval for feeds whose update_interval is 0/unset. The initial
    tick doubles as the startup delay so a fetch never blocks startup, and the
    short tick keeps shutdown prompt. The refresh lock still serializes against
    manual refreshes."""
    while not _scheduler_stop.wait(60):
        # Time-based DB backup (independent of feed cadence).
        _maybe_backup()
        try:
            due = pipeline.due_feeds(core.db, _refresh_interval_minutes() * 60)
        except Exception as e:  # never let a bad tick kill the scheduler thread
            logger.error(f"Scheduler due-check failed: {e}")
            continue
        if not due:
            continue
        if _do_refresh(only=due):
            logger.info(f"Scheduled refresh ran for due feeds: {', '.join(due)}")
        else:
            # A manual refresh is holding the lock; log it and retry on the
            # next tick rather than skipping silently.
            logger.warning("Scheduled refresh skipped: another refresh is in progress")
