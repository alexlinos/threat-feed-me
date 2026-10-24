"""Robustness fixes for 2.5.7, from the 2026-10 piperev review.

Each fix has a regression test here: a feed delete that raced the rescore
writers, a purge that failed past SQLite's bound-variable limit, a scheduler
thread that died on a malformed backup block, and a one-time VACUUM that a
kill could skip for good.
"""
import os
import sqlite3
import threading
from datetime import datetime, timezone

import pytest

from threatfeedme import core, jobs, pipeline, scheduler
from threatfeedme.database import Database
from threatfeedme.models import FeedSource, FeedType
from threatfeedme.routers import feeds as feeds_router


class RecordingLock:
    """Stands in for jobs.write_lock and counts how many holders are inside.
    Reentrant like the real one (the refresh phase nests calls)."""

    def __init__(self):
        self._lock = threading.RLock()
        self.depth = 0

    def __enter__(self):
        self._lock.acquire()
        self.depth += 1
        return self

    def __exit__(self, *exc):
        self.depth -= 1
        self._lock.release()
        return False


@pytest.fixture
def core_env(tmp_path, monkeypatch):
    """A temp database and upload dir patched onto the core singletons. The
    module __dict__ is patched (not the attribute) so core never lazy-inits
    from the environment during the test (see tests/conftest.py)."""
    db = Database(str(tmp_path / "t.db"))
    uploads = os.path.realpath(str(tmp_path / "uploads"))
    os.makedirs(uploads, exist_ok=True)
    monkeypatch.setitem(core.__dict__, "db", db)
    monkeypatch.setitem(core.__dict__, "config", {})
    monkeypatch.setitem(core.__dict__, "UPLOAD_DIR", uploads)
    return db, uploads


# ---- 1. feed delete holds the write lock; uploads are removed with the feed --

def test_delete_feed_holds_the_write_lock_across_delete_and_rescore(core_env, monkeypatch):
    db, _ = core_env
    db.add_feed(FeedSource(name="remote", url="https://feeds.example/x.txt"))
    lock = RecordingLock()
    monkeypatch.setitem(jobs.__dict__, "write_lock", lock)
    seen = {}

    real_remove = db.remove_feed

    def spy_remove(name):
        seen["remove"] = lock.depth
        return real_remove(name)

    real_recalc = pipeline.recalculate

    def spy_recalc(d, config):
        seen["recalc"] = lock.depth
        return real_recalc(d, config)

    monkeypatch.setattr(db, "remove_feed", spy_remove)
    monkeypatch.setattr(pipeline, "recalculate", spy_recalc)

    out = feeds_router.delete_feed("remote", _=None, _csrf=None)
    assert out["success"] is True
    # Both the delete and the rescore ran with the lock held by the request.
    assert seen == {"remove": 1, "recalc": 1}
    assert lock.depth == 0


def test_delete_of_a_missing_feed_is_404_and_releases_the_lock(core_env, monkeypatch):
    from fastapi import HTTPException
    lock = RecordingLock()
    monkeypatch.setitem(jobs.__dict__, "write_lock", lock)
    with pytest.raises(HTTPException) as exc:
        feeds_router.delete_feed("nope", _=None, _csrf=None)
    assert exc.value.status_code == 404
    assert lock.depth == 0


def test_deleting_a_local_feed_removes_its_upload(core_env):
    db, uploads = core_env
    dest = feeds_router._safe_upload_path("mylist")
    feeds_router._store_upload(b"45.66.230.5\n45.66.230.6\n", "mylist", dest,
                               FeedType.CUSTOM, 1.0, "ip")
    assert os.path.isfile(dest)
    feeds_router.delete_feed("mylist", _=None, _csrf=None)
    assert not os.path.exists(dest)
    assert db.get_feed_source("mylist") is None


def test_deleting_a_remote_feed_never_touches_the_uploads_dir(core_env):
    db, uploads = core_env
    db.add_feed(FeedSource(name="remote", url="https://feeds.example/x.txt"))
    # A same-named file must survive: only a LOCAL feed owns its upload.
    sentinel = os.path.join(uploads, "remote.txt")
    with open(sentinel, "w", encoding="utf-8") as f:
        f.write("45.66.230.5\n")
    feeds_router.delete_feed("remote", _=None, _csrf=None)
    assert os.path.isfile(sentinel)


def test_delete_with_a_missing_upload_file_still_succeeds(core_env):
    db, _ = core_env
    feeds_router._store_upload(b"45.66.230.5\n", "gone", feeds_router._safe_upload_path("gone"),
                               FeedType.CUSTOM, 1.0, "ip")
    os.remove(feeds_router._safe_upload_path("gone"))   # already gone
    assert feeds_router.delete_feed("gone", _=None, _csrf=None)["success"] is True
    assert db.get_feed_source("gone") is None


def test_recalculate_rides_out_a_briefly_locked_writer(core_env, monkeypatch):
    db, _ = core_env
    monkeypatch.setitem(pipeline.__dict__, "_LOCKED_BACKOFF_S", 0.0)
    real = db.prune_left_memberships
    calls = []

    def flaky(grace):
        calls.append(grace)
        if len(calls) == 1:
            raise sqlite3.OperationalError("database is locked")
        return real(grace)

    monkeypatch.setattr(db, "prune_left_memberships", flaky)
    pipeline.recalculate(db, {})
    assert len(calls) == 2


def test_recalculate_does_not_mask_other_operational_errors(core_env, monkeypatch):
    db, _ = core_env
    monkeypatch.setitem(pipeline.__dict__, "_LOCKED_BACKOFF_S", 0.0)

    def broken(grace):
        raise sqlite3.OperationalError("no such table: source_left")

    monkeypatch.setattr(db, "prune_left_memberships", broken)
    with pytest.raises(sqlite3.OperationalError, match="no such table"):
        pipeline.recalculate(db, {})


# ---- 2. purge_stale_indicators past SQLite's bound-variable limit -----------

def test_purge_survives_a_whitelist_past_the_bound_variable_limit(tmp_path):
    """33,000 global whitelist entries is past SQLite's 32,766 bound-variable
    limit. The purge used to bind the whole protected set into one IN (...)
    list and raised "too many SQL variables" on every refresh. It must now
    keep exactly the protected stale rows and drop the rest."""
    db = Database(str(tmp_path / "t.db"))
    conn = sqlite3.connect(db.db_path)
    conn.executemany(
        "INSERT INTO whitelist (ip, feed_name, reason, added_by, added_at, reason_code) "
        "VALUES (?, '*', 'asset', 'import', '2026-01-01T00:00:00+00:00', 'internal_asset')",
        [(f"10.{(i >> 16) & 255}.{(i >> 8) & 255}.{i & 255}",) for i in range(33_000)])
    conn.commit()
    conn.close()

    db.add_to_whitelist("192.0.2.10", "scoped asset", "alex", feed_name="feedA")
    db.add_to_whitelist("192.0.2.11", "expired entry", "alex",
                        expires_at=datetime(2020, 1, 1, tzinfo=timezone.utc))
    db.add_to_whitelist("192.0.2.12", "global asset", "alex")

    db.add_indicators_bulk([("203.0.113.1", {}), ("203.0.113.2", {}), ("10.0.0.5", {})], "feedA")
    db.add_indicator("192.0.2.10", "feedA", {})          # feed-scoped whitelist: kept
    db.add_indicator("192.0.2.11", "feedA", {})          # whitelist expired: purged
    db.add_indicator("192.0.2.12", "feedA", {})          # global whitelist: kept
    db.add_indicator("203.0.113.3", "manual", {})        # manual rows are never purged
    db.add_indicator("203.0.113.9", "feedA", {})         # fresh: kept
    conn = sqlite3.connect(db.db_path)
    conn.execute("UPDATE indicators SET last_seen = '2020-01-01T00:00:00+00:00' "
                 "WHERE ip != '203.0.113.9'")
    conn.commit()
    conn.close()

    deleted = db.purge_stale_indicators(14, db.get_whitelist_map())

    conn = sqlite3.connect(db.db_path)
    remaining = {row[0] for row in conn.execute("SELECT ip FROM indicators")}
    conn.close()
    assert remaining == {"192.0.2.10", "192.0.2.12", "203.0.113.3", "10.0.0.5", "203.0.113.9"}
    assert deleted == 3   # 203.0.113.1, 203.0.113.2 and the expired-whitelist 192.0.2.11


# ---- 3. scheduler survives a malformed backup block -------------------------

@pytest.fixture
def sched_env(core_env, monkeypatch):
    # Module-level imports only: a suite that purges and re-imports
    # `threatfeedme` leaves an in-function import holding a different `core`
    # than the one these tests patch, so the patches silently miss.
    db, _ = core_env
    monkeypatch.setitem(core.__dict__, "db_path", db.db_path)
    monkeypatch.setitem(scheduler.__dict__, "_warned_config", set())
    backups = []
    monkeypatch.setitem(scheduler.__dict__, "_run_backup",
                        lambda: backups.append(1) or "stub.db")
    return scheduler, backups


@pytest.mark.parametrize("database_block", [
    {"path": "x.db", "backup": True},     # the dict(True) TypeError
    {"path": "x.db", "backup": "yes"},    # a bare string
    None,                                 # a null `database:` key
])
def test_maybe_backup_does_not_raise_on_a_malformed_block(sched_env, monkeypatch, database_block):
    scheduler, backups = sched_env
    monkeypatch.setitem(core.__dict__, "config", {"database": database_block})
    cfg = scheduler._backup_cfg()          # defaults, not an exception
    assert cfg["enabled"] is True and cfg["keep"] == 7
    scheduler._maybe_backup()              # must not raise
    assert backups == [1]                  # the defaults still back up


def test_malformed_backup_block_warns_once(sched_env, monkeypatch):
    scheduler, _ = sched_env
    warnings = []

    class StubLogger:
        def warning(self, msg, *args, **kwargs):
            warnings.append(msg)

    # Checks the emission directly with a stub logger.
    monkeypatch.setitem(scheduler.__dict__, "logger", StubLogger())
    monkeypatch.setitem(core.__dict__, "config", {"database": {"backup": True}})
    scheduler._backup_cfg()
    scheduler._backup_cfg()
    assert sum("'database.backup' is not a mapping" in w for w in warnings) == 1


def test_scheduler_loop_keeps_ticking_after_a_backup_check_fails(sched_env, monkeypatch):
    scheduler, _ = sched_env
    monkeypatch.setitem(core.__dict__, "config", {"database": None})

    def boom():
        raise RuntimeError("backup exploded")

    monkeypatch.setitem(scheduler.__dict__, "_maybe_backup", boom)
    ticks = []

    class OneTick:
        """First wait() passes a tick; the second stops the loop."""
        n = 0

        def wait(self, timeout):
            OneTick.n += 1
            return OneTick.n > 1

    monkeypatch.setitem(scheduler.__dict__, "_scheduler_stop", OneTick())
    monkeypatch.setattr(pipeline, "due_feeds", lambda db, secs: ticks.append(1) or [])
    scheduler._scheduler_loop()           # returns; does not raise out of the loop
    assert ticks == [1]                   # the due-check still ran after the backup failure


# ---- 4. the one-time migration VACUUM is retry-safe -------------------------

def _bloat(path):
    """Leave free pages in the file: a dropped table's pages sit on the
    freelist until a VACUUM reclaims them."""
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE junk (x TEXT)")
    conn.executemany("INSERT INTO junk VALUES (?)", [("x" * 512,)] * 4000)
    conn.commit()
    conn.execute("DROP TABLE junk")
    conn.commit()
    conn.close()


def _freelist(path):
    conn = sqlite3.connect(path)
    try:
        return conn.execute("PRAGMA freelist_count").fetchone()[0]
    finally:
        conn.close()


def _setting(path, key):
    conn = sqlite3.connect(path)
    try:
        row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        return row[0] if row else None
    finally:
        conn.close()


def test_pending_vacuum_runs_on_the_next_start_and_clears_its_marker(tmp_path):
    path = str(tmp_path / "t.db")
    Database(path)
    _bloat(path)
    assert _freelist(path) > 0
    conn = sqlite3.connect(path)
    conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('vacuum_pending', '1')")
    conn.commit()
    conn.close()

    Database(path)                                  # the next start

    assert _freelist(path) == 0                     # VACUUM ran
    assert _setting(path, "vacuum_pending") is None  # marker cleared after it


def test_without_the_marker_a_start_does_not_vacuum(tmp_path):
    # Control: the VACUUM is one-time. A normal start leaves free pages alone.
    path = str(tmp_path / "t.db")
    Database(path)
    _bloat(path)
    Database(path)
    assert _freelist(path) > 0


def test_a_crash_during_the_vacuum_is_retried_on_the_next_start(tmp_path, monkeypatch):
    path = str(tmp_path / "t.db")
    Database(path)
    _bloat(path)
    conn = sqlite3.connect(path)
    conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('vacuum_pending', '1')")
    conn.commit()
    conn.close()

    class CrashOnVacuum:
        """Connection proxy: the process 'dies' inside VACUUM."""

        def __init__(self, inner):
            self._inner = inner

        def __getattr__(self, name):
            return getattr(self._inner, name)

        def execute(self, sql, *args):
            if sql.strip().upper().startswith("VACUUM"):
                raise RuntimeError("killed during VACUUM")
            return self._inner.execute(sql, *args)

    real = Database._get_connection
    monkeypatch.setattr(Database, "_get_connection",
                        lambda self, any_thread=False: CrashOnVacuum(real(self, any_thread)))
    with pytest.raises(RuntimeError, match="killed during VACUUM"):
        Database(path)
    monkeypatch.setattr(Database, "_get_connection", real)   # restore the real one

    assert _freelist(path) > 0                      # the crash left the file bloated
    assert _setting(path, "vacuum_pending") == "1"  # ...and the marker for the retry

    Database(path)                                  # the restart
    assert _freelist(path) == 0
    assert _setting(path, "vacuum_pending") is None
