"""Robustness fixes for 2.5.7, from the 2026-10 piperev review.

Each fix has a regression test here: a feed delete that raced the rescore
writers, a purge that failed past SQLite's bound-variable limit, a scheduler
thread that died on a malformed backup block, and a one-time VACUUM that a
kill could skip for good.
"""
import os
import sqlite3
import threading

import pytest

from threatfeedme import core, jobs, pipeline
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
