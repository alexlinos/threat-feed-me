"""Issue #10: the update checker is notification-only and silent on every
failure path. All tests are offline: the network seam is
update_checker._http_get (2.5.7 lesson — anything that opens a socket
needs an injectable seam), so no test here can reach api.github.com even
by accident.
"""
import logging
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock

import pytest
import requests

import importlib
from types import SimpleNamespace

from threatfeedme.database import Database
from threatfeedme import __version__

_LIVE = {
    "core": "threatfeedme.core",
    "scheduler": "threatfeedme.scheduler",
    "pipeline": "threatfeedme.pipeline",
    "update_checker": "threatfeedme.update_checker",
    "system_router": "threatfeedme.routers.system",
}


@pytest.fixture
def M():
    """The CURRENT module instances — the same objects the code under test
    resolves at call time. Other suites purge and re-import `threatfeedme.*`
    mid-session; a collection-time binding would patch a dead instance (and
    let the live one open a real socket)."""
    return SimpleNamespace(**{k: importlib.import_module(p) for k, p in _LIVE.items()})


@pytest.fixture
def db(tmp_path):
    return Database(str(tmp_path / "t.db"))


class Resp:
    """Minimal stand-in for a requests.Response."""

    def __init__(self, status_code=200, payload=None, bad_json=False):
        self.status_code = status_code
        self._payload = payload
        self._bad_json = bad_json

    def json(self):
        if self._bad_json:
            raise ValueError("not json")
        return self._payload


NOW = datetime(2026, 10, 25, 12, 0, tzinfo=timezone.utc)


# ---- 1. newer tag => badge data + ONE INFO log ------------------------------

def test_newer_tag_persists_state_and_logs_a_single_info(db, M, monkeypatch, caplog):
    get = Mock(return_value=Resp(payload={"tag_name": "v99.1.2"}))
    monkeypatch.setattr(M.update_checker, "_http_get", get)
    with caplog.at_level(logging.DEBUG, logger="threatfeedme.update_checker"):
        state1 = M.update_checker.check_for_updates(db, {}, now=NOW)
        assert db.get_setting(M.update_checker.LAST_CHECK_KEY) == NOW.isoformat()
        state2 = M.update_checker.check_for_updates(db, {}, now=NOW + timedelta(hours=1))
    assert state1["available"] is True and state1["latest"] == "99.1.2"
    assert state1["current"] == __version__
    # The release link is built from constants + the validated tag, never
    # from the response body.
    assert state1["release_url"] == M.update_checker.RELEASE_PAGE_BASE + "99.1.2"
    assert db.get_setting(M.update_checker.LATEST_VERSION_KEY) == "99.1.2"
    assert db.get_setting(M.update_checker.AVAILABLE_KEY) == "1"
    assert db.get_setting(M.update_checker.LAST_CHECK_KEY) == (NOW + timedelta(hours=1)).isoformat()
    infos = [r for r in caplog.records if r.levelno >= logging.INFO]
    assert len(infos) == 1, "one INFO when the newer version is FIRST seen, none per-cycle"
    assert "99.1.2" in infos[0].getMessage()
    assert state2["available"] is True  # state stays correct, log stays silent


def test_request_carries_ua_header_and_default_url(db, M, monkeypatch):
    # Patch one level deeper (requests.get) to see exactly what goes on the
    # wire; monkeypatch restores it, and the _http_get seam above is what
    # keeps every other test off the network entirely.
    get = Mock(return_value=Resp(payload={"tag_name": "v99.0.0"}))
    monkeypatch.setattr(M.update_checker.requests, "get", get)
    M.update_checker.check_for_updates(db, {}, now=NOW)
    args, kwargs = get.call_args
    assert args[0] == M.update_checker.RELEASES_URL
    assert args[0] == "https://api.github.com/repos/alexlinos/threat-feed-me/releases/latest"
    assert kwargs["timeout"] == M.update_checker.FETCH_TIMEOUT_S
    assert kwargs["headers"]["User-Agent"].startswith("ThreatFeedMe/")


def test_url_override_is_used(db, M, monkeypatch):
    get = Mock(return_value=Resp(payload={"tag_name": "v99.0.0"}))
    monkeypatch.setattr(M.update_checker, "_http_get", get)
    cfg = {"updates": {"url": "https://mirror.example.net/releases/latest"}}
    M.update_checker.check_for_updates(db, cfg, now=NOW)
    assert get.call_args_list[0][0][0] == "https://mirror.example.net/releases/latest"
    # ...but the human-facing release link still points at the public repo.
    state = M.update_checker.update_state(db, cfg)
    assert state["release_url"] == M.update_checker.RELEASE_PAGE_BASE + "99.0.0"


# ---- 2. equal / older => nothing --------------------------------------------

@pytest.mark.parametrize("tag", [__version__, "v" + __version__, "v0.0.1", "1.9.9"])
def test_equal_or_older_renders_nothing_and_logs_nothing(db, M, monkeypatch, caplog, tag):
    get = Mock(return_value=Resp(payload={"tag_name": tag}))
    monkeypatch.setattr(M.update_checker, "_http_get", get)
    with caplog.at_level(logging.DEBUG, logger="threatfeedme.update_checker"):
        state = M.update_checker.check_for_updates(db, {}, now=NOW)
    assert state["available"] is False and state["release_url"] is None
    assert db.get_setting(M.update_checker.AVAILABLE_KEY) == "0"
    assert [r for r in caplog.records if r.levelno >= logging.INFO] == []


# ---- 3. every failure path is silent ----------------------------------------

FAILURES = {
    "timeout": dict(raises=requests.Timeout("read timed out")),
    "dns": dict(raises=requests.ConnectionError("could not resolve host")),
    "refused": dict(raises=OSError("connection refused")),
    "403 rate limit": dict(resp=Resp(status_code=403)),
    "404": dict(resp=Resp(status_code=404)),
    "5xx": dict(resp=Resp(status_code=502)),
    "garbage body": dict(resp=Resp(bad_json=True)),
    "non-dict payload": dict(resp=Resp(payload=["surprise"])),
    "missing tag_name": dict(resp=Resp(payload={"name": "latest"})),
    "garbage tag: release-7": dict(resp=Resp(payload={"tag_name": "release-7"})),
    "garbage tag: v1.2": dict(resp=Resp(payload={"tag_name": "v1.2"})),
    "garbage tag: 1.2.3.4": dict(resp=Resp(payload={"tag_name": "1.2.3.4"})),
    "garbage tag: 2.6.0-rc1": dict(resp=Resp(payload={"tag_name": "2.6.0-rc1"})),
    "garbage tag: empty": dict(resp=Resp(payload={"tag_name": ""})),
    "garbage tag: non-string": dict(resp=Resp(payload={"tag_name": 42})),
}


@pytest.mark.parametrize("case", list(FAILURES), ids=list(FAILURES))
def test_failure_paths_never_raise_never_log_never_claim(db, M, monkeypatch, caplog, case):
    spec = FAILURES[case]
    if "raises" in spec:
        get = Mock(side_effect=spec["raises"])
    else:
        get = Mock(return_value=spec["resp"])
    monkeypatch.setattr(M.update_checker, "_http_get", get)
    with caplog.at_level(logging.DEBUG, logger="threatfeedme.update_checker"):
        state = M.update_checker.check_for_updates(db, {}, now=NOW)   # must not raise
        assert M.update_checker.run_due_check(db, {}, now=NOW) is None  # scheduler entry too
    assert state is None or state["available"] is False
    assert db.get_setting(M.update_checker.AVAILABLE_KEY) in (None, "0")
    # The attempt is still stamped: a down network is retried daily, not
    # every scheduler tick (no hammering GitHub from a broken install).
    assert db.get_setting(M.update_checker.LAST_CHECK_KEY) == NOW.isoformat()
    # "no error logs": nothing at INFO or above escapes on failure.
    noisy = [r for r in caplog.records if r.levelno >= logging.INFO]
    assert noisy == []


def test_garbage_tag_is_rejected_by_the_publish_guard(M):
    # Same shape as the publish workflow's ^[0-9]+\.[0-9]+\.[0-9]+$ guard,
    # with the conventional 'v' prefix accepted.
    assert M.update_checker._clean_tag("v2.6.1") == "2.6.1"
    assert M.update_checker._clean_tag(" 2.6.1 ") == "2.6.1"
    for bad in ("v2", "2.6", "2.6.1.0", "v2.6.1rc1", "ver2.6.1", "", "2.6.x",
                "v", None, 7, ["2.6.1"]):
        assert M.update_checker._clean_tag(bad) is None, bad


def test_is_newer_uses_numeric_tuple_compare(M):
    assert M.update_checker.is_newer("v2.10.0", "2.9.9")      # not string compare
    assert not M.update_checker.is_newer("v2.6.0", "2.6.0")   # equal is not newer
    assert not M.update_checker.is_newer("v1.99.99", "2.6.0")
    assert not M.update_checker.is_newer("garbage", "2.6.0")  # garbage: silence


# ---- 4. enabled: false => zero outbound calls --------------------------------

def test_disabled_makes_zero_outbound_calls(db, M, monkeypatch):
    get = Mock(side_effect=AssertionError("outbound call while disabled!"))
    monkeypatch.setattr(M.update_checker, "_http_get", get)
    cfg = {"updates": {"enabled": False}}
    assert M.update_checker.run_due_check(db, cfg, now=NOW) is None
    get.assert_not_called()
    # A malformed updates block is treated as absent (defaults), not fatal.
    assert M.update_checker.updates_enabled({"updates": "yes"}) is True
    assert M.update_checker.updates_enabled({"updates": None}) is True
    assert M.update_checker.updates_enabled({"updates": {"enabled": "false"}}) is False


def test_cadence_one_attempt_per_interval(db, M, monkeypatch):
    get = Mock(return_value=Resp(payload={"tag_name": "v99.0.0"}))
    monkeypatch.setattr(M.update_checker, "_http_get", get)
    M.update_checker.run_due_check(db, {}, now=NOW)
    assert get.call_count == 1
    # A few hours later: not due, zero calls.
    M.update_checker.run_due_check(db, {}, now=NOW + timedelta(hours=23))
    assert get.call_count == 1
    # Past the interval: one more attempt.
    M.update_checker.run_due_check(db, {}, now=NOW + timedelta(hours=25))
    assert get.call_count == 2


# ---- 5. state view / read-only exposure --------------------------------------

def test_update_state_recomputes_available_from_stored_tag(db, M, monkeypatch):
    get = Mock(return_value=Resp(payload={"tag_name": "v99.0.0"}))
    monkeypatch.setattr(M.update_checker, "_http_get", get)
    M.update_checker.check_for_updates(db, {}, now=NOW)
    assert M.update_checker.update_state(db)["available"] is True
    # A stale "1" with a tag that is no longer ahead (e.g. the install was
    # upgraded past it) reads as false: available is re-derived, never
    # trusted from settings.
    db.set_setting(M.update_checker.LATEST_VERSION_KEY, "0.0.1")
    db.set_setting(M.update_checker.AVAILABLE_KEY, "1")
    state = M.update_checker.update_state(db)
    assert state["available"] is False and state["release_url"] is None


def test_api_settings_exposes_update_readonly(db, M, monkeypatch):
    monkeypatch.setitem(M.core.__dict__, "db", db)
    monkeypatch.setitem(M.core.__dict__, "config", {})
    get = Mock(return_value=Resp(payload={"tag_name": "v99.0.0"}))
    monkeypatch.setattr(M.update_checker, "_http_get", get)
    M.update_checker.check_for_updates(db, {}, now=NOW)
    body = M.system_router.get_settings(_=None)
    upd = body["update"]
    assert upd["available"] is True
    assert upd["latest"] == "99.0.0"
    assert upd["release_url"].endswith("/releases/tag/99.0.0")


# ---- 6. scheduler hook --------------------------------------------------------

class OneTick:
    """First wait() passes a tick; the second stops the loop (pattern from
    test_robustness_2_5_7)."""
    def __init__(self):
        self.n = 0

    def wait(self, timeout):
        self.n += 1
        return self.n > 1


@pytest.fixture
def sched_env(db, M, monkeypatch):
    monkeypatch.setitem(M.core.__dict__, "db", db)
    monkeypatch.setitem(M.core.__dict__, "config", {})
    monkeypatch.setitem(M.core.__dict__, "db_path", db.db_path)
    monkeypatch.setitem(M.scheduler.__dict__, "_run_backup", lambda: "stub.db")
    monkeypatch.setattr(M.pipeline, "due_feeds", lambda db, secs: [])
    monkeypatch.setitem(M.scheduler.__dict__, "_scheduler_stop", OneTick())
    return db


def test_scheduler_tick_runs_the_update_check(sched_env, M, monkeypatch):
    ran = []
    monkeypatch.setitem(M.scheduler.__dict__, "_maybe_check_updates",
                        lambda: ran.append(1))
    M.scheduler._scheduler_loop()  # returns after one tick; must not raise
    assert ran == [1]


def test_scheduler_survives_a_failing_update_check_with_zero_error_logs(sched_env, M, monkeypatch, caplog):
    def boom():
        raise RuntimeError("checker exploded")

    monkeypatch.setitem(M.scheduler.__dict__, "_maybe_check_updates", boom)
    with caplog.at_level(logging.DEBUG, logger="threatfeedme.scheduler"):
        M.scheduler._scheduler_loop()  # does not raise out of the loop
    errors = [r for r in caplog.records if r.levelno >= logging.ERROR]
    assert errors == [], "an update-check failure must not log at error level"


def test_scheduler_loop_end_to_end_silence(db, M, monkeypatch, caplog):
    """The real path: run_due_check -> a raising network seam -> the loop
    keeps ticking, update_available stays false, zero INFO/ERROR records."""
    monkeypatch.setitem(M.core.__dict__, "db", db)
    monkeypatch.setitem(M.core.__dict__, "config", {"updates": {"enabled": True}})
    monkeypatch.setitem(M.core.__dict__, "db_path", db.db_path)
    monkeypatch.setattr(M.pipeline, "due_feeds", lambda db, secs: [])
    monkeypatch.setitem(M.scheduler.__dict__, "_scheduler_stop", OneTick())
    monkeypatch.setitem(M.scheduler.__dict__, "_run_backup", lambda: "stub.db")
    monkeypatch.setattr(M.update_checker, "_http_get",
                        Mock(side_effect=requests.ConnectionError("offline")))
    with caplog.at_level(logging.DEBUG):
        M.scheduler._scheduler_loop()
    assert db.get_setting(M.update_checker.AVAILABLE_KEY) in (None, "0")
    noisy = [r for r in caplog.records
             if r.levelno >= logging.INFO and "update" in r.name.lower()]
    assert noisy == []


# ---- identity guards (public repo: nothing identifying ships) ----------------

def test_no_identifying_literals_in_the_module(M):
    import inspect
    import re
    src = inspect.getsource(M.update_checker)
    assert not re.search(r"\b(192\.168\.\d|10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.)", src)
    assert "example.com" not in src
