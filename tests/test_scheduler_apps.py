"""The application-list pass runs on its own thread (2.7): a slow vendor must
never stall the scheduler tick that refreshes the threat feeds, and a tick
that finds the previous pass still running skips instead of stacking threads.

Offline per repo rule: the pass itself is a fake controlled by Events. The
scheduler module is taken at test time (other suites purge and re-import
threatfeedme)."""
import importlib
import os
import sys
import threading
import time

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))


@pytest.fixture
def sched():
    sched = importlib.import_module("threatfeedme.scheduler")
    sched._apps_pass_running = False
    yield sched
    sched._apps_pass_running = False


def _wait_until_apps_pass_clears(sched):
    deadline = time.monotonic() + 5
    while sched._apps_pass_running:
        if time.monotonic() >= deadline:
            pytest.fail("Application-list pass flag did not clear in time")
        time.sleep(0.01)


def test_start_returns_immediately_while_the_pass_runs(sched, monkeypatch):
    started = threading.Event()
    release = threading.Event()

    def fake_refresh():
        started.set()
        assert release.wait(5) is True

    monkeypatch.setattr(sched, "_refresh_application_lists", fake_refresh)

    assert sched.start_application_lists_pass() is True
    assert started.wait(5) is True
    assert sched._apps_pass_running is True      # still running, yet we returned
    release.set()
    _wait_until_apps_pass_clears(sched)


def test_a_second_start_is_skipped_while_one_runs(sched, monkeypatch):
    entered = threading.Event()
    block = threading.Event()
    calls = []

    def fake_refresh():
        calls.append(True)
        entered.set()
        assert block.wait(5) is True

    monkeypatch.setattr(sched, "_refresh_application_lists", fake_refresh)

    assert sched.start_application_lists_pass() is True
    assert entered.wait(5) is True
    assert sched.start_application_lists_pass() is False
    assert len(calls) == 1

    block.set()
    _wait_until_apps_pass_clears(sched)


def test_flag_clears_after_a_failing_pass(sched, monkeypatch):
    calls = []

    def fake_refresh():
        calls.append(True)
        raise RuntimeError("boom")

    monkeypatch.setattr(sched, "_refresh_application_lists", fake_refresh)

    assert sched.start_application_lists_pass() is True
    _wait_until_apps_pass_clears(sched)
    assert len(calls) == 1

    assert sched.start_application_lists_pass() is True
    _wait_until_apps_pass_clears(sched)
    assert len(calls) == 2
