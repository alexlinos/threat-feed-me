"""Server side of the dashboard's URL builder (2.7): its count probe must not
be recorded as a poll. The "last polled by" line under each list URL is the
only proof a firewall really pulls it, so a probe from the operator's own
browser showing up there would defeat it.

Offline per repo rule; routers are called directly (repo pattern). Every
module is taken at test time, never at import: other suites purge and
re-import threatfeedme, and a module object held from import time would be
a stale copy the routers no longer use (CLAUDE.md test-isolation traps)."""
import importlib
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))


class FakeRequest:
    def __init__(self, headers=None):
        self.headers = headers or {}
        self.query_params = {}


@pytest.fixture
def live(tmp_path, monkeypatch):
    """The live routers, a fresh DB behind them, and polls.record captured."""
    apps_r = importlib.import_module("threatfeedme.routers.applications")
    feeds_r = importlib.import_module("threatfeedme.routers.indicators")
    polls = importlib.import_module("threatfeedme.polls")
    Database = importlib.import_module("threatfeedme.database").Database
    d = Database(str(tmp_path / "t.db"))
    d.add_application_list("acme", "https://vendor.example/acme.txt",
                           "list", "", 3600, 8, 20, 50.0)
    d.replace_entries("acme", ["198.51.100.1"], 1, 0, [], [])
    # setitem on __dict__, never setattr: core.__getattr__ lazy-inits on a probe.
    for r in (apps_r, feeds_r):
        monkeypatch.setitem(r.core.__dict__, "db", d)
    feeds_r.feed_cache.invalidate()
    calls = []
    monkeypatch.setattr(polls, "record", lambda db, key, ua: calls.append(key))
    yield apps_r, feeds_r, calls
    feeds_r.feed_cache.invalidate()


PROBE = {"x-tfm-probe": "1"}     # Starlette headers are case-insensitive; the fake is not


def test_list_probe_is_not_a_poll(live):
    apps_r, _feeds_r, recorded = live
    apps_r.list_txt("acme", FakeRequest(PROBE), limit=1)
    assert recorded == []
    apps_r.list_txt("acme", FakeRequest(), limit=None)
    assert recorded == ["lists/acme.txt"]


def test_feed_probe_is_not_a_poll(live):
    _apps_r, feeds_r, recorded = live
    resp = feeds_r.feed_txt("high", FakeRequest(PROBE), limit=1, hosts=None, family=None)
    assert recorded == [] and resp.headers["X-Entry-Count"] == "0"
    feeds_r.feed_txt("high", FakeRequest(), limit=None, hosts=None, family=None)
    assert recorded == ["high.txt"]
