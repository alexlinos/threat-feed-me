"""Shrink-guard and membership-baseline semantics (pipeline.py, database.py).

Each group pins one reviewer-confirmed bug:
1. a fetch held back by the shrink guard kept its ETag/Last-Modified, so the
   next refresh's 304 touched the OLD membership and the streak never advanced;
2. a collapse accepted to a non-empty stub, then recovered, wrote a mass leave
   and a mass return into the churn log;
3. a URL change kept the old list's membership baseline.
"""
import sqlite3

import pytest
import requests

from threatfeedme import pipeline
from threatfeedme.database import Database
from threatfeedme.feed_ingestor import FeedIngestor
from threatfeedme.models import FeedSource, FeedType


class _FakeResponse:
    def __init__(self, status_code=200, headers=None, text=""):
        self.status_code = status_code
        self.headers = headers or {}
        self.text = text
        self.encoding = "utf-8"

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.exceptions.HTTPError(f"HTTP {self.status_code}")

    def close(self):
        pass

    def iter_content(self, chunk_size=65536, decode_unicode=False):
        if self.text:
            yield self.text.encode(self.encoding or "utf-8")


def _stub_get(monkeypatch, responses):
    """Script requests.get with a fixed response sequence; returns the calls."""
    calls = []
    seq = iter(responses)

    def fake_get(url, headers=None, timeout=None, **kwargs):
        calls.append({"url": url, "headers": dict(headers or {})})
        return next(seq)

    monkeypatch.setattr("threatfeedme.feed_ingestor.requests.get", fake_get)
    return calls


def _http_feed(name="f"):
    return FeedSource(name=name, url="http://feeds.example/list.txt",
                      feed_type=FeedType.CUSTOM, weight=0.6, update_interval=3600)


def _config(tmp_path):
    return {"scoring": {}, "retention": {"max_age_days": 14},
            "output": {"base_dir": str(tmp_path / "out")}}


def _body(n, prefix="185.7.0"):
    return "\n".join(f"{prefix}.{i}" for i in range(1, n + 1)) + "\n"


def _refresh(db, ing, feed, config):
    """One refresh of one feed: ingest, then the post-fetch churn step that
    run_refresh performs (shrink guard included). Returns the fetch result."""
    ing.ingested_values.clear()
    count = ing.ingest_feed(feed)
    res = {feed.name: {"status": "success", "count": count}}
    pipeline._after_fetch(db, config, res, dict(ing.ingested_values))
    return res[feed.name]


def _churn_counts(db):
    conn = sqlite3.connect(db.db_path)
    try:
        conn.execute("ATTACH DATABASE ? AS churn", (db.churn_path,))
        return conn.execute(
            "SELECT COALESCE(SUM(present = 0), 0), COALESCE(SUM(present = 1), 0) "
            "FROM churn.sightings").fetchone()
    finally:
        conn.close()


# ---- 1. a held-back fetch must not keep its validators ----------------------

def test_held_back_fetch_clears_validators_and_collapse_is_accepted_on_third(
        tmp_path, monkeypatch):
    db = Database(str(tmp_path / "t.db"))
    feed = _http_feed()
    db.add_feed(feed)
    config = _config(tmp_path)
    calls = _stub_get(monkeypatch, [
        _FakeResponse(200, {"ETag": '"v1"'}, _body(200)),        # full list
        _FakeResponse(200, {"ETag": '"stub"'}, "1.2.3.4\n"),     # held back
        _FakeResponse(200, {"ETag": '"stub"'}, "1.2.3.4\n"),     # held back
        _FakeResponse(200, {"ETag": '"stub"'}, "1.2.3.4\n"),     # accepted
    ])
    ing = FeedIngestor(db)

    _refresh(db, ing, feed, config)
    assert db.get_feed_http_cache("f") == ('"v1"', None)

    held = _refresh(db, ing, feed, config)
    assert "churn not recorded" in held["warning"]
    # Without this the next refresh would send If-None-Match, get a 304 and
    # keep voting for the 200-entry list the streak never got past.
    assert db.get_feed_http_cache("f") == (None, None)
    assert db.get_setting("shrink_guard:f") == "1"

    _refresh(db, ing, feed, config)                              # held back again
    assert "If-None-Match" not in calls[2]["headers"]
    assert db.get_setting("shrink_guard:f") == "2"
    assert db.get_feed_http_cache("f") == (None, None)

    # The third consecutive collapse is the accepted one: the guard's
    # threshold is _COLLAPSE_ACCEPT_AFTER = 3, and it holds the first two.
    accepted = _refresh(db, ing, feed, config)
    assert accepted.get("warning") is None
    assert db.source_state_count("f") == 1
    assert db.get_setting("shrink_guard:f") == "0"
    assert len(calls) == 4
