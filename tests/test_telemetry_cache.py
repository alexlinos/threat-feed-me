"""Dashboard aggregates are cached until the corpus moves (v2.5.0: ~3.8 s of
full scans per dashboard view at 890k indicators before)."""
from threatfeedme import telemetry
from threatfeedme.database import Database
from threatfeedme.models import FeedSource, FeedType


def _db(tmp_path):
    telemetry.invalidate_cache()
    d = Database(str(tmp_path / "t.db"))
    for name in ("feed_a", "feed_b"):      # telemetry lists registered feeds only
        d.add_feed(FeedSource(name=name, url=f"https://example.com/{name}.txt",
                              feed_type=FeedType.THREAT_INTEL))
    d.add_indicators_bulk([("185.1.1.1", {}), ("185.1.1.2", {})], source="feed_a")
    return d


def test_a_repeat_view_does_not_rescan(tmp_path, monkeypatch):
    db = _db(tmp_path)
    calls = []
    real = db.get_feed_overlap
    monkeypatch.setattr(db, "get_feed_overlap", lambda: calls.append(1) or real())
    telemetry.feed_telemetry(db)
    telemetry.feed_telemetry(db)
    assert calls == [1]


def test_a_corpus_change_is_visible_at_once(tmp_path):
    db = _db(tmp_path)
    before = {r["name"]: r["indicators"] for r in telemetry.feed_telemetry(db)["rows"]}
    db.add_indicators_bulk([("185.1.1.3", {})], source="feed_a")
    after = {r["name"]: r["indicators"] for r in telemetry.feed_telemetry(db)["rows"]}
    assert after.get("feed_a", 0) == before.get("feed_a", 0) + 1


def test_cached_results_are_not_mutated_between_views(tmp_path):
    db = _db(tmp_path)
    db.add_indicators_bulk([("185.1.1.1", {})], source="feed_b")      # an overlapping pair
    a = telemetry.feed_telemetry(db)
    a["overlap"].clear()                                               # a caller mangles its copy
    b = telemetry.feed_telemetry(db)
    assert b["overlap"], "the cache handed out its own objects"


def test_mid_refresh_views_reuse_the_last_numbers_and_the_warmup_rebuilds(tmp_path, monkeypatch):
    # Each feed ingested moves the corpus key, so during a multi-feed fetch
    # every click paid a ~4 s rebuild (prod, 2026-09-24). Mid-refresh the
    # page keeps its last numbers; the refresh's warm-up then rebuilds.
    from threatfeedme import scheduler
    db = _db(tmp_path)
    count = lambda: {r["name"]: r["indicators"] for r in telemetry.feed_telemetry(db)["rows"]}["feed_a"]
    assert count() == 2
    monkeypatch.setitem(scheduler._refresh_state, "running", True)
    db.add_indicators_bulk([("185.1.1.3", {})], source="feed_a")
    assert count() == 2                       # last numbers, no rebuild
    telemetry.warming.on = True
    try:
        assert count() == 3                   # the warm-up thread does rebuild
    finally:
        telemetry.warming.on = False
    assert count() == 3                       # and later views get the new numbers
