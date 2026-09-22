"""Retention on a 304 (v2.4.19): an unchanged fetch keeps current only what the
feed STILL lists. It used to touch everything the feed ever listed (add-only
attribution), so dropped IPs never aged out and kept their stale vote."""
from threatfeedme.database import Database

OLD = "2026-01-01T00:00:00+00:00"


def _age_everything(db):
    with db._cursor() as cur:
        cur.execute("UPDATE indicators SET last_seen = ?", (OLD,))


def _last_seen(db, ip):
    return str(db.get_indicator(ip).last_seen)


def test_304_touch_keeps_only_currently_listed_ips(tmp_path):
    db = Database(str(tmp_path / "t.db"))
    db.add_indicators_bulk([("185.1.1.1", {}), ("185.1.1.2", {}),
                            ("185.1.1.3", {})], source="feedA")
    # first clean fetch listed all three; the next dropped .3
    db.update_source_sightings("feedA", {"185.1.1.1", "185.1.1.2", "185.1.1.3"},
                               "2026-01-01T00:00:00+00:00")
    db.update_source_sightings("feedA", {"185.1.1.1", "185.1.1.2"},
                               "2026-01-02T00:00:00+00:00")
    _age_everything(db)

    touched = db.touch_feed_indicators("feedA")   # the feed now answers 304

    assert touched == 2
    assert not _last_seen(db, "185.1.1.1").startswith("2026-01-01")
    assert not _last_seen(db, "185.1.1.2").startswith("2026-01-01")
    # dropped by the feed: must be left to age out, not kept alive by the 304
    assert _last_seen(db, "185.1.1.3").startswith("2026-01-01")


def test_304_touch_falls_back_when_feed_state_was_never_seeded(tmp_path):
    # a feed that has only ever answered 304 since the transition log shipped
    # has no source_state; refreshing nothing would age out all it still serves
    db = Database(str(tmp_path / "t.db"))
    db.add_indicators_bulk([("185.2.2.1", {}), ("185.2.2.2", {})], source="feedB")
    _age_everything(db)

    assert db.touch_feed_indicators("feedB") == 2
    assert not _last_seen(db, "185.2.2.1").startswith("2026-01-01")


def test_304_touch_does_not_touch_other_feeds_ips(tmp_path):
    db = Database(str(tmp_path / "t.db"))
    db.add_indicators_bulk([("185.3.3.1", {})], source="feedA")
    db.add_indicators_bulk([("185.3.3.9", {})], source="feedC")
    db.update_source_sightings("feedA", {"185.3.3.1"}, "2026-01-01T00:00:00+00:00")
    _age_everything(db)

    db.touch_feed_indicators("feedA")

    assert _last_seen(db, "185.3.3.9").startswith("2026-01-01")


def test_shrink_guard_holds_back_a_collapsed_fetch(tmp_path):
    """An HTML error page or empty body parses to ~nothing; recording that as
    churn fakes a mass leave, then a mass return (= fake predictor labels)."""
    from threatfeedme.pipeline import _collapsed_fetch, _COLLAPSE_ACCEPT_AFTER
    db = Database(str(tmp_path / "t.db"))
    members = {f"185.4.{i // 250}.{i % 250 + 1}" for i in range(400)}
    db.update_source_sightings("feedA", members, "2026-01-01T00:00:00+00:00")

    # a collapse is held back for the first few fetches...
    for _ in range(_COLLAPSE_ACCEPT_AFTER - 1):
        assert _collapsed_fetch(db, "feedA", 3) is True
    # ...and accepted once it persists, so a real shrink can't freeze state
    assert _collapsed_fetch(db, "feedA", 3) is False


def test_shrink_guard_ignores_normal_and_small_feeds(tmp_path):
    from threatfeedme.pipeline import _collapsed_fetch
    db = Database(str(tmp_path / "t.db"))
    db.update_source_sightings("big", {f"185.5.0.{i}" for i in range(1, 201)},
                               "2026-01-01T00:00:00+00:00")
    assert _collapsed_fetch(db, "big", 150) is False       # ordinary churn
    db.update_source_sightings("tiny", {"185.6.0.1", "185.6.0.2"},
                               "2026-01-01T00:00:00+00:00")
    assert _collapsed_fetch(db, "tiny", 0) is False        # too small to judge
