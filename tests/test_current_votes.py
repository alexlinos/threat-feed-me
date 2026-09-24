"""Current-listing votes with a grace window (v2.5.0): a feed corroborates an
indicator while it lists it and for scoring.vote_grace_days after it drops it.
Attribution history is kept; only the vote goes."""
from datetime import datetime, timedelta, timezone

import pytest

from threatfeedme import pipeline
from threatfeedme.database import Database
from threatfeedme.scorer import ConfidenceScorer, current_votes_enabled, vote_grace_days

X = "185.1.0.1"
NOW = datetime.now(timezone.utc)
TICK1 = (NOW - timedelta(hours=2)).isoformat()
TICK2 = (NOW - timedelta(hours=1)).isoformat()


def _cfg(grace=3, on=True):
    return {"scoring": {"votes_require_current_listing": on, "vote_grace_days": grace}}


def _own(prefix, n=20):
    return {f"{prefix}.{i}" for i in range(1, n + 1)}


@pytest.fixture
def db(tmp_path):
    """Two INDEPENDENT feeds (mostly their own IPs) that both list X, both
    seeded from a clean fetch — so X starts with ~2 effective votes."""
    d = Database(str(tmp_path / "t.db"))
    for name, prefix in (("feed_a", "185.2.0"), ("feed_b", "185.3.0")):
        members = _own(prefix) | {X}
        d.add_indicators_bulk([(v, {}) for v in sorted(members)], source=name)
        d.update_source_sightings(name, members, TICK1)
    return d


def _votes(db, ip=X):
    return db.get_indicator(ip).effective_votes


def _recalc(db, cfg=None):
    pipeline.recalculate(db, cfg if cfg is not None else _cfg())


def _drop_x_from_b(db):
    db.update_source_sightings("feed_b", _own("185.3.0"), TICK2)


def _age_drops(db, days):
    old = (NOW - timedelta(days=days)).isoformat()
    with db._cursor() as cur:
        cur.execute("UPDATE source_left SET left_at = ?", (old,))


# ---- the grace --------------------------------------------------------------

def test_a_dropped_ip_keeps_the_vote_inside_the_grace(db):
    _drop_x_from_b(db)
    _recalc(db)
    assert _votes(db) > 1.8                        # dropped an hour ago: still counts


def test_the_vote_ends_when_the_grace_expires(db):
    _drop_x_from_b(db)
    _age_drops(db, 4)                              # dropped four days ago
    _recalc(db)
    assert _votes(db) == pytest.approx(1.0)        # only A still lists it
    assert "feed_b" in db.get_indicator(X).sources  # history is kept


def test_zero_grace_is_a_hard_cut(db):
    _drop_x_from_b(db)
    _recalc(db, _cfg(grace=0))
    assert _votes(db) == pytest.approx(1.0)


def test_coming_back_on_the_list_clears_the_grace_clock(db):
    _drop_x_from_b(db)
    db.update_source_sightings("feed_b", _own("185.3.0") | {X}, NOW.isoformat())
    _age_drops(db, 4)                              # would expire X if still pending
    _recalc(db)
    assert _votes(db) > 1.8


def test_an_expiry_moves_the_rescore_gate(db):
    # an expiry changes votes without touching any attribution row
    _drop_x_from_b(db)
    _age_drops(db, 4)
    before = pipeline.scoring_input_key(db, _cfg())
    assert db.prune_left_memberships(3) == 1
    assert pipeline.scoring_input_key(db, _cfg()) != before


def test_upgrade_backfills_recent_drop_times_from_the_churn_log(tmp_path):
    path = str(tmp_path / "t.db")
    d = Database(path)
    d.update_source_sightings("feed_a", {X, "185.2.0.1"}, TICK1)
    d.update_source_sightings("feed_a", {"185.2.0.1"}, TICK2)     # X left (logged)
    with d._cursor() as cur:                       # a 2.4.x DB: no source_left
        cur.execute("DROP TABLE source_left")
    d2 = Database(path)
    with d2._cursor() as cur:
        rows = cur.execute("SELECT source_name, ip, left_at FROM source_left").fetchall()
    # the churn log keeps whole seconds, so the recovered drop time does too
    assert [(r[0], r[1]) for r in rows] == [("feed_a", X)]
    assert rows[0][2] == datetime.fromisoformat(TICK2).strftime("%Y-%m-%dT%H:%M:%S+00:00")


@pytest.mark.parametrize("raw, expected", [
    (None, 3.0), ("2", 2.0), (0, 0.0), (-1, 3.0), ("abc", 3.0),
    (float("nan"), 3.0), (400, 30.0)])
def test_grace_config_is_parsed_defensively(raw, expected):
    cfg = {"scoring": {}} if raw is None else {"scoring": {"vote_grace_days": raw}}
    assert vote_grace_days(cfg) == expected


# ---- current-listing rules (grace 0 isolates them) ---------------------------

def test_the_shipped_default_is_on():
    assert current_votes_enabled({}) is True


def test_a_feed_with_no_membership_state_keeps_its_votes(tmp_path):
    # never cleanly fetched since the transition log shipped (or 'manual'):
    # attribution history is the only evidence, so it still counts
    d = Database(str(tmp_path / "t.db"))
    for name, prefix in (("feed_a", "185.2.0"), ("feed_b", "185.3.0")):
        d.add_indicators_bulk([(v, {}) for v in sorted(_own(prefix) | {X})], source=name)
    _recalc(d, _cfg(grace=0))
    assert _votes(d) > 1.8


def test_switching_it_off_restores_permanent_credit(db):
    _drop_x_from_b(db)
    _recalc(db, _cfg(grace=0, on=False))
    assert _votes(db) > 1.8


def test_single_ip_scoring_agrees_with_the_rescore(db):
    _drop_x_from_b(db)
    _recalc(db, _cfg(grace=0))
    stored_tier = db.get_indicator(X).tier
    _score, tier = ConfidenceScorer(db, _cfg(grace=0)).calculate_score(X)
    assert tier == stored_tier


def test_a_dropped_netblock_stops_corroborating_the_ips_inside_it(db):
    db.add_indicators_bulk([("185.2.0.0", {"cidr": "185.2.0.0/24"})], source="feed_c")
    db.update_source_sightings("feed_c", {"185.2.0.0"}, TICK1)
    _recalc(db, _cfg(grace=0))
    with_block = _votes(db, "185.2.0.5")
    assert with_block > 1.5                        # A + C's /24

    db.update_source_sightings("feed_c", set(), TICK2)   # C drops the block
    _recalc(db, _cfg(grace=0))
    assert _votes(db, "185.2.0.5") < with_block


def test_a_feed_whose_list_empties_votes_for_nothing(db):
    # no state rows left must NOT read as "never fetched" (history fallback)
    db.update_source_sightings("feed_b", set(), TICK2)
    _recalc(db, _cfg(grace=0))
    assert _votes(db) == pytest.approx(1.0)
    assert _votes(db, "185.3.0.1") == 0.0


def test_a_304_on_an_emptied_feed_does_not_revive_its_history(db):
    db.update_source_sightings("feed_b", set(), TICK2)
    assert db.touch_feed_indicators("feed_b") == 0


def test_upgrade_backfills_seeded_sources(tmp_path):
    # a 2.4.x DB has source_state but no source_seeded table
    path = str(tmp_path / "t.db")
    d = Database(path)
    d.update_source_sightings("feed_a", {X}, TICK1)
    with d._cursor() as cur:
        cur.execute("DROP TABLE source_seeded")
    d2 = Database(path)
    with d2._cursor() as cur:
        rows = cur.execute("SELECT source_name FROM source_seeded").fetchall()
    assert [r[0] for r in rows] == ["feed_a"]


def test_removing_a_feed_clears_its_membership(db):
    _drop_x_from_b(db)
    db.remove_feed("feed_b")
    assert db.source_state_count("feed_b") == 0
    with db._cursor() as cur:
        for table in ("source_seeded", "source_left"):
            assert cur.execute(f"SELECT 1 FROM {table} WHERE source_name = 'feed_b'"
                               ).fetchone() is None


# ---- the rescore gate --------------------------------------------------------

def test_a_pure_leave_moves_the_rescore_gate(db):
    # a leave deletes no attribution row, so without the membership stamp the
    # refresh would skip the rescore that starts the vote's grace clock
    before = pipeline.scoring_input_key(db, _cfg())
    _drop_x_from_b(db)
    assert pipeline.scoring_input_key(db, _cfg()) != before


def test_with_the_switch_off_churn_alone_does_not_rescore(db):
    before = pipeline.scoring_input_key(db, _cfg(on=False))
    _drop_x_from_b(db)
    assert pipeline.scoring_input_key(db, _cfg(on=False)) == before


def test_an_unchanged_refetch_does_not_move_the_gate(db):
    before = pipeline.scoring_input_key(db, _cfg())
    db.update_source_sightings("feed_b", _own("185.3.0") | {X}, TICK2)
    assert pipeline.scoring_input_key(db, _cfg()) == before
