"""Current-listing votes (v2.5.0, opt-in: scoring.votes_require_current_listing):
a feed corroborates an indicator only while the feed still lists it.
Attribution history is kept; only the vote goes."""
import pytest

from threatfeedme import pipeline
from threatfeedme.database import Database
from threatfeedme.scorer import ConfidenceScorer

X = "185.1.0.1"
TICK1 = "2026-09-01T00:00:00+00:00"
TICK2 = "2026-09-02T00:00:00+00:00"
ON = {"scoring": {"votes_require_current_listing": True}}


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


def _rescore(db, scoring=None):
    ConfidenceScorer(db, {"scoring": scoring if scoring is not None
                          else ON["scoring"]}).recalculate_all_scores()


def test_a_feed_that_drops_an_ip_stops_voting_for_it(db):
    _rescore(db)
    before = _votes(db)
    assert before > 1.8                            # two independent witnesses

    db.update_source_sightings("feed_b", _own("185.3.0"), TICK2)   # B drops X
    _rescore(db)

    assert _votes(db) == pytest.approx(1.0)        # only A still lists it
    # history is kept: B is still recorded as having reported X
    assert "feed_b" in db.get_indicator(X).sources


def test_a_feed_with_no_membership_state_keeps_its_votes(tmp_path):
    # never cleanly fetched since the transition log shipped (or 'manual'):
    # attribution history is the only evidence, so it still counts
    d = Database(str(tmp_path / "t.db"))
    for name, prefix in (("feed_a", "185.2.0"), ("feed_b", "185.3.0")):
        d.add_indicators_bulk([(v, {}) for v in sorted(_own(prefix) | {X})], source=name)
    _rescore(d)
    assert _votes(d) > 1.8


def test_config_switch_restores_permanent_credit(db):
    db.update_source_sightings("feed_b", _own("185.3.0"), TICK2)
    _rescore(db, {"votes_require_current_listing": False})
    assert _votes(db) > 1.8
    _rescore(db, {})                               # the shipped default: off
    assert _votes(db) > 1.8


def test_single_ip_scoring_uses_current_listings_too(db):
    db.update_source_sightings("feed_b", _own("185.3.0"), TICK2)
    _rescore(db)
    stored_tier = db.get_indicator(X).tier
    _score, tier = ConfidenceScorer(db, ON).calculate_score(X)
    assert tier == stored_tier


def test_a_dropped_netblock_stops_corroborating_the_ips_inside_it(db):
    net = {"185.2.0.0"}
    db.add_indicators_bulk([("185.2.0.0", {"cidr": "185.2.0.0/24"})], source="feed_c")
    db.update_source_sightings("feed_c", net, TICK1)
    _rescore(db)
    with_block = _votes(db, "185.2.0.5")
    assert with_block > 1.5                        # A + C's /24

    db.update_source_sightings("feed_c", set(), TICK2)   # C drops the block
    _rescore(db)
    assert _votes(db, "185.2.0.5") < with_block


def test_a_feed_whose_list_empties_votes_for_nothing(db):
    # no state rows left must NOT read as "never fetched" (history fallback)
    db.update_source_sightings("feed_b", set(), TICK2)
    _rescore(db)
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
    db.remove_feed("feed_b")
    assert db.source_state_count("feed_b") == 0
    with db._cursor() as cur:
        assert cur.execute("SELECT 1 FROM source_seeded WHERE source_name = 'feed_b'"
                           ).fetchone() is None


def test_a_pure_leave_moves_the_rescore_gate(db):
    # a leave deletes no attribution row, so without the membership stamp the
    # refresh would skip the rescore that drops the stale vote
    before = pipeline.scoring_input_key(db, ON)
    db.update_source_sightings("feed_b", _own("185.3.0"), TICK2)
    assert pipeline.scoring_input_key(db, ON) != before


def test_with_the_switch_off_churn_alone_does_not_rescore(db):
    before = pipeline.scoring_input_key(db, {})
    db.update_source_sightings("feed_b", _own("185.3.0"), TICK2)
    assert pipeline.scoring_input_key(db, {}) == before


def test_an_unchanged_refetch_does_not_move_the_gate(db):
    before = pipeline.scoring_input_key(db, ON)
    db.update_source_sightings("feed_b", _own("185.3.0") | {X}, TICK2)
    assert pipeline.scoring_input_key(db, ON) == before
