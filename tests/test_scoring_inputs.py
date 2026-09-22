"""Scoring inputs (v2.4.19): disabled feeds cast no vote, the predictor factor
is inert without a model file, and the rescore gate sees every input that
changes scores — not just corpus row counts."""
import pytest

from threatfeedme.database import Database
from threatfeedme.models import FeedSource, FeedType
from threatfeedme.pipeline import PREDICT_STAMP_KEY, scoring_input_key
from threatfeedme.scorer import ConfidenceScorer, predictor_live


def _feed(name, enabled=True, weight=1.0):
    return FeedSource(name=name, url=f"https://{name}.example/list.txt",
                      feed_type=FeedType.THREAT_INTEL, weight=weight,
                      enabled=enabled)


@pytest.fixture
def db(tmp_path):
    d = Database(str(tmp_path / "t.db"))
    d.add_feed(_feed("feed_on"))
    d.add_feed(_feed("feed_off"))
    # shared IP 185.1.1.1; each feed also has IPs of its own, so the pair's
    # overlap is partial and a second vote is worth something
    d.add_indicators_bulk([(ip, {}) for ip in ("185.1.1.1", "185.1.1.2",
                                               "185.1.1.3", "185.1.1.4")],
                          source="feed_on")
    d.add_indicators_bulk([(ip, {}) for ip in ("185.1.1.1", "185.2.2.2",
                                               "185.2.2.3", "185.2.2.4")],
                          source="feed_off")
    return d


def _votes(db, ip):
    return db.get_indicator(ip).effective_votes


def test_a_disabled_feed_casts_no_vote(db):
    ConfidenceScorer(db, {}).recalculate_all_scores()
    corroborated = _votes(db, "185.1.1.1")
    single = _votes(db, "185.1.1.2")
    assert corroborated > single            # two feeds agree while both enabled

    db.add_feed(_feed("feed_off", enabled=False))
    ConfidenceScorer(db, {}).recalculate_all_scores()
    # with feed_off disabled, the shared IP has exactly one witness left
    assert _votes(db, "185.1.1.1") == pytest.approx(single)
    # an IP only the disabled feed reported has no evidence at all
    assert _votes(db, "185.2.2.2") == 0.0


def test_predictor_is_inert_without_a_model_file(tmp_path):
    model = tmp_path / "model.txt"
    cfg = {"predictor": {"enabled": True, "model_path": str(model)},
           "scoring": {"predictor_weight": 0.10}}
    assert predictor_live(cfg) is False
    # no renormalization: the shipped enabled:true used to scale every
    # fresh install's scores down ~9% for a factor that contributes nothing
    assert ConfidenceScorer(None, cfg).weights["predictor"] == 0.0

    model.write_text("tree\n")
    assert predictor_live(cfg) is True
    assert ConfidenceScorer(None, cfg).weights["predictor"] > 0.0

    cfg["predictor"]["enabled"] = False
    assert predictor_live(cfg) is False


def test_rescore_key_is_stable_when_nothing_changed(db):
    cfg = {"scoring": {"source_weight": 0.45}}
    assert scoring_input_key(db, cfg) == scoring_input_key(db, cfg)


@pytest.mark.parametrize("change", [
    "scoring_config", "feed_weight", "feed_toggle", "whitelist", "predict_pass",
])
def test_rescore_key_moves_on_every_scoring_input(db, change):
    cfg = {"scoring": {"source_weight": 0.45}}
    before = scoring_input_key(db, cfg)
    if change == "scoring_config":          # the documented "force a recalc" gotcha
        cfg = {"scoring": {"source_weight": 0.60}}
    elif change == "feed_weight":
        db.add_feed(_feed("feed_on", weight=0.5))
    elif change == "feed_toggle":
        db.add_feed(_feed("feed_off", enabled=False))
    elif change == "whitelist":
        db.add_to_whitelist("185.1.1.1", reason="internal", added_by="test")
    elif change == "predict_pass":
        db.set_setting(PREDICT_STAMP_KEY, "2026-09-22T06:00:00+00:00")
    assert scoring_input_key(db, cfg) != before, change


def test_corpus_key_catches_an_equal_add_and_purge(db):
    # counts alone let one add + one purge cancel out and skip a needed rescore
    before = db.corpus_change_key()
    db.add_indicators_bulk([("185.9.9.9", {})], source="feed_on")
    with db._cursor() as cur:
        cur.execute("DELETE FROM indicators WHERE ip = '185.1.1.4'")
    assert db.corpus_change_key() != before
