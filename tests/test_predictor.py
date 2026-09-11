"""Task 6 tests: predictor module + FeatureBuilder.

The predictor ships dark: these tests cover feature construction from the
transition-format sightings log, graceful behavior without a model, and the
metadata-persistence path. No training here — that's Task 7.
"""
from datetime import datetime, timedelta, timezone

import pytest

from threatfeedme.database import Database
from threatfeedme.predictor import FEATURE_NAMES, FeatureBuilder, Predictor


def _ticks(n, start_hour=0):
    base = datetime(2026, 8, 1, tzinfo=timezone.utc) + timedelta(hours=start_hour)
    return [(base + timedelta(hours=i)).isoformat() for i in range(n)]


def _db(tmp_path):
    return Database(str(tmp_path / "pred.db"))


_SENTINEL = "192.0.2.254"  # keeps source_state non-empty between cycles


def _seed_cycle(db, ip, source, pattern, start_tick=0, stride_h=1):
    """pattern: list of 1/0 written as ticks stride_h hours apart.

    A sentinel member is seeded first so the source is never EMPTY:
    update_source_sightings treats empty state as a silent baseline, and
    without the sentinel a return after the target's leave would be
    mis-seeded instead of logged as an arrival event.

    Leave->return pairs closer than CHURN_MIN_GAP_H (6h) count as
    cadence noise, not churn: use stride_h >= 6 for churn-positive patterns.
    """
    base = datetime(2026, 8, 1, tzinfo=timezone.utc)
    ticks = [(base + timedelta(hours=(start_tick + i) * stride_h)).isoformat()
             for i in range(len(pattern))]
    db.update_source_sightings(source, {_SENTINEL}, ticks[0])
    for tick, present in zip(ticks, pattern):
        current = {_SENTINEL} | ({ip} if present else set())
        db.update_source_sightings(source, current, tick)


class TestFeatureBuilder:
    def test_feature_vector_built_from_db(self, tmp_path):
        db = _db(tmp_path)
        db.add_indicator("203.0.113.77", "honeydb_mydata")
        _seed_cycle(db, "203.0.113.77", "honeydb_mydata", [1, 0, 1])
        fb = FeatureBuilder(db, now=datetime(2026, 8, 1, 6, tzinfo=timezone.utc))
        vec = fb.build("203.0.113.77")
        assert len(vec) == len(FEATURE_NAMES) == 14
        assert fb.window_days == 14

    def test_churn_counts_and_gaps(self, tmp_path):
        db = _db(tmp_path)
        db.add_indicator("198.51.100.5", "talos")
        # 6h-stride ticks: two churn cycles, gaps exactly at the floor
        _seed_cycle(db, "198.51.100.5", "talos", [1, 0, 1, 0, 1], stride_h=6)
        now = datetime(2026, 8, 2, tzinfo=timezone.utc)
        fb = FeatureBuilder(db, now=now)
        vec = dict(zip(FEATURE_NAMES, fb.build("198.51.100.5")))
        assert vec["arrival_count"] == 3   # t0 arrival + two returns
        assert vec["leave_count"] == 2
        assert vec["churn_count"] == 2
        assert vec["churned_flag"] == 1.0
        assert vec["max_consec_churn"] == 2.0  # both returns followed leaves back-to-back
        assert vec["mean_gap_h"] == pytest.approx(6.0)
        assert vec["min_gap_h"] == pytest.approx(6.0)
        assert vec["max_gap_h"] == pytest.approx(6.0)

    def test_first_appearance_is_not_a_return(self, tmp_path):
        db = _db(tmp_path)
        db.add_indicator("192.0.2.9", "phishunt")
        # baseline seed then arrival: not churn (update_source_sightings
        # seeds state without an event on first observation)
        db.update_source_sightings("phishunt", {"192.0.2.9"}, _ticks(1)[0])
        fb = FeatureBuilder(db, now=datetime(2026, 8, 1, tzinfo=timezone.utc))
        vec = dict(zip(FEATURE_NAMES, fb.build("192.0.2.9")))
        assert vec["churn_count"] == 0.0
        assert vec["churned_flag"] == 0.0
        assert vec["arrival_count"] == 0.0  # baseline writes no rows

    def test_unknown_ip_yields_zero_row_not_crash(self, tmp_path):
        db = _db(tmp_path)
        fb = FeatureBuilder(db, now=datetime(2026, 8, 1, tzinfo=timezone.utc))
        vec = fb.build("203.0.113.250")
        assert len(vec) == 14
        assert vec[FEATURE_NAMES.index("source_count")] == 0.0

    def test_domain_value_does_not_crash_geo_features(self, tmp_path):
        db = _db(tmp_path)
        db.add_indicator("bad.example.com", "feed_x", kind="domain")
        fb = FeatureBuilder(db, now=datetime(2026, 8, 1, tzinfo=timezone.utc))
        vec = fb.build("bad.example.com")
        assert vec[FEATURE_NAMES.index("prefix_density")] == 0.0
        assert vec[FEATURE_NAMES.index("country_code")] == -1.0

    def test_prefix_density_counts_corpus_neighbors(self, tmp_path):
        db = _db(tmp_path)
        for last in (1, 2, 3):
            db.add_indicator(f"203.0.113.{last}", "talos")
        db.add_indicator("198.18.0.7", "talos")
        fb = FeatureBuilder(db, now=datetime(2026, 8, 1, tzinfo=timezone.utc))
        vec = dict(zip(FEATURE_NAMES, fb.build("203.0.113.1")))
        assert vec["prefix_density"] == 3.0  # all three share 203.0.0.0/16

    def test_multi_source_history_aggregates(self, tmp_path):
        db = _db(tmp_path)
        db.add_indicator("203.0.113.40", "talos")
        db.add_indicator("203.0.113.40", "proofpoint")
        # 6h stride so leave->return gaps meet CHURN_MIN_GAP_H
        _seed_cycle(db, "203.0.113.40", "talos", [1, 0], start_tick=0, stride_h=6)
        _seed_cycle(db, "203.0.113.40", "proofpoint", [1, 0, 1], start_tick=2, stride_h=6)
        # now past every seeded tick: the builder clamps out future events
        fb = FeatureBuilder(db, now=datetime(2026, 8, 2, tzinfo=timezone.utc))
        vec = dict(zip(FEATURE_NAMES, fb.build("203.0.113.40")))
        assert vec["source_count"] == 2.0
        # events: arrive t0, leave t6 (talos); arrive t12, leave t18, return
        # t24 (proofpoint) -> two churn cycles (t12 return closes the t6
        # leave cross-source; t24 closes t18), gaps 6h
        assert vec["churn_count"] == 2.0
        assert vec["mean_gap_h"] == pytest.approx(6.0)


class TestReviewFixes:
    """Regression pins for the 2026-09-11 Claude review findings."""

    def test_naive_now_is_coerced_to_utc(self, tmp_path):
        from datetime import datetime as dt
        db = _db(tmp_path)
        db.add_indicator("203.0.113.77", "talos")
        _seed_cycle(db, "203.0.113.77", "talos", [1, 0, 1])
        fb = FeatureBuilder(db, now=dt(2026, 8, 1, 10))  # naive
        vec = fb.build("203.0.113.77")  # must not raise TypeError
        assert len(vec) == 14

    def test_nan_predictive_score_does_not_poison(self, tmp_path):
        from threatfeedme.scorer import ConfidenceScorer
        db = _db(tmp_path)
        db.add_indicator("203.0.113.90", "talos", {"predictive_score": float("nan")})
        db.add_indicator("203.0.113.91", "talos", {})
        cfg = {"predictor": {"enabled": True},
               "scoring": {"predictor_weight": 0.08},
               "feeds": [{"name": "talos", "weight": 0.9}]}
        s = ConfidenceScorer(db, cfg)
        score, tier = s.calculate_score("203.0.113.90")
        import math
        assert math.isfinite(score)
        # approx: recency decays with wall-clock between the two calls
        assert score == pytest.approx(s.calculate_score("203.0.113.91")[0], abs=1e-6)

    def test_geo_buckets_loaded_once_per_build(self, tmp_path):
        import threatfeedme.predictor as P
        db = _db(tmp_path)
        calls = {"n": 0}
        orig = P.FeatureBuilder._geo_buckets
        def counting(self):
            calls["n"] += 1
            return orig(self)
        P.FeatureBuilder._geo_buckets = counting
        try:
            fb = P.FeatureBuilder(db)
            fb.build_many([f"203.0.{i}.1" for i in range(20)])
        finally:
            P.FeatureBuilder._geo_buckets = orig
        assert calls["n"] == 1, f"geo table loaded {calls['n']}x, expected 1"


class TestPredictor:
    def test_dark_predictor_returns_none_never_raises(self, tmp_path):
        db = _db(tmp_path)
        db.add_indicator("203.0.113.77", "talos")
        p = Predictor(db, {"predictor": {"enabled": False}})
        assert p.score("203.0.113.77") is None
        assert p.predict_and_store("203.0.113.77") is None
        ind = db.get_indicator("203.0.113.77")
        assert "predictive_score" not in ind.metadata

    def test_enabled_without_model_file_is_still_dark(self, tmp_path):
        db = _db(tmp_path)
        db.add_indicator("203.0.113.77", "talos")
        p = Predictor(db, {"predictor": {
            "enabled": True, "model_path": str(tmp_path / "nope.txt")}})
        assert not p.model_ready()
        assert p.score("203.0.113.77") is None

    def test_score_many_with_real_lightgbm_model(self, tmp_path):
        """Train a trivial in-memory booster on synthetic rows and prove the
        predict path returns floats and predict_and_store persists metadata."""
        lgb = pytest.importorskip("lightgbm")
        import numpy as np
        db = _db(tmp_path)
        rng = np.random.default_rng(7)
        X = rng.random((64, len(FEATURE_NAMES)))
        y = (X[:, 5] + rng.random(64) * 0.1 > 0.5).astype(int)
        booster = lgb.train({"verbose": -1, "num_leaves": 5, "min_data_in_leaf": 5},
                            lgb.Dataset(X, label=y), num_boost_round=3)
        model = tmp_path / "m.txt"
        booster.save_model(str(model))

        db.add_indicator("203.0.113.77", "talos")
        _seed_cycle(db, "203.0.113.77", "talos", [1, 0, 1])
        p = Predictor(db, {"predictor": {"enabled": True, "model_path": str(model)}})
        scores = p.score_many(["203.0.113.77", "203.0.113.78"])
        assert all(isinstance(v, float) for v in scores.values())
        s = p.predict_and_store("203.0.113.77")
        assert isinstance(s, float)
        ind = db.get_indicator("203.0.113.77")
        assert ind.metadata["predictive_score"] == pytest.approx(s)
