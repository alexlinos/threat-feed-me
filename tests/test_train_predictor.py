"""
Task 7 tests: offline training on churn labels.

Dataset semantics are the load-bearing part (leakage control), so they are
tested directly without lightgbm; the train() smoke test is gated on the
package being importable.
"""
from datetime import datetime, timedelta, timezone

import pytest

from threatfeedme.database import Database
from threatfeedme import train_predictor as tp

BASE = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _tick(i):
    return (BASE + timedelta(hours=i)).isoformat()


def _feed(db, source, ip, present_at, absent_at=None, returned_at=None):
    """Drive source_state through explicit tick membership."""
    if absent_at is not None:
        db.update_source_sightings(source, {ip, tp_sentinel()}, _tick(present_at))
        db.update_source_sightings(source, {tp_sentinel()}, _tick(absent_at))
    if returned_at is not None:
        db.update_source_sightings(source, {ip, tp_sentinel()}, _tick(returned_at))


def tp_sentinel():
    return "192.0.2.254"


def _db(tmp_path):
    return Database(str(tmp_path / "train.db"))


class TestLabels:
    def test_gap_floor_separates_real_churn_from_cadence_noise(self, tmp_path):
        db = _db(tmp_path)
        # real churn: gone 10h
        _feed(db, "talos", "203.0.113.10", 0, 10, 20)
        # cadence artifact: gone 2h (< 6h floor)
        _feed(db, "proofpoint", "203.0.113.11", 0, 30, 32)
        first, returns, tmin, tmax = tp.collect_labels(db, set())
        assert "203.0.113.10" in returns
        assert "203.0.113.11" not in returns
        # first ROW is talos's leave at h10 (baselines write no events)
        assert tmin == BASE + timedelta(hours=10)
        assert tmax == BASE + timedelta(hours=32)

    def test_excluded_sources_drop_events_and_labels(self, tmp_path):
        db = _db(tmp_path)
        _feed(db, "talos", "203.0.113.10", 0, 10, 20)
        _feed(db, "cins_army", "203.0.113.12", 0, 10, 22)
        _, returns, _, _ = tp.collect_labels(db, {"cins_army"})
        assert set(returns) == {"203.0.113.10"}
        _, returns_all, _, _ = tp.collect_labels(db, set())
        assert "203.0.113.12" in returns_all


class TestDataset:
    def test_rolling_origin_rows_and_labels(self, tmp_path):
        db = _db(tmp_path)
        # churner: leaves at h10, returns at h30 (gap 20h >= floor)
        _feed(db, "talos", "203.0.113.10", 0, 10, 30)
        # stayers never churn
        db.update_source_sightings("talos", {tp_sentinel(), "198.18.0.1"}, _tick(0))
        db.update_source_sightings("talos", {tp_sentinel(), "198.18.0.1"}, _tick(50))
        db.add_indicator("203.0.113.10", "talos")
        db.add_indicator("198.18.0.1", "talos")
        cfg = {"retention": {"churn_log_exclude": []}}
        X, y, snap_ix, snaps = tp.build_dataset(
            db, cfg, horizon_h=24, snapshot_h=12, max_neg=100)
        assert snaps, "expected at least one snapshot"
        total_pos = sum(y)
        # positives only exist in snapshots strictly BEFORE the return tick:
        # at/beyond T=30 the churn is past, so the ip reads as a non-repeater
        for (T, npos, _, _) in snaps:
            if T >= BASE + timedelta(hours=30):
                assert npos == 0
        assert total_pos >= 1

    def test_features_cannot_see_label_events(self, tmp_path):
        """Leakage gate: in every positive row, churned_flag must be 0 at the
        snapshot before the return happened — features are clamped to T."""
        db = _db(tmp_path)
        _feed(db, "talos", "203.0.113.10", 0, 10, 30)
        db.add_indicator("203.0.113.10", "talos")
        cfg = {"retention": {"churn_log_exclude": []}}
        from threatfeedme.predictor import FEATURE_NAMES
        X, y, snap_ix, snaps = tp.build_dataset(
            db, cfg, horizon_h=24, snapshot_h=12, max_neg=100)
        ci = FEATURE_NAMES.index("churned_flag")
        for row, label, si in zip(X, y, snap_ix):
            T = snaps[si][0]
            if label == 1 and T < BASE + timedelta(hours=30):
                assert row[ci] == 0.0, (
                    "positive row leaks its future churn return into features")

    def test_negative_stride_caps_cohort(self, tmp_path):
        db = _db(tmp_path)
        # 29 stayers + the baseline sentinel (in the corpus throughout, so in
        # the population since v2.5.0) = a 30-ip cohort
        stayers = {f"198.18.{i}.1" for i in range(1, 30)}
        db.update_source_sightings("talos", {tp_sentinel()}, _tick(0))
        db.update_source_sightings("talos", {tp_sentinel()} | stayers, _tick(5))
        # one SUB-FLOOR pair (3h gap): logs events advancing the timeline past
        # the first snapshot (t_min + step) without creating a churn label
        leaver = "198.18.1.1"
        db.update_source_sightings("talos",
                                   {tp_sentinel()} | (stayers - {leaver}), _tick(30))
        db.update_source_sightings("talos", {tp_sentinel()} | stayers, _tick(33))
        cfg = {"retention": {"churn_log_exclude": []}}
        X, y, snap_ix, snaps = tp.build_dataset(
            db, cfg, horizon_h=24, snapshot_h=24, max_neg=10)
        assert X, "expected rows"
        assert sum(y) == 0  # sub-floor pair is cadence noise, not churn
        # cohort: 30 IPs (the leaver is one of them), zero labels, cap 10
        for (_, npos, nkeep, stride) in snaps:
            assert npos == 0
            assert stride == 3  # ceil(30/10)
            assert nkeep == 10  # exactly the budget (floor+1 form kept fewer)

    def test_staggered_cohorts_reach_full_population(self, tmp_path):
        """Regression (review finding 5): IPs whose first events are spread
        over time must ALL join the cohort at late snapshots. A lexicographic
        sort regression stalls obs_i at the first out-of-order IP."""
        db = _db(tmp_path)
        db.update_source_sightings("talos", {tp_sentinel()}, _tick(0))
        by_time = []  # ip arrives at hour 4*i
        for i in range(60):
            ip = f"10.{(i * 7) % 251}.{(i * 13) % 251}.1"
            by_time.append((ip, 4 * i))
            db.add_indicator(ip, "talos")
            cur = {tp_sentinel()} | {p for p, t in by_time if t <= 4 * i}
            db.update_source_sightings("talos", cur, _tick(4 * i))
        # churner: leaves at 250, returns at 260 (gap 10h)
        db.update_source_sightings("talos", {tp_sentinel()}, _tick(250))
        db.update_source_sightings("talos", {tp_sentinel()} | {p for p, _ in by_time}, _tick(260))
        cfg = {"retention": {"churn_log_exclude": []}}
        X, y, snap_ix, snaps = tp.build_dataset(
            db, cfg, horizon_h=24, snapshot_h=24, max_neg=1000)
        last_T, npos, nkeep, _ = snaps[-1]
        # every staggered arrival joins the final cohort: all 60 left at 250
        # and returned at 260 (10h gap), so the last snapshot reads 60
        # positives. A lexicographic-sort regression stalls obs_i far below
        # 60 and this collapses.
        # + the baseline sentinel: listed since before the log, in the corpus
        # at every snapshot, never churned -> the one negative
        assert npos == 60 and nkeep == 1, \
            f"cohort wrong at {last_T}: {npos}p/{nkeep}n of 60 staggered IPs"

    def test_empty_log_exits_cleanly(self, tmp_path):
        db = _db(tmp_path)
        cfg = {"retention": {"churn_log_exclude": []}}
        with pytest.raises(SystemExit):
            tp.build_dataset(db, cfg)


class TestAUC:
    def test_perfect_and_random(self):
        assert tp._auc([1, 1, 0, 0], [0.9, 0.8, 0.2, 0.1]) == pytest.approx(1.0)
        assert tp._auc([1, 0, 1, 0], [0.5, 0.5, 0.5, 0.5]) == pytest.approx(0.5)

    def test_single_class_is_nan(self):
        import math
        assert math.isnan(tp._auc([1, 1], [0.6, 0.4]))


class TestPointInTime:
    """v2.5.0: features and population as of T, never read from today's
    tables. The old trainer let an ip evicted since T read zeros, which is
    what an eventual non-returner looks like: the features encoded the label."""

    def _history(self, tmp_path):
        db = _db(tmp_path)
        a, gone = "198.18.5.1", "198.18.5.2"
        for src in ("talos", "et"):
            db.update_source_sightings(src, {tp_sentinel()}, _tick(0))
            db.update_source_sightings(src, {tp_sentinel(), a, gone}, _tick(10))
        db.add_indicators_bulk([(a, {}), (gone, {})], source="talos")
        db.add_indicators_bulk([(a, {}), (gone, {})], source="et")
        for src in ("talos", "et"):                     # gone leaves both lists
            db.update_source_sightings(src, {tp_sentinel(), a}, _tick(100))
        with db._cursor() as cur:                       # ...and is evicted
            cur.execute("DELETE FROM indicators WHERE ip = ?", (gone,))
        return db, a, gone

    def test_an_evicted_ip_reads_its_features_as_they_were(self, tmp_path):
        from threatfeedme.predictor import FEATURE_NAMES, FeatureBuilder
        db, a, gone = self._history(tmp_path)
        fb = FeatureBuilder(db, now=BASE + timedelta(hours=50))
        va = dict(zip(FEATURE_NAMES, fb.build(a)))
        vg = dict(zip(FEATURE_NAMES, fb.build(gone)))
        # at hour 50 both were on both lists and 40h old; eviction came later
        assert va["live_source_count"] == vg["live_source_count"] == 2.0
        assert vg["first_seen_age_h"] == pytest.approx(40.0)
        assert va["first_seen_age_h"] == pytest.approx(40.0)

    def test_a_readded_row_does_not_leak_its_later_first_seen(self, tmp_path):
        from threatfeedme.predictor import FEATURE_NAMES, FeatureBuilder
        db, a, _gone = self._history(tmp_path)
        with db._cursor() as cur:       # evicted then re-added after hour 50
            cur.execute("UPDATE indicators SET first_seen = ? WHERE ip = ?",
                        (_tick(200), a))
        fb = FeatureBuilder(db, now=BASE + timedelta(hours=50))
        v = dict(zip(FEATURE_NAMES, fb.build(a)))
        assert v["first_seen_age_h"] == pytest.approx(40.0)   # from history

    def test_population_is_the_corpus_at_t(self, tmp_path):
        from threatfeedme.predictor import FeatureBuilder
        db, a, gone = self._history(tmp_path)
        db.update_source_sightings("talos", {tp_sentinel(), a, "bad.example.com"}, _tick(20))
        fb = FeatureBuilder(db)
        day = 86400.0
        cands = fb.candidate_ips()
        assert "bad.example.com" not in cands            # serving scores IPs only
        assert tp_sentinel() in cands                    # baseline-only, no events
        t = lambda h: (BASE + timedelta(hours=h)).timestamp()
        assert not fb.in_corpus_at(gone, t(5), 14 * day)       # not listed yet
        assert fb.in_corpus_at(gone, t(50), 14 * day)          # listed
        assert fb.in_corpus_at(gone, t(100 + 24 * 13), 14 * day)   # dropped 13d ago
        assert not fb.in_corpus_at(gone, t(100 + 24 * 15), 14 * day)  # aged out
        assert fb.in_corpus_at(tp_sentinel(), t(1), 14 * day)


class TestModelFeatureGuard:
    def test_a_model_trained_on_other_features_is_refused(self, tmp_path):
        lgb = pytest.importorskip("lightgbm")
        import numpy as np
        from threatfeedme.predictor import FEATURE_NAMES, Predictor
        rng = np.random.default_rng(1)
        X = rng.random((64, len(FEATURE_NAMES)))
        y = (X[:, 5] > 0.5).astype(int)
        old = ["source_count"] + list(FEATURE_NAMES[1:])     # the 2.4.x set
        booster = lgb.train({"verbose": -1, "num_leaves": 4, "min_data_in_leaf": 5},
                            lgb.Dataset(X, label=y, feature_name=old), num_boost_round=2)
        path = tmp_path / "old.txt"
        booster.save_model(str(path))
        p = Predictor(_db(tmp_path), {"predictor": {"enabled": True, "model_path": str(path)}})
        assert p._load() is None
        assert p.score("198.18.5.1") is None


class TestRetrainGate:
    """A retrain replaces the live model only when it's good enough, and
    never leaves a half-written file (the weekly cron runs unattended)."""

    class _Booster:
        best_iteration = 7

        def save_model(self, path, num_iteration):
            with open(path, "w") as f:
                f.write(f"new model ({num_iteration} rounds)")

    def _live(self, tmp_path):
        p = tmp_path / "predictor_model.txt"
        p.write_text("current model")
        return str(p)

    def test_a_good_model_replaces_the_live_one(self, tmp_path):
        out = self._live(tmp_path)
        assert tp._save_if_good(self._Booster(), 0.83, out) is True
        assert open(out).read() == "new model (7 rounds)"
        assert not (tmp_path / "predictor_model.txt.tmp").exists()

    @pytest.mark.parametrize("auc", [0.69, float("nan")])
    def test_a_weak_model_keeps_the_current_one(self, tmp_path, auc):
        out = self._live(tmp_path)
        assert tp._save_if_good(self._Booster(), auc, out) is False
        assert open(out).read() == "current model"
