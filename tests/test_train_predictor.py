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
        stayers = {f"198.18.{i}.1" for i in range(1, 31)}
        db.update_source_sightings("talos", {tp_sentinel()}, _tick(0))
        db.update_source_sightings("talos", {tp_sentinel()} | stayers, _tick(5))
        db.update_source_sightings("talos", {tp_sentinel()} | stayers, _tick(40))
        cfg = {"retention": {"churn_log_exclude": []}}
        X, y, snap_ix, snaps = tp.build_dataset(
            db, cfg, horizon_h=24, snapshot_h=24, max_neg=10)
        assert X, "expected rows"
        assert sum(y) == 0  # pure-negative pool: nobody churned
        for (_, npos, nkeep, stride) in snaps:
            assert npos == 0
            assert nkeep <= 10  # capped by max_neg... 30 negatives, stride 3
            assert stride >= 3

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
