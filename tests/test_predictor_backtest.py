"""Task 9: predictor backtest acceptance gate.

Synthetic-data tests that always run and prove the backtest harness math, plus
a real-data test that skips unless the environment has a production DB copy.
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import pytest

from threatfeedme.database import Database
from threatfeedme import train_predictor as tp

BASE = datetime(2026, 1, 1, tzinfo=timezone.utc)
# All seed timestamps are hours since BASE
_tick = lambda h: (BASE + timedelta(hours=h)).isoformat()
_SENTINEL = "192.0.2.254"


def _db(tmp_path):
    return Database(str(tmp_path / "backtest.db"))


class TestBacktestHarness:
    """Prove the harness can tell signal from nothing."""

    @staticmethod
    def _seed_signal_population(db):
        """50 signal IPs (churn history → future churn), 150 noise IPs (no churn).

        Churn cycles are written as ONE membership set per source, not
        per-IP calls (per-IP calls would make every other IP appear to
        leave/return and manufacture churn the group doesn't have). All 50
        churn on identical 18h cycles (gap 6h >= floor); the 150 noise IPs
        are present at every tick and never churn. A sentinel baseline at
        t=-1 makes the t0 arrivals REAL events: without it t0 would seed
        silently and the noise IPs would never appear in the observed
        population at all.
        """
        signal = [f"203.0.113.{i}" for i in range(50)]
        noise = [f"198.18.{i // 256}.{i % 256}" for i in range(150)]
        for ip in signal + noise:
            db.add_indicator(ip, "talos")
        everyone = set(signal) | set(noise) | {_SENTINEL}
        signal_out = set(noise) | {_SENTINEL}
        db.update_source_sightings("talos", {_SENTINEL}, _tick(-1))
        db.update_source_sightings("talos", everyone, _tick(0))
        for c in range(10):
            db.update_source_sightings("talos", signal_out, _tick(12 + 18 * c))
            db.update_source_sightings("talos", everyone, _tick(18 + 18 * c))

    @staticmethod
    def _seed_noise_population(db):
        """200 IPs: 100 churn, 100 stay — but IDENTICAL features at T=0.

        Seeded on a SHARED membership set per source (not per-IP calls):
        update_source_sightings diffs the whole set, so per-IP calls would
        make every other IP appear to leave/return and manufacture churn
        events the noise group does not have.

        Tick plan (source talos):
          t0   baseline: all 200 present (state seeded, zero events written)
          t12  churn group (100) absent, stay group present   -> 100 leaves
          t18  churn group present again                      -> 100 returns (gap 6h)
          t30  churn group absent again                       -> 100 leaves
          t36  churn group present                            -> 100 returns
          t60  churn group absent                             -> 100 leaves
          t66  churn group present                            -> 100 returns
        Snapshots every 24h from t0: T=0, 24, 48 (max event t66). Boundary
        T=24: train rows are the T=0 snapshot, where features clamp to
        strictly-before-0 — every IP's feature vector is identical, while
        100 are positive (return t18 within horizon) and 100 negative. A
        tree routes constant features to one leaf: the booster can only
        predict a constant, so holdout AUROC sits at chance (0.5).
        Both groups live in ONE /16 (203.0.113.x): country_code and
        prefix_density must not encode group membership, or the model
        separates on netblock instead of history (learned the hard way).
        """
        churn = [f"203.0.113.{i}" for i in range(100)]
        stay = [f"203.0.113.{100 + i}" for i in range(100)]
        for ip in churn + stay:
            db.add_indicator(ip, "talos")
        everyone = set(churn) | set(stay) | {_SENTINEL}
        present_at_off = set(stay) | {_SENTINEL}
        db.update_source_sightings("talos", {_SENTINEL}, _tick(-1))
        db.update_source_sightings("talos", everyone, _tick(0))
        for off, back in ((12, 18), (30, 36), (60, 66)):
            db.update_source_sightings("talos", present_at_off, _tick(off))
            db.update_source_sightings("talos", everyone, _tick(back))

    def test_harness_detects_signal(self, tmp_path):
        """AUROC > 0.65 when churn_count predicts future churn."""
        db = _db(tmp_path)
        self._seed_signal_population(db)
        db_path = str(tmp_path / "backtest.db")

        cfg = {"retention": {"churn_log_exclude": []}}
        cfg_path = str(tmp_path / "config.yaml")
        import yaml
        with open(cfg_path, "w") as f:
            yaml.dump(cfg, f)

        # boundary at T=48 → train: T=0,T=24 ; hold: T=48,72,96,120,144,168,192
        result = tp.backtest(db_path, cfg_path, "",
                             boundary=BASE + timedelta(hours=48),
                             horizon_h=168, snapshot_h=24, max_neg=500)
        assert result["pos_hold"] >= 2, (
            f"need ≥2 holdout positives, got {result['pos_hold']}")
        assert result["model_auc"] > 0.65, (
            f"model AUC {result['model_auc']:.4f} should beat 0.65 "
            f"on injected signal")
        # Random baseline should be near 0.5
        assert 0.4 <= result["rand_auc"] <= 0.6, (
            f"random AUC {result['rand_auc']:.4f} should be near 0.5")

    def test_harness_reports_noise_as_chance(self, tmp_path):
        """AUROC ∼0.5 when features carry no information about labels."""
        db = _db(tmp_path)
        self._seed_noise_population(db)
        db_path = str(tmp_path / "backtest.db")

        cfg = {"retention": {"churn_log_exclude": []}}
        cfg_path = str(tmp_path / "config.yaml")
        import yaml
        with open(cfg_path, "w") as f:
            yaml.dump(cfg, f)

        # boundary at T=24 → train: T=0 ; hold: T=24, T=48
        result = tp.backtest(db_path, cfg_path, "",
                             boundary=BASE + timedelta(hours=24),
                             horizon_h=168, snapshot_h=24, max_neg=500)
        assert result["pos_hold"] >= 2, (
            f"need ≥2 holdout positives, got {result['pos_hold']}")
        # Model got no signal at T=0 (identical features) → can't beat random
        assert result["model_auc"] < 0.65, (
            f"model AUC {result['model_auc']:.4f} should be below 0.65 "
            f"on noise with identical features at train time")
        # Random should be near 0.5
        assert 0.4 <= result["rand_auc"] <= 0.6, (
            f"random AUC {result['rand_auc']:.4f} should be near 0.5")


@pytest.mark.skipif(
    "THREATFEED_BACKTEST_DB" not in os.environ,
    reason="requires production DB at $THREATFEED_BACKTEST_DB")
def test_backtest_on_real_data():
    """Run the full backtest against a production DB copy.

    Skipped unless the env var is set (never runs in CI). Reads the DB path,
    config path, and model output path from env so the caller can point at
    wherever the copy was placed.
    """
    db_path = os.environ["THREATFEED_BACKTEST_DB"]
    cfg_path = os.environ.get("THREATFEED_CONFIG",
                              os.path.join(os.path.dirname(__file__),
                                           "..", "config.yaml"))
    model_path = os.environ.get("THREATFEED_MODEL", "")
    tp.backtest(db_path, cfg_path, model_path)
    # no assert — the function prints and returns; the test passes if it
    # ran without raising