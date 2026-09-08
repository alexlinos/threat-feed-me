"""End-to-end trainer smoke test: synthetic churn corpus -> LightGBM model.

Gated on lightgbm import (dev-only dep; the app never trains at runtime).
Proves train() produces a loadable booster whose rows FeatureBuilder can
feed, i.e. the train/predict feature contract holds across the two modules.
"""
from datetime import datetime, timedelta, timezone

import pytest

from threatfeedme.database import Database

lgb = pytest.importorskip("lightgbm")

BASE = datetime(2026, 7, 1, tzinfo=timezone.utc)
SENTINEL = "192.0.2.254"


def _tick(h):
    return (BASE + timedelta(hours=h)).isoformat()


def test_train_end_to_end(tmp_path):
    db = Database(str(tmp_path / "synth.db"))
    churners = [f"203.0.{i // 50}.{i % 50 + 1}" for i in range(60)]
    stayers = [f"198.18.{i // 50}.{i % 50 + 1}" for i in range(120)]
    everyone = set(churners) | set(stayers)
    db.update_source_sightings("talos", everyone | {SENTINEL}, _tick(0))
    # 6 cycles, 20h apart: one third of the churners leave, return 8h later
    # (gap >= MIN_GAP_H), others hold. Last cycle ends at hour 128.
    for c in range(6):
        h0 = 20 + c * 20
        gone = set(churners[(c * 20) % 60:(c * 20) % 60 + 20] or churners[:20])
        db.update_source_sightings("talos", (everyone - gone) | {SENTINEL}, _tick(h0))
        db.update_source_sightings("talos", everyone | {SENTINEL}, _tick(h0 + 8))
    for ip in everyone:
        db.add_indicator(ip, "talos")

    cfg = tmp_path / "cfg.yaml"
    cfg.write_text("retention:\n  churn_log_exclude: []\n")
    model = tmp_path / "model.txt"

    from threatfeedme.train_predictor import train
    assert train(str(tmp_path / "synth.db"), str(cfg), str(model)) == 0
    assert model.exists()

    # the saved booster consumes exactly FeatureBuilder's feature vector
    booster = lgb.Booster(model_file=str(model))
    assert booster.num_feature() == 14

    from threatfeedme.predictor import Predictor
    p = Predictor(db, {"predictor": {"enabled": True, "model_path": str(model)}})
    scores = p.score_many(churners[:5] + stayers[:5])
    assert all(isinstance(v, float) and 0.0 <= v <= 1.0 for v in scores.values())
