"""Offline predict-pass tests.

Pure-logic guards (missing model, train/serve exclusion wiring) run everywhere;
the end-to-end write path is gated on lightgbm (dev-only dep, never in the
serving image).
"""
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

import pytest

from threatfeedme.database import Database
from threatfeedme import predict_pass
from threatfeedme.predictor import Predictor

BASE = datetime(2026, 7, 1, tzinfo=timezone.utc)
SENTINEL = "192.0.2.254"


def _tick(h):
    return (BASE + timedelta(hours=h)).isoformat()


def _cfg(tmp_path, exclude="[]", enabled="false"):
    p = tmp_path / "cfg.yaml"
    p.write_text(
        f"retention:\n  churn_log_exclude: {exclude}\n"
        f"predictor:\n  enabled: {enabled}\n")
    return str(p)


def test_missing_model_returns_no_model(tmp_path):
    # No lightgbm required: the guard fires before any ML import.
    db = Database(str(tmp_path / "x.db"))
    db.add_indicator("203.0.113.1", "talos")
    res = predict_pass.run(str(tmp_path / "x.db"), _cfg(tmp_path),
                           model_path=str(tmp_path / "does_not_exist.txt"))
    assert res["status"] == "no_model"
    # and the indicator was left untouched
    assert "predictive_score" not in (db.get_indicator("203.0.113.1").metadata or {})


def test_main_missing_db_returns_2(tmp_path, monkeypatch):
    # main() resolves the DB from THREATFEED_DB (argv[1] is the model path).
    monkeypatch.setenv("THREATFEED_DB", str(tmp_path / "nope.db"))
    monkeypatch.setenv("THREATFEED_CONFIG", _cfg(tmp_path))
    assert predict_pass.main(["predict_pass"]) == 2


class _FakeCursor:
    def __init__(self, sink):
        self.sink = sink

    def execute(self, *a):        # the PRAGMA busy_timeout
        pass

    def executemany(self, _sql, rows):
        self.sink.extend(rows)


class _FakeLockingDB:
    """A db whose _cursor() raises 'database is locked' the first `fail_n`
    times, then succeeds — to exercise _write_chunks' retry loop without a
    real writer to contend with."""
    def __init__(self, fail_n):
        self.fail_n = fail_n
        self.calls = 0
        self.sink = []

    @contextmanager
    def _cursor(self):
        self.calls += 1
        if self.calls <= self.fail_n:
            raise sqlite3.OperationalError("database is locked")
        yield _FakeCursor(self.sink)


def test_write_chunks_retries_transient_lock(monkeypatch):
    monkeypatch.setattr(predict_pass.time, "sleep", lambda *_: None)  # no real backoff
    db = _FakeLockingDB(fail_n=2)  # locked twice, succeeds on the 3rd attempt
    rows = [("{}", f"1.2.3.{i}") for i in range(4)]
    written = predict_pass._write_chunks(db, rows, chunk=10)
    assert written == 4
    assert len(db.sink) == 4
    assert db.calls == 3  # 2 failures + 1 success


def test_write_chunks_reraises_when_lock_never_clears(monkeypatch):
    monkeypatch.setattr(predict_pass.time, "sleep", lambda *_: None)
    db = _FakeLockingDB(fail_n=99)  # never clears
    with pytest.raises(sqlite3.OperationalError):
        predict_pass._write_chunks(db, [("{}", "1.2.3.4")], chunk=10)
    assert db.calls == predict_pass._LOCK_RETRIES  # gave up after the cap


def test_builder_excludes_churn_log_feeds(tmp_path):
    # The train/serve skew fix: Predictor's feature builder must drop the same
    # churn_log_exclude feeds train_predictor.build_dataset drops. No lightgbm
    # needed — this only constructs the FeatureBuilder.
    db = Database(str(tmp_path / "x.db"))
    p = Predictor(db, {"retention": {"churn_log_exclude": ["cins_army", "foo"]},
                       "predictor": {"enabled": True}})
    assert p.builder.exclude_sources == ["cins_army", "foo"]


def _seed_corpus(db):
    churners = [f"203.0.{i // 50}.{i % 50 + 1}" for i in range(60)]
    stayers = [f"198.18.{i // 50}.{i % 50 + 1}" for i in range(120)]
    everyone = set(churners) | set(stayers)
    db.update_source_sightings("talos", everyone | {SENTINEL}, _tick(0))
    for c in range(6):
        h0 = 20 + c * 20
        gone = set(churners[(c * 20) % 60:(c * 20) % 60 + 20] or churners[:20])
        db.update_source_sightings("talos", (everyone - gone) | {SENTINEL}, _tick(h0))
        db.update_source_sightings("talos", everyone | {SENTINEL}, _tick(h0 + 8))
    for ip in everyone:
        db.add_indicator(ip, "talos")
    return churners, stayers


def test_predict_pass_writes_scores_and_is_switch_independent(tmp_path):
    lgb = pytest.importorskip("lightgbm")
    db_path = str(tmp_path / "synth.db")
    db = Database(db_path)
    churners, stayers = _seed_corpus(db)
    # a domain indicator must be ignored (features are IP-centric)
    db.add_indicator("evil.example", "talos", kind="domain")

    model = tmp_path / "model.txt"
    from threatfeedme.train_predictor import train
    assert train(db_path, _cfg(tmp_path), str(model)) == 0

    # config says enabled:false — the pass must STILL write (decoupled from the
    # serving switch); it only borrows Predictor's loader.
    res = predict_pass.run(db_path, _cfg(tmp_path, enabled="false"),
                           model_path=str(model), chunk=50)
    assert res["status"] == "ok"
    # SENTINEL is seeded into sightings but never added as an indicator, and the
    # domain is kind='domain' — neither is scored. Only the 180 IP indicators.
    assert res["scored"] == len(set(churners) | set(stayers))
    assert res["written"] == res["scored"]
    assert 0.0 <= res["score_min"] <= res["score_max"] <= 1.0

    # every scored IP carries a valid probability in metadata
    got = db.get_indicator(churners[0]).metadata["predictive_score"]
    assert isinstance(got, float) and 0.0 <= got <= 1.0
    # the domain was not scored
    assert "predictive_score" not in (db.get_indicator("evil.example").metadata or {})


def test_predict_pass_preserves_other_metadata(tmp_path):
    pytest.importorskip("lightgbm")
    db_path = str(tmp_path / "synth.db")
    db = Database(db_path)
    churners, _ = _seed_corpus(db)
    # stamp an unrelated metadata key on one row
    db.add_indicator(churners[0], "talos", metadata={"note": "keep me"})

    model = tmp_path / "model.txt"
    from threatfeedme.train_predictor import train
    assert train(db_path, _cfg(tmp_path), str(model)) == 0
    predict_pass.run(db_path, _cfg(tmp_path), model_path=str(model), chunk=50)

    meta = db.get_indicator(churners[0]).metadata
    assert meta.get("note") == "keep me"          # json_patch preserved it
    assert "predictive_score" in meta             # and added the new key
