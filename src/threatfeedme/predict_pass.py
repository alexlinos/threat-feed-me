"""
Threat Feed Me! - Offline predict pass (serving side of the recurrence predictor)

Scores every live IP indicator with the trained LightGBM recurrence model and
writes P(recurrence) into ``indicators.metadata.predictive_score``. The
ConfidenceScorer reads that field and folds it into the score, weight-gated on
``predictor.enabled`` (Task 8).

Offline by design, exactly like ``train_predictor``: this module imports
lightgbm, is NEVER imported by the running app, and is meant to run in a
throwaway/tools container on a cadence (cron). Keeping it out of the request
path is what lets the serving image stay dark (no numpy/lightgbm, smaller CVE
surface).

    docker run --rm \
        -e THREATFEED_DB=/data/threatfeedme.db \
        -e THREATFEED_CONFIG=/app/config.yaml \
        <tools-image> python -m threatfeedme.predict_pass [model_path]

Decoupled from the serving switch on purpose: the pass populates
``predictive_score`` whenever a model file exists, so you can score first and
verify the distribution BEFORE flipping ``predictor.enabled: true``. ``enabled``
governs only whether the scorer *consumes* the field; it does not gate whether
this job *writes* it.

Writes go to the LIVE DB in chunked transactions (default 5k rows/commit) so
they interleave with the app's refresh writes over WAL instead of holding one
long write lock; ``busy_timeout`` (set by Database) absorbs brief contention.
The merge is ``json_patch`` so an indicator's other metadata keys survive.
"""
from __future__ import annotations

import json
import os
import sys
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional

# The metadata key the ConfidenceScorer reads (scorer.py). Kept here as the one
# writer's source of truth; the scorer reads the same literal.
SCORE_KEY = "predictive_score"

# Score precision. Four decimals is well inside the weight's resolution and
# keeps the json_patch payloads (and the WAL) small on a 700k-row pass.
_ROUND = 4


def _write_chunks(db, rows: List, chunk: int) -> int:
    """UPDATE ... json_patch in bounded transactions. Each _cursor() block is
    its own connection+commit, so a chunk is one short-lived write lock."""
    written = 0
    for i in range(0, len(rows), chunk):
        batch = rows[i:i + chunk]
        with db._cursor() as cur:
            cur.executemany(
                "UPDATE indicators SET metadata = json_patch("
                "COALESCE(metadata, '{}'), ?) WHERE ip = ?",
                batch)
        written += len(batch)
    return written


def run(db_path: str, config_path: str, model_path: str = "",
        chunk: int = 5000, now: Optional[datetime] = None) -> Dict:
    """Score all live IP indicators and persist predictive_score. Returns a
    metrics dict; prints a human summary. Return codes are surfaced by main()."""
    from .core import load_config
    from .database import Database
    from .predictor import Predictor

    config = load_config(config_path)
    pcfg = dict(config.get("predictor") or {})
    model_path = model_path or pcfg.get("model_path", "data/predictor_model.txt")

    if not os.path.exists(model_path):
        print(f"predict_pass: model not found: {model_path}", file=sys.stderr)
        return {"status": "no_model", "model_path": model_path}

    db = Database(db_path)

    # Force enabled + the resolved model path so Predictor.model_ready() unlocks
    # score_many. The offline pass is deliberately independent of the serving
    # flag (see module docstring); we only borrow Predictor's loader/feature
    # wiring, not its consumption policy.
    pcfg["enabled"] = True
    pcfg["model_path"] = model_path
    cfg = dict(config)
    cfg["predictor"] = pcfg
    predictor = Predictor(db, cfg)

    # Fail loud if the ML stack isn't present: this module only ever runs in the
    # tools image, so a missing booster is an operator error, not "contributes
    # 0" (that guard is for the dark serving path, not for this writer).
    if predictor._load() is None:
        print("predict_pass: lightgbm unavailable or model failed to load "
              f"({model_path})", file=sys.stderr)
        return {"status": "no_model_load", "model_path": model_path}

    if now is not None:
        predictor.builder.now = (now if now.tzinfo else
                                 now.replace(tzinfo=timezone.utc))

    with db._cursor() as cur:
        ips = [r["ip"] for r in cur.execute(
            "SELECT ip FROM indicators WHERE kind = 'ip'")]

    t0 = time.time()
    scores = predictor.score_many(ips)  # one feature build + one batch predict
    build_s = time.time() - t0

    rows = [(json.dumps({SCORE_KEY: round(s, _ROUND)}), ip)
            for ip, s in ((ip, scores.get(ip)) for ip in ips) if s is not None]

    t1 = time.time()
    written = _write_chunks(db, rows, chunk)
    write_s = time.time() - t1

    vals = [round(s, _ROUND) for s in scores.values() if s is not None]
    summary = {
        "status": "ok",
        "candidates": len(ips),
        "scored": len(vals),
        "written": written,
        "model_path": model_path,
        "build_s": round(build_s, 1),
        "write_s": round(write_s, 1),
        "score_min": round(min(vals), _ROUND) if vals else None,
        "score_max": round(max(vals), _ROUND) if vals else None,
        "score_mean": round(sum(vals) / len(vals), _ROUND) if vals else None,
        "ge_0_5": sum(1 for v in vals if v >= 0.5),
    }
    print(f"predict_pass: scored {summary['scored']}/{summary['candidates']} "
          f"ip indicators, wrote {written} "
          f"(build {summary['build_s']}s, write {summary['write_s']}s)")
    if vals:
        print(f"  score min/mean/max = {summary['score_min']}/"
              f"{summary['score_mean']}/{summary['score_max']}  "
              f"(>=0.5: {summary['ge_0_5']})")
    return summary


def main(argv: List[str]) -> int:
    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(os.path.dirname(here))
    db_path = os.environ.get("THREATFEED_DB",
                             os.path.join(root, "data", "threatfeedme.db"))
    cfg_path = os.environ.get("THREATFEED_CONFIG",
                              os.path.join(root, "config.yaml"))
    model_path = argv[1] if len(argv) > 1 else ""
    if not os.path.exists(db_path):
        print(f"predict_pass: db not found: {db_path}", file=sys.stderr)
        return 2
    res = run(db_path, cfg_path, model_path)
    status = res.get("status")
    if status in ("no_model", "no_model_load"):
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
