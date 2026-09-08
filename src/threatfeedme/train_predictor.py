"""
Threat Feed Me! - Offline predictor training on churn labels (Task 7)

Builds the recurrence dataset from the sightings transition log and trains a
LightGBM binary classifier. Deliberately offline: never imported by the app,
so lightgbm is not a runtime requirement of the image.

Run on the deploy host (where the corpus lives):

    docker exec threat-feed-me python -m threatfeedme.train_predictor \
        data/predictor_model.txt

Dataset design (rolling-origin sampling):
  - Snapshots every SNAPSHOT_H hours across the log. At snapshot time T a row
    is (features as of T, label = did this ip make a qualifying churn return
    in (T, T+HORIZON_H]?).
  - Features are computed by FeatureBuilder with its reference time clamped
    to T, so a row's features can NEVER contain the label event: the whole
    feature stream is strictly older than the whole label window. This is
    the leakage control the plan demands (a random train/test split over
    pooled rows would let churned_flag BE the label).
  - Positive = a leave followed by a return with absence gap >= MIN_GAP_H.
    The floor matters: sub-hour gaps are feed-cadence artifacts, not repeat
    offender behavior.
  - Population = ips with >=1 event at or before T (an unobserved ip has no
    history to score); negatives are stride-sampled per snapshot to bound
    work, with scale_pos_weight compensating the known sampling rate.
  - Train/holdout split is DISJOINT BY SNAPSHOT TIME (last HOLDOUT_FRACTION
    of snapshots are holdout), not random.
  - churn_log_exclude feeds are dropped from both events and labels; their
    rotation is list churn, not ip churn.

Known anachronism (documented, acceptable for a dark predictor): prefix
density and country rank come from the CURRENT corpus, not the corpus as of
T, and indicators evicted by retention read source_count=0 at past snapshots.
"""
from __future__ import annotations

import os
import sys
from bisect import bisect_right
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Set, Tuple

MIN_GAP_H = 6.0          # absence-gap floor for a churn positive (hours)
HORIZON_H = 7 * 24       # label window after each snapshot (hours)
SNAPSHOT_H = 24          # snapshot cadence (hours)
MAX_NEG_PER_SNAPSHOT = 60_000
HOLDOUT_FRACTION = 0.25


def _event_stream(db, exclude_sources: Set[str]):
    """Yield (ip, ts, present) ordered by ts. One pass; the caller buckets."""
    sql = "SELECT ip, tick, present FROM sightings ORDER BY tick, source_name, ip"
    params: Tuple = ()
    if exclude_sources:
        marks = ",".join("?" * len(exclude_sources))
        sql = sql.replace("FROM sightings",
                          f"FROM sightings WHERE source_name NOT IN ({marks})")
        params = tuple(sorted(exclude_sources))
    with db._cursor() as cur:
        for row in cur.execute(sql, params):
            ts = datetime.fromisoformat(row["tick"])
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            yield row["ip"], ts, int(row["present"])


def collect_labels(db, exclude_sources: Set[str],
                   min_gap_h: float = MIN_GAP_H):
    """Single pass over the log -> (first_event, churn_returns, t_min, t_max).

    churn_returns: ip -> sorted list of qualifying churn-return ticks.
    """
    first_event: Dict[str, datetime] = {}
    last_leave: Dict[str, datetime] = {}
    churn_returns: Dict[str, List[datetime]] = {}
    t_min: Optional[datetime] = None
    t_max: Optional[datetime] = None
    for ip, ts, present in _event_stream(db, exclude_sources):
        if t_min is None:
            t_min = ts
        t_max = ts
        if ip not in first_event:
            first_event[ip] = ts
        if present == 0:
            last_leave[ip] = ts
        elif ip in last_leave:
            gap = (ts - last_leave[ip]).total_seconds() / 3600.0
            if gap >= min_gap_h:
                churn_returns.setdefault(ip, []).append(ts)
            del last_leave[ip]
    return first_event, churn_returns, t_min, t_max


def build_dataset(db, config: Dict, min_gap_h: float = MIN_GAP_H,
                  horizon_h: int = HORIZON_H, snapshot_h: int = SNAPSHOT_H,
                  max_neg: int = MAX_NEG_PER_SNAPSHOT):
    """Returns (X, y, snap_index, snaps) with rows grouped by snapshot.

    snaps = list of (T, n_pos, n_neg_kept, neg_stride).
    """
    from .predictor import FeatureBuilder
    from .pipeline import churn_log_exclude

    exclude = churn_log_exclude(config)
    first_event, churn_returns, t_min, t_max = collect_labels(db, exclude, min_gap_h)
    if t_min is None or t_max is None:
        raise SystemExit("sightings log is empty; nothing to train on")
    horizon = timedelta(hours=horizon_h)
    step = timedelta(hours=snapshot_h)
    snaps: List[Tuple[datetime, int, int, int]] = []
    X: List[List[float]] = []
    y: List[int] = []
    snap_ix: List[int] = []

    fb = FeatureBuilder(db, config, exclude_sources=exclude)
    observed = sorted(first_event)
    T = t_min  # rolling origin starts at the first logged event
    # monotonic cursors over the sorted population
    obs_i = 0
    while T <= t_max:
        while obs_i < len(observed) and first_event[observed[obs_i]] <= T:
            obs_i += 1
        cohort = observed[:obs_i]  # observed at T (first_event <= T)
        pos: List[str] = []
        neg: List[str] = []
        for ip in cohort:
            lst = churn_returns.get(ip)
            if lst:
                j = bisect_right(lst, T)
                if j < len(lst) and lst[j] <= T + horizon:
                    pos.append(ip)
                    continue
            neg.append(ip)
        stride = max(1, (len(neg) + max_neg) // max_neg)
        keep = neg[::stride]
        s_i = len(snaps)
        snaps.append((T, len(pos), len(keep), stride))
        # clamp the shared feature cache to strictly before the label window
        fb.now = T - timedelta(microseconds=1)
        built = fb.build_many(pos + keep)
        for ip in pos:
            X.append(built[ip]); y.append(1); snap_ix.append(s_i)
        for ip in keep:
            X.append(built[ip]); y.append(0); snap_ix.append(s_i)
        T = T + step
    return X, y, snap_ix, snaps


def train(db_path: str, config_path: str, model_out: str) -> int:
    import numpy as np
    import lightgbm as lgb
    from .database import Database
    from .core import load_config

    db = Database(db_path)
    config = load_config(config_path)
    X, y, snap_ix, snaps = build_dataset(db, config)
    if not X:
        raise SystemExit("no rows built; log too short")
    X = np.asarray(X, dtype=np.float64)
    y = np.asarray(y, dtype=np.int8)
    s = np.asarray(snap_ix)
    n_snap = len(snaps)
    split = max(1, min(n_snap - 1, int(n_snap * (1 - HOLDOUT_FRACTION))))
    hold = s >= split
    tr = ~hold
    if hold.sum() < 10 or tr.sum() < 10 or y[hold].sum() < 2 or y[tr].sum() < 2:
        raise SystemExit(f"split too thin (train={int(tr.sum())}/{int(y[tr].sum())}p, "
                         f"hold={int(hold.sum())}/{int(y[hold].sum())}p); "
                         "accumulate more churn first")

    n_pos_tr, n_neg_tr = int(y[tr].sum()), int((y[tr] == 0).sum())
    stride_avg = sum(x[3] for x in snaps) / max(1, n_snap)
    spw = stride_avg * max(1, n_neg_tr) / max(1, n_pos_tr)
    params = {
        "objective": "binary", "metric": "auc", "verbose": -1,
        "num_leaves": 31, "learning_rate": 0.05, "feature_fraction": 0.9,
        "min_data_in_leaf": 50, "scale_pos_weight": spw, "seed": 42,
    }
    dtrain = lgb.Dataset(X[tr], label=y[tr], feature_name=_feature_names())
    dhold = lgb.Dataset(X[hold], label=y[hold], reference=dtrain)
    booster = lgb.train(params, dtrain, num_boost_round=300,
                        valid_sets=[dhold],
                        callbacks=[lgb.early_stopping(25, verbose=False)])
    auc = _auc(y[hold], booster.predict(X[hold]))
    print(f"rows={len(y)} pos={int(y.sum())} snaps={n_snap} "
          f"train={int(tr.sum())} hold={int(hold.sum())} "
          f"split_at={snaps[split][0].isoformat()} "
          f"rounds={booster.best_iteration} holdout_auc={auc:.4f}")
    imp = sorted(zip(_feature_names(), booster.feature_importance("gain")),
                 key=lambda kv: kv[1], reverse=True)
    for name, gain in imp[:8]:
        print(f"  {name}: {gain:.0f}")
    booster.save_model(model_out, num_iteration=booster.best_iteration)
    print(f"model written: {model_out}")
    return 0


def _feature_names() -> List[str]:
    from .predictor import FEATURE_NAMES
    return list(FEATURE_NAMES)


def _auc(y_true, scores) -> float:
    """Rank-based AUC without sklearn (Mann-Whitney with tie correction)."""
    import numpy as np
    order = np.argsort(scores)
    ranks = np.empty(len(scores), dtype=np.float64)
    s_sorted = np.asarray(scores)[order]
    i = 0
    while i < len(s_sorted):
        j = i
        while j + 1 < len(s_sorted) and s_sorted[j + 1] == s_sorted[i]:
            j += 1
        ranks[order[i:j + 1]] = (i + j) / 2.0 + 1.0
        i = j + 1
    pos = np.asarray(y_true) == 1
    n_pos, n_neg = int(pos.sum()), int((~pos).sum())
    if n_pos == 0 or n_neg == 0:
        return float("nan")
    return float((ranks[pos].sum() - n_pos * (n_pos + 1) / 2.0) / (n_pos * n_neg))


def main(argv: List[str]) -> int:
    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(os.path.dirname(here))
    db_path = os.environ.get("THREATFEED_DB", os.path.join(root, "data", "threatfeedme.db"))
    cfg_path = os.environ.get("THREATFEED_CONFIG", os.path.join(root, "config.yaml"))
    out = argv[1] if len(argv) > 1 else os.path.join(root, "data", "predictor_model.txt")
    if not os.path.exists(db_path):
        print(f"db not found: {db_path}", file=sys.stderr)
        return 2
    return train(db_path, cfg_path, out)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
