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
    # present DESC: arrivals before leaves within one tick, so a same-tick
    # leave cannot be swallowed by a same-tick return and erase the pair
    # (A2A review 2026-09-11, finding 8; FeatureBuilder orders identically).
    sql = ("SELECT ip, tick, present FROM sightings "
           "ORDER BY tick, present DESC, source_name, ip")
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
    # stream order is tick-ascending; arrivals precede leaves within a tick
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
            del last_leave[ip]  # consumed either way (feature side agrees)
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
    # MUST be sorted by first-event TIME, not by IP string: the cursor below
    # advances monotonically and assumes chronological order. Lexicographic
    # sort stalls the cohort at the first out-of-order IP (found running this
    # against the real 21-day log; synthetic tests share one first tick and
    # cannot see it).
    observed = sorted(first_event, key=lambda ip: (first_event[ip], ip))
    # first snapshot at t_min + step: at T == t_min every feature clamps to
    # before the FIRST logged event, i.e. an all-zero vector with some rows
    # labeled positive, pure label noise (A2A review finding 3)
    T = t_min + step
    # monotonic cursors over the chronologically sorted population
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
        # ceil: (n + cap - 1) // cap keeps <= cap negatives (floor+1 form
        # halved the budget at exactly max_neg, finding 9)
        stride = max(1, -(-len(neg) // max_neg))
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
    tr, hold, tr_hi, spw = _split_masks(y, s, snaps, split)
    if hold.sum() < 10 or tr.sum() < 10 or y[hold].sum() < 2 or y[tr].sum() < 2:
        raise SystemExit(f"split too thin (train={int(tr.sum())}/{int(y[tr].sum())}p, "
                         f"hold={int(hold.sum())}/{int(y[hold].sum())}p); "
                         "accumulate more churn first")

    params = _lgb_params(spw)
    dtrain = lgb.Dataset(X[tr], label=y[tr], feature_name=_feature_names())
    dhold = lgb.Dataset(X[hold], label=y[hold], reference=dtrain)
    booster = lgb.train(params, dtrain, num_boost_round=300,
                        valid_sets=[dhold],
                        callbacks=[lgb.early_stopping(25, verbose=False)])
    auc = _auc(y[hold], booster.predict(X[hold]))
    print(f"rows={len(y)} pos={int(y.sum())} snaps={n_snap} "
          f"train={int(tr.sum())} hold={int(hold.sum())} "
          f"split_at={snaps[split][0].isoformat()} embargo_to={snaps[tr_hi-1][0].isoformat()} "
          f"spw={spw:.1f} rounds={booster.best_iteration} holdout_auc={auc:.4f}")
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


def _split_masks(y, s, snaps, split: int, horizon_s: Optional[float] = None):
    """Train/holdout masks + exact scale_pos_weight, shared by train() and
    backtest() so the two cannot drift (A2A review finding 7).

    HOLDOUT EMBARGO (finding 1, HIGH): a return within (T, T+horizon] labels
    ~horizon/snapshot_h CONSECUTIVE snapshots positive. With a 7-day horizon
    and daily snapshots, a split inside that span reuses the SAME return
    event as the positive label of near-identical rows on both sides of the
    split: the holdout is not label-independent. Dropping train snapshots
    within `horizon` of the split leaves the label events cleanly apart:
    train labels end before the embargo window, holdout labels live inside
    the holdout future. On fixtures with fewer snapshots than the embargo
    spans, tr_hi floors at 1 and the gate number is contaminated: the guard
    is honest about it via the printed embargo_to timestamp.
    """
    import numpy as np
    # snapshot cadence measured from the snaps themselves (not the module
    # constant, so a caller's snapshot_h cannot desync the embargo)
    if horizon_s is None:
        horizon_s = HORIZON_H * 3600.0
    if len(snaps) > 1:
        step_s = (snaps[1][0] - snaps[0][0]).total_seconds()
    else:
        step_s = SNAPSHOT_H * 3600.0
    embargo_snaps = int(np.ceil(horizon_s / step_s))
    tr_hi = max(1, split - embargo_snaps)
    # a tiny fixture (fewer snapshots than the embargo spans) must still
    # leave train rows: shrink the embargo until train is non-empty
    if tr_hi > split - 1:
        tr_hi = max(1, split - 1)
    hold = np.asarray(s) >= split
    tr = (np.asarray(s) >= 0) & (np.asarray(s) < tr_hi)
    # exact spw: true kept-negatives-per-positive over the TRAIN snapshots,
    # = sum(kept_i * stride_i) / n_pos_tr (a real neg appears stride_i times)
    n_pos_tr = int(np.asarray(y)[tr].sum())
    true_neg_tr = sum(nk * st for i, (_T, _p, nk, st) in enumerate(snaps)
                      if i < tr_hi)
    spw = true_neg_tr / max(1, n_pos_tr)
    if spw <= 0:
        spw = 1.0  # all-positive (or empty) train partition: unweighted
    return tr, hold, tr_hi, spw


def _lgb_params(spw: float) -> dict:
    return {
        "objective": "binary", "metric": "auc", "verbose": -1,
        "num_leaves": 31, "learning_rate": 0.05, "feature_fraction": 0.9,
        "min_data_in_leaf": 50, "scale_pos_weight": spw, "seed": 42,
    }


def _recall_at(scores, y_hold, frac: int = 10) -> float:
    """Recall of positives in the top-frac rows. Ties are broken by rank
    average (finding 9): with a constant score every row shares the mean
    rank, so top-k must be taken from a deterministic order, not argsort's
    incident row order (rows are appended positives-first, which otherwise
    lets a constant model report 100% recall)."""
    import numpy as np
    n = len(scores)
    k = max(1, n // frac)
    # tie-break by a fixed random permutation (seeded): breaking ties by ROW
    # order would hand a constant-scoring model 100% recall, since rows are
    # appended positives-first
    tie = np.random.default_rng(12345).random(n)
    order = np.lexsort((tie, -np.asarray(scores, dtype=float)))
    return int(np.asarray(y_hold)[order[:k]].sum()) / max(1, int(np.sum(np.asarray(y_hold) == 1)))


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


def backtest(db_path: str, config_path: str, model_path: str = "",
              boundary: Optional[datetime] = None,
              horizon_h: int = HORIZON_H, snapshot_h: int = SNAPSHOT_H,
              max_neg: int = MAX_NEG_PER_SNAPSHOT) -> dict:
    """Train on pre-boundary snapshots, score post-boundary holdout, compute
    AUROC and recall@10pct vs random and source-count baselines.

    Prints all numbers. Returns a dict of the metrics for programmatic access.
    """
    import numpy as np
    import lightgbm as lgb
    from .database import Database
    from .core import load_config

    db = Database(db_path)
    config = load_config(config_path)
    X, y, snap_ix, snaps = build_dataset(db, config,
                                          horizon_h=horizon_h,
                                          snapshot_h=snapshot_h,
                                          max_neg=max_neg)
    if not X:
        raise SystemExit("no rows built; log too short")
    X = np.asarray(X, dtype=np.float64)
    y = np.asarray(y, dtype=np.int8)
    s = np.asarray(snap_ix)
    n_snap = len(snaps)

    # Determine split: first snapshot at or after boundary, or default 75/25
    if boundary is not None:
        split = n_snap
        for i, (T, _, _, _) in enumerate(snaps):
            if T >= boundary:
                split = i
                break
        if split < 1:
            raise SystemExit("boundary too early — no train snapshots")
    else:
        split = max(1, min(n_snap - 1, int(n_snap * (1 - HOLDOUT_FRACTION))))

    tr, hold, tr_hi, spw = _split_masks(y, s, snaps, split,
                                        horizon_s=horizon_h * 3600.0)
    n_tr, n_hold = int(tr.sum()), int(hold.sum())
    n_pos_tr, n_pos_hold = int(y[tr].sum()), int(y[hold].sum())
    n_neg_hold = n_hold - n_pos_hold

    split_dt = snaps[min(split, n_snap - 1)][0]
    print(f"backtest: rows={len(y)} pos={int(y.sum())} snaps={n_snap}")
    print(f"  train={n_tr} ({n_pos_tr}p {n_tr - n_pos_tr}n) "
          f"hold={n_hold} ({n_pos_hold}p {n_neg_hold}n)")
    print(f"  split_at={split_dt.isoformat()} embargo_to={snaps[max(0,tr_hi-1)][0].isoformat()}")

    if n_pos_hold < 2:
        print("  too few holdout positives — metrics are unreliable")
        return {"pos_hold": n_pos_hold}
    if n_tr < 10 or n_pos_tr < 2:
        # same thin-split guard train() has (finding 7): an empty training
        # partition must not silently produce a constant booster
        raise SystemExit(f"train partition too thin (rows={n_tr}, "
                         f"pos={n_pos_tr}) — move the boundary later")

    # Train booster on the embargoed training partition
    params = _lgb_params(spw)
    dtrain = lgb.Dataset(X[tr], label=y[tr], feature_name=_feature_names())
    dhold = lgb.Dataset(X[hold], label=y[hold], reference=dtrain)
    booster = lgb.train(params, dtrain, num_boost_round=300,
                        valid_sets=[dhold],
                        callbacks=[lgb.early_stopping(25, verbose=False)])

    scores = np.asarray(booster.predict(X[hold]), dtype=float).reshape(-1)
    model_auc = _auc(y[hold], scores)
    model_recall = _recall_at(scores, y[hold])

    # Random baseline (seeded for reproducibility)
    rng = np.random.default_rng(42)
    rand_scores = rng.random(n_hold)
    rand_auc = _auc(y[hold], rand_scores)
    rand_recall = _recall_at(rand_scores, y[hold])

    # Source-count baseline (feature index 0 = FEATURE_NAMES[0] = source_count)
    sc_scores = X[hold][:, 0]
    sc_auc = _auc(y[hold], sc_scores)
    sc_recall = _recall_at(sc_scores, y[hold])

    print(f"  rounds={booster.best_iteration}")
    print("  --- AUROC ---")
    print(f"  model:         {model_auc:.4f}")
    print(f"  random:        {rand_auc:.4f}")
    print(f"  source_count:  {sc_auc:.4f}")
    print("  --- Recall@10pct ---")
    print(f"  model:         {model_recall:.4f}")
    print(f"  random:        {rand_recall:.4f}")
    print(f"  source_count:  {sc_recall:.4f}")

    if model_path:
        booster.save_model(model_path, num_iteration=booster.best_iteration)
        print(f"model written: {model_path}")

    return {
        "rows": len(y),
        "pos": int(y.sum()),
        "snaps": n_snap,
        "train": n_tr,
        "hold": n_hold,
        "pos_train": n_pos_tr,
        "pos_hold": n_pos_hold,
        "split_at": split_dt.isoformat(),
        "rounds": booster.best_iteration,
        "model_auc": model_auc,
        "rand_auc": rand_auc,
        "sc_auc": sc_auc,
        "model_recall": model_recall,
        "rand_recall": rand_recall,
        "sc_recall": sc_recall,
    }


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
