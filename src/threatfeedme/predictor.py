"""
Threat Feed Me! - Recurrence predictor (ships dark)

FeatureBuilder turns the churn event log (`sightings`) plus indicator context
into a fixed 14-column tabular row per IP. Predictor wraps a LightGBM booster
loaded from `data/predictor_model.txt` and scores rows to P(recurrence).

Design constraints (from the implementation plan):
- LightGBM native API only (``lgb.Booster`` / ``lgb.Dataset``); no sklearn, no
  pandas, scipy must never be imported at predict time (numpy + lightgbm are
  the only wheels the image may grow).
- The module must import and run WITHOUT lightgbm installed: the predictor
  ships dark (``predictor.enabled: false``) and Task 8 calls into it through
  a guard that treats a missing model as "contributes 0".
- Features are computed in pure Python; numpy arrays are only handed to the
  booster.
- Source-agnostic history: the log already excludes wholesale-rotating feeds
  (retention.churn_log_exclude), so events here are clean per-source
  transitions. Aggregating across sources is the intended feature view; the
  training hold-out (Task 7) is what must stay time-disjoint.

Model file lives in ``data/`` (never baked into the image).
"""
from __future__ import annotations

import ipaddress
import json
import os
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Dict, Iterable, List, Optional, Tuple

FEATURE_NAMES: List[str] = [
    "source_count",        # feeds that currently report this ip
    "first_seen_age_h",    # hours since the indicator row was created
    "last_event_age_h",    # hours since the ip's latest churn event (any kind)
    "arrival_count",       # arrival events in the feature window
    "leave_count",         # leave events in the feature window
    "churn_count",         # leave->return pairs (per-source adjacent pairs)
    "churned_flag",        # 1 if churn_count > 0
    "mean_gap_h",          # mean leave->return gap (hours)
    "min_gap_h",           # fastest observed return (hours)
    "max_gap_h",           # slowest observed return (hours)
    "median_gap_h",        # median leave->return gap (hours)
    "max_consec_churn",    # longest run of consecutive churn cycles
    "prefix_density",      # corpus members sharing the /16 (v4) or /64 (v6)
    "country_code",        # offline /16 -> ISO2, rank by global frequency (-1 = ZZ)
]


def _parse_tick(ts: str) -> Optional[datetime]:
    try:
        dt = datetime.fromisoformat(ts)
    except (ValueError, TypeError):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _prefix6_for(addr) -> str:
    net = ipaddress.IPv6Network(((int(addr) >> 64) << 64, 64), strict=False)
    return str(net)


def _prefix4_for(addr) -> str:
    net = ipaddress.IPv4Network(((int(addr) >> 16) << 16, 16), strict=False)
    return str(net)


# Minimum absence gap (hours) for a leave->return pair to count as churn.
# A sub-hour gap is feed-cadence noise (list rotation between fetches), not
# repeat-offender behavior. The label side (train_predictor.MIN_GAP_H) and the
# feature side MUST share this one constant: when they diverged, features
# counted artifacts the labels rejected (A2A review 2026-09-11, finding 4).
CHURN_MIN_GAP_H = 6.0


class FeatureBuilder:
    """Builds FEATURE_NAMES rows from the DB. Batch-first: the event log and
    the corpus-side lookups load once per build, not once per IP."""

    def __init__(self, db, config: Optional[Dict] = None,
                 window_days: Optional[int] = None,
                 now: Optional[datetime] = None,
                 exclude_sources: Optional[Iterable[str]] = None):
        cfg = (config or {}).get("predictor", {}) or {}
        self.window_days = int(window_days if window_days is not None
                               else cfg.get("feature_window_days", 14))
        self.db = db
        self.now = now or datetime.now(timezone.utc)
        if self.now.tzinfo is None:  # a naive now would crash event clamping
            self.now = self.now.replace(tzinfo=timezone.utc)
        self.exclude_sources = sorted(set(exclude_sources or []))
        self.churn_min_gap_h = float(cfg.get("churn_min_gap_h", CHURN_MIN_GAP_H))
        self._buckets = None
        self._loaded = False
        self._events: Dict[str, List[Tuple[datetime, str, int]]] = {}
        self._prefix_counts: Counter = Counter()
        self._country_rank: Dict[str, int] = {}
        self._ind_ctx: Dict[str, Tuple[datetime, int]] = {}

    # ---- corpus-side loads (once per build) ----

    def _ensure_loaded(self) -> None:
        if self._loaded:
            return
        # Load the FULL log: the ring prune keeps it bounded (<= ~30d), and
        # one cache serves every reference time — live scoring (ref=now) and
        # offline training (ref=past tick) share this single code path.
        # Rows are clamped to events <= ref time in _build_one. window_days
        # is reserved (not yet applied as a lower bound); the Task 9 gate
        # numbers were measured on full-log features, so applying it now
        # would silently change the thing the backtest certified.
        with self.db._cursor() as cur:
            sql = ("SELECT ip, source_name, tick, present FROM sightings")
            params: Tuple = ()
            if self.exclude_sources:
                marks = ",".join("?" * len(self.exclude_sources))
                sql += f" WHERE source_name NOT IN ({marks})"
                params = tuple(self.exclude_sources)
            # present DESC: at one tick, process arrivals BEFORE leaves. A
            # leave ordered first would be consumed by a same-tick arrival
            # (gap 0), swallowing the pair AND deleting last_leave, so a real
            # return 12h later never registers (A2A review finding 8).
            cur.execute(sql + " ORDER BY tick, present DESC, source_name, ip",
                        params)
            events: Dict[str, List[Tuple[datetime, str, int]]] = defaultdict(list)
            # stream the cursor: fetchall() on a 4.6M-row log materialized a
            # second full copy of the rows on top of the events dict (review
            # finding 1)
            for row in cur:
                ts = _parse_tick(row["tick"])
                if ts is None:
                    continue
                events[row["ip"]].append((ts, row["source_name"], int(row["present"])))
        self._events = events
        # geo table once per build, not once per row (review finding 4:
        # CountryBuckets.load() re-reads the file on every call)
        self._buckets = self._geo_buckets()

        # /16 (and /64) densities and country ranks over the current IP corpus.
        prefix_counts: Counter = Counter()
        country_counts: Counter = Counter()
        buckets = self._buckets
        with self.db._cursor() as cur:
            cur.execute("SELECT ip FROM indicators WHERE kind = 'ip'")
            for row in cur.fetchall():
                s = row["ip"]
                try:
                    addr = ipaddress.ip_address(s)
                except ValueError:
                    continue
                if addr.version == 4:
                    prefix_counts[_prefix4_for(addr)] += 1
                else:
                    prefix_counts[_prefix6_for(addr)] += 1
                if buckets is not None:
                    country_counts[buckets.country_for_ip(int(addr))] += 1
        self._prefix_counts = prefix_counts
        ranked = sorted(country_counts, key=lambda c: country_counts[c], reverse=True)
        self._country_rank = {c: i for i, c in enumerate(ranked)}

        # Indicator context in ONE pass: build_one only needs first_seen and
        # the source count. One get_indicator round trip per row was measured
        # as the dominant share of a 2.22 ms/row build cost on the real log
        # (50 calls / 50 rows probed 2026-09-11); at ~7.4M projected training
        # rows that is hours. Parsed once here, dict-hit per row. Absent from
        # the map (row deleted mid-run) falls back to the live query.
        ind_ctx: Dict[str, Tuple[datetime, int]] = {}
        with self.db._cursor() as cur:
            # two flat scans: correlated per-row COUNTs measured 45 s on a
            # 500k-indicator DB; one GROUP BY over the source index is ~1 s
            src_counts = {row["indicator_id"]: int(row["c"]) for row in cur.execute(
                "SELECT indicator_id, COUNT(*) AS c FROM indicator_sources "
                "GROUP BY indicator_id")}
            for row in cur.execute("SELECT id, ip, first_seen FROM indicators"):
                fs = _parse_tick(row["first_seen"])
                if fs is not None:
                    ind_ctx[row["ip"]] = (fs, src_counts.get(row["id"], 0))
        self._ind_ctx = ind_ctx
        self._loaded = True

    def _geo_buckets(self):
        try:
            from .geo import CountryBuckets
            return CountryBuckets.load()
        except Exception:
            return None

    # ---- per-IP features ----

    def build(self, ip: str) -> List[float]:
        return self.build_many([ip])[ip]

    def build_many(self, ips: Iterable[str]) -> Dict[str, List[float]]:
        self._ensure_loaded()
        out: Dict[str, List[float]] = {}
        for ip_str in ips:
            out[ip_str] = self._build_one(ip_str)
        return out

    def _build_one(self, ip_str: str) -> List[float]:
        # Clamp the stream to the reference time: a builder instantiated at a
        # past tick (offline training, Task 7) must see ONLY events up to that
        # tick. Live scoring passes now=real-now, so this is a no-op there.
        ev = sorted((e for e in self._events.get(ip_str, []) if e[0] <= self.now),
                    key=lambda t: t[0])
        # Batch path uses the preloaded context map; fall back to the live
        # query only for rows added after the map was built.
        if ip_str in self._ind_ctx:
            first_seen, n_src = self._ind_ctx[ip_str]
            ind = None
        else:
            first_seen, n_src = None, None
            ind = self.db.get_indicator(ip_str)

        arrival_count = sum(1 for _, _, p in ev if p == 1)
        leave_count = sum(1 for _, _, p in ev if p == 0)

        # churn = a leave immediately followed (any source) by a return.
        gaps: List[float] = []
        churn = 0
        streak = 0
        max_streak = 0
        last_leave: Optional[datetime] = None
        for ts, _src, present in ev:
            if present == 0:
                # advance to the LATEST unanswered leave: a return's gap is
                # measured from when the ip was last actually gone (matches
                # the label semantics in Database.detect_leaves)
                last_leave = ts
            else:
                if last_leave is not None:
                    delta = (ts - last_leave).total_seconds() / 3600.0
                    if delta >= self.churn_min_gap_h:
                        churn += 1
                        streak += 1
                        max_streak = max(max_streak, streak)
                        gaps.append(delta)
                    # consumed either way: an unresolved short gap is
                    # cadence noise, and the NEXT return measures from the
                    # next leave after it (arrival-first tick ordering means
                    # same-tick pairs no longer land here)
                    last_leave = None
        if last_leave is not None:
            streak = 0  # trailing unanswered leave is not a churn cycle

        mean_gap = sum(gaps) / len(gaps) if gaps else 0.0
        min_gap = min(gaps) if gaps else 0.0
        max_gap = max(gaps) if gaps else 0.0
        if gaps:
            sg = sorted(gaps)
            n = len(sg)
            median_gap = sg[n // 2] if n % 2 else (sg[n // 2 - 1] + sg[n // 2]) / 2.0
        else:
            median_gap = 0.0

        first_seen_age_h = 0.0
        last_event_age_h = 0.0
        if first_seen is None and ind is not None:
            first_seen = ind.first_seen
        if first_seen is not None:
            fs = first_seen
            if fs.tzinfo is None:
                fs = fs.replace(tzinfo=timezone.utc)
            if fs <= self.now:
                first_seen_age_h = (self.now - fs).total_seconds() / 3600.0
        if ev:
            last_event_age_h = max(0.0, (self.now - ev[-1][0]).total_seconds() / 3600.0)

        try:
            addr = ipaddress.ip_address(ip_str)
            key = (_prefix4_for(addr) if addr.version == 4 else _prefix6_for(addr))
            density = self._prefix_counts.get(key, 0)
        except ValueError:
            density = 0

        country = -1.0
        buckets = self._buckets
        if buckets is not None:
            try:
                code = buckets.country_for_ip(int(ipaddress.ip_address(ip_str)))
                country = float(self._country_rank.get(code, -1))
            except Exception:
                country = -1.0

        if n_src is None:
            n_src = len(ind.sources) if ind is not None else 0
        source_count = float(n_src)

        return [
            source_count,
            first_seen_age_h,
            last_event_age_h,
            float(arrival_count),
            float(leave_count),
            float(churn),
            1.0 if churn > 0 else 0.0,
            mean_gap,
            min_gap,
            max_gap,
            median_gap,
            float(max_streak),
            float(density),
            country,
        ]


class Predictor:
    """LightGBM recurrence scorer. Dark by default: ``enabled`` comes from
    ``predictor.enabled`` and a missing model always yields None, never an
    exception — Task 8's scoring hook treats None as "contributes 0"."""

    def __init__(self, db, config: Optional[Dict] = None):
        cfg = (config or {}).get("predictor", {}) or {}
        self.enabled = bool(cfg.get("enabled", False))
        self.model_path = cfg.get("model_path", "data/predictor_model.txt")
        self.db = db
        self.config = config or {}
        self._booster = None
        self._builder: Optional[FeatureBuilder] = None

    @property
    def builder(self) -> FeatureBuilder:
        if self._builder is None:
            self._builder = FeatureBuilder(self.db, self.config)
        return self._builder

    def model_ready(self) -> bool:
        return bool(self.enabled) and os.path.exists(self.model_path)

    def _load(self):
        if self._booster is not None:
            return self._booster
        try:
            import lightgbm as lgb  # lazy: the module must import without it
        except Exception:
            return None
        try:
            self._booster = lgb.Booster(model_file=self.model_path)
        except Exception:
            self._booster = None
        return self._booster

    def score_many(self, ips: Iterable[str]) -> Dict[str, Optional[float]]:
        ips = list(ips)
        if not self.model_ready():
            return {ip: None for ip in ips}
        booster = self._load()
        if booster is None:
            return {ip: None for ip in ips}
        import numpy as np
        rows = self.builder.build_many(ips)
        X = np.asarray([rows[ip] for ip in ips], dtype=np.float64)
        preds = np.asarray(booster.predict(X), dtype=float).reshape(-1)
        return {ip: float(p) for ip, p in zip(ips, preds)}

    def score(self, ip: str) -> Optional[float]:
        return self.score_many([ip])[ip]

    def predict_and_store(self, ip: str) -> Optional[float]:
        """Score one IP and persist it into the indicator row's metadata.

        Metadata (json_patch-merged by add_indicator) is the storage point
        deliberately: no schema change, so a dark predictor never touches
        the migration path. A first-seen re-add keeps the stale field; it is
        refreshed on the next predict pass and Task 8 re-scores live values.
        """
        score = self.score(ip)
        if score is None:
            return None
        with self.db._cursor() as cur:
            cur.execute(
                "UPDATE indicators SET metadata = json_patch("
                "COALESCE(metadata, '{}'), ?) WHERE ip = ?",
                (json.dumps({"predictive_score": score}), ip))
        return score
