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
import logging
import math
import os
from bisect import bisect_right
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Dict, Iterable, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

# Every feature is computed AS OF the builder's reference time (v2.5.0). The
# first two used to come from today's tables — attribution count and the
# indicator row's first_seen — so at a past training snapshot an ip that had
# since been evicted (typically: one that never returned) read 0 for both,
# and the features partly encoded the label (review 2026-09-22). They are now
# reconstructed from membership history (listing_intervals). Renamed rather
# than silently redefined: a model trained on the old meaning is refused
# (Predictor._load) instead of scoring features it never saw.
FEATURE_NAMES: List[str] = [
    "live_source_count",   # feeds listing this ip at the reference time
    "first_seen_age_h",    # hours since the first evidence of the ip (as of ref)
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
    "prefix_density",      # OTHER corpus members sharing the /16 (v4) or /64 (v6)
    "country_code",        # offline /16 -> ISO2, rank by global frequency (-1 = ZZ)
]


def _parse_tick(ts) -> Optional[datetime]:
    if isinstance(ts, (int, float)):          # churn-log ticks are epoch seconds
        return datetime.fromtimestamp(ts, timezone.utc)
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
        self._ind_ctx: Dict[str, datetime] = {}
        # ip -> sources whose CURRENT list holds it (source_state), for
        # memberships the transition log never recorded: a baseline member
        # that never left has no events at all.
        self._state_srcs: Dict[str, Set[str]] = {}
        self._log_start: Optional[float] = None
        self._intervals: Dict[str, Tuple[List[float], List[float]]] = {}

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
            sql = ("SELECT ip, source_name, tick, present FROM churn.sightings")
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
        starts = [ev[0][0] for ev in events.values() if ev]
        self._log_start = min(starts).timestamp() if starts else None
        state: Dict[str, Set[str]] = defaultdict(set)
        with self.db._cursor() as cur:
            sql = "SELECT source_name, ip FROM source_state"
            params = ()
            if self.exclude_sources:
                marks = ",".join("?" * len(self.exclude_sources))
                sql += f" WHERE source_name NOT IN ({marks})"
                params = tuple(self.exclude_sources)
            for row in cur.execute(sql, params):
                state[row["ip"]].add(row["source_name"])
        self._state_srcs = state
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

        # first_seen of every CURRENT indicator in one pass (one get_indicator
        # per row was the dominant build cost on the real log, 2026-09-11).
        # Membership in this map also marks "in today's corpus" for the
        # prefix-density self-exclusion. An ip absent from it has been
        # evicted (or is a domain): its evidence comes from history alone.
        ind_ctx: Dict[str, datetime] = {}
        with self.db._cursor() as cur:
            for row in cur.execute("SELECT ip, first_seen FROM indicators WHERE kind = 'ip'"):
                fs = _parse_tick(row["first_seen"])
                if fs is not None:
                    ind_ctx[row["ip"]] = fs
        self._ind_ctx = ind_ctx
        self._loaded = True

    # ---- membership history (point-in-time) ----

    def _source_intervals(self, ip: str) -> Dict[str, List[Tuple[float, float]]]:
        """Per source, the [start, end) epoch intervals during which it listed
        this ip, reconstructed from transitions plus today's source_state:
        a source whose first event is a LEAVE held the ip before the log saw
        it (a baseline, which logs no arrival), so that interval opens at
        -inf; a source with no events but the ip in its state has listed it
        throughout. Known limit: a feed added mid-log reads as listing its
        baseline members from -inf, not from when it was added."""
        by_src: Dict[str, List[Tuple[float, int]]] = defaultdict(list)
        for ts, src, present in self._events.get(ip, []):
            by_src[src].append((ts.timestamp(), present))
        out: Dict[str, List[Tuple[float, float]]] = {}
        for src in set(by_src) | self._state_srcs.get(ip, set()):
            evs = by_src.get(src)
            if not evs:
                out[src] = [(-math.inf, math.inf)]
                continue
            spans: List[Tuple[float, float]] = []
            open_at: Optional[float] = -math.inf if evs[0][1] == 0 else None
            for t, present in evs:       # loaded in (tick, arrivals-first) order
                if present == 1 and open_at is None:
                    open_at = t
                elif present == 0 and open_at is not None:
                    spans.append((open_at, t))
                    open_at = None
            if open_at is not None:
                spans.append((open_at, math.inf))
            out[src] = spans
        return out

    def listing_intervals(self, ip: str) -> Tuple[List[float], List[float]]:
        """Merged [start, end) intervals when ANY (non-excluded) source listed
        the ip, as parallel sorted lists. Cached: the trainer asks for every
        candidate at every snapshot."""
        self._ensure_loaded()
        hit = self._intervals.get(ip)
        if hit is not None:
            return hit
        spans = sorted(sp for v in self._source_intervals(ip).values() for sp in v)
        starts: List[float] = []
        ends: List[float] = []
        for a, b in spans:
            if ends and a <= ends[-1]:
                ends[-1] = max(ends[-1], b)
            else:
                starts.append(a)
                ends.append(b)
        self._intervals[ip] = (starts, ends)
        return starts, ends

    def in_corpus_at(self, ip: str, t: float, retention_s: float) -> bool:
        """Would this ip have been in the corpus at epoch t: listed then, or
        dropped within the retention window before it? That is the population
        serving scores, so it is the population training must sample."""
        starts, ends = self.listing_intervals(ip)
        i = bisect_right(starts, t) - 1
        return i >= 0 and ends[i] > t - retention_s

    def candidate_ips(self) -> List[str]:
        """Every ip (not domain) with any membership history."""
        self._ensure_loaded()
        out = []
        for v in set(self._events) | set(self._state_srcs):
            try:
                ipaddress.ip_address(v)
            except ValueError:
                continue
            out.append(v)
        return out

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
        ref = self.now.timestamp()
        per_src = self._source_intervals(ip_str)
        n_src = sum(1 for spans in per_src.values()
                    if any(a <= ref < b for a, b in spans))

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

        # First evidence as of ref: the indicator row's first_seen only if it
        # already existed then (a row evicted and re-added after ref carries a
        # LATER first_seen), else the earliest listing interval; a baseline
        # listing (open at -inf) counts from the start of the log.
        first_seen_age_h = 0.0
        last_event_age_h = 0.0
        candidates = []
        row_fs = self._ind_ctx.get(ip_str)
        if row_fs is not None and row_fs.timestamp() <= ref:
            candidates.append(row_fs.timestamp())
        starts = [a for spans in per_src.values() for a, _b in spans if a <= ref]
        if starts:
            first = min(starts)
            if math.isinf(first):
                first = self._log_start if self._log_start is not None else ref
            candidates.append(first)
        if candidates:
            first_seen_age_h = max(0.0, (ref - min(candidates)) / 3600.0)
        if ev:
            last_event_age_h = max(0.0, (self.now - ev[-1][0]).total_seconds() / 3600.0)

        try:
            addr = ipaddress.ip_address(ip_str)
            key = (_prefix4_for(addr) if addr.version == 4 else _prefix6_for(addr))
            # neighbours only: counting the ip itself leaked eviction (a
            # still-present returner counted itself, an evicted one did not)
            density = self._prefix_counts.get(key, 0) - (1 if ip_str in self._ind_ctx else 0)
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
            # Match the trainer EXACTLY: build_dataset drops churn_log_exclude
            # feeds AND static (local_file) feeds from the event stream. If
            # scoring excluded a different set, features would count transitions
            # the labels never saw — train/serve skew that silently invalidates
            # the backtest the model was certified against. Read churn_log_exclude
            # from config directly (no pipeline import: predictor must stay
            # importable without the app's fetch stack) and union the static
            # feeds from the DB, mirroring train_predictor.build_dataset.
            excl = {str(n) for n in
                    (self.config.get("retention", {}) or {}).get(
                        "churn_log_exclude", []) or []}
            excl |= self.db.local_file_feed_names()
            self._builder = FeatureBuilder(
                self.db, self.config, exclude_sources=excl)
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
            booster = lgb.Booster(model_file=self.model_path)
        except Exception:
            return None
        # A model trained on a different feature set would score these rows
        # without error and without meaning (v2.5.0 redefined two features).
        if list(booster.feature_name()) != list(FEATURE_NAMES):
            logger.error("[predictor] %s was trained on features %s, this build "
                         "computes %s; retrain before predicting",
                         self.model_path, booster.feature_name(), FEATURE_NAMES)
            return None
        self._booster = booster
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
