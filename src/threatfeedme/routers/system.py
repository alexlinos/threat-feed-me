"""The HTML dashboard page plus stats, settings, backup, and rescore endpoints."""
import json
import os
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from threatfeedme import pipeline
from threatfeedme.auth import csrf_check, require_auth
from threatfeedme import core
from threatfeedme.exporter import is_included
from threatfeedme.feed_helpers import TIER_FEEDS, _feed_base
from threatfeedme.models import (ALL_FEEDS, ConfidenceTier, CUMULATIVE_TIERS,
                                 FeedType, WHITELIST_REASONS)
from threatfeedme.scheduler import (REFRESH_INTERVAL_KEY, _refresh_interval_minutes,
                                    _refresh_state, _run_backup)
from threatfeedme.pipeline import RETENTION_MAX_AGE_KEY, retention_max_age_days
from threatfeedme.schemas import SettingsRequest
from threatfeedme.scorer import fp_penalty_factor, FP_DEGRADED_FACTOR
from threatfeedme.telemetry import feed_telemetry

router = APIRouter()


# ==================== DASHBOARD (HTML) ====================

# Badge class + label per whitelist reason code (rendered by the template).
_REASON_BADGES = {
    "false_positive": ("badge badge-error", "false positive"),
    "risk_accepted": ("badge badge-warn", "risk accepted"),
    "internal_asset": ("badge badge-success", "internal asset"),
    "other": ("badge", "other"),
}


# Keyed by indicator count so a refresh that changes the corpus invalidates
# the cache; otherwise the map would show first-computed numbers until the
# process restarted.
_geo_cache = {"data": None, "total": None, "key": None}


def _geo_counts(db):
    """Country buckets for the dashboard geo heatmap, computed lazily and
    cached. Returns [(name, count), ...] or [] if the compact geo table is
    not built yet. Never runs on dashboard load — only on demand (see the
    /api/geo/countries endpoint the heatmap <details> opens)."""
    try:
        key = db.geo_cache_key()
    except Exception:
        key = None
    if _geo_cache["data"] is not None and _geo_cache["key"] == key:
        return _geo_cache["data"]
    try:
        raw = db.country_counts()
    except Exception:
        return []
    # ISO code alongside the name: the choropleth keys country shapes by code,
    # the ranked list shows the name.
    from threatfeedme.geo.countries import code_name
    data = [(iso, code_name(iso), n) for iso, n in raw]
    total = sum(row[2] for row in data)
    # Set the cache key only AFTER data/total are fully computed, so a failure
    # mid-build never advances the key while leaving stale data behind (which
    # would permanently serve the old map under a new fingerprint).
    _geo_cache["data"] = data
    _geo_cache["total"] = total
    _geo_cache["key"] = key
    return data

def _human_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024.0


def _age_text(iso) -> str:
    try:
        dt = datetime.fromisoformat(str(iso))
    except (TypeError, ValueError):
        return ""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    m = max(0, int((datetime.now(timezone.utc) - dt).total_seconds() // 60))
    if m < 1:
        return "just now"
    if m < 60:
        return f"{m}m ago"
    if m < 60 * 48:
        return f"{m // 60}h ago"
    return f"{m // 1440}d ago"


def _system_info(request: Request, poll_log: dict) -> dict:
    """The System panel: the operational facts that were only reachable by
    SSH before (DB size, last backup, predictor state), plus the TAXII URL.
    Everything read-only here; actions go through existing endpoints."""
    from threatfeedme import __version__
    from threatfeedme.scheduler import LAST_BACKUP_KEY
    from threatfeedme.scorer import current_votes_enabled, predictor_live, vote_grace_days
    size = 0
    for path in (core.db_path, core.db.churn_path):      # main DB + churn log
        for suffix in ("", "-wal"):
            try:
                size += os.path.getsize(path + suffix)
            except OSError:
                pass
    last_backup = core.db.get_setting(LAST_BACKUP_KEY)
    pcfg = core.config.get("predictor", {}) or {}
    model_path = pcfg.get("model_path", "data/predictor_model.txt")
    try:
        model_age = _age_text(datetime.fromtimestamp(os.path.getmtime(model_path),
                                                     timezone.utc).isoformat())
    except OSError:
        model_age = ""
    predict_stamp = core.db.get_setting(pipeline.PREDICT_STAMP_KEY)
    taxii_polls = sorted(
        ((k.split(":", 1)[1], v) for k, v in poll_log.items() if k.startswith("taxii:")),
        key=lambda kv: kv[1].get("at", ""), reverse=True)
    from threatfeedme import polls
    return {
        "version": __version__,
        "db_size": _human_bytes(size),
        "last_backup": _age_text(last_backup) if last_backup else "",
        "predictor": {
            "enabled": bool(pcfg.get("enabled")),
            "live": predictor_live(core.config),
            "weight": (core.config.get("scoring", {}) or {}).get("predictor_weight", 0),
            "model_age": model_age,
            "last_pass": _age_text(predict_stamp) if predict_stamp else "",
        },
        "vote_grace_days": vote_grace_days(core.config) if current_votes_enabled(core.config) else None,
        "retention_days": retention_max_age_days(core.db, core.config),
        "auth": _dashboard_auth_status(request),
        "taxii_url": f"{_feed_base(request)}/taxii2/",
        "taxii_polls": [{"collection": c, "age": _age_text(v.get("at")),
                         "by": polls.agent_label(v.get("agent", ""))} for c, v in taxii_polls[:6]],
    }


def _every_text(seconds: int) -> str:
    """A feed's cadence for the Feeds table: 15m, 1h, 12h, 1d."""
    m = max(1, int(seconds) // 60)
    if m % 1440 == 0:
        return f"{m // 1440}d"
    return f"{m // 60}h" if m % 60 == 0 else f"{m}m"


def _compact(n: int) -> str:
    """Human-compact count for the matrix's narrow layout (42.4k, 1.2M)."""
    if n >= 1_000_000:
        return f"{n / 1_000_000:.1f}M"
    if n >= 10_000:
        return f"{n / 1_000:.1f}k"
    return f"{n:,}"


_OUTPUTS_CONTAINING = {t: tuple(out for out, members in CUMULATIVE_TIERS.items()
                                if t in members)
                       for t in ConfidenceTier}


_COUNTS_TTL_S = 300
_counts_cache = {"key": None, "at": 0.0, "value": None}


def _served_counts_cached(db, wl_map):
    """_served_counts keyed on serve_fingerprint (rows, the rescore stamp, the
    whitelist): it moves exactly when a served list can. ~1.6 s per dashboard
    view at 890k indicators before this. The TTL covers whitelist entries that
    expire by the clock without changing the fingerprint."""
    import copy
    import time
    key = (getattr(db, "db_path", None), db.serve_fingerprint())
    now = time.monotonic()
    c = _counts_cache
    if c["key"] == key and now - c["at"] < _COUNTS_TTL_S:
        return copy.deepcopy(c["value"])
    value = _served_counts(db, wl_map)
    c.update(key=key, at=now, value=value)
    return copy.deepcopy(value)


def _served_counts(db, wl_map):
    """(served, total_inds) per kind for the feed matrix.

    Fast path: whitelists are rare and small, the corpus is not — so count
    the corpus in SQL (one aggregation) and apply whitelist exclusions as
    per-entry corrections against indexed single-row lookups. Walking 600k+
    rows through Python is_included checks took ~10s per dashboard view on
    prod once the domain corpus landed.

    CIDR whitelist rules can exclude unbounded rows, so their presence
    falls back to the exact full walk. Both paths must agree — there is a
    parity test."""
    # CIDR and wildcard-domain rules can each exclude unbounded rows —
    # either forces the exact walk.
    if getattr(wl_map, "cidr_rules", None) or getattr(wl_map, "wildcard_rules", None):
        return _served_counts_walk(db, wl_map)

    raw = db.get_tier_kind_counts()
    served = {k: {t.value: 0 for t in ConfidenceTier} for k in ("ip", "domain")}
    served["ip"]["all"] = served["domain"]["all"] = 0
    total_inds = {"ip": 0, "domain": 0}
    for (kind, tier), n in raw.items():
        kind = kind if kind in served else "ip"
        total_inds[kind] += n
        served[kind]["all"] += n
        try:
            tier_enum = ConfidenceTier(tier)
        except ValueError:
            continue
        for out in _OUTPUTS_CONTAINING[tier_enum]:
            served[kind][out.value] += n

    # Corrections: each whitelisted value is at most one indicator row
    # (indexed lookup). Recompute its true inclusion and subtract what the
    # raw counts credited.
    seen = set()
    for entry in db.get_whitelist():
        ip = entry.ip
        if ip in seen or "/" in ip:
            continue
        seen.add(ip)
        ind = db.get_indicator(ip)
        if ind is None:
            continue
        kind = ind.kind if ind.kind in served else "ip"
        if not is_included(ind, wl_map):
            served[kind]["all"] -= 1
        for out in _OUTPUTS_CONTAINING[ind.tier]:
            if not is_included(ind, wl_map, tier=out):
                served[kind][out.value] -= 1
    return served, total_inds


def _served_counts_walk(db, wl_map):
    """Exact full walk (the original path); kept for CIDR whitelist rules
    and as the parity oracle for the fast path."""
    served = {k: {t.value: 0 for t in ConfidenceTier} for k in ("ip", "domain")}
    served["ip"]["all"] = served["domain"]["all"] = 0
    total_inds = {"ip": 0, "domain": 0}
    for i in db.iter_indicators_by_tiers(tuple(ConfidenceTier)):
        kind = i.kind if i.kind in served else "ip"
        total_inds[kind] += 1
        if not is_included(i, wl_map):
            continue
        served[kind]["all"] += 1
        for out in _OUTPUTS_CONTAINING[i.tier]:
            if is_included(i, wl_map, tier=out):
                served[kind][out.value] += 1
    return served, total_inds


@router.get("/", response_class=HTMLResponse)
def dashboard(request: Request, _=Depends(require_auth)):
    """Main dashboard page.

    All values are rendered through the Jinja2 template (autoescape on), so no
    manual HTML escaping happens here — the route only computes plain data.
    """
    feed_base = _feed_base(request)
    feed_sources = core.db.get_feed_sources()
    feed_stats = {fs.feed_name: fs for fs in core.db.get_feed_stats()}

    # Per-feed counts, whitelist-scoped (including tier-scoped entries) so
    # each matrix cell's number matches what its URL actually serves.
    #
    # Load the indicator list ONCE and derive every (tier x kind) count from
    # that single pass. The old code re-fetched the full table per tier
    # (the old per-tier full-table query) and again for total_inds — each fetch runs
    # a correlated GROUP_CONCAT subquery per row, so with tens of thousands
    # of indicators the dashboard was spending seconds just to count.
    wl_map = core.db.get_whitelist_map()
    # `served` is what each feed URL actually returns (cumulative: medium.txt
    # contains high), computed PER KIND for the feed matrix (D2 revised).
    # Which output feeds contain an indicator is the inverse of
    # CUMULATIVE_TIERS; tier-scoped whitelist exclusions apply per output.
    # Streamed, not materialized: a full-table model list on every dashboard
    # view was one of the allocations that OOMed 2 GB deployments.
    served, total_inds = _served_counts_cached(core.db, wl_map)

    # ---- Feed matrix (the hero of the page; D2 revised) ----
    # Rows = tiers, columns = kinds; each cell is a URL + the count it serves.
    # The old stat-tile row is retired — the counts live inline in the cells.
    #
    # "Processing…" is only honest in the window between first ingest and
    # first rescore. Once a kind has tier breaks persisted it HAS been
    # tiered, and an empty high feed is a real answer (with only a few
    # domain feeds, zero triple-corroborated domains is steady state), not
    # a spinner.
    from threatfeedme.scorer import ConfidenceScorer
    # Legacy tiering never persists breaks, so the settings probe would show
    # "Processing…" forever there; legacy tiers synchronously at rescore, so
    # treat it as always-scored.
    legacy = ((core.config.get('scoring', {}).get('tiering', {}) or {})
              .get('method') == 'legacy')
    kind_scored = {
        "ip": legacy or core.db.get_setting(ConfidenceScorer.TIER_BREAKS_KEY) is not None,
        "domain": legacy or core.db.get_setting(ConfidenceScorer.TIER_BREAKS_KEY_DOMAINS) is not None,
    }
    from threatfeedme import polls
    poll_log = polls.snapshot(core.db)

    def _last_poll(kind: str, key: str):
        """Most recent poll of this cell's URL in any format; the Everything
        cell also counts its low.txt alias."""
        names = [key] + (["low"] if key == "all" else [])
        pre = "domains/" if kind == "domain" else ""
        hits = [poll_log[f"{pre}{n}.{ext}"] for n in names for ext in ("txt", "csv", "json")
                if f"{pre}{n}.{ext}" in poll_log]
        if not hits:
            return None
        last = max(hits, key=lambda e: e.get("at", ""))
        return {"age_min": polls.age_minutes(last), "by": polls.agent_label(last.get("agent", "")),
                "count": sum(int(e.get("count", 0)) for e in hits),
                "agent": last.get("agent", "")}

    matrix_rows = []
    for f in TIER_FEEDS:
        if f.get("hidden"):
            continue
        key = f["key"]
        cells = {}
        for kind, prefix in (("ip", "/feeds/"), ("domain", "/feeds/domains/")):
            n = served[kind][key]
            cells[kind] = {
                "path": f"{prefix}{key}",
                "count": n,
                "compact": _compact(n),
                "processing": (key != "all" and n == 0 and total_inds[kind] > 0
                               and not kind_scored[kind]),
                "polled": _last_poll(kind, key),
            }
        matrix_rows.append({
            "name": key,
            "label": f["label"],
            "blurb": f["description"],
            "recommended": f["recommended"],
            "ip": cells["ip"],
            "domain": cells["domain"],
        })

    # ---- Feed false-positive health ----
    fp_counts = core.db.get_feed_fp_counts()
    report_counts = core.db.get_feed_report_counts()

    # ---- Feed management rows ----
    # Configuration, last-run status, and telemetry are one table: a feed's
    # settings and its actual value are the same question, and splitting them
    # into two sections pushed the management surface off the page.
    telemetry = feed_telemetry(core.db)
    tele_by_name = {r["name"]: r for r in telemetry["rows"]}
    schedule = pipeline.feed_schedule(core.db, _refresh_interval_minutes() * 60)
    feed_rows = []
    for fsrc in feed_sources:
        st = feed_stats.get(fsrc.name)
        fp = fp_counts.get(fsrc.name, 0)
        degraded_pct = None
        if fp:
            factor = fp_penalty_factor(fp, report_counts.get(fsrc.name, 0))
            if factor <= FP_DEGRADED_FACTOR:
                degraded_pct = int(round((1 - factor) * 100))
        tele = tele_by_name.get(fsrc.name)
        feed_rows.append({
            "name": fsrc.name,
            "url": fsrc.url,
            "feed_type": fsrc.feed_type.value,
            "kind": fsrc.indicator_kind or "ip",
            "source_kind": ("file" if fsrc.local_file
                            else "taxii 2.1" if fsrc.scraper == "taxii21" else "url"),
            "taxii": fsrc.scraper == "taxii21",
            "weight": fsrc.weight,
            "enabled": fsrc.enabled,
            # Own clock: cadence and a countdown (None when disabled).
            "every": _every_text(schedule[fsrc.name][0]) if fsrc.name in schedule else None,
            "next_min": (-(-max(0, int(schedule[fsrc.name][1])) // 60)
                         if fsrc.name in schedule else None),
            "status": st.status if st else None,          # None = never run
            "indicators": st.total_indicators if st else None,
            "fp_count": fp,
            "degraded_pct": degraded_pct,
            # Problems float (D9): a feed that is erroring, stale, or
            # reputation-degraded surfaces above healthy rows within its kind
            # group — a monitoring table must not hide its alarms mid-scroll.
            "problem": bool(
                (tele and tele["health"]["state"] in ("error", "stale"))
                or degraded_pct is not None),
            # API-key UI: only whether a key exists — never the value.
            "auth_env": fsrc.auth_env,
            # Multi-credential feeds (comma-separated auth_env): the badge
            # shows Key ✓ only when every declared var is present.
            "key_configured": bool(fsrc.auth_env) and all(
                os.environ.get(v.strip())
                for v in fsrc.auth_env.split(',') if v.strip()),
            # Telemetry, merged in so each row answers "is this feed worth it?"
            "tele": tele,
        })
    # Within each kind group: problems first, then the feeds you would most
    # miss (exclusive contribution), then size, then name.
    feed_rows.sort(key=lambda r: (
        0 if r["problem"] else 1,
        -(r["tele"]["exclusive"] if r["tele"] else 0),
        -(r["indicators"] or 0),
        r["name"],
    ))

    # One table, kind-grouped (D9): slim group header rows carry the per-kind
    # feed count and DISTINCT indicator count (total_inds from the counting
    # pass above). Summing the rows' per-feed attributions double-counts
    # every shared indicator — with the roster's documented overlap the IP
    # header would read ~2x the real corpus, beside a matrix showing truth.
    feed_groups = []
    for kind, label in (("ip", "IP feeds"), ("domain", "Domain feeds")):
        rows = [r for r in feed_rows if r["kind"] == kind]
        if not rows:
            continue
        feed_groups.append({
            "kind": kind,
            "label": label,
            "feed_count": len(rows),
            "entry_count": total_inds[kind],
        })

    # ---- Ops pulse row ----
    # Five glanceable answers: anything broken / data fresh / what arrived /
    # what am I overriding / did it reach the gateway. Deliberately carries
    # NO corpus sizes — the matrix below owns those (the old stat tiles died
    # for duplicating them).
    enabled_tele = [r for r in telemetry["rows"] if r["enabled"]]
    last_fin = _refresh_state.get("last_finished")
    if not last_fin:
        # The run state lives in memory, so after a restart the page said
        # "first fetch pending" over a fully fetched corpus. The newest feed
        # fetch in the DB is when the data was last refreshed.
        stamps = [v for v in core.db.get_feed_last_updates().values() if v]
        last_fin = max(stamps) if stamps else None
    # "never run" = no successful fetch yet. Before any refresh has finished
    # that is just pending; after one, the feed had its chance and has
    # nothing, which is a problem (it used to count as healthy, so a feed
    # failing since day one sat inside "all feeds reporting").
    never = [r for r in enabled_tele if r["health"]["state"] == "never run"]
    problem_rows = [r for r in enabled_tele if r["health"]["state"] in ("error", "stale")]
    pending_rows = []
    if last_fin:
        problem_rows += never
    else:
        pending_rows = never
    interval_min = _refresh_interval_minutes()
    refresh_age_min = refresh_next_min = None
    refresh_overdue = False
    if last_fin:
        try:
            fin = datetime.fromisoformat(last_fin)
            if fin.tzinfo is None:
                fin = fin.replace(tzinfo=timezone.utc)
            refresh_age_min = max(0, int((datetime.now(timezone.utc) - fin).total_seconds() // 60))
        except (ValueError, TypeError):
            pass
    # "next" is the soonest FEED to come due: feeds run on their own clocks
    # (15 min to 24 h), so the global interval said "next in ~46m" while a
    # 15-minute feed was minutes away. Overdue = a feed a full interval late.
    next_feed = None
    nxt = pipeline.next_due(core.db, interval_min * 60) if last_fin else None
    if nxt:
        refresh_next_min = -(-nxt["in_s"] // 60)
        refresh_overdue = nxt["late"]
        next_feed = nxt["feed"]
    fp_total = sum(fp_counts.values())
    unifi_pulse = None
    from threatfeedme import pusher_unifi
    if pusher_unifi.push_ready(core.db, core.config):
        push_age_min = push_ok = None
        try:
            raw = core.db.get_setting(pusher_unifi.LAST_PUSH_KEY)
            if raw:
                outcome = json.loads(raw)
                push_ok = not outcome.get("error")
                at = datetime.fromisoformat(outcome["at"])
                if at.tzinfo is None:
                    at = at.replace(tzinfo=timezone.utc)
                push_age_min = max(0, int((datetime.now(timezone.utc) - at).total_seconds() // 60))
        except (ValueError, TypeError, KeyError):
            pass
        unifi_pulse = {
            "ok": push_ok,
            "age_min": push_age_min,
            "tier": pusher_unifi.effective_block(core.db, core.config).get("tier", "high"),
        }
    crowdsec_pulse = None
    from threatfeedme import crowdsec
    if crowdsec.push_ready(core.db, core.config):
        cs_last = crowdsec._last(core.db)
        crowdsec_pulse = {
            "ok": (not cs_last.get("error")) if cs_last else None,
            "tier": crowdsec.effective_block(core.db, core.config).get("tier", "medium"),
        }
    system_info = _system_info(request, poll_log)
    new24 = core.db.get_new_indicator_counts(
        (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat())
    pulse = {
        "feeds_total": len(enabled_tele),
        "feeds_healthy": len(enabled_tele) - len(problem_rows) - len(pending_rows),
        "first_problem": problem_rows[0]["name"] if problem_rows else None,
        "problem_count": len(problem_rows),
        "pending_count": len(pending_rows),
        "refresh_age_min": refresh_age_min,
        "refresh_next_min": refresh_next_min,
        "refresh_next_feed": next_feed,
        "refresh_overdue": refresh_overdue,
        "new24_ip": new24.get("ip", 0),
        "new24_domain": new24.get("domain", 0),
        "whitelist_count": len(core.db.get_whitelist()),
        "fp_total": fp_total,
        "unifi": unifi_pulse,
        "crowdsec": crowdsec_pulse,
    }

    # ---- First-run guide (v2.5 "Guided" view) ----
    # Each step is answered from facts the page already has: a firewall has
    # "pulled" once any IP URL was polled, DNS is covered once a domain URL
    # was. The guide is the default view until the first IP poll, after
    # which the block lists are (the operator can reopen the guide any time).
    def _latest_poll(kind):
        polled = [(row, row[kind]["polled"]) for row in matrix_rows if row[kind]["polled"]]
        if not polled:
            return None
        row, p = min(polled, key=lambda rp: rp[1]["age_min"] if rp[1]["age_min"] >= 0 else 10**9)
        return {"tier": row["label"].replace(" Confidence", ""), **p}
    medium = next((r for r in matrix_rows if r["name"] == "medium"), matrix_rows[0] if matrix_rows else None)
    high = next((r for r in matrix_rows if r["name"] == "high"), None)
    ip_poll, dom_poll = _latest_poll("ip"), _latest_poll("domain")
    guide = {
        "feeds_in": (total_inds["ip"] + total_inds["domain"]) > 0,
        "ip_poll": ip_poll,
        "dom_poll": dom_poll,
        "integrations": bool(unifi_pulse or crowdsec_pulse or system_info["taxii_polls"]),
        "medium": medium,
        "high": high,
        "default": ip_poll is None,
    }

    return core.templates.TemplateResponse(request, "dashboard.html", {
        "page": "dashboard",
        "pulse": pulse,
        "guide": guide,
        "system": system_info,
        "first_run": (total_inds["ip"] + total_inds["domain"]) == 0,
        "telemetry": telemetry,
        "feed_base": feed_base,
        "matrix_rows": matrix_rows,
        "feed_rows": feed_rows,
        "feed_groups": feed_groups,
        "feed_types": [t.value for t in FeedType],
        "interval_min": _refresh_interval_minutes(),
        "retention_days": retention_max_age_days(core.db, core.config),
        "feed_names": [fsrc.name for fsrc in feed_sources],
        "all_feeds": ALL_FEEDS,
        "generated_at": datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC'),
    })


@router.get("/indicators", response_class=HTMLResponse)
def indicators_page(request: Request, q: str = "", _=Depends(require_auth)):
    """Merged indicators and whitelist management.

    Split off the dashboard: a 50-row page of a 50,000-row list is data
    exhaust, not an answer, and it buried the feed URLs that are the point of
    the landing page. `q` pre-fills the search so the dashboard's lookup box
    can deep-link straight to one address.
    """
    whitelist = core.db.get_whitelist()
    whitelist_rows = []
    for w in whitelist[:50]:
        badge_class, badge_label = _REASON_BADGES.get(w.reason_code, _REASON_BADGES["other"])
        whitelist_rows.append({
            "ip": w.ip,
            "feed_name": w.feed_name,
            "reason": w.reason,
            "added_by": w.added_by,
            "reason_class": badge_class,
            "reason_label": badge_label,
        })

    return core.templates.TemplateResponse(request, "indicators.html", {
        "page": "indicators",
        "q": q,
        "whitelist_rows": whitelist_rows,
        "all_feeds": ALL_FEEDS,
        "reason_options": WHITELIST_REASONS,
        "generated_at": datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC'),
    })


@router.get("/healthz")
def healthz():
    """Container liveness probe: constant-cost and unauthenticated.

    Deliberately NOT a feed URL — the old healthcheck streamed
    /feeds/all.txt, whose response time grows with the corpus, and past
    ~300k indicators it exceeded its own 5s timeout on a small box, marking
    every large deployment permanently unhealthy (and flooding the Docker
    event buffer with failed probes). Not /api/* either: those 401 when
    dashboard Basic auth is enabled. db.ping() is a commit-free read — it
    proves the server thread and the database file are both alive without
    ever touching the WAL single-writer lock (get_setting's _cursor()
    commits, which the 30s-interval probe must not do)."""
    core.db.ping()
    return {"ok": True}


@router.get("/api/stats")
def get_stats(_=Depends(require_auth)):
    """Get statistics summary"""
    return core.db.get_stats_summary()


@router.get("/api/telemetry")
def get_telemetry(_=Depends(require_auth)):
    """Per-feed contribution, freshness, health, and pairwise overlap."""
    return feed_telemetry(core.db)


@router.get("/api/geo/countries")
def geo_countries(_=Depends(require_auth)):
    """Blocked-IP country breakdown. Computed lazily and cached — the
    dashboard heatmap <details> fetches this only when a user opens it, so
    normal dashboard loads never pay the geo cost."""
    return {"data": _geo_counts(core.db), "total": _geo_cache["total"] or 0}


@router.get("/api/domains/tlds")
def domain_tlds(_=Depends(require_auth)):
    """Blocked-domain TLD breakdown for the dashboard TLD panel (ranked
    bars). Fetched lazily when the panel <details> is opened, same pattern
    as the geo heatmap; cheap enough (single-column scan) to skip a server
    cache."""
    data = core.db.get_domain_tld_counts()
    return {"data": data, "total": sum(n for _tld, n in data)}


# ---------------------- Settings ----------------------

@router.get("/api/settings")
def get_settings(_=Depends(require_auth)):
    return {
        "refresh_interval_minutes": _refresh_interval_minutes(),
        "retention_max_age_days": retention_max_age_days(core.db, core.config),
    }


@router.post("/api/settings")
def update_settings(request: SettingsRequest, _=Depends(require_auth), _csrf=Depends(csrf_check)):
    if request.refresh_interval_minutes is not None:
        if request.refresh_interval_minutes < 1:
            raise HTTPException(status_code=400, detail="refresh_interval_minutes must be >= 1")
        core.db.set_setting(REFRESH_INTERVAL_KEY, request.refresh_interval_minutes)
    if request.retention_max_age_days is not None:
        if not (0 <= request.retention_max_age_days <= 3650):
            raise HTTPException(status_code=400, detail="retention_max_age_days must be 0-3650 (0 = keep forever)")
        core.db.set_setting(RETENTION_MAX_AGE_KEY, request.retention_max_age_days)
    return {
        "success": True,
        "refresh_interval_minutes": _refresh_interval_minutes(),
        "retention_max_age_days": retention_max_age_days(core.db, core.config),
    }


class HostCheckRequest(BaseModel):
    allowed: List[str] = []
    # None keeps the current lock state; the first-run guide sends False so a
    # name the operator is about to create never starts refusing anything.
    enforce: Optional[bool] = None


class HostResolveRequest(BaseModel):
    name: str


_RESOLVE_TIMEOUT_S = 3.0


def _host_check_status(request: Request) -> dict:
    from threatfeedme import middleware as mw
    env = sorted(mw.env_allowed_hosts())
    configured = mw.configured_hosts(core.db)
    current = mw.host_of_header(request.headers.get("host"))
    enforcing = bool(mw.effective_allowlist(core.db))
    return {
        "mode": "enforcing" if enforcing else "report-only",
        "env": env,                  # TFM_ALLOWED_HOSTS (read-only here)
        "configured": configured,    # the dashboard-managed list
        "locked": bool(configured) and mw.enforce_configured(core.db),
        "seen": [s for s in mw.seen_hosts()
                 if s["host"] not in env and s["host"] not in configured],
        "current_host": current,
        "current_is_ip": mw.always_allowed(current),
    }


@router.get("/api/host-check")
def host_check_status(request: Request, _=Depends(require_auth)):
    """Host-header allowlist state: mode, allowed names, and the hostnames
    that have reached the dashboard (so the operator locks to real ones)."""
    return _host_check_status(request)


@router.post("/api/host-check")
def host_check_update(body: HostCheckRequest, request: Request,
                      _=Depends(require_auth), _csrf=Depends(csrf_check)):
    """Replace the dashboard-managed allowlist and, optionally, switch the
    host check on or off. `enforce` omitted keeps the current switch; the
    switch is OFF by default (upgrades and fresh installs refuse nothing).
    An empty list is always off. The hostname this request arrived on is
    always kept, so switching on can never lock out the page doing it."""
    from threatfeedme import middleware as mw
    names = []
    for value in body.allowed[:64]:
        name = mw.normalize_hostname(value)
        if name is None:
            raise HTTPException(status_code=400, detail=f"Not a valid hostname: {value!r}")
        names.append(name)
    current = mw.host_of_header(request.headers.get("host"))
    if names and not mw.always_allowed(current):
        names.append(current)
    enforce = mw.enforce_configured(core.db) if body.enforce is None else body.enforce
    core.db.set_setting(mw.ALLOWED_HOSTS_SETTING, json.dumps(sorted(set(names))))
    core.db.set_setting(mw.ENFORCE_SETTING, "1" if (enforce and names) else "0")
    mw.invalidate_allowlist_cache()
    return _host_check_status(request)


@router.post("/api/host-check/resolve")
def host_check_resolve(body: HostResolveRequest, request: Request,
                       _=Depends(require_auth), _csrf=Depends(csrf_check)):
    """Does a name the operator wants to use resolve, and to this server?

    A DNS lookup only (no connection is made), of a syntactically valid
    hostname, bounded by a short timeout. The answer is compared with the
    address the operator is using right now when that is an IP: a name that
    resolves elsewhere would hand firewalls a URL pointing at another box.
    """
    import concurrent.futures
    import ipaddress
    import socket
    from threatfeedme import middleware as mw
    name = mw.normalize_hostname(body.name)
    if name is None or mw.always_allowed(name):
        raise HTTPException(status_code=400, detail="Enter a DNS name, e.g. threatfeedme.lan")
    current = mw.host_of_header(request.headers.get("host"))
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    fut = pool.submit(socket.getaddrinfo, name, None, 0, socket.SOCK_STREAM)
    addresses, error = [], None
    try:
        infos = fut.result(timeout=_RESOLVE_TIMEOUT_S)
        addresses = sorted({i[4][0] for i in infos})[:8]
    except concurrent.futures.TimeoutError:
        error = "timed out"
    except socket.gaierror:
        error = "does not resolve"
    except (OSError, UnicodeError):
        error = "does not resolve"
    finally:
        pool.shutdown(wait=False)
    matches = None
    try:
        cur_ip = ipaddress.ip_address(current)
        matches = any(ipaddress.ip_address(a) == cur_ip for a in addresses)
    except ValueError:
        pass
    return {"name": name, "resolves": bool(addresses), "addresses": addresses,
            "error": error, "current_host": current, "matches_current": matches}


class DashboardAuthRequest(BaseModel):
    username: str
    password: str
    current_password: str = ""


def _bootstrap_host_ok(request: Request) -> bool:
    """Setting the FIRST sign-in (auth off) is only accepted on a request that
    reached us by IP, localhost or a hostname the operator saved. With auth
    off, a DNS-rebinding page in a LAN browser can send the CSRF header, but
    it arrives under the attacker's own domain, so it can't take the
    dashboard over by setting a password the operator doesn't know."""
    from threatfeedme import middleware as mw
    host = mw.host_of_header(request.headers.get("host"))
    return (mw.always_allowed(host) or host in mw.env_allowed_hosts()
            or host in mw.configured_hosts(core.db))


def _dashboard_auth_status(request: Request) -> dict:
    from threatfeedme import auth
    source = auth.auth_source()
    stored = auth.stored_credentials() if source == "dashboard" else None
    return {"source": source, "username": stored["user"] if stored else None,
            "bootstrap_ok": source is not None or _bootstrap_host_ok(request),
            "min_password": auth.MIN_PASSWORD}


@router.get("/api/dashboard-auth")
def dashboard_auth_status(request: Request, _=Depends(require_auth)):
    """Where the dashboard sign-in comes from. Never returns a password or hash."""
    return _dashboard_auth_status(request)


@router.post("/api/dashboard-auth")
def dashboard_auth_update(body: DashboardAuthRequest, request: Request,
                          _=Depends(require_auth), _csrf=Depends(csrf_check)):
    """Set or change the dashboard sign-in from the System page. The server
    environment (DASHBOARD_USER/PASSWORD) wins and can't be changed here; a
    change needs the current password; the first one needs the bootstrap
    host check above. Locked out? `python -m threatfeedme.main
    --reset-dashboard-auth` on the host clears it."""
    from threatfeedme import auth
    source = auth.auth_source()
    if source == "env":
        raise HTTPException(status_code=409, detail="The sign-in is set by the server's environment "
                            "(DASHBOARD_USER / DASHBOARD_PASSWORD); change it there")
    if source == "dashboard":
        if not auth.check_stored_password(auth.stored_credentials(), body.current_password):
            raise HTTPException(status_code=403, detail="Current password is wrong")
    elif not _bootstrap_host_ok(request):
        raise HTTPException(status_code=403, detail="Open the dashboard by its IP address (or a name "
                            "saved under Dashboard hostnames) to set the first password")
    problem = auth.invalid_new_credentials(body.username, body.password)
    if problem:
        raise HTTPException(status_code=400, detail=problem)
    auth.save_credentials(core.db, body.username, body.password)
    return _dashboard_auth_status(request)


@router.post("/api/recalculate-scores")
def recalculate_scores(_=Depends(require_auth), _csrf=Depends(csrf_check)):
    """Recalculate confidence scores for all indicators"""
    count = pipeline.recalculate(core.db, core.config)
    return {"success": True, "recalculated": count}


@router.post("/api/backup")
def trigger_backup(_=Depends(require_auth), _csrf=Depends(csrf_check)):
    """Take a database backup now (regardless of the auto-backup schedule)."""
    try:
        path = _run_backup()
        return {"success": True, "path": path}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Backup failed: {e}")
