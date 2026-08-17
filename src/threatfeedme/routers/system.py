"""The HTML dashboard page plus stats, settings, backup, and rescore endpoints."""
import json
import os
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse

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
    # (get_all_indicators_by_tier) and again for total_inds — each fetch runs
    # a correlated GROUP_CONCAT subquery per row, so with tens of thousands
    # of indicators the dashboard was spending seconds just to count.
    wl_map = core.db.get_whitelist_map()
    # `served` is what each feed URL actually returns (cumulative: medium.txt
    # contains high), computed PER KIND for the feed matrix (D2 revised).
    # Which output feeds contain an indicator is the inverse of
    # CUMULATIVE_TIERS; tier-scoped whitelist exclusions apply per output.
    # Streamed, not materialized: a full-table model list on every dashboard
    # view was one of the allocations that OOMed 2 GB deployments.
    served, total_inds = _served_counts(core.db, wl_map)

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
            "source_kind": "file" if fsrc.local_file else "url",
            "weight": fsrc.weight,
            "enabled": fsrc.enabled,
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
    problem_rows = [r for r in enabled_tele if r["health"]["state"] in ("error", "stale")]
    interval_min = _refresh_interval_minutes()
    refresh_age_min = refresh_next_min = None
    refresh_overdue = False
    last_fin = _refresh_state.get("last_finished")
    if last_fin:
        try:
            fin = datetime.fromisoformat(last_fin)
            if fin.tzinfo is None:
                fin = fin.replace(tzinfo=timezone.utc)
            refresh_age_min = max(0, int((datetime.now(timezone.utc) - fin).total_seconds() // 60))
            refresh_next_min = max(0, interval_min - refresh_age_min)
            refresh_overdue = refresh_age_min > 2 * interval_min
        except (ValueError, TypeError):
            pass
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
    pulse = {
        "feeds_total": len(enabled_tele),
        "feeds_healthy": len(enabled_tele) - len(problem_rows),
        "first_problem": problem_rows[0]["name"] if problem_rows else None,
        "refresh_age_min": refresh_age_min,
        "refresh_next_min": refresh_next_min,
        "refresh_overdue": refresh_overdue,
        "new24_ip": sum((r["new"] or 0) for r in enabled_tele if r["kind"] == "ip"),
        "new24_domain": sum((r["new"] or 0) for r in enabled_tele if r["kind"] == "domain"),
        "whitelist_count": len(core.db.get_whitelist()),
        "fp_total": fp_total,
        "unifi": unifi_pulse,
    }

    return core.templates.TemplateResponse(request, "dashboard.html", {
        "page": "dashboard",
        "pulse": pulse,
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
