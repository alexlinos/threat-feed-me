"""The HTML dashboard page plus stats, settings, backup, and rescore endpoints."""
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
from threatfeedme.scheduler import REFRESH_INTERVAL_KEY, _refresh_interval_minutes, _run_backup
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
    outputs_containing = {t: tuple(out for out, members in CUMULATIVE_TIERS.items()
                                   if t in members)
                          for t in ConfidenceTier}
    served = {k: {t.value: 0 for t in ConfidenceTier} for k in ("ip", "domain")}
    served["ip"]["all"] = served["domain"]["all"] = 0
    total_inds = {"ip": 0, "domain": 0}
    for i in core.db.iter_indicators_by_tiers(tuple(ConfidenceTier)):
        kind = i.kind if i.kind in served else "ip"
        total_inds[kind] += 1
        if not is_included(i, wl_map):
            continue
        served[kind]["all"] += 1
        for out in outputs_containing[i.tier]:
            if is_included(i, wl_map, tier=out):
                served[kind][out.value] += 1

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
    kind_scored = {
        "ip": core.db.get_setting(ConfidenceScorer.TIER_BREAKS_KEY) is not None,
        "domain": core.db.get_setting(ConfidenceScorer.TIER_BREAKS_KEY_DOMAINS) is not None,
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
    # feed + indicator counts. Entries are the currently-attributed telemetry
    # counts (same number the rows show), summed within kind.
    feed_groups = []
    for kind, label in (("ip", "IP feeds"), ("domain", "Domain feeds")):
        rows = [r for r in feed_rows if r["kind"] == kind]
        if not rows:
            continue
        feed_groups.append({
            "kind": kind,
            "label": label,
            "feed_count": len(rows),
            "entry_count": sum((r["tele"]["indicators"] if r["tele"] else (r["indicators"] or 0))
                               for r in rows),
        })

    return core.templates.TemplateResponse(request, "dashboard.html", {
        "page": "dashboard",
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
