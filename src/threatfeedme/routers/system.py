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
from threatfeedme.models import ALL_FEEDS, ConfidenceTier, FeedType, WHITELIST_REASONS
from threatfeedme.scheduler import REFRESH_INTERVAL_KEY, _refresh_interval_minutes, _run_backup
from threatfeedme.pipeline import RETENTION_MAX_AGE_KEY, retention_max_age_days
from threatfeedme.schemas import SettingsRequest
from threatfeedme.scorer import fp_penalty_factor, FP_DEGRADED_FACTOR

router = APIRouter()


# ==================== DASHBOARD (HTML) ====================

# Badge class + label per whitelist reason code (rendered by the template).
_REASON_BADGES = {
    "false_positive": ("badge badge-error", "false positive"),
    "risk_accepted": ("badge badge-warn", "risk accepted"),
    "internal_asset": ("badge badge-success", "internal asset"),
    "other": ("badge", "other"),
}


@router.get("/", response_class=HTMLResponse)
def dashboard(request: Request, _=Depends(require_auth)):
    """Main dashboard page.

    All values are rendered through the Jinja2 template (autoescape on), so no
    manual HTML escaping happens here — the route only computes plain data.
    """
    feed_base = _feed_base(request)
    feed_sources = core.db.get_feed_sources()
    feed_stats = {fs.feed_name: fs for fs in core.db.get_feed_stats()}
    whitelist = core.db.get_whitelist()

    # Per-feed counts, whitelist-scoped (including tier-scoped entries) so
    # each card's number matches what its URL actually serves.
    wl_map = core.db.get_whitelist_map()
    counts = {}
    for f in TIER_FEEDS:
        tier_key = f["key"]
        if tier_key == "all":
            inds = core.db.get_all_indicators()
            counts[tier_key] = sum(1 for i in inds if is_included(i, wl_map))
        else:
            tier_enum = ConfidenceTier(tier_key)
            inds = core.db.get_all_indicators_by_tier(tier_enum)
            counts[tier_key] = sum(1 for i in inds if is_included(i, wl_map, tier=tier_enum))

    # ---- Feed URL cards (the hero of the page) ----
    total_inds = len(core.db.get_all_indicators())
    feed_cards = [
        {
            "name": f["key"],
            "label": f["label"],
            "blurb": f["description"],
            "recommended": f["recommended"],
            "count": counts[f["key"]],
            "processing": f["key"] != "all" and counts[f["key"]] == 0 and total_inds > 0,
        }
        for f in TIER_FEEDS
    ]

    # ---- Feed false-positive health ----
    fp_counts = core.db.get_feed_fp_counts()
    report_counts = core.db.get_feed_report_counts()

    # ---- Feed management rows (config joined with last-run status) ----
    feed_rows = []
    for fsrc in feed_sources:
        st = feed_stats.get(fsrc.name)
        fp = fp_counts.get(fsrc.name, 0)
        degraded_pct = None
        if fp:
            factor = fp_penalty_factor(fp, report_counts.get(fsrc.name, 0))
            if factor <= FP_DEGRADED_FACTOR:
                degraded_pct = int(round((1 - factor) * 100))
        feed_rows.append({
            "name": fsrc.name,
            "url": fsrc.url,
            "feed_type": fsrc.feed_type.value,
            "source_kind": "file" if fsrc.local_file else "url",
            "weight": fsrc.weight,
            "enabled": fsrc.enabled,
            "status": st.status if st else None,          # None = never run
            "indicators": st.total_indicators if st else None,
            "fp_count": fp,
            "degraded_pct": degraded_pct,
            # API-key UI: only whether a key exists — never the value.
            "auth_env": fsrc.auth_env,
            "key_configured": bool(fsrc.auth_env and os.environ.get(fsrc.auth_env)),
        })

    return core.templates.TemplateResponse(request, "dashboard.html", {
        "page": "dashboard",
        "feed_base": feed_base,
        "counts": counts,
        "whitelist_count": len(whitelist),
        "feed_cards": feed_cards,
        "feed_rows": feed_rows,
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
