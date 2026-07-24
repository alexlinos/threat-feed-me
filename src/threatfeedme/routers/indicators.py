"""Merged-indicator API endpoints and the firewall-facing public feed routes."""
import csv
import io
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import PlainTextResponse, Response

from threatfeedme import pipeline
from threatfeedme.auth import csrf_check, require_auth
from threatfeedme import core
from threatfeedme.exporter import firewall_value
from threatfeedme.feed_helpers import _FEEDS_BY_NAME, _indicators_for, _normalize_indicator
from threatfeedme.models import ALL_FEEDS
from threatfeedme.schemas import IndicatorRequest, WhitelistResponse

router = APIRouter()


# ==================== FEED ENDPOINTS (firewall-facing, unauthenticated) ======

@router.get("/feeds/{name}.txt", response_class=PlainTextResponse)
def feed_txt(name: str):
    """Plain-text block list, one IP/CIDR per line — the firewall feed format."""
    if name not in _FEEDS_BY_NAME:
        raise HTTPException(status_code=404, detail="Unknown feed")
    body = "".join(f"{firewall_value(i)}\n" for i in _indicators_for(name))
    return PlainTextResponse(body, headers={"Cache-Control": "no-cache"})


@router.get("/feeds/{name}.csv")
def feed_csv(name: str):
    """CSV with metadata (for SIEM / spreadsheet use)."""
    if name not in _FEEDS_BY_NAME:
        raise HTTPException(status_code=404, detail="Unknown feed")
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["ip", "confidence_score", "tier", "first_seen", "last_seen", "sources"])
    for i in _indicators_for(name):
        writer.writerow([
            firewall_value(i), i.confidence_score, i.tier.value,
            i.first_seen, i.last_seen, ";".join(i.sources),
        ])
    return Response(buf.getvalue(), media_type="text/csv")


@router.get("/feeds/{name}.json")
def feed_json(name: str):
    """JSON with full details (for programmatic / SIEM ingestion)."""
    if name not in _FEEDS_BY_NAME:
        raise HTTPException(status_code=404, detail="Unknown feed")
    indicators = _indicators_for(name)
    return {
        "feed": name,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_count": len(indicators),
        "indicators": [
            {
                "value": firewall_value(i),
                "ip": i.ip,
                "confidence_score": i.confidence_score,
                "tier": i.tier.value,
                "sources": i.sources,
                "last_seen": i.last_seen,
            }
            for i in indicators
        ],
    }


# ==================== JSON API (authenticated when auth enabled) ============

@router.get("/api/indicators")
def get_indicators(q: Optional[str] = None, limit: int = 50, offset: int = 0,
                         _=Depends(require_auth)):
    """Searchable, paginated view of the merged indicators (removed/globally
    whitelisted IPs excluded)."""
    limit = max(1, min(limit, 500))
    offset = max(0, offset)
    result = core.db.query_indicators(q=q, limit=limit, offset=offset)
    return {
        "total": result["total"],
        "count": len(result["rows"]),
        "offset": offset,
        "limit": limit,
        "indicators": result["rows"],
    }


@router.post("/api/indicators", response_model=WhitelistResponse)
def add_indicator(request: "IndicatorRequest", _=Depends(require_auth), _csrf=Depends(csrf_check)):
    """Manually add an IP/CIDR to the merged set (source 'manual')."""
    try:
        stored_ip, cidr = _normalize_indicator(request.ip)
    except ValueError:
        raise HTTPException(status_code=400, detail="Not a valid IP or CIDR")

    # Safety guard: refuse to add internal/reserved space or well-known good
    # infrastructure (e.g. 8.8.8.8) that must never be blocked.
    reason = core.SAFETY.excluded_reason(cidr or stored_ip)
    if reason:
        raise HTTPException(status_code=400, detail=f"Refusing to add {cidr or stored_ip}: {reason}")

    # If it was previously removed (globally whitelisted), un-remove it.
    core.db.remove_from_whitelist(stored_ip, feed_name=ALL_FEEDS)

    meta = {"cidr": cidr} if cidr else {}
    core.db.add_indicator(ip=stored_ip, source="manual", metadata=meta)

    # Score just this indicator so it lands in the right tier immediately.
    from threatfeedme.scorer import ConfidenceScorer
    scorer = ConfidenceScorer(core.db, pipeline.scorer_config(core.db, core.config))
    score, tier = scorer.calculate_score(stored_ip)
    core.db.set_indicator_score(stored_ip, score, tier.value)
    return WhitelistResponse(success=True, message=f"Added {cidr or stored_ip}")


@router.get("/api/indicators/{ip}")
def get_indicator_detail(ip: str, _=Depends(require_auth)):
    """Detail for one IP, including which feeds reported it (for the whitelist
    dialog so the operator can see the source before choosing a scope)."""
    ind = core.db.get_indicator(ip)
    if not ind:
        raise HTTPException(status_code=404, detail="Indicator not found")
    return {
        "ip": ind.ip,
        "value": ind.metadata.get("cidr") or ind.ip,
        "tier": ind.tier.value,
        "confidence_score": round(ind.confidence_score, 3),
        "sources": ind.sources,
    }


@router.delete("/api/indicators/{ip}")
def remove_indicator(ip: str, _=Depends(require_auth), _csrf=Depends(csrf_check)):
    """Remove an IP from the merged set.

    This globally whitelists it (so a feed refresh won't bring it back) and
    deletes the current row for immediate effect."""
    # Normalize so a CIDR value (e.g. 1.2.3.0/24) maps to the stored network
    # address the same way the add path does; reject values that aren't IPs so
    # no junk is persisted to the whitelist.
    try:
        stored_ip, _cidr = _normalize_indicator(ip)
    except ValueError:
        raise HTTPException(status_code=400, detail="Not a valid IP or CIDR")
    core.db.add_to_whitelist(stored_ip, reason="removed via dashboard", added_by="dashboard",
                        feed_name=ALL_FEEDS)
    core.db.delete_indicator(stored_ip)
    return {"success": True, "message": f"{stored_ip} removed and won't return on refresh"}
