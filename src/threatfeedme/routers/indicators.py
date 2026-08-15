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
from threatfeedme.feed_helpers import (_FEEDS_BY_NAME, _indicators_for,
                                       _normalize_indicator, _value_kind)
from threatfeedme.models import ALL_FEEDS
from threatfeedme.schemas import IndicatorRequest, WhitelistResponse

router = APIRouter()


# ==================== FEED ENDPOINTS (firewall-facing, unauthenticated) ======
# The same tier catalogue is served twice, once per indicator kind:
#   /feeds/{tier}.{fmt}          -> IPs/CIDRs only (never a domain — a
#                                   FortiGate address feed errors the whole
#                                   import on a hostname)
#   /feeds/domains/{tier}.{fmt}  -> domains only (DNS-filter / RPZ consumers)
# One shared body builder per format so the two kinds can never drift apart.


def _feed_txt(name: str, kind: str) -> PlainTextResponse:
    if name not in _FEEDS_BY_NAME:
        raise HTTPException(status_code=404, detail="Unknown feed")
    body = "".join(f"{firewall_value(i)}\n" for i in _indicators_for(name, kind=kind))
    return PlainTextResponse(body, headers={"Cache-Control": "no-cache"})


def _feed_csv(name: str, kind: str) -> Response:
    if name not in _FEEDS_BY_NAME:
        raise HTTPException(status_code=404, detail="Unknown feed")
    buf = io.StringIO()
    writer = csv.writer(buf)
    # The first column is the indicator value; the header keeps the historical
    # name "ip" for both kinds so existing SIEM column mappings don't break.
    writer.writerow(["ip", "confidence_score", "tier", "first_seen", "last_seen", "sources"])
    for i in _indicators_for(name, kind=kind):
        writer.writerow([
            firewall_value(i), i.confidence_score, i.tier.value,
            i.first_seen, i.last_seen, ";".join(i.sources),
        ])
    return Response(buf.getvalue(), media_type="text/csv")


def _feed_json(name: str, kind: str) -> dict:
    if name not in _FEEDS_BY_NAME:
        raise HTTPException(status_code=404, detail="Unknown feed")
    indicators = _indicators_for(name, kind=kind)
    return {
        "feed": name if kind == "ip" else f"domains/{name}",
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


@router.get("/feeds/{name}.txt", response_class=PlainTextResponse)
def feed_txt(name: str):
    """Plain-text block list, one IP/CIDR per line — the firewall feed format."""
    return _feed_txt(name, kind="ip")


@router.get("/feeds/{name}.csv")
def feed_csv(name: str):
    """CSV with metadata (for SIEM / spreadsheet use)."""
    return _feed_csv(name, kind="ip")


@router.get("/feeds/{name}.json")
def feed_json(name: str):
    """JSON with full details (for programmatic / SIEM ingestion)."""
    return _feed_json(name, kind="ip")


@router.get("/feeds/domains/{name}.txt", response_class=PlainTextResponse)
def domain_feed_txt(name: str):
    """Plain-text domain block list, one domain per line (DNS filter / RPZ)."""
    return _feed_txt(name, kind="domain")


@router.get("/feeds/domains/{name}.csv")
def domain_feed_csv(name: str):
    """Domain CSV with metadata (for SIEM / spreadsheet use)."""
    return _feed_csv(name, kind="domain")


@router.get("/feeds/domains/{name}.json")
def domain_feed_json(name: str):
    """Domain JSON with full details (for programmatic / SIEM ingestion)."""
    return _feed_json(name, kind="domain")


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
    """Manually add an IP/CIDR/domain to the merged set (source 'manual')."""
    try:
        stored_ip, pattern = _normalize_indicator(request.ip)
    except ValueError:
        raise HTTPException(status_code=400, detail="Not a valid IP, CIDR, or domain")
    # A CIDR is a real indicator (stored as network + prefix metadata); a
    # wildcard is only a whitelist matcher pattern — there is nothing to score.
    if pattern is not None and pattern.startswith("*."):
        raise HTTPException(status_code=400,
                            detail="A wildcard can be whitelisted, not added as an indicator")

    # Safety guard: refuse to add internal/reserved space, special-use TLDs,
    # or well-known good infrastructure (e.g. 8.8.8.8, update.microsoft.com)
    # that must never be blocked.
    reason = core.SAFETY.excluded_reason(pattern or stored_ip)
    if reason:
        raise HTTPException(status_code=400, detail=f"Refusing to add {pattern or stored_ip}: {reason}")

    # If it was previously removed (globally whitelisted), un-remove it.
    core.db.remove_from_whitelist(stored_ip, feed_name=ALL_FEEDS)

    meta = {"cidr": pattern} if pattern else {}
    core.db.add_indicator(ip=stored_ip, source="manual", metadata=meta,
                          kind=_value_kind(stored_ip))

    # Score just this indicator so it lands in the right tier immediately.
    from threatfeedme.scorer import ConfidenceScorer
    scorer = ConfidenceScorer(core.db, pipeline.scorer_config(core.db, core.config))
    score, tier = scorer.calculate_score(stored_ip)
    core.db.set_indicator_score(stored_ip, score, tier.value)
    return WhitelistResponse(success=True, message=f"Added {pattern or stored_ip}")


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
        # Overlap-discounted independent-witness count from the last rescore.
        # Includes netblock-derived votes, so it can exceed len(sources) —
        # this is what explains the tier when the source list looks short.
        "effective_votes": (round(ind.effective_votes, 2)
                            if ind.effective_votes is not None else None),
        "sources": ind.sources,
    }


@router.delete("/api/indicators/{ip}")
def remove_indicator(ip: str, _=Depends(require_auth), _csrf=Depends(csrf_check)):
    """Remove an IP from the merged set.

    This globally whitelists it (so a feed refresh won't bring it back) and
    deletes the current row for immediate effect."""
    # Normalize so a CIDR value (e.g. 1.2.3.0/24) maps to the stored network
    # address the same way the add path does; reject junk so nothing invalid
    # is persisted to the whitelist.
    try:
        stored_ip, _pattern = _normalize_indicator(ip)
    except ValueError:
        raise HTTPException(status_code=400, detail="Not a valid IP, CIDR, or domain")
    core.db.add_to_whitelist(stored_ip, reason="removed via dashboard", added_by="dashboard",
                        feed_name=ALL_FEEDS)
    core.db.delete_indicator(stored_ip)
    return {"success": True, "message": f"{stored_ip} removed and won't return on refresh"}
