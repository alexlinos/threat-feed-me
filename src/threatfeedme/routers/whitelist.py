"""Whitelist management endpoints."""
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException

from threatfeedme import pipeline
from threatfeedme.auth import csrf_check, require_auth
from threatfeedme import core
from threatfeedme.feed_helpers import _normalize_indicator
from threatfeedme.models import ALL_FEEDS, WHITELIST_REASONS, REASON_FALSE_POSITIVE
from threatfeedme.schemas import WhitelistRequest, WhitelistResponse

router = APIRouter()


def _feedback_scope(feed_name: Optional[str]) -> Optional[str]:
    """Map a whitelist scope to the feed_feedback scope it governs.

    Feedback rows are keyed by REAL feed names. Global ('*') and tier-scoped
    ('tier:high') entries attribute a false positive to every feed that
    reported the IP, so withdrawing/clearing them must clear the IP's
    feedback across all feeds (None). Only a real feed-name scope clears
    narrowly — passing 'tier:high' through literally would match nothing and
    leave the feed penalty (and its FP badge) stuck forever.
    """
    if feed_name and feed_name != ALL_FEEDS and not feed_name.startswith('tier:'):
        return feed_name
    return None


@router.get("/api/whitelist")
def get_whitelist(_=Depends(require_auth)):
    """Get all whitelist entries"""
    return core.db.get_whitelist()


@router.post("/api/whitelist", response_model=WhitelistResponse)
def add_to_whitelist(request: WhitelistRequest, _=Depends(require_auth), _csrf=Depends(csrf_check)):
    """Add an IP to the whitelist"""
    if request.reason_code not in WHITELIST_REASONS:
        raise HTTPException(status_code=400, detail="Invalid reason_code")
    # Validate the value so junk can't be persisted (defends the whitelist
    # table and eliminates any HTML/JS-injection vector on render). Accepts
    # an IP, a CIDR, a domain, or a "*.domain" wildcard (D6).
    try:
        stored_ip, pattern = _normalize_indicator(request.ip)
    except ValueError:
        raise HTTPException(status_code=400, detail="Not a valid IP, CIDR, or domain")
    # A range entry (CIDR or wildcard) is stored WITH its range syntax
    # (10.0.0.0/8, *.example.com) so it suppresses everything it contains
    # (WhitelistMatcher builds range rules from those keys). A bare host or
    # exact domain is stored as-is.
    wl_key = pattern or stored_ip
    try:
        expires = datetime.fromisoformat(request.expires_at) if request.expires_at else None
        feed_name = request.feed_name or ALL_FEEDS

        # Capture which feeds are "blamed" for a false positive BEFORE any
        # state change, so scoring feedback is attributed correctly. FP feedback
        # is a HOST-level signal — attributed to the feeds that reported this
        # exact IP/domain — and is always keyed on stored_ip (consistent with
        # the indicator lookup). A range (CIDR or wildcard) has no single
        # reporting indicator, so it is still suppressed via the whitelist but
        # records no (un-attributable) feed feedback.
        if request.reason_code == REASON_FALSE_POSITIVE and pattern is None:
            ind = core.db.get_indicator(stored_ip)
            sources = ind.sources if ind else []
            if feed_name == ALL_FEEDS or feed_name.startswith('tier:'):
                blamed = sources
            else:
                blamed = [feed_name]
            core.db.record_false_positive(stored_ip, [f for f in blamed if f])
        else:
            # Not an attributable FP: clear any prior FP attribution this
            # scope governs (all feeds for */tier: scopes, one feed otherwise).
            core.db.clear_feedback(stored_ip, feed_name=_feedback_scope(feed_name))

        core.db.add_to_whitelist(
            ip=wl_key,
            reason=request.reason,
            added_by=request.added_by,
            expires_at=expires,
            feed_name=feed_name,
            reason_code=request.reason_code,
        )

        # Rescore so the change is reflected immediately. For a single host or
        # domain this updates that indicator; for a range (CIDR or wildcard),
        # contained values are excluded live by the matcher and their tiers
        # settle on the next full recalc — rescoring the range's anchor value
        # is meaningless.
        if pattern is None:
            from threatfeedme.scorer import ConfidenceScorer
            scorer = ConfidenceScorer(core.db, pipeline.scorer_config(core.db, core.config))
            score, tier = scorer.calculate_score(stored_ip)
            core.db.set_indicator_score(stored_ip, score, tier.value)

        # The live feed URLs exclude whitelisted IPs at serve time, so the
        # change is already visible; the on-disk export files rebuild in the
        # background instead of freezing this request for 12 full-table loads.
        pipeline.export_tiers_async(core.db, core.config)

        if feed_name == ALL_FEEDS:
            scope = "all tiers"
        elif feed_name.startswith('tier:'):
            scope = f"tier '{feed_name.split(':')[1]}' only"
        else:
            scope = f"feed '{feed_name}'"
        return WhitelistResponse(success=True, message=f"{wl_key} whitelisted from {scope}")
    except Exception as e:
        return WhitelistResponse(success=False, message=str(e))


@router.delete("/api/whitelist")
def remove_from_whitelist(ip: str, feed: Optional[str] = None, _=Depends(require_auth), _csrf=Depends(csrf_check)):
    """Remove a whitelist entry: DELETE /api/whitelist?ip=<ip-or-cidr>[&feed=<name>].

    `ip` is a query parameter (not a path segment) so CIDR entries like
    10.0.0.0/8 — whose slash won't route as a path param — can be removed.
    Pass feed=<name> (or feed=* for the global entry) to remove a single scope;
    omit it to remove all scopes for the IP."""
    if core.db.remove_from_whitelist(ip, feed_name=feed):
        # Withdraw the false-positive feedback this entry's scope governs.
        # Tier/global scopes blamed every reporting feed at add time, so they
        # must clear feedback for all feeds — clearing by the literal scope
        # name would match nothing and leave the penalty stuck.
        core.db.clear_feedback(ip, feed_name=_feedback_scope(feed))
        # Rescore the IP and re-export all tier feeds so the IP reappears
        # in the correct tier immediately (not just on the next pipeline run).
        try:
            stored_ip, _ = _normalize_indicator(ip)  # strip /cidr
        except ValueError:
            stored_ip = ip
        if '/' not in stored_ip:  # bare IP — CIDR ranges excluded live by matcher
            from threatfeedme.scorer import ConfidenceScorer
            scorer = ConfidenceScorer(core.db, pipeline.scorer_config(core.db, core.config))
            score, tier = scorer.calculate_score(stored_ip)
            core.db.set_indicator_score(stored_ip, score, tier.value)
        # Live URLs reflect the removal immediately; the on-disk export
        # files rebuild in the background (see export_tiers_async).
        pipeline.export_tiers_async(core.db, core.config)
        return {"success": True, "message": f"Whitelist entry for {ip} removed — rescored; exports rebuilding"}
    raise HTTPException(status_code=404, detail="IP not found in whitelist")
