"""Never-block management endpoints (issue #19).

The operator's hard exclusion list: values that must never be emitted at any
tier, whatever the feeds say. It is a SEPARATE concept from the whitelist —
no per-feed scope, no expiry, no false-positive/reputation feedback — so the
two are never confused and a never-block value is never read as a feed error.

The veto itself is enforced at the emission chokepoint (exporter.row_included),
not here; these endpoints only manage the list. A change bumps the serve stamp
and rebuilds exports so live URLs and on-disk files reflect it immediately. No
rescore: never-block governs what is served, not how anything is scored.
"""
import logging
import re

from fastapi import APIRouter, Depends, HTTPException

from threatfeedme import core, pipeline
from threatfeedme.auth import csrf_check, require_auth
from threatfeedme.feed_helpers import _normalize_indicator, _value_kind
from threatfeedme.schemas import NeverBlockRequest

logger = logging.getLogger(__name__)

router = APIRouter()

# Bidi overrides make a note render as different text than was stored.
_BIDI_CONTROLS = re.compile(r"[\u202a-\u202e\u2066-\u2069\u200e\u200f]")


def _stored_key(value: str):
    """Canonical storage key for a submitted value, plus its kind. Raises
    ValueError on anything that is not an IP/CIDR/domain/wildcard."""
    stored, pattern = _normalize_indicator(value)
    return (pattern or stored), _value_kind(stored)


@router.get("/api/never-block")
def list_never_block(_=Depends(require_auth)):
    return core.db.get_never_block()


@router.post("/api/never-block")
def add_never_block(request: NeverBlockRequest, _=Depends(require_auth),
                    _csrf=Depends(csrf_check)):
    try:
        key, kind = _stored_key(request.value)
    except ValueError:
        raise HTTPException(status_code=400, detail="Not a valid IP, CIDR, or domain")
    reason = _BIDI_CONTROLS.sub("", request.reason or "")
    try:
        core.db.add_never_block(key, kind, reason=reason,
                                added_by=(request.added_by or "dashboard"))
    except Exception:
        logger.exception("[never-block] adding %s failed", key)
        raise HTTPException(status_code=500, detail="Could not add the never-block entry; see the server log")
    core.db.touch_serve_stamp()
    pipeline.export_tiers_async(core.db, core.config)
    return {"success": True, "message": f"{key} will never be emitted, at any tier"}


@router.delete("/api/never-block")
def remove_never_block(value: str, _=Depends(require_auth), _csrf=Depends(csrf_check)):
    # Normalize to the canonical key the ADD path stored, but fall through raw
    # so a value that no longer normalizes is still removable.
    try:
        key, _kind = _stored_key(value)
    except ValueError:
        key = value
    if core.db.remove_never_block(key):
        core.db.touch_serve_stamp()
        pipeline.export_tiers_async(core.db, core.config)
        return {"success": True, "message": f"{key} may be emitted again"}
    raise HTTPException(status_code=404, detail="Never-block entry not found")
