"""Application-list management and serving endpoints (issue #26).

Two surfaces with deliberately different trust levels:

  * /lists/<name>.txt|csv|json — public, host-check exempt, ETag/304, the
    firewall-facing shape. No auth: the same rule as /feeds is that
    firewalls must always be able to poll. Serving reads only the approved
    entry set; a held refresh cannot reach this path.
  * /api/applications... — dashboard, auth + CSRF on every mutation, like
    every other /api surface.

The safety gate (prefix floors, special-use rejection, change guard) lives
in threatfeedme.applications, applied at write time; there is no second
filter here, and notably NOT the known-good output filter, which would
strip these entries by design.
"""
import hashlib
import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import PlainTextResponse, Response, StreamingResponse

from threatfeedme import applications, core
from threatfeedme.auth import csrf_check, require_auth
from threatfeedme.schemas import ApplicationListRequest

logger = logging.getLogger(__name__)

router = APIRouter()

_LIMIT = Query(None, ge=1, le=1_000_000,
               description="Serve only the first N entries (entries are sorted)")


def _row_or_404(name: str) -> dict:
    row = core.db.get_application_list(name)
    if row is None:
        raise HTTPException(status_code=404, detail="Unknown application list")
    return row


def _validate(req: ApplicationListRequest) -> None:
    if not applications.valid_name(req.name):
        raise HTTPException(status_code=400,
                            detail="Name must be lowercase letters, digits and dashes (2-64)")
    if not req.url.startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="URL must be http(s)")
    if req.format not in ("list", "json"):
        raise HTTPException(status_code=400, detail="Format is 'list' or 'json'")
    if req.format == "json" and not req.filter_expr:
        raise HTTPException(status_code=400, detail="JSON lists need a filter expression")
    if not (300 <= req.update_interval <= 7 * 86400):
        raise HTTPException(status_code=400, detail="update_interval must be 300..604800 s")
    if not (0 <= req.min_v4_prefix <= 32) or not (0 <= req.min_v6_prefix <= 128):
        raise HTTPException(status_code=400, detail="prefix floors out of range")
    if not (0.0 <= req.change_threshold_pct <= 100.0):
        raise HTTPException(status_code=400, detail="change_threshold_pct must be 0..100")


# ---------------------------------------------------------------- serving --

def _served(request: Request, name: str, ext: str, limit: Optional[int]):
    """Entries + ETag for one list. The ETag mixes body digest and the row's
    entry_version, so a swap bustes caches even through a proxy that hashes
    bodies."""
    _row_or_404(name)
    entries = core.db.get_entries(name)
    if limit is not None:
        entries = entries[:limit]
    from threatfeedme import polls
    polls.record(core.db, f"lists/{name}.{ext}", request.headers.get("user-agent", ""))
    return entries


@router.get("/lists/{name}.txt", response_class=PlainTextResponse)
def list_txt(name: str, request: Request, limit: Optional[int] = _LIMIT):
    entries = _served(request, name, "txt", limit)
    body = "\n".join(entries) + ("\n" if entries else "")
    etag = '"' + hashlib.sha256(body.encode()).hexdigest() + '"'
    headers = {"Cache-Control": "no-cache", "ETag": etag}
    if request.headers.get("if-none-match") == etag:
        return Response(status_code=304, headers=headers)
    return Response(body, media_type="text/plain; charset=utf-8", headers=headers)


@router.get("/lists/{name}.csv")
def list_csv(name: str, request: Request, limit: Optional[int] = _LIMIT):
    entries = _served(request, name, "csv", limit)
    return StreamingResponse((f"{e}\r\n" for e in entries),
                             media_type="text/csv; charset=utf-8")


@router.get("/lists/{name}.json")
def list_json(name: str, request: Request, limit: Optional[int] = _LIMIT):
    entries = _served(request, name, "json", limit)
    import json as _json
    return StreamingResponse(iter([_json.dumps({"entries": entries})]),
                             media_type="application/json")


# ------------------------------------------------------------------- API --

@router.get("/api/applications")
def list_applications(_=Depends(require_auth)):
    rows = core.db.get_application_lists()
    for row in rows:
        row["pending"] = core.db.get_pending(row["name"]) is not None
    return {"applications": rows}


@router.get("/api/applications/{name}")
def get_application(name: str, _=Depends(require_auth)):
    row = _row_or_404(name)
    pending = core.db.get_pending(name)
    if pending:
        pending = {k: pending[k] for k in
                   ("received_at", "reason", "added", "removed",
                    "added_sample", "removed_sample")}
    return {
        "application": row,
        "history": core.db.get_history(name),
        "pending": pending,
        "entries_preview": core.db.get_entries(name)[:200],
        "served_url": f"/lists/{name}.txt",
    }


@router.post("/api/applications")
def add_application(req: ApplicationListRequest, _=Depends(require_auth),
                    _csrf=Depends(csrf_check)):
    _validate(req)
    if core.db.get_application_list(req.name):
        raise HTTPException(status_code=409, detail="A list with that name exists")
    try:
        core.db.add_application_list(
            req.name, req.url, req.format, req.filter_expr, req.update_interval,
            req.min_v4_prefix, req.min_v6_prefix, req.change_threshold_pct)
    except Exception:
        logger.exception("[applications] creating %s failed", req.name)
        raise HTTPException(status_code=500, detail="Could not create the list")
    return {"success": True, "message": f"List '{req.name}' created; "
            "it serves after its first successful refresh"}


@router.put("/api/applications/{name}")
def update_application(name: str, req: ApplicationListRequest,
                       _=Depends(require_auth), _csrf=Depends(csrf_check)):
    _row_or_404(name)
    _validate(req)
    core.db.update_application_list(name, {
        "source_url": req.url, "format": req.format, "filter_expr": req.filter_expr,
        "enabled": 1 if req.enabled else 0, "update_interval": req.update_interval,
        "min_v4_prefix": req.min_v4_prefix, "min_v6_prefix": req.min_v6_prefix,
        "change_threshold_pct": req.change_threshold_pct})
    return {"success": True, "message": f"List '{name}' saved"}


@router.delete("/api/applications/{name}")
def delete_application(name: str, _=Depends(require_auth), _csrf=Depends(csrf_check)):
    _row_or_404(name)
    core.db.delete_application_list(name)
    return {"success": True, "message": f"List '{name}' deleted"}


@router.post("/api/applications/{name}/refresh")
def refresh_application(name: str, _=Depends(require_auth), _csrf=Depends(csrf_check)):
    _row_or_404(name)
    # Sync route: FastAPI runs it in the threadpool, so one vendor poll
    # cannot block the event loop. Manual refresh bypasses the schedule's
    # due check but not the change guard — the guard is a property of the
    # write path, not of the scheduler.
    summary = applications.refresh_list(core.db, name)
    return {"success": summary["outcome"] != "error", **summary}


@router.post("/api/applications/{name}/pending/approve")
def approve(name: str, _=Depends(require_auth), _csrf=Depends(csrf_check)):
    _row_or_404(name)
    if core.db.approve_pending(name) is None:
        raise HTTPException(status_code=404, detail="Nothing pending for this list")
    return {"success": True, "message": f"Held refresh for '{name}' is now served"}


@router.post("/api/applications/{name}/pending/reject")
def reject(name: str, _=Depends(require_auth), _csrf=Depends(csrf_check)):
    _row_or_404(name)
    if not core.db.reject_pending(name):
        raise HTTPException(status_code=404, detail="Nothing pending for this list")
    return {"success": True, "message": f"Held refresh for '{name}' discarded"}
