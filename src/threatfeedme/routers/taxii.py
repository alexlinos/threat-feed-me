"""TAXII 2.1 endpoints (read-only). See taxii.py for the data model.

Unauthenticated like /feeds (SIEM/TIP pollers, non-secret content) and exempt
from the Host-header check for the same reason. Everything served passes the
same whitelist rules as the feed URLs."""
from typing import Optional

from fastapi import APIRouter, Query, Request
from fastapi.responses import JSONResponse

from threatfeedme import core, taxii
from threatfeedme.feed_helpers import _feed_base

router = APIRouter()


def _resp(body, status: int = 200, headers: Optional[dict] = None,
          media: str = taxii.TAXII_MEDIA) -> JSONResponse:
    h = {"X-Content-Type-Options": "nosniff"}
    h.update(headers or {})
    return JSONResponse(body, status_code=status, media_type=media, headers=h)


def _error(status: int, title: str, description: str = "") -> JSONResponse:
    body = {"title": title, "http_status": str(status)}
    if description:
        body["description"] = description
    return _resp(body, status)


def _acceptable(request: Request) -> bool:
    """TAXII clients send Accept: application/taxii+json;version=2.1; plenty
    send */* or application/json. Refuse only what we can't produce."""
    accept = (request.headers.get("accept") or "*/*").lower()
    if "version=" in accept and "taxii+json" in accept and "version=2.1" not in accept:
        return False
    return any(t in accept for t in ("taxii+json", "stix+json", "application/json", "*/*"))


def _guard(request: Request) -> Optional[JSONResponse]:
    if not _acceptable(request):
        return _error(406, "Not Acceptable", f"This server speaks {taxii.TAXII_MEDIA}")
    return None


@router.get("/taxii2/")
def discovery(request: Request):
    if (bad := _guard(request)):
        return bad
    base = _feed_base(request, swap_loopback=False)
    return _resp({
        "title": "threat-feed-me TAXII 2.1",
        "description": "Consensus-scored block lists as STIX 2.1 Indicators (read-only).",
        "default": f"{base}/taxii2/api/",
        "api_roots": [f"{base}/taxii2/api/"],
    })


@router.get("/taxii2/api/")
def api_root(request: Request):
    if (bad := _guard(request)):
        return bad
    return _resp({"title": "threat-feed-me", "versions": [taxii.TAXII_MEDIA],
                  "max_content_length": 10 * 1024 * 1024})


@router.get("/taxii2/api/collections/")
def collections(request: Request):
    if (bad := _guard(request)):
        return bad
    return _resp({"collections": [taxii.collection_info(c) for c in taxii.COLLECTIONS]})


@router.get("/taxii2/api/collections/{cid}/")
def collection(cid: str, request: Request):
    if (bad := _guard(request)):
        return bad
    if cid not in taxii.COLLECTIONS:
        return _error(404, "Collection not found")
    return _resp(taxii.collection_info(cid))


def _page(cid, added_after, next_token, limit):
    if cid not in taxii.COLLECTIONS:
        return None, _error(404, "Collection not found")
    try:
        return taxii.page(core.db, cid, added_after=added_after,
                          next_token=next_token, limit=limit), None
    except ValueError as e:
        return None, _error(400, "Bad request", str(e) or "invalid added_after or next")


def _date_headers(added) -> dict:
    if not added:
        return {}
    return {"X-TAXII-Date-Added-First": added[0], "X-TAXII-Date-Added-Last": added[-1]}


@router.get("/taxii2/api/collections/{cid}/objects/")
def objects(cid: str, request: Request,
            added_after: Optional[str] = Query(None, max_length=64),
            next: Optional[str] = Query(None, max_length=1024),
            limit: int = Query(taxii.DEFAULT_LIMIT, ge=1),
            match_type: Optional[str] = Query(None, alias="match[type]", max_length=256)):
    if (bad := _guard(request)):
        return bad
    if match_type is not None and "indicator" not in [t.strip() for t in match_type.split(",")]:
        return _resp({"more": False, "objects": []}, media=taxii.TAXII_MEDIA)
    result, err = _page(cid, added_after, next, limit)
    if err:
        return err
    objs, added, more, token = result
    body = {"more": more, "objects": objs}
    if token:
        body["next"] = token
    return _resp(body, headers=_date_headers(added))


@router.get("/taxii2/api/collections/{cid}/manifest/")
def manifest(cid: str, request: Request,
             added_after: Optional[str] = Query(None, max_length=64),
             next: Optional[str] = Query(None, max_length=1024),
             limit: int = Query(taxii.DEFAULT_LIMIT, ge=1)):
    if (bad := _guard(request)):
        return bad
    result, err = _page(cid, added_after, next, limit)
    if err:
        return err
    objs, added, more, token = result
    body = {"more": more, "objects": [
        {"id": o["id"], "date_added": o["modified"], "version": o["modified"],
         "media_type": taxii.STIX_MEDIA} for o in objs]}
    if token:
        body["next"] = token
    return _resp(body, headers=_date_headers(added))
