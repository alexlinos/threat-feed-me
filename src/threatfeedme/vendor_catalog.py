"""Built-in application-list catalog (issue #28): the offer, not the data.

The project factory (scripts/build_catalog.py, running in GitHub Actions
on the infra-snapshots branch) slices the vendor files once, centrally,
and publishes finished lists plus a small manifest, ``catalog.json``.
This module is the client half:

  * fetch the manifest only (never list data) to render the Applications
    page's catalog, grouped by vendor like the source-templates page the
    design follows;
  * a list downloads nothing until the operator toggles it on. Toggling
    on creates the slice 1 application list pointing at the published
    list URL and refreshes it through the ordinary machinery (local
    safety gate, change guard, diff history). Toggling off disables it:
    no fetching, and the serving routes 404 it like an unknown list.

The manifest fetch follows catalog_sync's discipline: public-HTTPS check
up front, the process-wide urllib3 SSRF guard at connect time (the same
one applications.fetch relies on), a hard byte cap, and any failure
keeps the last good manifest. The cache is in-memory with a TTL; the
manifest is small and the page is the only reader.
"""
from __future__ import annotations

import json
import logging
import threading
import time
from typing import Callable, Dict, List, Optional

import requests

from threatfeedme import applications
from threatfeedme.feed_ingestor import _FETCH_TIMEOUT, _require_public_url

logger = logging.getLogger(__name__)

DEFAULT_CATALOG_URL = ("https://raw.githubusercontent.com/alexlinos/"
                       "threat-feed-me/infra-snapshots/catalog/catalog.json")
CATALOG_URL_SETTING = "app_catalog_url"
USER_AGENT = "threat-feed-me (application catalog)"
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
CACHE_TTL_SECONDS = 900

_cache_lock = threading.Lock()
_cache: Dict = {"at": 0.0, "doc": None, "error": None}


def _clean(doc) -> Optional[Dict]:
    """Validate a parsed manifest; drop malformed entries, keep the rest."""
    if not isinstance(doc, dict) or not isinstance(doc.get("lists"), list):
        return None
    lists: List[Dict] = []
    for e in doc["lists"]:
        if not isinstance(e, dict):
            continue
        slug = e.get("slug") or ""
        if not applications.valid_name(slug):
            continue
        if not all(isinstance(e.get(k), str) and e[k]
                   for k in ("name", "vendor", "url")):
            continue
        lists.append({
            "slug": slug, "name": e["name"], "vendor": e["vendor"],
            "description": e.get("description") or "",
            "format": "list",
            "entries": int(e.get("entries") or 0),
            "bytes": int(e.get("bytes") or 0),
            "url": e["url"],
        })
    return {"generated_at": doc.get("generated_at") or "", "lists": lists}


def _fetch(url: str, get: Callable) -> Dict:
    _require_public_url(url)
    resp = get(url, headers={"User-Agent": USER_AGENT}, timeout=_FETCH_TIMEOUT)
    resp.raise_for_status()
    raw = resp.content
    if len(raw) > MAX_MANIFEST_BYTES:
        raise ValueError("catalog manifest over size cap")
    doc = _clean(json.loads(raw.decode("utf-8", errors="replace")))
    if doc is None:
        raise ValueError("catalog manifest has no lists")
    return doc


def get_catalog(db, get: Callable = requests.get,
                force: bool = False) -> Dict:
    """The manifest, cached. Never raises: on failure the result carries
    the last good lists (possibly none) plus an ``error`` string."""
    with _cache_lock:
        fresh = _cache["doc"] is not None \
            and (time.time() - _cache["at"]) < CACHE_TTL_SECONDS
        if fresh and not force:
            return {**_cache["doc"], "error": _cache["error"]}
        url = db.get_setting(CATALOG_URL_SETTING) or DEFAULT_CATALOG_URL
        try:
            doc = _fetch(url, get)
            _cache.update(at=time.time(), doc=doc, error=None)
        except Exception as exc:  # fetch/parse failure: keep last state
            logger.warning("[catalog] manifest fetch failed: %s", exc)
            _cache["error"] = str(exc)[:200]
            doc = _cache["doc"] or {"generated_at": "", "lists": []}
        return {**doc, "error": _cache["error"]}


def catalog_view(db, get: Callable = requests.get) -> Dict:
    """Manifest entries merged with local state for the Apps page."""
    doc = get_catalog(db, get=get)
    rows = []
    for entry in doc["lists"]:
        local = db.get_application_list(entry["slug"])
        rows.append({
            **entry,
            "adopted": local is not None,
            "enabled": bool(local and local["enabled"]),
            "local_entries": local["entry_count"] if local else None,
            "last_status": local["last_status"] if local else None,
            "pending": bool(local and db.get_pending(entry["slug"])),
        })
    return {"generated_at": doc["generated_at"], "error": doc["error"],
            "catalog": rows}


def set_enabled(db, slug: str, enabled: bool,
                get: Callable = requests.get) -> Dict:
    """The toggle. On: create the list from the manifest definition if it
    does not exist yet (an existing row keeps the operator's settings),
    enable it, and refresh now through the slice 1 machinery. Off:
    disable; entries stay stored so toggling back on is instant, but
    nothing fetches and nothing serves while off."""
    doc = get_catalog(db, get=get)
    entry = next((e for e in doc["lists"] if e["slug"] == slug), None)
    if entry is None:
        if doc["error"] and not doc["lists"]:
            raise ValueError(f"catalog unavailable: {doc['error']}")
        raise KeyError(slug)
    if not enabled:
        if db.get_application_list(slug) is not None:
            db.update_application_list(slug, {"enabled": 0})
        return {"name": slug, "outcome": "disabled"}
    if db.get_application_list(slug) is None:
        db.add_application_list(
            slug, entry["url"], "list", "",
            applications.DEFAULT_UPDATE_INTERVAL,
            applications.DEFAULT_V4_FLOOR, applications.DEFAULT_V6_FLOOR,
            applications.DEFAULT_CHANGE_PCT)
    else:
        db.update_application_list(slug, {"enabled": 1})
    return applications.refresh_list(db, slug, get=get)
