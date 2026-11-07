"""Built-in application-list catalog (issue #28): the offer, not the data.

The project factory (scripts/build_catalog.py, running in GitHub Actions
on the infra-snapshots branch) slices the vendor files once, centrally,
and publishes finished lists plus a small manifest, ``catalog.json``.
This module is the client half:

  * fetch the manifest only (never list data) to render the Applications
    page's catalog: vendors, each with a description and a link to the
    vendor's own documentation on what to allow, and each list in a group
    (Microsoft's endpoint categories, for one);
  * a list downloads nothing until the operator toggles it on. Toggling
    on creates the slice 1 application list pointing at the published
    list URL and refreshes it through the ordinary machinery (local
    safety gate, change guard, diff history). Toggling off disables it:
    no fetching, and the serving routes 404 it like an unknown list.

The manifest fetch goes through feed_ingestor.guarded_get (the connect-time
SSRF guard, no env proxies) and a capped read, and any failure keeps the
last good manifest. A failure is remembered for a few minutes, so a network
that cannot reach GitHub costs one timeout, not one per page load, and
app_catalog.enabled: false switches the fetch off entirely (air-gapped
installs). List URLs must sit beside the manifest: whoever controls the
manifest still cannot point installs at another host.
"""
from __future__ import annotations

import json
import logging
import threading
import time
from typing import Callable, Dict, List, Optional
from urllib.parse import urlsplit

import requests

from threatfeedme import applications
from threatfeedme.feed_ingestor import _FETCH_TIMEOUT, _read_capped_bytes, guarded_get

logger = logging.getLogger(__name__)

DEFAULT_CATALOG_URL = ("https://raw.githubusercontent.com/alexlinos/"
                       "threat-feed-me/infra-snapshots/catalog/catalog.json")
CATALOG_URL_SETTING = "app_catalog_url"
USER_AGENT = "threat-feed-me (application catalog)"
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
CACHE_TTL_SECONDS = 900
FAILURE_RETRY_SECONDS = 300
_MAX_TEXT = 300                  # vendor description / list description cap

_cache_lock = threading.Lock()
_cache: Dict = {"at": 0.0, "doc": None, "error": None, "next_try": 0.0}

_EMPTY = {"generated_at": "", "lists": [], "vendors": {}}


def _text(value) -> str:
    return value[:_MAX_TEXT] if isinstance(value, str) else ""


def _https_url(value) -> str:
    """A vendor docs link is shown as a hyperlink: https only, or nothing."""
    if isinstance(value, str) and len(value) <= 2048:
        parts = urlsplit(value)
        if parts.scheme == "https" and parts.hostname:
            return value
    return ""


def _clean(doc, base: str) -> Optional[Dict]:
    """Validate a parsed manifest; drop malformed entries, keep the rest.
    ``base`` is the manifest's own directory: a list URL anywhere else is
    dropped, so the manifest can only offer lists the factory published."""
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
        if not e["url"].startswith(base):
            continue  # off the factory's directory: not a list it published
        try:
            entries = int(e.get("entries") or 0)
            nbytes = int(e.get("bytes") or 0)
        except (TypeError, ValueError):
            continue  # malformed counts: drop this entry, keep the rest
        lists.append({
            "slug": slug, "name": _text(e["name"]), "vendor": _text(e["vendor"]),
            "group": _text(e.get("group")),
            "description": _text(e.get("description")),
            "format": "list",
            "entries": entries,
            "bytes": nbytes,
            "url": e["url"],
        })
    vendors: Dict[str, Dict] = {}
    raw_vendors = doc.get("vendors")
    if isinstance(raw_vendors, dict):
        for name, v in raw_vendors.items():
            if isinstance(name, str) and isinstance(v, dict):
                vendors[name[:_MAX_TEXT]] = {"description": _text(v.get("description")),
                                             "docs": _https_url(v.get("docs"))}
    return {"generated_at": _text(doc.get("generated_at")), "lists": lists,
            "vendors": vendors}


def _fetch(url: str, get: Callable) -> Dict:
    resp = guarded_get(url, get=get, headers={"User-Agent": USER_AGENT},
                       timeout=_FETCH_TIMEOUT)
    try:
        resp.raise_for_status()
        raw = _read_capped_bytes(resp, "catalog manifest", MAX_MANIFEST_BYTES)
    finally:
        resp.close()
    doc = _clean(json.loads(raw.decode("utf-8", errors="replace")),
                 url.rsplit("/", 1)[0] + "/")
    if doc is None:
        raise ValueError("catalog manifest has no lists")
    return doc


def get_catalog(db, get: Callable = requests.get, force: bool = False,
                enabled: bool = True) -> Dict:
    """The manifest, cached. Never raises: on failure the result carries
    the last good lists (possibly none) plus an ``error`` string."""
    if not enabled:
        return {**_EMPTY, "error": None, "disabled": True}
    with _cache_lock:
        if not force and time.time() < _cache["next_try"]:
            return {**(_cache["doc"] or _EMPTY), "error": _cache["error"]}
        url = db.get_setting(CATALOG_URL_SETTING) or DEFAULT_CATALOG_URL
        try:
            doc = _fetch(url, get)
            _cache.update(at=time.time(), doc=doc, error=None,
                          next_try=time.time() + CACHE_TTL_SECONDS)
        except Exception as exc:  # fetch/parse failure: keep last state
            logger.warning("[catalog] manifest fetch failed: %s", exc)
            _cache.update(error=_friendly(exc),
                          next_try=time.time() + FAILURE_RETRY_SECONDS)
            doc = _cache["doc"] or _EMPTY
        return {**doc, "error": _cache["error"]}


def _friendly(exc: Exception) -> str:
    """What the page says when the manifest can't be read: a sentence, not
    a requests traceback (a 404 also means the factory hasn't published)."""
    resp = getattr(exc, "response", None)
    status = getattr(resp, "status_code", None)
    if status == 404:
        return "the project hasn't published the catalog yet"
    if isinstance(exc, requests.RequestException):
        return "GitHub couldn't be reached from this server"
    return "the published catalog couldn't be read"


def catalog_view(db, get: Callable = requests.get, enabled: bool = True) -> Dict:
    """Manifest entries merged with local state for the Apps page."""
    doc = get_catalog(db, get=get, enabled=enabled)
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
            "disabled": bool(doc.get("disabled")), "vendors": doc.get("vendors", {}),
            "catalog": rows}


def set_enabled(db, slug: str, enabled: bool, get: Callable = requests.get,
                allow_private: bool = False, catalog_enabled: bool = True) -> Dict:
    """The toggle. On: create the list from the manifest definition if it
    does not exist yet (an existing row keeps the operator's settings),
    enable it, and refresh now through the slice 1 machinery. Off:
    disable; entries stay stored so toggling back on is instant, but
    nothing fetches and nothing serves while off."""
    if not enabled:
        # Off needs no manifest definition: if the factory retires a list,
        # its toggle must still be able to shut it off.
        if db.get_application_list(slug) is not None:
            db.update_application_list(slug, {"enabled": 0})
        return {"name": slug, "outcome": "disabled"}
    if not catalog_enabled:
        raise ValueError("the application catalog is switched off (app_catalog.enabled)")
    doc = get_catalog(db, get=get)
    entry = next((e for e in doc["lists"] if e["slug"] == slug), None)
    if entry is None:
        if doc["error"] and not doc["lists"]:
            raise ValueError(f"catalog unavailable: {doc['error']}")
        raise KeyError(slug)
    if db.get_application_list(slug) is None:
        db.add_application_list(
            slug, entry["url"], "list", "",
            applications.DEFAULT_UPDATE_INTERVAL,
            applications.DEFAULT_V4_FLOOR, applications.DEFAULT_V6_FLOOR,
            applications.DEFAULT_CHANGE_PCT)
    else:
        db.update_application_list(slug, {"enabled": 1})
    return applications.refresh_list(db, slug, get=get, allow_private=allow_private)
