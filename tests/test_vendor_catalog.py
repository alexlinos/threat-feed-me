"""Application catalog client (issue #28): manifest fetch discipline,
the toggle that turns a catalog offer into a slice 1 list, disabled
lists not serving, and the all-on storm the operator demanded: every
catalog list enabled at once, one scheduler pass, nothing held, nothing
starved, the largest list still serving.

Offline per repo rule: every fetch is an injected fake keyed by URL.
"""

import json
import os
import sys
import time

import pytest
import requests

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from fastapi import HTTPException

from threatfeedme import applications, vendor_catalog
from threatfeedme.database import Database

MANIFEST_URL = "https://factory.example/catalog/catalog.json"
BASE = "https://factory.example/catalog/"


class FakeResp:
    def __init__(self, body=b"", status=200):
        self.content = body if isinstance(body, bytes) else body.encode()
        self.headers = {}
        self.status_code = status

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def iter_content(self, chunk_size=1, decode_unicode=False):
        for i in range(0, len(self.content), chunk_size):
            yield self.content[i:i + chunk_size]

    def close(self):
        pass


def transport(bodies: dict, fail_urls=()):
    """bodies: url -> text. fail_urls raise like a network error. Accepts the
    stream/proxies keywords feed_ingestor.guarded_get passes."""
    calls = []

    def get(url, headers=None, timeout=None, **kwargs):
        calls.append(url)
        if url in fail_urls:
            raise requests.ConnectionError("connection refused")
        return FakeResp(bodies[url])

    get.calls = calls
    return get


def manifest_json(lists):
    return json.dumps({"generated_at": "2026-11-07T00:00:00Z", "lists": [
        {"slug": slug, "name": slug, "vendor": "TestVendor",
         "description": f"the {slug} list", "format": "list",
         "entries": n, "bytes": 0, "url": BASE + slug + ".txt"}
        for slug, n in lists]})


@pytest.fixture(autouse=True)
def _fresh_cache():
    vendor_catalog._cache.update(at=0.0, doc=None, error=None, next_try=0.0)
    yield
    vendor_catalog._cache.update(at=0.0, doc=None, error=None, next_try=0.0)


@pytest.fixture
def db(tmp_path):
    d = Database(str(tmp_path / "t.db"))
    d.set_setting(vendor_catalog.CATALOG_URL_SETTING, MANIFEST_URL)
    return d


@pytest.fixture
def rtr(db, monkeypatch):
    # Patch the core module object the ROUTER holds, not the one this
    # module imported: test_dashboard_feeds reloads threatfeedme.core
    # mid-suite, after which the two are different module objects and
    # patching the test's own core silently misses the router's.
    from threatfeedme.routers import applications as r
    monkeypatch.setitem(r.__dict__["core"].__dict__, "db", db)
    # Seams, not core.config (reading it lazily initializes core).
    monkeypatch.setitem(r.__dict__, "_allow_private", lambda: False)
    monkeypatch.setitem(r.__dict__, "_catalog_enabled", lambda: True)
    return r


class FakeRequest:
    def __init__(self, headers=None):
        self.headers = headers or {}
        self.query_params = {}


def _small_setup():
    lists = [("aws-ec2", 2), ("m365-exchange-urls", 1)]
    bodies = {MANIFEST_URL: manifest_json(lists),
              BASE + "aws-ec2.txt": "192.0.2.0/24\n198.51.100.0/24\n",
              BASE + "m365-exchange-urls.txt": "outlook.office.com\n"}
    return lists, bodies


# ------------------------------------------------------------ manifest --

def test_manifest_parsed_cached_and_cleaned(db):
    lists, bodies = _small_setup()
    doc = json.loads(bodies[MANIFEST_URL])
    doc["lists"].append({"slug": "Bad Slug!", "name": "x", "vendor": "v",
                         "url": "https://factory.example/x.txt"})
    bodies[MANIFEST_URL] = json.dumps(doc)
    get = transport(bodies)
    first = vendor_catalog.get_catalog(db, get=get)
    second = vendor_catalog.get_catalog(db, get=get)
    assert [e["slug"] for e in first["lists"]] == ["aws-ec2", "m365-exchange-urls"]
    assert second["lists"] == first["lists"]
    assert get.calls.count(MANIFEST_URL) == 1          # cached, not refetched
    assert first["error"] is None


def test_manifest_failure_keeps_last_good(db):
    lists, bodies = _small_setup()
    good = vendor_catalog.get_catalog(db, get=transport(bodies))
    assert good["error"] is None
    bad = vendor_catalog.get_catalog(db, get=transport({}, fail_urls={MANIFEST_URL}),
                                     force=True)
    assert bad["error"] and len(bad["lists"]) == 2     # last good retained


def test_catalog_view_merges_local_state(db):
    lists, bodies = _small_setup()
    get = transport(bodies)
    view = vendor_catalog.catalog_view(db, get=get)
    assert all(r["adopted"] is False and r["enabled"] is False
               for r in view["catalog"])
    vendor_catalog.set_enabled(db, "aws-ec2", True, get=get)
    view = vendor_catalog.catalog_view(db, get=get)
    ec2 = next(r for r in view["catalog"] if r["slug"] == "aws-ec2")
    assert ec2["adopted"] is True and ec2["enabled"] is True
    assert ec2["local_entries"] == 2


# -------------------------------------------------------------- toggle --

def test_toggle_on_creates_and_populates(db):
    lists, bodies = _small_setup()
    get = transport(bodies)
    summary = vendor_catalog.set_enabled(db, "aws-ec2", True, get=get)
    assert summary["outcome"] == "ok"
    row = db.get_application_list("aws-ec2")
    assert row is not None and row["enabled"] == 1
    assert row["source_url"] == BASE + "aws-ec2.txt"
    assert db.get_entries("aws-ec2") == ["192.0.2.0/24", "198.51.100.0/24"]


def test_toggle_unknown_slug_raises(db):
    lists, bodies = _small_setup()
    with pytest.raises(KeyError):
        vendor_catalog.set_enabled(db, "nope", True, get=transport(bodies))


def test_toggle_off_stops_serving(db, rtr):
    lists, bodies = _small_setup()
    get = transport(bodies)
    vendor_catalog.set_enabled(db, "aws-ec2", True, get=get)
    resp = rtr.list_txt("aws-ec2", FakeRequest(), limit=None)
    assert b"192.0.2.0/24" in resp.body
    vendor_catalog.set_enabled(db, "aws-ec2", False, get=get)
    assert db.get_application_list("aws-ec2")["enabled"] == 0
    with pytest.raises(HTTPException) as ei:
        rtr.list_txt("aws-ec2", FakeRequest(), limit=None)
    assert ei.value.status_code == 404
    # Entries survive the off state; toggling back on is instant.
    assert db.get_entries("aws-ec2") == ["192.0.2.0/24", "198.51.100.0/24"]


# ----------------------------------------------------------- all-on storm --

def _storm_setup(n_lists=24, big_entries=7000):
    slugs = [f"aws-svc-{i:02d}" for i in range(n_lists - 1)] + ["aws-amazon"]
    bodies = {}
    counts = {}
    for slug in slugs:
        n = big_entries if slug == "aws-amazon" else 40 + (len(slug) % 7)
        counts[slug] = n
        bodies[BASE + slug + ".txt"] = "".join(
            f"45.{16 + (i // 65536) % 200}.{(i // 256) % 256}.{i % 256}\n"
            for i in range(n))
    bodies[MANIFEST_URL] = manifest_json([(s, counts[s]) for s in slugs])
    return slugs, bodies, counts


def test_all_on_storm(db, rtr, monkeypatch):
    slugs, bodies, counts = _storm_setup()
    get = transport(bodies)

    # Phase 1: somebody toggles EVERYTHING on. First loads populate from
    # empty in sequence; the guard must not misfire on any of them.
    for slug in slugs:
        summary = vendor_catalog.set_enabled(db, slug, True, get=get)
        assert summary["outcome"] == "ok", (slug, summary)
    for slug in slugs:
        assert db.get_application_list(slug)["entry_count"] == counts[slug]
        assert db.get_pending(slug) is None

    # Phase 2: every list comes due in the same scheduler pass while every
    # body moves a little (one entry swapped, far under the guard). No
    # list may starve, error, or be held because the pass is sequential.
    for slug in slugs:
        db.update_application_list(slug, {"update_interval": 0})
        lines = bodies[BASE + slug + ".txt"].splitlines()
        lines[0] = "45.250.250.250"
        bodies[BASE + slug + ".txt"] = "\n".join(lines) + "\n"
    orig = applications.refresh_list
    monkeypatch.setattr(applications, "refresh_list",
                        lambda d, n, **kw: orig(d, n, get=get))
    started = time.time()
    applications.refresh_due(db)
    elapsed = time.time() - started
    assert elapsed < 60, f"all-on pass took {elapsed:.1f}s"
    for slug in slugs:
        row = db.get_application_list(slug)
        assert row["last_status"] == "ok", (slug, row["last_status"])
        assert row["entry_count"] == counts[slug]
        assert db.get_pending(slug) is None

    # Phase 3: the biggest list still serves in full mid-catalog, and the
    # catalog view renders the whole set with live counts.
    resp = rtr.list_txt("aws-amazon", FakeRequest(), limit=None)
    assert resp.body.count(b"\n") == counts["aws-amazon"]
    view = vendor_catalog.catalog_view(db, get=get)
    assert len(view["catalog"]) == len(slugs)
    assert all(r["enabled"] for r in view["catalog"])


def test_manifest_malformed_counts_drop_one_entry(db):
    # Regression: a non-numeric entries/bytes field raised ValueError out
    # of the manifest cleaner and condemned the whole catalog. _clean's
    # contract is drop-the-entry: the bad list goes, the rest stay.
    doc = json.loads(manifest_json([("aws-ec2", 2)]))
    doc["lists"].append({"slug": "gcp-cloud", "name": "gcp-cloud",
                         "vendor": "TestVendor", "description": "x",
                         "format": "list", "entries": "many", "bytes": 0,
                         "url": BASE + "gcp-cloud.txt"})
    got = vendor_catalog.get_catalog(db, get=transport({MANIFEST_URL: json.dumps(doc)}))
    assert [e["slug"] for e in got["lists"]] == ["aws-ec2"]


def test_toggle_off_a_factory_retired_list(db):
    # Regression: the manifest lookup ran before the disable branch, so a
    # list the factory had retired from the manifest raised KeyError on
    # toggle-off and could never be shut off from the catalog.
    db.add_application_list("old-list", "https://factory.example/old.txt",
                            "list", "", 3600, 8, 20, 50.0)
    _, bodies = _small_setup()
    out = vendor_catalog.set_enabled(db, "old-list", False, get=transport(bodies))
    assert out["outcome"] == "disabled"
    assert db.get_application_list("old-list")["enabled"] == 0


# ------------------------------------------------- 2.7 catalog hardening --

def test_list_urls_must_sit_beside_the_manifest(db):
    # Whoever controls the manifest still can't point installs elsewhere.
    doc = json.loads(manifest_json([("aws-ec2", 2)]))
    doc["lists"].append({"slug": "evil", "name": "evil", "vendor": "v",
                         "url": "https://elsewhere.example/catalog/evil.txt"})
    doc["lists"].append({"slug": "sneaky", "name": "sneaky", "vendor": "v",
                         "url": "https://factory.example/other/sneaky.txt"})
    got = vendor_catalog.get_catalog(db, get=transport({MANIFEST_URL: json.dumps(doc)}))
    assert [e["slug"] for e in got["lists"]] == ["aws-ec2"]


def test_a_failed_fetch_is_remembered_not_retried_per_page_load(db):
    # A network that can't reach GitHub costs one timeout, not one per load.
    get = transport({}, fail_urls={MANIFEST_URL})
    first = vendor_catalog.get_catalog(db, get=get)
    second = vendor_catalog.get_catalog(db, get=get)
    assert get.calls.count(MANIFEST_URL) == 1
    assert first["error"] == second["error"] == "GitHub couldn't be reached from this server"


def test_manifest_fetch_follows_the_private_url_policy(db):
    # Guarded by default (env proxies off), like every fetch; an install that
    # allows private feed URLs can mirror the catalog on its own network.
    seen = []
    bodies = {MANIFEST_URL: manifest_json([("aws-ec2", 2)])}
    base = transport(bodies)

    def get(url, **kw):
        seen.append(kw.get("proxies"))
        return base(url, **kw)
    vendor_catalog.get_catalog(db, get=get)
    vendor_catalog.get_catalog(db, get=get, force=True, allow_private=True)
    assert seen == [{"http": None, "https": None, "all": None}, None]


def test_switched_off_catalog_fetches_nothing(db):
    get = transport({})
    view = vendor_catalog.catalog_view(db, get=get, enabled=False)
    assert view["disabled"] and view["catalog"] == [] and get.calls == []
    with pytest.raises(ValueError):
        vendor_catalog.set_enabled(db, "aws-ec2", True, get=get, catalog_enabled=False)


def test_vendor_docs_and_groups_survive_cleaning(db):
    doc = json.loads(manifest_json([("aws-ec2", 2)]))
    doc["lists"][0]["group"] = "All regions"
    doc["vendors"] = {
        "TestVendor": {"description": "Ranges for the test cloud.",
                       "docs": "https://docs.vendor.example/ip-ranges"},
        "Sneaky": {"description": "x", "docs": "javascript:alert(1)"},
    }
    view = vendor_catalog.catalog_view(db, get=transport({MANIFEST_URL: json.dumps(doc)}))
    assert view["catalog"][0]["group"] == "All regions"
    assert view["vendors"]["TestVendor"]["docs"] == "https://docs.vendor.example/ip-ranges"
    assert view["vendors"]["Sneaky"]["docs"] == ""     # only https links are kept
