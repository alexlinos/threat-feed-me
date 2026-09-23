"""TAXII 2.1 output (v2.5.0): same content as /feeds, valid STIX, stable
paging. core.db is pointed at a temp DB (reading the real core would
initialize it from ./config.yaml and ./data)."""
import re
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from starlette.testclient import TestClient

from threatfeedme import core, feed_cache, taxii
from threatfeedme.database import Database
from threatfeedme.scorer import ConfidenceScorer

H = {"Accept": taxii.TAXII_MEDIA}
STIX_TS = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$")


@pytest.fixture
def db(tmp_path):
    feed_cache.invalidate()
    d = Database(str(tmp_path / "t.db"))
    d.add_indicators_bulk([("45.66.230.0", {"cidr": "45.66.230.0/24"}), ("185.1.1.1", {}),
                           ("2001:db8:1::5", {}), ("185.1.1.2", {})], source="spamhaus_drop")
    d.add_indicators_bulk([("185.1.1.1", {}), ("185.9.9.9", {}), ("185.1.1.2", {})],
                          source="blocklist_de")
    d.add_indicators_bulk([("evil-login.top", {}), ("x'y.example.net", {})],
                          source="phishing_army", kind="domain")
    ConfidenceScorer(d, {}).recalculate_all_scores()
    yield d
    feed_cache.invalidate()


@pytest.fixture
def client(db, monkeypatch):
    # A minimal app (the TAXII router behind the host check), NOT the full
    # app: importing threatfeedme.app before any fixture set CONFIG_PATH
    # lazily initialized core from ./config.yaml + ./data, and every later
    # test in the session wrote into the developer's real data directory.
    from fastapi import FastAPI
    from threatfeedme.middleware import HostCheckMiddleware
    from threatfeedme.routers import taxii as taxii_router
    # Patch the core module the router ACTUALLY uses (other suites purge and
    # re-import threatfeedme, so this file's collection-time `core` can be a
    # stale module), and via setitem, NOT setattr: monkeypatch.setattr reads
    # the old value first, and reading core.db triggers core's lazy init.
    live_core = taxii_router.core
    monkeypatch.setitem(live_core.__dict__, "db", db)
    app = FastAPI()
    app.include_router(taxii_router.router)

    @app.get("/api/host-check")
    def _probe():                       # a non-exempt path, for the host test
        return {"ok": True}
    app.add_middleware(HostCheckMiddleware)
    return TestClient(app)


def _cid(kind, tier):
    return next(c for c, kt in taxii.COLLECTIONS.items() if kt == (kind, tier))


def _all(client, cid, **params):
    objs, token, pages = [], None, 0
    while True:
        q = dict(params, **({"next": token} if token else {}))
        r = client.get(f"/taxii2/api/collections/{cid}/objects/", params=q, headers=H)
        assert r.status_code == 200, r.text
        j = r.json()
        objs += j["objects"]
        pages += 1
        if not j["more"]:
            return objs, pages
        token = j["next"]


def test_discovery_root_and_collections(client):
    d = client.get("/taxii2/", headers=H)
    assert d.status_code == 200 and d.headers["content-type"].startswith("application/taxii+json")
    root = d.json()["api_roots"][0]
    assert root.endswith("/taxii2/api/")
    assert client.get("/taxii2/api/", headers=H).json()["versions"] == [taxii.TAXII_MEDIA]
    cols = client.get("/taxii2/api/collections/", headers=H).json()["collections"]
    assert len(cols) == 6 and all(c["can_read"] and not c["can_write"] for c in cols)
    for c in cols:
        uuid.UUID(c["id"])
        assert client.get(f"/taxii2/api/collections/{c['id']}/", headers=H).json() == c


def test_each_collection_serves_exactly_what_its_feed_url_serves(client, db):
    for kind in ("ip", "domain"):
        for tier in ("high", "medium", "all"):
            objs, _ = _all(client, _cid(kind, tier))
            feed = set(feed_cache.txt(db, tier, kind)[0].decode().split())
            assert {o["name"] for o in objs} == feed, (kind, tier)


def test_ip_and_domain_collections_never_mix(client):
    ips, _ = _all(client, _cid("ip", "all"))
    doms, _ = _all(client, _cid("domain", "all"))
    assert all("addr:value" in o["pattern"] for o in ips)
    assert all(o["pattern"].startswith("[domain-name:value") for o in doms)


def test_stix_indicators_are_well_formed(client):
    objs, _ = _all(client, _cid("ip", "all"))
    objs += _all(client, _cid("domain", "all"))[0]
    for o in objs:
        assert o["type"] == "indicator" and o["spec_version"] == "2.1"
        assert o["id"].startswith("indicator--") and uuid.UUID(o["id"][11:])
        for f in ("created", "modified", "valid_from", "valid_until"):
            assert STIX_TS.match(o[f]), (f, o[f])
        assert o["modified"] >= o["created"] and o["valid_until"] > o["valid_from"]
        assert o["pattern_type"] == "stix" and 0 <= o["confidence"] <= 100
    pats = {o["name"]: o["pattern"] for o in objs}
    assert pats["45.66.230.0/24"] == "[ipv4-addr:value = '45.66.230.0/24']"
    assert pats["2001:db8:1::5"].startswith("[ipv6-addr:value")
    # a quote in a value can't break out of the pattern string
    if "x'y.example.net" in pats:
        assert pats["x'y.example.net"] == "[domain-name:value = 'x\\'y.example.net']"


def test_ids_are_stable_across_polls(client):
    a = {o["name"]: o["id"] for o in _all(client, _cid("ip", "all"))[0]}
    b = {o["name"]: o["id"] for o in _all(client, _cid("ip", "all"))[0]}
    assert a == b


def test_paging_has_no_gaps_or_duplicates(client):
    full, _ = _all(client, _cid("ip", "all"))
    paged, pages = _all(client, _cid("ip", "all"), limit=2)
    assert pages > 1
    assert [o["id"] for o in paged] == [o["id"] for o in full]
    assert len({o["id"] for o in paged}) == len(paged)


def test_added_after_is_strict_and_headers_report_the_window(client, db):
    cid = _cid("ip", "all")
    r = client.get(f"/taxii2/api/collections/{cid}/objects/", headers=H)
    last = r.headers["X-TAXII-Date-Added-Last"]
    assert STIX_TS.match(r.headers["X-TAXII-Date-Added-First"])
    future = (datetime.now(timezone.utc) + timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    assert _all(client, cid, added_after=future)[0] == []
    past = "2000-01-01T00:00:00.000Z"
    assert len(_all(client, cid, added_after=past)[0]) == len(r.json()["objects"])
    assert last


def test_whitelist_and_tier_scopes_apply(client, db):
    db.add_to_whitelist("185.9.9.9", "internal", "t")
    names = {o["name"] for o in _all(client, _cid("ip", "all"))[0]}
    assert "185.9.9.9" not in names
    hi = {o["name"] for o in _all(client, _cid("ip", "high"))[0]}
    med = {o["name"] for o in _all(client, _cid("ip", "medium"))[0]}
    assert hi <= med <= names


def test_bad_requests_get_taxii_errors(client):
    cid = _cid("ip", "all")
    r = client.get("/taxii2/api/collections/nope/objects/", headers=H)
    assert r.status_code == 404 and r.json()["http_status"] == "404"
    assert r.headers["content-type"].startswith("application/taxii+json")
    for bad in ({"next": "!!!"}, {"next": "WyJhIl0"}, {"added_after": "yesterday"}):
        assert client.get(f"/taxii2/api/collections/{cid}/objects/", params=bad,
                          headers=H).status_code == 400, bad
    r = client.get("/taxii2/", headers={"Accept": "application/taxii+json;version=2.0"})
    assert r.status_code == 406
    assert client.get("/taxii2/", headers={"Accept": "text/html"}).status_code == 406
    assert client.get("/taxii2/", headers={"Accept": "*/*"}).status_code == 200
    j = client.get(f"/taxii2/api/collections/{cid}/objects/",
                   params={"match[type]": "malware"}, headers=H).json()
    assert j == {"more": False, "objects": []}


def test_limit_is_clamped(client):
    cid = _cid("ip", "all")
    assert client.get(f"/taxii2/api/collections/{cid}/objects/", params={"limit": 0},
                      headers=H).status_code == 422
    r = client.get(f"/taxii2/api/collections/{cid}/objects/", params={"limit": 10**9},
                   headers=H)
    assert r.status_code == 200


def test_manifest_matches_objects(client):
    cid = _cid("ip", "all")
    objs = _all(client, cid)[0]
    man = client.get(f"/taxii2/api/collections/{cid}/manifest/", headers=H).json()["objects"]
    assert [m["id"] for m in man] == [o["id"] for o in objs]
    assert all(m["media_type"] == taxii.STIX_MEDIA for m in man)


def test_writes_are_not_offered(client):
    cid = _cid("ip", "all")
    r = client.post(f"/taxii2/api/collections/{cid}/objects/", json={"objects": []},
                    headers={**H, "X-Requested-With": "XMLHttpRequest"})
    assert r.status_code in (403, 405)


def test_taxii_is_exempt_from_the_host_allowlist(client, db, monkeypatch):
    import sys
    middleware = sys.modules["threatfeedme.middleware"]
    monkeypatch.setenv(middleware.ALLOWED_HOSTS_ENV, "tfm.example.net")
    middleware.invalidate_allowlist_cache()
    try:
        r = client.get("/taxii2/", headers={**H, "Host": "siem-proxy.example.org"})
        assert r.status_code == 200
        r = client.get("/api/host-check", headers={"Host": "siem-proxy.example.org"})
        assert r.status_code == 400                      # the dashboard API still is
    finally:
        monkeypatch.delenv(middleware.ALLOWED_HOSTS_ENV)
        middleware.invalidate_allowlist_cache()


def test_discovery_sends_clients_back_to_the_host_they_used(client):
    # the dashboard's feed URLs swap loopback for the LAN IP (for pasting into
    # a firewall); a TAXII client must be sent back where it came from
    j = client.get("/taxii2/", headers={**H, "Host": "127.0.0.1:8080"}).json()
    assert j["api_roots"] == ["http://127.0.0.1:8080/taxii2/api/"]
    j = client.get("/taxii2/", headers={**H, "Host": "tfm.example.net",
                                        "X-Forwarded-Proto": "https"}).json()
    assert j["api_roots"] == ["https://tfm.example.net/taxii2/api/"]


def test_a_junk_host_header_is_not_echoed_into_urls(client):
    j = client.get("/taxii2/", headers={**H, "Host": "evil.example\"><x"}).json()
    assert "evil" not in j["api_roots"][0] and "<" not in j["api_roots"][0]


def test_objects_describe_their_evidence(client):
    objs, _ = _all(client, _cid("ip", "all"))
    o = next(x for x in objs if x["name"] == "185.1.1.1")
    assert "reported by 2 feeds" in o["description"]
    assert set(o["labels"]) >= {"source:blocklist_de", "source:spamhaus_drop"}
    assert not any(k.startswith("x_") for k in o)
