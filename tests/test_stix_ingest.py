"""Reading TAXII 2.1 / STIX 2.1 as a feed (v2.5.0): only unconditional
indicator patterns become blocks, withdrawn indicators drop out, paging is
complete or the fetch fails, and our own TAXII output reads back exactly."""
import json
from datetime import datetime, timedelta, timezone

import pytest

from threatfeedme import feed_ingestor
from threatfeedme.credentials import KeyPolicy
from threatfeedme.feed_ingestor import FeedIngestor, taxii_objects_url
from threatfeedme.models import FeedSource
from threatfeedme.stix_ingest import _Skip, indicator_values, pattern_values


# ---- patterns --------------------------------------------------------------

@pytest.mark.parametrize("pattern,expected", [
    ("[ipv4-addr:value = '198.51.100.1']", ["198.51.100.1"]),
    ("[ipv4-addr:value = '198.51.100.1' OR ipv4-addr:value = '198.51.100.2']",
     ["198.51.100.1", "198.51.100.2"]),
    ("[ipv4-addr:value ISSUBSET '198.51.100.0/24']", ["198.51.100.0/24"]),
    ("[ipv6-addr:value = '2001:db8::1']", ["2001:db8::1"]),
    # MISP's ip-dst shape: the *_ref.type half is an annotation, not a condition
    ("[network-traffic:dst_ref.type = 'ipv4-addr' AND network-traffic:dst_ref.value = '203.0.113.9']",
     ["203.0.113.9"]),
    # ...and its multi-value form: AND binds tighter than OR
    ("[network-traffic:dst_ref.type = 'ipv4-addr' AND network-traffic:dst_ref.value = '203.0.113.1'"
     " OR network-traffic:dst_ref.type = 'ipv4-addr' AND network-traffic:dst_ref.value = '203.0.113.2']",
     ["203.0.113.1", "203.0.113.2"]),
    ("[(ipv4-addr:value = '198.51.100.1' OR ipv4-addr:value = '198.51.100.2')]",
     ["198.51.100.1", "198.51.100.2"]),
    ("[ipv4-addr:value = '198.51.100.1'] OR [ipv4-addr:value = '198.51.100.2']",
     ["198.51.100.1", "198.51.100.2"]),
    # A OR (B AND C): A is asserted on its own; the conditional chain is not
    ("[ipv4-addr:value = '198.51.100.1' OR ipv4-addr:value = '198.51.100.2'"
     " AND domain-name:value = 'x.example']", ["198.51.100.1"]),
])
def test_unconditional_values_are_read(pattern, expected):
    assert [v for _, v in pattern_values(pattern)] == expected


@pytest.mark.parametrize("pattern", [
    "[ipv4-addr:value = '198.51.100.1' AND network-traffic:dst_port = 443]",   # IP on a port
    "[ipv4-addr:value = '198.51.100.1' AND domain-name:value = 'x.example']",
    "[(ipv4-addr:value = '1.1.1.1' OR ipv4-addr:value = '2.2.2.2') AND network-traffic:dst_port = 22]",
    "[ipv4-addr:value = '198.51.100.1'] AND [domain-name:value = 'x.example']",
    "[ipv4-addr:value = '198.51.100.1'] FOLLOWEDBY [ipv4-addr:value = '198.51.100.2']",
    "[ipv4-addr:value = '198.51.100.1'] WITHIN 300 SECONDS",
    "[ipv4-addr:value = '198.51.100.1'] START t'2026-01-01T00:00:00Z' STOP t'2026-02-01T00:00:00Z'",
    "[ipv4-addr:value != '198.51.100.1']",
    "[ipv4-addr:value MATCHES '^198\\\\.']",
    "[ipv4-addr:value LIKE '198.51.%']",
    "[NOT ipv4-addr:value = '198.51.100.1']",
    "[ipv4-addr:value = '198.51.100.1'",          # unbalanced
    "ipv4-addr:value = '198.51.100.1'",           # no brackets
    "[ipv4-addr:value = '198.51.100.1'] ; DROP",  # junk
    "",
    "[" + "ipv4-addr:value = '1.1.1.1' OR " * 2000 + "ipv4-addr:value = '1.1.1.1']",   # oversized
])
def test_conditional_or_malformed_patterns_are_skipped(pattern):
    with pytest.raises(_Skip):
        pattern_values(pattern)


def test_quotes_in_values_round_trip():
    assert pattern_values("[domain-name:value = 'o\\'brien.example']") == \
        [("domain-name:value", "o'brien.example")]


# ---- indicator selection --------------------------------------------------

NOW = datetime(2026, 9, 23, tzinfo=timezone.utc)


def _ind(i, pattern, **extra):
    return {"type": "indicator", "spec_version": "2.1", "id": f"indicator--{i:08d}-0000-4000-8000-000000000000",
            "created": "2026-09-01T00:00:00.000Z", "modified": extra.pop("modified", "2026-09-01T00:00:00.000Z"),
            "pattern": pattern, "pattern_type": "stix", "valid_from": "2026-09-01T00:00:00Z", **extra}


def test_withdrawn_benign_and_foreign_indicators_are_left_out():
    objs = [
        _ind(1, "[ipv4-addr:value = '198.51.100.1']"),
        _ind(2, "[ipv4-addr:value = '198.51.100.2']", revoked=True),
        _ind(3, "[ipv4-addr:value = '198.51.100.3']", valid_until="2026-09-10T00:00:00Z"),
        _ind(4, "[ipv4-addr:value = '198.51.100.4']", valid_until="2026-12-01T00:00:00Z"),
        _ind(5, "[ipv4-addr:value = '198.51.100.5']", indicator_types=["benign"]),
        _ind(6, "alert tcp any any -> any any", pattern_type="snort"),
        _ind(7, "[ipv4-addr:value = '198.51.100.7' AND network-traffic:dst_port = 443]"),
        _ind(8, "[domain-name:value = 'evil.example']"),
        _ind(9, "[file:hashes.'SHA-256' = 'aa']"),
        {"type": "ipv4-addr", "id": "ipv4-addr--x", "value": "198.51.100.99"},   # bare SCO: context, not a block
        {"type": "malware", "id": "malware--x", "name": "x"},
        "not an object",
    ]
    ips, stats = indicator_values(objs, "ip", now=NOW)
    assert ips == ["198.51.100.1", "198.51.100.4"]
    assert stats["revoked"] == 1 and stats["expired"] == 1 and stats["benign"] == 1
    assert stats["not_stix"] == 1 and stats["conditional"] == 2
    domains, _ = indicator_values(objs, "domain", now=NOW)
    assert domains == ["evil.example"]


def test_latest_version_of_an_indicator_wins():
    old = _ind(1, "[ipv4-addr:value = '198.51.100.1']", modified="2026-09-01T00:00:00.000Z")
    new = _ind(1, "[ipv4-addr:value = '198.51.100.1']", modified="2026-09-20T00:00:00.000Z", revoked=True)
    assert indicator_values([old, new], "ip", now=NOW)[0] == []
    assert indicator_values([new, old], "ip", now=NOW)[0] == []


# ---- collection URL -------------------------------------------------------

@pytest.mark.parametrize("url,expected", [
    ("https://t.example/api/collections/abc/", "https://t.example/api/collections/abc/objects/"),
    ("https://t.example/api/collections/abc", "https://t.example/api/collections/abc/objects/"),
    ("https://t.example/api/collections/abc/objects/", "https://t.example/api/collections/abc/objects/"),
    ("https://t.example:8443/taxii2/root/collections/abc/?x=1", "https://t.example:8443/taxii2/root/collections/abc/objects/"),
])
def test_collection_urls(url, expected):
    assert taxii_objects_url(url) == expected


@pytest.mark.parametrize("url", ["https://t.example/taxii2/", "https://t.example/api/",
                                 "ftp://t.example/api/collections/abc/", "https:///collections/abc/"])
def test_non_collection_urls_are_refused(url):
    with pytest.raises(ValueError):
        taxii_objects_url(url)


# ---- the scraper against a fake server --------------------------------------

class _Resp:
    def __init__(self, status=200, body=b"", headers=None):
        self.status_code, self._body = status, body
        self.headers, self.encoding = headers or {}, "utf-8"

    def iter_content(self, chunk_size=65536, decode_unicode=False):
        yield self._body

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def close(self):
        pass


def _pages(n, per=3):
    out = []
    for p in range(n):
        objs = [_ind(p * per + k, f"[ipv4-addr:value = '198.51.{p}.{k + 1}']") for k in range(per)]
        env = {"more": p < n - 1, "objects": objs}
        if p < n - 1:
            env["next"] = f"tok{p + 1}"
        out.append(env)
    return out


def _ingestor(db, pages, seen, status=200):
    ing = FeedIngestor(db, allow_private_urls=True, key_policy=KeyPolicy([]))

    def fake_get(url, headers):
        seen.append((url, dict(headers)))
        if status != 200:
            return _Resp(status)
        from urllib.parse import parse_qs, urlsplit
        tok = parse_qs(urlsplit(url).query).get("next", ["tok0"])[0]
        env = pages[int(tok[3:])]
        return _Resp(200, json.dumps(env).encode())
    ing._get_with_retries = fake_get
    return ing


@pytest.fixture
def db(tmp_path):
    from threatfeedme.database import Database
    return Database(str(tmp_path / "t.db"))


def _feed(**kw):
    return FeedSource(name="misp_ips", url="https://misp.example/taxii2/root/collections/c1/",
                      scraper="taxii21", **kw)


def test_scraper_reads_every_page_and_sends_the_taxii_headers(db, monkeypatch):
    monkeypatch.setenv("TFM_FEED_MISP_IPS", "k3y")
    seen = []
    ing = _ingestor(db, _pages(3), seen)
    out = ing.fetch_feed(_feed(requires_auth=True, auth_env="TFM_FEED_MISP_IPS"))
    assert len(out) == 9
    assert [u.split("?")[1] for u, _ in seen] == ["limit=1000", "limit=1000&next=tok1", "limit=1000&next=tok2"]
    assert all(h["Accept"] == "application/taxii+json;version=2.1" and h["Authorization"] == "k3y"
               for _, h in seen)


def test_a_read_cut_short_fails_instead_of_recording_mass_leaves(db, monkeypatch):
    monkeypatch.setattr(feed_ingestor, "_TAXII_MAX_PAGES", 2)
    with pytest.raises(RuntimeError, match="partial read"):
        _ingestor(db, _pages(3), []).fetch_feed(_feed())


def test_more_without_next_fails(db):
    pages = _pages(2)
    del pages[0]["next"]
    with pytest.raises(RuntimeError, match="without a next token"):
        _ingestor(db, pages, []).fetch_feed(_feed())


@pytest.mark.parametrize("status,msg", [(401, "refused the credentials"), (403, "refused the credentials"),
                                        (406, "doesn't speak TAXII 2.1")])
def test_http_errors_are_named(db, status, msg):
    with pytest.raises(RuntimeError, match=msg):
        _ingestor(db, _pages(1), [], status=status).fetch_feed(_feed())


def test_a_collection_of_the_other_kind_says_so(db):
    pages = [{"more": False, "objects": [_ind(1, "[domain-name:value = 'evil.example']")]}]
    with pytest.raises(RuntimeError, match="no current ip indicators.*1 of another kind"):
        _ingestor(db, pages, []).fetch_feed(_feed())


def test_a_shipped_key_is_never_sent_to_a_taxii_server(db, monkeypatch):
    # KeyPolicy binds OTX_API_KEY to otx.alienvault.com; a TAXII feed naming
    # it must not carry it to another host.
    monkeypatch.setenv("OTX_API_KEY", "secret")
    ing = _ingestor(db, _pages(1), [])
    ing.key_policy = KeyPolicy([{"url": "https://otx.alienvault.com/api", "auth_env": "OTX_API_KEY"}])
    with pytest.raises(RuntimeError, match="refusing to send OTX_API_KEY"):
        ing.fetch_feed(_feed(requires_auth=True, auth_env="OTX_API_KEY"))


# ---- round trip: our own TAXII server read back by our own client -------------

def test_our_taxii_output_reads_back_exactly(tmp_path, monkeypatch):
    """threat-feed-me -> TAXII 2.1 -> threat-feed-me: every IP and domain the
    Everything collections serve comes back through the scraper, paging and
    quote-escaping included."""
    from fastapi import FastAPI
    from starlette.testclient import TestClient
    from threatfeedme import feed_cache, taxii
    from threatfeedme.database import Database
    from threatfeedme.routers import taxii as taxii_router
    from threatfeedme.scorer import ConfidenceScorer

    feed_cache.invalidate()
    src = Database(str(tmp_path / "src.db"))
    src.add_indicators_bulk([("45.66.230.0", {"cidr": "45.66.230.0/24"}), ("185.1.1.1", {}),
                             ("2001:db8:1::5", {}), ("185.1.1.2", {}), ("185.9.9.9", {})],
                            source="spamhaus_drop")
    src.add_indicators_bulk([("evil-login.top", {}), ("x'y.example.net", {})],
                            source="phishing_army", kind="domain")
    ConfidenceScorer(src, {}).recalculate_all_scores()
    monkeypatch.setitem(taxii_router.core.__dict__, "db", src)
    app = FastAPI()
    app.include_router(taxii_router.router)
    web = TestClient(app)

    def via_testclient(url, headers):
        r = web.get(url.replace("http://tfm.test", ""), headers=headers)
        return _Resp(r.status_code, r.content, dict(r.headers))
    monkeypatch.setattr(feed_ingestor, "_TAXII_PAGE_LIMIT", 2)      # force several pages

    dst = Database(str(tmp_path / "dst.db"))
    try:
        for kind in ("ip", "domain"):
            cid = next(c for c, kt in taxii.COLLECTIONS.items() if kt == (kind, "all"))
            ing = FeedIngestor(dst, allow_private_urls=True, key_policy=KeyPolicy([]))
            ing._get_with_retries = via_testclient
            feed = FeedSource(name=f"rt_{kind}", url=f"http://tfm.test/taxii2/api/collections/{cid}/",
                              scraper="taxii21", indicator_kind=kind)
            got = feed_ingestor._scrape_taxii21(ing, feed).splitlines()
            want = {"ip": {"45.66.230.0/24", "185.1.1.1", "2001:db8:1::5", "185.1.1.2", "185.9.9.9"},
                    "domain": {"evil-login.top", "x'y.example.net"}}[kind]
            assert set(got) == want, (kind, got)
    finally:
        feed_cache.invalidate()
