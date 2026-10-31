"""Opt-in keyed URLhaus feed (issue #8).

abuse.ch retired every keyless /downloads/ endpoint (410 Gone, verified
2026-10-25); the roster's authoritative domain source now ships as
`urlhaus_keyed`: disabled by default, its URL carries a {auth_key} template
substituted from URLHAUS_AUTH_KEY at fetch time only. The rules these tests
pin: the key never reaches the DB, the dashboard's error text, or any log
line; it never follows a redirect off urlhaus-api.abuse.ch; and a fresh
install without the key makes ZERO network calls to abuse.ch.

Fully offline: requests.get is replaced with a scripted fake (the
test_hardening_2_5_7._TalosSession style) and DNS comes from the conftest
autouse public-resolution stub — nothing here can open a socket.
"""
import logging
import os
from urllib.parse import quote

import pytest
import requests
import yaml

from threatfeedme.credentials import KeyPolicy
from threatfeedme.database import Database
from threatfeedme.feed_ingestor import (AUTH_URL_PLACEHOLDER, FeedIngestor,
                                        NOT_MODIFIED, url_has_auth_placeholder)
from threatfeedme.models import FeedSource, FeedType
from threatfeedme.scorer import ConfidenceScorer

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "..", "config.yaml")

FEED_NAME = "urlhaus_keyed"
TEMPLATE = ("https://urlhaus-api.abuse.ch/v2/files/exports/"
            "{auth_key}/recent.csv")
KEY = "synthetic-test-key-7f3c1d"          # obviously synthetic fixture
RESOLVED = TEMPLATE.replace(AUTH_URL_PLACEHOLDER, KEY)

# Plain-header variant: quoted CSV, header row, and one URL that legally
# contains a comma INSIDE its quotes — the reason parsing must use the csv
# module rather than line/regex splitting. (The LIVE export's layout is
# LIVE_CSV_BODY below.)
CSV_BODY = (
    "urlhash,url,url_status,last_online,event\r\n"
    "d41d8cd98f00b204e9800998ecf8427e,"
    "http://malware-drop.example/payload,online,2026-10-25 00:00:00,drop\r\n"
    '"e3b0c44298fc1c149afbf4c8996fb924",'
    '"http://evil-c2.example:8080/get,payload?x=1",online,'
    "2026-10-25 00:00:01,drop\r\n"
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,,offline,2026-10-25 00:00:02,drop\r\n"
)

# The live export's layout (checked against the real recent.csv, 2026-10-31):
# a '#' banner, then the header as a COMMENTED line, then fully quoted rows.
# csv.DictReader on the raw body took the banner as its header and the feed
# failed with "no 'url' values" on a valid 32 MB download.
LIVE_CSV_BODY = (
    "################################################################\r\n"
    "# abuse.ch URLhaus Database Dump (CSV - recent URLs only)      #\r\n"
    "# Last updated: 2026-10-31 19:20:17 (UTC)                      #\r\n"
    "#                                                              #\r\n"
    "# Terms Of Use: https://urlhaus.abuse.ch/api/                  #\r\n"
    "################################################################\r\n"
    "#\r\n"
    "# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter\r\n"
    '"4049094","2026-10-31 19:20:17","http://malware-drop.example/payload",'
    '"online","2026-10-31 19:20:17","malware_download","exe",'
    '"https://urlhaus.abuse.ch/url/4049094/","reporter1"\r\n'
    '"4049093","2026-10-31 19:20:13","http://evil-c2.example:8080/get,payload?x=1",'
    '"online","2026-10-31 19:20:13","malware_download","elf,mirai",'
    '"https://urlhaus.abuse.ch/url/4049093/","reporter2"\r\n'
)


def _shipped_cfg():
    with open(CONFIG_PATH, encoding="utf-8") as f:
        return yaml.safe_load(f)


class _Headers(dict):
    """Case-insensitive like requests' real Headers (the fetch path reads
    'Location' verbatim)."""

    def get(self, key, default=None):
        return super().get(str(key).lower(), default)


class _Resp:
    """Enough of requests.Response for the fetch path. raise_for_status
    quotes the URL the way requests does — that string is the redaction
    trap these tests exist for."""

    def __init__(self, url="", body="", status=200, headers=None):
        self.url = url
        self.status_code = status
        self.headers = _Headers({k.lower(): v for k, v in (headers or {}).items()})
        self.encoding = "utf-8"
        self.closed = False
        self._body = body

    def iter_content(self, chunk_size=65536, decode_unicode=False):
        yield self._body.encode("utf-8")

    def close(self):
        self.closed = True

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.exceptions.HTTPError(
                f"{self.status_code} Client Error for url: {self.url}")


class _UrlhausGateway:
    """Scripted requests.get replacement. Every call is recorded; unknown
    URLs answer 404 with a page that ECHOES the requested URL (a leaky
    upstream), so redaction has to hold even then."""

    def __init__(self, script=None, redirects=None):
        self.calls = []
        self.script = dict(script or {})
        self.redirects = dict(redirects or {})

    def get(self, url, **kw):
        self.calls.append(dict(kw, url=url))
        if url in self.redirects:
            return _Resp(url, "", 302, {"location": self.redirects[url]})
        if url in self.script:
            status, headers, body = self.script[url]
            return _Resp(url, body, status, headers)
        if url == RESOLVED:
            return _Resp(url, CSV_BODY, 200)
        return _Resp(url, f"not found, tried {url}", 404)


def _feed(**over):
    fields = dict(name=FEED_NAME, url=TEMPLATE, feed_type=FeedType.THREAT_INTEL,
                  indicator_kind="domain", update_interval=3600,
                  auth_env="URLHAUS_AUTH_KEY", scraper="urlhaus_keyed_csv",
                  enabled=True)
    fields.update(over)
    return FeedSource(**fields)


def _setup(tmp_path, monkeypatch, key=KEY, gateway=None, policy=None):
    """Ingestor + feed with the network and DNS replaced by seams. The key
    policy mirrors the SHIPPED roster (urlhaus_keyed declares auth_env +
    its host), which is what binds the key to urlhaus-api.abuse.ch."""
    from threatfeedme import feed_ingestor as fi
    if key is None:
        monkeypatch.delenv("URLHAUS_AUTH_KEY", raising=False)
    else:
        monkeypatch.setenv("URLHAUS_AUTH_KEY", key)
    monkeypatch.setattr(fi, "_sleep", lambda s: None)
    gw = gateway if gateway is not None else _UrlhausGateway()
    monkeypatch.setattr(requests, "get", gw.get)
    db = Database(str(tmp_path / "t.db"))
    ing = FeedIngestor(db, key_policy=policy or KeyPolicy([
        {"name": FEED_NAME, "url": TEMPLATE, "auth_env": "URLHAUS_AUTH_KEY"}]))
    return fi, db, ing, gw


# ---------------------------------------------------------------- config ----

def test_shipped_config_declares_the_keyed_feed():
    """The keyed entry carries every field issue #8 ratified. The dead
    keyless hostfile stays listed but DISABLED: dropping it would leave it
    enabled and failing on every install that was seeded with it (sync only
    switches off feeds still listed in config)."""
    cfg = _shipped_cfg()
    feeds = {f["name"]: f for f in cfg["feeds"]}
    assert feeds["urlhaus_hostfile"]["enabled"] is False
    entry = feeds[FEED_NAME]
    assert entry["url"] == TEMPLATE
    assert AUTH_URL_PLACEHOLDER in entry["url"], "template, never a real key"
    assert entry["indicator_kind"] == "domain"
    assert entry["update_interval"] == 3600
    assert entry["update_interval"] >= 300, "upstream fair-use floor"
    assert entry["auth_env"] == "URLHAUS_AUTH_KEY"
    assert entry["enabled"] is False, "keyless-default promise: opt-in only"
    assert entry["scraper"] == "urlhaus_keyed_csv"
    # The roster's authoritative domain source is restored to the list that
    # grants force-HIGH provenance.
    auth = (cfg["scoring"]["high_confidence"]["authoritative_domain_feeds"])
    assert FEED_NAME in auth and "cert_pl" in auth


def test_shipped_key_is_bound_to_the_api_host_by_key_policy():
    """KeyPolicy builds the shipped binding straight from config.yaml: the
    URLHAUS key may go to urlhaus-api.abuse.ch and nowhere else."""
    policy = KeyPolicy.from_config(_shipped_cfg())
    assert policy.allowed_var("URLHAUS_AUTH_KEY")
    assert policy.may_send("URLHAUS_AUTH_KEY", TEMPLATE)
    assert not policy.may_send("URLHAUS_AUTH_KEY",
                               "https://evil.example/v2/files/exports/{auth_key}/recent.csv")


# ------------------------------------------------- AC1: fresh install -------

def test_fresh_install_shows_feed_disabled_with_zero_network_calls(tmp_path, monkeypatch):
    """No URLHAUS_AUTH_KEY anywhere: the feed is visible, ships disabled,
    its stored url is the template — and the refresh path that the scheduler
    uses makes ZERO network calls to abuse.ch."""
    gw = _UrlhausGateway()
    cfg = _shipped_cfg()
    monkeypatch.setattr(requests, "get", gw.get)
    from threatfeedme import feed_ingestor as fi
    from threatfeedme import pipeline
    db = Database(str(tmp_path / "t.db"))
    db.seed_feeds_from_config(cfg)
    row = db.get_feed_source(FEED_NAME)
    assert row is not None and not row.enabled
    assert AUTH_URL_PLACEHOLDER in row.url and KEY not in row.url

    results = pipeline.fetch_feeds(db, cfg, only=[FEED_NAME])
    assert results == {}                     # disabled: skipped, no error
    assert gw.calls == []                    # not one byte toward abuse.ch


def test_enabled_without_key_errors_with_set_message_and_no_network(tmp_path, monkeypatch):
    """An operator who enables the feed before setting the key gets a clear
    'Set URLHAUS_AUTH_KEY' error (same refusal posture as OTX's missing key),
    recorded as an error row — and still no network call."""
    fi, db, ing, gw = _setup(tmp_path, monkeypatch, key=None)
    feed = _feed()
    with pytest.raises(RuntimeError, match="Set URLHAUS_AUTH_KEY"):
        ing.fetch_feed(feed)
    assert gw.calls == []
    stats = {s.feed_name: s for s in db.get_feed_stats()}
    with pytest.raises(RuntimeError, match="Set URLHAUS_AUTH_KEY"):
        ing.ingest_feed(feed)
    assert stats is not None
    err = {s.feed_name: s for s in db.get_feed_stats()}[FEED_NAME]
    assert err.status == "error"
    assert "Set URLHAUS_AUTH_KEY" in err.error_message


# ------------------------------------- AC2: key set, feed ingests -----------

def test_enabled_feed_with_key_ingests_domains(tmp_path, monkeypatch):
    """Live (scripted) fetch through the scraper: both CSV rows become
    domains through the normal pipeline — including the quoted URL whose
    comma would destroy a naive line split — and feed status is success
    with the count."""
    fi, db, ing, gw = _setup(tmp_path, monkeypatch)
    feed = _feed()
    entries = ing.fetch_feed(feed)
    values = {e["ip"] for e in entries}
    assert values == {"malware-drop.example", "evil-c2.example"}
    assert all(e["kind"] == "domain" for e in entries)
    # The comma-bearing quoted URL survived only because the csv module,
    # not regex lines, read the file.
    assert "evil-c2.example" in values

    count = ing.ingest_feed(feed)
    assert count == 2
    stats = {s.feed_name: s for s in db.get_feed_stats()}[FEED_NAME]
    assert stats.status == "success" and stats.total_indicators == 2
    # The request carried the key in the PATH only — never a header.
    call = gw.calls[0]
    assert call["url"] == RESOLVED
    assert "Authorization" not in call["headers"]


def test_live_export_layout_with_commented_header_ingests(tmp_path, monkeypatch):
    """The real export: '#' banner and a commented header line. Both rows
    must ingest (the banner is not the header; the commented field list is),
    including the quoted URL that contains a comma."""
    fi, db, ing, gw = _setup(tmp_path, monkeypatch)
    gw.script[RESOLVED] = (200, {}, LIVE_CSV_BODY)
    entries = ing.fetch_feed(_feed())
    assert {e["ip"] for e in entries} == {"malware-drop.example", "evil-c2.example"}
    assert all(e["kind"] == "domain" for e in entries)


def test_not_modified_is_passed_through(tmp_path, monkeypatch):
    fi, db, ing, gw = _setup(tmp_path, monkeypatch)
    db.set_feed_http_cache(FEED_NAME, '"etag1"', "Wed, 01 Jan 2025 00:00:00 GMT")
    gw.script[RESOLVED] = (304, {}, "")
    assert ing.fetch_feed(_feed()) is NOT_MODIFIED


def test_unusable_csv_body_fails_loud(tmp_path, monkeypatch):
    """A 200 that isn't the export (auth error page, schema change) must
    fail the fetch, not ingest zero domains and let retention drain the
    feed."""
    fi, db, ing, gw = _setup(tmp_path, monkeypatch)
    gw.script[RESOLVED] = (200, {}, "<html>invalid auth key</html>")
    with pytest.raises(RuntimeError, match="no 'url' values"):
        ing.fetch_feed(_feed())


def test_key_is_percent_encoded_into_its_path_segment(tmp_path, monkeypatch):
    """A credential that contains URL syntax can't rewrite the request
    target: it is escaped, staying one path segment."""
    weird = "key/with?and&and %20chars"
    escaped = TEMPLATE.replace(AUTH_URL_PLACEHOLDER, quote(weird, safe=""))
    gw = _UrlhausGateway(script={escaped: (200, {}, CSV_BODY)})
    fi, db, ing, gw = _setup(tmp_path, monkeypatch, key=weird, gateway=gw)
    entries = ing.fetch_feed(_feed())
    assert {e["ip"] for e in entries} == {"malware-drop.example", "evil-c2.example"}
    assert gw.calls[0]["url"] == escaped


# ------------------------------------------- AC3: key redaction -------------

def test_failed_fetch_error_text_carries_no_key(tmp_path, monkeypatch, caplog):
    """The spec's pinned assertion: a failed fetch's error text contains no
    key substring — in the exception, the log lines, or the feed_stats row
    the dashboard renders. The host stays (diagnosis needs it); the key
    never does."""
    # Upstream echoes the full URL (key included) in its 403 body — the
    # classic leak path — and requests quotes it in raise_for_status.
    gw = _UrlhausGateway(script={RESOLVED: (403, {}, f"invalid auth key: {RESOLVED}")})
    fi, db, ing, gw = _setup(tmp_path, monkeypatch, gateway=gw)
    db.set_feed_http_cache(FEED_NAME, '"etag1"', "Wed, 01 Jan 2025 00:00:00 GMT")
    caplog.set_level(logging.DEBUG)
    with pytest.raises(requests.exceptions.HTTPError) as excinfo:
        ing.ingest_feed(_feed())
    blob = str(excinfo.value) + "\n".join(r.getMessage() for r in caplog.records) \
        + str([s.error_message for s in db.get_feed_stats()])
    assert KEY not in blob
    assert "urlhaus-api.abuse.ch" in str(excinfo.value)  # diagnosis survives
    err = {s.feed_name: s for s in db.get_feed_stats()}[FEED_NAME]
    assert err.status == "error" and KEY not in (err.error_message or "")
    # An invalid key must also clear the stored validators: a saved ETag
    # could otherwise 304 the feed green on stale membership.
    assert db.get_feed_http_cache(FEED_NAME) == (None, None)


def test_feed_row_never_stores_the_resolved_url(tmp_path, monkeypatch):
    """Only the template is persisted; substitution happens at fetch time."""
    fi, db, ing, gw = _setup(tmp_path, monkeypatch)
    db.add_feed(_feed())
    row = db.get_feed_source(FEED_NAME)
    assert row.url == TEMPLATE and KEY not in row.url
    ing.ingest_feed(_feed())
    row = db.get_feed_source(FEED_NAME)
    assert row.url == TEMPLATE and KEY not in row.url


def test_redact_helper_scrubs_secret_values():
    from threatfeedme.feed_ingestor import _redact
    assert _redact(f"failed for url: {RESOLVED}", (KEY,)) == \
        f"failed for url: {RESOLVED.replace(KEY, '[redacted]')}"
    # query-string behavior is unchanged
    assert "?" in _redact("https://x.example/a?token=abc")
    assert "abc" not in _redact("https://x.example/a?token=abc")
    assert url_has_auth_placeholder(TEMPLATE)
    assert not url_has_auth_placeholder("https://x.example/list.txt")


# ------------------------------- AC4: redirect / retarget discipline --------

def test_redirect_off_the_key_host_is_refused(tmp_path, monkeypatch):
    """A Location off urlhaus-api.abuse.ch is refused outright — the key in
    the path must never travel, not even inside a followed chain."""
    gw = _UrlhausGateway(redirects={RESOLVED: "https://mirror.example/recent.csv"})
    fi, db, ing, gw = _setup(tmp_path, monkeypatch, gateway=gw)
    with pytest.raises(RuntimeError, match="never travels off its host"):
        ing.fetch_feed(_feed())
    assert [c["url"] for c in gw.calls] == [RESOLVED]   # mirror never fetched


def test_key_host_never_sees_a_cross_origin_header_leak_but_follows_its_own_redirect(
        tmp_path, monkeypatch):
    """Same-host redirects keep working (upstream shuffles export paths);
    the hop stays on the origin and the fetch succeeds."""
    moved = f"https://urlhaus-api.abuse.ch/v2/files/exports/{KEY}/active.csv"
    gw = _UrlhausGateway(redirects={RESOLVED: moved},
                         script={moved: (200, {}, CSV_BODY)})
    fi, db, ing, gw = _setup(tmp_path, monkeypatch, gateway=gw)
    entries = ing.fetch_feed(_feed())
    assert {e["ip"] for e in entries} == {"malware-drop.example", "evil-c2.example"}
    assert [c["url"] for c in gw.calls] == [RESOLVED, moved]


def test_retargeted_keyed_feed_is_refused_by_key_policy(tmp_path, monkeypatch):
    """Re-pointing the keyed feed at another host must not carry the shipped
    key off-box — same discipline as header keys (credentials.py)."""
    fi, db, ing, gw = _setup(tmp_path, monkeypatch)
    feed = _feed(url="https://evil.example/v2/files/exports/{auth_key}/recent.csv")
    with pytest.raises(RuntimeError, match="refusing to send"):
        ing.fetch_feed(feed)
    assert gw.calls == []


# -------------------------------- AC2 (scoring): authoritative boost --------

def test_urlhaus_keyed_grants_authoritative_domain_high():
    """Mirrors the authoritative-tier pins in test_aggregator: with the
    keyed feed seeded from the shipped config, a domain it alone reports
    is force-HIGH — the roster's provenance path is restored."""
    cfg = {"feeds": [{"name": FEED_NAME, "url": TEMPLATE,
                      "feed_type": "threat_intel",
                      "indicator_kind": "domain",
                      "auth_env": "URLHAUS_AUTH_KEY",
                      "scraper": "urlhaus_keyed_csv",
                      "enabled": True}],
           "scoring": {"tiering": {"method": "effective_votes"},
                       "high_confidence": {
                           "authoritative_domain_feeds": [FEED_NAME]}}}
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        db = Database(os.path.join(td, "score.db"))
        db.seed_feeds_from_config(cfg)
        scorer = ConfidenceScorer(db, cfg)
        assert scorer._tier_from_votes(1.0, [FEED_NAME], 1.1, 10.0,
                                       kind="domain").value == "high"
        # A non-authoritative domain feed with the same evidence stays LOW.
        assert scorer._tier_from_votes(1.0, ["openphish_community"], 1.1, 10.0,
                                       kind="domain").value == "low"
        # And through the shape pipeline.scorer_config actually builds
        # (DB-fed 'feeds' without URLs + explicit config_feed_urls).
        from threatfeedme import pipeline
        sc_cfg = pipeline.scorer_config(db, cfg)
        assert ConfidenceScorer(db, sc_cfg)._tier_from_votes(
            1.0, [FEED_NAME], 1.1, 10.0, kind="domain").value == "high"
