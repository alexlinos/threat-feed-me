"""Tests for the remote feed catalog (issue #9): feed_catalog.yaml pulled
from GitHub, gated on a monotonic catalog_version, merged with the same
provenance/tombstone semantics as the baked defaults.

Fully offline by construction: every fetch goes through the injected
``fetch`` seam (or a monkeypatched ``requests.get``); no test can reach the
network. Covers the acceptance criteria: never-destructive failures (1),
tombstones (2), URL overrides (3), stale-version refusal (4), row
provenance + preference stickiness (5), and the auto_add OFF review
queue with Add/Dismiss (6).
"""
import logging
import os
import sys
from datetime import datetime, timedelta, timezone

import pytest
import yaml

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from threatfeedme import catalog_sync, pipeline, scheduler
from threatfeedme.database import Database
from threatfeedme.models import FeedSource

CATALOG_URL = ("https://raw.githubusercontent.com/alexlinos/threat-feed-me"
               "/main/feed_catalog.yaml")
CONFIG = {"catalog": {"enabled": True, "url": CATALOG_URL, "auto_add": True}}

ALPHA = {"name": "alpha_bl", "url": "https://feeds.example.org/alpha.txt",
         "feed_type": "threat_intel", "update_interval": 3600}
BETA = {"name": "beta_list", "url": "https://feeds.example.org/beta.txt",
        "feed_type": "threat_intel", "update_interval": 7200}


def catalog_text(version, feeds):
    return yaml.safe_dump({"catalog_version": version,
                           "updated": "2026-10-25",
                           "feeds": list(feeds)}, sort_keys=False)


def fetcher(text):
    return lambda url: text


def raiser(exc):
    def _f(url):
        raise exc
    return _f


def roster(db):
    """(name, url, enabled) tuples — the state a failure must never move."""
    return sorted((f.name, f.url, f.enabled) for f in db.get_feed_sources())


@pytest.fixture
def db(tmp_path):
    return Database(str(tmp_path / "catalog-test.db"))


# ------------------------------------------------------------------ config ----

def test_default_url_is_this_repo_over_tls():
    """The trust anchor: GitHub raw content, main, the pinned path, HTTPS."""
    assert catalog_sync.DEFAULT_CATALOG_URL.startswith("https://raw.githubusercontent.com/")
    assert catalog_sync.DEFAULT_CATALOG_URL.endswith("/main/feed_catalog.yaml")
    cfg = catalog_sync.catalog_config({})
    assert cfg["enabled"] is True and cfg["auto_add"] is True
    assert cfg["url"] == catalog_sync.DEFAULT_CATALOG_URL


def test_http_url_refused_before_any_network():
    from threatfeedme.catalog_sync import CatalogError
    with pytest.raises(CatalogError):
        catalog_sync.http_get_text("http://feeds.example.org/catalog.yaml")


def test_redirect_rule_stays_on_github_cdn():
    """No redirect-following onto non-githubusercontent hosts; same-host
    hops (self-hosted mirrors) stay allowed."""
    ok = catalog_sync._is_allowed_redirect
    assert ok(CATALOG_URL, "raw.githubusercontent.com")
    assert ok("https://mirror.example.org/c.yaml", "mirror.example.org")  # same host
    assert not ok(CATALOG_URL, "feeds.example.org")            # off-origin: refused
    assert not ok(CATALOG_URL, "evil.example.net")
    assert not ok(CATALOG_URL, "githubusercontent.com.evil.example")


# --------------------------------------------------------- happy path + (5) ----

def test_sync_adds_catalog_rows_with_provenance(db):
    res = catalog_sync.sync_catalog(db, CONFIG, fetch=fetcher(catalog_text(7, [ALPHA, BETA])))
    assert res["status"] == "synced" and res["catalog_version"] == 7
    assert sorted(res["added"]) == ["alpha_bl", "beta_list"]
    prov = db.get_feed_provenance()
    assert prov["alpha_bl"] == "sync-catalog"        # distinguishable in the table
    assert db.get_setting("catalog_version") == "7"
    assert db.get_setting("catalog_last_error") is None


def test_same_version_is_skipped_bump_applies(db):
    catalog_sync.sync_catalog(db, CONFIG, fetch=fetcher(catalog_text(7, [ALPHA])))
    res = catalog_sync.sync_catalog(db, CONFIG, fetch=fetcher(catalog_text(7, [ALPHA, BETA])))
    assert res["status"] == "skipped"                      # no re-apply per poll
    assert db.get_feed_source("beta_list") is None
    res = catalog_sync.sync_catalog(db, CONFIG, fetch=fetcher(catalog_text(8, [ALPHA, BETA])))
    assert res["status"] == "synced" and "beta_list" in res["added"]


def test_plumbing_follows_the_ship_on_catalog_rows(db):
    catalog_sync.sync_catalog(db, CONFIG, fetch=fetcher(catalog_text(1, [ALPHA])))
    moved = dict(ALPHA, url="https://feeds.example.org/alpha-v2.txt", update_interval=1800)
    res = catalog_sync.sync_catalog(db, CONFIG, fetch=fetcher(catalog_text(2, [moved])))
    assert "alpha_bl" in res["updated"]
    assert db.get_feed_source("alpha_bl").url == "https://feeds.example.org/alpha-v2.txt"


def test_disable_sticks_across_restart(db, tmp_path):
    """AC5: an operator disabling a catalog row keeps it disabled — through a
    restart (fresh Database on the same file) and a later catalog bump."""
    catalog_sync.sync_catalog(db, CONFIG, fetch=fetcher(catalog_text(1, [ALPHA])))
    db.set_feed_enabled("alpha_bl", False)
    restarted = Database(str(tmp_path / "catalog-test.db"))
    assert restarted.get_feed_source("alpha_bl").enabled is False
    catalog_sync.sync_catalog(restarted, CONFIG, fetch=fetcher(catalog_text(2, [ALPHA])))
    assert restarted.get_feed_source("alpha_bl").enabled is False   # preference sacred
    assert restarted.get_feed_provenance()["alpha_bl"] == "sync-catalog"


def test_keyed_entry_never_auto_enabled(db):
    """#8 pattern: requires_auth entries land disabled even with auto_add ON."""
    keyed = dict(ALPHA, name="urlhaus_keyed", requires_auth=True, auth_env="URLHAUS_AUTH_KEY")
    res = catalog_sync.sync_catalog(db, CONFIG, fetch=fetcher(catalog_text(3, [keyed])))
    assert "urlhaus_keyed" in res["added"]
    assert db.get_feed_source("urlhaus_keyed").enabled is False
    assert db.catalog_pending_names() == set()   # ships disabled, not review-queued


# ------------------------------------------------- never destructive (1, 4) ----

def test_offline_keeps_last_state_with_one_warning(db, caplog):
    """AC1 + GitHub-down: zero roster changes, one warning line, the last
    version retained, no exception escapes (the app stays healthy)."""
    catalog_sync.sync_catalog(db, CONFIG, fetch=fetcher(catalog_text(5, [ALPHA])))
    before, before_version = roster(db), db.get_setting("catalog_version")
    with caplog.at_level(logging.WARNING, logger="threatfeedme.catalog_sync"):
        res = catalog_sync.sync_catalog(db, CONFIG, fetch=raiser(RuntimeError("connection refused")))
    assert res["status"] == "error"
    assert roster(db) == before
    assert db.get_setting("catalog_version") == before_version      # last-good kept
    assert "connection refused" in db.get_setting("catalog_last_error")
    assert len(caplog.records) == 1 and caplog.records[0].levelno == logging.WARNING


@pytest.mark.parametrize("bad", [
    "this is not: [valid yaml",                 # malformed YAML
    "- just: a list",                            # not a mapping
    "feeds:\n  - name: a\n    url: https://x/y\n",        # no catalog_version
    "catalog_version: 9\n",                      # no feeds at all
    "catalog_version: 9\nfeeds: []\n",           # EMPTY roster: never a wipe
    "catalog_version: 9\nfeeds:\n  - name: a\n",  # entries missing url
    "catalog_version: 'nine'\nfeeds:\n  - {name: a, url: https://x/y}\n",  # non-int version
])
def test_malformed_and_empty_never_touch_state(db, bad):
    before = roster(db)
    res = catalog_sync.sync_catalog(db, CONFIG, fetch=fetcher(bad))
    assert res["status"] == "error"
    assert roster(db) == before
    assert db.get_setting("catalog_version") is None
    assert db.get_setting("catalog_last_error") is not None


def test_stale_version_changes_nothing(db, caplog):
    """AC4: a URL flipped to a lower-version (stale mirror) source is a
    no-op — the monotonic gate refuses replay of an old commit."""
    catalog_sync.sync_catalog(db, CONFIG, fetch=fetcher(catalog_text(41, [ALPHA])))
    before = roster(db)
    stale = catalog_text(40, [dict(BETA)])   # older version, different content
    with caplog.at_level(logging.WARNING, logger="threatfeedme.catalog_sync"):
        res = catalog_sync.sync_catalog(db, CONFIG, fetch=fetcher(stale))
    assert res["status"] == "stale"
    assert roster(db) == before
    assert db.get_feed_source("beta_list") is None
    assert db.get_setting("catalog_version") == "41"
    assert len(caplog.records) == 1


def test_corrupt_version_stamp_refuses_sync(db):
    """A hand-corrupted version stamp is not a licence to apply anything."""
    db.set_setting("catalog_version", "not-a-number")
    res = catalog_sync.sync_catalog(db, CONFIG, fetch=fetcher(catalog_text(3, [ALPHA])))
    assert res["status"] == "error" and db.get_feed_source("alpha_bl") is None


# ------------------------------------------------------------ tombstones (2) ----

def test_operator_deleted_catalog_feed_stays_deleted(db):
    """AC2: an operator delete (tombstone) is not resurrected by a bump."""
    catalog_sync.sync_catalog(db, CONFIG, fetch=fetcher(catalog_text(1, [ALPHA, BETA])))
    db.remove_feed("beta_list")                       # operator deletes it
    res = catalog_sync.sync_catalog(db, CONFIG,
                                    fetch=fetcher(catalog_text(2, [ALPHA, BETA])))
    assert "beta_list" in res["skipped_deleted"]
    assert db.get_feed_source("beta_list") is None


def test_dashboard_url_override_survives_plumbing_update(db):
    """AC3: a dashboard edit nulls the fingerprint; catalog plumbing updates
    must never clobber the operator's URL."""
    catalog_sync.sync_catalog(db, CONFIG, fetch=fetcher(catalog_text(1, [ALPHA])))
    db.add_feed(FeedSource(**dict(ALPHA, url="https://mirror.example.org/alpha.txt")))  # dashboard edit nulls fp
    assert db.get_feed_source("alpha_bl") is not None
    moved = dict(ALPHA, url="https://feeds.example.org/alpha-v2.txt")
    res = catalog_sync.sync_catalog(db, CONFIG, fetch=fetcher(catalog_text(2, [moved])))
    assert "alpha_bl" not in res["updated"]
    assert db.get_feed_source("alpha_bl").url == "https://mirror.example.org/alpha.txt"


# ------------------------------------------------------- review queue (6) ----

def test_auto_add_off_pending_add_and_dismiss(db):
    """AC6 end to end: OFF lands entries pending (not fetched, not scored),
    Add activates, Dismiss tombstones against future bumps."""
    db.set_setting(catalog_sync.CATALOG_AUTO_ADD_KEY, "0")   # toggle saved OFF
    res = catalog_sync.sync_catalog(db, CONFIG, fetch=fetcher(catalog_text(1, [ALPHA, BETA])))
    assert sorted(res["pending"]) == ["alpha_bl", "beta_list"] and not res["added"]
    assert db.catalog_pending_names() == {"alpha_bl", "beta_list"}
    for name in ("alpha_bl", "beta_list"):
        assert db.get_feed_source(name).enabled is False
    # Not fetched, not scored: the scheduler's due set and the enabled-only
    # roster the pipeline fetches both ignore disabled rows.
    assert "alpha_bl" not in pipeline.due_feeds(db, 3600)
    assert "alpha_bl" not in {f.name for f in db.get_feed_sources(enabled_only=True)}

    # Add activates one...
    assert db.catalog_add_pending("alpha_bl") is True
    assert db.get_feed_source("alpha_bl").enabled is True
    assert "alpha_bl" not in db.catalog_pending_names()
    # ...and a later bump must not re-queue or re-disable it.
    catalog_sync.sync_catalog(db, CONFIG, fetch=fetcher(catalog_text(2, [ALPHA, BETA])))
    assert db.get_feed_source("alpha_bl").enabled is True
    assert db.catalog_pending_names() == {"beta_list"}
    # A pending row a bump re-sees stays pending (sync never flips queues).
    assert db.get_feed_source("beta_list").enabled is False

    # Dismiss tombstones the other, surviving future bumps.
    assert db.catalog_dismiss_pending("beta_list") is True
    assert db.get_feed_source("beta_list") is None
    res = catalog_sync.sync_catalog(db, CONFIG, fetch=fetcher(catalog_text(3, [ALPHA, BETA])))
    assert "beta_list" in res["skipped_deleted"]
    assert db.get_feed_source("beta_list") is None


def test_add_keyless_only_keyed_pending_stays_disabled(db):
    """Add accepts a keyed entry but does not conjure its credential."""
    keyed = dict(ALPHA, name="keyed_bl", requires_auth=True, auth_env="KEYED_BL_KEY")
    db.set_setting(catalog_sync.CATALOG_AUTO_ADD_KEY, "0")
    catalog_sync.sync_catalog(db, CONFIG, fetch=fetcher(catalog_text(1, [keyed])))
    assert db.catalog_add_pending("keyed_bl") is True
    assert db.get_feed_source("keyed_bl").enabled is False   # no key, no live fetch


def test_toggle_persisted_wins_over_config_and_survives_restart(db, tmp_path):
    """The persisted settings toggle is the operator's answer; config.yaml
    is only the initial default (and default ON)."""
    assert catalog_sync.resolve_auto_add(db, CONFIG) is True          # default
    db.set_setting(catalog_sync.CATALOG_AUTO_ADD_KEY, "0")
    assert catalog_sync.resolve_auto_add(db, CONFIG) is False
    restarted = Database(str(tmp_path / "catalog-test.db"))
    assert catalog_sync.resolve_auto_add(restarted, CONFIG) is False  # across restarts
    off_config = {"catalog": dict(CONFIG["catalog"], auto_add=False)}
    fresh = Database(str(tmp_path / "other.db"))
    assert catalog_sync.resolve_auto_add(fresh, off_config) is False  # config default


# --------------------------------------------------------- settings surface ----

def test_settings_api_toggle_and_endpoints(db, monkeypatch):
    """The toggle is on the /api/settings surface, persists through its POST,
    and the Add/Dismiss endpoints drive the queue (404 off-queue)."""
    from fastapi import HTTPException
    from threatfeedme import core
    from threatfeedme.routers import system as sysmod
    # Never setattr on the core singletons: `db`/`config` normally live only
    # in __getattr__ (lazy), and restoring an old value read through it leaves
    # a shadowing real attribute (CLAUDE.md test-isolation trap). Patch the
    # dict directly so teardown deletes, not restores.
    monkeypatch.setitem(core.__dict__, "db", db)
    monkeypatch.setitem(core.__dict__, "config", CONFIG)

    payload = sysmod.get_settings(_=True)
    assert payload["catalog_auto_add"] is True
    assert payload["catalog"]["url"] == CATALOG_URL
    assert payload["catalog"]["version"] is None

    out = sysmod.update_catalog_auto_add(sysmod.CatalogAutoAddRequest(auto_add=False),
                                         _=True, _csrf=True)
    assert out["catalog_auto_add"] is False
    assert db.get_setting(catalog_sync.CATALOG_AUTO_ADD_KEY) == "0"
    assert sysmod.get_settings(_=True)["catalog_auto_add"] is False

    catalog_sync.sync_catalog(db, CONFIG, fetch=fetcher(catalog_text(1, [ALPHA])))  # OFF -> pending
    assert "alpha_bl" in db.catalog_pending_names()
    assert sysmod.catalog_pending_add("alpha_bl", _=True, _csrf=True) == {"success": True,
                                                                          "name": "alpha_bl"}
    with pytest.raises(HTTPException) as exc:
        sysmod.catalog_pending_add("alpha_bl", _=True, _csrf=True)   # no longer pending
    assert exc.value.status_code == 404
    catalog_sync.sync_catalog(db, CONFIG, fetch=fetcher(catalog_text(2, [ALPHA, BETA])))
    assert sysmod.catalog_pending_dismiss("beta_list", _=True, _csrf=True)["success"] is True
    with pytest.raises(HTTPException):
        sysmod.catalog_pending_dismiss("never_existed", _=True, _csrf=True)
    assert db.get_feed_source("beta_list") is None
    status = sysmod.get_settings(_=True)["catalog"]
    assert status["version"] == "2" and status["pending"] == []


# ------------------------------------------------------------ scheduler hook ----

class FakeDb:
    def __init__(self):
        self.settings = {}

    def get_setting(self, key, default=None):
        return self.settings.get(key, default)

    def set_setting(self, key, value):
        self.settings[key] = str(value)


def test_scheduler_polls_daily_not_every_tick(monkeypatch):
    fdb = FakeDb()
    calls = []
    monkeypatch.setattr(catalog_sync, "sync_catalog",
                        lambda db, config: (calls.append(1), {"status": "skipped"})[1])
    scheduler._maybe_catalog_poll(db=fdb, config=CONFIG)
    assert len(calls) == 1                                   # the startup poll
    scheduler._maybe_catalog_poll(db=fdb, config=CONFIG)     # next 60 s tick
    scheduler._maybe_catalog_poll(db=fdb, config=CONFIG)
    assert len(calls) == 1                                   # 24 h gate holds
    fdb.settings[scheduler.CATALOG_LAST_POLL_KEY] = (
        datetime.now(timezone.utc) - timedelta(hours=25)).isoformat()
    scheduler._maybe_catalog_poll(db=fdb, config=CONFIG)
    assert len(calls) == 2                                   # due again after a day


def test_scheduler_poll_off_when_disabled(monkeypatch):
    fdb = FakeDb()
    calls = []
    monkeypatch.setattr(catalog_sync, "sync_catalog",
                        lambda db, config: (calls.append(1), {"status": "skipped"})[1])
    scheduler._maybe_catalog_poll(db=fdb, config={"catalog": {"enabled": False}})
    assert calls == [] and scheduler.CATALOG_LAST_POLL_KEY not in fdb.settings


def test_scheduler_survives_a_raising_sync(monkeypatch):
    """The thread must never die: a raising sync_catalog is swallowed."""
    fdb = FakeDb()

    def boom(db, config):
        raise RuntimeError("disk on fire")
    monkeypatch.setattr(catalog_sync, "sync_catalog", boom)
    scheduler._maybe_catalog_poll(db=fdb, config=CONFIG)     # no raise


# ------------------------------------------------------------- fetch plumbing ----

class FakeResp:
    def __init__(self, status_code=200, body=b"catalog_version: 1\nfeeds: []\n", headers=None):
        self.status_code = status_code
        self._body = body
        self.headers = headers or {}
        self.encoding = "utf-8"
        self.closed = False

    def iter_content(self, chunk_size=65536, decode_unicode=False):
        yield self._body

    def close(self):
        self.closed = True


def test_fetch_discipline_no_proxies_no_redirects_capped(db, monkeypatch):
    """Reuse the feed path's discipline: no env proxies, redirects are NOT
    auto-followed (manual, same-CDN only), streamed reads go through the cap."""
    seen = {}

    def fake_get(url, **kwargs):
        seen.update(kwargs)
        return FakeResp()
    monkeypatch.setattr(catalog_sync.requests, "get", fake_get)
    monkeypatch.setattr(catalog_sync, "_require_public_url", lambda url: None)
    text = catalog_sync.http_get_text(CATALOG_URL)
    assert "catalog_version" in text
    assert seen["allow_redirects"] is False
    assert seen["stream"] is True
    assert set(seen["proxies"]) >= {"http", "https", "all"}     # _NO_PROXIES pattern
    assert all(v is None for v in seen["proxies"].values())


def test_fetch_rejects_non_200_and_oversized(monkeypatch):
    monkeypatch.setattr(catalog_sync, "_require_public_url", lambda url: None)
    monkeypatch.setattr(catalog_sync.requests, "get",
                        lambda url, **kw: FakeResp(status_code=404))
    with pytest.raises(catalog_sync.CatalogError):
        catalog_sync.http_get_text(CATALOG_URL)
    fat = FakeResp(body=b"x" * (catalog_sync._SOFT_MAX_CATALOG_BYTES + 1))
    monkeypatch.setattr(catalog_sync.requests, "get", lambda url, **kw: fat)
    with pytest.raises(catalog_sync.CatalogError):
        catalog_sync.http_get_text(CATALOG_URL)


def test_fetch_refers_offsite_redirect(monkeypatch):
    monkeypatch.setattr(catalog_sync, "_require_public_url", lambda url: None)
    monkeypatch.setattr(catalog_sync.requests, "get", lambda url, **kw: FakeResp(
        status_code=302, headers={"location": "https://evil.example.net/catalog.yaml"}))
    with pytest.raises(catalog_sync.CatalogError) as exc:
        catalog_sync.http_get_text(CATALOG_URL)
    assert "githubusercontent" in str(exc.value)
