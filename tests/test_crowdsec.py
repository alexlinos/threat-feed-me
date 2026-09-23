"""CrowdSec integration (v2.5.0), hermetic: a fake LAPI records every call.
tests/test_crowdsec_live.py runs the same paths against a real CrowdSec."""
import json
from datetime import datetime, timedelta, timezone

import pytest

from threatfeedme import crowdsec, pipeline
from threatfeedme.database import Database
from threatfeedme.feed_ingestor import FeedIngestor, NOT_MODIFIED
from threatfeedme.models import FeedSource, FeedType
from threatfeedme.scorer import ConfidenceScorer

LAPI = "http://10.9.8.7:8080"


class _Resp:
    def __init__(self, status=200, body=None, redirect=False):
        self.status_code = status
        self._body = body
        self.is_redirect = redirect
        self.encoding = "utf-8"

    def json(self):
        return self._body

    def raise_for_status(self):
        if self.status_code >= 400:
            import requests
            raise requests.HTTPError(f"{self.status_code}")

    def iter_content(self, chunk_size=65536, decode_unicode=False):
        yield json.dumps(self._body).encode()

    def close(self):
        pass


class FakeLAPI:
    """Just enough LAPI: login, alerts (store decisions), delete by scenario,
    decisions read. fail_post_after makes the Nth alert POST fail."""

    def __init__(self, fail_post_after=None, redirect=False):
        self.decisions = []          # (value, scenario, origin)
        self.calls = []
        self.posts = 0
        self.fail_post_after = fail_post_after
        self.redirect = redirect

    def post(self, url, json=None, headers=None, **kw):
        self.calls.append(("POST", url, headers or {}))
        if self.redirect:
            return _Resp(302, redirect=True)
        if url.endswith("/v1/watchers/login"):
            return _Resp(200, {"token": "jwt"})
        if url.endswith("/v1/alerts"):
            self.posts += 1
            if self.fail_post_after is not None and self.posts > self.fail_post_after:
                return _Resp(500)
            for alert in json:
                for d in alert["decisions"]:
                    self.decisions.append((d["value"], d["scenario"], d["origin"]))
            return _Resp(201, ["1"])
        return _Resp(404)

    def delete(self, url, params=None, headers=None, **kw):
        self.calls.append(("DELETE", url, params))
        before = len(self.decisions)
        self.decisions = [d for d in self.decisions if d[1] != params["scenario"]]
        return _Resp(200, {"nbDeleted": str(before - len(self.decisions))})

    def get(self, url, headers=None, params=None, **kw):
        self.calls.append(("GET", url, headers or {}, params))
        return _Resp(200, [{"type": "ban", "scope": "Ip", "value": v, "scenario": s,
                            "origin": o} for v, s, o in self.decisions] or None)

    def live(self):
        return {(v, s) for v, s, _o in self.decisions}


@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setenv(crowdsec.ENV_MACHINE_ID, "tfm")
    monkeypatch.setenv(crowdsec.ENV_MACHINE_PASSWORD, "pw")
    d = Database(str(tmp_path / "cs.db"))
    d.set_setting(crowdsec.SETTINGS_KEY, json.dumps(
        {"enabled": True, "lapi_url": LAPI, "tier": "low", "duration_hours": 24}))
    d.add_indicators_bulk([("198.51.100.1", {}), ("198.51.100.2", {}),
                           ("203.0.113.0", {"cidr": "203.0.113.0/24"})], source="feed_a")
    ConfidenceScorer(d, {}).recalculate_all_scores()
    return d


def _push(db, lapi, **kw):
    return crowdsec.push_to_crowdsec(db, {}, session=lapi, **kw)


# ---- push ----------------------------------------------------------------------

def test_publishes_the_tier_with_ranges_as_range_scope(db):
    lapi = FakeLAPI()
    s = _push(db, lapi)
    assert {v for v, _s in lapi.live()} == {"198.51.100.1", "198.51.100.2", "203.0.113.0/24"}
    assert all(o == crowdsec.ORIGIN for _v, _s, o in lapi.decisions)
    assert s["scenario"].startswith("threatfeedme/low@")


def test_a_new_generation_lands_before_the_old_one_is_expired(db):
    lapi = FakeLAPI()
    first = _push(db, lapi)["scenario"]
    db.add_indicators_bulk([("198.51.100.3", {})], source="feed_a")
    ConfidenceScorer(db, {}).recalculate_all_scores()
    second = _push(db, lapi)["scenario"]
    ops = [c[0] for c in lapi.calls]
    # the new generation's alert POST precedes the DELETE of the old one
    assert ops.index("DELETE") > max(i for i, c in enumerate(lapi.calls)
                                     if c[0] == "POST" and c[1].endswith("/v1/alerts"))
    assert lapi.calls[-1][2] == {"scenario": first}
    assert {s for _v, s in lapi.live()} == {second}


def test_unchanged_and_young_is_a_noop_but_half_duration_republishes(db):
    lapi = FakeLAPI()
    _push(db, lapi)
    n = len(lapi.calls)
    assert _push(db, lapi)["skipped"] == "unchanged" and len(lapi.calls) == n
    # 13h later (duration 24h): must re-publish before the decisions expire
    last = json.loads(db.get_setting(crowdsec.LAST_PUSH_KEY))
    last["pushed_at"] = (datetime.now(timezone.utc) - timedelta(hours=13)).isoformat()
    db.set_setting(crowdsec.LAST_PUSH_KEY, json.dumps(last))
    assert "skipped" not in _push(db, lapi)


def test_a_failed_push_keeps_the_live_generation_and_drops_the_partial_one(db, monkeypatch):
    monkeypatch.setattr(crowdsec, "_CHUNK", 1)          # 3 alerts per generation
    lapi = FakeLAPI()
    live = _push(db, lapi)["scenario"]
    lapi.fail_post_after = lapi.posts + 1               # 2nd alert of the next push fails
    with pytest.raises(Exception):
        _push(db, lapi, force=True)
    assert {s for _v, s in lapi.live()} == {live}        # still enforced, never gapped
    assert len(lapi.live()) == 3
    rec = json.loads(db.get_setting(crowdsec.LAST_PUSH_KEY))
    assert rec["error"] and rec["live_scenario"] == live
    # recovery: the next push is forced by the error and expires `live`
    lapi.fail_post_after = None
    new = _push(db, lapi)["scenario"]
    assert {s for _v, s in lapi.live()} == {new}


def test_a_redirecting_lapi_gets_no_credentials_followed(db):
    lapi = FakeLAPI(redirect=True)
    with pytest.raises(RuntimeError, match="redirect"):
        _push(db, lapi, force=True)


def test_disabled_or_unconfigured_does_nothing(db):
    db.set_setting(crowdsec.SETTINGS_KEY, json.dumps({"enabled": False, "lapi_url": LAPI}))
    lapi = FakeLAPI()
    assert _push(db, lapi) is None and lapi.calls == []
    assert crowdsec.push_ready(db, {}) is False


def test_max_entries_keeps_the_strongest(db):
    db.set_setting(crowdsec.SETTINGS_KEY, json.dumps(
        {"enabled": True, "lapi_url": LAPI, "tier": "low", "max_entries": 2}))
    lapi = FakeLAPI()
    assert _push(db, lapi)["entries"] == 2


@pytest.mark.parametrize("url", ["http://10.0.0.1:8080/v1/alerts", "ftp://x", "http://a b",
                                 "http://user:pw@10.0.0.1", "http://10.0.0.1:99999",
                                 "http://10.0.0.1?x=1"])
def test_lapi_url_must_be_a_bare_origin(url):
    with pytest.raises(ValueError):
        crowdsec.normalize_lapi_url(url)


def test_lapi_url_accepts_origins():
    assert crowdsec.normalize_lapi_url("http://crowdsec:8080/") == "http://crowdsec:8080"
    assert crowdsec.normalize_lapi_url("https://[fd00::5]:8080") == "https://[fd00::5]:8080"


def test_the_refresh_skip_path_still_keeps_decisions_alive(db, monkeypatch):
    called = []
    monkeypatch.setattr(pipeline, "_push_crowdsec", lambda d, c: called.append(1))
    monkeypatch.setattr(pipeline, "scoring_input_key", lambda d, c: "same")
    db.set_setting(pipeline._RESCORE_KEY, "same")
    pipeline._after_fetch(db, {}, {}, {})
    assert called == [1]


# ---- pull ----------------------------------------------------------------------

def _pull(db, lapi, monkeypatch, url="https://crowdsec-lapi/v1/decisions?origins=CAPI",
          lapi_url=LAPI):
    monkeypatch.setenv(crowdsec.ENV_BOUNCER_KEY, "bkey")
    monkeypatch.setattr(crowdsec, "_session", lambda verify=True: lapi)
    ing = FeedIngestor(db, crowdsec_lapi=lapi_url)
    feed = FeedSource(name="crowdsec_community", feed_type=FeedType.THREAT_INTEL,
                      url=url, scraper="crowdsec_lapi")
    return ing.fetch_feed(feed)


def test_pull_reads_the_configured_lapi_and_never_our_own(db, monkeypatch):
    lapi = FakeLAPI()
    lapi.decisions = [("192.0.2.5", "crowdsecurity/ssh-bf", "CAPI"),
                      ("198.51.100.1", "threatfeedme/medium@x", "threatfeedme"),
                      ("198.51.100.9", "sneaky", "threatfeedme")]
    rows = _pull(db, lapi, monkeypatch)
    assert {r["ip"] for r in rows} == {"192.0.2.5"}
    method, url, headers, params = lapi.calls[-1]
    assert url == f"{LAPI}/v1/decisions" and headers["X-Api-Key"] == "bkey"
    assert params["origins"] == "CAPI" and params["scenarios_not_containing"] == "threatfeedme"


def test_the_feed_url_host_is_ignored_so_the_key_cannot_be_redirected(db, monkeypatch):
    lapi = FakeLAPI()
    lapi.decisions = [("192.0.2.5", "x", "CAPI")]
    _pull(db, lapi, monkeypatch, url="https://attacker.example/v1/decisions?origins=CAPI")
    assert all(c[1].startswith(LAPI) for c in lapi.calls)


def test_no_active_decisions_keeps_prior_indicators(db, monkeypatch):
    assert _pull(db, FakeLAPI(), monkeypatch) is NOT_MODIFIED


def test_pull_without_lapi_or_key_fails_clearly(db, monkeypatch):
    with pytest.raises(RuntimeError, match="LAPI URL"):
        _pull(db, FakeLAPI(), monkeypatch, lapi_url="")
    monkeypatch.delenv(crowdsec.ENV_BOUNCER_KEY, raising=False)
    ing = FeedIngestor(db, crowdsec_lapi=LAPI)
    feed = FeedSource(name="x", feed_type=FeedType.THREAT_INTEL,
                      url="https://crowdsec-lapi/v1/decisions", scraper="crowdsec_lapi")
    with pytest.raises(RuntimeError, match="bouncer key"):
        ing.fetch_feed(feed)


def test_a_hostile_origins_selector_is_refused(db, monkeypatch):
    with pytest.raises(RuntimeError, match="origins"):
        _pull(db, FakeLAPI(), monkeypatch,
              url="https://x/v1/decisions?origins=CAPI%26type%3Dcaptcha")


def test_decision_values_distrusts_shape():
    junk = [None, 1, "x", {"type": "captcha", "scope": "Ip", "value": "192.0.2.1"},
            {"type": "ban", "scope": "Country", "value": "RU"},
            {"type": "ban", "scope": "Range", "value": "192.0.2.0/24", "scenario": "s"}]
    assert crowdsec.decision_values(junk) == ["192.0.2.0/24"]
    assert crowdsec.decision_values(None) == [] and crowdsec.decision_values({}) == []


# ---- the shipped roster + key policy -------------------------------------------

def test_no_feed_can_borrow_the_crowdsec_credentials():
    from threatfeedme.core import load_config
    from threatfeedme.credentials import KeyPolicy
    policy = KeyPolicy.from_config(load_config("config.yaml"))
    for var in crowdsec.CREDENTIAL_VARS:
        assert policy.disallowed_reason(var)
    # the Console feed's Basic-auth pair is bound to CrowdSec's API host
    url = crowdsec.CONSOLE_CONTENT_URL.format(id="abc")
    assert policy.may_send("CROWDSEC_CONSOLE_USER", url)
    assert not policy.may_send("CROWDSEC_CONSOLE_USER", "https://evil.example/x")


def test_shipped_crowdsec_feeds_are_off_and_declare_their_scrapers():
    from threatfeedme.core import load_config
    feeds = {f["name"]: f for f in load_config("config.yaml")["feeds"]}
    for name, scraper in (("crowdsec_local", "crowdsec_lapi"),
                          ("crowdsec_community", "crowdsec_lapi"),
                          ("crowdsec_lists", "crowdsec_lapi"),
                          ("crowdsec_console", "crowdsec_console")):
        assert feeds[name]["enabled"] is False and feeds[name]["scraper"] == scraper
