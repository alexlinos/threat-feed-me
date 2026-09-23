"""End-to-end against a REAL CrowdSec Local API. Opt-in: skipped unless
TFM_CS_LAPI (e.g. http://127.0.0.1:18080) plus a test machine login and bouncer
key are provided. Never point it at production: it writes and expires
decisions under the threatfeedme/ scenario prefix, and adds one cscli-style
decision of its own through the machine login.

    docker run -d --name tfm-crowdsec -p 127.0.0.1:18080:8080 \\
      -e DISABLE_ONLINE_API=true -e CROWDSEC_BYPASS_DB_VOLUME_CHECK=true \\
      crowdsecurity/crowdsec:latest
    docker exec tfm-crowdsec cscli machines add tfm-test --password PW -f /dev/null
    docker exec tfm-crowdsec cscli bouncers add tfm-test -k KEY
    TFM_CS_LAPI=http://127.0.0.1:18080 TFM_CS_MACHINE=tfm-test \\
      TFM_CS_PASSWORD=PW TFM_CS_BOUNCER=KEY pytest tests/test_crowdsec_live.py
"""
import json
import os
from datetime import datetime, timezone

import pytest
import requests

from threatfeedme import crowdsec
from threatfeedme.database import Database
from threatfeedme.feed_ingestor import FeedIngestor
from threatfeedme.models import FeedSource, FeedType
from threatfeedme.scorer import ConfidenceScorer

LAPI = os.environ.get("TFM_CS_LAPI")
pytestmark = pytest.mark.skipif(not LAPI, reason="set TFM_CS_LAPI to run against a live CrowdSec")


@pytest.fixture
def env(monkeypatch, tmp_path):
    monkeypatch.setenv(crowdsec.ENV_MACHINE_ID, os.environ["TFM_CS_MACHINE"])
    monkeypatch.setenv(crowdsec.ENV_MACHINE_PASSWORD, os.environ["TFM_CS_PASSWORD"])
    monkeypatch.setenv(crowdsec.ENV_BOUNCER_KEY, os.environ["TFM_CS_BOUNCER"])
    db = Database(str(tmp_path / "cs.db"))
    db.set_setting(crowdsec.SETTINGS_KEY, json.dumps(
        {"enabled": True, "lapi_url": LAPI, "tier": "low", "duration_hours": 2}))
    yield db
    _expire_ours()


def _bouncer_view():
    r = requests.get(f"{LAPI}/v1/decisions",
                     headers={"X-Api-Key": os.environ["TFM_CS_BOUNCER"]}, timeout=30)
    return r.json() or []


def _ours():
    return {(d["value"], d["scenario"]) for d in _bouncer_view()
            if d["scenario"].startswith(crowdsec.SCENARIO_PREFIX)}


def _machine():
    p = crowdsec.CrowdSecPusher(LAPI)
    p.login()
    return p


def _expire_ours():
    p = _machine()
    for scenario in {s for _v, s in _ours()}:
        p.expire(scenario)


def _seed(db, values, source="feed_a"):
    db.add_indicators_bulk([(v.split("/")[0], {"cidr": v} if "/" in v else {})
                            for v in values], source=source)
    ConfidenceScorer(db, {}).recalculate_all_scores()


def test_push_publishes_replaces_and_never_gaps(env):
    db = env
    _seed(db, ["198.51.100.10", "198.51.100.11", "203.0.113.0/24"])
    s1 = crowdsec.push_to_crowdsec(db, {})
    gen1 = s1["scenario"]
    assert {v for v, s in _ours() if s == gen1} == {"198.51.100.10", "198.51.100.11",
                                                    "203.0.113.0/24"}
    # unchanged list, young generation: no churn at the LAPI at all
    assert crowdsec.push_to_crowdsec(db, {})["skipped"] == "unchanged"

    _seed(db, ["198.51.100.12"])
    s2 = crowdsec.push_to_crowdsec(db, {})
    assert s2["scenario"] != gen1 and s2["expired_previous"] == 3
    live = _ours()
    assert {s for _v, s in live} == {s2["scenario"]}          # old generation gone
    assert {v for v, _s in live} == {"198.51.100.10", "198.51.100.11",
                                     "203.0.113.0/24", "198.51.100.12"}


def test_whitelisted_values_are_not_published(env):
    db = env
    _seed(db, ["198.51.100.20", "198.51.100.21"])
    db.add_to_whitelist("198.51.100.21", "internal", "test")
    crowdsec.push_to_crowdsec(db, {}, force=True)
    assert {v for v, _s in _ours()} == {"198.51.100.20"}


def test_pull_ingests_crowdsec_decisions_but_never_our_own(env):
    db = env
    _seed(db, ["198.51.100.30"])
    crowdsec.push_to_crowdsec(db, {}, force=True)             # ours: must be skipped
    # a "local detection": a machine-posted decision under a crowdsec scenario
    p = _machine()
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    alert = p._alert("crowdsecurity/ssh-bf", ["192.0.2.77"], now)
    alert["decisions"][0]["origin"] = "cscli"
    alert["decisions"][0]["scenario"] = "crowdsecurity/ssh-bf"
    requests.post(f"{LAPI}/v1/alerts", headers=p._auth(), json=[alert],
                  timeout=30).raise_for_status()
    try:
        ing = FeedIngestor(db, crowdsec_lapi=LAPI)
        feed = FeedSource(name="crowdsec_local", feed_type=FeedType.THREAT_INTEL,
                          url="https://crowdsec-lapi/v1/decisions?origins=crowdsec,cscli",
                          scraper="crowdsec_lapi")
        values = {e["ip"] for e in ing.fetch_feed(feed)}
        assert "192.0.2.77" in values
        assert "198.51.100.30" not in values                  # no self-corroboration
    finally:
        requests.delete(f"{LAPI}/v1/decisions", headers=p._auth(),
                        params={"scenario": "crowdsecurity/ssh-bf"}, timeout=30)


def test_back_to_back_pushes_never_share_a_generation(env):
    db = env
    _seed(db, ["198.51.100.40"])
    a = crowdsec.push_to_crowdsec(db, {}, force=True)["scenario"]
    b = crowdsec.push_to_crowdsec(db, {}, force=True)["scenario"]
    assert a != b
    assert _ours() == {("198.51.100.40", b)}                  # exactly one live copy


def test_test_connection_and_bad_password(env, monkeypatch):
    assert crowdsec.CrowdSecPusher(LAPI).test_connection() == {"ok": True}
    with monkeypatch.context() as m:
        m.setenv(crowdsec.ENV_MACHINE_PASSWORD, "wrong")
        with pytest.raises(requests.HTTPError):
            crowdsec.CrowdSecPusher(LAPI).login()
