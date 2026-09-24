"""CrowdSec dashboard API (v2.5.0): settings, write-only credentials bound to
the LAPI, read-only Test, and Push now. (Named to sort after the other
module-reloading suites: this one reloads threatfeedme like test_unifi does.)"""
import json
import os
import sys

import pytest

VARS = ("CROWDSEC_MACHINE_ID", "CROWDSEC_MACHINE_PASSWORD", "CROWDSEC_BOUNCER_KEY")


@pytest.fixture(scope="module")
def api(tmp_path_factory):
    work = tmp_path_factory.mktemp("crowdsec_api")
    db_path = str(work / "t.db").replace("\\", "/")
    cfg_path = work / "config.yaml"
    cfg_path.write_text("database:\n"
                        f"  path: {db_path}\n"
                        "feeds: []\n"
                        "dashboard: {auth_required: false}\n")
    old = os.environ.get("CONFIG_PATH")
    os.environ["CONFIG_PATH"] = str(cfg_path)
    for m in list(sys.modules):
        if m == "threatfeedme" or m.startswith("threatfeedme."):
            sys.modules.pop(m, None)
    from threatfeedme import core
    core.reset()
    core.init(str(cfg_path))
    from starlette.testclient import TestClient
    from threatfeedme import dashboard
    yield TestClient(dashboard.app, headers={"X-Requested-With": "XMLHttpRequest"})
    for v in VARS:
        os.environ.pop(v, None)
    if old is None:
        os.environ.pop("CONFIG_PATH", None)
    else:
        os.environ["CONFIG_PATH"] = old


def _creds(api, **kw):
    return api.post("/api/integrations/crowdsec/credentials", json=kw)


def test_defaults_are_off_and_recommend_medium(api):
    j = api.get("/api/integrations/crowdsec").json()
    assert j["enabled"] is False and j["tier"] == "medium" and j["lapi_url"] == ""
    assert j["machine_configured"] is False and j["bouncer_configured"] is False


def test_settings_validate_and_merge(api):
    assert api.post("/api/integrations/crowdsec",
                    json={"lapi_url": "http://10.1.1.5:8080/v1/alerts"}).status_code == 400
    assert api.post("/api/integrations/crowdsec", json={"tier": "all"}).status_code == 400
    assert api.post("/api/integrations/crowdsec", json={"duration_hours": 1}).status_code == 400
    assert api.post("/api/integrations/crowdsec",
                    json={"console_integration_id": "../x"}).status_code == 400
    r = api.post("/api/integrations/crowdsec",
                 json={"lapi_url": "http://10.1.1.5:8080/", "tier": "high"})
    assert r.status_code == 200 and r.json()["lapi_url"] == "http://10.1.1.5:8080"
    api.post("/api/integrations/crowdsec", json={"duration_hours": 12})
    j = api.get("/api/integrations/crowdsec").json()
    assert j["tier"] == "high" and j["duration_hours"] == 12


def test_credentials_are_write_only(api):
    from threatfeedme import core
    r = _creds(api, machine_id="tfm", machine_password="s3cr3t-pw", bouncer_key="bk-777")
    assert r.json() == {"success": True, "machine_configured": True, "bouncer_configured": True}
    with open(core.env_file(), encoding="utf-8") as f:
        assert "CROWDSEC_MACHINE_PASSWORD=s3cr3t-pw" in f.read()
    for path in ("/api/integrations/crowdsec", "/"):
        body = api.get(path).text
        assert "s3cr3t-pw" not in body and "bk-777" not in body
    # None leaves a value alone; "" clears it
    _creds(api, bouncer_key="")
    j = api.get("/api/integrations/crowdsec").json()
    assert j["machine_configured"] is True and j["bouncer_configured"] is False
    assert _creds(api, machine_password="a\nb").status_code == 400


def test_moving_the_lapi_clears_its_credentials(api):
    api.post("/api/integrations/crowdsec", json={"lapi_url": "http://10.1.1.5:8080"})
    _creds(api, machine_id="tfm", machine_password="pw", bouncer_key="bk")
    r = api.post("/api/integrations/crowdsec", json={"lapi_url": "http://attacker.example:8080"})
    assert r.json()["credentials_cleared"] is True
    assert not any(os.environ.get(v) for v in VARS)
    # same host again (scheme/slash differences) does not clear
    _creds(api, machine_id="tfm", machine_password="pw")
    r = api.post("/api/integrations/crowdsec", json={"lapi_url": "http://attacker.example:8080/"})
    assert r.json()["credentials_cleared"] is False


def test_test_endpoint_reports_each_direction(api, monkeypatch):
    from threatfeedme import crowdsec as cs
    api.post("/api/integrations/crowdsec", json={"lapi_url": "http://10.1.1.5:8080"})
    _creds(api, machine_id="tfm", machine_password="pw", bouncer_key="")
    monkeypatch.setattr(cs.CrowdSecPusher, "test_connection", lambda self: {"ok": True})
    j = api.post("/api/integrations/crowdsec/test").json()
    assert j["ok"] is True and "machine login OK" in j["message"] and "pull" not in j["checks"]

    def boom(self):
        raise RuntimeError("401 Unauthorized")
    monkeypatch.setattr(cs.CrowdSecPusher, "test_connection", boom)
    j = api.post("/api/integrations/crowdsec/test").json()
    assert j["ok"] is False and "401" in j["message"]


def test_push_now_requires_enabled(api):
    api.post("/api/integrations/crowdsec", json={"enabled": False})
    assert api.post("/api/integrations/crowdsec/push").status_code == 400


def test_mutations_need_the_csrf_header(api):
    from starlette.testclient import TestClient
    from threatfeedme import dashboard
    bare = TestClient(dashboard.app)
    for path in ("/api/integrations/crowdsec", "/api/integrations/crowdsec/credentials",
                 "/api/integrations/crowdsec/test", "/api/integrations/crowdsec/push"):
        assert bare.post(path, json={}).status_code == 403, path
