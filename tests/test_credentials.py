"""Credential policy (v2.4.19): a feed can't name someone else's secret, a
shipped key only goes to its own feed's host, keys never follow a redirect off
their origin, and the data-volume .env can't set process knobs."""
import json
import os

import pytest

from threatfeedme.credentials import KeyPolicy, env_file_may_set, same_origin
from threatfeedme.database import Database
from threatfeedme.feed_ingestor import FeedIngestor
from threatfeedme.models import FeedSource, FeedType

ROSTER = [
    {"name": "alienVault_otx", "auth_env": "OTX_API_KEY",
     "url": "https://otx.alienvault.com/api/v1/pulses/subscribed/?limit=50"},
    {"name": "honeydb_bad_hosts", "auth_env": "HONEYDB_API_ID,HONEYDB_API_KEY",
     "url": "https://honeydb.io/api/bad-hosts"},
    {"name": "spamhaus_drop", "url": "https://www.spamhaus.org/drop/drop.txt"},
]
POLICY = KeyPolicy(ROSTER)


# ---------------------------------------------------------------- policy ----

@pytest.mark.parametrize("var", ["OTX_API_KEY", "HONEYDB_API_KEY", "TFM_FEED_MY_TOKEN"])
def test_allowed_key_names(var):
    assert POLICY.allowed_var(var)


@pytest.mark.parametrize("var", [
    "UNIFI_PASSWORD", "UNIFI_USER",          # the gateway admin login
    "DASHBOARD_PASSWORD",                    # the dashboard's own credential
    "HTTPS_PROXY", "PATH", "PYTHONPATH",     # process knobs
    "tfm_feed_lower", "TFM_FEED_",           # prefix must be exact + non-empty
])
def test_refused_key_names(var):
    assert not POLICY.allowed_var(var)
    assert "TFM_FEED_" in POLICY.disallowed_reason(var)   # tells them the way out


def test_shipped_key_is_bound_to_its_feed_host():
    assert POLICY.may_send("OTX_API_KEY", "https://otx.alienvault.com/api/v1/x")
    assert not POLICY.may_send("OTX_API_KEY", "https://attacker.example/steal")
    # an operator's own key may go wherever their own feed lives
    assert POLICY.may_send("TFM_FEED_MY_TOKEN", "https://intel.corp.example/list")
    assert not POLICY.may_send("UNIFI_PASSWORD", "https://otx.alienvault.com/")


@pytest.mark.parametrize("name,ok", [
    ("OTX_API_KEY", True), ("UNIFI_PASSWORD", True), ("TFM_FEED_X", True),
    ("HTTPS_PROXY", False), ("https_proxy", False), ("NO_PROXY", False),
    ("ALL_PROXY", False), ("SSL_CERT_FILE", False), ("REQUESTS_CA_BUNDLE", False),
    ("CURL_CA_BUNDLE", False), ("PYTHONPATH", False), ("LD_PRELOAD", False),
    ("DASHBOARD_PASSWORD", False), ("PATH", False),
])
def test_env_file_may_set(name, ok):
    assert env_file_may_set(name) is ok


def test_load_env_file_ignores_process_knobs(tmp_path, monkeypatch):
    # a .env poisoned before the fix must not reroute traffic on next boot
    from threatfeedme.core import load_env_file
    for var in ("HTTPS_PROXY", "DASHBOARD_PASSWORD", "TFM_FEED_OK"):
        monkeypatch.delenv(var, raising=False)
    env = tmp_path / ".env"
    env.write_text("HTTPS_PROXY=http://attacker:3128\n"
                   "DASHBOARD_PASSWORD=attacker-chosen\n"
                   "TFM_FEED_OK=keep-me\n")
    load_env_file(str(env))
    assert "HTTPS_PROXY" not in os.environ
    assert "DASHBOARD_PASSWORD" not in os.environ
    assert os.environ["TFM_FEED_OK"] == "keep-me"


@pytest.mark.parametrize("a,b,same", [
    ("https://feeds.example/a", "https://feeds.example/b?x=1", True),
    ("https://feeds.example/a", "https://cdn.example/a", False),
    ("https://feeds.example/a", "http://feeds.example/a", False),     # downgrade
    ("https://feeds.example/a", "https://feeds.example:8443/a", False),
    ("https://Feeds.Example/a", "https://feeds.example/a", True),
])
def test_same_origin(a, b, same):
    assert same_origin(a, b) is same


# ---------------------------------------------------------- fetch paths ----

class _Resp:
    def __init__(self, status=200, headers=None, text=""):
        self.status_code, self.headers, self.text = status, headers or {}, text
        self.encoding = "utf-8"

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def close(self):
        pass

    def iter_content(self, chunk_size=65536, decode_unicode=False):
        if self.text:
            yield self.text.encode("utf-8")


def _stub(monkeypatch, responses):
    calls, seq = [], iter(responses)

    def fake_get(url, headers=None, **kw):
        calls.append({"url": url, "headers": dict(headers or {})})
        return next(seq)

    monkeypatch.setattr("threatfeedme.feed_ingestor.requests.get", fake_get)
    return calls


def _ingestor(db):
    # allow_private_urls skips the SSRF DNS lookup for these synthetic hosts;
    # the SSRF guard has its own tests
    return FeedIngestor(db, allow_private_urls=True, key_policy=POLICY)


def test_repointed_shipped_feed_does_not_carry_its_key(tmp_path, monkeypatch):
    monkeypatch.setenv("OTX_API_KEY", "real-otx-secret")
    calls = _stub(monkeypatch, [])
    feed = FeedSource(name="alienVault_otx", url="https://attacker.example/x",
                      feed_type=FeedType.THREAT_INTEL, requires_auth=True,
                      auth_env="OTX_API_KEY", auth_header="X-OTX-API-KEY")
    with pytest.raises(RuntimeError, match="refusing to send OTX_API_KEY"):
        _ingestor(Database(str(tmp_path / "t.db"))).ingest_feed(feed)
    assert calls == []   # refused before any request left the box


def _keyed_custom_feed(url="https://feeds.example/a.txt"):
    return FeedSource(name="corp_feed", url=url, feed_type=FeedType.CUSTOM,
                      requires_auth=True, auth_env="TFM_FEED_CORP",
                      auth_header="Authorization")


@pytest.mark.parametrize("location,keeps_key", [
    ("https://feeds.example/moved.txt", True),     # same origin: fine
    ("https://cdn.other.example/b.txt", False),    # other host
    ("http://feeds.example/moved.txt", False),     # https -> http downgrade
])
def test_key_never_follows_a_redirect_off_origin(tmp_path, monkeypatch, location, keeps_key):
    monkeypatch.setenv("TFM_FEED_CORP", "Bearer corp-secret")
    calls = _stub(monkeypatch, [_Resp(302, {"Location": location}),
                                _Resp(200, {}, "185.1.1.1\n")])
    assert _ingestor(Database(str(tmp_path / "t.db"))).ingest_feed(_keyed_custom_feed()) == 1
    assert calls[0]["headers"]["Authorization"] == "Bearer corp-secret"
    assert ("Authorization" in calls[1]["headers"]) is keeps_key


def test_otx_pagination_off_origin_is_refused(tmp_path, monkeypatch):
    monkeypatch.setenv("OTX_API_KEY", "real-otx-secret")
    page1 = json.dumps({"results": [{"indicators": [
        {"type": "IPv4", "indicator": "185.1.1.1"}]}],
        "next": "https://evil.example/page2"})
    calls = _stub(monkeypatch, [_Resp(200, {}, page1)])
    feed = FeedSource(name="alienVault_otx", url=ROSTER[0]["url"],
                      feed_type=FeedType.THREAT_INTEL, requires_auth=True,
                      auth_env="OTX_API_KEY", auth_header="X-OTX-API-KEY",
                      scraper="otx_pulses")
    with pytest.raises(RuntimeError, match="off-origin"):
        _ingestor(Database(str(tmp_path / "t.db"))).ingest_feed(feed)
    assert len(calls) == 1   # the key never went to evil.example
