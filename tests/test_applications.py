"""Application lists (issue #26, 2.6 slice 1): the emission gate, the
change guard, storage/serving, and the dashboard API.

Offline per repo rule: fetches are injected fakes, never the network. The
gate tests assert the THREAT-side filter is not on this path by feeding it
exactly the shapes the known-good filter would strip (a vendor's own public
ranges) plus the shapes the poison scenario produces (0.0.0.0/0, a /4,
RFC1918).
"""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from threatfeedme import applications, auth, core, feed_ingestor
from threatfeedme.database import Database


# auth._ensure_auth_config() latches _AUTH_* once from os.environ and then
# never re-reads until something sets them back to None. This file drives the
# real app through httpx, so it would be the FIRST module to trigger that
# latch — before the dashboard fixtures own the auth lifecycle — and the
# latched credentials then 401 every later dashboard request
# (test_hardening_2_5_7 resets them the same way). Snapshot at import, restore
# after every test here: this file must be state-neutral for auth.
_AUTH_SNAPSHOT = (auth._AUTH_REQUIRED, auth._AUTH_USER, auth._AUTH_PASSWORD,
                  dict(auth._stored_cache))


@pytest.fixture(autouse=True)
def _keep_auth_state():
    yield
    req, user, pw, cache = _AUTH_SNAPSHOT
    auth._AUTH_REQUIRED, auth._AUTH_USER, auth._AUTH_PASSWORD = req, user, pw
    auth._stored_cache.clear()
    auth._stored_cache.update(cache)


# ---------------------------------------------------------------- fixtures --

class FakeResp:
    def __init__(self, body=b"", etag=None, status=200):
        self.content = body if isinstance(body, bytes) else body.encode()
        self.headers = {"ETag": etag} if etag else {}
        self.status_code = status
        self.closed = False

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def iter_content(self, chunk_size=1, decode_unicode=False):
        for i in range(0, len(self.content), chunk_size):
            yield self.content[i:i + chunk_size]

    def close(self):
        self.closed = True


def fake_get_factory(body=None, etag="v1", status=200):
    calls = []
    def get(url, headers=None, timeout=None, **kwargs):
        calls.append((url, headers))
        get.kwargs = kwargs
        get.guard_armed = getattr(feed_ingestor._ssrf_guard, "active", False)
        return FakeResp(body, etag=etag, status=status)
    get.calls = calls
    return get


@pytest.fixture
def db(tmp_path):
    d = Database(str(tmp_path / "t.db"))
    d.add_application_list("acme", "https://vendor.example/acme.txt",
                           "list", "", 3600, 8, 20, 50.0)
    return d


class FakeRequest:
    """Just the surface the serving path reads (repo pattern: direct router
    calls, no portal threads — TestClient hung this suite on exit here)."""
    def __init__(self, headers=None, query=None):
        self.headers = headers or {}
        self.query_params = query or {}


@pytest.fixture
def rtr(db, monkeypatch):
    # setitem on __dict__, never setattr: core.__getattr__ lazy-inits on a
    # getattr-probe and monkeypatch would then restore THAT db as the module
    # attribute, hijacking every later test's core.db (repo pattern:
    # test_never_block).
    monkeypatch.setitem(core.__dict__, "db", db)
    from threatfeedme.routers import applications as r
    # Seam, not core.config: reading core.config lazily initializes core
    # (CLAUDE.md test-isolation traps).
    monkeypatch.setitem(r.__dict__, "_allow_private", lambda: False)
    return r


# ------------------------------------------------------------- entry gate --

@pytest.mark.parametrize("entry", [
    "203.0.113.7", "198.51.100.0/24", "2001:db8:4000::/36",
    "login.example.net", "*.cdn.example.net", "https://teams.example.net/foo",
])
def test_gate_accepts_policy_shapes(entry):
    # A vendor's real ranges are public space (documentation ranges stand in,
    # repo fixture rule); the threat-side known-good filter would strip
    # nothing here, and this gate must accept all of it.
    ok, reason = applications.guard_entry(entry)
    assert ok, reason


@pytest.mark.parametrize("entry,why", [
    ("0.0.0.0/0", "floor"),          # the poison case
    ("10.0.0.0/4", "floor"),         # wider than the default v4 /8
    ("192.0.2.0/33", "not valid"),   # invalid prefix length
    ("127.0.0.1", "special-use"),
    ("10.1.2.3", "private"),
    ("169.254.1.1", "link-local"),
    ("224.0.0.5", "multicast"),
    ("2001:db8::/8", "v6 floor"),
    # Supernets straddling special-use space: is_private on a network needs
    # both ends private, so 2.7.0 accepted all four (overlap is the rule).
    ("172.0.0.0/8", "holds RFC1918 172.16/12"),
    ("192.0.0.0/8", "holds RFC1918 192.168/16"),
    ("100.0.0.0/8", "holds CGNAT 100.64/10"),
    ("2001::/20", "holds IETF 2001::/23"),
])
def test_gate_rejects_dangerous(entry, why):
    ok, _ = applications.guard_entry(entry)
    assert not ok, f"{entry} accepted ({why})"


def test_gate_rejects_control_chars_and_oversize():
    assert not applications.guard_entry("exa\u202emple.net")[0]   # bidi override
    assert not applications.guard_entry("a" * 600)[0]
    assert not applications.guard_entry("")[0]


def test_gate_honours_per_list_floors():
    # A public /8 that touches no special-use space (a real vendor block;
    # there is no documentation range this wide).
    ok, reason = applications.guard_entry("3.0.0.0/8")   # /8 == floor: allowed
    assert ok, reason
    ok, _ = applications.guard_entry("2.0.0.0/7", v4_floor=8)
    assert not ok


# ----------------------------------------------------------- source parse --

def test_extract_json_paths_expands_lists():
    data = {"prefixes": [{"ipv4Prefix": "198.51.100.0/24"},
                         {"ipv4Prefix": "203.0.113.0/24"}]}
    assert applications.extract_json_paths(data, "$.prefixes[*].ipv4Prefix") == \
        ["198.51.100.0/24", "203.0.113.0/24"]


def test_extract_json_paths_missing_key_raises():
    with pytest.raises(ValueError):
        applications.extract_json_paths({"a": 1}, "$.nope")


def test_parse_body_plain_skips_comments():
    body = "# comment\n198.51.100.1\n\n203.0.113.0/24\n"
    assert applications.parse_body(body, "list", "") == ["198.51.100.1", "203.0.113.0/24"]


def test_parse_body_json_without_filter_raises():
    with pytest.raises(ValueError):
        applications.parse_body("{}", "json", "")


# --------------------------------------------------------------- refresh --

def _seed(db, entries):
    db.replace_entries("acme", entries, len(entries), 0, entries[:5], [])


def test_refresh_seeds_then_updates_and_records_history(db):
    base = "\n".join(f"198.51.100.{i}" for i in range(10))
    get = fake_get_factory(base + "\n")
    s = applications.refresh_list(db, "acme", get=get)
    assert s["outcome"] == "ok" and s["count"] == 10

    swapped = base.replace("198.51.100.9", "203.0.113.9")
    get2 = fake_get_factory(swapped + "\n")
    s2 = applications.refresh_list(db, "acme", get=get2)
    assert s2["outcome"] == "ok" and s2["added"] == 1 and s2["removed"] == 1
    hist = db.get_history("acme")
    assert hist[0]["added"] == 1 and hist[0]["removed"] == 1
    assert hist[0]["added_sample"] == ["203.0.113.9"]


def test_refresh_poisoned_entry_is_rejected_not_served(db):
    _seed(db, ["198.51.100.1"])
    get = fake_get_factory("198.51.100.1\n0.0.0.0/0\n")
    s = applications.refresh_list(db, "acme", get=get)
    assert s["outcome"] == "ok" and s["rejected"] == 1
    assert db.get_entries("acme") == ["198.51.100.1"]   # poison never landed


def test_change_guard_holds_and_approval_serves(db):
    _seed(db, [f"198.51.100.{i}" for i in range(20)])
    # Vendor replaces most of the list at once: 60% moved, threshold 50%.
    get = fake_get_factory("\n".join(f"203.0.113.{i}" for i in range(12)) + "\n"
                           + "\n".join(f"198.51.100.{i}" for i in range(8)) + "\n")
    s = applications.refresh_list(db, "acme", get=get)
    assert s["outcome"] == "held"
    assert set(db.get_entries("acme")) == {f"198.51.100.{i}" for i in range(20)}  # old serves
    pending = db.get_pending("acme")
    assert pending and "moves" in pending["reason"]

    db.approve_pending("acme")
    assert db.get_pending("acme") is None
    assert len(db.get_entries("acme")) == 20
    assert db.get_history("acme")[0]["added"] == 12


def test_change_guard_reject_keeps_baseline(db):
    _seed(db, ["198.51.100.1", "198.51.100.2", "198.51.100.3"])
    get = fake_get_factory("203.0.113.9\n")
    s = applications.refresh_list(db, "acme", get=get)
    assert s["outcome"] == "held"
    db.reject_pending("acme")
    assert db.get_entries("acme") == ["198.51.100.1", "198.51.100.2", "198.51.100.3"]
    assert db.get_pending("acme") is None


def test_refresh_etag_304_is_not_modified(db):
    get = fake_get_factory(b"", etag="v9", status=304)
    s = applications.refresh_list(db, "acme", get=get)
    assert s["outcome"] == "not-modified"
    assert "If-None-Match" not in get.calls[0][1]        # no etag stored yet
    db.set_application_list_state("acme", "ok", etag="v9")
    applications.refresh_list(db, "acme", get=get)       # same fake sees the stored etag
    assert get.calls[-1][1]["If-None-Match"] == "v9"


def test_refresh_bug_propagates_not_swallowed(db):
    # Only vendor-shaped failures become per-list status; a programming bug
    # (RuntimeError) must raise so it is loud, not recorded as "error".
    def boom(url, headers=None, timeout=None, **kwargs):
        raise RuntimeError("bug")
    with pytest.raises(RuntimeError):
        applications.refresh_list(db, "acme", get=boom)


def test_refresh_network_error_records_status(db):
    import requests
    def boom(url, headers=None, timeout=None, **kwargs):
        raise requests.ConnectionError("down")
    s = applications.refresh_list(db, "acme", get=boom)
    assert s["outcome"] == "error" and "down" in s["error"]
    assert db.get_application_list("acme")["last_status"].startswith("error:")


# ------------------------------------------------------------ fetch safety --
# 2.7.0 shipped list fetches with no SSRF guard: the connect-time guard is
# thread-local and only FeedIngestor armed it, so a list URL could read
# cloud metadata or any LAN host and echo it back via rejected-entry notes.

def test_fetch_arms_ssrf_guard_and_drops_env_proxies(db):
    get = fake_get_factory("198.51.100.1\n")
    s = applications.refresh_list(db, "acme", get=get)
    assert s["outcome"] == "ok"
    assert get.guard_armed, "connect-time guard was not armed for the fetch"
    assert get.kwargs["proxies"] == feed_ingestor._NO_PROXIES
    assert get.kwargs["stream"] is True
    assert not getattr(feed_ingestor._ssrf_guard, "active", False)   # restored


def _no_socket(monkeypatch):
    """The real requests/urllib3 path down to the connect, with the connect
    itself stubbed: the guard must refuse before it, and if it doesn't the
    test fails loudly instead of touching the network."""
    def connect(address, *a, **kw):
        raise AssertionError(f"would have connected to {address}")
    monkeypatch.setattr(feed_ingestor, "_original_create_connection", connect)


def test_real_fetch_to_private_address_is_refused_at_connect(db, monkeypatch):
    # End to end through requests and urllib3 (no injected get): this is the
    # check that also covers every redirect hop.
    _no_socket(monkeypatch)
    monkeypatch.setattr(feed_ingestor, "_host_addresses", lambda h: ["169.254.169.254"])
    db.update_application_list("acme", {"source_url": "http://metadata.example/latest/"})
    s = applications.refresh_list(db, "acme")
    assert s["outcome"] == "error" and "non-public" in s["error"]
    assert not getattr(feed_ingestor._ssrf_guard, "active", False)


def test_real_fetch_reaches_connect_when_private_is_allowed(db, monkeypatch):
    # The control for the test above: with the guard off the same request
    # gets as far as the (stubbed) connect, so that test can't pass by luck.
    _no_socket(monkeypatch)
    monkeypatch.setattr(feed_ingestor, "_host_addresses", lambda h: ["10.0.0.5"])
    db.update_application_list("acme", {"source_url": "http://intranet.example/list"})
    with pytest.raises(AssertionError, match="would have connected"):
        applications.refresh_list(db, "acme", allow_private=True)


def test_refresh_allow_private_leaves_guard_off(db, monkeypatch):
    # safety.allow_private_feed_urls: true governs list URLs like feed URLs.
    monkeypatch.setattr(feed_ingestor, "_host_addresses", lambda h: ["10.0.0.5"])
    get = fake_get_factory("198.51.100.1\n")
    s = applications.refresh_list(db, "acme", get=get, allow_private=True)
    assert s["outcome"] == "ok" and not get.guard_armed
    assert get.kwargs["proxies"] is None


def test_refresh_size_cap_is_enforced_while_streaming(db, monkeypatch):
    monkeypatch.setattr(applications, "MAX_BODY_BYTES", 64)
    get = fake_get_factory("198.51.100.1\n" * 20)        # 260 bytes
    s = applications.refresh_list(db, "acme", get=get)
    assert s["outcome"] == "error" and "exceeded 64 bytes" in s["error"]
    assert db.get_entries("acme") == []


def test_scheduler_passes_the_ssrf_policy(db, monkeypatch):
    from threatfeedme import scheduler
    seen = []
    monkeypatch.setitem(core.__dict__, "db", db)
    monkeypatch.setattr(applications, "refresh_due",
                        lambda d, allow_private=False: seen.append(allow_private))
    for flag in (False, True):
        monkeypatch.setitem(core.__dict__, "config",
                            {"safety": {"allow_private_feed_urls": flag}})
        scheduler._refresh_application_lists()
    assert seen == [False, True]


def test_prune_keeps_recent_rows(db):
    _seed(db, ["198.51.100.1"])
    with db._cursor() as cur:
        cur.execute("UPDATE application_list_history SET refreshed_at = '2000-01-01T00:00:00'")
        cur.execute("INSERT INTO application_list_history (list_name, refreshed_at, added,"
                    " removed, count_after) VALUES ('acme','2000-01-01T00:00:00',0,0,1),"
                    " ('acme','2000-01-01T00:00:00',0,0,1)")
    removed = db.prune_application_history(30, 200)   # keep_rows protects the newest
    assert removed >= 0
    with db._cursor() as cur:
        cur.execute("SELECT COUNT(*) c FROM application_list_history")
        assert cur.fetchone()["c"] >= 1


def test_isolation_refresh_touches_no_intel(db):
    with db._cursor() as cur:
        cur.execute("INSERT INTO indicators (ip, first_seen, last_seen,"
                    " confidence_score, tier, metadata) VALUES ('203.0.113.5',"
                    " '2026-01-01','2026-01-01',1.0,'high','{}')")
        cur.execute("INSERT INTO whitelist (ip, feed_name, reason, added_by, added_at)"
                    " VALUES ('203.0.113.6','*','x','test','2026-01-01')")
        cur.execute("INSERT INTO feed_stats (feed_name, total_indicators, last_update, status)"
                    " VALUES ('f', 1, '2026-01-01', 'ok')")
    get = fake_get_factory("198.51.100.1\n")
    applications.refresh_list(db, "acme", get=get)
    with db._cursor() as cur:
        assert cur.execute("SELECT COUNT(*) c FROM indicators").fetchone()["c"] == 1
        assert cur.execute("SELECT COUNT(*) c FROM whitelist").fetchone()["c"] == 1
        assert cur.execute("SELECT COUNT(*) c FROM feed_stats").fetchone()["c"] == 1


# ---------------------------------------------------------------- serving --

def _serve_db(db):
    db.replace_entries("acme", ["198.51.100.1", "198.51.100.2"], 2, 0, [], [])


def test_serving_txt_etag_and_304(rtr, db):
    from fastapi import HTTPException
    _serve_db(db)
    r = rtr.list_txt("acme", FakeRequest(), limit=None)
    assert r.status_code == 200 and r.body == b"198.51.100.1\n198.51.100.2\n"
    r2 = rtr.list_txt("acme", FakeRequest({"if-none-match": r.headers["ETag"]}), limit=None)
    assert r2.status_code == 304
    with pytest.raises(HTTPException) as e:
        rtr.list_txt("nope", FakeRequest())
    assert e.value.status_code == 404


def test_serving_csv_json_and_limit(rtr, db):
    _serve_db(db)
    csv_r = rtr.list_csv("acme", FakeRequest(), limit=None)
    assert csv_r.body == b"198.51.100.1\r\n198.51.100.2\r\n" and csv_r.headers["ETag"]
    body = rtr.list_json("acme", FakeRequest(), limit=None).body
    assert json.loads(body)["entries"] == ["198.51.100.1", "198.51.100.2"]
    top = rtr.list_txt("acme", FakeRequest(), limit=1)
    assert top.body == b"198.51.100.1\n" and top.headers["X-Entry-Count"] == "2"


# ------------------------------------------------------------- URL options --

MIXED = ["198.51.100.0/24", "198.51.100.7", "203.0.113.9/32", "2001:db8::/48",
         "2001:db8::1", "a.example.net", "*.cdn.example.net", "*.a.example.net",
         "https://teams.example.net/foo"]


@pytest.mark.parametrize("opts,expected", [
    ({"kind": "ip"}, ["198.51.100.0/24", "198.51.100.7", "203.0.113.9/32",
                      "2001:db8::/48", "2001:db8::1"]),
    ({"kind": "domain"}, ["a.example.net", "*.cdn.example.net", "*.a.example.net"]),
    ({"kind": "url"}, ["https://teams.example.net/foo"]),
    ({"kind": "ip", "family": 4}, ["198.51.100.0/24", "198.51.100.7", "203.0.113.9/32"]),
    ({"kind": "ip", "family": 6}, ["2001:db8::/48", "2001:db8::1"]),
    # Sophos: v4 single addresses, bare (a /32 is served as its address).
    ({"kind": "ip", "family": 4, "hosts": True}, ["198.51.100.7", "203.0.113.9"]),
    ({"kind": "domain", "wildcards": "drop"}, ["a.example.net"]),
])
def test_select_entries_options(opts, expected):
    assert applications.select_entries(MIXED, **opts) == expected


def test_options_only_select_never_rewrite_vendor_entries():
    # Maintainer's rule: serve strictly what the vendor publishes. Every
    # option is a subset of the stored entries (hosts=1 only drops the /32
    # prefix length from the same address); no domain becomes an address and
    # no wildcard is widened or narrowed.
    combos = [{"kind": k, "family": f, "wildcards": w}
              for k in (None, "ip", "domain", "url") for f in (None, 4, 6)
              for w in ("keep", "drop")]
    for opts in combos:
        assert set(applications.select_entries(MIXED, **opts)) <= set(MIXED), opts
    assert "cdn.example.net" not in applications.select_entries(MIXED, kind="domain")


def test_select_entries_family_leaves_domains_alone():
    out = applications.select_entries(MIXED, family=4)
    assert "a.example.net" in out and "2001:db8::1" not in out


def test_list_url_options_reach_the_response(rtr, db):
    db.replace_entries("acme", MIXED, len(MIXED), 0, [], [])
    r = rtr.list_txt("acme", FakeRequest(), limit=None, kind="ip", family="4", hosts=1)
    assert r.body == b"198.51.100.7\n203.0.113.9\n"
    assert r.headers["X-Entry-Count"] == "2"
    other = rtr.list_txt("acme", FakeRequest(), limit=None, kind="domain")
    assert other.headers["ETag"] != r.headers["ETag"]     # each combination its own


def test_list_url_unknown_option_is_400(rtr, db):
    from fastapi import HTTPException
    _serve_db(db)
    with pytest.raises(HTTPException) as e:
        rtr.list_txt("acme", FakeRequest(query={"kinds": "ip"}), limit=None)
    assert e.value.status_code == 400 and "kinds" in e.value.detail


# -------------------------------------------------------------------- API --

def test_api_crud_validation(rtr, db):
    from fastapi import HTTPException
    from threatfeedme.schemas import ApplicationListRequest
    rows = rtr.list_applications(_=None)
    assert rows["applications"][0]["name"] == "acme"

    def post(**kw):
        return rtr.add_application(ApplicationListRequest(**kw), _=None, _csrf=None)
    post(name="bb", url="https://e/x")                      # 200 shape
    with pytest.raises(HTTPException) as e:
        post(name="bb", url="https://e/x")                  # duplicate
    assert e.value.status_code == 409
    with pytest.raises(HTTPException) as e:
        post(name="BAD NAME", url="https://e/x")
    assert e.value.status_code == 400
    with pytest.raises(HTTPException) as e:
        post(name="j", url="https://e/x", format="json")    # json needs filter
    assert e.value.status_code == 400
    assert rtr.delete_application("bb", _=None, _csrf=None)["success"]
    with pytest.raises(HTTPException) as e:
        rtr.delete_application("bb", _=None, _csrf=None)
    assert e.value.status_code == 404


def test_api_add_refuses_internal_url(rtr, db, monkeypatch):
    from fastapi import HTTPException
    from threatfeedme.schemas import ApplicationListRequest
    monkeypatch.setattr(feed_ingestor, "_host_addresses", lambda h: ["169.254.169.254"])
    with pytest.raises(HTTPException) as e:
        rtr.add_application(ApplicationListRequest(
            name="meta", url="http://metadata.example/latest/"), _=None, _csrf=None)
    assert e.value.status_code == 400 and "non-public" in e.value.detail
    assert db.get_application_list("meta") is None


def test_api_add_malformed_host_is_saved_not_500(rtr, db, monkeypatch):
    # Only an SSRF refusal is a 400; a host that can't be resolved or parsed
    # is stored and reports its error at fetch time, as on the feeds page.
    from threatfeedme.schemas import ApplicationListRequest

    def idna_fail(host):
        raise UnicodeError("encoding with 'idna' codec failed (label empty)")
    monkeypatch.setattr(feed_ingestor, "_host_addresses", idna_fail)
    rtr.add_application(ApplicationListRequest(name="dots", url="http://a..b/x"),
                        _=None, _csrf=None)
    rtr.add_application(ApplicationListRequest(name="v6", url="http://[::1/x"),
                        _=None, _csrf=None)   # urlsplit raises ValueError
    assert db.get_application_list("dots") and db.get_application_list("v6")


def test_csrf_enforced_over_http(db, monkeypatch):  # setitem, see rtr
    # The standing rule — mutations without X-Requested-With are rejected
    # even with auth off — proven through the real ASGI stack. httpx over
    # ASGITransport, not TestClient: no portal thread, no exit hang.
    import asyncio
    import httpx
    monkeypatch.setitem(core.__dict__, "db", db)
    from threatfeedme.app import app
    async def go():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
            bad = await c.post("/api/applications",
                               json={"name": "zz", "url": "https://e/x"})
            good = await c.post("/api/applications",
                                json={"name": "zz", "url": "https://e/x"},
                                headers={"X-Requested-With": "XMLHttpRequest"})
            txt = await c.get("/lists/acme.txt")
            return bad.status_code, good.status_code, txt.status_code
    bad, good, txt = asyncio.run(go())
    assert bad == 403 and good == 200
    assert txt == 200   # firewall-facing route, no auth


def test_api_detail_shows_pending_without_payload(rtr, db):
    db.add_pending("acme", ["198.51.100.9"], [{"e": "198.51.100.9"}], [], "moved")
    row = rtr.list_applications(_=None)["applications"][0]
    assert row["pending"] is True and "entries" not in row
    detail = rtr.get_application("acme", _=None)
    assert detail["pending"]["reason"] == "moved"
    assert "entries" not in detail["pending"]      # full blob stays server-side


def test_change_guard_pending_keeps_true_counts_above_sample_cap(db):
    # 600 entries move; the stored/displayed sample is capped at 500, but
    # the pending counts and the history written on approval must be 600.
    _seed(db, [f"198.51.{i // 250}.{i % 250}" for i in range(600)])
    body = "\n".join(f"203.0.{i // 250}.{i % 250}" for i in range(600)) + "\n"
    s = applications.refresh_list(db, "acme", get=fake_get_factory(body))
    assert s["outcome"] == "held" and s["added"] == 600 and s["removed"] == 600
    pending = db.get_pending("acme")
    assert pending["added"] == 600 and pending["removed"] == 600
    assert len(pending["added_sample"]) == applications.DIFF_SAMPLE_CAP
    db.approve_pending("acme")
    hist = db.get_history("acme")[0]
    assert hist["added"] == 600 and hist["removed"] == 600


# --------------------------------------------------------- refresh pacing --

def test_refresh_due_honours_update_interval(db, monkeypatch):
    # Regression: last_refresh_at is written by database._utcnow_iso
    # (offset form, e.g. 2026-11-06T13:45:52+00:00). refresh_due parsed it
    # with a "%Y-%m-%dT%H:%M:%SZ" format, the parse always failed, and
    # every enabled list polled on every scheduler tick.
    calls = []
    monkeypatch.setattr(
        applications, "refresh_list",
        lambda d, name, **kw: calls.append(name) or {"name": name, "outcome": "ok"})
    db.set_application_list_state("acme", "ok")   # refreshed just now
    assert applications.refresh_due(db) == [] and calls == []
    with db._cursor() as cur:                     # interval long past
        cur.execute("UPDATE application_lists SET last_refresh_at = ?"
                    " WHERE name = 'acme'", ("2020-01-01T00:00:00+00:00",))
    applications.refresh_due(db)
    assert calls == ["acme"]


def test_refresh_due_unparseable_stamp_is_due(db, monkeypatch):
    calls = []
    monkeypatch.setattr(
        applications, "refresh_list",
        lambda d, name, **kw: calls.append(name) or {"name": name, "outcome": "ok"})
    with db._cursor() as cur:
        cur.execute("UPDATE application_lists SET last_refresh_at = 'junk'"
                    " WHERE name = 'acme'")
    applications.refresh_due(db)
    assert calls == ["acme"]


def test_api_approve_reject_round_trip(rtr, db):
    from fastapi import HTTPException
    _serve_db(db)
    db.add_pending("acme", ["203.0.113.1"], [{"e": "203.0.113.1"}],
                   [{"e": "198.51.100.1"}], "moved")
    assert rtr.approve("acme", _=None, _csrf=None)["success"]
    assert rtr.list_txt("acme", FakeRequest(), limit=None).body == b"203.0.113.1\n"
    with pytest.raises(HTTPException) as e:
        rtr.approve("acme", _=None, _csrf=None)
    assert e.value.status_code == 404
