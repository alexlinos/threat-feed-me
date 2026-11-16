"""The UniFi domain check behind a DNS filter, and the opt-in public resolver.

The day 2.7.3 rolled, both installs that push to a gateway resolved names
through that gateway, whose own DNS filter answered about 95% of the listed
names with its block-page address (203.0.113.250, 2001:db8:1000::fa). The
address check read that as "private or reserved" and held back almost the
whole tier, 31 of 870 pushed on one install, while reporting them as names
on protected addresses. Pinned here:

  * a placeholder-only answer is its own verdict, still held back (the real
    addresses are unknown) but counted and reported apart;
  * the operator can point the check at a public resolver (a closed list,
    DNS over HTTPS, off by default), which sees the real addresses;
  * a resolver that does not answer leaves names unchecked, never "dead".

Offline: every lookup is a fake passed in or patched on the module.
"""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from threatfeedme import pusher_unifi as pu
from threatfeedme import resolved_guard as rg
from threatfeedme.database import Database
from threatfeedme.pusher_unifi import ENV_PASSWORD, ENV_USER, UniFiPusher
from threatfeedme.safety import SafetyFilter

from test_unifi import FakeSession

EDGE_V4 = "104.16.0.1"
PLAIN = "5.6.7.8"
BLOCK_PAGE_V4 = "203.0.113.250"
BLOCK_PAGE_V6 = "2001:db8:1000::fa"


def _lookups(table, calls=None):
    def lookup(name):
        if calls is not None:
            calls.append(name)
        return list(table.get(name, []))
    return lookup


def _judge(address):
    return SafetyFilter().address_reason(address)


def _answer(*addresses, status=0):
    return {"Status": status,
            "Answer": [{"name": "x.", "type": 28 if ":" in a else 1, "TTL": 60,
                        "data": a} for a in addresses]}


def _queries(table, calls=None):
    """A fake DNS-JSON endpoint: name -> addresses, NXDOMAIN when unknown."""
    def query(url, name, rtype, allow_private):
        if calls is not None:
            calls.append((url, name, rtype, allow_private))
        if name not in table:
            return {"Status": 3}
        want_v6 = rtype == "AAAA"
        return _answer(*[a for a in table[name] if (":" in a) == want_v6])
    return query


@pytest.fixture
def db(tmp_path):
    return Database(str(tmp_path / "t.db"))


def _domains(db, names, score=0.9):
    for i, name in enumerate(names):
        db.add_indicator(name, "f1", {}, kind="domain")
        db.set_indicator_score(name, score - i * 0.01, "high")


def _pusher(session=None, **kw):
    kw.setdefault("host", "192.168.1.1")
    kw.setdefault("tier", "high")
    kw.setdefault("group_prefix", "tfm")
    return UniFiPusher(session=session or FakeSession(), **kw)


def _configured_push(db, monkeypatch, session, **kw):
    monkeypatch.setenv(ENV_USER, "svc")
    monkeypatch.setenv(ENV_PASSWORD, "pw")
    monkeypatch.setattr(pu.UniFiPusher, "from_config",
                        classmethod(lambda cls, config, db=None: _pusher(session, **kw)))
    return pu.push_to_unifi(db, {"integrations": {"unifi": {
        "enabled": True, "host": "192.168.1.1"}}})


# ---------------- placeholder answers ----------------

@pytest.mark.parametrize("address", [
    "0.0.0.0", "127.0.0.1", "127.0.0.53", BLOCK_PAGE_V4, "192.0.2.1",
    "198.51.100.7", "::", "::1", BLOCK_PAGE_V6])
def test_filter_answers_are_recognised(address):
    assert rg.is_placeholder(address)


@pytest.mark.parametrize("address", [
    PLAIN, EDGE_V4, "192.168.1.1", "10.0.0.1", "2606:4700::1", "fe80::1",
    "not-an-address", ""])
def test_real_and_lan_addresses_are_not_placeholders(address):
    # A LAN address stays a "protected address" verdict: a listed domain
    # whose owner points it at the LAN is an attack, not a filter.
    assert not rg.is_placeholder(address)


def test_a_placeholder_only_answer_is_its_own_verdict():
    table = {"blocked-v4.example.io": [BLOCK_PAGE_V4],
             "blocked-both.example.io": [BLOCK_PAGE_V4, BLOCK_PAGE_V6],
             "nulled.example.io": ["0.0.0.0"],
             "on-cdn.example.io": [EDGE_V4],
             "half.example.io": [BLOCK_PAGE_V4, PLAIN],
             "own-host.example.io": [PLAIN]}
    names = list(table)
    verdicts = rg.screen(names, 10, _judge, lookup=_lookups(table))
    assert [v for v, _ in verdicts] == [
        rg.FILTERED, rg.FILTERED, rg.FILTERED, rg.PROTECTED,
        rg.PROTECTED,            # one real address beside a placeholder: not a filter's answer
        rg.OK]
    assert verdicts[0][1] == BLOCK_PAGE_V4


def test_a_filtered_name_does_not_take_a_slot_at_the_cap():
    table = {"blocked.example.io": [BLOCK_PAGE_V4], "host-1.example.io": [PLAIN],
             "host-2.example.io": ["5.6.7.9"]}
    verdicts = rg.screen(list(table), 2, _judge, lookup=_lookups(table))
    assert [v for v, _ in verdicts] == [rg.FILTERED, rg.OK, rg.OK]


def test_each_resolver_has_its_own_cache():
    # Switching from a filtering resolver to a public one must not reuse the
    # filter's placeholder for the two hours it stays cached.
    name = "listed.example.io"
    assert rg.screen([name], 1, _judge,
                     lookup=_lookups({name: [BLOCK_PAGE_V4]}))[0][0] == rg.FILTERED
    calls = []
    verdict = rg.screen([name], 1, _judge, source="cloudflare",
                        lookup=_lookups({name: [PLAIN]}, calls))[0][0]
    assert verdict == rg.OK and calls == [name]
    # And the first resolver's answer is still its own.
    assert rg.screen([name], 1, _judge, resolve=False)[0][0] == rg.FILTERED


# ---------------- reading a DNS-JSON answer ----------------

def test_answer_addresses_keeps_only_address_records():
    document = {"Status": 0, "Answer": [
        {"type": 5, "data": "edge.example.net."},            # CNAME: not an address
        {"type": 1, "data": " 5.6.7.8 "},
        {"type": 28, "data": "2606:4700::1"},
        {"type": 1, "data": "999.1.1.1"},                    # junk is dropped
        {"type": 1, "data": "<script>"},
        {"type": 1},                                          # no data
        "not a record",
        {"type": 16, "data": "5.6.7.9"}]}                    # TXT that looks like an address
    assert rg._answer_addresses(document) == ["5.6.7.8", "2606:4700::1"]


def test_answer_addresses_tolerates_a_missing_or_malformed_answer():
    assert rg._answer_addresses({"Status": 0}) == []
    assert rg._answer_addresses({"Status": 0, "Answer": "nope"}) == []
    assert rg._answer_addresses({"Status": 0, "Answer": None}) == []


@pytest.mark.parametrize("status", [2, 3, 5])
def test_nxdomain_servfail_and_refused_mean_not_resolving(status):
    # 5 (REFUSED) is a lame delegation passed through: live, one resolver
    # said 5 and the other SERVFAIL for the same two names. Left as a
    # failure it would be retried, and reported as a resolver fault, forever.
    assert rg._answer_addresses({"Status": status}) == []


@pytest.mark.parametrize("status", [1, 4, None, "0", 99])
def test_any_other_status_is_a_failed_lookup(status):
    with pytest.raises(rg.LookupFailed):
        rg._answer_addresses({"Status": status, "Answer": [{"type": 1, "data": PLAIN}]})


def test_answer_addresses_caps_the_records_it_reads():
    document = {"Status": 0, "Answer": [
        {"type": 1, "data": f"5.6.{i // 250}.{i % 250 + 1}"} for i in range(500)]}
    assert len(rg._answer_addresses(document)) == rg._DOH_MAX_RECORDS


# ---------------- PublicLookup ----------------

def test_public_lookup_asks_for_both_families_and_merges(monkeypatch):
    calls = []
    monkeypatch.setitem(rg.__dict__, "_query", _queries(
        {"dual.example.io": [PLAIN, "2606:4700::1"]}, calls))
    lookup = rg.PublicLookup("cloudflare")
    assert lookup("dual.example.io") == ["2606:4700::1", PLAIN]
    assert [(name, rtype) for _, name, rtype, _ in calls] == [
        ("dual.example.io", "A"), ("dual.example.io", "AAAA")]
    assert {url for url, *_ in calls} == {rg.PUBLIC_RESOLVERS["cloudflare"]}
    assert lookup("gone.example.io") == []               # NXDOMAIN: a dead name
    assert lookup.failed == 0 and not lookup.down


def test_public_lookup_passes_the_private_url_policy_through(monkeypatch):
    calls = []
    monkeypatch.setitem(rg.__dict__, "_query", _queries({}, calls))
    rg.PublicLookup("google", allow_private=True)("a.example.io")
    assert all(allow for *_, allow in calls)
    assert {url for url, *_ in calls} == {rg.PUBLIC_RESOLVERS["google"]}


def test_public_lookup_only_knows_the_shipped_resolvers():
    # A closed list: the operator picks a name, never an address.
    for bad in ("", "quad9", "https://resolver.example.net/dns-query", "CLOUDFLARE "):
        with pytest.raises(ValueError):
            rg.PublicLookup(bad)
    assert all(url.startswith("https://") for url in rg.PUBLIC_RESOLVERS.values())


def test_a_failed_query_raises_and_is_counted(monkeypatch):
    def broken(url, name, rtype, allow_private):
        raise OSError("connection reset")
    monkeypatch.setitem(rg.__dict__, "_query", broken)
    lookup = rg.PublicLookup("cloudflare")
    with pytest.raises(rg.LookupFailed) as failure:
        lookup("a.example.io")
    # The category, not the text: this can reach a log line.
    assert str(failure.value) == "OSError"
    assert lookup.failed == 1 and not lookup.down


def test_a_resolver_that_keeps_failing_is_given_up_on(monkeypatch):
    calls = []

    def broken(url, name, rtype, allow_private):
        calls.append(name)
        raise OSError("timed out")
    monkeypatch.setitem(rg.__dict__, "_query", broken)
    lookup = rg.PublicLookup("cloudflare")
    for i in range(rg._DOH_TRIP + 50):
        with pytest.raises(rg.LookupFailed):
            lookup(f"n{i}.example.io")
    assert lookup.down
    assert len(calls) == rg._DOH_TRIP        # nothing more is sent once it is down


def test_one_answer_ends_a_failure_streak(monkeypatch):
    state = {"fail": True}

    def flaky(url, name, rtype, allow_private):
        if state["fail"]:
            raise OSError("blip")
        return _answer(PLAIN) if rtype == "A" else _answer()
    monkeypatch.setitem(rg.__dict__, "_query", flaky)
    lookup = rg.PublicLookup("cloudflare")
    for i in range(rg._DOH_TRIP - 1):
        with pytest.raises(rg.LookupFailed):
            lookup(f"n{i}.example.io")
    state["fail"] = False
    assert lookup("ok.example.io") == [PLAIN]
    state["fail"] = True
    with pytest.raises(rg.LookupFailed):
        lookup("again.example.io")
    assert not lookup.down                    # the streak started over


# ---------------- the query itself ----------------

class _Response:
    def __init__(self, body=b"{}", status=200):
        self.status_code = status
        self._body = body
        self.closed = False

    def iter_content(self, chunk_size=65536, decode_unicode=False):
        for start in range(0, len(self._body), chunk_size):
            yield self._body[start:start + chunk_size]

    def close(self):
        self.closed = True


class _Session:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def get(self, url, **kwargs):
        from threatfeedme import feed_ingestor
        self.calls.append((url, kwargs,
                           getattr(feed_ingestor._ssrf_guard, "active", False)))
        return self.response


def _query_with(monkeypatch, response, **kw):
    session = _Session(response)
    monkeypatch.setitem(rg.__dict__, "_session", lambda: session)
    kw.setdefault("allow_private", False)
    result = rg.doh_query(rg.PUBLIC_RESOLVERS["cloudflare"], "a.example.io", "A", **kw)
    return result, session


def test_the_query_goes_out_under_the_feed_fetch_rules(monkeypatch):
    response = _Response(json.dumps(_answer(PLAIN)).encode())
    document, session = _query_with(monkeypatch, response)
    assert rg._answer_addresses(document) == [PLAIN]
    (url, kwargs, guard_armed), = session.calls
    assert url == rg.PUBLIC_RESOLVERS["cloudflare"]
    assert kwargs["params"] == {"name": "a.example.io", "type": "A"}
    assert guard_armed                                   # the SSRF guard is on
    assert kwargs["proxies"] == {"http": None, "https": None, "all": None}
    assert kwargs["stream"] is True
    assert kwargs["allow_redirects"] is False            # a resolver has no business redirecting
    assert kwargs["timeout"] == rg._DOH_TIMEOUT
    assert response.closed


def test_the_private_url_setting_releases_the_guard_as_for_feeds(monkeypatch):
    response = _Response(json.dumps(_answer(PLAIN)).encode())
    _, session = _query_with(monkeypatch, response, allow_private=True)
    (_, kwargs, guard_armed), = session.calls
    assert not guard_armed and kwargs["proxies"] is None


def test_a_non_200_answer_is_a_failed_lookup(monkeypatch):
    response = _Response(b"rate limited", status=429)
    with pytest.raises(rg.LookupFailed):
        _query_with(monkeypatch, response)
    assert response.closed


def test_an_oversized_answer_is_refused(monkeypatch):
    from threatfeedme.feed_ingestor import ResponseTooLargeError
    response = _Response(b"x" * (rg._DOH_MAX_BYTES + 1))
    with pytest.raises(ResponseTooLargeError):
        _query_with(monkeypatch, response)
    assert response.closed


@pytest.mark.parametrize("body", [b"[]", b'"text"', b"not json", b""])
def test_a_body_that_is_not_a_dns_document_is_a_failure(monkeypatch, body):
    with pytest.raises(Exception):
        _query_with(monkeypatch, _Response(body))


def test_the_suite_never_queries_a_public_resolver_for_real():
    # conftest points the seam at a fake for every test.
    assert rg.__dict__["_query"] is not rg.doh_query


# ---------------- the domain arm ----------------

def test_selection_counts_filtered_names_apart(db, monkeypatch):
    names = ["blocked-1.example.io", "on-cdn.example.io", "own-host.example.io",
             "blocked-2.example.io", "dead.example.io"]
    _domains(db, names)
    monkeypatch.setitem(pu.resolved_guard.__dict__, "_lookup", _lookups({
        "blocked-1.example.io": [BLOCK_PAGE_V4], "blocked-2.example.io": [BLOCK_PAGE_V6],
        "on-cdn.example.io": [EDGE_V4], "own-host.example.io": [PLAIN]}))
    sel = _pusher(domain_tier="high").select(db, "domain", "high")
    assert sel.values == ["own-host.example.io"]
    assert sel.filtered_count == 2
    assert sel.protected_count == 1 and sel.unresolved_count == 1
    # The reason sample is for addresses that must not be blocked; a filter's
    # placeholder is not one of them.
    assert [v for v, _ in sel.protected] == ["on-cdn.example.io"]
    assert sel.total == 1 and sel.check_error == ""


def test_a_public_resolver_sees_past_the_filter(db, monkeypatch):
    # The 2.7.3 roll in one test: this server's DNS answers every listed name
    # with the gateway's block page; the public resolver knows where they
    # really live.
    names = ["phish-own-host.example.io", "phish-on-cdn.example.io", "gone.example.io"]
    _domains(db, names)
    system_calls = []
    monkeypatch.setitem(pu.resolved_guard.__dict__, "_lookup", _lookups(
        {n: [BLOCK_PAGE_V4] for n in names}, system_calls))
    monkeypatch.setitem(pu.resolved_guard.__dict__, "_query", _queries({
        "phish-own-host.example.io": [PLAIN], "phish-on-cdn.example.io": [EDGE_V4]}))

    behind_filter = _pusher(domain_tier="high").select(db, "domain", "high")
    assert behind_filter.values == [] and behind_filter.filtered_count == 3

    system_calls.clear()
    public = _pusher(domain_tier="high", domain_check_resolver="cloudflare")
    sel = public.select(db, "domain", "high")
    assert sel.values == ["phish-own-host.example.io"]
    assert sel.protected_count == 1 and sel.unresolved_count == 1
    assert sel.filtered_count == 0 and sel.check_error == ""
    assert system_calls == []                 # the server's own DNS is not asked


def test_an_unknown_resolver_name_falls_back_to_this_server(db, monkeypatch):
    # The check must never go to a host nobody chose.
    queries = []
    monkeypatch.setitem(pu.resolved_guard.__dict__, "_query", _queries({}, queries))
    monkeypatch.setitem(pu.resolved_guard.__dict__, "_lookup",
                        _lookups({"own-host.example.io": [PLAIN]}))
    _domains(db, ["own-host.example.io"])
    for bad in ("https://resolver.example.net/dns-query", "quad9", 7):
        p = _pusher(domain_tier="high", domain_check_resolver=bad)
        assert p.check_resolver == ""
        assert p.select(db, "domain", "high").values == ["own-host.example.io"]
    assert queries == []
    assert _pusher(domain_check_resolver=" Google ").check_resolver == "google"


def test_from_block_reads_the_resolver_setting():
    p = UniFiPusher.from_block({"host": "192.168.1.1",
                                "domain_check_resolver": "cloudflare"})
    assert p.check_resolver == "cloudflare"
    assert UniFiPusher.from_block({"host": "192.168.1.1"}).check_resolver == ""


def test_from_config_carries_the_private_url_policy(db):
    config = {"integrations": {"unifi": {"enabled": True, "host": "192.168.1.1"}},
              "safety": {"allow_private_feed_urls": True}}
    assert UniFiPusher.from_config(config, db=db).allow_private_urls is True
    config["safety"] = {}
    assert UniFiPusher.from_config(config, db=db).allow_private_urls is False


def test_a_public_resolver_that_is_down_fails_closed(db, monkeypatch):
    # Nothing can be checked, so nothing is pushed, and the summary says why
    # in a fixed sentence (never the exception text).
    names = [f"n{i}.example.io" for i in range(rg._DOH_TRIP + 10)]
    _domains(db, names)

    def broken(url, name, rtype, allow_private):
        raise OSError("connect to 192.0.2.9 port 443 failed")
    monkeypatch.setitem(pu.resolved_guard.__dict__, "_query", broken)
    session = FakeSession()
    summary = _configured_push(db, monkeypatch, session, domain_tier="high",
                               domain_check_resolver="cloudflare")
    d = summary["domains"]
    assert d["entries"] == 0 and d["unchecked_withheld"] == len(names)
    assert d["check_error"] == "the public resolver did not answer"
    assert "192.0.2.9" not in json.dumps(summary)
    assert d["check_resolver"] == "cloudflare"
    # Not cached as dead: the next push, with the resolver back, checks them.
    monkeypatch.setitem(pu.resolved_guard.__dict__, "_query",
                        _queries({n: [PLAIN] for n in names}))
    again = _configured_push(db, monkeypatch, session, domain_tier="high",
                             domain_check_resolver="cloudflare")
    assert again["domains"]["entries"] == len(names)
    assert "check_error" not in again["domains"]


def test_a_few_failed_lookups_are_reported_without_calling_it_down(db, monkeypatch):
    _domains(db, ["flaky.example.io", "own-host.example.io"])

    def flaky(url, name, rtype, allow_private):
        if name.startswith("flaky"):
            raise OSError("reset")
        return _answer(PLAIN) if rtype == "A" else _answer()
    monkeypatch.setitem(pu.resolved_guard.__dict__, "_query", flaky)
    sel = _pusher(domain_tier="high", domain_check_resolver="google").select(
        db, "domain", "high")
    assert sel.values == ["own-host.example.io"] and sel.unchecked_count == 1
    assert sel.check_error == "the public resolver failed for some names"


def test_push_summary_reports_filtered_names(db, monkeypatch):
    _domains(db, ["blocked.example.io", "own-host.example.io"])
    monkeypatch.setitem(pu.resolved_guard.__dict__, "_lookup", _lookups({
        "blocked.example.io": [BLOCK_PAGE_V4], "own-host.example.io": [PLAIN]}))
    session = FakeSession()
    summary = _configured_push(db, monkeypatch, session, domain_tier="high")
    d = summary["domains"]
    assert d["entries"] == 1 and d["filtered_withheld"] == 1
    assert "address_withheld" not in d and "check_resolver" not in d
    lists = {g["name"]: g["group_members"] for g in session.groups.values()}
    assert lists["tfm-dom-high-1"] == ["own-host.example.io"]


def test_coverage_view_uses_the_chosen_resolvers_cache(db, monkeypatch):
    # The read-only view must report what the configured resolver found, not
    # what the other one has cached, and still start no lookups.
    _domains(db, ["listed.example.io"])
    monkeypatch.setitem(pu.resolved_guard.__dict__, "_lookup",
                        _lookups({"listed.example.io": [BLOCK_PAGE_V4]}))
    queries = []
    monkeypatch.setitem(pu.resolved_guard.__dict__, "_query",
                        _queries({"listed.example.io": [PLAIN]}, queries))
    _pusher(domain_tier="high").select(db, "domain", "high")
    public = _pusher(domain_tier="high", domain_check_resolver="cloudflare")
    cold = public.select(db, "domain", "high", resolve=False)
    assert cold.values == [] and cold.unchecked_count == 1 and queries == []
    public.select(db, "domain", "high")
    seen = len(queries)
    warm = public.select(db, "domain", "high", resolve=False)
    assert warm.values == ["listed.example.io"] and len(queries) == seen
