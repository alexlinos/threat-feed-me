"""Lean feed serving (v2.5.0): byte-identical to the old renderer, never
stale, limit-able, and built once under concurrency."""
import csv
import io
import json
import threading

import pytest
from fastapi.encoders import jsonable_encoder
from starlette.responses import JSONResponse

from threatfeedme import feed_cache
from threatfeedme.database import Database
from threatfeedme.exporter import firewall_value, is_included
from threatfeedme.scorer import ConfidenceScorer


@pytest.fixture
def db(tmp_path):
    feed_cache.invalidate()
    d = Database(str(tmp_path / "t.db"))
    d.add_indicators_bulk([("45.66.230.0", {"cidr": "45.66.230.0/24"}),
                           ("185.1.1.1", {}), ("185.1.1.2", {})], source="spamhaus_drop")
    d.add_indicators_bulk([("185.1.1.1", {}), ("185.9.9.9", {})], source="blocklist_de")
    # deliberate ties: identical evidence -> identical scores, inserted out of
    # value order, so the tie-break is actually exercised
    d.add_indicators_bulk([("185.5.5.9", {}), ("185.5.5.1", {}), ("185.5.5.5", {})],
                          source="greensnow")
    d.add_indicators_bulk([("evil-login.top", {}), ("phish.example.net", {})],
                          source="phishing_army", kind="domain")
    ConfidenceScorer(d, {}).recalculate_all_scores()
    yield d
    feed_cache.invalidate()


# ---- the OLD renderer, reproduced verbatim, as the parity oracle -------------

def _old_indicators(db, name, kind):
    """The old path's entries, in the order the lean path now DEFINES: score
    descending, ties by value. The old SQL left tie order unspecified (it
    simply came out of SQLite's sort); a deterministic tie-break is what keeps
    ?limit=N stable between polls, so parity is asserted under that order."""
    tiers, scope = feed_cache._FEEDS[name]
    wl = db.get_whitelist_map()
    inds = [i for i in db.get_indicators_by_kind_and_tiers(kind, tiers)
            if is_included(i, wl, tier=scope)]
    return sorted(inds, key=lambda i: (-i.confidence_score, i.ip))


def _old_txt(db, name, kind):
    return "".join(f"{firewall_value(i)}\n" for i in _old_indicators(db, name, kind)).encode()


def _old_csv(db, name, kind):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["ip", "confidence_score", "tier", "first_seen", "last_seen", "sources"])
    for i in _old_indicators(db, name, kind):
        w.writerow([firewall_value(i), i.confidence_score, i.tier.value,
                    i.first_seen, i.last_seen, ";".join(i.sources)])
    return buf.getvalue().encode()


def _old_json(db, name, kind):
    inds = _old_indicators(db, name, kind)
    # the old route returned a dict; FastAPI ran jsonable_encoder (datetime ->
    # isoformat) before JSONResponse rendered it — reproduce that exactly
    return json.loads(JSONResponse(jsonable_encoder({
        "feed": name if kind == "ip" else f"domains/{name}",
        "generated_at": "x", "total_count": len(inds),
        "indicators": [{"value": firewall_value(i), "ip": i.ip,
                        "confidence_score": i.confidence_score, "tier": i.tier.value,
                        "sources": i.sources, "last_seen": i.last_seen} for i in inds],
    })).body)


@pytest.mark.parametrize("kind", ["ip", "domain"])
@pytest.mark.parametrize("name", ["high", "medium", "low", "all"])
def test_output_is_identical_to_the_old_renderer(db, name, kind):
    assert feed_cache.txt(db, name, kind)[0] == _old_txt(db, name, kind)
    assert b"".join(feed_cache.stream_csv(db, name, kind)) == _old_csv(db, name, kind)
    new = json.loads(b"".join(feed_cache.stream_json(db, name, kind)))
    old = _old_json(db, name, kind)
    new["generated_at"] = old["generated_at"] = "x"
    assert new == old


def test_same_entries_as_the_old_path_and_ties_are_ordered_by_value(db):
    old = [firewall_value(i) for i in db.get_indicators_by_kind_and_tiers(
        "ip", feed_cache._FEEDS["all"][0])]
    new = feed_cache.txt(db, "all", "ip")[0].decode().splitlines()
    assert sorted(new) == sorted(old)            # nothing added or lost
    # force a genuine tie (recency makes near-identical rows differ by a hair)
    with db._cursor() as cur:
        cur.execute("UPDATE indicators SET confidence_score = 0.5 "
                    "WHERE ip LIKE '185.5.5.%'")
    feed_cache.mark_scores_changed(db)
    new = feed_cache.txt(db, "all", "ip")[0].decode().splitlines()
    ties = [v for v in new if v.startswith("185.5.5.")]
    assert ties == ["185.5.5.1", "185.5.5.5", "185.5.5.9"]   # value order, stable


def test_the_cidr_is_served_not_the_network_address(db):
    body = feed_cache.txt(db, "all", "ip")[0].decode()
    assert "45.66.230.0/24\n" in body and "\n45.66.230.0\n" not in body


# ---- never stale -------------------------------------------------------------

def test_a_whitelist_change_is_visible_on_the_next_poll(db):
    assert b"185.9.9.9\n" in feed_cache.txt(db, "all", "ip")[0]
    db.add_to_whitelist("185.9.9.9", "internal", "test")
    assert b"185.9.9.9\n" not in feed_cache.txt(db, "all", "ip")[0]
    db.remove_from_whitelist("185.9.9.9")
    assert b"185.9.9.9\n" in feed_cache.txt(db, "all", "ip")[0]


def test_a_new_indicator_is_visible_on_the_next_poll(db):
    feed_cache.txt(db, "all", "ip")
    db.add_indicators_bulk([("185.7.7.7", {})], source="blocklist_de")
    assert b"185.7.7.7\n" in feed_cache.txt(db, "all", "ip")[0]


def test_a_rescore_invalidates_even_with_identical_row_counts(db):
    # tiers change IN PLACE on a rescore; only the stamp can reveal that
    body1, tag1 = feed_cache.txt(db, "high", "ip")
    with db._cursor() as cur:                 # simulate a rescore's in-place writes
        cur.execute("UPDATE indicators SET tier = 'high' WHERE kind = 'ip'")
    feed_cache.mark_scores_changed(db)
    body2, tag2 = feed_cache.txt(db, "high", "ip")
    assert tag2 != tag1 and body2.count(b"\n") == 7


# ---- limit / etag / single-flight -------------------------------------------

def test_limit_serves_the_top_n_by_score(db):
    full = feed_cache.txt(db, "all", "ip")[0].splitlines()
    top2, tag = feed_cache.txt(db, "all", "ip", limit=2)
    assert top2.splitlines() == full[:2]
    assert tag.endswith('-top2"')
    csv_rows = b"".join(feed_cache.stream_csv(db, "all", "ip", limit=2)).splitlines()
    assert len(csv_rows) == 3                 # header + 2
    doc = json.loads(b"".join(feed_cache.stream_json(db, "all", "ip", limit=2)))
    assert doc["total_count"] == 2 and len(doc["indicators"]) == 2


def test_etag_is_stable_until_the_data_changes(db):
    tag1 = feed_cache.txt(db, "all", "ip")[1]
    assert feed_cache.txt(db, "all", "ip")[1] == tag1
    db.add_indicators_bulk([("185.8.8.8", {})], source="blocklist_de")
    assert feed_cache.txt(db, "all", "ip")[1] != tag1


def test_concurrent_polls_build_once(db, monkeypatch):
    builds = []
    real = feed_cache._build_txt
    gate = threading.Event()

    def slow_build(*a):
        builds.append(1)
        gate.wait(2)
        return real(*a)

    monkeypatch.setattr(feed_cache, "_build_txt", slow_build)
    threads = [threading.Thread(target=feed_cache.txt, args=(db, "all", "ip"))
               for _ in range(6)]
    for t in threads:
        t.start()
    gate.set()
    for t in threads:
        t.join()
    assert len(builds) == 1


def test_an_in_place_tier_change_moves_the_serve_fingerprint(tmp_path):
    """Manual re-add / whitelist edits rescore ONE existing row in place: no
    row count or rowid change, so without the stamp the cached list (and its
    ETag) kept serving the pre-edit tier."""
    from threatfeedme.database import Database
    db = Database(str(tmp_path / "t.db"))
    db.add_indicator("198.51.100.7", "feed_a", {})
    before = db.serve_fingerprint()
    db.set_indicator_score("198.51.100.7", 0.9, "high")
    assert db.serve_fingerprint() != before


def test_fortigates_default_user_agent_is_labelled_fortigate():
    # FortiOS external connectors send curl/7.58.0 unless set otherwise
    from threatfeedme import polls
    assert polls.agent_label("curl/7.58.0") == "FortiGate"
    assert polls.agent_label("curl/8.5.0") == "curl"
