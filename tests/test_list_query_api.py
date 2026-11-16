"""Tests for issue #39: the read-only application-list query API.

This covers the firewall-sync contract: stable list versions/checksums,
index enumeration, JSON list documents, option filtering, and cached list
summaries. These tests remain offline and use documentation-only values so
serving behaviour can be exercised without vendor traffic.
"""

import hashlib
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from fastapi import HTTPException

from threatfeedme import applications
from threatfeedme.database import Database


MIXED = ["198.51.100.0/24", "198.51.100.7", "2001:db8::/48",
         "a.example.net", "*.cdn.example.net", "https://teams.example.net/foo"]


class FakeRequest:
    def __init__(self, headers=None, query=None):
        self.headers = headers or {}
        self.query_params = query or {}


@pytest.fixture
def db(tmp_path):
    d = Database(str(tmp_path / "t.db"))
    d.add_application_list("acme", "https://vendor.example/acme.txt",
                           "list", "", 3600, 8, 20, 50.0)
    d.replace_entries("acme", sorted(MIXED), len(MIXED), 0, [], [])
    return d


@pytest.fixture
def rtr(db, monkeypatch):
    # setitem on __dict__, never setattr (core lazy-inits on a getattr probe).
    from threatfeedme.routers import applications as r
    monkeypatch.setitem(r.core.__dict__, "db", db)
    monkeypatch.setitem(r.__dict__, "_allow_private", lambda: False)
    return r


@pytest.fixture(autouse=True)
def _fresh_summary_cache():
    applications._summary_cache.clear()
    yield
    applications._summary_cache.clear()


class FakeResp:
    def __init__(self, body):
        self.content = body.encode()
        self.headers = {}
        self.status_code = 200

    def raise_for_status(self):
        pass

    def iter_content(self, chunk_size=1, decode_unicode=False):
        yield self.content

    def close(self):
        pass


def fake_get(body):
    def get(url, headers=None, timeout=None, **kwargs):
        return FakeResp(body)
    return get


def test_split_entries_by_firewall_object_kind():
    # Firewall object models do not mix address families or name objects.
    split = applications.split_entries(sorted(MIXED))

    assert split["ipv4"] == ["198.51.100.0/24", "198.51.100.7"]
    assert split["ipv6"] == ["2001:db8::/48"]
    assert split["domains"] == ["*.cdn.example.net", "a.example.net"]
    assert split["urls"] == ["https://teams.example.net/foo"]


def test_checksum_is_the_sha256_of_the_txt_body(rtr):
    # The query API's checksum must match the bytes /lists/<name>.txt serves,
    # so sync scripts can verify downloads against the index document.
    expected = hashlib.sha256(("\n".join(sorted(MIXED)) + "\n").encode()).hexdigest()

    assert applications.checksum(sorted(MIXED)) == expected
    assert applications.checksum([]) == hashlib.sha256(b"").hexdigest()
    txt = rtr.list_txt("acme", FakeRequest(), limit=None)
    assert hashlib.sha256(txt.body).hexdigest() == expected


def test_index_lists_enabled_lists_with_version_checksum_counts(rtr):
    # The index is the sync script's cheap "what changed?" document.
    resp = rtr.list_index(FakeRequest())
    body = json.loads(resp.body)

    assert resp.headers.get("X-Entry-Count") == "1"
    assert len(body["lists"]) == 1

    listed = body["lists"][0]
    assert listed["name"] == "acme"
    assert listed["entries"] == 6
    assert listed["counts"] == {
        "ipv4": 2,
        "ipv6": 1,
        "domains": 2,
        "urls": 1,
    }
    assert listed["url"] == "/lists/acme.json"
    assert listed["checksum"] == applications.checksum(sorted(MIXED))
    assert isinstance(listed["changed_at"], str)
    assert listed["changed_at"]


def test_index_leaves_out_switched_off_lists(rtr, db):
    # Catalog-disabled lists 404 at their URLs, so the index must not advertise them.
    db.update_application_list("acme", {"enabled": 0})

    body = json.loads(rtr.list_index(FakeRequest()).body)

    assert body["lists"] == []


def test_index_etag_304_and_no_options(rtr):
    # The index has a cache revalidator and deliberately takes no options:
    # a misspelt query should be loud, not silently ignored.
    resp = rtr.list_index(FakeRequest())
    etag = resp.headers["ETag"]

    revalidated = rtr.list_index(FakeRequest(headers={"if-none-match": etag}))
    assert revalidated.status_code == 304

    with pytest.raises(HTTPException) as excinfo:
        rtr.list_index(FakeRequest(query={"x": "1"}))
    assert excinfo.value.status_code == 400


def test_list_json_is_one_consistent_document(rtr):
    # A firewall sync needs one document whose version and per-kind arrays
    # come from the same stored revision.
    index_body = json.loads(rtr.list_index(FakeRequest()).body)
    indexed = index_body["lists"][0]

    resp = rtr.list_json("acme", FakeRequest(), limit=None)
    doc = json.loads(resp.body)

    assert doc["name"] == "acme"
    assert doc["version"] == indexed["version"]
    assert doc["checksum"] == indexed["checksum"]
    assert doc["changed_at"] == indexed["changed_at"]
    assert doc["entries"] == sorted(MIXED)
    assert doc["ipv4"] == ["198.51.100.0/24", "198.51.100.7"]
    assert doc["ipv6"] == ["2001:db8::/48"]
    assert doc["domains"] == ["*.cdn.example.net", "a.example.net"]
    assert doc["urls"] == ["https://teams.example.net/foo"]


def test_list_json_options_filter_entries_not_the_checksum(rtr):
    # URL options shape the served subset only; checksum remains the whole
    # stored list so consumers can detect a refresh while importing one kind.
    resp = rtr.list_json("acme", FakeRequest(), limit=None, kind="ip", family="4")
    doc = json.loads(resp.body)

    assert doc["entries"] == ["198.51.100.0/24", "198.51.100.7"]
    assert doc["ipv4"] == ["198.51.100.0/24", "198.51.100.7"]
    assert doc["ipv6"] == []
    assert doc["domains"] == []
    assert doc["urls"] == []
    assert doc["checksum"] == applications.checksum(sorted(MIXED))


def test_version_moves_only_when_content_does(rtr, db):
    # Content equality must not bump the version or write churn history;
    # vendors without ETags must not make idle polls look like updates.
    row = db.get_application_list("acme")
    before_version = row["entry_version"]
    before_history = len(db.get_history("acme"))
    before_checksum = applications.checksum(sorted(MIXED))

    same = applications.refresh_list(
        db, "acme", get=fake_get("\n".join(MIXED) + "\n")
    )
    assert same["outcome"] == "ok"
    assert db.get_application_list("acme")["entry_version"] == before_version
    assert len(db.get_history("acme")) == before_history

    extra_body = "\n".join(MIXED + ["203.0.113.9"]) + "\n"
    updated = applications.refresh_list(db, "acme", get=fake_get(extra_body))
    assert updated["outcome"] == "ok"

    row = db.get_application_list("acme")
    assert row["entry_version"] == before_version + 1

    index_body = json.loads(rtr.list_index(FakeRequest()).body)
    listed = next(item for item in index_body["lists"] if item["name"] == "acme")
    assert listed["checksum"] != before_checksum


def test_summary_is_cached_per_version(db, monkeypatch):
    # Index requests would otherwise re-read and re-hash every list; cache
    # correctness depends on invalidating when entry_version moves.
    real_get_entries = db.get_entries
    reads = []

    def counting_get_entries(name):
        reads.append(name)
        return real_get_entries(name)

    monkeypatch.setattr(db, "get_entries", counting_get_entries)
    row = db.get_application_list("acme")
    first = applications.list_summary(db, row)
    assert applications.list_summary(db, row) == first
    assert reads == ["acme"]                    # second call served from the cache

    db.replace_entries("acme", sorted(MIXED + ["203.0.113.9"]), 1, 0, ["203.0.113.9"], [])
    changed = applications.list_summary(db, db.get_application_list("acme"))
    assert reads == ["acme", "acme"]            # a new version is read again
    assert changed["checksum"] != first["checksum"] and changed["entries"] == 7


def test_index_is_a_reserved_list_name():
    # /lists/index.json is the enumeration document, so no list may shadow it.
    assert applications.valid_name("index") is False
    assert applications.valid_name("index-2") is True
