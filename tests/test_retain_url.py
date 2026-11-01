"""Issue #17: URL-shaped feeds keep the submitted URL in indicator metadata.

A feed published as a corpus of URLs used to be reduced to its hostname at
ingest and the rest thrown away, so a payload parked on a shared platform and
malware served from a domain the attacker owns were byte-identical rows. These
tests pin the three things that make the retention safe and useful: it is
scoped to lines that actually were URLs, it is length-capped, and it is one
config switch off.

Offline by construction: the content is a string handed to the parser, and the
hostnames are synthetic (a random-shaped r2.dev bucket, an
.example-forge.tld host) — nothing here reaches a network or names a real
operator, host or machine.
"""
import csv
import io
import json

import pytest

from threatfeedme import feed_cache
from threatfeedme.database import Database
from threatfeedme.feed_ingestor import (FeedIngestor, _MAX_STORED_URL,
                                        parse_domain_feed_content)
from threatfeedme.pipeline import resolve_retain_submitted_url
from threatfeedme.scorer import DEFAULT_SHARED_PLATFORMS, shared_platform_for

# A release-asset URL on a shared platform: the shape from the issue. The host
# is a synthetic Cloudflare R2 bucket — random by construction, and matched by
# shared_platform_for through the shipped DEFAULT_SHARED_PLATFORMS entry
# "r2.dev", so the test asserts the tag a real deployment would write.
SHARED_HOST = "pub-1f3c9be74d524a08b6e1c0d7a2f58e34.r2.dev"
RELEASE_PATH = "/acme/widgets/releases/download/v1.0/setup-x64.zip"
RELEASE_URL = f"https://{SHARED_HOST}{RELEASE_PATH}"


@pytest.fixture
def db(tmp_path):
    feed_cache.invalidate()
    d = Database(str(tmp_path / "retain.db"))
    yield d
    feed_cache.invalidate()


def _ingest(db, content, retain=True, source="synthetic_urls"):
    """The real ingest path for a domain feed — parse, build row metadata,
    bulk-store — without a network fetch or an app import."""
    ing = FeedIngestor(db, retain_submitted_url=retain)
    entries = parse_domain_feed_content(content)
    rows = [(e['ip'], ing.row_metadata(e, e['ip'], 'domain')) for e in entries]
    db.add_indicators_bulk(rows, source=source, kind='domain')
    return {r[0]: r[1] for r in rows}


def _meta(db, value):
    with db._cursor() as cur:
        cur.execute("SELECT metadata FROM indicators WHERE ip = ?", (value,))
        row = cur.fetchone()
    return json.loads(row[0]) if row and row[0] else {}


# ---- A: the shared-platform case the issue is about -------------------------

def test_release_asset_url_keeps_both_the_platform_tag_and_the_path(db):
    """The row must carry the tag AND the retained path: the tag says "this
    host is shared", the path says which payload was parked on it."""
    assert shared_platform_for(SHARED_HOST) in DEFAULT_SHARED_PLATFORMS   # fixture is honest

    meta = _ingest(db, RELEASE_URL)[SHARED_HOST]
    assert meta['shared_platform'] == 'r2.dev'
    assert meta['url'] == RELEASE_URL
    # What actually landed in the database, not just what the parser returned.
    stored = _meta(db, SHARED_HOST)
    assert stored['shared_platform'] == 'r2.dev'
    assert stored['url'].endswith('/setup-x64.zip')


def test_first_submission_wins_when_two_urls_share_a_host(db):
    """Dedupe collapses URLs onto one host; the row remembers the URL that
    made it, and a second submission for the same host adds no new evidence."""
    rows = _ingest(db, RELEASE_URL + "\n" + f"https://{SHARED_HOST}/other/second.exe")
    assert rows[SHARED_HOST]['url'] == RELEASE_URL


def test_deduped_host_still_gets_a_url_when_only_the_second_is_a_url(db):
    """A host that appears plain first and as a URL later still gets the URL:
    the plain line carries no path, so it has nothing to claim the slot."""
    rows = _ingest(db, f"{SHARED_HOST}\n" + RELEASE_URL)
    assert rows[SHARED_HOST]['url'] == RELEASE_URL


# ---- B: the switch off ------------------------------------------------------

def test_flag_off_stores_no_url_but_keeps_the_platform_tag(db):
    """Off means the metadata is exactly what it was before issue #17: the
    shared-platform tag (settled in PR #16) is not this feature's to remove."""
    meta = _ingest(db, RELEASE_URL, retain=False)[SHARED_HOST]
    assert meta['shared_platform'] == 'r2.dev'
    assert 'url' not in meta
    assert _meta(db, SHARED_HOST) == {'shared_platform': 'r2.dev'}


def test_flag_defaults_to_on(db):
    """An ingestor built without the argument keeps the URL: the default is
    the useful behaviour, and an operator has to opt out of it."""
    assert FeedIngestor(db).retain_submitted_url is True
    assert _ingest(db, RELEASE_URL)[SHARED_HOST]['url'] == RELEASE_URL


@pytest.mark.parametrize("cfg, expected", [
    ({}, True),                                     # absent -> on
    (None, True),
    ({"feeds_settings": {}}, True),
    ({"feeds_settings": {"retain_submitted_url": False}}, False),
    ({"feeds_settings": {"retain_submitted_url": True}}, True),
    ({"feeds_settings": {"retain_submitted_url": 0}}, False),
    # the documented dotted name, for an operator who wrote it that way
    ({"feeds.retain_submitted_url": False}, False),
    # a dict-shaped feeds block is tolerated (the roster is normally a list)
    ({"feeds": {"retain_submitted_url": False}}, False),
    ({"feeds": [{"name": "a"}, {"name": "b"}]}, True),
])
def test_config_reader_default_on(cfg, expected):
    assert resolve_retain_submitted_url(cfg) is expected


# ---- C: the cap -------------------------------------------------------------

def test_long_url_is_stored_truncated_to_the_cap(db):
    """A hostile feed cannot inflate every row with a megabyte of path; the
    leading segments — host, org, repo — survive, only the tail is lost."""
    long_url = f"https://{SHARED_HOST}/" + "a" * 900
    meta = _ingest(db, long_url)[SHARED_HOST]
    assert meta['url'] == long_url[:_MAX_STORED_URL]
    assert len(meta['url']) == _MAX_STORED_URL
    assert len(_meta(db, SHARED_HOST)['url']) == _MAX_STORED_URL


def test_cap_is_the_parser_bound_not_a_convention():
    """One constant, applied where the string is captured."""
    entries = parse_domain_feed_content("https://x.example-forge.tld/" + "b" * 900)
    assert len(entries[0]['url']) == _MAX_STORED_URL


# ---- D: what stays untouched ------------------------------------------------

def test_plain_domain_per_line_stores_no_url(db):
    """The scope of the feature: a line that was not a URL has no submission
    path to remember, so its metadata stays {} as it is today."""
    rows = _ingest(db, "tracker.example-forge.tld\n# a comment\n")
    assert rows['tracker.example-forge.tld'] == {}


def test_hosts_file_lines_store_no_url(db):
    """Same for the sinkhole-address format: several hostnames per line, no
    URL on any of them."""
    rows = _ingest(db, "0.0.0.0 ads.example-forge.tld track.example-forge.tld")
    assert rows['ads.example-forge.tld'] == {}
    assert rows['track.example-forge.tld'] == {}


def test_ip_rows_never_carry_a_url(db):
    """The guard is on kind, not on the entry: an IP feed that somehow handed
    over a url key would still not store one."""
    ing = FeedIngestor(db)
    assert ing.row_metadata({'ip': '203.0.113.7', 'url': RELEASE_URL},
                            '203.0.113.7', 'ip') == {}


def test_url_carrying_row_keeps_the_cidr_key_too(db):
    """The new key must not crowd out the one key scoring reads."""
    ing = FeedIngestor(db)
    meta = ing.row_metadata({'ip': SHARED_HOST, 'cidr': SHARED_HOST,
                             'url': RELEASE_URL}, SHARED_HOST, 'domain')
    assert meta == {'cidr': SHARED_HOST, 'shared_platform': 'r2.dev',
                    'url': RELEASE_URL}


def test_a_url_is_still_parsed_as_a_host_not_a_path(db):
    """Retention must not change what is STORED as the indicator: the row is
    keyed on the host, exactly as before the URL was kept."""
    rows = _ingest(db, "https://" + SHARED_HOST + ":8443" + RELEASE_PATH + "?utm=1")
    assert list(rows) == [SHARED_HOST]          # port and path never become the value


# ---- E: the surfaces triage actually reads ----------------------------------

def test_domain_csv_carries_the_submitted_url_column(db):
    """Triage without SQL: the domain CSV's last column is the submitted URL."""
    _ingest(db, RELEASE_URL + "\n" + "plain.example-forge.tld\n")
    body = b"".join(feed_cache.stream_csv(db, "all", "domain")).decode()
    rows = list(csv.reader(io.StringIO(body)))
    assert rows[0] == ["ip", "confidence_score", "tier", "first_seen",
                       "last_seen", "sources", "submitted_url"]
    by_value = {r[0]: r for r in rows[1:]}
    assert by_value[SHARED_HOST][-1] == RELEASE_URL
    assert by_value['plain.example-forge.tld'][-1] == ""      # blank, not absent


def test_ip_csv_columns_are_unchanged(db):
    """The IP feed a firewall or SIEM already maps by position gains nothing:
    an empty column bought for nothing is still a format change."""
    db.add_indicators_bulk([("203.0.113.7", {})], source="synthetic_ips", kind='ip')
    body = b"".join(feed_cache.stream_csv(db, "all", "ip")).decode()
    header = next(csv.reader(io.StringIO(body)))
    assert header == ["ip", "confidence_score", "tier", "first_seen",
                      "last_seen", "sources"]
