"""Issue #7: shipped feed deprecations must reach existing installs.

sync_default_feeds treats enabled as an operator preference, which correctly
protects opt-in feeds (OTX ships disabled) and deliberate dashboard enables —
and also meant a shipped flip of enabled never reached an existing row, so a
retired feed (urlhaus's keyless downloads, all 410) kept failing every cycle
forever on installs that predated the deprecation. The fix is the 2.5.6
interval rule extended to enabled: a switch the operator never moved was
never chosen, so it follows the ship; a switch they moved — either switch,
enabled OR weight — is theirs and the row is left alone.
"""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from threatfeedme.database import Database


@pytest.fixture
def db(tmp_path):
    return Database(str(tmp_path / "test.db"))


def _ship(**overrides):
    """A one-feed shipped config, like a release bumping config.yaml."""
    cfg = {"name": "a", "url": "http://a/x.txt", "enabled": True,
           "weight": 1.0, "update_interval": 3600}
    cfg.update(overrides)
    return {"feeds": [cfg]}


def _set_weight(db, name, weight):
    with db._cursor() as cur:  # how an operator's pinned weight is stored
        cur.execute("UPDATE feeds SET weight = ? WHERE name = ?", (weight, name))


def _strip_enabled_from_fingerprint(db, name):
    """Rewrite the stored fingerprint without the enabled field, as a
    pre-#7 release left it (backward-compatibility fixture)."""
    with db._cursor() as cur:
        cur.execute("SELECT seed_fingerprint FROM feeds WHERE name = ?", (name,))
        fp = json.loads(cur.fetchone()[0])
        assert "enabled" in fp  # the shipped format records it
        fp.pop("enabled")
        cur.execute("UPDATE feeds SET seed_fingerprint = ? WHERE name = ?",
                    (json.dumps(fp, sort_keys=True), name))


# ------------------------------------------------ shipped flips propagate ----

def test_shipped_enabled_flip_propagates_to_an_untouched_row(db):
    """The urlhaus case: the release ships enabled:false for a retired
    endpoint; an install that never touched the feed gets switched off
    instead of looping [fail] 410 forever."""
    db.seed_feeds_from_config(_ship(enabled=True))
    actions = db.sync_default_feeds(_ship(enabled=False))
    assert actions["updated"] == ["a"]
    feed = db.get_feed_source("a")
    assert feed.enabled is False
    # A preference follow must not smuggle in changes to the other fields.
    assert feed.weight == 1.0 and feed.update_interval == 3600
    # Idempotent: the rewritten fingerprint matches the ship.
    assert db.sync_default_feeds(_ship(enabled=False))["updated"] == []


def test_shipped_enable_flip_propagates_back_symmetrically(db):
    """The rule is symmetric: a re-vindication shipped as enabled:true
    reaches untouched rows too (e.g. an outage ends upstream)."""
    db.seed_feeds_from_config(_ship(enabled=True))
    db.sync_default_feeds(_ship(enabled=False))
    actions = db.sync_default_feeds(_ship(enabled=True))
    assert actions["updated"] == ["a"]
    assert db.get_feed_source("a").enabled is True


def test_flip_propagates_alongside_a_plumbing_fix(db):
    """One release can both fix mechanics and deprecate; both land."""
    db.seed_feeds_from_config(_ship(enabled=True))
    actions = db.sync_default_feeds(_ship(enabled=False, url="http://a/moved.txt"))
    assert actions["updated"] == ["a"]
    feed = db.get_feed_source("a")
    assert feed.url == "http://a/moved.txt" and feed.enabled is False


def test_flip_propagates_after_an_earlier_plumbing_rewrite(db):
    """The plumbing update rewrites the fingerprint with the shipped
    preferences (nobody had moved them), so a LATER release's enabled flip
    still finds the row untouched and propagates."""
    db.seed_feeds_from_config(_ship(enabled=True))
    db.sync_default_feeds(_ship(enabled=True, url="http://a/new.txt"))
    actions = db.sync_default_feeds(_ship(enabled=False, url="http://a/new.txt"))
    assert actions["updated"] == ["a"]
    assert db.get_feed_source("a").enabled is False


# --------------------------------------------- operator switches respected ----

def test_operator_enabled_feed_is_not_switched_off(db):
    """The OTX protection: a feed that ships disabled and the operator
    deliberately enabled is NEVER silently switched off by an upgrade."""
    db.seed_feeds_from_config(_ship(enabled=False))  # ships opt-in
    db.set_feed_enabled("a", True)                   # operator opts in
    actions = db.sync_default_feeds(_ship(enabled=False))
    assert actions["updated"] == []
    assert db.get_feed_source("a").enabled is True


def test_operator_disabled_feed_is_not_re_enabled(db):
    """Symmetric protection: a feed the operator switched off is not
    re-enabled by a shipped enabled:true."""
    db.seed_feeds_from_config(_ship(enabled=True))
    db.set_feed_enabled("a", False)                  # operator switches off
    actions = db.sync_default_feeds(_ship(enabled=True))
    assert actions["updated"] == []
    assert db.get_feed_source("a").enabled is False


def test_touched_weight_blocks_an_enabled_flip(db):
    """The row must match its seeded preferences EXACTLY: a pinned weight
    is operator attention on the feed, so the enabled switch stays theirs
    too — propagation is all-or-nothing on the untouched test."""
    db.seed_feeds_from_config(_ship(enabled=True, weight=1.0))
    _set_weight(db, "a", 0.5)                        # operator pins weight
    actions = db.sync_default_feeds(_ship(enabled=False, weight=1.0))
    assert actions["updated"] == []
    feed = db.get_feed_source("a")
    assert feed.enabled is True and feed.weight == 0.5


def test_dashboard_override_nulls_fingerprint_and_blocks_flip(db):
    """A dashboard edit is the loudest possible 'operator touched this':
    the nulled fingerprint freezes the row, flip or no flip."""
    from threatfeedme.models import FeedSource
    db.seed_feeds_from_config(_ship(enabled=True))
    db.add_feed(FeedSource(name="a", url="http://a/x.txt", weight=1.0,
                           update_interval=3600, enabled=True))
    actions = db.sync_default_feeds(_ship(enabled=False))
    assert actions["updated"] == []
    assert db.get_feed_source("a").enabled is True


# -------------------------------------------------- backward compatibility ----

def test_legacy_fingerprint_without_enabled_keeps_old_behavior(db):
    """A row seeded by a pre-#7 release carries no enabled in its
    fingerprint: there is no seeded enabled to compare against, so the
    shipped flip does NOT propagate — while the 2.5.6 interval rule keeps
    working untouched (no regression on the existing contract)."""
    db.seed_feeds_from_config(_ship(enabled=True, update_interval=3600))
    _strip_enabled_from_fingerprint(db, "a")
    actions = db.sync_default_feeds(_ship(enabled=False, update_interval=21600))
    assert actions["updated"] == ["a"]                # interval followed
    feed = db.get_feed_source("a")
    assert feed.enabled is True                       # flip did NOT propagate
    assert feed.update_interval == 21600


def test_untouched_interval_still_follows_the_ship(db):
    """The 2.5.6 contract, re-pinned beside the new rule: a row still on
    its seeded interval follows a new shipped interval."""
    db.seed_feeds_from_config(_ship(enabled=True, update_interval=3600))
    actions = db.sync_default_feeds(_ship(enabled=True, update_interval=21600))
    assert actions["updated"] == ["a"]
    feed = db.get_feed_source("a")
    assert feed.update_interval == 21600 and feed.enabled is True
    assert db.sync_default_feeds(_ship(enabled=True, update_interval=21600))["updated"] == []
