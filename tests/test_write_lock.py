"""Heavy-writer coordination (v2.5.0): rescores never overlap, and a rescore
writes only what changed, in short transactions."""
import threading
import time

import pytest

from threatfeedme import jobs, pipeline
from threatfeedme.database import Database
from threatfeedme.scorer import ConfidenceScorer


@pytest.fixture
def db(tmp_path):
    d = Database(str(tmp_path / "t.db"))
    d.add_indicators_bulk([(f"185.1.{i // 250}.{i % 250 + 1}", {}) for i in range(300)],
                          source="blocklist_de")
    d.add_indicators_bulk([(f"185.1.{i // 250}.{i % 250 + 1}", {}) for i in range(150)],
                          source="abuseipdb_s100_3d")
    return d


def test_concurrent_rescores_never_overlap(db, monkeypatch):
    active, overlaps = [0], []
    real = ConfidenceScorer.recalculate_all_scores

    def tracked(self):
        active[0] += 1
        if active[0] > 1:
            overlaps.append(1)
        time.sleep(0.05)
        try:
            return real(self)
        finally:
            active[0] -= 1

    monkeypatch.setattr(ConfidenceScorer, "recalculate_all_scores", tracked)
    threads = [threading.Thread(target=pipeline.recalculate, args=(db, {})) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert overlaps == []           # each waited for the one before it


def test_the_lock_is_reentrant_for_the_refresh_phase():
    # the refresh's post-fetch phase holds it and calls recalculate/export/push
    with jobs.write_lock:
        with jobs.write_lock:
            pass


def _capture_writes(monkeypatch):
    written = []
    real = ConfidenceScorer._write_changes

    def spy(self, changed):
        written.append(len(changed))
        return real(self, changed)

    monkeypatch.setattr(ConfidenceScorer, "_write_changes", spy)
    return written


def test_an_unchanged_rescore_writes_nothing(db, monkeypatch):
    ConfidenceScorer(db, {}).recalculate_all_scores()      # first scoring
    written = _capture_writes(monkeypatch)
    ConfidenceScorer(db, {}).recalculate_all_scores()      # nothing moved
    assert written == [0]


def test_only_the_rows_that_move_are_written(db, monkeypatch):
    ConfidenceScorer(db, {}).recalculate_all_scores()
    written = _capture_writes(monkeypatch)
    # An INDEPENDENT witness (mostly its own IPs) that also reports one shared
    # IP. (A feed fully contained in the others adds ~0 votes — the overlap
    # discount pricing it as an echo — so it would legitimately move nothing.)
    own = [(f"185.9.0.{i}", {}) for i in range(1, 41)]
    db.add_indicators_bulk(own + [("185.1.0.1", {})], source="greensnow")
    ConfidenceScorer(db, {}).recalculate_all_scores()
    # its 40 new rows + the one shared IP it now corroborates; the other 449
    # are untouched and not rewritten
    assert written == [41]


def test_chunked_writes_produce_the_same_result_as_one_big_write(db, monkeypatch):
    ConfidenceScorer(db, {}).recalculate_all_scores()
    one_shot = {i.ip: (i.confidence_score, i.tier) for i in db.get_indicators_by_kind("ip")}
    with db._cursor() as cur:                 # force every row to be rewritten
        cur.execute("UPDATE indicators SET effective_votes = NULL")
    monkeypatch.setattr(ConfidenceScorer, "_WRITE_CHUNK", 7)
    ConfidenceScorer(db, {}).recalculate_all_scores()
    chunked = {i.ip: (i.confidence_score, i.tier) for i in db.get_indicators_by_kind("ip")}
    assert chunked.keys() == one_shot.keys()
    for ip, (score, tier) in chunked.items():
        # two rescores at different instants: recency drifts a hair between them
        assert tier == one_shot[ip][1]
        assert score == pytest.approx(one_shot[ip][0], abs=1e-6)
