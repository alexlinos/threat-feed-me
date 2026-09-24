"""Streaming feed generators hold an SQLite connection, and the web server may
resume or finalize them on a different worker thread (found on the v2.5.0
canary: a client that disconnected early left the generator to be closed on
another thread, SQLite's same-thread check refused, and the connection and its
read snapshot leaked)."""
import threading

import pytest

from threatfeedme.database import Database
from threatfeedme.models import ConfidenceTier
from threatfeedme.scorer import ConfidenceScorer

ALL = tuple(ConfidenceTier)


@pytest.fixture
def db(tmp_path):
    d = Database(str(tmp_path / "t.db"))
    d.add_indicators_bulk([(f"185.1.{i // 250}.{i % 250 + 1}", {}) for i in range(30)],
                          source="blocklist_de")
    ConfidenceScorer(d, {}).recalculate_all_scores()
    return d


def _in_thread(fn):
    out = {}

    def run():
        try:
            out["value"] = fn()
        except BaseException as e:      # noqa: BLE001 - surface anything
            out["error"] = e
    t = threading.Thread(target=run)
    t.start()
    t.join()
    if "error" in out:
        raise out["error"]
    return out.get("value")


@pytest.mark.parametrize("make", [
    lambda db: db.iter_served_rows("ip", ALL, batch=5),
    lambda db: db.iter_served_rows_by_added("ip", ALL, batch=5),
    lambda db: db.iter_indicators_by_tiers(ALL, batch=5),
])
def test_a_stream_can_hop_threads_and_be_closed_anywhere(db, make):
    gen = make(db)
    _in_thread(lambda: next(gen))            # starts (opens its connection) on thread A
    _in_thread(lambda: [next(gen) for _ in range(10)])   # resumes on thread B
    gen.close()                               # finalized on the main thread: must not raise
