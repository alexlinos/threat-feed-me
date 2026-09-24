"""Pytest bootstrap: make the `threatfeedme` package importable without an
install step by putting the `src/` directory on sys.path.

The package is also pip-installable via pyproject.toml (``pip install -e .``);
this conftest just lets ``pytest`` run straight from a checkout.
"""
import os
import sys

import pytest

_SRC = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

# ---- Never the developer's real data directory -------------------------------
# core initializes LAZILY on first attribute access, from CONFIG_PATH or else
# ./config.yaml, whose database lives in ./data. A test that touches core (or
# imports the app) before any fixture set CONFIG_PATH therefore opened the
# developer's real DB, and every later test in the session wrote into it:
# fixture feeds, uploads, a .env key, settings, backups. It happened twice
# (2026-09-22 and 2026-09-23). Two guards:
#   1. CONFIG_PATH defaults to a throwaway config + DB for the whole session,
#      so an accidental lazy init lands in a temp dir.
#   2. The repo's data/ is snapshotted at session start and the run FAILS if
#      anything in it changed.
_REPO_DATA = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data"))


def _data_snapshot():
    out = {}
    for root, _dirs, files in os.walk(_REPO_DATA):
        for name in files:
            path = os.path.join(root, name)
            try:
                st = os.stat(path)
                out[path] = (st.st_mtime_ns, st.st_size)
            except OSError:
                pass
    return out


def pytest_sessionstart(session):
    if not os.environ.get("CONFIG_PATH"):
        import tempfile
        tmp = tempfile.mkdtemp(prefix="tfm-test-core-")
        cfg = os.path.join(tmp, "config.yaml")
        with open(cfg, "w", encoding="utf-8") as f:
            f.write(f"database:\n  path: {tmp}/t.db\nfeeds: []\n"
                    "dashboard: {auth_required: false}\n")
        os.environ["CONFIG_PATH"] = cfg
    session.config._tfm_data_before = _data_snapshot()


def pytest_sessionfinish(session, exitstatus):
    before = getattr(session.config, "_tfm_data_before", None)
    if before is None:
        return
    after = _data_snapshot()
    changed = sorted(p for p in set(before) | set(after) if before.get(p) != after.get(p))
    if changed:
        sys.stderr.write(
            "\n\nTEST ISOLATION FAILURE: the test run modified the repo's data/ "
            "directory (the developer's real instance):\n  " + "\n  ".join(changed)
            + "\n(If a local server was running against data/, stop it and re-run.)\n")
        session.exitstatus = 1


@pytest.fixture(autouse=True)
def _public_dns(monkeypatch):
    """The feed-fetch SSRF guard resolves feed hostnames; tests use fake hosts
    (feeds.example, example.com, ...) and must not depend on real DNS. Resolve
    everything to a public address; tests of the guard itself override this."""
    from threatfeedme import feed_ingestor
    monkeypatch.setattr(feed_ingestor, "_host_addresses", lambda host: ["8.8.8.8"])
