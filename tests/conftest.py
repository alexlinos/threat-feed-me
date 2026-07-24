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


@pytest.fixture(autouse=True)
def _public_dns(monkeypatch):
    """The feed-fetch SSRF guard resolves feed hostnames; tests use fake hosts
    (feeds.example, example.com, ...) and must not depend on real DNS. Resolve
    everything to a public address; tests of the guard itself override this."""
    from threatfeedme import feed_ingestor
    monkeypatch.setattr(feed_ingestor, "_host_addresses", lambda host: ["8.8.8.8"])
