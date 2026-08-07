"""Host/port resolution tests for the --serve dashboard bind.

Asserts the resolution order in threatfeedme.main._resolve_host_port:
$DASHBOARD_HOST/$DASHBOARD_PORT env override > dashboard.host/port in config
> safe localhost defaults (127.0.0.1:8080).
"""

import pytest


@pytest.fixture(autouse=True)
def _clear_dash_env(monkeypatch):
    # Isolate each test from any DASHBOARD_HOST/PORT set on the host.
    monkeypatch.delenv("DASHBOARD_HOST", raising=False)
    monkeypatch.delenv("DASHBOARD_PORT", raising=False)


def _resolve(cfg):
    from threatfeedme.main import _resolve_host_port
    return _resolve_host_port(cfg)


def test_env_override_wins_over_config_and_default(monkeypatch):
    monkeypatch.setenv("DASHBOARD_HOST", "0.0.0.0")
    monkeypatch.setenv("DASHBOARD_PORT", "9090")
    cfg = {"dashboard": {"host": "127.0.0.1", "port": 8080}}
    host, port = _resolve(cfg)
    assert host == "0.0.0.0"
    assert port == 9090


def test_config_wins_over_default_when_no_env():
    cfg = {"dashboard": {"host": "10.0.0.5", "port": 9000}}
    host, port = _resolve(cfg)
    assert host == "10.0.0.5"
    assert port == 9000


def test_defaults_are_localhost_when_nothing_configured():
    cfg = {}
    host, port = _resolve(cfg)
    assert host == "127.0.0.1"
    assert port == 8080


def test_config_defaults_used_when_dashboard_absent_but_no_env():
    cfg = {"dashboard": {}}
    host, port = _resolve(cfg)
    assert host == "127.0.0.1"
    assert port == 8080


def test_env_only_host_keeps_config_port(monkeypatch):
    monkeypatch.setenv("DASHBOARD_HOST", "0.0.0.0")
    cfg = {"dashboard": {"host": "127.0.0.1", "port": 9000}}
    host, port = _resolve(cfg)
    assert host == "0.0.0.0"
    assert port == 9000
