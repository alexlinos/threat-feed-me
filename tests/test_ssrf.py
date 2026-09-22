"""Connect-time SSRF guard (v2.5.0): the address that is validated is the
address that is connected to, so a DNS-rebinding host can't answer "public" to
the check and "private" to the connection."""
import pytest

from threatfeedme import feed_ingestor as fi
from threatfeedme.database import Database
from threatfeedme.feed_ingestor import FeedIngestor
from threatfeedme.models import FeedSource, FeedType


@pytest.fixture
def connects(monkeypatch):
    """Record what the guard ultimately connects to, without real sockets."""
    calls = []
    monkeypatch.setattr(fi, "_original_create_connection",
                        lambda address, *a, **k: calls.append(address) or "sock")
    return calls


def _armed(monkeypatch, active=True):
    monkeypatch.setattr(fi._ssrf_guard, "active", active, raising=False)


def test_inactive_guard_is_a_passthrough(monkeypatch, connects):
    # the UniFi pusher (and anything else) must still reach LAN hosts
    _armed(monkeypatch, False)
    assert fi._guarded_create_connection(("192.168.1.1", 443)) == "sock"
    assert connects == [("192.168.1.1", 443)]


def test_active_guard_refuses_a_private_resolution(monkeypatch, connects):
    _armed(monkeypatch)
    monkeypatch.setattr(fi, "_host_addresses", lambda host: ["10.0.0.5"])
    with pytest.raises(RuntimeError, match="non-public address"):
        fi._guarded_create_connection(("rebind.example", 443))
    assert connects == []            # nothing was dialed


def test_active_guard_connects_to_the_address_it_validated(monkeypatch, connects):
    _armed(monkeypatch)
    lookups = []

    def resolve(host):
        lookups.append(host)
        # a rebinding server would answer private on a SECOND lookup; the
        # guard must never perform one
        return ["93.184.216.34"] if len(lookups) == 1 else ["10.0.0.5"]

    monkeypatch.setattr(fi, "_host_addresses", resolve)
    fi._guarded_create_connection(("rebind.example", 443))
    assert connects == [("93.184.216.34", 443)]   # the IP, not the hostname
    assert lookups == ["rebind.example"]          # resolved exactly once


def test_any_private_answer_in_a_mixed_set_is_refused(monkeypatch, connects):
    _armed(monkeypatch)
    monkeypatch.setattr(fi, "_host_addresses",
                        lambda host: ["93.184.216.34", "127.0.0.1"])
    with pytest.raises(RuntimeError):
        fi._guarded_create_connection(("mixed.example", 80))
    assert connects == []


def _local_feed(tmp_path):
    p = tmp_path / "list.txt"
    p.write_text("185.1.1.1\n")
    return FeedSource(name="f", url=str(p), feed_type=FeedType.CUSTOM, local_file=True)


@pytest.mark.parametrize("allow_private,expected", [(False, True), (True, False)])
def test_fetch_arms_the_guard_only_for_its_own_duration(tmp_path, monkeypatch,
                                                        allow_private, expected):
    seen = {}
    ing = FeedIngestor(Database(str(tmp_path / "t.db")), allow_private_urls=allow_private)
    real_read = ing._read_local_file

    def spy(path):
        seen["active"] = getattr(fi._ssrf_guard, "active", False)
        return real_read(path)

    monkeypatch.setattr(ing, "_read_local_file", spy)
    ing.fetch_feed(_local_feed(tmp_path))
    assert seen["active"] is expected
    assert getattr(fi._ssrf_guard, "active", False) is False   # disarmed after


def test_real_requests_connections_go_through_the_guard(monkeypatch):
    """End to end with real urllib3 sockets: proves the hook is on urllib3's
    actual connect path, not just a function we call ourselves."""
    import http.server
    import socket
    import threading
    import requests

    # conftest resolves every host to 8.8.8.8 so tests never need real DNS;
    # this test needs the real answer for 127.0.0.1. (With the stub in place
    # the guard dialed 8.8.8.8 instead of 127.0.0.1 — the pinning working:
    # it connects to the address it validated, never the name.)
    monkeypatch.setattr(fi, "_host_addresses", lambda host: [
        info[4][0] for info in socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)])

    class _Ok(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200); self.end_headers(); self.wfile.write(b"ok")
        def log_message(self, *a):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), _Ok)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{srv.server_port}/"
    try:
        assert requests.get(url, timeout=5).text == "ok"   # guard off: reachable
        fi._ssrf_guard.active = True
        try:
            with pytest.raises(RuntimeError, match="non-public address"):
                requests.get(url, timeout=5)                # guard on: refused
        finally:
            fi._ssrf_guard.active = False
    finally:
        srv.shutdown()
