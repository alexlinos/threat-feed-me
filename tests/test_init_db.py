"""--init-db (container entrypoint, v2.5.0): while the database opens (a first
start after an upgrade migrates it, ~2 min on prod), a holding page answers
503 + Retry-After on the dashboard port, then frees the port for the app."""
import socket
import urllib.error
import urllib.request

from threatfeedme import main as m


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_holding_page_answers_while_the_database_opens(tmp_path, monkeypatch):
    port = _free_port()
    monkeypatch.setenv("DASHBOARD_HOST", "127.0.0.1")
    monkeypatch.setenv("DASHBOARD_PORT", str(port))
    seen = {}

    def migrating_db(path):                      # stands in for a slow migration
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/feeds/high.txt", timeout=5)
        except urllib.error.HTTPError as e:
            seen.update(code=e.code, retry=e.headers["Retry-After"],
                        cache=e.headers["Cache-Control"], body=e.read())
    monkeypatch.setitem(m.__dict__, "Database", migrating_db)

    m._init_db({}, str(tmp_path / "t.db"))
    assert seen["code"] == 503 and seen["retry"] == "30" and seen["cache"] == "no-store"
    assert b"is starting" in seen["body"]
    with socket.socket() as s:                   # released: the app can bind next
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)   # as uvicorn binds
        s.bind(("127.0.0.1", port))


def test_a_busy_port_does_not_block_the_migration(tmp_path, monkeypatch):
    with socket.socket() as held:
        held.bind(("127.0.0.1", 0))
        held.listen()
        monkeypatch.setenv("DASHBOARD_HOST", "127.0.0.1")
        monkeypatch.setenv("DASHBOARD_PORT", str(held.getsockname()[1]))
        opened = []
        monkeypatch.setitem(m.__dict__, "Database", opened.append)
        m._init_db({}, str(tmp_path / "t.db"))
    assert opened == [str(tmp_path / "t.db")]
