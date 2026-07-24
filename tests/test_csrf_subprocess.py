"""Standalone subprocess test for CSRF rejection — run in a clean Python process
so import-time globals (auth_required, DASHBOARD_USER/PASSWORD) are guaranteed
fresh, unlike the module-caching in the pytest fixture."""

import os
import sys
import tempfile

# ---- Config: auth ON, with credentials --------------------------------
cfg = {
    "database": {"path": ""},  # filled below
    "scoring": {
        "source_weight": 0.45, "reputation_weight": 0.33, "recency_weight": 0.22,
        "high_confidence": {"min_sources": 3, "min_score": 0.75},
    },
    "feeds": [
        {"name": "spamhaus_drop", "url": "https://example.com/drop.txt",
         "feed_type": "spam", "weight": 0.95},
    ],
    "safety": {"drop_private_reserved": False, "protect_known_good": True},
    "dashboard": {"auth_required": True},
}

if __name__ == "__main__":
    work = tempfile.mkdtemp("csrf_subprocess")
    db_path = os.path.join(work, "t.db").replace("\\", "/")
    cfg["database"]["path"] = db_path
    cfg_path = os.path.join(work, "config.yaml")
    with open(cfg_path, "w") as f:
        import yaml
        yaml.dump(cfg, f)

    os.environ["CONFIG_PATH"] = cfg_path
    os.environ["DASHBOARD_USER"] = "admin"
    os.environ["DASHBOARD_PASSWORD"] = "testpass"

    # Import in a clean process — no stale module references.
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))
    from threatfeedme import dashboard
    from starlette.testclient import TestClient
    client = TestClient(dashboard.app)

    import base64
    token = base64.b64encode(b"admin:testpass").decode("ascii")
    auth_headers = {"Authorization": f"Basic {token}"}

    failures = 0

    # Test 1: POST without header -> 403
    r = client.post("/api/whitelist", json={
        "ip": "203.0.113.100", "reason_code": "other",
    }, headers=auth_headers)
    if r.status_code != 403:
        print(f"FAIL test_csrf_rejected_without_header: got {r.status_code}, want 403")
        failures += 1
    elif "CSRF" not in r.json().get("detail", ""):
        print("FAIL test_csrf_rejected_without_header: detail missing 'CSRF'")
        failures += 1
    else:
        print("PASS test_csrf_rejected_without_header")

    # Test 2: DELETE without header -> 403
    r = client.delete("/api/whitelist?ip=203.0.113.99&feed=*", headers=auth_headers)
    if r.status_code != 403:
        print(f"FAIL test_csrf_rejected_delete_without_header: got {r.status_code}, want 403")
        failures += 1
    elif "CSRF" not in r.json().get("detail", ""):
        print("FAIL test_csrf_rejected_delete_without_header: detail missing 'CSRF'")
        failures += 1
    else:
        print("PASS test_csrf_rejected_delete_without_header")

    # Test 3: POST with wrong header value -> 403
    bad_headers = dict(auth_headers)
    bad_headers["X-Requested-With"] = "EvilScript"
    r = client.post("/api/whitelist", json={
        "ip": "203.0.113.101", "reason_code": "other",
    }, headers=bad_headers)
    if r.status_code != 403:
        print(f"FAIL test_csrf_rejected_invalid_header_value: got {r.status_code}, want 403")
        failures += 1
    else:
        print("PASS test_csrf_rejected_invalid_header_value")

    # Clean up
    import shutil
    shutil.rmtree(work, ignore_errors=True)

    sys.exit(failures)  # 0 = all pass, >0 = failures
