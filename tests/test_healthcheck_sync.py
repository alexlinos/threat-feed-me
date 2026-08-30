"""Regression guard for the v2.4.10 healthcheck fix.

The image HEALTHCHECK (Dockerfile) and its docker-compose.yml override are
defined separately and MUST stay in sync. Both must probe the constant-cost
unauthenticated /healthz endpoint; probing a corpus-sized feed URL instead is
the exact bug this guards against (response time grows with the indicator
count until it outlives the probe timeout, marking healthy deployments
permanently unhealthy).
"""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_healthchecks_probe_healthz_and_stay_in_sync():
    df = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    cm = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")

    # Image-side: HEALTHCHECK ... \n CMD python -c "<cmd>" || exit 1
    df_match = re.search(r'HEALTHCHECK[^\n]*\n\s+CMD python -c "([^"]+)"', df)
    assert df_match, "HEALTHCHECK CMD not found in Dockerfile"

    # Compose-side: test: ["CMD", "python", "-c", "<cmd>"]
    cm_match = re.search(r'test:\s*\["CMD",\s*"python",\s*"-c",\s*"([^"]+)"\]', cm)
    assert cm_match, "compose healthcheck test command not found"

    df_cmd, cm_cmd = df_match.group(1), cm_match.group(1)

    # The whole point of the guard: the two payloads must be identical.
    # Compose overrides the image HEALTHCHECK, so drift means the deployed
    # probe silently differs from the tested one.
    assert df_cmd == cm_cmd, (
        "Dockerfile and compose healthcheck commands drifted out of sync:\n"
        f"  Dockerfile: {df_cmd}\n  compose:    {cm_cmd}"
    )

    assert "/healthz" in df_cmd, "Dockerfile healthcheck must probe /healthz"
    assert "/healthz" in cm_cmd, "compose healthcheck must probe /healthz"
    assert "/feeds/" not in df_cmd, "never probe a corpus-sized feed URL (Dockerfile)"
    assert "/feeds/" not in cm_cmd, "never probe a corpus-sized feed URL (compose)"
