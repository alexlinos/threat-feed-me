"""Runtime dependency pins live in BOTH requirements.txt and pyproject.toml,
and the Dockerfile runs `pip install -r requirements.txt` then
`pip install -e .` — which re-resolves from pyproject. A bump made in only one
file is silently undone: that is exactly how the python-multipart security fix
(GHSA-5rvq-cxj2-64vf) first shipped un-applied in v2.4.12. This keeps the two
in lockstep."""
import os
import re

try:
    import tomllib
except ModuleNotFoundError:  # py < 3.11
    tomllib = None

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_PIN = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*==\s*([^\s;#]+)")


def _norm(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def _requirements_pins():
    pins = {}
    with open(os.path.join(ROOT, "requirements.txt"), encoding="utf-8") as f:
        for line in f:
            m = _PIN.match(line)
            if m:
                pins[_norm(m.group(1))] = m.group(2)
    return pins


@pytest.mark.skipif(tomllib is None, reason="tomllib needs Python 3.11+")
def test_runtime_pins_match_between_requirements_and_pyproject():
    with open(os.path.join(ROOT, "pyproject.toml"), "rb") as f:
        deps = tomllib.load(f)["project"]["dependencies"]
    pyproject = {}
    for spec in deps:
        m = _PIN.match(spec)
        assert m, f"pyproject dependency is not an exact pin: {spec!r}"
        pyproject[_norm(m.group(1))] = m.group(2)
    assert pyproject == _requirements_pins(), (
        "requirements.txt and pyproject.toml disagree — bump BOTH, or "
        "`pip install -e .` silently reverts the requirements.txt version")
