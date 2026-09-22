"""On-disk export writers (v2.4.19): CIDR-aware values and atomic replacement."""
import csv
import json
import os
from datetime import datetime, timezone

import pytest

from threatfeedme import exporter
from threatfeedme.models import ConfidenceTier, ThreatIndicator

NOW = datetime(2026, 9, 22, tzinfo=timezone.utc)


def _ind(ip, cidr=None):
    return ThreatIndicator(ip=ip, sources=["spamhaus_drop"], first_seen=NOW,
                           last_seen=NOW, confidence_score=0.9,
                           tier=ConfidenceTier.HIGH,
                           metadata={"cidr": cidr} if cidr else {})


def test_csv_export_serves_the_netblock_not_its_network_address(tmp_path):
    out = tmp_path / "high.csv"
    exporter._write_csv([_ind("42.128.0.0", "42.128.0.0/12"), _ind("185.1.1.1")], str(out))
    rows = list(csv.reader(out.open()))
    assert rows[1][0] == "42.128.0.0/12"   # was "42.128.0.0" — a single host
    assert rows[2][0] == "185.1.1.1"


def test_json_export_carries_the_served_value(tmp_path):
    out = tmp_path / "high.json"
    exporter._write_json([_ind("42.128.0.0", "42.128.0.0/12")], ConfidenceTier.HIGH, str(out))
    doc = json.loads(out.read_text())
    assert doc["indicators"][0]["value"] == "42.128.0.0/12"
    assert doc["total_count"] == 1


def test_writes_are_atomic_and_leave_no_temp_files(tmp_path):
    out = tmp_path / "high.txt"
    out.write_text("previous complete list\n")

    def exploding():
        yield _ind("185.1.1.1")
        raise RuntimeError("export died mid-stream")

    with pytest.raises(RuntimeError):
        exporter._write_text(exploding(), str(out))
    # a failed export must leave the previous complete file in place
    assert out.read_text() == "previous complete list\n"
    assert [p for p in os.listdir(tmp_path) if p.startswith(".tmp-")] == []

    exporter._write_text([_ind("185.1.1.1")], str(out))
    assert out.read_text() == "185.1.1.1\n"
    assert [p for p in os.listdir(tmp_path) if p.startswith(".tmp-")] == []
