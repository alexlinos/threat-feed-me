"""Export functions: firewall-ready output generation from indicator sets.

Kept as a separate module so callers (feed_helpers, routers) can import
is_included and firewall_value without pulling in the full pipeline.
"""
import csv
import json
from datetime import datetime, timezone
from typing import List

from threatfeedme.models import ThreatIndicator, ConfidenceTier, effective_sources


def is_included(indicator: ThreatIndicator, whitelist_map: dict) -> bool:
    """Whether an indicator should appear in outputs after whitelist scoping."""
    eff = effective_sources(indicator.ip, indicator.sources, whitelist_map)
    return eff is not None and len(eff) > 0


def firewall_value(indicator: ThreatIndicator) -> str:
    """The value a firewall should actually block for this indicator."""
    return indicator.metadata.get('cidr') or indicator.ip


# ---- Low-level format writers (no DB dependency) ----

def _write_text(indicators: List[ThreatIndicator], filepath: str) -> None:
    with open(filepath, 'w') as f:
        for ind in indicators:
            f.write(f"{firewall_value(ind)}\n")


def _write_csv(indicators: List[ThreatIndicator], filepath: str) -> None:
    with open(filepath, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["ip", "confidence_score", "tier", "first_seen", "last_seen", "sources"])
        for ind in indicators:
            writer.writerow([
                ind.ip, ind.confidence_score, ind.tier.value,
                ind.first_seen, ind.last_seen, ";".join(ind.sources),
            ])


def _write_json(indicators: List[ThreatIndicator], tier: ConfidenceTier, filepath: str) -> None:
    data = {
        "tier": tier.value,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_count": len(indicators),
        "indicators": [
            {
                "ip": i.ip,
                "confidence_score": i.confidence_score,
                "tier": i.tier.value,
                "first_seen": i.first_seen.isoformat() if isinstance(i.first_seen, datetime) else i.first_seen,
                "last_seen": i.last_seen.isoformat() if isinstance(i.last_seen, datetime) else i.last_seen,
                "sources": i.sources,
                "metadata": i.metadata,
            }
            for i in indicators
        ],
    }
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=2)
