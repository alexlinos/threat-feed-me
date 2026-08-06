"""Export functions: firewall-ready output generation from indicator sets.

Kept as a separate module so callers (feed_helpers, routers) can import
is_included and firewall_value without pulling in the full pipeline.
"""
import csv
import json
from datetime import datetime, timezone
from typing import List

from threatfeedme.models import ThreatIndicator, ConfidenceTier, effective_sources


def is_included(indicator: ThreatIndicator, whitelist_map: dict, tier: ConfidenceTier = None) -> bool:
    """Whether an indicator should appear in outputs after whitelist scoping.

    When `tier` is set, also checks for tier-scoped whitelist entries
    (feed_name starting with 'tier:') that exclude the indicator from that
    specific tier's output while allowing it in others.
    """
    eff = effective_sources(indicator.ip, indicator.sources, whitelist_map)
    if eff is None:
        return False
    if tier and len(eff) > 0:
        # Check tier-scoped whitelist: feed_name="tier:high" means
        # "exclude from high tier output only".
        tier_scope = f"tier:{tier.value}"
        if hasattr(whitelist_map, "scoped_feeds"):
            scoped = whitelist_map.scoped_feeds(indicator.ip)
            if scoped and tier_scope in scoped:
                return False
        elif whitelist_map.get(indicator.ip) and tier_scope in whitelist_map.get(indicator.ip, set()):
            return False
    return len(eff) > 0


def firewall_value(indicator: ThreatIndicator) -> str:
    """The value a firewall should actually block for this indicator."""
    return indicator.metadata.get('cidr') or indicator.ip


# ---- Low-level format writers (no DB dependency) ----

def _write_text(indicators, filepath: str) -> None:
    with open(filepath, 'w') as f:
        for ind in indicators:
            f.write(f"{firewall_value(ind)}\n")


def _write_csv(indicators, filepath: str) -> None:
    with open(filepath, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["ip", "confidence_score", "tier", "first_seen", "last_seen", "sources"])
        for ind in indicators:
            writer.writerow([
                ind.ip, ind.confidence_score, ind.tier.value,
                ind.first_seen, ind.last_seen, ";".join(ind.sources),
            ])


def _write_json(indicators, tier: ConfidenceTier, filepath: str) -> None:
    """Stream-write the JSON export one indicator at a time.

    `indicators` may be any iterable (the export path passes a generator so
    the whole tier never sits in memory). total_count is therefore written
    AFTER the indicators array — key order carries no meaning in JSON, and
    the count isn't known until the stream is exhausted.
    """
    with open(filepath, 'w') as f:
        f.write('{\n')
        f.write(f'  "tier": {json.dumps(tier.value)},\n')
        f.write(f'  "generated_at": {json.dumps(datetime.now(timezone.utc).isoformat())},\n')
        f.write('  "indicators": [')
        count = 0
        for i in indicators:
            entry = {
                "ip": i.ip,
                "confidence_score": i.confidence_score,
                "tier": i.tier.value,
                "first_seen": i.first_seen.isoformat() if isinstance(i.first_seen, datetime) else i.first_seen,
                "last_seen": i.last_seen.isoformat() if isinstance(i.last_seen, datetime) else i.last_seen,
                "sources": i.sources,
                "metadata": i.metadata,
            }
            f.write((',' if count else '') + '\n    ' + json.dumps(entry))
            count += 1
        f.write('\n  ],\n' if count else '],\n')
        f.write(f'  "total_count": {count}\n')
        f.write('}\n')
