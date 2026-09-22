"""Export functions: firewall-ready output generation from indicator sets.

Kept as a separate module so callers (feed_helpers, routers) can import
is_included and firewall_value without pulling in the full pipeline.
"""
import csv
import json
import os
import tempfile
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import List

from threatfeedme.models import ThreatIndicator, ConfidenceTier, effective_sources


def is_included(indicator: ThreatIndicator, whitelist_map: dict, tier: ConfidenceTier = None) -> bool:
    """Whether an indicator should appear in outputs after whitelist scoping.

    When `tier` is set, also checks for tier-scoped whitelist entries
    (feed_name starting with 'tier:') that exclude the indicator from that
    specific tier's output while allowing it in others.
    """
    return row_included(indicator.ip, indicator.sources, whitelist_map, tier)


def row_included(ip: str, sources, whitelist_map: dict, tier: ConfidenceTier = None) -> bool:
    """is_included on raw fields — the ONE implementation of the rule. The
    lean feed-serving path (feed_cache) works on plain row tuples rather than
    ThreatIndicator objects, and must never disagree with the object-based
    callers (UniFi push, stats, exports) about what a feed contains."""
    eff = effective_sources(ip, sources, whitelist_map)
    if eff is None:
        return False
    if tier and len(eff) > 0:
        # Check tier-scoped whitelist: feed_name="tier:high" means
        # "exclude from high tier output only".
        tier_scope = f"tier:{tier.value}"
        if hasattr(whitelist_map, "scoped_feeds"):
            scoped = whitelist_map.scoped_feeds(ip)
            if scoped and tier_scope in scoped:
                return False
        elif whitelist_map.get(ip) and tier_scope in whitelist_map.get(ip, set()):
            return False
    return len(eff) > 0


def firewall_value(indicator: ThreatIndicator) -> str:
    """The value a firewall should actually block for this indicator."""
    return indicator.metadata.get('cidr') or indicator.ip


# ---- Low-level format writers (no DB dependency) ----

@contextmanager
def _atomic_open(filepath: str, newline=None):
    """Write to a temp file in the same directory, then os.replace() it over
    the target. A reader (a firewall polling the export, or a second export
    that overlaps this one) sees either the old complete file or the new
    complete file — never a truncated one mid-write. Same-directory temp keeps
    the rename on one filesystem, which is what makes it atomic."""
    directory = os.path.dirname(os.path.abspath(filepath))
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=directory)
    try:
        with os.fdopen(fd, 'w', newline=newline) as f:
            yield f
        os.chmod(tmp, 0o644)
        os.replace(tmp, filepath)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _write_text(indicators, filepath: str) -> None:
    with _atomic_open(filepath) as f:
        for ind in indicators:
            f.write(f"{firewall_value(ind)}\n")


def _write_csv(indicators, filepath: str) -> None:
    with _atomic_open(filepath, newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["ip", "confidence_score", "tier", "first_seen", "last_seen", "sources"])
        for ind in indicators:
            # firewall_value, not ind.ip: the store keeps only a netblock's
            # network address, so ind.ip silently turned 42.128.0.0/12 into a
            # single host. Matches the HTTP CSV (routers/indicators.py).
            writer.writerow([
                firewall_value(ind), ind.confidence_score, ind.tier.value,
                ind.first_seen, ind.last_seen, ";".join(ind.sources),
            ])


def _write_json(indicators, tier: ConfidenceTier, filepath: str) -> None:
    """Stream-write the JSON export one indicator at a time.

    `indicators` may be any iterable (the export path passes a generator so
    the whole tier never sits in memory). total_count is therefore written
    AFTER the indicators array — key order carries no meaning in JSON, and
    the count isn't known until the stream is exhausted.
    """
    with _atomic_open(filepath) as f:
        f.write('{\n')
        f.write(f'  "tier": {json.dumps(tier.value)},\n')
        f.write(f'  "generated_at": {json.dumps(datetime.now(timezone.utc).isoformat())},\n')
        f.write('  "indicators": [')
        count = 0
        for i in indicators:
            entry = {
                "value": firewall_value(i),  # what to block (CIDR-aware), as in the HTTP JSON
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
