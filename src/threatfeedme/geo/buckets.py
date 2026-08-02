"""Server-side country bucketing of blocked indicators.

The DB holds only integer IPs (or dotted strings) — no geo data. We pull the
indicator IPs once, bucket each to its /16, and use the compact table to get
a country count. Returns {iso2: count} sorted descending by count.
"""
import ipaddress
from collections import Counter

from .data import CountryBuckets


def bucket_ips(ip_iter, buckets: CountryBuckets) -> list:
    """ip_iter: iterable of integer IPs (int). Returns [(iso2, count), ...]."""
    counts = Counter()
    for ip in ip_iter:
        counts[buckets.country_for_ip(ip)] += 1
    return counts.most_common()


def bucket_ip_strings(ip_str_iter, buckets: CountryBuckets) -> list:
    """Accept dotted-quad strings (also handle CIDR/short forms defensively)."""
    counts = Counter()
    for s in ip_str_iter:
        try:
            ip = int(ipaddress.ip_address(s))
        except Exception:
            continue
        counts[buckets.country_for_ip(ip)] += 1
    return counts.most_common()


def country_totals(ip_iter, buckets: CountryBuckets) -> dict:
    """Return {iso2: count} for the given integer IPs."""
    return dict(bucket_ips(ip_iter, buckets))
