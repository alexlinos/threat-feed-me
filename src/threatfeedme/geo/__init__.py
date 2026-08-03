"""Geo package: offline /16 -> country lookup for the dashboard heatmap.

Modules:
  data.py      packed /16 -> country table (fully offline at runtime)
  buckets.py   country bucketing of indicator IPs
  generate.py  build-time generator for the compact table
  countries.py ISO-3166 codes + names

The heatmap is rendered client-side from /api/geo/countries; there is no
server-side SVG rendering here.
"""
from .data import CountryBuckets
from .buckets import country_totals

__all__ = ["CountryBuckets", "country_totals"]
