"""Geo heatmap package: compact /16 -> country table + SVG choropleth.

Modules:
  data.py     packed /16 -> country lookup (fully offline at runtime)
  buckets.py  server-side country bucketing of indicator IPs
  render.py   static SVG world choropleth
  generate.py build-time generator (collapses GeoLite2 into the compact table)
  countries.py ISO-3166 codes + names
"""
from .data import CountryBuckets
from .buckets import country_totals
from .render import render_choropleth, render_country_bars

__all__ = [
    "CountryBuckets",
    "country_totals",
    "render_choropleth",
    "render_country_bars",
]
