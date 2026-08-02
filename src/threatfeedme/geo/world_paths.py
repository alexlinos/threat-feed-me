"""Country-path map for the SVG choropleth.

This file is normally a compact simplified world-map: a dict mapping
ISO-3166 alpha-2 -> SVG <path d="...">. It is populated by a build step
(see generate.py) from a public-domain simplified world map. It is kept
OUT of the runtime path so the feature degrades gracefully to the country
bars fallback until the map file is present.
"""
WORLD_PATHS = {}

def available():
    return bool(WORLD_PATHS)
