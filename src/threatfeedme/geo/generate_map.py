"""Build-time generator: GeoJSON country borders -> compact SVG path data.

    python -m threatfeedme.geo.generate_map ne_110m_admin_0_countries.geojson

Source: Natural Earth 1:110m Admin 0 Countries, which is in the **public
domain** (no attribution required, though credited in the README). Fetch the
GeoJSON from https://github.com/nvkelso/natural-earth-vector.

Output: src/threatfeedme/static/world-paths.json —
{"paths": {iso2: "M... Z"}, "names": {iso2: "Country"}} in a viewBox of
WIDTH x HEIGHT, ready to drop straight into an <svg>. Names are included so
countries with no blocked indicators still label themselves on hover (the
counts API only returns countries that have some). The dashboard fetches
this once when the heatmap is expanded and shades each country client-side,
so there is no runtime map service and no tiles.

Projection is equirectangular (lon/lat scaled linearly). It is not
area-accurate, but for "which countries are attacking me" it reads correctly
and costs nothing to compute.

Size control: coordinates are rounded to one decimal and rings smaller than
MIN_AREA are dropped, which discards specks too small to see while keeping
every country that has any visible landmass.
"""
import argparse
import json
from pathlib import Path

WIDTH = 1000.0
HEIGHT = 500.0
# Latitude cutoff: below this, the map is Antarctica and empty ocean. Cropping
# it removes a large dead band and lets the populated world render bigger.
LAT_MIN = -58.0
LAT_MAX = 84.0
MIN_AREA = 0.8          # in projected square units; drops invisible specks
PRECISION = 1
# Ramer-Douglas-Peucker tolerance in projected units. The map displays ~900px
# wide, so 0.7 units (~0.6px) is below what a viewer can resolve but removes
# most of the vertices in a 110m coastline. Page weight matters more than
# coastline fidelity here.
SIMPLIFY_EPS = 0.7

OUT = Path(__file__).resolve().parents[1] / "static" / "world-paths.json"


def _project(lon, lat):
    x = (lon + 180.0) * (WIDTH / 360.0)
    y = (LAT_MAX - lat) * (HEIGHT / (LAT_MAX - LAT_MIN))
    return x, y


def _ring_area(pts):
    """Shoelace area of a projected ring, used only to drop tiny islands."""
    a = 0.0
    for i in range(len(pts)):
        x1, y1 = pts[i]
        x2, y2 = pts[(i + 1) % len(pts)]
        a += x1 * y2 - x2 * y1
    return abs(a) / 2.0


def _simplify(pts, eps):
    """Ramer-Douglas-Peucker, iterative so a long coastline can't blow the
    recursion limit. Keeps the points that carry the shape."""
    if len(pts) < 3:
        return pts
    keep = [False] * len(pts)
    keep[0] = keep[-1] = True
    stack = [(0, len(pts) - 1)]
    while stack:
        first, last = stack.pop()
        if last <= first + 1:
            continue
        x1, y1 = pts[first]
        x2, y2 = pts[last]
        dx, dy = x2 - x1, y2 - y1
        norm = (dx * dx + dy * dy) ** 0.5
        worst, worst_i = -1.0, first
        for i in range(first + 1, last):
            px, py = pts[i]
            if norm == 0:
                dist = ((px - x1) ** 2 + (py - y1) ** 2) ** 0.5
            else:
                dist = abs(dy * px - dx * py + x2 * y1 - y2 * x1) / norm
            if dist > worst:
                worst, worst_i = dist, i
        if worst > eps:
            keep[worst_i] = True
            stack.append((first, worst_i))
            stack.append((worst_i, last))
    return [p for p, k in zip(pts, keep) if k]


def _ring_to_path(ring):
    pts = []
    last = None
    for lon, lat in ring:
        if lat < LAT_MIN or lat > LAT_MAX:
            lat = max(LAT_MIN, min(LAT_MAX, lat))
        x, y = _project(lon, lat)
        p = (round(x, PRECISION), round(y, PRECISION))
        if p != last:               # collapse duplicate points after rounding
            pts.append(p)
            last = p
    if len(pts) < 3:
        return None, 0.0
    area = _ring_area(pts)          # measured before simplifying
    pts = _simplify(pts, SIMPLIFY_EPS)
    if len(pts) < 3:
        return None, 0.0
    # Trim trailing ".0" — a third of the bytes in a coordinate list.
    fmt = lambda v: f"{v:g}"
    d = "M" + "L".join(f"{fmt(x)} {fmt(y)}" for x, y in pts) + "Z"
    return d, area


def _feature_paths(geom):
    polys = []
    if geom["type"] == "Polygon":
        polys = [geom["coordinates"]]
    elif geom["type"] == "MultiPolygon":
        polys = geom["coordinates"]
    out = []
    for poly in polys:
        for ring in poly:           # ring 0 is outer, rest are holes
            d, area = _ring_to_path(ring)
            if d and area >= MIN_AREA:
                out.append(d)
    return out


def build(geojson_path, out=OUT):
    data = json.loads(Path(geojson_path).read_text(encoding="utf-8"))
    paths, names = {}, {}
    skipped = []
    for feat in data.get("features", []):
        props = feat.get("properties", {})
        iso = (props.get("ISO_A2_EH") or props.get("ISO_A2") or "").strip().upper()
        # Natural Earth uses "-99" for disputed/unrecognised entities.
        if len(iso) != 2 or iso == "-9":
            skipped.append(props.get("NAME"))
            continue
        segs = _feature_paths(feat.get("geometry") or {})
        if segs:
            paths[iso] = "".join(segs)
            names[iso] = props.get("NAME") or iso
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"paths": paths, "names": names},
                              separators=(",", ":")), encoding="utf-8")
    kb = out.stat().st_size / 1024
    print(f"wrote {out} ({kb:.0f} KB), {len(paths)} countries"
          + (f", skipped {len(skipped)} without ISO codes" if skipped else ""))
    return paths


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("geojson", help="Natural Earth admin_0_countries GeoJSON")
    a = p.parse_args()
    build(a.geojson)


if __name__ == "__main__":
    main()
