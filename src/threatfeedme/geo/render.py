"""Static SVG world choropleth renderer.

Takes {iso2: count} and a country-path map (iso2 -> SVG <path d=...>), and
emits an inline SVG where each country is filled with an opacity proportional
to its share of blocked IPs. Fully static — no tiles, no external calls.

The country-path map lives in world_paths.py (a compact, simplified
public-domain world map). Countries not present in the map simply don't
render; the legend lists the top offenders by name so the map stays honest.
"""
from .countries import code_name

# fill ramp: 0.06 .. 0.95 opacity, warm reds, on a dark surface
def _ramp(share):
    return max(0.06, min(0.95, share))


def render_choropleth(counts, world_paths, width=860, height=430, view="0 0 860 430"):
    """counts: {iso2: count} (int). world_paths: {iso2: path_d_str}."""
    total = sum(counts.values()) or 1
    # build cells in descending count so the heaviest are drawn last / on top
    ranked = sorted(counts.items(), key=lambda kv: -kv[1])
    cells = []
    for iso, n in ranked:
        d = world_paths.get(iso)
        if not d:
            continue
        share = n / total
        op = _ramp(share)
        cells.append(
            f'<path d="{d}" fill="#e0b0ff" fill-opacity="{op:.3f}" '
            f'stroke="#1a1a2e" stroke-width="0.35" '
            f'data-country="{iso}" data-count="{n}"/>'
        )
    # legend: top 10 countries
    legend = []
    for iso, n in ranked[:10]:
        legend.append(f'<span class="geo-legend-item">{code_name(iso)} ({n})</span>')
    legend_html = "".join(legend) if legend else "<span>no geo data</span>"

    return f"""<svg class="geo-choropleth" width="{width}" height="{height}"
 viewBox="{view}" xmlns="http://www.w3.org/2000/svg">
 <rect width="100%" height="100%" fill="#101024"/>
 {''.join(cells)}
 <text x="12" y="20" fill="#8ab4ff" font-size="13" font-family="monospace"
   font-weight="600">blocked IP country heatmap</text>
 <text x="{width-8}" y="20" fill="#8ab4ff" font-size="12"
   font-family="monospace" text-anchor="end">total {total}</text>
</svg>
<div class="geo-legend">{legend_html}</div>"""


def render_country_bars(counts, top=12):
    """Fallback list view (when map paths unavailable): top countries + bars."""
    total = sum(counts.values()) or 1
    rows = []
    for iso, n in counts.most_common(top):
        pct = 100.0 * n / total
        rows.append(
            f'<div class="geo-bar-row"><span class="geo-bar-name">'
            f'{code_name(iso)}</span><span class="geo-bar-val">{n} '
            f'({pct:.1f}%)</span></div>'
        )
    return f'<div class="geo-bars">{ "".join(rows) }</div>'
