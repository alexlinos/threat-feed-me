"""Build-time generator: collapse a GeoIP source into the compact /16 table.

Usage:
    python -m threatfeedme.geo.generate --csv GeoLite2-Country-Locations-en.csv GeoLite2-Country-Blocks-IPv4.csv
    python -m threatfeedme.geo.generate --pairs /16-country.txt

Inputs:
  --csv  two GeoLite2 Country CSVs: the locations file (to map geoname_id ->
         ISO alpha-2) and the IPv4 blocks file (start_ip, mask, geoname_id).
         For each /16 we pick the most frequent country across its covering
         blocks, so the output is accurate to /16 granularity — enough for a
         country heatmap.
  --pairs  a plain text file with one line per /16 -> country, e.g.
         "1.0.0.0 US" or "1.0.0.0/16 US". Fastest path if you already have a
         collapsed table.

Output: src/threatfeedme/geo/country-buckets.geo1
"""
import argparse
import struct
from collections import Counter
from pathlib import Path
from ipaddress import ip_address, ip_network

from .countries import known_codes
from .data import BUCKET_COUNT, MAGIC, VERSION, UNMAPPED

OUT = Path(__file__).with_name("country-buckets.geo1")


def _parse_geolite(blocks_csv, locations_csv):
    # locations: geoname_id -> iso code
    loc = {}
    with open(locations_csv, encoding="utf-8") as f:
        header = f.readline().strip().split(",")
        # columns: geoname_id, ..., country_iso_code, ...
        gi = header.index("geoname_id")
        ci = header.index("country_iso_code")
        for line in f:
            row = line.split(",")
            if len(row) <= max(gi, ci):
                continue
            gid = row[gi].strip().strip('"')
            iso = row[ci].strip().strip('"')
            if iso and len(iso) == 2:
                loc[gid] = iso
    # blocks: accumulate country votes per /16
    votes = {}
    with open(blocks_csv, encoding="utf-8") as f:
        header = f.readline().strip().split(",")
        # columns: network, geoname_id, ...
        ni = next(i for i, h in enumerate(header) if "network" in h)
        gi = next(i for i, h in enumerate(header) if "geoname_id" in h)
        for line in f:
            row = line.split(",")
            if len(row) <= max(ni, gi):
                continue
            net = row[ni].strip().strip('"')
            gid = row[gi].strip().strip('"')
            iso = loc.get(gid)
            if not iso:
                continue
            try:
                n = ip_network(net)
            except Exception:
                continue
            idx = int(n.network_address) >> 16
            weight = 1 << max(0, 16 - n.prefixlen) if n.prefixlen < 16 else 1
            c = votes.setdefault(idx, Counter())
            c[iso] += weight
    # pick most frequent country per /16
    table = {}
    for idx, c in votes.items():
        table[idx] = c.most_common(1)[0][0]
    return table


def _parse_pairs(pairs_txt):
    table = {}
    for line in Path(pairs_txt).read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        net = parts[0]
        iso = parts[1].upper()
        try:
            if "/" in net:
                n = ip_network(net)
            else:
                n = ip_network(f"{net}/16")
        except Exception:
            continue
        idx = int(n.network_address) >> 16
        table[idx] = iso
    return table


def generate(table, codes, out=OUT):
    # codes: index -> iso, built from table values, in a stable order
    used = sorted({iso for iso in table.values() if iso in codes})
    # keep only codes we know; unknown codes map to ZZ
    code_index = {iso: i for i, iso in enumerate(used)}
    header = struct.pack("<IHHI", MAGIC, VERSION, 0, len(used))
    code_tbl = "".join(used).encode("latin-1")
    buckets = bytearray()
    for idx in range(BUCKET_COUNT):
        iso = table.get(idx)
        if iso in code_index:
            buckets += struct.pack("<H", code_index[iso])
        else:
            buckets += struct.pack("<H", UNMAPPED)
    out.write_bytes(header + code_tbl + bytes(buckets))
    mapped = sum(1 for idx in range(BUCKET_COUNT) if idx in table and table[idx] in code_index)
    print(f"wrote {out} ({out.stat().st_size} bytes), {mapped}/65536 /16s mapped")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--csv", nargs=2, metavar=("LOCATIONS", "BLOCKS"))
    p.add_argument("--pairs", help="plain /16 -> country text file")
    a = p.parse_args()
    codes = set(known_codes())
    if a.csv:
        table = _parse_geolite(a.csv[1], a.csv[0])
    elif a.pairs:
        table = _parse_pairs(a.pairs)
    else:
        p.error("need --csv or --pairs")
    generate(table, codes)


if __name__ == "__main__":
    main()
