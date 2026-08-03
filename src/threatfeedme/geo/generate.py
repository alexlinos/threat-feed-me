"""Build-time generator: collapse an IP-to-country source into the compact
/16 table.

Usage:
    python -m threatfeedme.geo.generate --dbip dbip-country-lite.csv
    python -m threatfeedme.geo.generate --pairs /16-country.txt
    python -m threatfeedme.geo.generate --csv Locations.csv Blocks-IPv4.csv

LICENSING — read before regenerating and redistributing:
  The table shipped in this repo is built from DB-IP's free IP-to-Country
  Lite database, which is CC-BY licensed: redistribution is permitted with
  attribution (see the Geo attribution section of the README). Use --dbip
  to reproduce it.

  --csv accepts MaxMind GeoLite2 Country CSVs. GeoLite2 is NOT CC-BY; its
  EULA restricts redistribution and imposes update obligations. A table
  built that way is fine for your own deployment, but do not commit or
  redistribute it under this project's DB-IP attribution.

Inputs:
  --dbip   DB-IP IP-to-Country Lite CSV: start_ip,end_ip,country_code with
           no header. Ranges are expanded across the /16s they cover, and
           each /16 takes the country with the most addresses in it.
  --pairs  a plain text file with one line per /16 -> country, e.g.
           "1.0.0.0 US" or "1.0.0.0/16 US". Fastest path if you already have
           a collapsed table.
  --csv    two GeoLite2 Country CSVs: the locations file (geoname_id -> ISO
           alpha-2) and the IPv4 blocks file. See the licensing note above.

Note on granularity: /16 buckets mean an IP inherits the dominant country of
its /16, so small allocations inside a mixed /16 can be misattributed. That
is an accepted trade-off for a 131KB offline table with no runtime lookups.

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


def _parse_dbip(csv_path):
    """DB-IP IP-to-Country Lite: start_ip,end_ip,country_code (no header).

    A range can span many /16s and several ranges can share one /16, so each
    /16 is awarded to whichever country covers the most addresses in it.
    """
    votes = {}
    with open(csv_path, encoding="utf-8") as f:
        for line in f:
            row = [c.strip().strip('"') for c in line.split(",")]
            if len(row) < 3:
                continue
            start_s, end_s, iso = row[0], row[1], row[2].upper()
            if len(iso) != 2:
                continue
            try:
                start, end = int(ip_address(start_s)), int(ip_address(end_s))
            except ValueError:
                continue  # skips IPv6 rows, which share the file
            if end < start or start > 0xFFFFFFFF:
                continue
            first_bucket, last_bucket = start >> 16, min(end, 0xFFFFFFFF) >> 16
            # Guard against a malformed row claiming the whole address space.
            if last_bucket - first_bucket > BUCKET_COUNT:
                continue
            for idx in range(first_bucket, last_bucket + 1):
                lo = max(start, idx << 16)
                hi = min(end, (idx << 16) | 0xFFFF)
                votes.setdefault(idx, Counter())[iso] += hi - lo + 1
    return {idx: c.most_common(1)[0][0] for idx, c in votes.items()}


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
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--dbip", help="DB-IP IP-to-Country Lite CSV (CC-BY; the shipped source)")
    p.add_argument("--csv", nargs=2, metavar=("LOCATIONS", "BLOCKS"),
                   help="MaxMind GeoLite2 Country CSVs — NOT CC-BY, do not redistribute")
    p.add_argument("--pairs", help="plain /16 -> country text file")
    a = p.parse_args()
    codes = set(known_codes())
    if a.dbip:
        table = _parse_dbip(a.dbip)
    elif a.csv:
        print("NOTE: GeoLite2 output is not CC-BY — do not redistribute the "
              "generated table under this project's DB-IP attribution.")
        table = _parse_geolite(a.csv[1], a.csv[0])
    elif a.pairs:
        table = _parse_pairs(a.pairs)
    else:
        p.error("need --dbip, --csv or --pairs")
    generate(table, codes)


if __name__ == "__main__":
    main()
