"""Compact /16 -> country lookup.

The runtime geo table is a flat, packed binary file:

    header (12 bytes):
      magic   u32  0x47454F31  ("GEO1")
      version u16  1
      flags   u16  0
      ncodes  u32  number of distinct country codes in the table

    code table: ncodes * 2 bytes, each a 2-byte ISO-3166 alpha-2 code
                (two ASCII chars, big-endian so 'US' = 0x5553)

    buckets:   65536 * 2 bytes, little-endian u16 index into the code table.
               0xFFFF marks "unmapped/unknown" (no country data for that /16).

A /16 index is `A*256 + B` for the network `A.B.0.0/16`. So any IPv4 can be
bucketed to its /16 in O(1): `ip >> 16` gives the index directly.

Total size: 12 + ncodes*2 + 131072 bytes. For ~200 codes that is ~131KB —
fully self-contained and cheap to load into a 131KB bytes object.
"""
import struct
from pathlib import Path

MAGIC = 0x47454F31  # "GEO1"
VERSION = 1
BUCKET_COUNT = 65536
UNMAPPED = 0xFFFF

_DEFAULT = Path(__file__).with_name("country-buckets.geo1")


class CountryBuckets:
    """Loads and serves the packed /16 -> country table."""

    def __init__(self, data: bytes):
        if len(data) < 12:
            raise ValueError("geo table too small")
        magic, version, flags, ncodes = struct.unpack_from("<IHHI", data, 0)
        if magic != MAGIC:
            raise ValueError("bad geo table magic")
        if version != VERSION:
            raise ValueError("unsupported geo table version")
        self._ncodes = ncodes
        off = 12
        self._codes = data[off : off + ncodes * 2].decode("latin-1", "replace")
        off += ncodes * 2
        body = data[off : off + BUCKET_COUNT * 2]
        if len(body) != BUCKET_COUNT * 2:
            raise ValueError("geo table bucket body truncated")
        self._buckets = body

    @classmethod
    def load(cls, path=None):
        path = Path(path or _DEFAULT)
        if not path.exists():
            raise FileNotFoundError(
                f"compact geo table missing: {path}. Run "
                "`python -m threatfeedme.geo.generate --dbip <dbip-country-lite.csv>` "
                "to build it."
            )
        return cls(path.read_bytes())

    def country_for_ip(self, ip_int: int) -> str:
        """ISO-3166 alpha-2 code for an integer IPv4, or 'ZZ' if unmapped."""
        idx = (ip_int >> 16) & 0xFFFF
        # idx is already the /16 index: A.B.0.0/16 -> A*256+B = ip_int>>16
        code_idx = struct.unpack_from("<H", self._buckets, idx * 2)[0]
        if code_idx == UNMAPPED or code_idx >= self._ncodes:
            return "ZZ"
        return self._codes[code_idx * 2 : code_idx * 2 + 2]

    def country_for_ip_str(self, ip: str) -> str:
        from ipaddress import ip_address

        try:
            return self.country_for_ip(int(ip_address(ip)))
        except Exception:
            return "ZZ"
