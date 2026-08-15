"""SQLite database layer for Threat Feed Me!
"""
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone, timedelta
from typing import List, Optional, Dict, Any, Set, Tuple
import json
import os

from threatfeedme.models import (ThreatIndicator, WhitelistEntry, ConfidenceTier, FeedStats,
                    FeedSource, FeedType, ALL_FEEDS, REASON_FALSE_POSITIVE, REASON_OTHER,
                    WhitelistMatcher)
from .geo.data import CountryBuckets


def _utcnow_iso() -> str:
    """Timezone-aware UTC timestamp as an ISO string."""
    return datetime.now(timezone.utc).isoformat()


def _meta_cidr(meta: Dict) -> str:
    """Return the CIDR string from metadata, or None."""
    return meta.get('cidr') if meta else None


# Feed fields that are mechanics (bug-fixable plumbing) rather than operator
# preferences. sync_default_feeds applies shipped changes to these on any
# seed-provenance row; enabled/weight/update_interval are never synced.
_PLUMBING_FIELDS = ('url', 'feed_type', 'requires_auth', 'auth_env',
                    'auth_header', 'local_file', 'scraper')


def _plumbing_differs(a: FeedSource, b: FeedSource) -> bool:
    return any(getattr(a, f) != getattr(b, f) for f in _PLUMBING_FIELDS)


def _feed_fingerprint(feed: FeedSource) -> str:
    """Stable digest of a feed definition's seedable fields.

    Its role since the plumbing/preference split: a NON-NULL value marks the
    row as seed/sync/restore provenance, whose PLUMBING (url/scraper/auth/
    type) follows shipped defaults on upgrade. A dashboard add/override
    stores NULL (see add_feed), freezing the row — that is the operator's
    way of owning a feed's plumbing. Preferences (enabled/weight/interval)
    are never synced either way."""
    return json.dumps({
        'url': feed.url,
        'feed_type': feed.feed_type.value,
        'weight': feed.weight,
        'update_interval': feed.update_interval,
        'requires_auth': bool(feed.requires_auth),
        'auth_env': feed.auth_env,
        'auth_header': feed.auth_header or 'Authorization',
        'local_file': bool(feed.local_file),
        'scraper': feed.scraper,
        'enabled': bool(feed.enabled),
    }, sort_keys=True)


class Database:
    def __init__(self, db_path: str = "./data/threatfeedme.db"):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._init_schema()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA busy_timeout = 5000")
        return conn

    @contextmanager
    def _cursor(self):
        """Acquire cursor, commit on success, always close."""
        conn = self._get_connection()
        try:
            yield conn.cursor()
            conn.commit()
        finally:
            conn.close()

    # ---- Factory helpers ----

    @staticmethod
    def _row_to_indicator(row, tier_override=None) -> ThreatIndicator:
        """Build a ThreatIndicator from a SQLite row (with sources_str or
        separate source query)."""
        meta = json.loads(row['metadata']) if row['metadata'] else {}
        sources_str = row['sources_str'] if 'sources_str' in row.keys() else ''
        sources = sources_str.split(',') if sources_str else []
        tier = tier_override if tier_override is not None else ConfidenceTier(row['tier'])
        kind_val = row['kind'] if 'kind' in row.keys() else 'ip'
        return ThreatIndicator(
            ip=row['ip'],
            sources=sources,
            first_seen=row['first_seen'],
            last_seen=row['last_seen'],
            confidence_score=row['confidence_score'],
            tier=tier,
            metadata=meta,
            effective_votes=(row['effective_votes']
                            if 'effective_votes' in row.keys() else None),
            kind=kind_val,
        )

    # ==================== SCHEMA ====================

    def _init_schema(self):
        conn = self._get_connection()
        try:
            cursor = conn.cursor()

            cursor.execute("PRAGMA journal_mode = WAL")

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS indicators (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT UNIQUE NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    confidence_score REAL DEFAULT 0.0,
                    tier TEXT DEFAULT 'low',
                    metadata TEXT DEFAULT '{}',
                    effective_votes REAL,
                    kind TEXT NOT NULL DEFAULT 'ip'
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS indicator_sources (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    indicator_id INTEGER NOT NULL,
                    source_name TEXT NOT NULL,
                    reported_at TEXT NOT NULL,
                    FOREIGN KEY (indicator_id) REFERENCES indicators(id) ON DELETE CASCADE,
                    UNIQUE(indicator_id, source_name)
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS whitelist (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT NOT NULL,
                    feed_name TEXT NOT NULL DEFAULT '*',
                    reason TEXT NOT NULL,
                    added_by TEXT NOT NULL,
                    added_at TEXT NOT NULL,
                    expires_at TEXT,
                    UNIQUE(ip, feed_name)
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS feed_stats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    feed_name TEXT NOT NULL,
                    total_indicators INTEGER DEFAULT 0,
                    last_update TEXT NOT NULL,
                    status TEXT NOT NULL,
                    error_message TEXT
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS feeds (
                    name TEXT PRIMARY KEY,
                    url TEXT NOT NULL,
                    feed_type TEXT NOT NULL DEFAULT 'custom',
                    weight REAL NOT NULL DEFAULT 0.5,
                    update_interval INTEGER NOT NULL DEFAULT 3600,
                    requires_auth INTEGER NOT NULL DEFAULT 0,
                    auth_env TEXT,
                    auth_header TEXT DEFAULT 'Authorization',
                    local_file INTEGER NOT NULL DEFAULT 0,
                    scraper TEXT,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    added_by TEXT,
                    added_at TEXT,
                    seed_fingerprint TEXT
                )
            """)

            # Tombstones for deliberately removed default feeds, so an app
            # update (sync_default_feeds) never resurrects a feed the operator
            # deleted. Cleared when the feed is explicitly re-added.
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS deleted_feeds (
                    name TEXT PRIMARY KEY,
                    deleted_at TEXT NOT NULL
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS feed_feedback (
                    feed_name TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    reason_code TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(feed_name, ip)
                )
            """)

            # Legacy whitelist migration
            existing_cols = [r[1] for r in cursor.execute("PRAGMA table_info(whitelist)").fetchall()]
            if existing_cols and 'feed_name' not in existing_cols:
                try:
                    cursor.executescript("""
                        ALTER TABLE whitelist RENAME TO whitelist_legacy;
                        CREATE TABLE whitelist (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            ip TEXT NOT NULL,
                            feed_name TEXT NOT NULL DEFAULT '*',
                            reason TEXT NOT NULL,
                            added_by TEXT NOT NULL,
                            added_at TEXT NOT NULL,
                            expires_at TEXT,
                            UNIQUE(ip, feed_name)
                        );
                        INSERT INTO whitelist (id, ip, feed_name, reason, added_by, added_at, expires_at)
                            SELECT id, ip, '*', reason, added_by, added_at, expires_at FROM whitelist_legacy;
                        DROP TABLE whitelist_legacy;
                    """)
                except sqlite3.OperationalError:
                    cols = [r[1] for r in cursor.execute("PRAGMA table_info(whitelist)").fetchall()]
                    if 'feed_name' not in cols:
                        raise

            # Additive migrations
            wl_cols = [r[1] for r in cursor.execute("PRAGMA table_info(whitelist)").fetchall()]
            if wl_cols and 'reason_code' not in wl_cols:
                try:
                    cursor.execute("ALTER TABLE whitelist ADD COLUMN reason_code TEXT NOT NULL DEFAULT 'other'")
                except sqlite3.OperationalError:
                    pass

            fs_cols = [r[1] for r in cursor.execute("PRAGMA table_info(feed_stats)").fetchall()]
            for col in ('etag', 'last_modified'):
                if fs_cols and col not in fs_cols:
                    try:
                        cursor.execute(f"ALTER TABLE feed_stats ADD COLUMN {col} TEXT")
                    except sqlite3.OperationalError:
                        pass

            f_cols = [r[1] for r in cursor.execute("PRAGMA table_info(feeds)").fetchall()]
            if f_cols and 'scraper' not in f_cols:
                try:
                    cursor.execute("ALTER TABLE feeds ADD COLUMN scraper TEXT")
                except sqlite3.OperationalError:
                    pass
            # Upgrade migration: pre-existing databases get the fingerprint
            # column with NULL values, which sync_default_feeds treats as
            # "possibly customized" — existing rows are never auto-updated,
            # only genuinely new defaults are added.
            if f_cols and 'seed_fingerprint' not in f_cols:
                try:
                    cursor.execute("ALTER TABLE feeds ADD COLUMN seed_fingerprint TEXT")
                except sqlite3.OperationalError:
                    pass

            # Defensive: every released version ships reported_at in the CREATE TABLE
            # above (since v1.0.0), so no real upgrade lacks it. This keeps the block
            # uniform with the other additive column adds and covers a hand-built or
            # hand-repaired database. Backfilled rows get NULL, which the telemetry
            # freshness window filters out (NULL >= ? is false); fetches fill it going
            # forward.
            is_cols = [r[1] for r in cursor.execute("PRAGMA table_info(indicator_sources)").fetchall()]
            if is_cols and 'reported_at' not in is_cols:
                try:
                    cursor.execute("ALTER TABLE indicator_sources ADD COLUMN reported_at TEXT")
                except sqlite3.OperationalError:
                    pass

            # Upgrade migration: overlap-discounted vote count per indicator
            # (v1.8 effective-votes tiering). NULL until the first rescore.
            i_cols = [r[1] for r in cursor.execute("PRAGMA table_info(indicators)").fetchall()]
            if i_cols and 'effective_votes' not in i_cols:
                try:
                    cursor.execute("ALTER TABLE indicators ADD COLUMN effective_votes REAL")
                except sqlite3.OperationalError:
                    pass

            # Domain intel v2.0: additive `kind` column on indicators ('ip'
            # default, 'domain'). The value stays in the existing `ip` column
            # (documented as "the indicator value"), so every UNIQUE and index
            # keeps working without a table rebuild. Existing rows default to
            # 'ip' so IP-only databases upgrade untouched.
            if i_cols and 'kind' not in i_cols:
                try:
                    cursor.execute("ALTER TABLE indicators ADD COLUMN kind TEXT NOT NULL DEFAULT 'ip'")
                except sqlite3.OperationalError:
                    pass

            # Domain intel v2.0: feeds declare their indicator kind. Existing
            # rows default to 'ip' (the historical behaviour; IP feeds are the
            # vast majority, and a freshly-created table already carries the
            # column via the CREATE TABLE above).
            f_cols = [r[1] for r in cursor.execute("PRAGMA table_info(feeds)").fetchall()]
            if f_cols and 'indicator_kind' not in f_cols:
                try:
                    cursor.execute("ALTER TABLE feeds ADD COLUMN indicator_kind TEXT NOT NULL DEFAULT 'ip'")
                except sqlite3.OperationalError:
                    pass

            cursor.execute("CREATE INDEX IF NOT EXISTS idx_indicators_ip ON indicators(ip)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_indicators_tier ON indicators(tier)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_sources_indicator ON indicator_sources(indicator_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_whitelist_ip ON whitelist(ip)")

            conn.commit()
        finally:
            conn.close()

    # ==================== INDICATOR OPERATIONS ====================

    def add_indicator(self, ip: str, source: str, metadata: Dict = None, kind: str = "ip") -> int:
        """Add or update an indicator from a feed source"""
        now = _utcnow_iso()
        meta_json = json.dumps(metadata or {})
        with self._cursor() as cur:
            cur.execute("SELECT id, kind FROM indicators WHERE ip = ?", (ip,))
            row = cur.fetchone()
            if row:
                indicator_id = row[0]
                # Preserve the existing row's kind on update: an IP row stays
                # an IP row, a domain row stays a domain row. The value in the
                # `ip` column is the indicator value either way.
                cur.execute(
                    "UPDATE indicators SET last_seen = ?, metadata = json_patch(COALESCE(metadata, '{}'), ?), kind = ? WHERE ip = ?",
                    (now, meta_json, row[1], ip),
                )
            else:
                cur.execute(
                    "INSERT INTO indicators (ip, first_seen, last_seen, metadata, kind) VALUES (?, ?, ?, ?, ?)",
                    (ip, now, now, meta_json, kind),
                )
                indicator_id = cur.lastrowid
            cur.execute(
                "INSERT OR IGNORE INTO indicator_sources (indicator_id, source_name, reported_at) VALUES (?, ?, ?)",
                (indicator_id, source, now),
            )
            return indicator_id

    # Chunk size for bulk ingest commits: large enough that a 90k-row feed
    # costs ~9 fsyncs instead of 90k, small enough to bound WAL growth and
    # release the write lock periodically for other writers.
    BULK_CHUNK = 10_000

    def add_indicators_bulk(self, rows: List[tuple], source: str, kind: str = "ip") -> int:
        """Add or update many indicators from one feed source.

        `rows` is a list of (ip, metadata) tuples. Semantically identical to
        calling add_indicator() per row — first_seen preserved on update,
        metadata json_patch-merged, earliest reported_at kept — but on a
        single connection with chunked commits. add_indicator() commits
        (fsyncs) per call, which wedged the refresh on large feeds.
        """
        if not rows:
            return 0
        now = _utcnow_iso()
        conn = self._get_connection()
        try:
            cur = conn.cursor()
            for start in range(0, len(rows), self.BULK_CHUNK):
                chunk = rows[start:start + self.BULK_CHUNK]
                cur.executemany(
                    "INSERT INTO indicators (ip, first_seen, last_seen, metadata, kind) VALUES (?, ?, ?, ?, ?) "
                    "ON CONFLICT(ip) DO UPDATE SET last_seen = excluded.last_seen, "
                    "metadata = json_patch(COALESCE(metadata, '{}'), excluded.metadata), "
                    "kind = excluded.kind",
                    [(ip, now, now, json.dumps(meta or {}), kind) for ip, meta in chunk],
                )
                cur.executemany(
                    "INSERT OR IGNORE INTO indicator_sources (indicator_id, source_name, reported_at) "
                    "SELECT id, ?, ? FROM indicators WHERE ip = ?",
                    [(source, now, ip) for ip, _meta in chunk],
                )
                conn.commit()
            return len(rows)
        finally:
            conn.close()

    def get_indicators_by_kind(self, kind: str = "ip") -> List[ThreatIndicator]:
        """All indicators of a specific kind (used by the kind-filtered
        feed URLs; IP and domain populations never bleed into each other)."""
        with self._cursor() as cur:
            cur.execute(
                "SELECT i.*, (SELECT GROUP_CONCAT(source_name) FROM indicator_sources "
                "WHERE indicator_id = i.id) AS sources_str "
                "FROM indicators i WHERE i.kind = ? ORDER BY i.confidence_score DESC",
                (kind,),
            )
            return [self._row_to_indicator(r) for r in cur.fetchall()]

    def get_indicators_by_kind_and_tiers(self, kind: str, tiers,
                                         batch: int = 5000) -> List[ThreatIndicator]:
        """Indicators of a specific kind in one or more tiers (cumulative
        serving). Streams in batches; mid-tier rows are collected here."""
        out = []
        marks = ",".join("?" * len(tiers))
        with self._cursor() as cur:
            cur.execute(
                "SELECT i.*, (SELECT GROUP_CONCAT(source_name) FROM indicator_sources "
                "WHERE indicator_id = i.id) AS sources_str "
                f"FROM indicators i WHERE i.kind = ? AND i.tier IN ({marks}) "
                "ORDER BY i.confidence_score DESC",
                (kind,) + tuple(t.value for t in tiers),
            )
            for r in cur.fetchall():
                out.append(self._row_to_indicator(r))
        return out

    def get_domain_tld_counts(self) -> list:
        """Count domain indicators by TLD (last label after the final dot).
        Returns [(tld, count), ...] sorted by count descending, used by the
        dashboard TLD panel (ranked bars).

        Counted in Python: SQLite's INSTR finds the FIRST dot, so a pure-SQL
        SUBSTR turns "evil.co.uk" into "co.uk" — not a TLD. The domain corpus
        is small enough (~100k) that a single-column scan is cheap.
        """
        counts: Dict[str, int] = {}
        with self._cursor() as cur:
            cur.execute("SELECT ip FROM indicators WHERE kind = 'domain'")
            for row in cur.fetchall():
                value = row["ip"]
                _, _, tld = value.rpartition('.')
                if not tld:
                    continue
                tld = tld.lower()
                counts[tld] = counts.get(tld, 0) + 1
        return sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))

    def get_indicator(self, ip: str) -> Optional[ThreatIndicator]:
        """Get a single indicator by its value (IP address or domain)."""
        with self._cursor() as cur:
            cur.execute(
                "SELECT i.*, (SELECT GROUP_CONCAT(source_name) FROM indicator_sources WHERE indicator_id = i.id) AS sources_str "
                "FROM indicators i WHERE i.ip = ?", (ip,))
            row = cur.fetchone()
            if not row:
                return None
            return self._row_to_indicator(row)

    def get_all_indicators_by_tier(self, tier: ConfidenceTier) -> List[ThreatIndicator]:
        """Get all indicators in a specific confidence tier"""
        return self.get_all_indicators_by_tiers((tier,))

    def get_all_indicators_by_tiers(self, tiers) -> List[ThreatIndicator]:
        """Indicators whose tier is in `tiers` (for cumulative feed serving:
        medium.txt is every high- OR medium-tier indicator)."""
        return list(self.iter_indicators_by_tiers(tiers))

    def iter_indicators_by_tiers(self, tiers, batch: int = 5000, kind: str = None):
        """Stream indicators whose tier is in `tiers`, in score order.

        Generator so the tier-file exports never hold the whole table as
        model objects — a full materialized list is hundreds of MB at 100k+
        indicators, which OOMed small (2 GB) container deployments when
        exports overlapped with a dashboard load or rescore.

        `kind` filters to one indicator kind ('ip' or 'domain'); None streams
        both. The on-disk tier exports pass it so the *_ips files never
        contain a domain and vice versa (same never-bleed rule as the URLs).
        """
        values = [t.value for t in tiers]
        marks = ",".join("?" * len(values))
        kind_sql = " AND i.kind = ?" if kind is not None else ""
        if kind is not None:
            values = values + [kind]
        conn = self._get_connection()
        try:
            cur = conn.cursor()
            cur.execute(
                "SELECT i.*, (SELECT GROUP_CONCAT(source_name) FROM indicator_sources WHERE indicator_id = i.id) AS sources_str "
                f"FROM indicators i WHERE i.tier IN ({marks}){kind_sql} ORDER BY i.confidence_score DESC",
                values)
            while True:
                rows = cur.fetchmany(batch)
                if not rows:
                    return
                for r in rows:
                    yield self._row_to_indicator(r)
        finally:
            conn.close()

    def get_all_indicators(self) -> List[ThreatIndicator]:
        """Get all indicators regardless of tier"""
        with self._cursor() as cur:
            cur.execute(
                "SELECT i.*, (SELECT GROUP_CONCAT(source_name) FROM indicator_sources WHERE indicator_id = i.id) AS sources_str "
                "FROM indicators i ORDER BY i.confidence_score DESC")
            return [self._row_to_indicator(r) for r in cur.fetchall()]

    def query_indicators(self, q: str = None, limit: int = 50, offset: int = 0,
                         include_whitelisted: bool = False) -> Dict:
        """Paginated/searchable view of merged indicators.

        Excludes globally-whitelisted (removed) IPs by default. Returns
        {'total': int, 'rows': [{ip, value, tier, confidence_score, sources}]}.
        """
        now = _utcnow_iso()
        where, params = [], []
        if not include_whitelisted:
            where.append(
                "i.ip NOT IN (SELECT ip FROM whitelist WHERE feed_name = ? "
                "AND (expires_at IS NULL OR expires_at > ?))"
            )
            params.extend([ALL_FEEDS, now])
        if q:
            where.append("i.ip LIKE ?")
            params.append(f"%{q}%")
        where_sql = (" WHERE " + " AND ".join(where)) if where else ""

        matcher = None
        if not include_whitelisted:
            matcher = self.get_whitelist_map()
        # A globally-scoped RANGE entry (CIDR or domain wildcard) can't be
        # expressed in the SQL NOT IN, so its presence switches to the
        # match-in-Python slow path below.
        has_global_range = matcher is not None and (
            any(ALL_FEEDS in feeds for _net, feeds in matcher.cidr_rules)
            or any(ALL_FEEDS in feeds for _apex, feeds in matcher.wildcard_rules))

        select_sql = f"""
            SELECT i.ip, i.confidence_score, i.tier, i.metadata, i.effective_votes,
                   (SELECT GROUP_CONCAT(source_name) FROM indicator_sources
                    WHERE indicator_id = i.id) AS sources_str
            FROM indicators i{where_sql}
            ORDER BY i.confidence_score DESC, i.ip
        """

        with self._cursor() as cur:
            if not has_global_range:
                cur.execute(f"SELECT COUNT(*) FROM indicators i{where_sql}", params)
                total = cur.fetchone()[0]
                cur.execute(select_sql + " LIMIT ? OFFSET ?", params + [limit, offset])
                page_rows = cur.fetchall()
            else:
                cur.execute(select_sql, params)
                survivors = [r for r in cur.fetchall()
                             if ALL_FEEDS not in matcher.scoped_feeds(r['ip'])]
                total = len(survivors)
                page_rows = survivors[offset:offset + limit]

            rows = []
            for row in page_rows:
                ip = row['ip']
                if matcher is not None and ALL_FEEDS in matcher.scoped_feeds(ip):
                    continue
                meta = json.loads(row['metadata']) if row['metadata'] else {}
                rows.append({
                    "ip": ip,
                    "value": _meta_cidr(meta) or ip,
                    "tier": row['tier'],
                    "confidence_score": round(row['confidence_score'], 3),
                    "effective_votes": (round(row['effective_votes'], 2)
                                        if row['effective_votes'] is not None else None),
                    "sources": (row['sources_str'] or '').split(',') if row['sources_str'] else [],
                })
            return {"total": total, "rows": rows}


    def country_counts(self) -> list:
        """Bucket all stored indicator IPs by country using the compact
        geo table. Returns [(iso2, count), ...] sorted by count desc.

        Read-only aggregation — never hits a network and stores nothing.
        """
        try:
            buckets = CountryBuckets.load()
        except Exception:
            return []
        with self._cursor() as cur:
            cur.execute("SELECT ip FROM indicators")
            rows = cur.fetchall()
        from .geo.buckets import bucket_ip_strings
        return bucket_ip_strings((r["ip"] for r in rows), buckets)

    def geo_cache_key(self) -> tuple:
        """Fingerprint of the indicator corpus for the geo cache.

        Returns (total, max_last_seen). Every auto-refresh touches indicators
        via touch_feed_indicators(), so max_last_seen changes whenever the
        corpus is rewritten — including a rotation that keeps the total the
        same, which a bare count would miss. Two aggregate rows over the whole
        table; no index on last_seen, so COUNT and MAX are full scans, but
        cheap enough to run on every geo request."""
        with self._cursor() as cur:
            cur.execute("SELECT COUNT(*), COALESCE(MAX(last_seen), 0) FROM indicators")
            total, max_last = cur.fetchone()
        return (total or 0, max_last or 0)
    def set_indicator_score(self, ip: str, score: float, tier: str,
                            votes: float = None) -> None:
        """Persist a single indicator's recalculated score/tier (and, when
        provided, its overlap-discounted effective-vote count)."""
        with self._cursor() as cur:
            if votes is None:
                cur.execute(
                    "UPDATE indicators SET confidence_score = ?, tier = ? WHERE ip = ?",
                    (score, tier, ip),
                )
            else:
                cur.execute(
                    "UPDATE indicators SET confidence_score = ?, tier = ?, effective_votes = ? WHERE ip = ?",
                    (score, tier, votes, ip),
                )

    def delete_indicator(self, ip: str) -> bool:
        """Delete an indicator (and, via cascade, its source rows)."""
        with self._cursor() as cur:
            cur.execute("DELETE FROM indicators WHERE ip = ?", (ip,))
            return cur.rowcount > 0

    def purge_stale_indicators(self, max_age_days: int) -> int:
        """Delete indicators whose last_seen is older than max_age_days.

        Manually-curated entries (any indicator with a 'manual' source) are
        never purged. Returns rows deleted.
        """
        if max_age_days <= 0:
            return 0
        cutoff = (datetime.now(timezone.utc) - timedelta(days=max_age_days)).isoformat()
        with self._cursor() as cur:
            cur.execute(
                "DELETE FROM indicators "
                "WHERE last_seen < ? "
                "AND id NOT IN (SELECT DISTINCT indicator_id FROM indicator_sources "
                "WHERE source_name = 'manual')",
                (cutoff,),
            )
            return cur.rowcount

    def touch_feed_indicators(self, feed_name: str) -> int:
        """Refresh last_seen on every indicator attributed to a feed."""
        now = _utcnow_iso()
        with self._cursor() as cur:
            cur.execute(
                "UPDATE indicators SET last_seen = ? "
                "WHERE id IN (SELECT indicator_id FROM indicator_sources "
                "WHERE source_name = ?)",
                (now, feed_name),
            )
            return cur.rowcount

    # ==================== WHITELIST OPERATIONS ====================

    def add_to_whitelist(self, ip: str, reason: str, added_by: str,
                         expires_at: datetime = None, feed_name: str = ALL_FEEDS,
                         reason_code: str = REASON_OTHER) -> bool:
        """Add (or update) a whitelist entry."""
        now = _utcnow_iso()
        expires = expires_at.isoformat() if expires_at else None
        feed_name = feed_name or ALL_FEEDS
        with self._cursor() as cur:
            cur.execute("""
                INSERT INTO whitelist (ip, feed_name, reason, added_by, added_at, expires_at, reason_code)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(ip, feed_name) DO UPDATE SET
                    reason = excluded.reason,
                    added_at = excluded.added_at,
                    expires_at = excluded.expires_at,
                    reason_code = excluded.reason_code
            """, (ip, feed_name, reason, added_by, now, expires, reason_code))
            return True

    def is_whitelisted(self, ip: str) -> bool:
        """True if the IP is globally (ALL_FEEDS) whitelisted and not expired."""
        now = _utcnow_iso()
        with self._cursor() as cur:
            cur.execute(
                "SELECT 1 FROM whitelist WHERE ip = ? AND feed_name = ? AND (expires_at IS NULL OR expires_at > ?)",
                (ip, ALL_FEEDS, now),
            )
            return cur.fetchone() is not None

    def get_whitelisted_ips(self) -> Set[str]:
        """Set of IPs whitelisted from ALL feeds (globally), non-expired."""
        now = _utcnow_iso()
        with self._cursor() as cur:
            cur.execute(
                "SELECT ip FROM whitelist WHERE feed_name = ? AND (expires_at IS NULL OR expires_at > ?)",
                (ALL_FEEDS, now),
            )
            return {row['ip'] for row in cur.fetchall()}

    def get_whitelist_map(self) -> WhitelistMatcher:
        """Map of ip -> set of whitelisted feed names (may include ALL_FEEDS)."""
        now = _utcnow_iso()
        mapping = WhitelistMatcher()
        with self._cursor() as cur:
            cur.execute(
                "SELECT ip, feed_name FROM whitelist WHERE expires_at IS NULL OR expires_at > ?",
                (now,),
            )
            for row in cur.fetchall():
                mapping.setdefault(row['ip'], set()).add(row['feed_name'])
        mapping.add_cidr_rules_from_keys()
        return mapping

    def get_whitelist(self) -> List[WhitelistEntry]:
        """Get all active whitelist entries"""
        now = _utcnow_iso()
        with self._cursor() as cur:
            cur.execute(
                "SELECT * FROM whitelist WHERE expires_at IS NULL OR expires_at > ? ORDER BY added_at DESC",
                (now,),
            )
            results = []
            for row in cur.fetchall():
                results.append(WhitelistEntry(
                    ip=row['ip'],
                    reason=row['reason'],
                    added_by=row['added_by'],
                    added_at=row['added_at'],
                    expires_at=row['expires_at'],
                    feed_name=row['feed_name'],
                    reason_code=row['reason_code'] if 'reason_code' in row.keys() else REASON_OTHER,
                ))
            return results

    def remove_from_whitelist(self, ip: str, feed_name: str = None) -> bool:
        """Remove whitelist entries for an IP.

        feed_name=None removes every scope for the IP; otherwise only the given
        scope (use ALL_FEEDS to remove just the global entry).
        """
        with self._cursor() as cur:
            if feed_name is None:
                cur.execute("DELETE FROM whitelist WHERE ip = ?", (ip,))
            else:
                cur.execute(
                    "DELETE FROM whitelist WHERE ip = ? AND feed_name = ?", (ip, feed_name)
                )
            return cur.rowcount > 0

    # ==================== FEED FALSE-POSITIVE FEEDBACK ====================

    def record_false_positive(self, ip: str, feeds: List[str]) -> None:
        """Attribute a false-positive report of `ip` to each of `feeds`."""
        if not feeds:
            return
        now = _utcnow_iso()
        with self._cursor() as cur:
            cur.executemany(
                "INSERT INTO feed_feedback (feed_name, ip, reason_code, created_at) "
                "VALUES (?, ?, ?, ?) "
                "ON CONFLICT(feed_name, ip) DO UPDATE SET created_at = excluded.created_at",
                [(feed, ip, REASON_FALSE_POSITIVE, now) for feed in feeds],
            )

    def clear_feedback(self, ip: str, feed_name: str = None) -> None:
        """Remove false-positive attributions for an IP.

        feed_name=None clears every feed's attribution for the IP; pass a feed
        name to clear only that one.
        """
        with self._cursor() as cur:
            if feed_name and feed_name != ALL_FEEDS:
                cur.execute(
                    "DELETE FROM feed_feedback WHERE ip = ? AND feed_name = ?", (ip, feed_name)
                )
            else:
                cur.execute("DELETE FROM feed_feedback WHERE ip = ?", (ip,))

    def get_feed_false_positives(self, feed_name: str) -> List[Dict[str, Any]]:
        """False positives attributed to one feed, newest first.

        `whitelisted` reports whether the IP still has a whitelist entry: a
        False here means the attribution is orphaned (the whitelist entry that
        justified it is gone) and the penalty should not still apply.
        """
        with self._cursor() as cur:
            cur.execute(
                "SELECT f.ip, f.created_at, "
                "       EXISTS(SELECT 1 FROM whitelist w WHERE w.ip = f.ip) AS whitelisted "
                "FROM feed_feedback f "
                "WHERE f.feed_name = ? AND f.reason_code = ? "
                "ORDER BY f.created_at DESC",
                (feed_name, REASON_FALSE_POSITIVE),
            )
            return [
                {"ip": r["ip"], "created_at": r["created_at"],
                 "whitelisted": bool(r["whitelisted"])}
                for r in cur.fetchall()
            ]

    def clear_feed_feedback(self, feed_name: str) -> int:
        """Drop every false-positive attribution against one feed, restoring
        its reputation. Returns the number of attributions removed."""
        with self._cursor() as cur:
            cur.execute("DELETE FROM feed_feedback WHERE feed_name = ?", (feed_name,))
            return cur.rowcount

    def purge_orphaned_feedback(self) -> int:
        """Delete false-positive attributions whose whitelist entry no longer
        exists, and return how many were removed.

        The FP penalty is meant to last exactly as long as the whitelist entry
        that justified it ("self-heals when the entry is removed"). Rows can
        outlive their entry — notably from the pre-fix bug where removing a
        tier-scoped entry cleared feedback by the literal 'tier:...' scope and
        matched nothing. Runs at startup so existing databases self-heal
        without operator action.
        """
        with self._cursor() as cur:
            cur.execute(
                "DELETE FROM feed_feedback "
                "WHERE NOT EXISTS (SELECT 1 FROM whitelist w WHERE w.ip = feed_feedback.ip)"
            )
            return cur.rowcount

    def get_feed_fp_counts(self) -> Dict[str, int]:
        """Distinct false-positive IP count per feed."""
        with self._cursor() as cur:
            cur.execute(
                "SELECT feed_name, COUNT(DISTINCT ip) AS n FROM feed_feedback WHERE reason_code = ? GROUP BY feed_name",
                (REASON_FALSE_POSITIVE,),
            )
            return {row['feed_name']: row['n'] for row in cur.fetchall()}

    def get_feed_report_counts(self) -> Dict[str, int]:
        """Distinct indicators reported per feed (denominator for FP rate)."""
        with self._cursor() as cur:
            cur.execute(
                "SELECT source_name, COUNT(DISTINCT indicator_id) AS n FROM indicator_sources GROUP BY source_name"
            )
            return {row['source_name']: row['n'] for row in cur.fetchall()}

    # ==================== FEED TELEMETRY ====================
    # Which feeds are actually earning their keep. All of this is derived from
    # data already on disk — indicator_sources carries a per-(indicator, feed)
    # `reported_at` that is written INSERT OR IGNORE, so it preserves the first
    # time that feed reported that IP. No history table, no cold start.

    def get_feed_exclusive_counts(self) -> Dict[str, int]:
        """Indicators only this feed reports. A feed with a high exclusive
        count is pulling weight no other feed covers; near-zero means it is
        contributing nothing you don't already have."""
        with self._cursor() as cur:
            cur.execute(
                "SELECT s.source_name, COUNT(*) AS n FROM indicator_sources s "
                "JOIN (SELECT indicator_id FROM indicator_sources "
                "      GROUP BY indicator_id HAVING COUNT(*) = 1) solo "
                "  ON solo.indicator_id = s.indicator_id "
                "GROUP BY s.source_name"
            )
            return {r['source_name']: r['n'] for r in cur.fetchall()}

    def get_feed_first_report_counts(self, since: Optional[str] = None) -> Dict[str, int]:
        """How often each feed was the FIRST to report an indicator — i.e. who
        gives you early warning versus who confirms what you already knew.

        `since` (ISO timestamp) restricts to indicators first seen in a window.
        Use it: a feed added last week cannot have been first for anything
        older, so an all-time count unfairly favours long-installed feeds.
        """
        params: List[Any] = []
        window = ""
        if since:
            window = "WHERE t >= ?"
            params.append(since)
        with self._cursor() as cur:
            cur.execute(
                "WITH firsts AS ("
                "  SELECT indicator_id, MIN(reported_at) AS t "
                "  FROM indicator_sources GROUP BY indicator_id"
                f") SELECT s.source_name, COUNT(*) AS n "
                "FROM indicator_sources s "
                f"JOIN (SELECT * FROM firsts {window}) f "
                "  ON s.indicator_id = f.indicator_id AND s.reported_at = f.t "
                "GROUP BY s.source_name",
                params,
            )
            return {r['source_name']: r['n'] for r in cur.fetchall()}

    def get_feed_new_counts(self, since: str) -> Dict[str, int]:
        """Indicators each feed reported for the first time since `since` —
        the feed's churn / freshness. A feed whose new count is flat at zero
        for days is serving a stale list (or silently 304ing forever)."""
        with self._cursor() as cur:
            cur.execute(
                "SELECT source_name, COUNT(*) AS n FROM indicator_sources "
                "WHERE reported_at >= ? GROUP BY source_name",
                (since,),
            )
            return {r['source_name']: r['n'] for r in cur.fetchall()}

    def get_feed_overlap(self) -> List[Dict[str, Any]]:
        """Pairwise overlap: how many indicators each pair of feeds both
        report. Two feeds overlapping near-totally are not two independent
        votes — several public feeds aggregate each other (Emerging Threats
        bundles Spamhaus/DShield, BBcan177 aggregates other lists), so this
        is how you tell real corroboration from an echo."""
        with self._cursor() as cur:
            cur.execute(
                "SELECT a.source_name AS x, b.source_name AS y, COUNT(*) AS n "
                "FROM indicator_sources a "
                "JOIN indicator_sources b "
                "  ON a.indicator_id = b.indicator_id AND a.source_name < b.source_name "
                "GROUP BY a.source_name, b.source_name"
            )
            return [{"a": r['x'], "b": r['y'], "n": r['n']} for r in cur.fetchall()]

    def get_source_counts(self) -> Dict[str, int]:
        """How many indicators each source currently reports. Together with
        get_feed_overlap this normalizes pair counts into overlap ratios
        (|A∩B| / min(|A|,|B|)) for effective-vote scoring."""
        with self._cursor() as cur:
            cur.execute(
                "SELECT source_name, COUNT(*) AS n FROM indicator_sources GROUP BY source_name"
            )
            return {r['source_name']: r['n'] for r in cur.fetchall()}

    # ==================== FEED STATS ====================

    def update_feed_stats(self, feed_name: str, total_indicators: int, status: str, error_message: str = None):
        """Update or create feed statistics"""
        now = _utcnow_iso()
        with self._cursor() as cur:
            cur.execute("SELECT id FROM feed_stats WHERE feed_name = ?", (feed_name,))
            row = cur.fetchone()
            if row:
                cur.execute(
                    "UPDATE feed_stats SET total_indicators = ?, last_update = ?, status = ?, error_message = ? WHERE feed_name = ?",
                    (total_indicators, now, status, error_message, feed_name),
                )
            else:
                cur.execute(
                    "INSERT INTO feed_stats (feed_name, total_indicators, last_update, status, error_message) VALUES (?, ?, ?, ?, ?)",
                    (feed_name, total_indicators, now, status, error_message),
                )

    def get_feed_http_cache(self, feed_name: str) -> Tuple[Optional[str], Optional[str]]:
        """Stored HTTP validators (etag, last_modified) for a feed."""
        with self._cursor() as cur:
            cur.execute(
                "SELECT etag, last_modified FROM feed_stats WHERE feed_name = ?", (feed_name,)
            )
            row = cur.fetchone()
            return (row['etag'], row['last_modified']) if row else (None, None)

    def set_feed_http_cache(self, feed_name: str, etag: Optional[str],
                            last_modified: Optional[str]) -> None:
        """Store (or clear, with Nones) a feed's HTTP validators."""
        with self._cursor() as cur:
            cur.execute(
                "UPDATE feed_stats SET etag = ?, last_modified = ? WHERE feed_name = ?",
                (etag, last_modified, feed_name),
            )

    def get_feed_last_updates(self) -> Dict[str, str]:
        """Raw {feed_name: last_update} strings from feed_stats."""
        with self._cursor() as cur:
            cur.execute("SELECT feed_name, last_update FROM feed_stats")
            return {row['feed_name']: row['last_update'] for row in cur.fetchall()}

    def get_feed_stats(self) -> List[FeedStats]:
        """Get statistics for all feeds"""
        with self._cursor() as cur:
            cur.execute("SELECT * FROM feed_stats ORDER BY last_update DESC")
            return [FeedStats(
                feed_name=row['feed_name'],
                total_indicators=row['total_indicators'],
                last_update=row['last_update'],
                status=row['status'],
                error_message=row['error_message'],
            ) for row in cur.fetchall()]

    # ==================== FEED SOURCE MANAGEMENT ====================

    @staticmethod
    def _row_to_feed(row) -> FeedSource:
        return FeedSource(
            name=row['name'],
            url=row['url'],
            feed_type=FeedType(row['feed_type']),
            weight=row['weight'],
            update_interval=row['update_interval'],
            requires_auth=bool(row['requires_auth']),
            auth_env=row['auth_env'],
            auth_header=row['auth_header'] or 'Authorization',
            local_file=bool(row['local_file']),
            scraper=row['scraper'],
            enabled=bool(row['enabled']),
        )

    def seed_feeds_from_config(self, config: Dict) -> int:
        """Populate the feeds table from config.yaml on first run only."""
        with self._cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM feeds")
            if cur.fetchone()[0] > 0:
                return 0
            now = _utcnow_iso()
            seeded = 0
            for feed_cfg in config.get('feeds', []):
                try:
                    feed = FeedSource(**feed_cfg)
                except Exception:
                    continue
                cur.execute(
                    "INSERT OR IGNORE INTO feeds "
                    "(name, url, feed_type, weight, update_interval, requires_auth, "
                    "auth_env, auth_header, local_file, scraper, enabled, added_by, "
                    "added_at, seed_fingerprint) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'seed', ?, ?)",
                    (feed.name, feed.url, feed.feed_type.value, feed.weight,
                     feed.update_interval, int(feed.requires_auth), feed.auth_env,
                     feed.auth_header, int(feed.local_file), feed.scraper,
                     int(feed.enabled), now, _feed_fingerprint(feed)),
                )
                seeded += 1
            return seeded

    def sync_default_feeds(self, config: Dict) -> Dict[str, List[str]]:
        """Merge the shipped default feeds into an existing database on app
        update, without touching user data or customizations.

        Runs on every startup. For each feed in config:
          - tombstoned (operator deleted it)     -> skipped, stays deleted
          - missing from the DB                  -> added (a new default)
          - present with seed provenance and
            shipped PLUMBING changed (url,
            scraper, auth, type)                 -> plumbing updated in place;
                                                    enabled/weight/interval
                                                    (preferences) untouched
          - operator-overridden row (dashboard
            add nulls seed_fingerprint) or
            predating fingerprints               -> left exactly as-is

        Indicators, whitelist entries, feedback, scores, and HTTP validators
        are never modified here — accumulated state (e.g. a multi-day rolling
        union of DShield netblocks) survives updates.
        """
        actions = {"added": [], "updated": [], "skipped_deleted": []}
        existing = {f.name: f for f in self.get_feed_sources()}
        with self._cursor() as cur:
            cur.execute("SELECT name FROM deleted_feeds")
            tombstoned = {r['name'] for r in cur.fetchall()}
            fingerprints = {
                r['name']: r['seed_fingerprint']
                for r in cur.execute("SELECT name, seed_fingerprint FROM feeds").fetchall()
            }
        for feed_cfg in config.get('feeds', []):
            try:
                feed = FeedSource(**feed_cfg)
            except Exception:
                continue
            if feed.name in tombstoned:
                actions["skipped_deleted"].append(feed.name)
                continue
            new_fp = _feed_fingerprint(feed)
            if feed.name not in existing:
                self.add_feed(feed, added_by='sync-defaults', seed_fingerprint=new_fp)
                actions["added"].append(feed.name)
                continue
            # Plumbing follows the ship; preferences belong to the operator.
            #
            # url/scraper/auth/type are MECHANICS — when a shipped default's
            # mechanics change it is a bug fix (an upstream endpoint died),
            # and it must reach every deployment using the feed. The old
            # whole-row fingerprint gate froze a feed the moment the operator
            # merely ENABLED it, which guaranteed opt-in feeds (OTX ships
            # disabled) could never receive their own fixes.
            #
            # enabled/weight/update_interval are PREFERENCES — sync never
            # touches them on an existing row.
            #
            # A non-NULL seed_fingerprint marks the row as seed/sync/restore
            # provenance; a dashboard add/override nulls it (see add_feed),
            # which is the one way an operator can change plumbing — those
            # rows stay frozen, protecting deliberate URL overrides.
            if fingerprints.get(feed.name) and _plumbing_differs(existing[feed.name], feed):
                with self._cursor() as cur:
                    cur.execute(
                        "UPDATE feeds SET url = ?, feed_type = ?, requires_auth = ?, "
                        "auth_env = ?, auth_header = ?, local_file = ?, scraper = ?, "
                        "seed_fingerprint = ? WHERE name = ?",
                        (feed.url, feed.feed_type.value, int(feed.requires_auth),
                         feed.auth_env, feed.auth_header, int(feed.local_file),
                         feed.scraper, new_fp, feed.name),
                    )
                actions["updated"].append(feed.name)
        return actions

    def restore_default_feeds(self, config: Dict) -> List[str]:
        """Add any config feeds that are not already configured (merge, no
        clobber). Explicit user action: restores even tombstoned defaults."""
        existing = {f.name for f in self.get_feed_sources()}
        added = []
        for feed_cfg in config.get('feeds', []):
            try:
                feed = FeedSource(**feed_cfg)
            except Exception:
                continue
            if feed.name in existing:
                continue
            self.add_feed(feed, added_by='restore-defaults',
                          seed_fingerprint=_feed_fingerprint(feed))
            added.append(feed.name)
        return added

    def get_feed_sources(self, enabled_only: bool = False) -> List[FeedSource]:
        """Return configured feed sources, optionally only enabled ones."""
        with self._cursor() as cur:
            if enabled_only:
                cur.execute("SELECT * FROM feeds WHERE enabled = 1 ORDER BY name")
            else:
                cur.execute("SELECT * FROM feeds ORDER BY name")
            return [self._row_to_feed(r) for r in cur.fetchall()]

    def get_feed_source(self, name: str) -> Optional[FeedSource]:
        with self._cursor() as cur:
            cur.execute("SELECT * FROM feeds WHERE name = ?", (name,))
            row = cur.fetchone()
            return self._row_to_feed(row) if row else None

    def add_feed(self, feed: FeedSource, added_by: str = "dashboard",
                 seed_fingerprint: Optional[str] = None) -> None:
        """Add or update a configured feed source (keyed by name).

        seed_fingerprint marks the row as an untouched default (set by
        seed/sync/restore paths); user-driven adds/edits leave it NULL, which
        excludes the row from automatic default-sync updates. Any explicit
        add also clears a deletion tombstone — the feed is wanted again.
        """
        now = _utcnow_iso()
        with self._cursor() as cur:
            cur.execute("SELECT url FROM feeds WHERE name = ?", (feed.name,))
            row = cur.fetchone()
            url_changed = row is not None and row['url'] != feed.url
            cur.execute(
                "INSERT INTO feeds "
                "(name, url, feed_type, weight, update_interval, requires_auth, "
                "auth_env, auth_header, local_file, scraper, enabled, added_by, "
                "added_at, seed_fingerprint) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(name) DO UPDATE SET "
                "url = excluded.url, feed_type = excluded.feed_type, weight = excluded.weight, "
                "update_interval = excluded.update_interval, "
                "requires_auth = excluded.requires_auth, auth_env = excluded.auth_env, "
                "auth_header = excluded.auth_header, local_file = excluded.local_file, "
                "scraper = excluded.scraper, enabled = excluded.enabled, "
                "seed_fingerprint = excluded.seed_fingerprint",
                (feed.name, feed.url, feed.feed_type.value, feed.weight,
                 feed.update_interval, int(feed.requires_auth), feed.auth_env,
                 feed.auth_header, int(feed.local_file), feed.scraper,
                 int(feed.enabled), added_by, now, seed_fingerprint),
            )
            cur.execute("DELETE FROM deleted_feeds WHERE name = ?", (feed.name,))
            if url_changed:
                cur.execute(
                    "UPDATE feed_stats SET etag = NULL, last_modified = NULL WHERE feed_name = ?",
                    (feed.name,),
                )

    def remove_feed(self, name: str) -> bool:
        """Remove a configured feed and purge the data it contributed.

        Leaves a tombstone so sync_default_feeds never resurrects a default
        the operator deliberately deleted (the dashboard's restore-defaults
        button, or manually re-adding the feed, clears it)."""
        with self._cursor() as cur:
            cur.execute("DELETE FROM feeds WHERE name = ?", (name,))
            affected = cur.rowcount
            if affected:
                cur.execute(
                    "INSERT OR REPLACE INTO deleted_feeds (name, deleted_at) VALUES (?, ?)",
                    (name, _utcnow_iso()),
                )
            cur.execute("DELETE FROM indicator_sources WHERE source_name = ?", (name,))
            cur.execute("DELETE FROM feed_feedback WHERE feed_name = ?", (name,))
            cur.execute(
                "UPDATE feed_stats SET etag = NULL, last_modified = NULL WHERE feed_name = ?",
                (name,),
            )
            cur.execute(
                "DELETE FROM indicators WHERE NOT EXISTS (SELECT 1 FROM indicator_sources WHERE indicator_id = indicators.id)"
            )
            return affected > 0

    def set_feed_enabled(self, name: str, enabled: bool) -> bool:
        with self._cursor() as cur:
            cur.execute("UPDATE feeds SET enabled = ? WHERE name = ?", (int(enabled), name))
            return cur.rowcount > 0

    # ==================== SETTINGS ====================

    def get_setting(self, key: str, default: str = None) -> Optional[str]:
        with self._cursor() as cur:
            cur.execute("SELECT value FROM settings WHERE key = ?", (key,))
            row = cur.fetchone()
            return row['value'] if row else default

    def set_setting(self, key: str, value: str) -> None:
        with self._cursor() as cur:
            cur.execute(
                "INSERT INTO settings (key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, str(value)),
            )

    # ==================== BACKUP ====================

    def backup_database(self, dest_dir: str, keep: int = 7) -> str:
        """Write a consistent, WAL-safe snapshot of the DB to dest_dir."""
        os.makedirs(dest_dir, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        dest = os.path.join(dest_dir, f'threat_feeds-{ts}.db')

        src = sqlite3.connect(self.db_path)
        try:
            dst = sqlite3.connect(dest)
            try:
                src.backup(dst)
            finally:
                dst.close()
        finally:
            src.close()

        self._prune_backups(dest_dir, keep)
        return dest

    @staticmethod
    def _prune_backups(dest_dir: str, keep: int) -> None:
        """Keep only the newest `keep` backup files (by timestamped name)."""
        if keep is None or keep <= 0:
            return
        try:
            files = sorted(
                [f for f in os.listdir(dest_dir) if f.startswith('threat_feeds-') and f.endswith('.db')],
                key=lambda f: os.path.getmtime(os.path.join(dest_dir, f)),
            )
        except OSError:
            return
        for stale in files[:-keep]:
            try:
                os.remove(os.path.join(dest_dir, stale))
            except OSError:
                pass

    # ==================== UTILITY ====================

    def get_stats_summary(self) -> Dict[str, int]:
        """Get a summary of all indicators by tier"""
        with self._cursor() as cur:
            stats = {}
            for tier in ConfidenceTier:
                cur.execute("SELECT COUNT(*) FROM indicators WHERE tier = ?", (tier.value,))
                stats[f"{tier.value}_count"] = cur.fetchone()[0]
            cur.execute("SELECT COUNT(*) FROM indicators")
            stats["total"] = cur.fetchone()[0]
            cur.execute("SELECT COUNT(*) FROM whitelist")
            stats["whitelisted"] = cur.fetchone()[0]
            return stats
