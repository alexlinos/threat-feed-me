#!/usr/bin/env python3
"""Threat Feed Me! - Main Entry Point

Usage:
    python -m threatfeedme.main --fetch          # Fetch all feeds
    python -m threatfeedme.main --score          # Recalculate confidence scores
    python -m threatfeedme.main --export         # Export all tiers
    python -m threatfeedme.main --full           # Run complete pipeline
    python -m threatfeedme.main --stats          # Show statistics
"""
import argparse
import yaml
import logging

from threatfeedme import pipeline
from threatfeedme.database import Database

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def _stats_table(db: Database):
    """Print statistics to stdout."""
    stats = db.get_stats_summary()
    print("\n" + "=" * 50)
    print(r"  \/\/\/  THREAT FEED ME! STATISTICS")
    print("=" * 50)
    print(f"Total unique IPs:      {stats.get('total', 0)}")
    print(f"High confidence:       {stats.get('high_count', 0)}")
    print(f"Medium confidence:     {stats.get('medium_count', 0)}")
    print(f"Low confidence:        {stats.get('low_count', 0)}")
    print(f"Whitelisted:           {stats.get('whitelisted', 0)}")
    print("=" * 50 + "\n")
    feed_stats = db.get_feed_stats()
    print("FEED STATUS:")
    print("-" * 50)
    for fs in feed_stats:
        # ASCII only: Windows consoles default to cp1252, where printing
        # "✓" raises UnicodeEncodeError and kills the stats table.
        icon = "[ok]" if fs.status == "success" else "[!!]"
        print(f"{icon} {fs.feed_name}: {fs.total_indicators} indicators ({fs.status})")
    print()


def main():
    parser = argparse.ArgumentParser(description='Threat Feed Me! - threat feed aggregator')
    parser.add_argument('--fetch', action='store_true', help='Fetch all feeds')
    parser.add_argument('--score', action='store_true', help='Recalculate confidence scores')
    parser.add_argument('--export', action='store_true', help='Export all tiers')
    parser.add_argument('--full', action='store_true', help='Run complete pipeline')
    parser.add_argument('--stats', action='store_true', help='Show statistics')
    parser.add_argument('--backup', action='store_true', help='Take a database backup now')
    parser.add_argument('--config', default='config.yaml', help='Config file path')

    args = parser.parse_args()

    cfg = yaml.safe_load(open(args.config))
    db_path = cfg.get('database', {}).get('path', './data/threatfeedme.db')
    db = Database(db_path)

    seeded = db.seed_feeds_from_config(cfg)
    if seeded:
        logger.info(f"Seeded {seeded} feed sources from config")

    if args.full or args.fetch:
        logger.info("Fetching feeds...")
        pipeline.fetch_feeds(db, cfg)
    if args.full or args.score:
        count = pipeline.recalculate(db, cfg)
        logger.info(f"Recalculated scores for {count} indicators")
    if args.full or args.export:
        results = pipeline.export_tiers(db, cfg)
        logger.info(f"Exported tiers to formats: {', '.join(results)}")
    if args.full or args.stats:
        _stats_table(db)

    if args.backup:
        bcfg = cfg.get('database', {}).get('backup', {}) or {}
        bdir = bcfg.get('dir') or f"{db_path.rsplit('/', 1)[0]}/backups"
        path = db.backup_database(bdir, keep=int(bcfg.get('keep', 7)))
        logger.info(f"Backup written to {path}")

    if not any(vars(args).values()):
        parser.print_help()


if __name__ == "__main__":
    main()
