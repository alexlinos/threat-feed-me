#!/usr/bin/env python3
"""Threat Feed Me! - Main Entry Point

Usage:
    python -m threatfeedme.main --fetch          # Fetch all feeds
    python -m threatfeedme.main --score          # Recalculate confidence scores
    python -m threatfeedme.main --export         # Export all tiers
    python -m threatfeedme.main --full           # Run complete pipeline
    python -m threatfeedme.main --serve          # Start web UI now, fetch feeds in background
    python -m threatfeedme.main --stats          # Show statistics
"""
import argparse
import os
import sys
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


def _resolve_host_port(cfg):
    """Resolve the dashboard bind host/port.

    Order: $DASHBOARD_HOST / $DASHBOARD_PORT env override (the Docker entrypoint
    sets DASHBOARD_HOST=0.0.0.0 so firewalls can poll the feed URLs), then
    dashboard.host / dashboard.port from config.yaml, then safe localhost
    defaults. Source runs stay loopback-only unless configured.
    """
    dash = cfg.get('dashboard', {}) or {}
    host = os.environ.get('DASHBOARD_HOST') or dash.get('host', '127.0.0.1')
    port = int(os.environ.get('DASHBOARD_PORT') or dash.get('port', 8080))
    return host, port

def _serve(cfg, config_path=None):
    """Start the web dashboard now and fetch feeds in the background.

    This is the container-equivalent startup: the UI comes up immediately and
    the initial feed fetch (fetch -> score -> export) runs on a background
    thread. The scheduler takes over ongoing refreshes from the app's lifespan.

    Host/port resolution: $DASHBOARD_HOST / $DASHBOARD_PORT env override
    (the Docker entrypoint sets DASHBOARD_HOST=0.0.0.0 so firewalls can poll
    the feed URLs), then dashboard.host / dashboard.port from config.yaml,
    then safe localhost defaults. Source runs stay loopback-only unless
    configured.
    """
    host, port = _resolve_host_port(cfg)

    # Make the served app and the background refresh use the SAME config and
    # database as this CLI loaded: pin CONFIG_PATH and initialize the core
    # singletons ONCE, before spawning the refresh thread. Without this, the
    # app's lifespan would re-init core (and the scheduler thread could lazily
    # trigger init) on a different config or race on the same SQLite file.
    cfg_path = config_path or os.environ.get('CONFIG_PATH') or 'config.yaml'
    os.environ['CONFIG_PATH'] = cfg_path
    from threatfeedme import core
    core.init(cfg_path)

    # Print the URL BEFORE starting the fetch or server, so the operator sees
    # where to go immediately (the point of watching the command line).
    print("\n" + "=" * 50)
    print(r"  \/\/\/  THREAT FEED ME!")
    print(f"  Web UI:  http://{host}:{port}")
    print("  Initial feed fetch is running in the background.")
    print("=" * 50 + "\n")

    # Kick off the initial refresh on a daemon thread. running=True is set
    # before the thread spawns, so the dashboard's first /api/refresh/status
    # poll already sees the fetch in progress.
    try:
        from threatfeedme.scheduler import start_refresh_async
        if not start_refresh_async():
            print('  A refresh was already in progress; skipping initial fetch.',
                  file=sys.stderr)
    except Exception as e:  # never block the UI on a fetch glitch
        logger.error(f"Could not start background feed fetch: {e}")

    # Run the server; this blocks until shutdown (SIGINT/SIGTERM).
    import uvicorn
    uvicorn.run("threatfeedme.app:app", host=host, port=port)


def main():
    parser = argparse.ArgumentParser(description='Threat Feed Me! - threat feed aggregator')
    parser.add_argument('--fetch', action='store_true', help='Fetch all feeds')
    parser.add_argument('--score', action='store_true', help='Recalculate confidence scores')
    parser.add_argument('--export', action='store_true', help='Export all tiers')
    parser.add_argument('--full', action='store_true', help='Run complete pipeline (one-shot, blocking)')
    parser.add_argument('--serve', action='store_true',
                        help='Start the web dashboard now and fetch feeds in the background (default container mode)')
    parser.add_argument('--stats', action='store_true', help='Show statistics')
    parser.add_argument('--backup', action='store_true', help='Take a database backup now')
    parser.add_argument('--config', default='config.yaml', help='Config file path')

    args = parser.parse_args()

    if not any([args.fetch, args.score, args.export, args.full,
                args.serve, args.stats, args.backup]):
        parser.print_help()
        return

    cfg = yaml.safe_load(open(args.config))
    db_path = cfg.get('database', {}).get('path', './data/threatfeedme.db')
    db = Database(db_path)

    seeded = db.seed_feeds_from_config(cfg)
    if seeded:
        logger.info(f"Seeded {seeded} feed sources from config")
    # Merge shipped-default changes into an existing DB (app update path);
    # never touches user customizations, deletions, or accumulated data.
    sync = db.sync_default_feeds(cfg)
    if sync["added"] or sync["updated"]:
        logger.info(f"Default feed sync: added {sync['added']}; updated {sync['updated']}")

    if args.serve:
        return _serve(cfg, args.config)

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



if __name__ == "__main__":
    main()
