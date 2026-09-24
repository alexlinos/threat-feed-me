#!/usr/bin/env python3
"""Threat Feed Me! - Main Entry Point

Usage:
    python -m threatfeedme.main --fetch          # Fetch all feeds
    python -m threatfeedme.main --score          # Recalculate confidence scores
    python -m threatfeedme.main --export         # Export all tiers
    python -m threatfeedme.main --full           # Run complete pipeline
    python -m threatfeedme.main --serve          # Start web UI now, fetch feeds in background
    python -m threatfeedme.main --stats          # Show statistics
    python -m threatfeedme.main --init-db        # Open (and migrate) the DB behind a holding page
"""
import argparse
import os
import sys
import threading
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


# Served while --init-db runs: a first start after an upgrade can spend minutes
# migrating the database, and a dashboard that just refuses connections reads
# as broken. Static, no request data reflected, no external resources.
_HOLDING_PAGE = b"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><meta http-equiv="refresh" content="20">
<title>Threat Feed Me! is starting</title></head>
<body style="margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#0e131a;color:#e4e9f0;font:16px/1.5 system-ui,-apple-system,Segoe UI,sans-serif">
<main style="max-width:520px;padding:32px;text-align:center">
<h1 style="margin:0 0 12px;font-size:26px">Threat Feed Me<span style="color:#f87171">!</span> is starting</h1>
<p style="margin:0 0 10px;color:#b9c4d2">After an upgrade the first start updates the database once. On a large
install that takes a few minutes; the dashboard appears here when it's done.</p>
<p style="margin:0;color:#93a0b2;font-size:14px">Your firewalls keep enforcing their last copy of the lists
meanwhile. This page reloads itself.</p></main></body></html>"""


def _init_db(cfg, db_path):
    """--init-db, the container entrypoint's step before --serve: open the
    database (running any one-time migration) while a holding page answers
    503 + Retry-After on the dashboard's own host and port, so a browser shows
    why nothing is up yet and a firewall poll gets a clean "try later". The
    page closes the moment the database is ready, freeing the port for the
    app. If the port can't be bound, the migration runs anyway."""
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class Holding(BaseHTTPRequestHandler):
        def _reply(self, body):
            self.send_response(503)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Retry-After", "30")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(_HOLDING_PAGE)))
            self.end_headers()
            if body:
                self.wfile.write(_HOLDING_PAGE)

        def do_GET(self):
            self._reply(True)

        do_POST = do_PUT = do_DELETE = do_PATCH = do_GET

        def do_HEAD(self):
            self._reply(False)

        def log_message(self, *args):
            pass

    server = None
    try:
        server = ThreadingHTTPServer(_resolve_host_port(cfg), Holding)
        threading.Thread(target=server.serve_forever, daemon=True).start()
    except OSError as e:
        logger.warning(f"Holding page not started ({e}); opening the database anyway")
    try:
        Database(db_path)
    finally:
        if server:
            server.shutdown()
            server.server_close()


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
    parser.add_argument('--push-unifi', action='store_true',
                        help='Push the configured tier into UniFi firewall groups now (integrations.unifi)')
    parser.add_argument('--push-crowdsec', action='store_true',
                        help='Publish the configured tier into the CrowdSec LAPI now (integrations.crowdsec)')
    parser.add_argument('--init-db', action='store_true',
                        help='Open the database, running any one-time migration, behind a holding page')
    parser.add_argument('--config', default='config.yaml', help='Config file path')

    args = parser.parse_args()

    if not any([args.fetch, args.score, args.export, args.full, args.serve, args.stats,
                args.backup, args.push_unifi, args.push_crowdsec, args.init_db]):
        parser.print_help()
        return

    cfg = yaml.safe_load(open(args.config))
    db_path = cfg.get('database', {}).get('path', './data/threatfeedme.db')
    if args.init_db:
        return _init_db(cfg, db_path)
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

    if args.push_unifi:
        # Dashboard-saved credentials live in the data-volume .env; load it so
        # a one-shot push works without exporting vars by hand. Real env wins.
        from threatfeedme.core import load_env_file
        load_env_file(os.path.join(os.path.dirname(db_path) or ".", ".env"))
        from threatfeedme.pusher_unifi import push_to_unifi
        summary = push_to_unifi(db, cfg)
        if summary is None:
            # ASCII only: Windows consoles default to cp1252 (see _stats_table).
            logger.error("UniFi push is not enabled - set integrations.unifi in config.yaml")
            sys.exit(2)
        logger.info(f"UniFi push complete: {summary}")

    if args.push_crowdsec:
        from threatfeedme.core import load_env_file
        load_env_file(os.path.join(os.path.dirname(db_path) or ".", ".env"))
        from threatfeedme.crowdsec import push_to_crowdsec
        summary = push_to_crowdsec(db, cfg, force=True)
        if summary is None:
            logger.error("CrowdSec publish is not enabled or has no LAPI URL "
                         "(dashboard CrowdSec panel, or integrations.crowdsec in config.yaml)")
            sys.exit(2)
        logger.info(f"CrowdSec publish complete: {summary}")



if __name__ == "__main__":
    main()
