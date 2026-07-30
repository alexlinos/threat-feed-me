<p align="center">
  <img src="assets/banner.svg" alt="Threat Feed Me! — a carnivorous blocklist for your firewall" width="100%">
</p>

# Threat Feed Me!

On-prem threat intelligence aggregator that normalizes, dedupes, and scores threat feeds into confidence tiers — then serves them as one URL your firewall polls. Feed it threats. It's always hungry.

## Deploy in 3 steps (out of the box)

Designed to run on a small on-prem box or VM with no tuning and no API keys.

```bash
docker compose up -d           # 1. start it
# 2. open the dashboard:
#    http://<this-server-ip>:8080
# 3. copy the "Medium confidence" feed URL into your firewall's threat-feed
#    setting (FortiGate, Sophos, SonicWall, Palo Alto, Cisco, pfSense, ...)
```

That's it. On first start it fetches **14 free, keyless threat feeds**, dedupes
and scores them, and begins serving block lists. It **auto-refreshes every 60
minutes** — no cron, no maintenance. Everything stays on-prem; feeds are pulled
inbound only.

- **No accounts or keys required** for the default feeds.
- The dashboard shows the exact URLs to paste, per confidence tier, with a
  Copy button and firewall-specific instructions.
- Add your own feeds, upload a custom list, whitelist false positives, or force
  a refresh — all from the dashboard, no config editing.
- A few feeds ship **disabled** (abuse.ch SSLBL and ThreatFox, AlienVault OTX,
  a sample custom list); enable them from the dashboard once configured. Feeds
  that need an API key (like OTX) have a **Set key** button — the key is
  stored server-side in the data volume's `.env`, applied immediately, and
  never displayed back.

To protect the dashboard on an untrusted network, set `DASHBOARD_USER` /
`DASHBOARD_PASSWORD` and `dashboard.auth_required: true`. Feed URLs stay open so
firewalls can poll them.

## Features

- **Feed Aggregation**: Pull from multiple sources (OSINT, commercial, custom)
- **Runtime feed management**: Add, remove, enable/disable, and mix-and-match
  feeds from the dashboard — including your own custom URL or local-file feeds
- **Force refresh & scheduling**: Refresh all feeds (or one) on demand, and set
  an auto-refresh interval (default 60 minutes)
- **Deduplication**: Merge duplicate IPs across feeds with source tracking
- **Confidence Scoring**: High/Medium/Low tiers based on:
  - Number of sources reporting the IP (including netblock overlap across feeds)
  - Feed reputation — equal for every feed by default and *earned* from there:
    flagging false positives automatically lowers the offending feed's weight
  - Age decay
- **Whitelist Management**: Override false positives — globally (all feeds) or
  scoped to a single feed (ignore one noisy source while trusting the rest).
  The whitelist dialog shows which feed(s) reported the IP, and a reason
  (false positive / risk accepted / internal asset). Flagging a **false
  positive** lowers that feed's reputation, so a noisy feed's IPs score lower
  and drop out of the higher-confidence firewall feeds (self-heals when the
  whitelist entry is removed).
- **Multi-format Export**: Text files, CSV, JSON for firewall/SIEM integration
- **Basic Dashboard**: Web UI for viewing feeds, managing whitelists, seeing stats
- **Containerized**: Docker deployment for easy on-prem install

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                       Threat Feed Me!                       │
├─────────────────────────────────────────────────────────────┤
│  Feed Ingestion Layer (free, keyless defaults)             │
│  ├── Talos (Snort.org IP block list, via scraper)          │
│  ├── DShield/SANS + Spamhaus DROP (netblock feeds)         │
│  ├── Emerging Threats (compromised + block IPs)            │
│  ├── Blocklist.de, CINS Army, GreenSnow, BBcan177          │
│  ├── DataPlane, BruteForceBlocker, Turris, BinaryDefense   │
│  ├── abuse.ch Feodo Tracker (botnet C2)                    │
│  ├── Optional: SSLBL, ThreatFox, OTX (ship disabled)       │
│  └── Custom Feeds (user-defined, e.g. local honeypot)      │
├─────────────────────────────────────────────────────────────┤
│  Processing Engine                                          │
│  ├── Normalization (common schema)                         │
│  ├── Deduplication (IP-based with source tracking)         │
│  ├── Confidence Scoring (multi-factor)                     │
│  └── Whitelist Filtering                                    │
├─────────────────────────────────────────────────────────────┤
│  Output Tiers                                               │
│  ├── High Confidence: 3+ sources + threat intel validated  │
│  ├── Medium Confidence: 2 reputable sources                │
│  └── Low Confidence: All deduped IPs (including custom)    │
├─────────────────────────────────────────────────────────────┤
│  Storage                                                    │
│  └── SQLite (IPs, sources, scores, whitelist, metadata)    │
└─────────────────────────────────────────────────────────────┘
```

## Quick Start

```bash
# Clone and setup
git clone https://github.com/alexlinos/threat-feed-me.git
cd threat-feed-me

# Install the package (and its dependencies)
pip install -e .

# Run initial feed fetch
python -m threatfeedme.main --fetch

# Generate output feeds
python -m threatfeedme.main --export

# Start dashboard
python -m threatfeedme.dashboard
```

## Using the feeds in your firewall

Start the dashboard (`python -m threatfeedme.dashboard` or via Docker) and open it in a
browser. Each confidence tier is published as a live URL you can paste directly
into your firewall's external threat-feed / block-list setting:

```
http://<server>:8080/feeds/high.txt      # 3+ sources agree (strictest)
http://<server>:8080/feeds/medium.txt    # 2+ sources (recommended)
http://<server>:8080/feeds/low.txt       # seen once (high volume)
http://<server>:8080/feeds/all.txt       # everything, deduplicated
```

Each URL returns plain text, one IP or CIDR per line, generated live with the
whitelist applied. `.csv` and `.json` variants are also available for SIEM use.

- **FortiGate:** Security Fabric → External Connectors → Create New → *IP Address Threat Feed*
- **Sophos Firewall** (SFOS 21.0+): Active threat response → Third-party threat feeds → Add (type IPv4, action Block)
- **SonicWall** (SonicOS 7): Object → Match Objects → Dynamic External Object (HTTPS URL)
- **Palo Alto:** Objects → External Dynamic Lists → *IP List*
- **Cisco Secure Firewall (FMC):** Objects → Object Management → Security Intelligence → Network Lists and Feeds
- **Check Point** (R81+): Security Policies → Threat Prevention → Custom Policy Tools → Indicators → External IOC Feed
- **pfSense (pfBlockerNG):** Firewall → pfBlockerNG → IPv4 → add the URL as a source
- **OPNsense:** Firewall → Aliases → URL Table (IPs)

### Custom lists

Add your own feeds from the dashboard: a remote **URL feed**, or **upload a list**
(one IP/CIDR per line). Uploads are stored server-side under `data/uploads/`,
capped at 5 MB, text-only, validated to contain at least one IP/CIDR, and the
storage path is boundary-checked so a filename can never escape that directory.

**Restore defaults:** the dashboard's *Restore default feeds* button re-adds the
curated feeds from `config.yaml` that are missing, without touching feeds you've
customized.

### Merged indicators

The dashboard's *Merged indicators* section shows the deduplicated result across
all feeds (searchable and paginated). You can:
- **Add** an IP or CIDR manually (recorded under a `manual` source)
- **Remove** an IP — this globally whitelists it so a feed refresh won't bring
  it back, and drops it from the served feeds immediately

Feed endpoints are unauthenticated by design (a firewall polling a block list
can't present credentials); the dashboard/API can be protected with optional
Basic auth (`auth_required: true` plus `DASHBOARD_USER`/`DASHBOARD_PASSWORD`).

### Backups

The database is backed up automatically (online, WAL-safe) on the schedule set
in `config.yaml` under `database.backup` (default: every 24h, keep 7, to
`data/backups/` — on the same persistent volume). Trigger one on demand with
`POST /api/backup` or `python -m threatfeedme.main --backup`. **Restore:** stop the app and
copy a backup file over `data/threatfeedme.db`.

## Upgrading

```bash
git pull
docker compose up -d --build
```

That's the whole procedure — **your data survives updates**. The database
lives on the `threatfeedme-data` volume, so whitelist entries, false-positive
feedback, scores, feed history, and accumulated indicators (e.g. the rolling
multi-day union of DShield netblocks) all carry over. Never delete the volume
to upgrade.

Changes to the *shipped default feeds* are merged into your database
automatically on startup:

- **New default feeds** are added.
- **Changed defaults** (e.g. an upstream URL moved) are updated — but only if
  you never customized that feed. Any edit you made (URL, weight, interval,
  enable/disable) exempts the feed from automatic updates permanently.
- **Feeds you deleted stay deleted.** An update never resurrects them; the
  dashboard's *Restore default feeds* button brings them back explicitly.

Schema migrations run automatically and are additive. Running from a plain
checkout instead of Docker? Same story: `git pull` never touches the `data/`
directory.

## Configuration

Edit `config.yaml` to customize:
- Feed sources and update intervals
- Confidence scoring weights
- Whitelist rules
- Export formats and paths

## License

MIT
