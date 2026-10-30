# Privacy Statement

*Effective 2026-10-30. Applies to Threat Feed Me v2.6.0 and later.*

Threat Feed Me runs on infrastructure you control. The project and its
maintainer collect nothing from you or from your installation: there is no
telemetry, no analytics, no crash reporting and no account. Two daily
requests to GitHub (a release check and the feed catalog, both described
below and both switchable off) are the only traffic that reaches the
project's infrastructure, and neither carries anything about your install.
This statement describes what the software stores on your host, what it
sends out and to whom, what it exposes to the network, and what that means
for you as the operator. It is written to be checked against the code, so
every claim names the component it comes from.

## What the software stores, and where

Everything lives in the data directory next to the SQLite database
(`/app/data` in the container, the `threatfeedme-data` volume in the
published compose file). Nothing is written anywhere else.

| Data | What it contains | Where | Retention |
|---|---|---|---|
| Indicators | IP addresses, CIDR ranges and domain names published by the threat feeds you enable, with first-seen, last-seen, per-feed membership, confidence score and tier. If you run the optional offline predictor, an IP's row also carries a derived recurrence probability (`predictive_score`) in its metadata — a number computed from your own churn log, not personal data and never sent anywhere | `indicators`, `indicator_sources` tables | Kept until `max_age_days` after the indicator was last seen in any feed (default 14 days since v2.5.0, 7 before; `0` keeps forever). Editable from the dashboard. |
| Sightings log | Arrival and departure transitions of each indicator per feed, with a timestamp. Used for churn statistics and the optional predictor | `sightings` in `threatfeedme-churn.db` (a second file beside the database since v2.5.0, backed up with it), `source_state` | Transitions only. Transitions older than the larger of 30 days and twice the indicator retention (`retention.max_age_days`) are deleted on every refresh; with retention set to `0` (keep forever) the bound is 30 days. `source_state` holds one row per indicator a feed currently lists, so it follows the live corpus. Feeds listed under `retention.churn_log_exclude` are not logged. |
| Vote grace | For each indicator a feed recently dropped: the feed name, the indicator and when it was dropped, so the feed's vote lasts `scoring.vote_grace_days` after the drop. Recorded for every feed, including `churn_log_exclude` ones | `source_left`, `source_seeded` | Pruned to the grace window (default 3 days) on every refresh; `source_seeded` holds one row per feed name. |
| Feed telemetry | Per-feed fetch times, counts, HTTP status, overlap and reputation metrics | `feeds`, `feed_stats`, `deleted_feeds` | Until the feed is deleted, then a tombstone with the name only |
| Whitelist | Indicator, scope, the reason text you typed, an `added_by` label, timestamps and optional expiry | `whitelist` | Until expiry or manual removal |
| False-positive flags | Indicator, feed name, reason code, timestamp | `feed_feedback` | Until cleared |
| Settings | Tier boundaries, refresh interval, retention, UniFi, CrowdSec and predictor toggles, the dashboard hostnames you saved whether the host check is switched on, the dashboard sign-in set on the System page (the username and a salted scrypt hash of the password, never the password itself), the SHA-256 fingerprint of your UniFi gateway's TLS certificate once a Test connection has pinned it, and the last UniFi/CrowdSec push outcome | `settings` | Until changed |
| Hostnames seen | The hostnames (from the `Host` header) the dashboard has been reached by, with a count and first/last time, so the System view can offer them for the host check. No client IP address. Capped at 200 names | Memory only, never written to disk | Until the process restarts |
| Feed polls | Per served feed URL and TAXII collection: when it was last fetched, how many times, and the fetching client's User-Agent (truncated), so the dashboard can show "polled 3m ago by FortiGate". No client IP address | `settings` (`feed_polls`) | Overwritten on every poll; one entry per URL |
| Uploaded lists | Custom indicator lists you upload through the dashboard, as text files | `uploads/` under the data directory | Deleted together with the feed, when you delete the feed |
| Backups | Consistent copies of the database and the churn log (`threat_feeds-<time>.db` and `.churn.db`): everything in the rows above except the hostnames seen, the uploaded lists and the credentials, which stay out of backups | `backups/` beside the database (`database.backup.dir`) | Taken every 24 hours; the newest 7 are kept (`database.backup.keep`). Switch off with `database.backup.enabled: false` |
| Credentials | Feed API keys, UniFi credentials and CrowdSec credentials (machine login, bouncer key, Console integration login) you save from the dashboard, as `KEY=value` lines | `.env` next to the database, plain text | Until you remove them |

The indicators are third-party threat intelligence about hosts on the
public internet. Under some privacy laws an IP address is personal data. If
that applies to you, you are the controller for what your installation
holds, and the retention setting is the knob that governs it.

Credentials in `.env` are readable by anyone who can read the data volume.
Protect the volume the way you would protect any file holding secrets, and
use dedicated, least-privilege credentials for feeds and for the UniFi
gateway (see `pusher_unifi.py`).

## What the software sends, and to whom

All outbound traffic is initiated by the feed ingestor, the daily release
check and feed catalog poll, and, if you enable them, the UniFi and CrowdSec
integrations. All are in `src/threatfeedme/`.

**To the threat feed providers you enable.** On every refresh the ingestor
makes an HTTP or HTTPS GET to each enabled feed URL with the User-Agent
`ThreatFeedMe/1.0` and, where the provider supports it, conditional request
headers. The provider therefore sees your server's public IP address, the
User-Agent and the request time. For feeds that require a key (AlienVault
OTX, HoneyDB, the auth-walled abuse.ch export), the key you saved is sent in
the request headers — and only to that feed's own host: a built-in key is
never sent to any other host (even if the feed's URL is edited), and no key
is forwarded when a provider redirects to a different host or downgrades
HTTPS to HTTP. Keys for your own custom feeds (named `TFM_FEED_*`) go to the
feed URL you configured. A TAXII 2.1 collection you add as a feed is read the
same way: an HTTPS GET of the collection's objects, page by page, carrying
the key you saved for it in the `Authorization` header, to that server
only. The Talos Snort.org scraper is the one exception to
the plain GET: it uses a browser User-Agent and accepts Snort.org's terms
form on your behalf, because the list is gated behind that form. Each
provider's own privacy policy governs what they do with the request.
Feed requests go straight to the provider: while the SSRF guard is on (the
default) the `HTTP(S)_PROXY` / `ALL_PROXY` environment variables are
ignored for them, so no proxy sees the traffic unless you switch the guard
off with `safety.allow_private_feed_urls`.

**To your UniFi gateway, only if you enable the push.** The pusher sends
the block lists and your UniFi credentials (from `UNIFI_USER` and
`UNIFI_PASSWORD`) to the gateway address you configured, on your own
network. Changing the gateway address clears the saved login, so it is
never sent to a host other than the one it was entered for. Certificate
verification is off by default because UDM certificates are self-signed;
turn it on if your gateway has a real one. With it off, each login first
opens a short TLS connection to the gateway only to read the certificate it
presents, and compares its fingerprint with the one pinned on your first
successful Test connection (see SECURITY.md); nothing is sent on that
connection.

**To your CrowdSec Local API, only if you configure it.** Publishing sends
the chosen block-list tier (IP addresses and CIDR ranges, each as a ban
decision under a `threatfeedme/` scenario) and the machine login you saved
to the LAPI address you configured, on your own network. The `crowdsec_*`
feeds send the bouncer key you saved to the same address to read its
decisions. Changing the LAPI address clears all three credentials, so they
are never sent to a host other than the one they were entered for, and no
redirect is followed. The optional `crowdsec_console` feed sends its Console
integration login to `admin.api.crowdsec.net` (CrowdSec's servers) to
download the blocklists your Console account subscribes to; CrowdSec's
privacy policy governs that request.

**To your DNS resolver, only when you ask.** The dashboard's *Check & add*
button (set-up guide and System → Dashboard hostnames) looks up the DNS name
you typed, through the server's own resolver, to tell you whether it points
at this server. That is a lookup only, no connection is made to the name,
and the answer is shown to you and not stored. Your resolver (and anything
upstream of it) sees the name and the time of the query.

**To GitHub, once a day, for the release check** (`update_checker.py`,
config `updates.enabled`, on by default). One unauthenticated HTTPS GET to
`api.github.com/repos/alexlinos/threat-feed-me/tags` (the list of release
versions) with the
User-Agent `ThreatFeedMe/update-checker`. No version, install ID, hostname,
feed list or count is sent; GitHub sees your server's public IP address and
the request time. The answer is used only to show "vX.Y.Z available" in the
dashboard's top bar: the software never downloads or installs anything, and
every failure (offline, blocked, rate-limited) is silent.

**To GitHub, once a day, for the feed catalog** (`catalog_sync.py`, config
`catalog.enabled`, on by default). One HTTPS GET of `feed_catalog.yaml` from
`raw.githubusercontent.com`, the project's list of recommended feeds,
following redirects only within GitHub's raw-content hosts and never through
a proxy. Nothing is sent but the request itself; GitHub sees your server's
public IP address and the request time. New feeds it lists wait for you to
Add them unless you turn on auto-add. If you point `catalog.url` at a mirror,
that host receives the request instead.

**To nobody else.** The software does not contact the maintainer, a
licensing server or an analytics endpoint, and it never updates itself.
Country lookups for the dashboard heatmap use an offline table derived from
the DB-IP Lite database and shipped inside the image; no geolocation
service is called at runtime. The map outline is served by the application
itself, not fetched from a CDN, and the dashboard loads no web fonts,
scripts or images from anywhere else. You can confirm all of this with an egress
rule that allows only your enabled feed hosts, your gateway and your
CrowdSec LAPI: the software works normally behind it (the release check and
catalog poll fail silently and the feeds already installed keep working;
set `updates.enabled` and `catalog.enabled` to false to stop the attempts).

## What the software exposes to the network

| Endpoint | Authentication | Who can see what |
|---|---|---|
| `/feeds/*` | None, by design | Anyone who can reach the port can download your block lists. Firewalls polling a feed cannot present credentials, so the lists are treated as non-secret. |
| `/taxii2/*` | None, by design | The same block lists as `/feeds/*`, as STIX 2.1 Indicators over TAXII 2.1 (read-only), each with its confidence, tier and the names of the feeds that reported it. For SIEM and threat-intel platforms that subscribe rather than poll a text file. |
| Startup holding page | None | Only while a first start or an upgrade migrates the database: every request to the dashboard port gets the same static "starting up" page with a 503. It reads nothing from the request and logs nothing. |
| `/healthz` | None | Returns `{"ok": true}` and nothing else. |
| Dashboard and `/api/*` | Optional HTTP Basic auth: a sign-in set under System, or `DASHBOARD_USER` + `DASHBOARD_PASSWORD` (which win), or `dashboard.auth_required: true` | Open by default for a trusted LAN. Enable auth on any network you do not fully trust, and do not expose it to the internet. |

**Access logs.** The web server (uvicorn) writes its default access log to
standard output: the client IP address, request path, status code and
User-Agent of every request, including your firewalls' polls and your
dashboard sessions. Those lines go wherever your container runtime sends
logs, and their retention is set by your log driver, not by this software.
Basic auth credentials are not logged.

## Third parties you may deal with because of this project

- **GitHub** hosts the source, releases and the project page.
  `threatfeedme.app` redirects to that GitHub Pages site. The page contains
  no analytics or tracking script; the only scripts are the copy-to-clipboard
  button and a check that pauses the hero animation for visitors who ask
  their system for reduced motion. The animation and the tour video are
  files served from the same site; the tour downloads only when you press
  play. GitHub's own privacy statement applies to your visit and to any
  issue or report you file.
- **Docker Hub** serves the published image. Pulling it is subject to
  Docker's privacy policy.
- **Feed providers** receive the requests described above under their own
  terms.

## Your responsibilities as the operator

- You decide which feeds to enable, and so which providers see your
  server's address and receive your keys.
- You decide retention. The default of 14 days after last sighting is a
  balance between useful history and not holding addresses longer than you
  need them.
- Whitelist reasons and the `added_by` label are free text you type. Keep
  personal details out of them; they are stored in plain text and shown in
  the dashboard.
- Block lists you export end up in your firewall's configuration and logs.
  What happens to them there is governed by that device and your policies.

## Reporting

Questions about this statement go through GitHub issues. Anything that
looks like a data exposure or a security problem goes through GitHub's
private vulnerability reporting instead, as described in `SECURITY.md`.

## Changes

This statement is versioned with the code. When a change to the software
alters what it stores, sends or exposes, the change to this file ships in
the same release, and the release notes say so.
