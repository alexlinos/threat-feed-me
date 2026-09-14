# Privacy Statement

*Effective 2026-09-14. Applies to Threat Feed Me v2.4.13 and later.*

Threat Feed Me runs on infrastructure you control. The project and its
maintainer collect nothing from you or from your installation: there is no
telemetry, no analytics, no crash reporting, no update check and no account.
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
| Indicators | IP addresses, CIDR ranges and domain names published by the threat feeds you enable, with first-seen, last-seen, per-feed membership, confidence score and tier | `indicators`, `indicator_sources` tables | Kept until `max_age_days` after the indicator was last seen in any feed (default 7 days; `0` keeps forever). Editable from the dashboard. |
| Sightings log | Arrival and departure transitions of each indicator per feed, with a timestamp. Used for churn statistics and the optional predictor | `sightings`, `source_state` | Transitions only, bounded by the live corpus. Feeds listed under `retention.churn_log_exclude` are not logged. |
| Feed telemetry | Per-feed fetch times, counts, HTTP status, overlap and reputation metrics | `feeds`, `feed_stats`, `deleted_feeds` | Until the feed is deleted, then a tombstone with the name only |
| Whitelist | Indicator, scope, the reason text you typed, an `added_by` label, timestamps and optional expiry | `whitelist` | Until expiry or manual removal |
| False-positive flags | Indicator, feed name, reason code, timestamp | `feed_feedback` | Until cleared |
| Settings | Tier boundaries, refresh interval, retention, UniFi and predictor toggles | `settings` | Until changed |
| Uploaded lists | Custom indicator lists you upload through the dashboard, as text files | `uploads/` under the data directory | Until you delete the feed |
| Credentials | Feed API keys and UniFi credentials you save from the dashboard, as `KEY=value` lines | `.env` next to the database, plain text | Until you remove them |

The indicators are third-party threat intelligence about hosts on the
public internet. Under some privacy laws an IP address is personal data. If
that applies to you, you are the controller for what your installation
holds, and the retention setting is the knob that governs it.

Credentials in `.env` are readable by anyone who can read the data volume.
Protect the volume the way you would protect any file holding secrets, and
use dedicated, least-privilege credentials for feeds and for the UniFi
gateway (see `pusher_unifi.py`).

## What the software sends, and to whom

All outbound traffic is initiated by the feed ingestor and, if you enable
it, the UniFi pusher. Both are in `src/threatfeedme/`.

**To the threat feed providers you enable.** On every refresh the ingestor
makes an HTTP or HTTPS GET to each enabled feed URL with the User-Agent
`ThreatFeedMe/1.0` and, where the provider supports it, conditional request
headers. The provider therefore sees your server's public IP address, the
User-Agent and the request time. For feeds that require a key (AlienVault
OTX, HoneyDB, the auth-walled abuse.ch export), the key you saved is sent in
the request headers. The Talos Snort.org scraper is the one exception to
the plain GET: it uses a browser User-Agent and accepts Snort.org's terms
form on your behalf, because the list is gated behind that form. Each
provider's own privacy policy governs what they do with the request.

**To your UniFi gateway, only if you enable the push.** The pusher sends
the block lists and your UniFi credentials (from `UNIFI_USER` and
`UNIFI_PASSWORD`) to the gateway address you configured, on your own
network. Certificate verification is off by default because UDM
certificates are self-signed; turn it on if your gateway has a real one.

**To nobody else.** The software does not contact the project, the
maintainer, a licensing server, an analytics endpoint or an update service.
Country lookups for the dashboard heatmap use an offline table derived from
the DB-IP Lite database and shipped inside the image; no geolocation
service is called at runtime. The map outline is served by the application
itself, not fetched from a CDN. You can confirm all of this with an egress
rule that allows only your enabled feed hosts and your gateway: the
software works normally behind it.

## What the software exposes to the network

| Endpoint | Authentication | Who can see what |
|---|---|---|
| `/feeds/*` | None, by design | Anyone who can reach the port can download your block lists. Firewalls polling a feed cannot present credentials, so the lists are treated as non-secret. |
| `/healthz` | None | Returns `{"ok": true}` and nothing else. |
| Dashboard and `/api/*` | Optional HTTP Basic auth (`DASHBOARD_USER`, `DASHBOARD_PASSWORD`, `dashboard.auth_required: true`) | Open by default for a trusted LAN. Enable auth on any network you do not fully trust, and do not expose it to the internet. |

**Access logs.** The web server (uvicorn) writes its default access log to
standard output: the client IP address, request path, status code and
User-Agent of every request, including your firewalls' polls and your
dashboard sessions. Those lines go wherever your container runtime sends
logs, and their retention is set by your log driver, not by this software.
Basic auth credentials are not logged.

## Third parties you may deal with because of this project

- **GitHub** hosts the source, releases and the project page.
  `threatfeedme.app` redirects to that GitHub Pages site. The page contains
  no analytics or tracking script; the only script is the copy-to-clipboard
  button. GitHub's own privacy statement applies to your visit and to any
  issue or report you file.
- **Docker Hub** serves the published image. Pulling it is subject to
  Docker's privacy policy.
- **Feed providers** receive the requests described above under their own
  terms.

## Your responsibilities as the operator

- You decide which feeds to enable, and so which providers see your
  server's address and receive your keys.
- You decide retention. The default of 7 days after last sighting is a
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
