# Roadmap

Direction, not promises. Each item names the design constraints that are
already decided, so whoever builds it starts from them.

## 2.6: application lists

**Why.** Allow-listing SaaS and cloud ranges was one of MineMeld's most
visible jobs: its Office 365 article was the most-published MineMeld how-to,
and AWS, Azure and GCP range miners came up constantly. People still build
EDLs for applications today (Microsoft 365, Zoom, Okta, cloud regions) to
allow them, exempt them from SSL decryption, or pin egress. Threat Feed Me
covers MineMeld's threat-feed pipeline but not this, and the
[MineMeld guide](https://alexlinos.github.io/threat-feed-me/minemeld.html)
says so.

**What it is.** A catalogue of application lists, each served at its own URL
(`/lists/<name>.txt`, plus CSV and JSON), refreshed on the normal schedule:

| Source | Shape | Filters to offer |
|---|---|---|
| Microsoft 365 endpoints web service | JSON (needs a client-request GUID) | service area (Exchange, SharePoint, Teams, Common), category (Optimize, Allow, Default), required only; IPs and URLs as separate lists |
| AWS `ip-ranges.json` | JSON | service, region, IPv4 / IPv6 |
| Google Cloud `cloud.json`, Google `goog.json` | JSON | scope (region) |
| Azure service tags | JSON, weekly file whose URL changes | tag, region. The awkward one: needs the download page followed or the Azure API |
| Cloudflare, GitHub `/meta`, Zoom, Okta, Atlassian, Slack | text or JSON | per product |
| Your own | URL or upload, list or JSON | a JSON filter expression |

**Decided constraints**

- **Policy, not intel.** Application lists never enter the indicator corpus,
  the vote engine, overlap telemetry, the churn log or the predictor.
  Corroboration means nothing for a vendor's own ranges, and
  false-positive feedback inverts. This is the same rule the parked LOLRMM
  design recorded in `CLAUDE.md`.
- **Separate from the threat lists everywhere.** Own storage, own URLs, own
  dashboard view ("Applications"). A threat list URL never contains an
  application-list entry, and the reverse.
- **Their own safety rules.** The known-good filter must not run on them (the
  entries *are* known-good infrastructure, so the filter would strip them),
  but an allow-list is dangerous in the other direction: a vendor file that
  suddenly contains `0.0.0.0/0` would open everything. So they get a prefix
  floor (no v4 prefix wider than a configurable /8, v6 /20), a
  bogon/private check, and a change guard. A refresh that changes more than
  a threshold share of a list is held, and the dashboard asks before
  serving it.
- **Change history.** Each refresh records a diff (+added / −removed) kept
  for 30 days, shown per list, because "why did Teams break yesterday?" is
  the first question anyone asks of an allow-list.
- **Engine.** A generic JSON source with a small filter expression
  (a JSONPath subset), shared with custom threat feeds, so most vendors are
  configuration, not code. Microsoft 365 and Azure get dedicated fetchers.
- **Serving.** Same as `/feeds`: exempt from the host check, ETag and
  `?limit=N`, last-polled-by per URL, TAXII not required.
- **Out of scope.** Default-deny RMM lists (parked; see `CLAUDE.md`).

## 2.6: decisions waiting on the maintainer

Researched 2026-09-25 and parked here so they ship together with 2.6. Nothing
below is in the product yet; each item is the maintainer's call.

**New feeds (ratify one at a time).** Probed keyless and live, unique share
measured against the roster, adoption and terms checked.

- Proposed default ON: `spamhaus_drop_v6` (91 IPv6 CIDRs, same terms as
  DROP; needs a small JSON-lines parser), `drb_ra_c2_ips` (C2 IPs, 99%
  unique, CC BY-NC-SA like `drb_ra_c2`), `etnetera_aggressive` (569 IPs,
  63% unique, MIT, in the Suricata rule index), `echap_stalkerware`
  (969 domains, CC BY 4.0, AdGuard's built-in filter).
- Proposed opt-in OFF: `opendbl_darknet` (22.9k IPs, 35% unique, own
  sensor, but no licence: ask the operator first), `ipnoise` (SekuriPy,
  "free for any use", only collecting since 2026-09-05: ON after two
  steady weeks), APNIC honeynet telnet and RDP (terms unpublished; telnet
  is 80% inside Dataplane telnet, pick one), `dataplane_telnetlogin`,
  `jamesbrine_honeypots` (non-commercial), `phishdestroy_live` (watch
  false positives), `threatview_ips`, `sfs_toxic_cidrs`, `sblam`.
- Rejected, with reasons in the research notes: Rutgers DROP and InterServer
  (almost all already in the roster), Stratosphere AIP (stopped updating
  2026-08-06), DroneBL (no keyless bulk access), Project Honey Pot and
  CleanTalk (terms), BotScout (Cloudflare addresses in a 35-IP list),
  myip.ms and Tor lists (policy, not threats), Feodo and AlienVault
  reputation (stale), aggregators (bitwire, IPFire DBL, NERD, FireHOL
  levels). FireHOL comparison: we cover 100% of the threat sources in its
  levels 1 to 3; the rest is bogon space and rejected sources.

Source URLs, all probed keyless on 2026-09-25 (re-probe before adding):

| Feed | URL | Format note |
|---|---|---|
| spamhaus_drop_v6 | https://www.spamhaus.org/drop/drop_v6.json | JSON lines, last line is metadata |
| drb_ra_c2_ips | https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/IPC2s-30day.csv | CSV `ip,ioc` |
| etnetera_aggressive | https://security.etnetera.cz/feeds/etn_aggressive.txt | plain, `#` header |
| echap_stalkerware | https://github.com/AssoEchap/stalkerware-indicators/raw/refs/heads/master/generated/quad9_blocklist.txt | plain domains |
| opendbl_darknet | https://opendbl.net/lists/opendbl-darknet.list | plain, `#` header |
| ipnoise | https://ipnoise.sekuripy.hr/1d.txt | plain (7d/14d/30d files also exist) |
| apnic_telnet / _rdp | https://feeds.honeynet.asia/bruteforce/latest-telnetbruteforce-unique.csv (and `latest-rdp-bruteforce-unique.csv`) | CSV, IP first field |
| dataplane_telnetlogin | https://dataplane.org/telnetlogin.txt | pipe-delimited, IP in field 3 (same parser as sshpwauth) |
| jamesbrine_honeypots | https://jamesbrine.com.au/csv | CSV `ip,activity,date`; drop junk rows like `0` |
| phishdestroy_live | https://raw.githubusercontent.com/phishdestroy/destroylist/main/dns/active_domains.txt | plain domains |
| threatview_ips | https://threatview.io/Downloads/IP-High-Confidence-Feed.txt | plain; contains junk like `0.0.0.2` |
| sfs_toxic_cidrs | https://www.stopforumspam.com/downloads/toxic_ip_cidr.txt | CIDRs; attribution required |
| sblam | https://sblam.com/blacklist.txt | plain; web-form spam only |

**Non-commercial feeds.** `dataplane_sshpwauth`, `phishing_army` and
`drb_ra_c2` already ship ON under non-commercial or no-redistribution
terms, and CrowdSec publishing and TAXII re-serve their data to other
systems. Options: (1) leave as is, (2) ship them opt-in, (3) keep them for
the operator's own firewalls but exclude them from CrowdSec publish and
TAXII. Recommended: 3.

**Interface.** Mockups on the maintainer's design canvas (row "2.6
proposal: expanded lists"): the Lists view as a tier matrix plus lists by
threat type (`/feeds/<type>/<tier>.txt`), a list builder
(`/feeds/custom/<name>.txt`), the Apps view and a per-app detail page for
the application lists above, and a Feeds view with a terms column, trial
state and a vetted opt-in catalog. Threat-type lists and the builder are
proposals, not yet agreed scope.

## Other candidates

- **Generic JSON feeds with a filter expression.** The application-list
  engine, also offered for threat feeds, so a new JSON feed needs no code.
- **Audit log** of dashboard changes (feeds, whitelist, settings, host
  check), with the `added_by` label that whitelist entries already carry.
- **Optional token on list URLs**, off by default, for lists reachable from
  the internet. It touches the rule that firewalls can always poll, so it
  needs a security review first.
- **Aging for manual entries.** MineMeld's local lists expired entries on
  their own; manual indicators here never do.
- **False-positive penalties that fade.** A flag lowers the feed's weight for
  as long as its whitelist entry stays, with no timer, so a feed that fixed
  its mistake months ago still pays for it. Decaying the penalty with the
  flag's age would let a feed earn its weight back.

## Not planned

Syslog-driven lists, PAN-OS Dynamic Address Group push, TAXII 1.x, writable
TAXII, and user-built processing graphs. Each was a MineMeld feature. None
fits a one-container tool whose job is scoring and serving lists.
