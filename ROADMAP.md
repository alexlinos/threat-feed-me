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
