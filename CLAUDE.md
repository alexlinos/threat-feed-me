# Working agreement

## GitHub is the source of truth

`https://github.com/alexlinos/threat-feed-me`: branch `main`.

Local checkouts are disposable views of it. If a local copy and the remote
disagree, the remote wins.

- **`git pull` before you start.** Another agent or session may have pushed
  since this checkout was last touched.
- **Push as soon as you commit.** Never leave a commit sitting locally; an
  unpushed commit is invisible to everyone else and is how two agents end up
  building on different bases.
- **One clone per machine.** Parallel folders (`...-2`, `-new`, `-copy`) have
  caused real divergence here: two checkouts a day apart, different agents
  building on different bases. If a checkout is broken, fix it or re-clone it
  in place rather than working beside it.
- Before a large change, re-check `git log origin/main -1`, cheap, and it
  catches a stale base immediately.

## Releasing

CI publishes the Docker image on a `v*.*.*` tag and **refuses to publish if
the tag and `pyproject.toml` disagree**; that guard has silently blocked two
releases already.

1. Bump `version` in `pyproject.toml` **and** `__version__` in
   `src/threatfeedme/__init__.py`; CI checks the tag against both (the
   footer displays `__version__`), and a unit test keeps the pair in sync.
2. Commit, push.
3. `git tag vX.Y.Z && git push origin vX.Y.Z`
4. Confirm the run at `gh run list --workflow "Publish Docker image"`. A tag
   alone is not a release; check that the build actually succeeded.

## Verifying

- `python -m pytest tests -q` must pass before pushing.
- For UI or behavioural changes, actually run it and look:
  actually run it and look: `python -m uvicorn --app-dir src threatfeedme.app:app --port 8080`.
  Several bugs here (a dead `esc()`, a hung geo panel, an unreadable heatmap)
  passed every test and were only visible in a browser.

## Conventions

- **No AI attribution in commits.** No `Co-Authored-By: Claude`, no naming
  models in commit messages or docs. Multiple models work on this repo; the
  history stays clean of all of them.
- Commit messages explain *why*, not just what: the reasoning is the part
  that isn't recoverable from the diff.
- `data/` is gitignored and disposable (fetched feed state, SQLite DB). Never
  commit it; never assume another checkout has the same contents.
- Comments carry design rationale, especially in `feed_ingestor.py`,
  `scorer.py`, and `telemetry.py`. Read before changing behaviour there.

## Open items (from the A2A serve review; fixes landed in 510d148)

Rounds 1-4 of the serve-immediately review were applied and committed in
`510d148`, the log that used to live here described them as uncommitted,
which stopped being true the moment they were committed. What remains open:

- `CONFIG_PATH` is inert as an operator knob on the CLI path: `args.config`
  always holds a truthy default, so the env fallback is never consulted.
  No deploy path sets it. Low priority.
- Redundant second `Database` on `--serve`: `main()` builds one and runs
  seed+sync, then `_serve` -> `core.init()` does it again. Idempotent waste,
  not corruption; cleanest fix is coupled with the CONFIG_PATH item.
- Config-shape edge cases: `dashboard: {host: }` yields `host=None` to
  uvicorn; `dashboard: {port: }` makes `int(None)` raise; a null `database:`
  key breaks path lookup. The shipped config.yaml is well-formed.

## HoneyDB feeds (v1.10.0, live-verified on prod)

Both feeds shipped, disabled by default: `honeydb_bad_hosts` (community,
rolling 24h window) and `honeydb_mydata` (only sensors the configured
HoneyDB account operates — relevant for deployments that contribute
sensors to honeydb.io). Implementation notes for whoever touches this next:

- `honeydb` scraper in feed_ingestor.py builds BOTH auth headers
  (`X-HoneyDb-ApiId` + `X-HoneyDb-ApiKey`) from `HONEYDB_API_ID` +
  `HONEYDB_API_KEY`; the generic single-var auth path can't express two
  headers. A valid-but-EMPTY JSON window returns NOT_MODIFIED (normal for
  /mydata, no attacks in 24h must not trip the zero-indicator guard).
- Multi-credential Set key: `auth_env` may be a comma-separated list. The
  dashboard button prompts per var; POST /api/feeds/{name}/api-key takes
  `{"keys": {VAR: value}}` (single-var feeds keep the plain `api_key`
  field). Only vars declared in auth_env are writable. Key ✓ badge requires
  ALL vars present.
- Live-verified 2026-08-11 on prod: bad_hosts pulls ~14.5k indicators at
  54% unique (highest-novelty feed in the roster); mydata pulls the
  account's own sensor sightings (0% unique by design — own sensors feed
  the community list too, and overlap discounting prices that
  correlation). The `remote_host` JSON key guess was correct.

## Domain intel: v2.0 design (approved direction, build not started)

Direction chosen: domains (not full URLs: path-level intel is email-proxy
territory; DNS-layer blocking is what firewalls consume). The votes engine
transfers unchanged; this is a data-model + serving expansion. Sources
live-verified 2026-08-13.

### Decisions (D1-D8)

- **D1 data model**: additive `kind` column on indicators ('ip' default,
  'domain'), value stays in the existing `ip` column (documented as "the
  indicator value"; avoids a table rebuild and every UNIQUE/index keeps
  working). Netblock-overlap votes and the geo heatmap gate on kind='ip'.
- **D2 serving**: new URLs `/feeds/domains/{high,medium,low,all}.{txt,csv,json}`.
  The existing IP URLs must NEVER emit a domain (regression test: a
  FortiGate address feed fed a hostname errors the whole import). Tiers
  cumulative, same as IPs.
- **D3 scoring**: same effective-votes engine; overlap pairs already work
  per indicator row so mixed feeds are fine; run natural breaks PER KIND
  (domain vote distribution will differ wildly from IPs; shared breaks
  would let one population set the other's tier lines). Two stored
  break pairs (settings keys tier_breaks / tier_breaks_domains).
- **D4 safety (the hard one)**: domain known-good floor. Shipped minimal
  core allowlist (major OS/update/CDN/mail infra), config
  `safety.known_good_domains` for operator additions (their own domains!),
  reject invalid/reserved (.test .example .invalid .localhost, bare TLDs),
  IDNA-normalize punycode before dedupe. Start small and curated, not a
  Tranco top-N dependency.
- **D5 sources at launch** (all probed live, keyless):
  - `urlhaus_hostfile` https://urlhaus.abuse.ch/downloads/hostfile/
    (malware distribution domains, hosts-file format, updated multiple
    times daily; NOT key-walled unlike other abuse.ch exports)
  - `openphish_community` https://openphish.com/feed.txt (phishing URLs;
    extract registrable domain)
  - `hagezi_threat_intel` https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domain/threat-intelligence.txt
    (malware/cryptojacking/scam/spam/phishing/C2 domains, the community-
    standard Threat Intelligence list; keyless, actively maintained)
  - `joewein_dom_bl` https://www.joewein.net/dl/bl/dom-bl.txt (spam/419;
    default OFF — spam-centric, low volume, no embedded freshness header)
- **D6 whitelist**: exact-domain entries + wildcard (`*.example.com`);
  matcher extension mirrors the CIDR pattern. Tier scopes work as-is.
- **D7 release**: v2.0.0, single release after the whole path is tested;
  build order: schema -> feed.indicator_kind plumbing -> parser (domain +
  hosts-file formats) -> per-kind breaks -> serving/exports -> safety ->
  whitelist -> dashboard -> feeds -> docs/site.
- **D8 parsing**: feeds DECLARE their kind (new plumbing field
  `indicator_kind` on FeedSource, default 'ip'); domain extraction only
  runs for domain feeds. Never sniff domains out of IP feeds (comments and
  URLs in feed headers would pollute the corpus).

### UI decisions ratified 2026-08-14 (mockups reviewed by the maintainer)

- **D2 revised, feed URLs**: the card section becomes a FEED MATRIX: rows =
  tiers (High/Medium/Everything), columns = kind (IP feeds / Domain feeds),
  each cell = URL + inline count + Copy. The stat-tile row is RETIRED
  (counts moved inline; page gets shorter despite the second kind). Below
  720px each matrix row collapses to a tier group with the two kinds
  stacked as labeled lines; URLs ellipsize from the LEFT so the tail stays
  readable; counts compact (42.4k).
- **D9, feeds management**: ONE table, kind-grouped with slim group header
  rows (green IP / purple domain, each with feed + indicator counts).
  Telemetry (Entries/Unique/First/New/twin) computed WITHIN KIND — cross-
  kind overlap is structurally zero, so mixed-roster uniqueness would be
  meaningless flattery. Long scroll, NO collapse (monitoring surface: a
  collapsed group is where a feed rots unseen); within each group,
  error/stale/degraded rows float above healthy ones ("problems float").
  Add-feed + upload forms gain an IP/Domain kind select. Overlap map
  renders as two blocks (IP map + domain map) in the same disclosure.
  "IPs" column header becomes "Entries". Lookup box accepts domains.
- **D10, TLD panel**: new collapsed <details> at the bottom (geo-panel
  pattern: lazy fetch on expand, cached): "problematic TLDs" for the
  domain corpus. Form: RANKED HORIZONTAL BARS (top ~15 + honest "other"
  row), NOT a pie — TLD abuse is heavily skewed and pies fail on long
  tails; matches the geo panel's map+ranked-list precedent. v1 ranks by
  raw blocked-domain count; tier-weighted ranking is a possible follow-up.
  Optional small top-5 donut beside the bars only if visual variety is
  wanted; bars carry the data. Endpoint: /api/domains/tlds.

### Ratified (maintainer, 2026-08-15) ← replaces "Still to ratify"

1. Domain feeds default-enabled: urlhaus_hostfile + openphish_community +
   hagezi_threat_intel ON (keyless = the product promise); joewein_dom_bl
   OFF (spam-centric, low volume, no embedded freshness header).
2. Single v2.0.0 release after the whole path is tested, per D7.
3. TLD panel: plain ranked bars (recommended, no top-5 donut; bars carry the
   data, matches geo-panel precedent).

Roster stays open for curation: the maintainer ratifies new sources one at
a time; keep blocklist-source research additive rather than fixing a
walled list.

### Ratified (maintainer, 2026-08-15) — domain roster expansion

Community-grounded (Firebog ticked tier, live-probed keyless):

1. `phishing_army` ON — the extended blocklist (~156k, 6h updates, CC BY
   4.0). Aggregates PhishTank + urlscan.io + Phishunt + OpenPhish +
   CERT.PL, with upstream FP-scrubbing against curated whitelists.
2. `hagezi_fake` OFF — ratified ON, then live-measured 100% contained in
   TIF mini (0% unique, twin-flagged; TIF aggregates hagezi's own Fake
   list). Same-publisher agreement isn't independent evidence, so it ships
   disabled; kept as an opt-in for TIF-less setups.
3. `cert_pl` OFF — highest provenance (national CERT, hourly) but an
   UPSTREAM of phishing_army: enabling both twin-flags it as ~100%
   contained. Opt-in for operators preferring the primary source.
4. `threatview_domains` OFF — ~500k aggregator-of-aggregators; opt-in.

Probed and rejected: red.flag.domains (French-only relevance), DigitalSide
(host down), botvrij (dead file), urlhaus-filter (repackaged urlhaus),
Spam404/quidsup/DandelionSprout/CyberHost (small hobbyist lists largely
inside hagezi TIF + phishing_army). FortiGate operators: external-resource
caps (~131k entries on mid-range) mean the DNS filter should point at
domains/medium or high, not Everything — noted in the dashboard how-to.

### UniFi push integration (v2.1.0, LIVE-VERIFIED on a real UDM SE 2026-08-15)

UniFi gateways (UDM/UDM Pro/UDM SE) cannot poll a blocklist URL (open
feature request for years), so `pusher_unifi.py` PUSHES via the gateway's
local Network API after every refresh (hooked in pipeline.run_refresh AND
the whitelist-triggered background export worker behind push_ready, all
guarded so a push failure never breaks anything; one-shot: `--push-unifi`).
Two arms, both live-verified against real UniFi OS:

- IP arm: firewall groups `{prefix}-{tier}-1..N` (address-group), chunked
  at 5k (UniFi caps ~10k/group). Verified: 3,082 high-tier IPs, one group.
- Domain arm (optional, off by default): Domain-type network lists
  `{prefix}-dom-{tier}-1..N` (group_type domain-group) through the SAME
  /rest/firewallgroup API — works on base firmware, NO CyberSecure needed.
  Verified: 41 high-tier domains created first try. (A content-filtering
  v2-API version existed for a few hours; replaced — CyberSecure-gated and
  undocumented.)

Shared mechanics: login via /api/auth/login with UNIFI_USER/UNIFI_PASSWORD
env (write-only via the dashboard panel, feed-API-key mechanics; CSRF token
echoed + rotated), stale groups EMPTIED not deleted (in-use groups refuse
deletion) with stale detection scoped per group_type (the arms share the
name prefix and must not clean each other), default tier high (fits one
group/one policy — the panel warns on dropdown change that other tiers
shard into multiple lists needing multiple policy references), hard
max_entries cap with strongest-kept truncation, IPv4 only on the IP arm.
The operator creates the Block policies in UniFi referencing the lists;
the pusher never touches policies. Managed from the dashboard's collapsed
"UniFi integration" panel (Test connection = read-only login+list).

### v2.0.0 build state (2026-08-15, shipped)

The whole D1-D10 path is implemented, tested (269 green), live-verified
against the real roster (114k IPs + 167k domains), and released as v2.0.0.
Things that CHANGED vs. the design above, for whoever reads it later:

- **Hagezi URL + variant (PENDING ALEX RE-RATIFICATION)**: the ratified URL
  (domain/threat-intelligence.txt) 404s; the list lives at
  wildcard/tif*-onlydomains.txt. Live sizes 2026-08-15: full 2.0M entries,
  medium 386k, mini 167k. Shipped default = **mini** on deployment-envelope
  grounds (full/medium would dwarf the IP corpus and strain the 2 GB
  rescore path). Operators can repoint the URL from the dashboard.
- Serving commit c484cd6 had only added queries, not routes — the actual
  /feeds/domains/* routes, kind-split on-disk exports
  (*_confidence_domains.*), and /api/domains/tlds landed later (23925f7).
- **indicator_kind was dead at the feeds persistence layer** (never
  read/written by _row_to_feed/seed/add_feed/sync): every DB-loaded feed
  came back kind='ip'. Fixed in e3d497d; kind is PLUMBING for
  sync_default_feeds, which self-heals DBs that seeded domain feeds as ip.
- A 4-agent adversarial pass (b02bf50) found and fixed 20 issues; the big
  ones: stdlib IDNA2003 eszett-folding blocked the WRONG domain (now
  IDNA2008/UTS46 via the idna package, a pinned direct dep);
  multi-hostname hosts lines parsed as empty; ambiguous shapes (01.2.3.4,
  1.2.3.4.5) could flip a row's kind between serving surfaces (all-numeric
  TLDs now rejected, bulk upsert never flips kind); one global wildcard
  whitelist entry made /api/indicators materialize the full table per
  keystroke; scorer roster fingerprints were shared across kinds (IP churn
  silently moved domain tier lines — now per-kind with 25% tolerance).
- Deliberately NOT fixed: *.co.uk-style public-suffix wildcards and
  0.0.0.0/0 are accepted in the whitelist (no-PSL is ratified D4; the
  whitelist is the operator's own gun). Rescore peak memory ~200 MB at
  280k rows: acceptable, revisit if the corpus grows.

## v2.2.0: ops pulse row + 429 retry

- Stat cards returned as the "ops pulse" row: feeds-healthy (amber + names
  the first problem feed), last-refresh age (amber when overdue 2x
  interval), new-in-24h split by kind, overrides (zero state reads "pure
  feed consensus"), UniFi push status (renders ONLY when push is
  configured). Deliberately carries no corpus sizes: the matrix owns those,
  which is why the original tiles were retired.
- 429 is now retried honoring Retry-After (capped at 120s;
  _RETRY_AFTER_CAP). GitHub raw rate-limits per source IP and refresh
  bursts across several raw.githubusercontent feeds tripped it hourly on
  prod (hagezi). Other 4xx still fail immediately.
- Dashboard how-to now covers WHERE the FortiGate domain connector gets
  used (DNS Filter profile, Threat Feeds category group) and the External
  IP Block Lists bonus: Alex had to ask, nobody else should.

## v2.3.x (RFC domain labels, honest refresh state; 299 tests)

- **v2.3.0** tightened the domain-label regex to RFC 952/1123 (no
  underscore-tolerant octets sneaking into UniFi DNS lists), aligned the
  UniFi domain arm so it emits the same `firewall_value` the IP arm uses
  (a FortiGate/UDM hostname that isn't a valid label surfaces as a
  degraded/error row instead of silently importing), and strips path
  components from coerced hosts so a URL fed to a host feeder loses its
  `/path`.
- **v2.3.1** made the dashboard's Last-refresh card honest: it reports the
  real refresh outcome (rejected / errored / succeeded) instead of the
  optimistically green state that the old layout could show while a feed
  had just failed. Per-feed refresh errors now surface in the feed rows
  (a rejected refresh says so), and feeds that the operator reordered are
  flagged rather than silently re-sorted.
- Backup pruning (54a524d) now keys on the timestamped filename, not
  `os.path.getmtime()` — closes the review-checklist item where an NTP
  clock correction could produce a lexicographically-later but actually
  older backup that survived the prune.

## Predictor-scoring layer (v2.4 design; infrastructure live, model parked)

Direction: predict which indicators are about to leave (churn) and which
will come back, so a scoring layer can discount transient noise. The probe
showed there is no aged-out population to train on yet (oldest ~5 days,
gt_30d = 0), so the model is deliberately parked behind `predictor.enabled:
false`. Build the infrastructure first; the model is the last thing, not
the first — no churn labels exist until the log has run some weeks, and
shipping the predictor before then is just an overfit guess.

The gate is the two enabling pieces, both shipped:

- **`retention_days: 14`** bounds indicator eviction. `purge_stale_indicators`
  drops entries older than the window, and whitelisted IPs (exact and
  feed-scoped whitelist entries) are never purged — whitelist is operator
  intent, not feed state. NOTE: CIDR/wildcard whitelist entries are not
  expanded at purge, so an indicator merely *covered* by a whitelisted CIDR
  can still be purged; serve-time filtering still excludes it — this governs
  row retention only. The refresh path passes `db.get_whitelist_map()` so a
  whitelisted IP never ages out.
- **`sightings` churn log** is the leave/return ground truth. Per source per
  refresh tick, `append_sightings(source, present_map, tick)` snapshots that
  source's current indicator set in ONE batch (executemany on the
  UNIQUE(source_name, ip, tick) key) — the same batching discipline as the
  feed bulk-write path, so a refresh tick never wedges the log. A source
  that errored/skipped the tick is left out; its prior rows make the leave
  observable (ip present at tick N, no row at N+1). `run_refresh` wires this
  per successfully-refreshed source each tick.

Training signal (leave then return within window) only exists once the log
has accumulated measurable churn — weeks out. The prediction remains
vehicle-specific: per-kind natural breaks (tier_breaks / tier_breaks_domains)
carry over from the domain work; a LightGBM recurrence model runs dark until
the backtest on real accumulated churn passes. Open infra debt: the
sightings ring-window prune (vs. unbounded growth) and indicator eviction
both roll on retention; the backup-prune by timestamped filename (54a524d)
already avoids the mtime NTP edge.

## soc-grfna01 prod host: DNS resolver (2026-08-18)

The prod box has ONE working upstream resolver (`172.31.10.1`);
`192.0.231.200` is unreachable from the `172.31.10.x` subnet (every query
times out from the box, though it answers from other vantage points, e.g. a
workstation). With no resolver redundancy, a single dropped UDP:53 query
surfaced as a hard "could not resolve feed host" and flapped random feeds —
seen on `alienVault_otx` and `talos_snort` (different hosts, same DNS error,
so it's the resolver, not the feed). Mitigated with
`dns_opt: ["attempts:3","timeout:2"]` in the box's
`docker-compose.override.yml` (alongside the 1g mem cap), so a dropped lookup
retries the working resolver before failing. This override is box-local, not
in the repo. The generic fetch path already treats `gaierror` as a retryable
`ConnectionError`; scraper paths (Talos) lean on this libc-level retry. Real
fix if it recurs: a genuinely reachable secondary resolver on the subnet.

## Considered and parked: LOLRAMP policy blocker (2026-08-18)

Working theory was a default-deny RMM domain feed from lolrmm.io (317
tools, keyless JSON, verified live): sanction the RMMs the org uses,
serve everything else's domains at a dedicated policy URL for DNS
blocking. Parked because Alex's deployment (and any FortiGate with an
App Control license) does this better at L7 — application signatures
catch RMM protocols regardless of domain/port.

Design notes that survive if revived: this is POLICY not intel — it must
never enter the indicators corpus or the votes engine (corroboration is
meaningless for legitimate tools, FP semantics invert). Separate serving
URL, catalog-with-sanction-toggle UX, Monitor-before-Block guidance,
regex artifacts reduce to static suffixes. Revive triggers: demand from
pfSense/OPNsense/UniFi users (no App Control there), or long-tail RMM
abuse evidence (unsignatured tools are why LOLRMM exists).
