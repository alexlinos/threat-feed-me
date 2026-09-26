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

## Security rules for every change

These are standing rules, not suggestions. An adversarial review attacks the
diff against them before any release; `SECURITY.md` records what has been
verified. OWASP Top 10 is the outline, ASVS is the checklist.

- **Every input is hostile**: request parameters, uploaded files, fetched
  feed content, dashboard config. Parse with `ipaddress` / `idna`, cap sizes,
  reject rather than coerce. Never trust a feed to be well formed.
- **SQL is parameterized.** Never interpolate request-derived values, not even
  column names. Internal constants only.
- **User-supplied paths are `realpath`-resolved and containment-checked**
  against the upload directory. A filename or symlink must not escape it.
- **Remote fetches go through the SSRF guard** (`safety.allow_private_feed_urls`,
  default false). No new fetch path bypasses it.
- **Served lists pass the output safety filter** (bogons, RFC1918, known-good
  infrastructure). Never add an export that skips it; a poisoned upstream
  must not be able to make a firewall block its own network.
- **Mutating endpoints require the `X-Requested-With` header** (CSRF). New
  endpoints inherit the check; do not special-case one.
- **Escape on output.** Jinja autoescape stays on; client-side rows HTML-escape
  feed-derived values. No `innerHTML` with feed data.
- **Secrets never round-trip to the browser** and never land in logs, test
  fixtures or commits.
- **Run Grype on the image before tagging.** A new finding is fixed or
  documented as won't-fix in `SECURITY.md` in the same release.
- **A change to what the app stores or sends updates `PRIVACY.md` in the same
  commit.**

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
  `python -m uvicorn --app-dir src threatfeedme.app:app --port 8080`.
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

1. `phishing_army` ON — the extended blocklist (~156k, 6h updates, CC BY-NC
   4.0, non-commercial). Aggregates PhishTank + urlscan.io + Phishunt + OpenPhish +
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
- **`sightings` churn log** is the leave/return ground truth — **TRANSITION
  format since v2.4.9**. The original per-tick full-presence snapshots wrote
  ~50M rows/day (~10 GB/day of DB + backups to match) and nearly filled the
  prod disk in two days; they also diffed `get_source_ips` (indicator_sources
  = add-only attribution that never shrinks), so leaves were unobservable
  anyway. Now: `FeedIngestor.ingested_values` captures each clean fetch's
  ACTUAL post-filter values; `run_refresh` passes them to
  `db.update_source_sightings(source, values, tick)`, which diffs against
  `source_state` (per-source membership, bounded by the live corpus) and
  writes ONLY arrivals (present=1) / leaves (present=0). Unchanged refetches
  and not-modified/errored fetches write nothing (no fake mass-leaves).
  First observation seeds state with NO events (a baseline is a censoring
  boundary, not churn). `detect_leaves` reads transitions directly. The
  v2.4.9 schema migration DROPs old-format rows (a row-wise DELETE would
  balloon the WAL on an already-full disk), VACUUMs once to shrink the file
  (else freed pages keep inflating every backup), and stamps
  settings.sightings_format — one-time, self-healing for every deployment
  that pulled 2.4.2-2.4.8.

Training signal (leave then return within window) only exists once the log
has accumulated measurable churn — weeks out. The prediction remains
vehicle-specific: per-kind natural breaks (tier_breaks / tier_breaks_domains)
carry over from the domain work; a LightGBM recurrence model runs dark until
the backtest on real accumulated churn passes. Open infra debt: the
sightings ring-window prune (vs. unbounded growth) and indicator eviction
both roll on retention; the backup-prune by timestamped filename (54a524d)
already avoids the mtime NTP edge.

### Backtest passed + serving wired (2026-09-16)

The Task 9 backtest ran on the real 27-day log for the first time and PASSED:
AUROC 0.862 vs 0.776 source-count baseline vs 0.500 random, time-disjoint
split with a Sep-01 embargo (289k leave→return positive labels; ~40% return
rate — 10x past the readiness bar). Recall@10pct edge is thin (0.194 vs 0.182)
and the trainer's documented anachronism mildly inflates, so the model is a
within-tier ranking nudge to enable-small-and-watch, not to lean on.

Operationalized the SERVING side (previously only the consumption half existed —
`scorer.py` read `predictive_score`, nothing wrote it, and `predict_and_store`
was called nowhere):

- **`predict_pass.py`** — offline pass, mirrors `train_predictor.py`. Scores
  every `kind='ip'` indicator via `Predictor.score_many` (one feature build +
  one batch predict) and writes `metadata.predictive_score` in chunked
  `json_patch` transactions. Decoupled from `predictor.enabled` on purpose:
  it populates the field whenever a model file exists (so you can score-then-
  verify BEFORE flipping the switch); `enabled` gates only whether the scorer
  consumes it. Runs against the LIVE DB — WAL + chunked commits + `busy_timeout`
  keep it from blocking refresh.
- **Train/serve skew fix**: `Predictor.builder` now excludes the same
  `churn_log_exclude` feeds `train_predictor.build_dataset` drops. Without it,
  serving fed the model transitions the labels never saw, silently invalidating
  the certified backtest.
- **Offline-only, image stays dark**: numpy/lightgbm are in `requirements-dev`,
  never `requirements.txt`. `Dockerfile.predictor` layers them (+ libgomp1) onto
  the app image as a TOOLS image; `scripts/predictor.sh {train|predict|both}`
  runs it in a throwaway container against the data volume (mem-capped), for
  cron. The serving image never grows the ML deps or their CVE surface.
- **CI note**: the predictor/backtest tests never ran in CI before — the v2.4.13
  tag predates the predictor commits and CI only fires on version tags. Adding
  numpy/lightgbm to `requirements-dev` is what lets them run from the next
  release on. `test_predict_pass` gates its ML path on `importorskip`.
- **ENABLED (v2.4.15, 2026-09-17)**: `predictor.enabled: true`,
  `predictor_weight: 0.10` (~9% of the normalized score). After a week of clean
  daily predict passes (438k→457k IPs scored, distribution stable at
  0.17/0.70/0.99), the factor now shifts within-tier ranking. Tiers are still
  pure vote math (effective_votes), so this reorders inside a tier and never
  moves an IP between High/Medium/Low. At the time a config-only scoring change
  did NOT move the rescore gate, so the roll was followed by a forced recalc
  (POST /api/recalculate-scores). Fixed in v2.4.19 — the gate now hashes the
  scoring config, so no forced recalc is needed after a scoring-config edit.
- **Lock-hardening (v2.4.16, 2026-09-21)**: the daily predict pass crashed once
  on `sqlite3.OperationalError: database is locked` — at ~552k IPs a live
  rescore holds the single WAL writer lock longer than Database's 5s
  busy_timeout, so a `_write_chunks` chunk timed out. Fixed: the write path now
  sets a 120s per-connection busy_timeout and retries a chunk on lock (chunks
  are atomic, so a retry re-applies idempotently). If this recurs, the corpus
  has grown enough that the rescore itself needs attention, not the timeout.
- **honeydb_bad_hosts added to churn_log_exclude (v2.4.17, 2026-09-22)**: profiling
  the corpus growth found honeydb is a 24h-window wholesale-rotator (11.8k members
  but 222k distinct IPs touched in 7d = 18.8x rotation) contributing 24% of all
  predictor leave→return positives — rotation artifacts, not recidivism (same
  pathology as cins_army). A same-snapshot comparison backtest confirmed excluding
  it SHARPENS the model: lift over the source_count baseline grew +0.108 → +0.149,
  recall-lift doubled, and training went 58→236 rounds (real signal to learn once
  the noise is gone). The growth itself was benign — a real arrival surge (09-14→18,
  ~40k new IPs/day vs ~10k baseline) already receding; eviction is healthy (0 IPs
  past the 14d window); box cap raised 2g→3g for headroom.
- **Static (uploaded) feeds excluded from the predictor (v2.4.18, 2026-09-22)**:
  a `local_file=True` feed is re-read from an operator upload, not fetched from a
  changing source, so it has no organic churn — its only "transitions" are
  re-uploads (operator edits, not recidivism). `Database.local_file_feed_names()`
  is unioned into the exclusion set at BOTH read paths — `train_predictor.build_dataset`
  and `Predictor.builder` — so uploads drop from labels and features identically
  (same set, or train/serve skew reopens). This is by feed *shape* (local_file),
  NOT the `custom` threat-*category*: an operator-added REMOTE feed is categorized
  custom but does churn and stays predictable. Preventive — the only custom feed on
  prod (`custom_honeypot`) is disabled, so the live model is unchanged; a no-op
  backtest wasn't run. Logging path (run_refresh) is left keyed on churn_log_exclude
  names only — static uploads barely churn, so no log-bloat reason to touch it.

### Ratified (maintainer, 2026-08-20) — go direct to primaries, not aggregates

Direction: copy the SOURCES of aggregate lists (romainmarcoux malicious-domains/
malicious-ip reviewed as the trigger), never the aggregates themselves —
primary provenance feeds the votes engine real independence and can qualify
as authoritative. Live-probed and shipped in v2.4.7:

1. `drb_ra_c2` ON — drb-ra C2IntelFeeds, Cobalt Strike/C2 domains
   (30day-filter-abused variant: excludes legit fronted/CDN domains). ~100
   entries but a threat class nothing else in the roster covers. CSV via
   `drb_ra_domains` scraper. Future authoritative candidate after live obs.
2. `phishunt` ON — keyless live phishing URLs (~700). Upstream of
   phishing_army; same freshness rationale as openphish.
3. `phishtank_online_valid` OFF — **keyless after all** (older "key-walled"
   notes are stale; online-valid.csv downloads publicly, follow redirects).
   ~70k verified+online phishing URLs via `phishtank_urls` scraper. OFF per
   the cert_pl precedent (upstream of phishing_army, twin-flags).
4. `bsdly_traplist` ON — Peter Hansteen's greytrap (~600 IPs, hourly),
   genuinely independent trap-caught senders.

Probed and rejected this pass: digitalside (still down), red.flag.domains
(re-affirmed: French TLDs), ut1-fr (tarball format + French focus),
malwarebytes (no discoverable public URL), duggytuxy (no stable raw URLs,
FR/BE focus), projecthoneypot (membership-walled), stamparm/ipsum +
romainmarcoux full-* (aggregators — the very thing this ratification avoids).
Zero-code option for later: subscribe the OTX account to romainmarcoux's
AlienVault pulses (banking/dropbox/googledocs/microsoft/paypal phishtank,
phishing-scam) — they'd flow through the existing otx_pulses scraper.

## v2.4.19: fixes from the 2026-09-22 full review

A three-reviewer pass (security / architecture / usability), every
high-impact claim re-verified against code before acting. Shipped:

- **Safety filter supernet bypass** (`safety.py`): `is_private` on a network
  needs BOTH ends private, so `10.0.0.0/7` etc. passed. Now: overlap against
  explicit IANA special-purpose v4+v6 registries, a prefix floor (default /10 —
  the widest legit prod entries are /12; /16 would have dropped Spamhaus DROP
  blocks), and `purge_unsafe_indicators` re-applies the filter to the store on
  every refresh. Prod had 0 stored offenders.
- **Credential exfiltration** (`credentials.py`, new): `auth_env` was taken
  verbatim, so a feed could name `UNIFI_PASSWORD`/`DASHBOARD_PASSWORD` and send
  it anywhere, or name `HTTPS_PROXY` and poison every request. KeyPolicy: keys
  are shipped vars or `TFM_FEED_*` only; shipped keys bound to their shipped
  host; no key crosses a redirect origin; OTX `next` must stay on-origin; `.env`
  can't set proxy/TLS/interpreter/dashboard vars. Ingestor fails closed without
  a roster. UniFi: host change clears the saved login; site id validated.
- **Retention was a no-op for ETag feeds**: a 304 touched every IP a feed EVER
  listed (add-only attribution). Now touches `source_state` (true current
  membership), attribution fallback only for never-seeded feeds. Expect a
  one-time purge wave ~14 days after rollout. This corrects the 2026-09-22
  growth profile's "eviction is healthy" — that reading was the bug's symptom.
- **Disabled feeds kept voting**; the scorer now ignores them.
- **Rescore gate** = `pipeline.scoring_input_key`: corpus counts + max(rowid)
  per table + a hash of scoring config, predictor state/model mtime, the feed
  catalog (weight/enabled/type), the whitelist, and a predict-pass stamp. The
  "config-only scoring change needs a forced recalc" gotcha is gone.
- **Predictor inert without a model file** (`scorer.predictor_live`). The
  v2.4.15 enable had turned it on for every install; fresh installs paid a ~9%
  renormalization for nothing. `predictor.sh` now rebuilds the tools image
  whenever the app image changes (label `tfm.app_image_id`).
- **Published-image auth**: setting both `DASHBOARD_USER`/`DASHBOARD_PASSWORD`
  enables auth (config is baked in, so pull-image users had no way before);
  constant-time byte compare of both fields. Compose has an optional,
  commented-out config mount (a missing file would become a directory).
- Shrink guard (collapsed fetch held out of the churn log, accepted after 3),
  loud logging where scoring used to fail open silently, atomic export writes,
  CIDR-correct on-disk CSV, capped reads on every fetch path, `_lan_ip` via the
  default route (the host-coupled test now passes), push/PR CI workflow, and a
  test that the two dependency pin lists agree.

**Test-isolation traps hit this release** (don't repeat): reading
`core.config` in a test lazily INITIALIZES core from the repo's real
config.yaml + `./data` DB and leaks into every later test (it once wrote test
data into a developer's local `data/` and did live feed fetches) — patch a
seam (`auth._dashboard_config`) instead. The csrf fixture must restore
`DASHBOARD_*` at teardown. Tests using `dashboard.db` must sit ABOVE the
module-reloading csrf tests in `test_dashboard_feeds.py`.

**Still open from the review (tracked for v2.5.0)**: Host-header allowlist
(`TrustedHostMiddleware`) against DNS rebinding; SSRF resolve-then-connect
gap (pin the checked address); request-body size cap before auth; grant
domain authority by seeded feed + URL, not name; `.env` temp-file mode 0600
at creation; runtime user owning only `data/` + `output/`; cached, ETag'd
feed bodies (a `/feeds/low.txt` poll peaks ~1.6 GB); a single writer lock
plus a chunked, changed-rows-only rescore; the predictor training-population
leakage (evicted IPs read `source_count=0` — re-backtest before quoting AUROC
externally); `?limit=N` on served feeds. Usability items (High-vs-Medium
recommendation conflict, FP-default whitelist reason, add-feed overwrite,
pulse-row false green / double-counted "new in 24h") also queued.

## v2.5.0 "Flytrap" (branch release/2.5.0; "the release that gets us noticed")

Work happens on `release/2.5.0` until tested; main stays the released
version (maintainer's call, 2026-09-23). Positioning: **the open-source
MineMeld replacement** (README + site lead with it; MineMeld hosted EOL
2021-08-01, archived 2023-03). What landed, with the decisions behind it:

- **Vote grace, 3 days (maintainer-ratified after measurement)**: a feed's vote
  lasts while it lists an indicator and `scoring.vote_grace_days` after
  (`source_left`, pruned before every rescore; `source_seeded` marks
  baselines). Prod snapshot: hard cut IP HIGH 36.8k -> 5.0k (rejected: most
  feeds are short windows, cross-day corroboration is real); 3d -> ~10.7k at
  rollout, 10.7-17k steady. The HIGH drop at rollout is the fix working.
- **Predictor leak fixed**: point-in-time features (`live_source_count`, first
  seen as of T, density excluding self), corpus-at-T population, IPs only.
  Honest AUROC **0.82** (was quoted 0.86-0.88; baseline 0.737 -> 0.598). Old
  models are refused by feature name: run `scripts/predictor.sh both` right
  after rolling 2.5.0.
- **CrowdSec both ways** (`crowdsec.py`): publish = generation-swapped ban
  decisions (post new, then expire old by scenario; never a gap), 24h
  duration, re-published at half-duration even on the skip-rescore path;
  pull = `crowdsec_local/community/lists` split by origin, own decisions
  excluded server- AND client-side. LAPI treated like the UniFi gateway
  (SSRF-exempt for that host only, creds bound + cleared on host change).
  Live-verified against CrowdSec 1.8.1 (`tests/test_crowdsec_live.py`,
  opt-in via TFM_CS_*). Never publish into a honeypot's CrowdSec.
- **TAXII 2.1** (`taxii.py`, read-only, 6 collections = the 6 feed URLs, same
  row_included rules, exempt from the host check like /feeds). Verified with
  the OASIS taxii2-client + stix2-validator (341k objects, 0 invalid).
  Discovery must use `_feed_base(..., swap_loopback=False)`.
- Also: Host-header allowlist (off until switched on; see below), connect-time SSRF
  pinning, body caps, least-privilege image, lean cached feed serving with
  ETag + `?limit=N`, single heavy-writer lock + changed-rows-only rescore,
  "last polled by" per URL (`polls.py`, no IPs stored), System panel,
  first-run card, masked key dialog, recommend Medium, 409 on duplicate feed
  names.

**Interface redesign (maintainer-ratified 2026-09-23, from 10 mockups)**:
direction 08 "Slate Pro" (icon rail + top bar, block lists as cards) with
direction 10 "Guided" as the first-run view. Mark **A** (side-on chomper on a
stem, red prey in front) everywhere; mark **D** (the chomper eating the red
dots of `203.0.113.7`, RFC 5737 space, never a real IP) for heroes, banner,
site and social card. Geometry lives in `templates/_mark.html`; the jaws are
separate groups so CSS chomps them during a refresh. Decisions that aren't
obvious from the code:
- One page, five hash-routed views (guide/lists/feeds/integrations/system);
  an inline script sets `html[data-view]` before paint so the wrong view
  never flashes, and `reloadPage()` carries the view across in
  sessionStorage (a same-URL+hash navigation is a fragment jump, not a
  reload). The guide is the default until any IP list has been polled.
- No web fonts, CDNs or external images: the dashboard runs air-gapped.
- **Host check is OFF on upgrade and by default** (maintainer): enforcing
  needs the explicit switch (`allowed_hosts_enforce` = "1") or
  `TFM_ALLOWED_HOSTS`. Saving names is separate from enforcing: the guide's
  "Name this server" saves a DNS name (enforce untouched) and
  `/api/host-check/resolve` reports whether it resolves to the address in
  use. A missing flag is off, not "legacy locked" (no release ever saved a
  list before the flag). With auth and the host check both off the app logs
  a DNS-rebinding warning on every start; NO dashboard banner for it
  (maintainer, 2026-09-24).

**TAXII 2.1 as a feed (2.5, `stix_ingest.py` + the `taxii21` scraper)**:
operator adds a collection URL with format `taxii21` (a closed map in
routers/feeds.py; clients never name scrapers). Indicators only (bare SCOs are
context, blocking them takes down victims); only unconditional patterns (AND
binds tighter than OR: a chain with two value comparisons, e.g. IP AND port,
is skipped, never widened; `*_ref.type` annotations are dropped first so
MISP's dst_ref shape works); revoked / expired / `benign` drop out. Every
refresh reads the WHOLE collection (added_after would only see arrivals, so
nothing would ever leave); a read cut short by the page cap FAILS instead of
recording mass leaves. One kind per feed. Verified by a TFM->TAXII->TFM round
trip (tests) and live over HTTP: 24,118 IPs / 81,798 domains, exact match.

**MineMeld claims (research 2026-09-23; Reddit was unreachable, sources are
LIVEcommunity, the archived GitHub repos/issues, blogs)**: we cover its core
job (open feeds -> confidence-tiered EDLs), whitelists, TAXII 2.1 in/out and
non-PAN firewalls. We do NOT cover its most visible job, the O365 and
AWS/Azure/GCP allow-lists (2.6, `ROADMAP.md`), nor DAG push, syslog miners,
TAXII 1.x or per-entry aging of manual lists. Say "replaces MineMeld's
threat-feed pipeline", not a blanket "replaces MineMeld"; the coverage table
in `docs/minemeld.html` is the source of truth for claims. Palo Alto's own
successors are Cortex XSOAR TIM and the EDL Hosting Service: name them
fairly. MineMeld/PAN-OS names are used nominatively, with the
not-affiliated line on the site, README and video end card.

**Database slimming (2.5, measured on a prod backup copy)**: the churn log
moved to `<db>-churn.db`, ATTACHed as `churn` on every connection (queries say
`churn.sightings`). One WITHOUT ROWID b-tree keyed (source, ip, tick), tick as
epoch seconds; no tick index (the prune scans, ~1 s at 6.7M rows). Upgrade
MIGRATES the log (dropping it would leave the predictor unable to retrain for
weeks), drops the duplicate `idx_indicators_ip`, strips the never-read
per-fetch metadata keys, VACUUMs once: 1,858 MB -> 421 MB main + 267 MB churn
in 124 s; backtest on the migrated copy AUROC 0.814 (unchanged). Health-check
start period is 300 s so a watchdog can't kill that first start. The entrypoint's
schema step is `main.py --init-db`: logging configured (the old `python -c`
swallowed INFO), a message BEFORE the long copy, and a static 503 + Retry-After
holding page on the dashboard host/port until the DB is ready. Skipped: a
predictive_score column (metadata is ~25 bytes now; no measured gain).

**External review of the branch (2026-09-24)**, each claim re-checked against
the code. Fixed: a manual re-add or in-place tier change left the feed cache's
`serve_fingerprint` unmoved (now `set_indicator_score` bumps `serve_stamp` in
the same transaction); `HTTP(S)_PROXY`/`ALL_PROXY` bypassed the connect-time
SSRF pin because the pin checked the proxy's address (guarded fetches now pass
`_NO_PROXIES`; installs with `allow_private_feed_urls` keep their proxy);
a 32 KB parametrize id broke Windows. Rejected, don't reopen without new
evidence: "KeyPolicy re-binds a shipped key when the DB URL changes" (the
policy binds to the host declared in config.yaml, and a test covers the
retarget case) and the Host-parsing edge cases (IP-literal and absent Host are
allowed on purpose so an operator can never lock themselves out; `h:80:8080`
is not a valid Host). The rebinding default stays a startup log warning, no
banner. The integrations, DB and serve-path sections of that review had not
arrived when this was written; verify each claim before acting on it.
Grype on the branch head: 162 matches, identical to the first 2.5 build, none
in app dependencies, the only fixable ones in the 3.11 interpreter
(documented in SECURITY.md). Rescan the final image before tagging.

**Released 2026-09-24** (maintainer's go): `release/2.5.0` merged into main
(970a14a), tagged `v2.5.0`, published to Docker Hub as 2.5.0 + latest (amd64 +
arm64); Grype on the final image matched the branch baseline. New 2.5.x work
goes on main. Prod (soc-grfna01) roll is a separate, explicit step: back up,
`git pull` (the compose health-check start period matters for the migration),
`docker compose pull && up -d`, then `scripts/predictor.sh both` at once.

**Test-isolation trap, third time**: core initializes lazily from
./config.yaml + ./data, and `monkeypatch.setattr(core, "db", ...)` READS the old
value (a lazy init). conftest now defaults CONFIG_PATH to a temp config AND
fails the run if anything under data/ changes. In tests, patch
`module.__dict__` via `monkeypatch.setitem`, on the live module (suites purge
and re-import threatfeedme). Never import `threatfeedme.app` bare in a test.

## v2.5.1 (2026-09-24, from the maintainer's post-roll bug hunt)

- **Dashboard sign-in on the System page**: username + salted scrypt hash
  in settings (`auth.AUTH_SETTING`); env DASHBOARD_USER/PASSWORD still win.
  The FIRST password is accepted only on a request that arrived by IP,
  localhost or a saved hostname (a DNS-rebinding page can pass the CSRF
  check with auth off, but not that). Why: the 2.5.0 prod roll recreated the
  container from a shell without the env vars and auth came up silently off.
  Lockout: `main.py --reset-dashboard-auth`. A verified login is cached under
  a per-process key so polling doesn't rerun scrypt.
- **Stall fix**: during a refresh the dashboard serves its last telemetry and
  list counts; the refresh warms both caches before reporting done. Prod
  measurement: rescore contention was ~0.3 s, the post-fetch rebuild 4.3 s,
  so the child-process-per-refresh idea was measured and REJECTED; don't
  revive it without new numbers.
- Per-feed timers (`pipeline.feed_schedule` is the one due-time source for
  scheduler and UI); FortiOS's default UA `curl/7.58.0` labels as FortiGate;
  retrain gate: a model replaces the live one only at hold-out AUC >= 0.70
  (atomic write). Kept at maintainer's call: 15/30-min openphish/dshield
  cadence, weekly retrain.

## v2.5.2 (2026-09-26): bugfix, and where 2.6 starts

- **Sign-in guard bypass closed** (bd3caa6): with no password set, POST
  /api/host-check accepted any names from any request, so a DNS-rebinding
  page could save its own domain, then pass the first-password guard from
  that "saved" name. Until a sign-in exists, the hostname list only changes
  from an IP, localhost or an already-saved name. A "Trust this name" button
  was considered and dropped: it is the same bypass.
- **Main is bugfix-only until the maintainer opens 2.6** (2026-09-25). Every
  open 2.6 decision is in ROADMAP.md, "2.6: decisions waiting on the
  maintainer": the vetted feed shortlist with URLs (ratify one at a time,
  re-probe first), the non-commercial-feed options (recommended: exclude
  those feeds from CrowdSec publish and TAXII), and the UI mockups on the
  maintainer's design canvas. The application lists section above it is
  the agreed 2.6 core; threat-type lists and the list builder are proposals.
- Prod (soc-grfna01) runs 2.5.1; its dashboard password must be set once by
  IP (`http://172.31.10.4:8080/#system`). The 2.5.0 canary (`tfm-canary`,
  `~/tfm-canary`, holds a prod DB copy + .env) still needs tearing down by
  the maintainer.

## Domain HIGH is provenance-first (v2.4.6, ratified 2026-08-20)

Live data settled it: domain blocklists aggregate each other, so the
overlap-discounted vote count collapses their consensus toward one witness —
measured on prod, the max domain sat at 1.97 effective votes (3 raw sources)
and NO domain could clear the 2.0 boundary; domain HIGH was structurally
empty. v2.4.4's raw-count witness gate was the wrong fix (it counted
correlated feeds as independent and bypassed require_threat_intel; reworked
in 2.4.5). The ratified model (2.4.6): **who reported a domain is the
signal** — feeds listed in `scoring.high_confidence.authoritative_domain_feeds`
(shipped: urlhaus_hostfile, cert_pl — primary curators, never aggregators)
force HIGH on their own word. The effective-votes witness gate remains as a
secondary path; both honor require_threat_intel; tier-scoped whitelist is the
per-domain FP escape hatch. Live-verified: 459 urlhaus domains in HIGH.

Post-roster-audit refinements (2026-08-20, v2.4.8): **authority is revocable
by evidence** — an authoritative feed whose FP penalty factor drops below
FP_DEGRADED_FACTOR (0.6, the same threshold as the dashboard's "degraded"
badge) loses force-HIGH until the flags clear; keyed on the penalty factor,
not weight, so an operator-pinned low base weight never strips authority.
Rationale: tiers are pure vote math and never see reputation, so without this
the FP self-heal loop couldn't touch provenance-HIGH at all. Also noted from
the audit: the witness gate (>=3 effective votes) is currently SHADOWED by
the 2.0 boundary floor — the boundary is the easier corroboration path to
domain HIGH; this is deliberate layering, don't "fix" it. Open decision:
promotion criteria for drb_ra_c2 into authoritative_domain_feeds (proposed:
~2 weeks live, zero FP flags, stable fetches) — its live C2s currently sit
in low/medium, below urlhaus commodity malware, until promoted.
(Historical gotcha, fixed in v2.4.19: a config-only scoring change used to
leave the rescore gate unmoved and needed a forced recalc via
POST /api/recalculate-scores — there is no dashboard button for it.)

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
