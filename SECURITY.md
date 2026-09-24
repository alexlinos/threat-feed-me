# Security Policy

## Reporting a vulnerability

Use **GitHub private vulnerability reporting**: *Security → Report a
vulnerability* on this repository. Please do not open public issues for
security problems. You can expect an acknowledgement within a few days;
fixes ship as a patch release with the advisory credited to you unless you
prefer otherwise.

## Supported versions

Only the **latest release** (`alexlinos/threat-feed-me:latest`) receives
fixes. There are no maintenance branches; upgrading is designed to be safe
(data survives on the volume; migrations run once on first start and
keep your data, e.g. 2.5.0 moves the churn log into its own file).

## Security model — read this before deploying

Threat Feed Me is built for a **trusted internal network**. Its trust
boundaries are deliberate and worth understanding:

| Surface | Posture | Why |
|---|---|---|
| Feed URLs (`/feeds/*`) | **Unauthenticated, by design** | Firewalls polling a block list cannot present credentials. Treat the feed content as non-secret. |
| TAXII 2.1 (`/taxii2/*`) | **Unauthenticated, read-only, by design** | The same content as `/feeds/*` for SIEM/TIP subscribers, with the same whitelist rules; no write endpoints exist. |
| Startup holding page | **Unauthenticated, static** | While a first start or an upgrade migrates the database, a stdlib server on the dashboard's port answers every request with one fixed 503 page (`Retry-After: 30`, `no-store`). It echoes nothing from the request, loads nothing external, and closes before the app binds the port. |
| Liveness probe (`/healthz`) | **Unauthenticated, by design** | The container healthcheck must pass even when Basic auth is enabled (`/api/*` would 401). Returns `{"ok": true}` and nothing else. |
| Dashboard + mutating API | Optional HTTP Basic auth — a sign-in set under System → Dashboard sign-in, or both `DASHBOARD_USER` and `DASHBOARD_PASSWORD` (the environment wins), turns it on (`dashboard.auth_required: true` also forces it, failing closed without them) | Open by default for trusted-LAN convenience; **enable auth on any network you don't fully trust.** |
| TLS | **Not built in** | Terminate TLS at a reverse proxy in front of the container; `X-Forwarded-Proto`/`X-Forwarded-Host` are honored. |
| Rate limiting | **None** | The service assumes a LAN with well-behaved clients. Do not expose it to the internet. |

**Do not expose the dashboard or API directly to the internet.**

What the software stores, sends and logs, and to whom, is documented in
[PRIVACY.md](PRIVACY.md).

## Hardening measures in place

Verified in code review (adversarial passes, 2026-08 and 2026-09, plus an
external review of the 2.5.0 branch on 2026-09-24; the fixes shipped in
v2.4.19 and v2.5.0):

- **Container runs as a non-root user** (`appuser`), single process, no shell
  services.
- **SQL is parameterized throughout**; the only interpolated fragments are
  internal constants (migration column names, placeholder counts), never
  request input.
- **Uploads** are size-capped (5 MB), text-only, validated to contain at
  least one valid entry of the feed's declared kind (IP/CIDR or domain),
  and the storage path is `realpath`-resolved and containment-checked so a crafted filename or symlink cannot escape the
  upload directory.
- **SSRF guard**: remote feed URLs whose host resolves to private/internal
  address space are refused (`safety.allow_private_feed_urls: false` by
  default), so a dashboard user cannot point a "feed" at cloud metadata or
  internal hosts. Since v2.5.0 the check is pinned to the connection: each
  hop resolves once, the addresses are validated, and the socket connects to
  exactly the validated address, so a DNS-rebinding host cannot answer
  public at check time and private at connect time. Adding a feed also runs
  the check up front, refusing an internal URL with a reason. While the guard
  is on, `HTTP(S)_PROXY` / `ALL_PROXY` are ignored for feed fetches: through a
  proxy the pin would check the proxy's address and the proxy would
  re-resolve the target itself (external review, 2026-09-24). Installs that
  set `allow_private_feed_urls` have no guard to protect and keep their proxy.
- **TAXII 2.1 collections added as feeds** (v2.5.0) use the same guarded
  fetch path: SSRF pin, hop-by-hop redirects, capped reads, and a key that
  must be a `TFM_FEED_*` variable sent only to the collection's origin.
  A read is bounded (250 pages of 1,000 objects, 250,000 objects in all),
  and one cut short by the cap fails instead of recording mass removals.
  Only STIX Indicators with unconditional patterns are taken; revoked,
  expired and `benign` ones are dropped, and a condition such as "this IP
  AND this port" is skipped rather than widened into a bare IP block.
- **Host-header allowlist** (v2.5.0, opt-in): switched on, the dashboard
  and API answer only to hostnames you allow, which stops DNS-rebinding
  pages in a LAN browser from driving the API. **Off by default and after an
  upgrade**: it refuses nothing until the operator turns on *Only answer to
  these names* (set-up guide or System) or sets `TFM_ALLOWED_HOSTS`. While
  off it only records which names reach the dashboard (in memory). Saving a
  name and enforcing are separate, so the guide can save a DNS name before
  its record exists without refusing anything; its *Check & add* does a DNS
  lookup only (no connection), of a syntactically valid hostname, behind
  auth and the CSRF check, with a 3-second timeout. IP literals and
  localhost always work, the name the switching request arrived on is kept,
  and `/feeds`, `/taxii2`, `/healthz` and static files are exempt so
  firewalls and SIEMs keep polling. We recommend switching it on once the
  names you use are listed.
- **Request bodies are capped** before authentication (1 MB, 6 MB for list
  uploads), by declared length and by counting streamed bytes.
- **Least privilege in the image** (v2.5.0): the runtime user owns only
  `data/` and `output/`; application code and config are read-only to it,
  and the `.env` temp file is created 0600.
- **CrowdSec credentials are bound to the LAPI** (v2.5.0): the machine login
  and bouncer key are sent only to the configured LAPI, never along a
  redirect or through an environment proxy, and are cleared when the LAPI
  address changes. The LAPI is an operator-configured LAN service, so the
  crowdsec scrapers are exempt from the feed SSRF guard for exactly that
  host; feed URLs cannot retarget the key (the scraper takes host and path
  from the integration, not the feed), and no feed may name the CrowdSec
  variables as its key. Decisions threat-feed-me published are excluded
  from the pull, so the tool can never corroborate itself.
- **Output safety filters**: any entry that *overlaps* IANA special-purpose
  space (RFC1918, CGNAT, loopback, link-local, multicast, documentation,
  IPv4-mapped/NAT64/ULA and other IPv6 special ranges) is refused, as are
  netblocks wider than a configurable floor (default /10, below the widest
  legitimate entries observed) and well-known public infrastructure (major
  DNS resolvers, a curated known-good domain floor). Overlap, not
  containment, is the rule: before v2.4.19 a supernet such as `10.0.0.0/7`
  passed because it is only partly private. The filter runs at ingest and is
  re-applied to everything already stored on every refresh, so a filter fix
  or a new operator known-good entry takes effect within one refresh.
- **Feed API keys are bound**: a feed's key variable must be one a built-in
  feed declares or an operator `TFM_FEED_*` name — never another secret
  (`UNIFI_*`, `DASHBOARD_*`) or a process setting (`*PROXY*`, TLS, interpreter
  variables). A built-in key is only ever sent to its built-in feed's host,
  keys are stripped from any redirect that changes origin (including
  https→http), and the data-volume `.env` cannot set proxy, TLS, interpreter
  or dashboard variables.
- **UniFi credentials are bound to their gateway**: changing the gateway host
  clears the saved login rather than carrying it to the new host; the site id
  is validated before it is used in gateway API paths.
- **Basic auth** compares credentials as bytes in constant time and always
  checks both fields. A sign-in set on the System page (v2.5.1) is stored as
  a salted scrypt hash, never the password; the password is always hashed,
  even for a wrong username, so timing doesn't reveal valid usernames. A
  verified login is remembered in memory, keyed by a per-process secret, so
  dashboard polling doesn't re-run scrypt. Changing it needs the current
  password. The first one can only be set on a request that arrived by IP
  address, localhost or a saved hostname: with auth off, a DNS-rebinding page
  can pass the CSRF check, but it arrives under its own domain, so it can't
  set a password the operator doesn't know. Environment credentials always
  win and can't be changed from the page. Locked out:
  `python -m threatfeedme.main --reset-dashboard-auth` on the host.
- **CSRF**: all mutating endpoints require the `X-Requested-With` header the
  dashboard JS always sends, independent of whether Basic auth is enabled.
- **XSS**: server-side rendering uses Jinja2 autoescape; client-side row
  rendering HTML-escapes all feed-derived values.
- **Secrets**: feed API keys are stored server-side in the data volume's
  `.env`, applied immediately, and never displayed back to the browser.
- **Supply chain**: the test suite runs on every push and pull request;
  images are built multi-arch in GitHub Actions from a tagged commit, gated
  on the full test suite and version-consistency checks (including that the
  two dependency pin lists agree); every image ships with an **SBOM and
  provenance attestation** (see below).

## SBOM & provenance

Images published from v1.9.0 onward include BuildKit-generated **SBOM** and
**SLSA provenance** attestations. To inspect them:

```bash
docker buildx imagetools inspect alexlinos/threat-feed-me:latest \
  --format '{{ json .SBOM }}'
docker buildx imagetools inspect alexlinos/threat-feed-me:latest \
  --format '{{ json .Provenance }}'
```

## Scanning the image yourself

The SBOM above is the input to a CVE scan. To scan the published image with
[Grype](https://github.com/anchore/grype) — no install required:

```bash
docker run --rm anchore/grype:latest alexlinos/threat-feed-me:latest
```

**How to read the results.** A scan covers the whole image, most of which is
the `python:3.11-slim` Debian base rather than this project's code. A raw
total (and the Critical count in particular) is misleading without this split:

| Bucket | Posture |
|---|---|
| **App dependencies** (`requests`, `fastapi`, `python-multipart`, …) | Pinned in `requirements.txt` **and** `pyproject.toml`, bumped promptly when an advisory affects a version we ship. This is the surface we own. |
| **Base OS packages with a fix available** (openssl, util-linux, …) | The Dockerfile runs `apt-get upgrade` at build, so a freshly built or pulled image carries the current Debian security fixes — rebuild/repull to refresh them. |
| **The Python interpreter** (`python` 3.11.x in the base image) | Built into `python:3.11-slim`, not installed by apt, so `apt-get upgrade` can't patch it. Grype may report a fix that exists only in a newer 3.11 patch release; it arrives when the upstream image publishes that release, and the Dockerfile's floating `python:3.11-slim` tag picks it up on the next build. (v2.4.19 and v2.5.0 were scanned against 3.11.16, the newest published; at v2.5.0 these interpreter entries were the only findings with a fix available anywhere in the image.) |
| **Base OS packages marked `wont-fix` / `not-fixed`** (perl-base, libc, …) | Debian's decision, present in essentially every Debian-based image. Several — e.g. all the perl CVEs — are **not reachable**: perl is never invoked by the application. Driving these to zero requires a different base image (distroless/alpine), a trade-off we have not taken. |
| **Build tooling** (pip, setuptools, wheel) | Present in the image but not part of the runtime attack surface: the service never installs packages at runtime. Since v2.5.0 the Dockerfile upgrades them past their advisories anyway, so a scan of a fresh build shows none. |

If you believe a finding is reachable and exploitable, report it via the
private vulnerability process at the top of this file — please include why
you believe it is reachable, not just the CVE id.

## Known limitations (accepted trade-offs)

- No rate limiting or brute-force lockout on Basic auth — front with a
  reverse proxy if you need either.
- Basic auth is the only built-in dashboard authentication (no OIDC/SSO).
- The UniFi gateway and CrowdSec LAPI are LAN hosts set from the dashboard,
  so anyone who can use the dashboard can point those integrations (and
  the credentials you saved for them, until the address change clears
  them) at a LAN host. Enable dashboard auth where that matters.
- With dashboard auth AND the host check both off (the defaults), a web
  page opened by anyone on your network can drive the dashboard through DNS
  rebinding: the browser treats the rebound page as same-origin, so the CSRF
  header check doesn't stop it. The app logs a warning on every start in
  that state. Set a password under System → Dashboard sign-in (or
  `DASHBOARD_USER`/`DASHBOARD_PASSWORD`), or switch on the host check once
  the names you use are listed.
- Credentials you save from the dashboard live in plain text in the data
  volume's `.env` (created 0600 on Linux; Windows ignores that mode).
  Protect the volume like any file holding secrets.
- Feed endpoints intentionally leak the block list to anyone who can reach
  the port; if that matters on your network, restrict reachability at the
  firewall.
- Upstream feed compromise is mitigated (safety filters, whitelist,
  reputation penalties) but not eliminated — a malicious upstream can still
  add arbitrary *public* IPs to your block lists. The confidence tiers exist
  precisely so you can choose how much corroboration to require.
