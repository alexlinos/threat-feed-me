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
(data survives on the volume, migrations are additive).

## Security model — read this before deploying

Threat Feed Me is built for a **trusted internal network**. Its trust
boundaries are deliberate and worth understanding:

| Surface | Posture | Why |
|---|---|---|
| Feed URLs (`/feeds/*`) | **Unauthenticated, by design** | Firewalls polling a block list cannot present credentials. Treat the feed content as non-secret. |
| Liveness probe (`/healthz`) | **Unauthenticated, by design** | The container healthcheck must pass even when Basic auth is enabled (`/api/*` would 401). Returns `{"ok": true}` and nothing else. |
| Dashboard + mutating API | Optional HTTP Basic auth — setting both `DASHBOARD_USER` and `DASHBOARD_PASSWORD` turns it on (`dashboard.auth_required: true` also forces it, failing closed without them) | Open by default for trusted-LAN convenience; **enable auth on any network you don't fully trust.** |
| TLS | **Not built in** | Terminate TLS at a reverse proxy in front of the container; `X-Forwarded-Proto`/`X-Forwarded-Host` are honored. |
| Rate limiting | **None** | The service assumes a LAN with well-behaved clients. Do not expose it to the internet. |

**Do not expose the dashboard or API directly to the internet.**

What the software stores, sends and logs, and to whom, is documented in
[PRIVACY.md](PRIVACY.md).

## Hardening measures in place

Verified in code review (adversarial passes, 2026-08 and 2026-09; the
2026-09 review's fixes shipped in v2.4.19):

- **Container runs as a non-root user** (`appuser`), single process, no shell
  services.
- **SQL is parameterized throughout**; the only interpolated fragments are
  internal constants (migration column names, placeholder counts), never
  request input.
- **Uploads** are size-capped (5 MB), text-only, validated to contain at
  least one IP/CIDR, and the storage path is `realpath`-resolved and
  containment-checked so a crafted filename or symlink cannot escape the
  upload directory.
- **SSRF guard**: remote feed URLs whose host resolves to private/internal
  address space are refused (`safety.allow_private_feed_urls: false` by
  default), so a dashboard user cannot point a "feed" at cloud metadata or
  internal hosts.
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
  checks both fields.
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
| **Base OS packages marked `wont-fix` / `not-fixed`** (perl-base, libc, …) | Debian's decision, present in essentially every Debian-based image. Several — e.g. all the perl CVEs — are **not reachable**: perl is never invoked by the application. Driving these to zero requires a different base image (distroless/alpine), a trade-off we have not taken. |
| **Build tooling** (pip, setuptools, wheel) | Present in the image but not part of the runtime attack surface — the service never installs packages at runtime. |

If you believe a finding is reachable and exploitable, report it via the
private vulnerability process at the top of this file — please include why
you believe it is reachable, not just the CVE id.

## Known limitations (accepted trade-offs)

- No rate limiting or brute-force lockout on Basic auth — front with a
  reverse proxy if you need either.
- Basic auth is the only built-in dashboard authentication (no OIDC/SSO).
- Feed endpoints intentionally leak the block list to anyone who can reach
  the port; if that matters on your network, restrict reachability at the
  firewall.
- Upstream feed compromise is mitigated (safety filters, whitelist,
  reputation penalties) but not eliminated — a malicious upstream can still
  add arbitrary *public* IPs to your block lists. The confidence tiers exist
  precisely so you can choose how much corroboration to require.
