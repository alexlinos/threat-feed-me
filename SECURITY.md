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
| Dashboard + mutating API | Optional HTTP Basic auth (`DASHBOARD_USER`/`DASHBOARD_PASSWORD` + `dashboard.auth_required: true`) | Open by default for trusted-LAN convenience; **enable auth on any network you don't fully trust.** |
| TLS | **Not built in** | Terminate TLS at a reverse proxy in front of the container; `X-Forwarded-Proto`/`X-Forwarded-Host` are honored. |
| Rate limiting | **None** | The service assumes a LAN with well-behaved clients. Do not expose it to the internet. |

**Do not expose the dashboard or API directly to the internet.**

## Hardening measures in place

Verified in code review (adversarial pass, 2026-08):

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
- **Output safety filters**: RFC1918/reserved/bogon space and well-known
  public infrastructure (major DNS resolvers) are dropped from served block
  lists so a poisoned upstream feed cannot trick your firewall into
  blocking its own network.
- **CSRF**: all mutating endpoints require the `X-Requested-With` header the
  dashboard JS always sends, independent of whether Basic auth is enabled.
- **XSS**: server-side rendering uses Jinja2 autoescape; client-side row
  rendering HTML-escapes all feed-derived values.
- **Secrets**: feed API keys are stored server-side in the data volume's
  `.env`, applied immediately, and never displayed back to the browser.
- **Supply chain**: images are built multi-arch in GitHub Actions from a
  tagged commit, gated on the full test suite and version-consistency
  checks; every image ships with an **SBOM and provenance attestation**
  (see below).

## SBOM & provenance

Images published from v1.9.0 onward include BuildKit-generated **SBOM** and
**SLSA provenance** attestations. To inspect them:

```bash
docker buildx imagetools inspect alexlinos/threat-feed-me:latest \
  --format '{{ json .SBOM }}'
docker buildx imagetools inspect alexlinos/threat-feed-me:latest \
  --format '{{ json .Provenance }}'
```

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
