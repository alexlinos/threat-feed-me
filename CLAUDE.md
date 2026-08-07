# Working agreement

## GitHub is the source of truth

`https://github.com/alexlinos/threat-feed-me` — branch `main`.

Local checkouts are disposable views of it. If a local copy and the remote
disagree, the remote wins.

- **`git pull` before you start.** Another agent or session may have pushed
  since this checkout was last touched.
- **Push as soon as you commit.** Never leave a commit sitting locally — an
  unpushed commit is invisible to everyone else and is how two agents end up
  building on different bases.
- **One clone per machine.** Parallel folders (`...-2`, `-new`, `-copy`) have
  caused real divergence here — two checkouts a day apart, different agents
  building on different bases. If a checkout is broken, fix it or re-clone it
  in place rather than working beside it.
- Before a large change, re-check `git log origin/main -1` — cheap, and it
  catches a stale base immediately.

## Releasing

CI publishes the Docker image on a `v*.*.*` tag and **refuses to publish if
the tag and `pyproject.toml` disagree** — that guard has silently blocked two
releases already.

1. Bump `version` in `pyproject.toml` **and** `__version__` in
   `src/threatfeedme/__init__.py` — CI checks the tag against both (the
   footer displays `__version__`), and a unit test keeps the pair in sync.
2. Commit, push.
3. `git tag vX.Y.Z && git push origin vX.Y.Z`
4. Confirm the run at `gh run list --workflow "Publish Docker image"`. A tag
   alone is not a release; check that the build actually succeeded.

## Verifying

- `python -m pytest tests -q` must pass before pushing.
- For UI or behavioural changes, actually run it and look —
  `python -m uvicorn --app-dir src threatfeedme.app:app --port 8080`.
  Several bugs here (a dead `esc()`, a hung geo panel, an unreadable heatmap)
  passed every test and were only visible in a browser.

## Conventions

- **No AI attribution in commits.** No `Co-Authored-By: Claude`, no naming
  models in commit messages or docs. Multiple models work on this repo; the
  history stays clean of all of them.
- Commit messages explain *why*, not just what — the reasoning is the part
  that isn't recoverable from the diff.
- `data/` is gitignored and disposable (fetched feed state, SQLite DB). Never
  commit it; never assume another checkout has the same contents.
- Comments carry design rationale, especially in `feed_ingestor.py`,
  `scorer.py`, and `telemetry.py`. Read before changing behaviour there.

## Review findings — round 4 complete, fixes applied (uncommitted, branch `main`)

Working copy: `C:\Users\Beefcess\threat-feed-me` (the canonical clone). Changes are
**NOT committed** — review against the working tree. Four A2A review passes done.

### Round 1 fixes (Claude pass 1)
- `main.py` `_serve(cfg)` — host/port resolve `$DASHBOARD_HOST`/`$DASHBOARD_PORT` env
  override, then `dashboard.host`/`dashboard.port` from config.yaml, then safe
  defaults `127.0.0.1`/`8080`; pins `CONFIG_PATH` + single `core.init()` before the
  refresh thread; dead `db` param removed.
- `core.py` `init()` — no-op guard on the SAME config (`if _initialized and
  `_config_path == path: return`), closing the lifespan vs scheduler-thread
  concurrent re-init race. `reset()` clears `_initialized`, so reset->init works.
- `Dockerfile` `ENV DASHBOARD_HOST=0.0.0.0` before CMD (container binds externally).
- `entrypoint.sh` `exec python -m threatfeedme.main --serve`.
- `README.md` + `config.yaml` — stale binding text fixed.

### Round 2 defect and fix (Claude pass 2)
Claude found `_serve` resolved `cfg_path` from `CONFIG_PATH`/hardcoded `'config.yaml'`,
discarding the CLI's `--config`. Fixed: `_serve(cfg, config_path=None)` accepts the
caller's path; resolves `cfg_path = config_path or os.environ.get('CONFIG_PATH') or
'config.yaml'`; call site passes `args.config`.

### Round 3 fixes (Claude pass 3 recommendations)
- `main.py`: host/port resolution extracted into module-level `_resolve_host_port(cfg)`
  returning `(host, port)`; `_serve` delegates to it.
- `tests/test_serve.py`: new host-resolution unit tests (env override > config >
  default; env host alone keeps configured port).

### Round 4 fixes (Claude pass 4 before-release)
- Healthcheck blind-spot: both `Dockerfile` + `docker-compose.yml` probes changed from
  `http://127.0.0.1:8080/...` to probe the container's own non-loopback address
  (`socket.gethostbyname(socket.gethostname())`). `--start-period=10s` aligned with
  compose's `start_period: 10s`. (Claude: 0.0.0.0 as destination is kernel-rewritten
  to loopback, so the earlier 0.0.0.0 probe was exactly as blind as the loopback one.)
- `main.py`: bare `python -m threatfeedme.main` now prints help and returns BEFORE
  Database construction (old `if not any(vars(args).values())` check removed, which
  could never fire because `args.config` always holds a truthy default).
- `core.py` `reset()` now also clears `_config_path`.
- Test env-leak fixed: `monkeypatch.setenv` instead of raw `os.environ[...]` writes,
  and the two affected test functions now declare `monkeypatch` as a parameter.

### Open items (Claude pass 4: can wait)
- 3.1 `CONFIG_PATH` is inert as an operator knob on the CLI path — `args.config` always
  has a default, so the env fallback is never consulted on the CLI. No deploy path sets
  it. Low priority.
- 3.4 Redundant second `Database` on `--serve`: `main()` builds one and runs seed+sync,
  then `_serve` -> `core.init()` builds a second and runs seed+sync again. Idempotent
  waste, not corruption. Cleanest fix is moving the `--serve` branch above Database
  construction, but that is coupled with 3.1.
- 3.5 Config-shape edge cases: `dashboard: {host: }` yields `host=None` passed to
  uvicorn; `dashboard: {port: }` makes `int(None)` raise TypeError; `database:` null
  breaks `cfg.get('database', {}).get('path', ...)`. Shipped `config.yaml` is well-formed.

### What to verify before release
- `python -m pytest tests -q` passes (202 passed locally).
- Healthcheck probe actually fails on loopback-only bind / succeeds on wildcard bind
  (new probe targets the container's non-loopback address).

