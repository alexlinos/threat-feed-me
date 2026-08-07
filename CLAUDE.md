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

## Open items (from the A2A serve review; fixes landed in 510d148)

Rounds 1-4 of the serve-immediately review were applied and committed in
`510d148` — the log that used to live here described them as uncommitted,
which stopped being true the moment they were committed. What remains open:

- `CONFIG_PATH` is inert as an operator knob on the CLI path — `args.config`
  always holds a truthy default, so the env fallback is never consulted.
  No deploy path sets it. Low priority.
- Redundant second `Database` on `--serve`: `main()` builds one and runs
  seed+sync, then `_serve` -> `core.init()` does it again. Idempotent waste,
  not corruption; cleanest fix is coupled with the CONFIG_PATH item.
- Config-shape edge cases: `dashboard: {host: }` yields `host=None` to
  uvicorn; `dashboard: {port: }` makes `int(None)` raise; a null `database:`
  key breaks path lookup. The shipped config.yaml is well-formed.
