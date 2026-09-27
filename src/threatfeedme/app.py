"""FastAPI application assembly: lifespan, static assets, and router wiring."""
import logging
import os
import threading
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

# Importing `core` triggers lazy init on first attribute access — no work is
# done at import time. The lifespan below explicitly warms the singletons.
from threatfeedme import core  # noqa: F401  (module-level __getattr__ lazy init)
from threatfeedme.middleware import BodyLimitMiddleware, HostCheckMiddleware
from threatfeedme.scheduler import _scheduler_loop, _scheduler_stop
from threatfeedme.routers import feeds, indicators, integrations, system, taxii, whitelist


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Warm the core singletons (config/db/safety/templates) so every module
    # that imports `from core import ...` gets a ready state, not a lazy-init
    # that might race with the first request.
    core.init()
    # Both stay OFF by default (maintainer's call), and together that means any
    # web page a LAN user opens can drive this dashboard through DNS rebinding
    # (review 2026-09-24). Behaviour unchanged; say so on every start.
    from threatfeedme import auth, middleware
    if not auth.auth_enabled() and not middleware.effective_allowlist(core.db):
        logging.getLogger(__name__).warning(
            "Dashboard auth and the host check are both off: a malicious web page opened on "
            "this network could use DNS rebinding to change feeds and whitelists. Set a "
            "password under System -> Dashboard sign-in (or DASHBOARD_USER and "
            "DASHBOARD_PASSWORD), or switch on 'Only answer to these names' under "
            "System -> Dashboard hostnames.")
    # Start the background auto-refresh scheduler (unless disabled, e.g. tests).
    if os.environ.get("DISABLE_SCHEDULER") != "1":
        threading.Thread(target=_scheduler_loop, name="feed-scheduler", daemon=True).start()
    yield
    _scheduler_stop.set()


# No /docs, /redoc or /openapi.json: FastAPI serves them outside every route
# dependency, so they handed a full map of the API to anyone on the network
# even with sign-in on (auth pentest, 2026-09-27). Nothing here uses them.
app = FastAPI(title="Threat Feed Me! Dashboard", lifespan=lifespan,
              docs_url=None, redoc_url=None, openapi_url=None)


# FastAPI's default 422 echoes each rejected value back ("input"). That both
# reflects whatever was sent (an oversized or malformed API key included) and
# crashed into a 500 on weight=inf, since the error body itself isn't valid
# JSON (QA, 2026-09-27). Say what was wrong and where, never the value.
@app.exception_handler(RequestValidationError)
async def _validation_error(request, exc: RequestValidationError):
    errors = [{k: e[k] for k in ("type", "loc", "msg") if k in e} for e in exc.errors()]
    return JSONResponse(status_code=422, content={"detail": errors})

# Compress anything sizeable: the world-map paths, the dashboard HTML, and the
# plain-text feeds a firewall polls (a 50k-line block list is mostly digits and
# compresses ~4x). Below 1 KB the header overhead is not worth it.
app.add_middleware(GZipMiddleware, minimum_size=1024)

# Cap request bodies before any route (or its auth dependency) reads them.
# Added last so it runs outermost: an oversized body is refused before the
# app — including FastAPI's own body parsing — touches it.
app.add_middleware(BodyLimitMiddleware)

# Host-header allowlist against DNS rebinding. Added last = outermost, so an
# unknown hostname is turned away before anything else runs. Report-only
# until an allowlist is configured; feeds/healthz/static are never checked.
app.add_middleware(HostCheckMiddleware)

# Static assets (extracted dashboard CSS/JS). Anchored to this module's
# directory so it works regardless of the process CWD (tests use a temp CWD).
app.mount("/static",
          StaticFiles(directory=os.path.join(os.path.dirname(__file__), "static")),
          name="static")

app.include_router(indicators.router)
app.include_router(system.router)
app.include_router(feeds.router)
app.include_router(whitelist.router)
app.include_router(integrations.router)
app.include_router(taxii.router)
