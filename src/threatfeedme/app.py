"""FastAPI application assembly: lifespan, static assets, and router wiring."""
import os
import threading
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.staticfiles import StaticFiles

# Importing `core` triggers lazy init on first attribute access — no work is
# done at import time. The lifespan below explicitly warms the singletons.
from threatfeedme import core  # noqa: F401  (module-level __getattr__ lazy init)
from threatfeedme.scheduler import _scheduler_loop, _scheduler_stop
from threatfeedme.routers import feeds, indicators, system, whitelist


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Warm the core singletons (config/db/safety/templates) so every module
    # that imports `from core import ...` gets a ready state, not a lazy-init
    # that might race with the first request.
    core.init()
    # Start the background auto-refresh scheduler (unless disabled, e.g. tests).
    if os.environ.get("DISABLE_SCHEDULER") != "1":
        threading.Thread(target=_scheduler_loop, name="feed-scheduler", daemon=True).start()
    yield
    _scheduler_stop.set()


app = FastAPI(title="Threat Feed Me! Dashboard", lifespan=lifespan)

# Compress anything sizeable: the world-map paths, the dashboard HTML, and the
# plain-text feeds a firewall polls (a 50k-line block list is mostly digits and
# compresses ~4x). Below 1 KB the header overhead is not worth it.
app.add_middleware(GZipMiddleware, minimum_size=1024)

# Static assets (extracted dashboard CSS/JS). Anchored to this module's
# directory so it works regardless of the process CWD (tests use a temp CWD).
app.mount("/static",
          StaticFiles(directory=os.path.join(os.path.dirname(__file__), "static")),
          name="static")

app.include_router(indicators.router)
app.include_router(system.router)
app.include_router(feeds.router)
app.include_router(whitelist.router)
