#!/bin/sh
# Container entrypoint.
#
# The dashboard must always come up even if the initial feed fetch is slow or
# fails (e.g. a source is down or a network is unavailable). So we run the
# pipeline in the background and never let its exit status block startup.
set -u

# Initialize the database schema ONCE, synchronously, before the pipeline and
# the dashboard open it concurrently. This avoids a first-run migration race
# (both processes attempting the legacy whitelist migration at the same time).
# --init-db logs its migration progress and serves a "starting" holding page on
# the dashboard port while it runs (a first start after an upgrade can take
# minutes on a large database).
python -m threatfeedme.main --init-db || echo "Schema init warning (continuing)" >&2

exec python -m threatfeedme.main --serve
