"""
The one lock for heavy writers.

Before v2.5.0, rescoring had four entry points — the refresh, the
recalculate endpoint, deleting a feed, clearing false positives — and the
UniFi push had three; none of them coordinated (review 2026-09-22). Two
rescores could run at once (each holding ~0.4 GB of evidence), and the last
one to finish wrote its tiers over the other's using stale reads; a rescore
running inside a request held a write transaction longer than the 5 s
busy_timeout, so any other writer could fail with "database is locked".

Everything that rewrites scores or rebuilds outputs from them now takes this
lock: the refresh's post-fetch phase, pipeline.recalculate, export_tiers and
push_to_unifi. Reentrant, because the refresh phase calls the others. Network
fetching deliberately stays outside it, so a slow feed can't block a rescore
or a whitelist-triggered export. Process-local: the offline predict pass runs
in another container and is handled by chunked writes and busy_timeout.
"""
import threading

write_lock = threading.RLock()
