// CSRF protection: when Basic auth is on, every mutating fetch must carry
// X-Requested-With: XMLHttpRequest so the server can distinguish same-origin
// dashboard JS from a cross-site form/script (browsers do not auto-set this
// header cross-origin).
// opts defaults: a GET caller has no options to pass, and omitting the
// argument used to throw synchronously here — before any promise existed, so
// the caller's .catch() never ran and the UI hung on its loading state.
function apiFetch(url, opts = {}) {
    const h = opts.headers || {};
    opts.headers = Object.assign(h, {'X-Requested-With': 'XMLHttpRequest'});
    return fetch(url, opts);
}

// Refresh the page after a mutation. NOT location.reload(): Firefox restores
// form field values (including the file input) across a reload, so a form
// that was just submitted comes back still populated, looking like the
// action didn't take. Reset the forms, then navigate fresh.
function reloadPage() {
    document.querySelectorAll('form').forEach(f => f.reset());
    location.replace(location.pathname + location.search);
}

function copyUrl(btn) {
    const url = btn.parentElement.querySelector('.url-box').value;
    const done = () => { const t = btn.textContent; btn.textContent = 'Copied!';
        btn.classList.add('ok'); setTimeout(() => { btn.textContent = t; btn.classList.remove('ok'); }, 1500); };
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(url).then(done).catch(() => fallback(url, done));
    } else { fallback(url, done); }
}
function fallback(url, done) {
    const ta = document.createElement('textarea'); ta.value = url; document.body.appendChild(ta);
    ta.select(); try { document.execCommand('copy'); done(); } catch (e) {} document.body.removeChild(ta);
}
async function addWl(e) {
    e.preventDefault();
    const body = {
        ip: document.getElementById('wl-ip').value.trim(),
        feed_name: document.getElementById('wl-feed').value,
        reason_code: document.getElementById('wl-reason-code').value,
        reason: document.getElementById('wl-reason').value.trim(),
        added_by: document.getElementById('wl-by').value.trim() || 'dashboard',
    };
    const r = await apiFetch('/api/whitelist', {
        method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body),
    });
    const j = await r.json().catch(() => ({}));
    if (r.ok && j.success !== false) { reloadPage(); }
    else { alert('Could not add: ' + (j.message || j.detail || r.status)); }
    return false;
}
async function removeWl(ip, feed) {
    const scopeLabel = feed === '*' ? 'all tiers' : feed.startsWith('tier:') ? feed.split(':')[1] + ' only' : feed;
    if (!confirm('Remove whitelist entry for ' + ip + ' (' + scopeLabel + ')?')) return;
    const r = await apiFetch('/api/whitelist?ip=' + encodeURIComponent(ip) + '&feed=' + encodeURIComponent(feed), {method: 'DELETE'});
    if (r.ok) { reloadPage(); }
    else { const j = await r.json().catch(() => ({})); alert('Could not remove: ' + (j.detail || r.status)); }
}

// ---- Feeds ----
async function addFeed(e) {
    e.preventDefault();
    const body = {
        name: document.getElementById('f-name').value.trim(),
        url: document.getElementById('f-url').value.trim(),
        feed_type: document.getElementById('f-type').value,
        weight: parseFloat(document.getElementById('f-weight').value) || 0.5,
    };
    const r = await apiFetch('/api/feeds', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body)});
    const j = await r.json().catch(() => ({}));
    if (r.ok && j.success !== false) { reloadPage(); }
    else { alert('Could not add feed: ' + (j.message || j.detail || r.status)); }
    return false;
}
async function uploadFeed(e) {
    e.preventDefault();
    const file = document.getElementById('u-file').files[0];
    if (!file) { alert('Choose a file'); return false; }
    const fd = new FormData();
    fd.append('name', document.getElementById('u-name').value.trim());
    fd.append('weight', document.getElementById('u-weight').value || '1.0');
    fd.append('file', file);
    const r = await apiFetch('/api/feeds/upload', {method:'POST', body: fd});
    const j = await r.json().catch(() => ({}));
    if (r.ok && j.success !== false) { alert(j.message || 'Uploaded'); reloadPage(); }
    else { alert('Upload failed: ' + (j.message || j.detail || r.status)); }
    return false;
}
async function removeFeed(name) {
    if (!confirm('Remove feed "' + name + '"? Existing indicators stay until the next refresh.')) return;
    const r = await apiFetch('/api/feeds/' + encodeURIComponent(name), {method:'DELETE'});
    if (r.ok) { reloadPage(); } else { alert('Could not remove feed'); }
}
// Flip a feed on/off. Update the row's dimmed styling immediately so the
// change is visible without waiting for a full page reload (the row used to
// stay greyed until refresh). Revert the toggle if the server rejects it.
async function toggleFeed(el, name) {
    const enabled = el.checked;
    const row = el.closest('tr');
    if (row) row.classList.toggle('row-off', !enabled);
    el.disabled = true;
    try {
        const r = await apiFetch('/api/feeds/' + encodeURIComponent(name) + '/enabled?enabled=' + enabled, {method:'POST'});
        if (!r.ok) throw new Error(r.status);
    } catch (e) {
        el.checked = !enabled;
        if (row) row.classList.toggle('row-off', enabled);
        alert('Could not ' + (enabled ? 'enable' : 'disable') + ' "' + name + '"');
    } finally {
        el.disabled = false;
    }
}
async function setApiKey(name, envVar) {
    // auth_env may declare several credentials (comma-separated, e.g.
    // HoneyDB's id+key pair) — prompt for each in turn. Cancel on any
    // prompt aborts the whole operation; nothing is saved.
    const vars = envVar.split(',').map(v => v.trim()).filter(Boolean);
    const keys = {};
    for (let i = 0; i < vars.length; i++) {
        const step = vars.length > 1 ? ' (' + (i + 1) + ' of ' + vars.length + ')' : '';
        const val = prompt(vars[i] + ' for "' + name + '"' + step +
            '\n\nSaved server-side to the data volume\'s .env and applied immediately.' +
            '\nLeave empty and press OK to clear this credential.');
        if (val === null) return; // cancelled — abort without saving anything
        keys[vars[i]] = val;
    }
    const r = await apiFetch('/api/feeds/' + encodeURIComponent(name) + '/api-key', {
        method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({keys: keys}),
    });
    const j = await r.json().catch(() => ({}));
    if (r.ok) { reloadPage(); }
    else { alert('Could not save key: ' + (j.detail || r.status)); }
}
async function saveInterval() {
    const v = parseInt(document.getElementById('interval-min').value, 10);
    if (!v || v < 1) { alert('Enter a whole number of minutes (>= 1)'); return; }
    const r = await apiFetch('/api/settings', {method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({refresh_interval_minutes: v})});
    alert(r.ok ? 'Auto-refresh set to every ' + v + ' min' : 'Could not save');
}
async function saveRetention() {
    const v = parseInt(document.getElementById('retention-days').value, 10);
    if (isNaN(v) || v < 0 || v > 3650) { alert('Enter a whole number of days (0-3650; 0 = keep forever)'); return; }
    const r = await apiFetch('/api/settings', {method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({retention_max_age_days: v})});
    alert(r.ok ? (v === 0 ? 'Retention set to keep IPs forever' : 'Retention set to ' + v + ' days') : 'Could not save');
}
function refreshAll(btn) { startRefresh(null, btn); }
function refreshFeed(name, btn) { startRefresh(name, btn); }

// The button that kicked off the running refresh, plus its original label, so
// pollRefresh can restore it when the run finishes (it may not be the toolbar
// button — a per-feed "Refresh" row button initiates too).
let refreshBtn = null, refreshBtnHtml = '';
async function startRefresh(name, initiator) {
    const globalBtn = document.getElementById('refresh-all-btn');
    const btn = initiator || globalBtn;
    const status = document.getElementById('refresh-status');
    // Flip the clicked button into an obvious animated "Refreshing…" state so
    // it's clear something is happening even when scrolled down the page.
    refreshBtn = btn;
    refreshBtnHtml = btn.innerHTML;
    btn.innerHTML = 'Refreshing<span class="loading-dots"><i></i><i></i><i></i></span>';
    btn.classList.add('refreshing');
    btn.disabled = true;
    if (globalBtn !== btn) globalBtn.disabled = true;  // block the toolbar button too
    const url = '/api/refresh' + (name ? '?feed=' + encodeURIComponent(name) : '');
    const r = await apiFetch(url, {method:'POST'});
    if (r.status === 409) { status.textContent = 'A refresh is already running…'; }
    else { status.textContent = 'Refreshing' + (name ? ' ' + name : ' all feeds') + '… this can take a minute.'; }
    pollRefresh();
}
function endRefreshUi() {
    const globalBtn = document.getElementById('refresh-all-btn');
    if (globalBtn) globalBtn.disabled = false;
    if (refreshBtn) {
        refreshBtn.classList.remove('refreshing');
        refreshBtn.disabled = false;
        refreshBtn.innerHTML = refreshBtnHtml;
        refreshBtn = null;
    }
}
async function pollRefresh() {
    const status = document.getElementById('refresh-status');
    const r = await fetch('/api/refresh/status');
    const j = await r.json();
    if (j.running) { setTimeout(pollRefresh, 2000); return; }
    endRefreshUi();
    status.textContent = j.last_error ? ('Last refresh error: ' + j.last_error) : 'Refresh complete.';
    if (!j.last_error) setTimeout(() => reloadPage(), 800);
}
async function restoreDefaults() {
    if (!confirm('Re-add the curated default feeds that are currently missing?')) return;
    const r = await apiFetch('/api/feeds/restore-defaults', {method:'POST'});
    const j = await r.json().catch(() => ({}));
    if (r.ok) { alert(j.count ? ('Added: ' + j.added.join(', ')) : 'All default feeds already present'); reloadPage(); }
    else { alert('Could not restore defaults'); }
}

// ---- Merged indicators ----
let indOffset = 0, indTotal = 0;
const IND_LIMIT = 50;
function esc(s) { return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
async function loadIndicators() {
    const q = document.getElementById('ind-q').value.trim();
    const r = await fetch('/api/indicators?limit=' + IND_LIMIT + '&offset=' + indOffset + (q ? '&q=' + encodeURIComponent(q) : ''));
    const j = await r.json();
    indTotal = j.total;
    const body = document.getElementById('ind-body');
    if (!j.indicators.length) {
        body.innerHTML = '<tr><td colspan="6" class="muted">No matching indicators.</td></tr>';
    } else {
        body.innerHTML = j.indicators.map(i => {
            const badge = 'tier-' + i.tier;
            // Effective votes can exceed the source count (netblock votes are
            // counted but not listed); flag that with a + so it reads as
            // "more evidence than the sources shown".
            const votes = i.effective_votes == null ? '—'
                : i.effective_votes.toFixed(1) + (i.effective_votes > i.sources.length ? '+' : '');
            return '<tr><td><code>' + esc(i.value) + '</code></td>' +
                '<td><span class="badge ' + badge + '">' + esc(i.tier) + '</span></td>' +
                '<td>' + esc(i.confidence_score) + '</td>' +
                '<td title="independent witnesses (overlap-discounted)">' + esc(votes) + '</td>' +
                '<td class="muted" style="font-size:.82em">' + esc(i.sources.join(', ')) + '</td>' +
                '<td><button class="mini-btn" data-ip="' + esc(i.ip) + '" onclick="openWhitelistModal(this.dataset.ip)">Whitelist…</button> <a class="vt-btn" href="https://www.virustotal.com/gui/search/' + encodeURIComponent(i.value) + '" target="_blank" title="Look up on VirusTotal">VT</a></td></tr>';
        }).join('');
    }
    const start = indTotal ? indOffset + 1 : 0;
    const end = Math.min(indOffset + IND_LIMIT, indTotal);
    document.getElementById('ind-pageinfo').textContent = start + '–' + end + ' of ' + indTotal.toLocaleString();
    document.getElementById('ind-prev').disabled = indOffset <= 0;
    document.getElementById('ind-next').disabled = end >= indTotal;
}
function indPage(dir) {
    indOffset = Math.max(0, indOffset + dir * IND_LIMIT);
    loadIndicators();
}
let indDebounce;
// The indicators table lives on /indicators only, so this bootstrap must be
// a no-op on the dashboard (app.js is shared by both pages).
document.addEventListener('DOMContentLoaded', () => {
    const q = document.getElementById('ind-q');
    if (!q) return;
    q.addEventListener('input', () => {
        clearTimeout(indDebounce);
        indDebounce = setTimeout(() => { indOffset = 0; loadIndicators(); }, 300);
    });
    loadIndicators();  // honors any ?q= the dashboard lookup box deep-linked with
});

// Dashboard lookup box: jump to the indicators page filtered to one address,
// so the common "is this IP in my feeds?" question never needs the full list.
function lookupIndicator(e) {
    e.preventDefault();
    const ip = document.getElementById('lookup-ip').value.trim();
    location.href = '/indicators' + (ip ? '?q=' + encodeURIComponent(ip) : '');
    return false;
}
async function addIndicator(e) {
    e.preventDefault();
    const ip = document.getElementById('ind-add').value.trim();
    if (!ip) return false;
    const r = await apiFetch('/api/indicators', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ip})});
    const j = await r.json().catch(() => ({}));
    if (r.ok && j.success !== false) { document.getElementById('ind-add').value=''; indOffset=0; loadIndicators(); }
    else { alert('Could not add: ' + (j.message || j.detail || r.status)); }
    return false;
}
async function removeIndicator(ip) {
    if (!confirm('Remove ' + ip + '? It will be globally whitelisted so refreshes won\'t re-add it.')) return;
    const r = await apiFetch('/api/indicators/' + encodeURIComponent(ip), {method:'DELETE'});
    if (r.ok) { loadIndicators(); } else { alert('Could not remove'); }
}

// ---- False-positive modal (opened from a feed row's "N FP" badge) ----
// Lets an operator review what a feed was penalized for and forgive it,
// without touching the whitelist entries themselves.
let fpModalFeed = null;
async function openFpModal(feed) {
    fpModalFeed = feed;
    document.getElementById('fp-modal-feed').textContent = feed;
    document.getElementById('fp-modal-summary').textContent = '';
    const list = document.getElementById('fp-modal-list');
    list.textContent = 'Loading…';
    document.getElementById('fp-modal').classList.add('open');
    try {
        const j = await (await fetch('/api/feeds/' + encodeURIComponent(feed) + '/false-positives')).json();
        document.getElementById('fp-modal-summary').textContent =
            j.count + ' flagged of ' + j.reported.toLocaleString() + ' reported — reputation reduced ~' + j.penalty_pct + '%';
        list.innerHTML = j.entries.length ? j.entries.map(e =>
            '<div class="fp-row"><code>' + esc(e.ip) + '</code>' +
            (e.whitelisted ? '' : ' <span class="badge badge-warn" title="No whitelist entry remains for this IP">orphaned</span>') +
            ' <button class="rm-btn" data-ip="' + esc(e.ip) + '" onclick="clearOneFp(this.dataset.ip)">Clear</button></div>'
        ).join('') : '<span class="muted">none</span>';
    } catch (e) { list.textContent = 'Could not load false positives'; }
}
function closeFpModal() { document.getElementById('fp-modal').classList.remove('open'); fpModalFeed = null; }
async function clearOneFp(ip) {
    if (!fpModalFeed) return;
    const r = await apiFetch('/api/feeds/' + encodeURIComponent(fpModalFeed) +
        '/false-positives?ip=' + encodeURIComponent(ip), {method: 'DELETE'});
    if (r.ok) { reloadPage(); } else { alert('Could not clear'); }
}
async function clearAllFp() {
    if (!fpModalFeed) return;
    if (!confirm('Clear all false-positive flags against "' + fpModalFeed + '"?\n\nThe feed\'s reputation penalty is removed. Whitelisted IPs stay whitelisted.')) return;
    const r = await apiFetch('/api/feeds/' + encodeURIComponent(fpModalFeed) + '/false-positives', {method: 'DELETE'});
    if (r.ok) { reloadPage(); } else { alert('Could not clear'); }
}

// ---- Whitelist modal (shows which feed reported the IP) ----
let wlModalIp = null;
async function openWhitelistModal(ip) {
    wlModalIp = ip;
    document.getElementById('wl-modal-ip').textContent = ip;
    document.getElementById('wl-modal-note').value = '';
    const scope = document.getElementById('wl-modal-scope');
    const srcBox = document.getElementById('wl-modal-sources');
    scope.innerHTML = '<option value="*">All tiers</option>' +
        '<option value="tier:high">High only</option>' +
        '<option value="tier:medium">Medium only</option>' +
        '<option value="tier:low">Low only</option>';
    srcBox.textContent = 'Loading…';
    try {
        const j = await (await fetch('/api/indicators/' + encodeURIComponent(ip))).json();
        const sources = j.sources || [];
        srcBox.innerHTML = sources.length
            ? sources.map(s => '<code>' + esc(s) + '</code>').join(' ')
            : '<span class="muted">no feed sources on record</span>';
        if (j.effective_votes != null) {
            srcBox.innerHTML += '<div class="muted" style="margin-top:6px" ' +
                'title="Independent witnesses after overlap discounting; netblock votes are counted but not listed above.">' +
                '≈ ' + esc(j.effective_votes.toFixed(1)) + ' independent votes</div>';
        }
    } catch (e) { srcBox.textContent = 'Could not load sources'; }
    document.getElementById('wl-modal').classList.add('open');
}
function closeWlModal() { document.getElementById('wl-modal').classList.remove('open'); wlModalIp = null; }
async function confirmWlModal() {
    if (!wlModalIp) return;
    const body = {
        ip: wlModalIp,
        feed_name: document.getElementById('wl-modal-scope').value,
        reason_code: document.getElementById('wl-modal-reason').value,
        reason: document.getElementById('wl-modal-note').value.trim(),
        added_by: 'dashboard',
    };
    const r = await apiFetch('/api/whitelist', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body)});
    const j = await r.json().catch(() => ({}));
    if (r.ok && j.success !== false) { closeWlModal(); reloadPage(); }
    else { alert('Could not whitelist: ' + (j.message || j.detail || r.status)); }
}

// Blocked-IP country heatmap: lazy, on-demand. The dashboard route never
// computes geo data — this fetches /api/geo/countries only the first time
// the user expands the collapsed <details id=geo-heatmap>, then caches.
let geoLoaded = false;

// Counts are extremely skewed — the top country is routinely 25%+ of all
// indicators while the tail is fractions of a percent. Linear hides the tail
// entirely; log flattens so hard that a 1,000-IP country looks as hot as a
// 20,000-IP one. Square root of the share keeps the leader clearly dominant
// while the middle of the pack stays distinguishable.
function geoShade(n, max) {
    if (!n) return null;
    const t = Math.sqrt(n / max);
    const hue = 45 - 40 * t;            // amber -> red, matching the overlap map
    return 'hsl(' + hue.toFixed(0) + ' 88% 55% / ' + (0.14 + 0.82 * t).toFixed(2) + ')';
}

function renderGeo(data, world) {
    const wrap = document.querySelector('#geo-heatmap .geo-wrap');
    if (!wrap) return;
    const rows = data.data || [];
    if (!rows.length) {
        wrap.innerHTML = '<p class="muted">Geo data not built yet. Run the generator with a DB-IP country CSV to populate the offline table.</p>';
        return;
    }
    const total = data.total || 0;
    const byIso = {};
    let max = 0;
    for (const [iso, , n] of rows) { byIso[iso] = n; if (n > max) max = n; }

    let svg = '';
    if (world && world.paths) {
        const names = world.names || {};
        const shapes = [];
        for (const iso in world.paths) {
            const n = byIso[iso] || 0;
            const fill = geoShade(n, max) || 'rgba(255,255,255,.05)';
            const name = names[iso] || iso;
            const label = n
                ? name + ' — ' + n.toLocaleString() +
                  (total ? ' (' + (100 * n / total).toFixed(1) + '%)' : '')
                : name + ' — none';
            shapes.push('<path d="' + world.paths[iso] + '" fill="' + fill +
                '" fill-rule="evenodd" stroke="rgba(255,255,255,.10)" stroke-width="0.4"><title>' +
                esc(label) + '</title></path>');
        }
        svg = '<svg class="geo-map" viewBox="0 0 1000 500" width="100%" height="100%" preserveAspectRatio="xMidYMid meet" role="img" ' +
              'aria-label="Blocked indicators by country">' + shapes.join('') + '</svg>';
    }

    // Ranked list stays: the map shows spread, the list gives exact numbers
    // (and covers countries too small to see, like Singapore or Hong Kong).
    let bars = '<div class="geo-bars">';
    for (const [, name, n] of rows.slice(0, 10)) {
        const pct = total ? (100 * n / total).toFixed(1) : '0.0';
        bars += '<div class="geo-bar-row"><span class="geo-bar-name">' + esc(name) +
                '</span><span class="geo-bar-track"><i style="width:' +
                (max ? (100 * n / max).toFixed(1) : 0) + '%"></i></span>' +
                '<span class="geo-bar-val">' + n.toLocaleString() + ' (' + pct + '%)</span></div>';
    }
    bars += '</div>';
    wrap.innerHTML = svg + bars;
}

function loadGeoOnce() {
    if (geoLoaded) return;
    geoLoaded = true;
    const wrap = document.querySelector('#geo-heatmap .geo-wrap');
    if (wrap) wrap.innerHTML = '<p class="muted">Loading geo data…</p>';
    // Country shapes are a static 64 KB file fetched only on first expand, so
    // a dashboard load that never opens this panel pays nothing for the map.
    // A failed map fetch still renders the ranked list.
    Promise.all([
        apiFetch('/api/geo/countries').then(r => r.json()),
        fetch('/static/world-paths.json').then(r => r.json()).catch(() => null),
    ]).then(([data, world]) => renderGeo(data, world))
        .catch(() => {
            // Allow a retry on the next expand rather than stranding the
            // panel on a permanent error.
            geoLoaded = false;
            const w = document.querySelector('#geo-heatmap .geo-wrap');
            if (w) w.innerHTML = '<p class="muted">Geo data unavailable — reopen to retry.</p>';
        });
}
document.addEventListener('DOMContentLoaded', () => {
    const box = document.getElementById('geo-heatmap');
    if (!box) return;
    box.addEventListener('toggle', () => { if (box.open) loadGeoOnce(); });
});
