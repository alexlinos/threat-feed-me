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
// The dashboard's view lives in the URL hash, and a navigation to the same
// URL plus a hash is a fragment jump, not a reload — so the view rides
// across in sessionStorage and the inline script in dashboard.html restores it.
function reloadPage() {
    document.querySelectorAll('form').forEach(f => f.reset());
    const view = document.documentElement.getAttribute('data-view');
    if (view) { try { sessionStorage.setItem('tfm.return', view); } catch (e) {} }
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
    if (!document.getElementById('wl-reason-code').value) {
        alert('Choose a reason. Only "False positive" lowers the reporting feeds\' reputation.');
        return false;
    }
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
    // NaN check, not ||: parseFloat('0') is falsy, and an explicit weight of
    // 0 (neutralize a feed without disabling it) must not turn into 0.5.
    const w = parseFloat(document.getElementById('f-weight').value);
    const body = {
        name: document.getElementById('f-name').value.trim(),
        url: document.getElementById('f-url').value.trim(),
        feed_type: document.getElementById('f-type').value,
        weight: isNaN(w) ? 1.0 : w,
        indicator_kind: document.getElementById('f-kind').value,
        format: document.getElementById('f-format').value,
    };
    // A keyed TAXII feed gets its own TFM_FEED_<NAME> variable (the only kind
    // of custom key the server accepts, credentials.py); Set key fills it in.
    if (body.format === 'taxii21' && document.getElementById('f-needs-key').checked) {
        body.auth_env = 'TFM_FEED_' + body.name.toUpperCase().replace(/[^A-Z0-9]/g, '_');
    }
    const post = () => apiFetch('/api/feeds', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body)});
    let r = await post();
    let j = await r.json().catch(() => ({}));
    if (r.status === 409 && confirm((j.detail || 'A feed with this name exists.') + '\n\nReplace it?')) {
        body.overwrite = true;
        r = await post();
        j = await r.json().catch(() => ({}));
    }
    if (r.ok && j.success !== false) { reloadPage(); }
    else if (r.status !== 409) { alert('Could not add feed: ' + (j.message || j.detail || r.status)); }
    return false;
}
async function uploadFeed(e) {
    e.preventDefault();
    const file = document.getElementById('u-file').files[0];
    if (!file) { alert('Choose a file'); return false; }
    const fd = new FormData();
    fd.append('name', document.getElementById('u-name').value.trim());
    fd.append('weight', document.getElementById('u-weight').value || '1.0');
    fd.append('indicator_kind', document.getElementById('u-kind').value);
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
function feedFormatChanged(sel) {
    const taxii = sel.value === 'taxii21';
    document.getElementById('f-key-wrap').hidden = !taxii;
    document.getElementById('f-url').placeholder = taxii
        ? 'https://taxii.example.org/api/collections/<id>/' : 'https://example.com/blocklist.txt';
}
// API keys go through a masked modal. They used to be typed into prompt(),
// which echoes the secret in plain text on screen and in screen shares.
// auth_env may declare several credentials (comma-separated, e.g. HoneyDB's
// id + key): one password field each; Cancel saves nothing.
let keyModalFeed = null;
function setApiKey(name, envVar, taxii) {
    keyModalFeed = name;
    // TAXII servers differ in how they take a key, and the value is sent
    // verbatim as the Authorization header, so say what to paste.
    const hint = document.getElementById('key-modal-hint');
    if (hint) {
        hint.hidden = !taxii;
        hint.textContent = taxii ? 'Paste the whole Authorization header value: "Bearer <token>" for OpenCTI, ' +
            'the API key for MISP, or "Basic <base64 of user:password>".' : '';
    }
    const box = document.getElementById('key-modal-fields');
    box.replaceChildren();
    envVar.split(',').map(v => v.trim()).filter(Boolean).forEach((v, i) => {
        const field = document.createElement('div');
        field.className = 'field';
        const label = document.createElement('label');
        label.htmlFor = 'key-field-' + i;
        label.textContent = v;
        const input = document.createElement('input');
        input.type = 'password'; input.id = 'key-field-' + i;
        input.autocomplete = 'new-password'; input.dataset.var = v;
        field.append(label, input);
        box.append(field);
    });
    document.getElementById('key-modal-title').textContent = 'API key for ' + name;
    openModal('key-modal');
}
function closeKeyModal() {
    document.getElementById('key-modal-fields').replaceChildren();  // never linger in the DOM
    closeModal('key-modal');
    keyModalFeed = null;
}
async function saveKeyModal() {
    if (!keyModalFeed) return;
    const keys = {};
    document.querySelectorAll('#key-modal-fields input').forEach(i => { keys[i.dataset.var] = i.value; });
    const r = await apiFetch('/api/feeds/' + encodeURIComponent(keyModalFeed) + '/api-key', {
        method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({keys: keys}),
    });
    const j = await r.json().catch(() => ({}));
    if (r.ok) { closeKeyModal(); reloadPage(); }
    else { alert('Could not save key: ' + (j.detail || r.status)); }
}

// ---- Modal accessibility: focus in on open, Esc closes, focus returns ----
let _modalOpener = null;
function openModal(id) {
    _modalOpener = document.activeElement;
    const m = document.getElementById(id);
    m.classList.add('open');
    const first = m.querySelector('input, select, textarea, button');
    if (first) first.focus();
}
function closeModal(id) {
    document.getElementById(id).classList.remove('open');
    if (_modalOpener && document.body.contains(_modalOpener)) _modalOpener.focus();
    _modalOpener = null;
}
const _MODAL_CLOSERS = {
    'key-modal': () => closeKeyModal(),
    'unifi-creds-modal': () => closeUnifiCredsModal(),
    'cs-creds-modal': () => closeCsCredsModal(),
    'fp-modal': () => (typeof closeFpModal === 'function' ? closeFpModal()
                       : document.getElementById('fp-modal').classList.remove('open')),
    'wl-modal': () => closeWlModal(),
};
document.addEventListener('keydown', (e) => {
    if (e.key !== 'Escape') return;
    const open = document.querySelector('.modal-overlay.open');
    if (open && _MODAL_CLOSERS[open.id]) { e.preventDefault(); _MODAL_CLOSERS[open.id](); }
});
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
    // The brand eats while it works: chomper + prey replaces the plain
    // marching dots (chomper inherits the button's dark text color).
    btn.innerHTML = 'Feeding<span class="feeding"><span class="chomp"><i></i><b></b></span><span class="prey"><i></i><i></i><i></i></span></span>';
    btn.classList.add('refreshing');
    setBrandState('running');
    btn.disabled = true;
    if (globalBtn !== btn) globalBtn.disabled = true;  // block the toolbar button too
    const url = '/api/refresh' + (name ? '?feed=' + encodeURIComponent(name) : '');
    const r = await apiFetch(url, {method:'POST'});
    if (r.status === 409) {
        // Rejected, not queued: another refresh (often the container's
        // startup fetch of every feed) holds the lock. Restore the button
        // immediately — leaving it "Feeding" would claim THIS refresh is
        // running — and keep polling so the page reloads when the other
        // refresh finishes and the operator can retry.
        endRefreshUi();
        status.textContent = 'Another refresh is already running (this one was not queued) — retry when it finishes.';
    }
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
// Names of feeds that errored in a refresh result map ({feed: {status,...}}).
function failedFeeds(lastResult) {
    return Object.entries(lastResult || {})
        .filter(([, v]) => v && v.status === 'error')
        .map(([name]) => name);
}
// Header mascot state: '' = idle (still), 'running' = feeding, 'error' = attention.
function setBrandState(state) {
    const logo = document.querySelector('.logo-mark');
    if (!logo) return;
    logo.classList.toggle('brand-running', state === 'running');
    logo.classList.toggle('brand-error', state === 'error');
}
async function pollRefresh() {
    const status = document.getElementById('refresh-status');
    const r = await fetch('/api/refresh/status');
    const j = await r.json();
    if (j.running) { setBrandState('running'); setTimeout(pollRefresh, 2000); return; }
    endRefreshUi();
    if (j.last_error) {
        status.textContent = 'Last refresh error: ' + j.last_error;
        setBrandState('error');
        return;
    }
    // A refresh completes even when individual feeds error (one flaky feed must
    // not fail the whole cycle) — name them instead of a bare "complete".
    const failed = failedFeeds(j.last_result);
    status.textContent = failed.length
        ? ('Refresh complete — ' + failed.length + ' feed' + (failed.length > 1 ? 's' : '') +
           ' errored: ' + failed.join(', '))
        : 'Refresh complete.';
    setBrandState(failed.length ? 'error' : '');
    // Reload either way so the table (health badges, "needs attention" flags)
    // reflects the run; linger longer when there's an error to read.
    setTimeout(() => reloadPage(), failed.length ? 4000 : 800);
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
let indAbort = null;
async function loadIndicators() {
    // Abort the in-flight request when a newer one starts: at large corpus
    // sizes each query is real server work, and a fast typer otherwise
    // stacks them up server-side while the UI shows stale results.
    if (indAbort) indAbort.abort();
    indAbort = new AbortController();
    const q = document.getElementById('ind-q').value.trim();
    let r;
    try {
        r = await fetch('/api/indicators?limit=' + IND_LIMIT + '&offset=' + indOffset + (q ? '&q=' + encodeURIComponent(q) : ''),
                        {signal: indAbort.signal});
    } catch (e) {
        if (e.name === 'AbortError') return;  // superseded by a newer search
        throw e;
    }
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
    openModal('fp-modal');
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
    document.getElementById('wl-modal-reason').value = '';   // never carry a reason over
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
    openModal('wl-modal');
}
function closeWlModal() { document.getElementById('wl-modal').classList.remove('open'); wlModalIp = null; }
async function confirmWlModal() {
    if (!wlModalIp) return;
    const reasonSel = document.getElementById('wl-modal-reason');
    if (!reasonSel.value) {
        alert('Choose a reason. Only "False positive" lowers the reporting feeds\' reputation.');
        reasonSel.focus();
        return;
    }
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

// The pulse row is server-rendered, but SOC dashboards sit open for days —
// a "Last refresh" card frozen at page-load time reads as broken (and once
// showed "first fetch pending" for a full day on a tab opened during
// container startup). Poll the cheap status endpoint and rewrite just this
// card; the heavier cards refresh on natural page loads.
function updateRefreshPulse() {
    const card = document.getElementById('pulse-refresh');
    if (!card) return;
    fetch('/api/refresh/status').then(r => r.json()).then(j => {
        const n = document.getElementById('pulse-refresh-n');
        const sub = document.getElementById('pulse-refresh-sub');
        if (j.running) {
            n.innerHTML = '<span class="feeding"><span class="chomp"><i></i><b></b></span></span>';
            sub.innerHTML = '<span class="nomming"></span>';
            card.classList.remove('warn');
            setBrandState('running');
            return;
        }
        // Idle: mascot reflects whether the last completed run had a feed error.
        setBrandState(failedFeeds(j.last_result).length ? 'error' : '');
        if (!j.last_finished) return;  // still pre-first-fetch: leave as rendered
        const ageMin = Math.max(0, Math.floor((Date.now() - Date.parse(j.last_finished)) / 60000));
        const interval = parseInt(card.dataset.intervalMin, 10) || 60;
        n.innerHTML = ageMin + 'm<small> ago</small>';
        const overdue = ageMin > 2 * interval;
        card.classList.toggle('warn', overdue);
        sub.textContent = overdue ? 'overdue' : 'next in ~' + Math.max(0, interval - ageMin) + 'm';
    }).catch(() => {});  // transient failure: keep last shown values
}
document.addEventListener('DOMContentLoaded', () => {
    if (!document.getElementById('pulse-refresh')) return;
    updateRefreshPulse();
    setInterval(updateRefreshPulse, 30000);
    document.addEventListener('visibilitychange', () => {
        if (!document.hidden) updateRefreshPulse();
    });
});

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

// ---- Problematic TLDs (lazy, on-demand — same pattern as the geo panel) ----
// Ranked horizontal bars: TLD abuse is heavily skewed and a pie fails on the
// long tail, so the top ~15 get bars and the rest collapse into one honest
// "other" row instead of vanishing.
let tldLoaded = false;
const TLD_TOP = 15;

function renderTlds(data) {
    const wrap = document.querySelector('#tld-panel .tld-wrap');
    if (!wrap) return;
    const rows = data.data || [];
    const total = data.total || 0;
    if (!rows.length) {
        wrap.innerHTML = '<p class="muted">No domain indicators yet — enable a domain feed and refresh.</p>';
        return;
    }
    const top = rows.slice(0, TLD_TOP);
    const rest = rows.slice(TLD_TOP);
    const otherN = rest.reduce((s, r) => s + r[1], 0);
    const max = top[0][1];
    let bars = '<div class="tld-bars">';
    for (const [tld, n] of top) {
        const pct = total ? (100 * n / total).toFixed(1) : '0.0';
        bars += '<div class="geo-bar-row"><span class="geo-bar-name"><code>.' + esc(tld) +
                '</code></span><span class="geo-bar-track"><i style="width:' +
                (max ? (100 * n / max).toFixed(1) : 0) + '%"></i></span>' +
                '<span class="geo-bar-val">' + n.toLocaleString() + ' (' + pct + '%)</span></div>';
    }
    if (otherN) {
        const pct = total ? (100 * otherN / total).toFixed(1) : '0.0';
        bars += '<div class="geo-bar-row tld-other"><span class="geo-bar-name muted">other (' +
                rest.length + ' TLDs)</span><span class="geo-bar-track"><i style="width:' +
                (max ? Math.min(100, 100 * otherN / max).toFixed(1) : 0) + '%"></i></span>' +
                '<span class="geo-bar-val">' + otherN.toLocaleString() + ' (' + pct + '%)</span></div>';
    }
    bars += '</div>';
    wrap.innerHTML = '<p class="hint" style="margin-top:8px">Blocked domains by top-level domain — ' +
        'a TLD carrying a big share of the corpus is one to watch (or block wholesale at the DNS filter).</p>' + bars;
}

function loadTldsOnce() {
    if (tldLoaded) return;
    tldLoaded = true;
    const wrap = document.querySelector('#tld-panel .tld-wrap');
    if (wrap) wrap.innerHTML = '<p class="muted">Loading TLD data…</p>';
    apiFetch('/api/domains/tlds').then(r => r.json()).then(renderTlds)
        .catch(() => {
            tldLoaded = false;  // allow a retry on the next expand
            const w = document.querySelector('#tld-panel .tld-wrap');
            if (w) w.innerHTML = '<p class="muted">TLD data unavailable — reopen to retry.</p>';
        });
}
document.addEventListener('DOMContentLoaded', () => {
    const box = document.getElementById('tld-panel');
    if (!box) return;
    box.addEventListener('toggle', () => { if (box.open) loadTldsOnce(); });
});

// ---- UniFi push integration panel ----
// Settings load lazily on first expand; credentials go through a dedicated
// modal (password-type input, write-only POST — never echoed back).
let unifiLoaded = false;

function unifiRenderStatus(s) {
    const el = document.getElementById('unifi-status');
    if (!el) return;
    let parts = [];
    parts.push(s.credentials_configured ? 'Credentials ✓' : 'Credentials not set');
    const btn = document.getElementById('unifi-creds-btn');
    if (btn) btn.textContent = s.credentials_configured ? 'Credentials ✓' : 'Set credentials';
    if (s.last_push) {
        const at = s.last_push.at ? new Date(s.last_push.at).toLocaleString() : '?';
        if (s.last_push.error) parts.push('Last push FAILED ' + at + ': ' + s.last_push.error);
        else if (s.last_push.summary) {
            const sum = s.last_push.summary;
            let msg = 'Last push ' + at + ': ' + sum.entries.toLocaleString() +
                ' IPs in ' + sum.groups + ' group(s)';
            if (sum.domains) msg += ' · ' + sum.domains.entries.toLocaleString() +
                ' domains in ' + sum.domains.groups + ' list(s)';
            if (sum.domain_error) msg += ' · DOMAIN PUSH FAILED: ' + sum.domain_error;
            parts.push(msg);
        }
    } else {
        parts.push('No push yet');
    }
    el.textContent = parts.join(' · ');
}

async function loadUnifiOnce() {
    if (unifiLoaded) return;
    unifiLoaded = true;
    try {
        const s = await (await apiFetch('/api/integrations/unifi')).json();
        document.getElementById('unifi-enabled').checked = !!s.enabled;
        document.getElementById('unifi-host').value = s.host || '';
        document.getElementById('unifi-tier').value = s.tier || 'high';
        document.getElementById('unifi-domain-tier').value = s.domain_tier || '';
        unifiRenderStatus(s);
    } catch (e) {
        unifiLoaded = false;
        const el = document.getElementById('unifi-status');
        if (el) el.textContent = 'Could not load settings — reopen to retry.';
    }
}
document.addEventListener('DOMContentLoaded', () => {
    const box = document.getElementById('unifi-panel');
    if (!box) return;
    box.addEventListener('toggle', () => { if (box.open) loadUnifiOnce(); });
    // Live warning: UniFi policies reference exactly ONE list each (every
    // firmware — the zone-based editor's List selector is single-select),
    // so a tier beyond High means one policy PER LIST, per direction. List
    // counts are fixed (High=1, Medium=4, Everything=10; empty lists are
    // pre-created) so the policy set you build once never goes stale.
    const warn = () => {
        const el = document.getElementById('unifi-tier-warning');
        const ip = document.getElementById('unifi-tier').value;
        const dom = document.getElementById('unifi-domain-tier').value;
        const msgs = [];
        if (ip === 'medium') msgs.push('IP Medium = 4 lists');
        if (ip === 'low') msgs.push('IP Everything = 10 lists');
        if (dom === 'medium') msgs.push('Domain Medium = 4 lists');
        if (msgs.length) {
            el.textContent = '⚠ ' + msgs.join(' · ') +
                ' — UniFi allows ONE list per policy, so that means one policy per list (per direction). ' +
                'All lists are created up front (some empty at first) so the policies you build now stay complete as the corpus grows. High = 1 list.';
            el.style.display = '';
        } else { el.style.display = 'none'; }
    };
    document.getElementById('unifi-tier').addEventListener('change', warn);
    document.getElementById('unifi-domain-tier').addEventListener('change', warn);
    box.addEventListener('toggle', () => { if (box.open) setTimeout(warn, 800); });
});

async function unifiSave(quiet) {
    const body = {
        enabled: document.getElementById('unifi-enabled').checked,
        host: document.getElementById('unifi-host').value.trim(),
        tier: document.getElementById('unifi-tier').value,
        domain_tier: document.getElementById('unifi-domain-tier').value,
    };
    const r = await apiFetch('/api/integrations/unifi', {
        method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)});
    const j = await r.json().catch(() => ({}));
    if (r.ok) {
        unifiRenderStatus(j);
        // A new gateway host clears the saved login server-side (it was bound
        // to the old gateway) — say so, even on a quiet save, or the next
        // Test/push just fails with "credentials not set".
        if (j.credentials_cleared) {
            alert('Gateway host changed, so the saved UniFi login was cleared. '
                + 'Re-enter it with "Set credentials" for the new gateway.');
        } else if (!quiet) {
            alert('UniFi settings saved');
        }
        return true;
    }
    alert('Could not save: ' + (j.detail || r.status));
    return false;
}

function openUnifiCredsModal() {
    document.getElementById('unifi-cred-user').value = '';
    document.getElementById('unifi-cred-pass').value = '';
    openModal('unifi-creds-modal');
}
function closeUnifiCredsModal() {
    // Clear the fields on close so the password never lingers in the DOM.
    document.getElementById('unifi-cred-user').value = '';
    document.getElementById('unifi-cred-pass').value = '';
    document.getElementById('unifi-creds-modal').classList.remove('open');
}
async function saveUnifiCreds() {
    const body = {
        username: document.getElementById('unifi-cred-user').value.trim(),
        password: document.getElementById('unifi-cred-pass').value,
    };
    const r = await apiFetch('/api/integrations/unifi/credentials', {
        method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)});
    const j = await r.json().catch(() => ({}));
    if (r.ok) {
        closeUnifiCredsModal();
        unifiLoaded = false; loadUnifiOnce();
        alert(j.credentials_configured ? 'Credentials saved' : 'Credentials cleared');
    } else { alert('Could not save credentials: ' + (j.detail || r.status)); }
}

async function unifiTest(btn) {
    const el = document.getElementById('unifi-status');
    btn.disabled = true; el.textContent = 'Testing connection…';
    try {
        const r = await apiFetch('/api/integrations/unifi/test', {method: 'POST'});
        const j = await r.json().catch(() => ({}));
        el.textContent = r.ok ? j.message : ('Test failed: ' + (j.detail || r.status));
    } finally { btn.disabled = false; }
}

async function unifiPush(btn) {
    const el = document.getElementById('unifi-status');
    btn.disabled = true;
    try {
        // Save the visible form first: an operator who set the toggle but
        // not Save got "enable the integration first" from a form that
        // LOOKED enabled. What you see is what gets pushed.
        if (!await unifiSave(true)) return;
        el.textContent = 'Pushing… (a large tier can take a minute)';
        const r = await apiFetch('/api/integrations/unifi/push', {method: 'POST'});
        const j = await r.json().catch(() => ({}));
        if (r.ok) {
            const s = j.summary;
            el.textContent = 'Pushed ' + s.entries.toLocaleString() + ' entries into ' + s.groups +
                ' group(s): ' + s.created + ' created, ' + s.updated + ' updated, ' +
                s.unchanged + ' unchanged, ' + s.emptied + ' emptied. Now reference the groups in a UDM block rule.';
        } else { el.textContent = 'Push failed: ' + (j.detail || r.status); }
    } finally { btn.disabled = false; }
}

// ---- CrowdSec integration panel (v2.5.0) ----
// Same shape as the UniFi panel. Everything the LAPI or the server says is
// rendered with textContent (error strings can carry LAPI-controlled text).
let csLoaded = false;

function csRenderStatus(s) {
    const el = document.getElementById('cs-status');
    if (!el) return;
    const parts = [];
    parts.push(s.machine_configured ? 'Publish login ✓' : 'Publish login not set');
    parts.push(s.bouncer_configured ? 'Bouncer key ✓' : 'Bouncer key not set');
    const btn = document.getElementById('cs-creds-btn');
    if (btn) btn.textContent = (s.machine_configured || s.bouncer_configured)
        ? 'Credentials ✓' : 'Set credentials';
    const last = s.last_push;
    if (last && last.at) {
        const at = new Date(last.at).toLocaleString();
        if (last.error) parts.push('Last publish FAILED ' + at + ': ' + last.error +
            (last.live_scenario ? ' (the previous list is still enforced)' : ''));
        else if (last.summary) parts.push('Last publish ' + at + ': ' +
            last.summary.entries.toLocaleString() + ' ' + last.summary.tier + '-tier IPs, ' +
            last.summary.duration_h + 'h decisions');
    } else { parts.push('Not published yet'); }
    el.textContent = parts.join(' · ');
}

async function loadCsOnce() {
    if (csLoaded) return;
    csLoaded = true;
    try {
        const s = await (await apiFetch('/api/integrations/crowdsec')).json();
        document.getElementById('cs-enabled').checked = !!s.enabled;
        document.getElementById('cs-lapi').value = s.lapi_url || '';
        document.getElementById('cs-tier').value = s.tier || 'medium';
        document.getElementById('cs-duration').value = s.duration_hours || 24;
        document.getElementById('cs-console').value = s.console_integration_id || '';
        csRenderStatus(s);
    } catch (e) {
        csLoaded = false;
        const el = document.getElementById('cs-status');
        if (el) el.textContent = 'Could not load settings: reopen to retry.';
    }
}
document.addEventListener('DOMContentLoaded', () => {
    const box = document.getElementById('crowdsec-panel');
    if (box) box.addEventListener('toggle', () => { if (box.open) loadCsOnce(); });
});

async function csSave(quiet) {
    const body = {
        enabled: document.getElementById('cs-enabled').checked,
        lapi_url: document.getElementById('cs-lapi').value.trim(),
        tier: document.getElementById('cs-tier').value,
        duration_hours: parseInt(document.getElementById('cs-duration').value, 10) || 24,
        console_integration_id: document.getElementById('cs-console').value.trim(),
    };
    const r = await apiFetch('/api/integrations/crowdsec', {
        method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)});
    const j = await r.json().catch(() => ({}));
    if (!r.ok) { alert('Could not save: ' + (j.detail || r.status)); return false; }
    csRenderStatus(j);
    if (j.credentials_cleared) {
        alert('The LAPI address changed, so the saved CrowdSec credentials were cleared '
            + '(they were bound to the old one). Re-enter them with "Set credentials".');
    } else if (!quiet) { alert('CrowdSec settings saved'); }
    return true;
}

function _csCredFields() {
    return ['cs-cred-machine', 'cs-cred-pass', 'cs-cred-bouncer'].map(id => document.getElementById(id));
}
function openCsCredsModal() {
    _csCredFields().forEach(f => { f.value = ''; });
    openModal('cs-creds-modal');
    _csCredFields()[0].focus();
}
function closeCsCredsModal() {
    _csCredFields().forEach(f => { f.value = ''; });   // never linger in the DOM
    document.getElementById('cs-creds-modal').classList.remove('open');
}
async function _postCsCreds(body) {
    const r = await apiFetch('/api/integrations/crowdsec/credentials', {
        method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)});
    const j = await r.json().catch(() => ({}));
    if (!r.ok) { alert('Could not save credentials: ' + (j.detail || r.status)); return; }
    closeCsCredsModal();
    csLoaded = false; loadCsOnce();
}
async function saveCsCreds() {
    const [m, p, b] = _csCredFields();
    const body = {};                       // empty field = leave unchanged
    if (m.value.trim()) body.machine_id = m.value.trim();
    if (p.value) body.machine_password = p.value;
    if (b.value.trim()) body.bouncer_key = b.value.trim();
    if (!Object.keys(body).length) { closeCsCredsModal(); return; }
    await _postCsCreds(body);
}
async function csClearCreds() {
    if (!confirm('Clear the saved CrowdSec machine login and bouncer key?')) return;
    await _postCsCreds({machine_id: '', machine_password: '', bouncer_key: ''});
}

async function csTest(btn) {
    const el = document.getElementById('cs-status');
    btn.disabled = true; el.textContent = 'Testing…';
    try {
        const r = await apiFetch('/api/integrations/crowdsec/test', {method: 'POST'});
        const j = await r.json().catch(() => ({}));
        el.textContent = r.ok ? ((j.ok ? '✓ ' : '✗ ') + j.message) : ('Test failed: ' + (j.detail || r.status));
    } finally { btn.disabled = false; }
}

async function csPush(btn) {
    const el = document.getElementById('cs-status');
    btn.disabled = true;
    try {
        if (!await csSave(true)) return;
        el.textContent = 'Publishing…';
        const r = await apiFetch('/api/integrations/crowdsec/push', {method: 'POST'});
        const j = await r.json().catch(() => ({}));
        if (r.ok) {
            const s = j.summary;
            el.textContent = 'Published ' + s.entries.toLocaleString() + ' ' + s.tier +
                '-tier IPs as ' + s.scenario + ' (' + s.expired_previous.toLocaleString() +
                ' from the previous publish expired). Your bouncers pick them up on their next pull.';
        } else { el.textContent = 'Publish failed: ' + (j.detail || r.status); }
    } finally { btn.disabled = false; }
}

// ---- System panel actions ----
async function backupNow(btn) {
    const el = document.getElementById('system-status');
    btn.disabled = true; el.textContent = 'Backing up…';
    try {
        const r = await apiFetch('/api/backup', {method: 'POST'});
        const j = await r.json().catch(() => ({}));
        el.textContent = r.ok ? 'Backup written.' : ('Backup failed: ' + (j.detail || r.status));
    } finally { btn.disabled = false; }
}
async function recalcNow(btn) {
    const el = document.getElementById('system-status');
    btn.disabled = true; el.textContent = 'Recalculating every score (can take a minute on a large corpus)…';
    try {
        const r = await apiFetch('/api/recalculate-scores', {method: 'POST'});
        const j = await r.json().catch(() => ({}));
        el.textContent = r.ok ? ('Recalculated ' + Number(j.recalculated).toLocaleString() + ' indicators.')
                              : ('Recalculate failed: ' + (j.detail || r.status));
    } finally { btn.disabled = false; }
}

// ---- Views (v2.5 shell) ----------------------------------------------------
// One page, five views; the hash names the view. The inline script in
// dashboard.html already picked the first one before paint.
const VIEWS = ['guide', 'lists', 'feeds', 'integrations', 'system'];
function showView(v, focus) {
    if (VIEWS.indexOf(v) < 0) return;
    const root = document.documentElement;
    if (!root.hasAttribute('data-view')) return;          // not the dashboard page
    if (root.getAttribute('data-view') !== v) window.scrollTo(0, 0);
    root.setAttribute('data-view', v);
    if (v === 'integrations') { loadUnifiOnce(); loadCsOnce(); }
    if (focus) {
        const h = document.querySelector('#view-' + v + ' h1');
        if (h) { h.setAttribute('tabindex', '-1'); h.focus({preventScroll: true}); }
    }
}
window.addEventListener('hashchange', () => {
    showView((location.hash || '').replace('#', '').split('/')[0], true);
});
document.addEventListener('DOMContentLoaded', () => {
    const v = document.documentElement.getAttribute('data-view');
    if (!v) return;
    // A view restored after a reload (reloadPage) gets its hash back, so the
    // address bar and the Back button agree with what is on screen.
    if (!location.hash && v !== 'lists' && v !== 'guide') history.replaceState(null, '', '#' + v);
    showView(v, false);
});
// "I'm set up": the full dashboard becomes the default; Guide stays in the rail.
function leaveGuide() {
    try { localStorage.setItem('tfm.guide', 'dismissed'); } catch (e) {}
    location.hash = 'lists';
}
// "/" jumps to the lookup box, unless the operator is typing somewhere.
document.addEventListener('keydown', (e) => {
    if (e.key !== '/' || e.ctrlKey || e.metaKey || e.altKey) return;
    const t = e.target;
    if (t && (t.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(t.tagName))) return;
    const box = document.getElementById('lookup-ip');
    if (box) { e.preventDefault(); box.focus(); }
});

// ---- Host check (DNS-rebinding allowlist) ----------------------------------
// OFF unless the operator switches it on (maintainer, 2026-09-23): an
// upgrade never starts refusing names. Names can be saved without switching
// it on, which is what the first-run guide does for a DNS name that may not
// resolve yet. Hostnames come from request headers (attacker-influenced) and
// DNS answers: esc() always.
let hostState = null;
async function loadHostCheck() {
    if (!document.getElementById('hostnames-body') && !document.getElementById('step-name')) return;
    try {
        const r = await apiFetch('/api/host-check');
        if (!r.ok) return;
        hostState = await r.json();
    } catch (e) { return; }
    renderHostCheck();
}
function _hostPost(allowed, enforce) {
    const body = {allowed: allowed};
    if (enforce !== undefined) body.enforce = enforce;
    return apiFetch('/api/host-check', {method: 'POST', headers: {'Content-Type': 'application/json'},
                                        body: JSON.stringify(body)});
}
function _chip(host, removable) {
    return '<span class="host-chip' + (removable ? '' : ' seen') + '">' + esc(host) +
        (removable ? '<button type="button" aria-label="Remove ' + esc(host) + '" data-rm="' + esc(host) + '">×</button>'
                   : '<button type="button" aria-label="Add ' + esc(host) + '" data-add="' + esc(host) + '">+</button>') +
        '</span>';
}
function _enforceSwitch(id, s) {
    const canLock = s.configured.length > 0 || !s.current_is_ip;
    return '<label class="enforce-row"><span class="switch"><input type="checkbox" id="' + id + '"' +
        (s.locked ? ' checked' : '') + (canLock ? '' : ' disabled') + ' onchange="setHostEnforce(this)"><span></span></span>' +
        '<span><b>Only answer to these names</b> (host check). ' +
        (canLock ? 'Off by default. When on, any other name is refused; the IP address still works.'
                 : 'Add a name first: the IP address you are using always works, so there is nothing to lock yet.') +
        '</span></label>';
}
function renderHostCheck() {
    const s = hostState;
    if (!s) return;
    const env = s.env.length
        ? '<p class="hint">Always enforced by <code>TFM_ALLOWED_HOSTS</code>: ' + s.env.map(esc).join(', ') + '</p>' : '';
    const saved = s.configured.length
        ? '<div class="host-names">' + s.configured.map(h => _chip(h, true)).join('') + '</div>'
        : '<p class="muted">No names saved.</p>';
    const seen = s.seen.length
        ? '<p class="hint" style="margin:8px 0 2px">Also reached as (not saved):</p><div class="host-names">' +
          s.seen.map(e => _chip(e.host, false)).join('') + '</div>' : '';
    const sys = document.getElementById('hostnames-body');
    if (sys) {
        sys.innerHTML = '<p><b class="' + (s.mode === 'enforcing' ? 'ok-text' : '') + '">' +
            (s.mode === 'enforcing' ? 'On: only the names below (and the IP address) reach the dashboard.'
                                    : 'Off: the dashboard answers to any name.') + '</b></p>' +
            env + saved + seen + _enforceSwitch('host-enforce-system', s);
    }
    const step = document.getElementById('step-name');
    if (step) {
        const done = s.configured.length > 0 || s.env.length > 0;
        step.classList.toggle('done', done);
        let html = '';
        if (s.configured.length) html += '<div class="host-names">' + s.configured.map(h => _chip(h, true)).join('') + '</div>';
        if (!s.current_is_ip && s.configured.indexOf(s.current_host) < 0 && s.env.indexOf(s.current_host) < 0) {
            html += '<p>You are using <code>' + esc(s.current_host) + '</code> right now. ' +
                '<button type="button" class="mini-btn" data-add="' + esc(s.current_host) + '">Save it</button></p>';
        }
        if (s.configured.length || !s.current_is_ip) html += _enforceSwitch('host-enforce-guide', s);
        let slot = document.getElementById('guide-name-state');
        if (!slot) {
            slot = document.createElement('div');
            slot.id = 'guide-name-state';
            slot.className = 'step-body';
            slot.style.gap = '8px';
            step.querySelector('.name-form').before(slot);
        }
        slot.innerHTML = html;
        const count = document.getElementById('guide-done');
        if (count) count.textContent = String(parseInt(count.dataset.serverDone, 10) + (done ? 1 : 0));
    }
    document.querySelectorAll('[data-rm]').forEach(b => { b.onclick = () => removeHostName(b.dataset.rm); });
    document.querySelectorAll('[data-add]').forEach(b => { b.onclick = () => saveHostName(b.dataset.add); });
}
async function saveHostName(name) {
    const names = (hostState ? hostState.configured : []).concat([name]);
    const r = await _hostPost(names);          // enforce omitted: the switch stays as it is
    const j = await r.json().catch(() => ({}));
    if (!r.ok) { alert('Could not save: ' + (j.detail || r.status)); return false; }
    hostState = j; renderHostCheck();
    return true;
}
async function removeHostName(name) {
    const names = (hostState ? hostState.configured : []).filter(h => h !== name);
    const r = await _hostPost(names);
    const j = await r.json().catch(() => ({}));
    if (r.ok) { hostState = j; renderHostCheck(); } else alert('Could not save: ' + (j.detail || r.status));
}
async function setHostEnforce(box) {
    const s = hostState;
    if (!s) return;
    if (box.checked) {
        const names = s.configured.slice();
        if (!s.current_is_ip && names.indexOf(s.current_host) < 0) names.push(s.current_host);
        if (!confirm('Only answer to these names?\n\n  ' + names.join('\n  ') +
                     '\n\nAny other name will be refused. The IP address always works, and list URLs, ' +
                     'TAXII and health checks are never affected.')) { box.checked = false; return; }
    }
    const r = await _hostPost(s.configured, box.checked);
    const j = await r.json().catch(() => ({}));
    if (r.ok) { hostState = j; renderHostCheck(); }
    else { box.checked = !box.checked; alert('Could not save: ' + (j.detail || r.status)); }
}
// "Check & add": resolve the name (a DNS lookup only, server-side), say
// whether it points at this server, then save it WITHOUT switching the
// host check on. A name that doesn't resolve yet is saved too: the guide
// is exactly where an operator adds the record they are about to create.
async function addHostName(e, where) {
    e.preventDefault();
    const input = document.getElementById(where + '-hostname');
    const out = document.getElementById(where + '-name-result');
    const name = (input.value || '').trim();
    if (!name) return false;
    out.textContent = 'Checking ' + name + '…';
    let res;
    try {
        const r = await apiFetch('/api/host-check/resolve', {method: 'POST',
            headers: {'Content-Type': 'application/json'}, body: JSON.stringify({name: name})});
        res = await r.json().catch(() => ({}));
        if (!r.ok) { out.innerHTML = '<span class="warn">' + esc(res.detail || ('Error ' + r.status)) + '</span>'; return false; }
    } catch (err) { out.textContent = 'Could not check the name.'; return false; }
    if (!(await saveHostName(res.name))) { out.textContent = ''; return false; }
    input.value = '';
    const n = '<code>' + esc(res.name) + '</code>';
    // Reached over loopback (on the box itself) the current address is no
    // use in a DNS record; firewalls need the LAN address.
    const loop = !res.current_host || /^(localhost|127\.|::1$)/.test(res.current_host);
    const here = loop ? "this server's LAN address" : '<code>' + esc(res.current_host) + '</code>';
    const addrs = (res.addresses || []).map(a => '<code>' + esc(a) + '</code>').join(', ');
    const off = hostState && hostState.mode !== 'enforcing' ? ' Nothing is blocked: the host check is off.' : '';
    let msg;
    if (!res.resolves) {
        msg = '<span class="warn">⚠ ' + n + (res.error === 'timed out' ? ' timed out in DNS.' : ' doesn\'t resolve yet.') +
            '</span> Create an A record for it pointing at ' + here + ' on your DNS server, then run Check again. Saved.' + off;
    } else if (res.matches_current === false) {
        msg = '<span class="warn">⚠ ' + n + ' resolves to ' + addrs + ', not ' + here +
            (loop ? '.' : ', the address you are using now.') + '</span> Firewalls given a URL with this name would poll that box. ' +
            'Check the DNS record. Saved.' + off;
    } else {
        const url = location.protocol + '//' + res.name + (location.port ? ':' + location.port : '') + '/';
        msg = '<span class="ok">✓ ' + n + ' resolves to ' + addrs + (res.matches_current ? ', this server' : '') +
            '.</span> Saved.' + off + ' <a href="' + esc(url) + '">Open the dashboard at ' + esc(res.name) +
            '</a> so the list URLs you copy use the name.';
    }
    out.innerHTML = msg;
    return false;
}
document.addEventListener('DOMContentLoaded', loadHostCheck);
