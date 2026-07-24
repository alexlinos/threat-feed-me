// CSRF protection: when Basic auth is on, every mutating fetch must carry
// X-Requested-With: XMLHttpRequest so the server can distinguish same-origin
// dashboard JS from a cross-site form/script (browsers do not auto-set this
// header cross-origin).
function apiFetch(url, opts) {
    const h = opts.headers || {};
    opts.headers = Object.assign(h, {'X-Requested-With': 'XMLHttpRequest'});
    return fetch(url, opts);
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
    if (r.ok && j.success !== false) { location.reload(); }
    else { alert('Could not add: ' + (j.message || j.detail || r.status)); }
    return false;
}
async function removeWl(ip, feed) {
    if (!confirm('Remove whitelist entry for ' + ip + ' (' + (feed === '*' ? 'all feeds' : feed) + ')?')) return;
    const r = await apiFetch('/api/whitelist?ip=' + encodeURIComponent(ip) + '&feed=' + encodeURIComponent(feed), {method: 'DELETE'});
    if (r.ok) { location.reload(); }
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
    if (r.ok && j.success !== false) { location.reload(); }
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
    if (r.ok && j.success !== false) { alert(j.message || 'Uploaded'); location.reload(); }
    else { alert('Upload failed: ' + (j.message || j.detail || r.status)); }
    return false;
}
async function removeFeed(name) {
    if (!confirm('Remove feed "' + name + '"? Existing indicators stay until the next refresh.')) return;
    const r = await apiFetch('/api/feeds/' + encodeURIComponent(name), {method:'DELETE'});
    if (r.ok) { location.reload(); } else { alert('Could not remove feed'); }
}
async function toggleFeed(name, enabled) {
    await apiFetch('/api/feeds/' + encodeURIComponent(name) + '/enabled?enabled=' + enabled, {method:'POST'});
}
async function setApiKey(name, envVar) {
    const key = prompt('API key for "' + name + '"\n\nSaved server-side to the data volume\'s .env as ' + envVar +
        ' and applied immediately.\nLeave empty and press OK to clear the stored key.');
    if (key === null) return; // cancelled
    const r = await apiFetch('/api/feeds/' + encodeURIComponent(name) + '/api-key', {
        method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({api_key: key}),
    });
    const j = await r.json().catch(() => ({}));
    if (r.ok) { location.reload(); }
    else { alert('Could not save key: ' + (j.detail || r.status)); }
}
async function saveInterval() {
    const v = parseInt(document.getElementById('interval-min').value, 10);
    if (!v || v < 1) { alert('Enter a whole number of minutes (>= 1)'); return; }
    const r = await apiFetch('/api/settings', {method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({refresh_interval_minutes: v})});
    alert(r.ok ? 'Auto-refresh set to every ' + v + ' min' : 'Could not save');
}
function refreshAll() { startRefresh(null); }
function refreshFeed(name) { startRefresh(name); }
async function startRefresh(name) {
    const btn = document.getElementById('refresh-all-btn');
    const status = document.getElementById('refresh-status');
    btn.disabled = true;
    const url = '/api/refresh' + (name ? '?feed=' + encodeURIComponent(name) : '');
    const r = await apiFetch(url, {method:'POST'});
    if (r.status === 409) { status.textContent = 'A refresh is already running…'; }
    else { status.textContent = 'Refreshing' + (name ? ' ' + name : ' all feeds') + '… this can take a minute.'; }
    pollRefresh();
}
async function pollRefresh() {
    const status = document.getElementById('refresh-status');
    const btn = document.getElementById('refresh-all-btn');
    const r = await fetch('/api/refresh/status');
    const j = await r.json();
    if (j.running) { setTimeout(pollRefresh, 2000); }
    else {
        btn.disabled = false;
        status.textContent = j.last_error ? ('Last refresh error: ' + j.last_error) : 'Refresh complete.';
        if (!j.last_error) setTimeout(() => location.reload(), 800);
    }
}
async function restoreDefaults() {
    if (!confirm('Re-add the curated default feeds that are currently missing?')) return;
    const r = await apiFetch('/api/feeds/restore-defaults', {method:'POST'});
    const j = await r.json().catch(() => ({}));
    if (r.ok) { alert(j.count ? ('Added: ' + j.added.join(', ')) : 'All default feeds already present'); location.reload(); }
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
        body.innerHTML = '<tr><td colspan="5" class="muted">No matching indicators.</td></tr>';
    } else {
        body.innerHTML = j.indicators.map(i => {
            const badge = 'tier-' + i.tier;
            return '<tr><td><code>' + esc(i.value) + '</code></td>' +
                '<td><span class="badge ' + badge + '">' + esc(i.tier) + '</span></td>' +
                '<td>' + esc(i.confidence_score) + '</td>' +
                '<td class="muted" style="font-size:.82em">' + esc(i.sources.join(', ')) + '</td>' +
                '<td><button class="mini-btn" data-ip="' + esc(i.ip) + '" onclick="openWhitelistModal(this.dataset.ip)">Whitelist…</button></td></tr>';
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
document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('ind-q').addEventListener('input', () => {
        clearTimeout(indDebounce);
        indDebounce = setTimeout(() => { indOffset = 0; loadIndicators(); }, 300);
    });
    loadIndicators();
});
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

// ---- Whitelist modal (shows which feed reported the IP) ----
let wlModalIp = null;
async function openWhitelistModal(ip) {
    wlModalIp = ip;
    document.getElementById('wl-modal-ip').textContent = ip;
    document.getElementById('wl-modal-note').value = '';
    const scope = document.getElementById('wl-modal-scope');
    const srcBox = document.getElementById('wl-modal-sources');
    scope.innerHTML = '<option value="*">All feeds</option>';
    srcBox.textContent = 'Loading…';
    try {
        const j = await (await fetch('/api/indicators/' + encodeURIComponent(ip))).json();
        const sources = j.sources || [];
        srcBox.innerHTML = sources.length
            ? sources.map(s => '<code>' + esc(s) + '</code>').join(' ')
            : '<span class="muted">no feed sources on record</span>';
        sources.forEach(s => {
            const o = document.createElement('option'); o.value = s;
            o.textContent = 'Only ' + s; scope.appendChild(o);
        });
        // Default to the reporting feed when there is exactly one.
        if (sources.length === 1) scope.value = sources[0];
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
    if (r.ok && j.success !== false) { closeWlModal(); location.reload(); }
    else { alert('Could not whitelist: ' + (j.message || j.detail || r.status)); }
}
