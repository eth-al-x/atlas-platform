/* ───────────────────────────────────────────────────────────
 * ATLAS — Operations Console (vanilla JS)
 *
 * Single-page app with hash-based routing. No framework — just
 * fetch(), template literals, and DOM manipulation against the
 * <template> elements baked into index.html.
 *
 * Routes:
 *   #overview            (default)
 *   #scans               list of scans
 *   #scans/:id           scan detail
 *   #watches             watch list
 * ─────────────────────────────────────────────────────────── */

const API = '/api/v1';

// ───── API client ─────────────────────────────────────────────

const api = {
  async stats()           { return get(`${API}/stats`); },
  async health()          { return get(`${API}/health`); },
  async scans(limit=50, offset=0) {
                            return get(`${API}/scans?limit=${limit}&offset=${offset}`);
                          },
  async scan(id)          { return get(`${API}/scans/${id}`); },
  async scanRecon(id)     { return get(`${API}/scans/${id}/recon`); },
  async watches(active=false) {
                            return get(`${API}/watches${active ? '?active=true' : ''}`);
                          },
  async addWatch(target)  { return post(`${API}/watches`, { target }); },
  async removeWatch(id)   { return del(`${API}/watches/${id}`); },
  async runWatches(changedOnly=false) {
                            return post(`${API}/watches/run`, { changed_only: changedOnly });
                          },
};

async function get(url) {
  const r = await fetch(url);
  if (!r.ok) throw new Error(`${r.status} ${r.statusText}`);
  return r.json();
}
async function post(url, body) {
  const r = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!r.ok) {
    const detail = await r.json().catch(() => ({}));
    throw new Error(detail.detail || `${r.status} ${r.statusText}`);
  }
  return r.json();
}
async function del(url) {
  const r = await fetch(url, { method: 'DELETE' });
  if (!r.ok) throw new Error(`${r.status} ${r.statusText}`);
  return r.json();
}

// ───── Formatting helpers ─────────────────────────────────────

function fmtDate(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  if (isNaN(d)) return '—';
  return d.toISOString().slice(0, 16).replace('T', ' ');
}

function fmtRelative(iso) {
  if (!iso) return 'never';
  const d = new Date(iso);
  const diff = (Date.now() - d.getTime()) / 1000;
  if (diff < 60)    return `${Math.floor(diff)}s ago`;
  if (diff < 3600)  return `${Math.floor(diff/60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff/3600)}h ago`;
  return `${Math.floor(diff/86400)}d ago`;
}

function escapeHtml(str) {
  if (str == null) return '';
  return String(str).replace(/[&<>"']/g, c => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  })[c]);
}

function pill(verdict) {
  return `<span class="pill" data-v="${escapeHtml(verdict || '—')}">${escapeHtml(verdict || '—')}</span>`;
}

function confidenceBand(c) {
  if (c >= 0.7) return 'high';
  if (c >= 0.4) return 'medium';
  if (c > 0)    return 'low';
  return 'zero';
}

// ───── View management ───────────────────────────────────────

const viewEl = document.getElementById('view');

function renderFromTemplate(templateId) {
  const tpl = document.getElementById(templateId);
  viewEl.innerHTML = '';
  viewEl.appendChild(tpl.content.cloneNode(true));
}

function setActiveNav(route) {
  document.querySelectorAll('.nav__item').forEach(el => {
    el.classList.toggle('is-active', el.dataset.route === route);
  });
}

// ───── Router ────────────────────────────────────────────────

const routes = {
  overview: renderOverview,
  scans:    renderScans,
  watches:  renderWatches,
};

function parseHash() {
  const hash = window.location.hash.replace(/^#/, '') || 'overview';
  const [route, ...rest] = hash.split('/');
  return { route, params: rest };
}

async function navigate() {
  const { route, params } = parseHash();

  // Detail view: #scans/123
  if (route === 'scans' && params.length === 1) {
    setActiveNav('scans');
    await renderScanDetail(params[0]);
    return;
  }

  const handler = routes[route] || routes.overview;
  setActiveNav(route in routes ? route : 'overview');
  await handler();
}

window.addEventListener('hashchange', navigate);

// ───── Overview ─────────────────────────────────────────────

async function renderOverview() {
  renderFromTemplate('tpl-overview');

  try {
    const resp = await api.stats();
    // Stats response is wrapped: { stats: {...}, generated_at: "..." }
    const stats = resp.stats || resp;

    viewEl.querySelector('[data-field="total"]').textContent = stats.total_scans;
    viewEl.querySelector('[data-field="high"]').textContent  = stats.high_risk;
    viewEl.querySelector('[data-field="medium"]').textContent = stats.medium_risk;
    viewEl.querySelector('[data-field="low"]').textContent   = stats.low_risk;
    viewEl.querySelector('[data-field="clean"]').textContent = stats.clean;
    viewEl.querySelector('[data-field="recent"]').textContent = `${stats.scans_last_24h} in 24h`;

    renderVerdictChart(stats);
    renderTopDomains(stats.top_flagged_domains || []);
  } catch (err) {
    viewEl.innerHTML = errorBlock(err);
  }
}

function renderVerdictChart(stats) {
  const total = stats.total_scans || 1;
  const rows = [
    { label: 'High Risk',   value: stats.high_risk },
    { label: 'Medium Risk', value: stats.medium_risk },
    { label: 'Low Risk',    value: stats.low_risk },
    { label: 'Clean',       value: stats.clean },
  ];

  const html = rows.map(r => {
    const pct = (r.value / total) * 100;
    return `
      <div class="verdict-bar" data-v="${r.label}">
        <span class="verdict-bar__label">${r.label.toLowerCase()}</span>
        <span class="verdict-bar__track">
          <span class="verdict-bar__fill" style="width: ${pct.toFixed(1)}%"></span>
        </span>
        <span class="verdict-bar__count">${r.value}</span>
      </div>
    `;
  }).join('');

  viewEl.querySelector('#verdict-chart').innerHTML = html;
}

function renderTopDomains(domains) {
  const container = viewEl.querySelector('#top-domains');
  if (!domains.length) {
    container.innerHTML = '<div class="empty">no flagged domains yet</div>';
    return;
  }
  container.innerHTML = domains.map(d => `
    <div class="data-list__row">
      <span class="data-list__key" title="${escapeHtml(d.domain)}">${escapeHtml(d.domain)}</span>
      <span class="data-list__val">${pill(d.final_verdict)} × ${d.count}</span>
    </div>
  `).join('');
}

// ───── Scan list ────────────────────────────────────────────

async function renderScans() {
  renderFromTemplate('tpl-scans');

  const filterEl = viewEl.querySelector('#filter-verdict');
  filterEl.addEventListener('change', () => loadScans(filterEl.value));
  await loadScans('');
}

async function loadScans(verdictFilter) {
  try {
    const { items } = await api.scans(100, 0);
    const filtered = verdictFilter
      ? items.filter(s => s.final_verdict === verdictFilter)
      : items;

    viewEl.querySelector('#scan-count').textContent =
      `${filtered.length} of ${items.length}`;

    const tbody = viewEl.querySelector('#scans-tbody');
    if (!filtered.length) {
      tbody.innerHTML = `<tr class="no-click"><td colspan="6" class="empty">no scans match</td></tr>`;
      return;
    }

    tbody.innerHTML = filtered.map(s => `
      <tr data-scan-id="${s.id}">
        <td class="col-id">#${s.id}</td>
        <td>${escapeHtml(s.domain)}</td>
        <td class="col-url" title="${escapeHtml(s.url)}">${escapeHtml(s.url)}</td>
        <td>${pill(s.final_verdict)}</td>
        <td class="col-time">${fmtDate(s.scanned_at)}</td>
        <td class="col-dur">${s.scan_duration_ms || '—'}</td>
      </tr>
    `).join('');

    tbody.querySelectorAll('tr[data-scan-id]').forEach(tr => {
      tr.addEventListener('click', () => {
        window.location.hash = `scans/${tr.dataset.scanId}`;
      });
    });
  } catch (err) {
    viewEl.querySelector('#scans-tbody').innerHTML =
      `<tr class="no-click"><td colspan="6">${errorRow(err)}</td></tr>`;
  }
}

// ───── Scan detail ──────────────────────────────────────────

async function renderScanDetail(scanId) {
  renderFromTemplate('tpl-scan-detail');

  viewEl.querySelector('[data-action="back-to-scans"]')
        .addEventListener('click', () => window.location.hash = 'scans');

  try {
    const { scan }   = await api.scan(scanId);
    const reconData  = await api.scanRecon(scanId).catch(() => ({}));

    // Header
    viewEl.querySelector('[data-field="domain"]').textContent = scan.domain;
    viewEl.querySelector('[data-field="id"]').textContent     = `scan id #${scan.id}`;
    viewEl.querySelector('[data-field="url"]').textContent    = scan.url;

    // Verdict banner
    const banner = viewEl.querySelector('[data-field="verdict-banner"]');
    banner.dataset.v = scan.final_verdict;
    viewEl.querySelector('[data-field="verdict"]').textContent = scan.final_verdict;
    viewEl.querySelector('[data-field="meta-scanned"]').textContent =
      `scanned ${fmtRelative(scan.scanned_at)}`;
    viewEl.querySelector('[data-field="meta-dur"]').textContent =
      `${scan.scan_duration_ms || '—'} ms`;

    renderTierResults(scan.tier_results || []);
    renderCorrelations(scan.correlations || []);
    renderRecon(reconData);
  } catch (err) {
    viewEl.innerHTML = errorBlock(err);
  }
}

function renderTierResults(tiers) {
  const container = viewEl.querySelector('#tier-results');
  if (!tiers.length) {
    container.innerHTML = '<div class="empty">no tier results</div>';
    return;
  }
  container.innerHTML = tiers.map(t => {
    const conf = t.confidence || 0;
    const pct = (conf * 100).toFixed(0);
    return `
      <div class="tier-row">
        <span class="tier-row__name" data-flagged="${t.flagged}">
          ${escapeHtml(t.display_name || t.tier_name)}
        </span>
        <span class="tier-row__bar">
          <span class="tier-row__fill"
                data-conf="${confidenceBand(conf)}"
                style="width: ${pct}%"></span>
        </span>
        <span class="tier-row__val">${pct}%</span>
      </div>
    `;
  }).join('');
}

function renderCorrelations(corrs) {
  for (const c of corrs) {
    if (c.error) continue;
    switch (c.correlator_name) {
      case 'risk_score': renderRiskScore(c); break;
      case 'mitre':      renderMitre(c); break;
      case 'timeline':   renderTimeline(c); break;
      case 'cross_scan': renderCrossScan(c); break;
    }
  }
}

function renderRiskScore(corr) {
  const score = corr.data?.score || 0;
  const band  = corr.data?.band  || 'Minimal';
  const breakdown = corr.findings || [];

  const panel = viewEl.querySelector('#risk-panel');
  panel.hidden = false;

  // SVG ring gauge
  const R = 42;
  const CIRC = 2 * Math.PI * R;
  const offset = CIRC * (1 - score / 100);

  panel.querySelector('#risk-gauge').innerHTML = `
    <svg viewBox="0 0 120 120" width="120" height="120">
      <circle class="risk-gauge__track" cx="60" cy="60" r="${R}"></circle>
      <circle class="risk-gauge__value" cx="60" cy="60" r="${R}"
              data-band="${escapeHtml(band)}"
              stroke-dasharray="${CIRC}"
              stroke-dashoffset="${offset.toFixed(2)}"></circle>
    </svg>
    <div class="risk-gauge__center">
      <div class="risk-gauge__num">${Math.round(score)}</div>
      <div class="risk-gauge__band">${escapeHtml(band)}</div>
    </div>
  `;

  panel.querySelector('#risk-breakdown').innerHTML = breakdown.map(f => `
    <div class="risk-source">
      <span class="risk-source__name">${escapeHtml(f.source || f.reason || '—')}</span>
      <span class="risk-source__points">+${(f.points || 0).toFixed(1)}</span>
    </div>
  `).join('') || '<div class="empty">no risk contributors</div>';
}

function renderMitre(corr) {
  if (!corr.findings?.length) return;
  const panel = viewEl.querySelector('#mitre-panel');
  panel.hidden = false;
  panel.querySelector('#mitre-chips').innerHTML = corr.findings.map(f => `
    <div class="mitre-chip">
      <span class="mitre-chip__id">${escapeHtml(f.technique_id || '—')}</span>
      <span class="mitre-chip__name">${escapeHtml(f.name || '—')}</span>
      <span class="mitre-chip__tactic">${escapeHtml(f.tactic || '—')}</span>
    </div>
  `).join('');
}

function renderTimeline(corr) {
  if (!corr.findings?.length) return;
  const panel = viewEl.querySelector('#timeline-panel');
  panel.hidden = false;
  panel.querySelector('#timeline-events').innerHTML = corr.findings.map(f => `
    <li class="timeline__event">
      <span class="timeline__date">${escapeHtml((f.date || '').slice(0, 10) || '—')}</span>
      <span class="timeline__desc">${escapeHtml(f.event || '—')}</span>
    </li>
  `).join('');
}

function renderCrossScan(corr) {
  if (!corr.findings?.length) return;
  const panel = viewEl.querySelector('#cross-scan-panel');
  panel.hidden = false;
  panel.querySelector('#cross-scan-list').innerHTML = corr.findings.map(f => `
    <div class="related-row">
      <span class="related-row__cat">${escapeHtml(f.category)}</span>
      <span class="related-row__domain">
        <a href="#scans/${f.scan_id}" style="color: inherit; text-decoration: none;">
          ${escapeHtml(f.domain)}
        </a>
        ${pill(f.verdict)}
      </span>
      <span class="related-row__value" title="${escapeHtml(f.matched_value)}">
        ${escapeHtml(f.matched_value)}
      </span>
    </div>
  `).join('');
}

function renderRecon(reconData) {
  const types = Object.keys(reconData || {});
  if (!types.length) return;

  const panel = viewEl.querySelector('#recon-panel');
  panel.hidden = false;
  const tabsEl = panel.querySelector('#recon-tabs');
  const preEl  = panel.querySelector('#recon-pre');

  tabsEl.innerHTML = types.map((t, i) => `
    <button class="recon-tab ${i === 0 ? 'is-active' : ''}" data-tab="${escapeHtml(t)}">
      ${escapeHtml(t)}
    </button>
  `).join('');

  function show(name) {
    preEl.textContent = JSON.stringify(reconData[name]?.data || {}, null, 2);
    tabsEl.querySelectorAll('.recon-tab').forEach(b => {
      b.classList.toggle('is-active', b.dataset.tab === name);
    });
  }
  tabsEl.querySelectorAll('.recon-tab').forEach(b => {
    b.addEventListener('click', () => show(b.dataset.tab));
  });
  show(types[0]);
}

// ───── Watches ──────────────────────────────────────────────

async function renderWatches() {
  renderFromTemplate('tpl-watches');

  const input = viewEl.querySelector('#watch-input');
  const addBtn = viewEl.querySelector('#watch-add-btn');
  const runBtn = viewEl.querySelector('#watch-run-btn');

  addBtn.addEventListener('click', async () => {
    const val = input.value.trim();
    if (!val) return;
    addBtn.disabled = true;
    try {
      await api.addWatch(val);
      input.value = '';
      await loadWatches();
    } catch (err) {
      alert(`Could not add watch: ${err.message}`);
    } finally {
      addBtn.disabled = false;
    }
  });

  input.addEventListener('keydown', e => {
    if (e.key === 'Enter') addBtn.click();
  });

  runBtn.addEventListener('click', async () => {
    runBtn.disabled = true;
    runBtn.textContent = 'running…';
    try {
      const alerts = await api.runWatches(false);
      renderWatchResults(alerts);
      await loadWatches();
    } catch (err) {
      alert(`Run failed: ${err.message}`);
    } finally {
      runBtn.disabled = false;
      runBtn.textContent = 'run all';
    }
  });

  await loadWatches();
}

async function loadWatches() {
  try {
    const watches = await api.watches(true);
    const tbody = viewEl.querySelector('#watches-tbody');
    if (!watches.length) {
      tbody.innerHTML = `<tr class="no-click"><td colspan="6" class="empty">no domains watched yet</td></tr>`;
      return;
    }
    tbody.innerHTML = watches.map(w => `
      <tr class="no-click">
        <td class="col-id">#${w.id}</td>
        <td>${escapeHtml(w.domain)}</td>
        <td>${pill(w.last_verdict || '—')}</td>
        <td class="col-time">${w.last_checked_at ? fmtRelative(w.last_checked_at) : 'never'}</td>
        <td class="col-checks">${w.check_count}</td>
        <td class="col-actions">
          <button class="btn btn--ghost" data-remove="${w.id}">remove</button>
        </td>
      </tr>
    `).join('');

    tbody.querySelectorAll('[data-remove]').forEach(btn => {
      btn.addEventListener('click', async () => {
        if (!confirm(`Stop watching this domain?`)) return;
        await api.removeWatch(btn.dataset.remove);
        await loadWatches();
      });
    });
  } catch (err) {
    viewEl.querySelector('#watches-tbody').innerHTML =
      `<tr class="no-click"><td colspan="6">${errorRow(err)}</td></tr>`;
  }
}

function renderWatchResults(alerts) {
  const panel = viewEl.querySelector('#watch-results-panel');
  const list  = viewEl.querySelector('#watch-results');

  panel.hidden = false;

  if (!alerts.length) {
    list.innerHTML = '<div class="empty">no domains to check</div>';
    return;
  }

  const icons = { new: '＋', escalated: '↑', 'de-escalated': '↓', unchanged: '·' };

  list.innerHTML = alerts.map(a => {
    const change = a.is_new
      ? 'first check'
      : (a.changed
          ? `${a.previous_verdict || '—'} → ${a.new_verdict}`
          : 'unchanged');
    return `
      <div class="alert" data-dir="${a.direction}">
        <span class="alert__icon">${icons[a.direction] || '·'}</span>
        <div>
          <div class="alert__domain">${escapeHtml(a.domain)}</div>
          <div class="alert__change">${escapeHtml(change)}</div>
        </div>
        <span class="alert__verdict">${pill(a.new_verdict)}</span>
      </div>
    `;
  }).join('');
}

// ───── Status indicator (health check) ──────────────────────

async function pingHealth() {
  const el = document.getElementById('api-status');
  const dot = el.querySelector('.status__dot');
  const txt = el.querySelector('.status__text');
  try {
    await api.health();
    dot.dataset.state = 'ok';
    txt.textContent = 'api online';
  } catch {
    dot.dataset.state = 'error';
    txt.textContent = 'api offline';
  }
}

// ───── Error helpers ────────────────────────────────────────

function errorBlock(err) {
  return `
    <div class="panel">
      <div class="panel__body">
        <div class="empty" style="color: var(--v-high)">
          error: ${escapeHtml(err.message)}
        </div>
      </div>
    </div>
  `;
}

function errorRow(err) {
  return `<div class="empty" style="color: var(--v-high)">error: ${escapeHtml(err.message)}</div>`;
}

// ───── Boot ─────────────────────────────────────────────────

pingHealth();
navigate();
setInterval(pingHealth, 30_000);
