/* NetMonitor Command Center - dashboard application */
(() => {
'use strict';

// ---------- helpers ----------
const $ = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => Array.from(el.querySelectorAll(s));
const css = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();
const C = {
  s1: css('--series-1'), s2: css('--series-2'), s3: css('--series-3'), s4: css('--series-4'),
  s5: css('--series-5'), s6: css('--series-6'), s7: css('--series-7'), s8: css('--series-8'),
  good: css('--good'), warning: css('--warning'), serious: css('--serious'), critical: css('--critical'),
  grid: css('--grid'), axis: css('--axis'), muted: css('--muted'), text2: css('--text-2'), text: css('--text'), surface: css('--surface'),
};
const SERIES = [C.s1, C.s2, C.s3, C.s4, C.s5, C.s6, C.s7, C.s8];
const SEV_COLOR = { critical: C.critical, high: C.serious, medium: C.warning, low: C.s1, info: C.muted };
const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

function fmtBytes(b) {
  b = Number(b) || 0;
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  while (b >= 1024 && i < u.length - 1) { b /= 1024; i++; }
  return (i === 0 ? b.toFixed(0) : b.toFixed(b >= 100 ? 0 : 1)) + ' ' + u[i];
}
const fmtRate = (b) => fmtBytes(b) + '/s';
function fmtAge(ms) {
  const s = Math.max(0, Math.floor(ms / 1000));
  if (s < 60) return s + 's';
  if (s < 3600) return Math.floor(s / 60) + 'm';
  if (s < 86400) return Math.floor(s / 3600) + 'h ' + Math.floor((s % 3600) / 60) + 'm';
  return Math.floor(s / 86400) + 'd ' + Math.floor((s % 86400) / 3600) + 'h';
}
const pad = (n) => String(n).padStart(2, '0');
function timeStr(ts) { const d = new Date(ts); return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`; }
function dateTimeStr(ts) { const d = new Date(ts); return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`; }
function esc(s) { return String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }
function flag(cc) {
  if (!cc || cc.length !== 2 || cc === '??') return '';
  return String.fromCodePoint(...cc.toUpperCase().split('').map((c) => 0x1f1e6 + c.charCodeAt(0) - 65));
}
function shortIp(ip) { return ip.includes(':') ? ip.split(':').slice(0, 3).join(':') + ':…' : ip; }
// Nice byte-based axis ticks (1 KB, 2 KB, 5 KB...) instead of decimal rounding of raw bytes.
function byteTicks(axis) {
  const max = Math.max(axis.max || 0, 1);
  const steps = [1, 2, 5, 10, 20, 50, 100, 200, 500];
  let unit = 1;
  while (max / unit >= 1024 && unit < 1024 ** 4) unit *= 1024;
  const target = max / 4;
  let step = steps.find((s) => s * unit >= target) * unit;
  if (!step) step = 500 * unit;
  const ticks = [];
  for (let v = 0; v <= max + step * 0.01; v += step) ticks.push({ value: v });
  axis.ticks = ticks;
}
function riskClass(r) { return r >= 60 ? 'm-critical' : r >= 25 ? 'm-serious' : r >= 10 ? 'm-warn' : ''; }
function riskColor(r) { return r >= 60 ? C.critical : r >= 25 ? C.serious : r >= 10 ? C.warning : C.s1; }
function meter(r) { r = Math.min(100, Number(r) || 0); return `<span class="meter ${riskClass(r)}"><span class="track"><span class="fill" style="width:${r}%"></span></span><small>${r}</small></span>`; }
function sigTag(meta) {
  const s = meta?.sig || 'pending';
  const map = { valid: ['sig-valid', '✓ signed'], notsigned: ['sig-notsigned', '✗ unsigned'], invalid: ['sig-invalid', '⚠ invalid'], unknown: ['sig-pending', '? unknown'], pending: ['sig-pending', '… checking'] };
  const [cls, label] = map[s] || map.pending;
  const signer = meta?.signer ? ` title="${esc(meta.signer)}"` : '';
  let vt = '';
  if (meta?.vt_checked && meta.vt_positives > 0) vt = ` <span class="tag intel">VT ${meta.vt_positives}/${meta.vt_total}</span>`;
  return `<span class="tag ${cls}"${signer}>${label}</span>${vt}`;
}
function pathTags(flags) {
  if (!flags || !flags.length) return '';
  const bad = ['temp', 'appdata-temp', 'downloads', 'public', 'recycle-bin', 'desktop', 'drive-root', 'profile-root', 'odd-extension'];
  return flags.filter((f) => f !== 'system' && f !== 'program-files' && f !== 'windows').map((f) => `<span class="tag ${bad.includes(f) ? 'flag' : ''}">${esc(f)}</span>`).join('');
}
async function api(path, opts) {
  const r = await fetch(path, opts);
  if (!r.ok) throw new Error(`${path}: ${r.status}`);
  return r.json();
}
async function post(path, body) { return api(path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body || {}) }); }
function toast(title, detail, cls = '') {
  const el = document.createElement('div');
  el.className = 'toast ' + cls;
  el.innerHTML = `<div class="t-title">${esc(title)}</div>${detail ? `<div class="t-detail">${esc(detail)}</div>` : ''}`;
  $('#toasts').appendChild(el);
  setTimeout(() => el.remove(), 7000);
}
const QTYPE = { 1: 'A', 28: 'AAAA', 5: 'CNAME', 16: 'TXT', 15: 'MX', 2: 'NS', 12: 'PTR', 33: 'SRV', 65: 'HTTPS', 6: 'SOA', 10: 'NULL', 255: 'ANY' };
const QSTATUS = { 0: 'ok', 9003: 'NXDOMAIN', 9701: 'no records', 1460: 'timeout', 9501: 'no records', 87: 'bad param', 9002: 'server fail', 1168: 'not found', 9560: 'blocked', 1223: 'cancelled' };

// Fixed entity -> color slot assignment (never recolored on filter).
const entityColors = new Map(JSON.parse(localStorage.getItem('nm-entity-colors') || '[]'));
function entityColor(name) {
  if (!entityColors.has(name)) {
    const used = new Set(entityColors.values());
    let slot = SERIES.findIndex((c) => !used.has(c));
    if (slot < 0) slot = entityColors.size % SERIES.length;
    entityColors.set(name, SERIES[slot]);
    localStorage.setItem('nm-entity-colors', JSON.stringify([...entityColors].slice(-64)));
  }
  return entityColors.get(name);
}

// ---------- Chart.js defaults ----------
Chart.defaults.color = C.muted;
Chart.defaults.font.family = 'system-ui, -apple-system, "Segoe UI", sans-serif';
Chart.defaults.font.size = 11;
Chart.defaults.borderColor = C.grid;
Chart.defaults.plugins.legend.display = false;
Chart.defaults.plugins.tooltip.backgroundColor = '#222221';
Chart.defaults.plugins.tooltip.titleColor = C.text;
Chart.defaults.plugins.tooltip.bodyColor = C.text2;
Chart.defaults.plugins.tooltip.borderColor = 'rgba(255,255,255,0.12)';
Chart.defaults.plugins.tooltip.borderWidth = 1;
Chart.defaults.plugins.tooltip.padding = 8;
Chart.defaults.animation = false;
const gridOpts = { color: C.grid, lineWidth: 1, drawTicks: false };
const crosshair = {
  id: 'crosshair',
  afterDraw(chart) {
    const a = chart.tooltip?.getActiveElements?.();
    if (!a || !a.length) return;
    const x = a[0].element.x, { top, bottom } = chart.chartArea, ctx = chart.ctx;
    ctx.save(); ctx.strokeStyle = C.axis; ctx.lineWidth = 1; ctx.beginPath(); ctx.moveTo(x, top); ctx.lineTo(x, bottom); ctx.stroke(); ctx.restore();
  },
};

// ---------- app state ----------
const S = {
  view: 'overview', overview: null, series: [], top: [], geo: [], home: null, alerts: [], conns: [], procs: [], dns: [],
  intel: null, config: null, wsOk: false, histHours: 24, drawerPid: null, lastConnKeys: new Set(), ticker: [],
};
const charts = {};

// ---------- navigation ----------
function setView(v) {
  S.view = v;
  $$('.nav-btn').forEach((b) => b.classList.toggle('active', b.dataset.view === v));
  $$('.view').forEach((s) => s.classList.toggle('active', s.id === 'view-' + v));
  $('#view-title').textContent = $(`.nav-btn[data-view="${v}"]`).textContent.replace(/[^A-Za-z ]/g, '').trim();
  if (v === 'globe') mountGlobe($('#globe-host-full'));
  else if (v === 'overview') mountGlobe($('#globe-host-overview'));
  refreshView(true);
}
$$('.nav-btn').forEach((b) => b.addEventListener('click', () => setView(b.dataset.view)));
$$('[data-goto]').forEach((b) => b.addEventListener('click', () => setView(b.dataset.goto)));
$('#pill-update').addEventListener('click', () => setView('settings'));
setInterval(() => { const d = new Date(); $('#clock').textContent = `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`; }, 1000);

// ---------- websocket ----------
function connectWs() {
  const ws = new WebSocket((location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host + '/ws');
  ws.onopen = () => { S.wsOk = true; $('#st-ws').className = 'dot on'; };
  ws.onclose = () => { S.wsOk = false; $('#st-ws').className = 'dot off'; setTimeout(connectWs, 2000); };
  ws.onmessage = (ev) => {
    let m; try { m = JSON.parse(ev.data); } catch { return; }
    if (m.type === 'hello') { applyOverview(m.overview); }
    else if (m.type === 'tick') onTick(m);
    else if (m.type === 'alert') onAlert(m.alert);
    else if (m.type === 'dns') onDns(m.event);
  };
}

function onTick(m) {
  S.series.push(m.sample);
  if (S.series.length > 300) S.series.shift();
  S.top = m.top;
  $('#t-out').textContent = fmtRate(m.sample.bytes_out);
  $('#t-in').textContent = fmtRate(m.sample.bytes_in);
  $('#t-conns').textContent = m.sample.conns;
  $('#t-conns-sub').textContent = `${m.public_conns} to the internet`;
  $('#t-procs').textContent = m.sample.procs;
  $('#st-etw').className = 'dot ' + (m.etw ? 'on' : 'off');
  $('#st-etw').title = m.etw ? `${m.etw_events} events captured` : 'ETW capture inactive';
  setUnacked(m.unacked);
  drawSpark($('#spark-out'), S.series.map((s) => s.bytes_out), C.s1);
  drawSpark($('#spark-in'), S.series.map((s) => s.bytes_in), C.s3);
  if (S.view === 'overview') { updateThroughput(); updateTop(); }
}

function setUnacked(n) {
  $('#t-alerts').textContent = n;
  const b = $('#nav-alert-badge');
  b.hidden = n === 0; b.textContent = n;
}

function onAlert(a) {
  S.alerts.unshift(a);
  if (S.alerts.length > 500) S.alerts.pop();
  if (a.severity === 'critical' || a.severity === 'high') toast(a.title, a.detail, 'sev-' + a.severity);
  renderOverviewAlerts();
  if (S.view === 'alerts') renderAlerts();
  updateSeverityPills();
}

function onDns(e) {
  S.dns.unshift(e);
  if (S.dns.length > 400) S.dns.pop();
  if (S.view === 'dns') renderDns();
}

function applyOverview(o) {
  S.overview = o;
  $('#st-admin').className = 'dot ' + (o.is_admin ? 'on' : 'off');
  $('#st-etw').className = 'dot ' + (o.etw_active ? 'on' : 'off');
  $('#st-intel').className = 'dot ' + (o.intel_ips > 0 ? 'on' : 'warn');
  $('#st-intel').title = `${o.intel_ips} IPs / ${o.intel_domains} domains`;
  $('#version').textContent = 'v' + o.app_version + (o.is_admin ? '' : ' · limited (not admin)');
  $('#t-listeners').textContent = `${o.listeners} listening ports`;
  $('#t-total').textContent = fmtBytes(o.total_out + o.total_in);
  $('#t-total-sub').textContent = `↑ ${fmtBytes(o.total_out)} · ↓ ${fmtBytes(o.total_in)}`;
  $('#pill-update').hidden = !o.update_required;
  setUnacked(o.unacked);
  const bs = o.alerts_by_sev || {};
  $('#t-alerts-sub').textContent = SEV_ORDER.filter((s) => bs[s]).map((s) => `${bs[s]} ${s}`).join(' · ') || 'nothing flagged';
  if (!S.series.length && !S.top.length) S.top = o.top;
  updateCountries(o.countries || []);
  updateSeverityPills();
}

function updateSeverityPills() {
  const open = S.alerts.filter((a) => !a.acked);
  const c = open.filter((a) => a.severity === 'critical').length;
  const h = open.filter((a) => a.severity === 'high').length;
  $('#pill-critical').hidden = !c; $('#pill-critical').textContent = `${c} critical`;
  $('#pill-high').hidden = !h; $('#pill-high').textContent = `${h} high`;
}

// ---------- sparklines ----------
function drawSpark(cv, data, color) {
  const ctx = cv.getContext('2d'), w = cv.width, h = cv.height;
  ctx.clearRect(0, 0, w, h);
  const pts = data.slice(-60);
  if (pts.length < 2) return;
  const max = Math.max(1, ...pts);
  ctx.beginPath();
  pts.forEach((v, i) => { const x = (i / (pts.length - 1)) * (w - 2) + 1, y = h - 2 - (v / max) * (h - 6); i ? ctx.lineTo(x, y) : ctx.moveTo(x, y); });
  ctx.strokeStyle = color; ctx.lineWidth = 1.5; ctx.lineJoin = 'round'; ctx.stroke();
  ctx.lineTo(w - 1, h); ctx.lineTo(1, h); ctx.closePath();
  ctx.fillStyle = color + '22'; ctx.fill();
}
function drawProcSpark(cv, series) {
  const ctx = cv.getContext('2d'), w = cv.width, h = cv.height;
  ctx.clearRect(0, 0, w, h);
  if (!series || series.length < 2) return;
  const max = Math.max(1, ...series.map((p) => Math.max(p[0], p[1])));
  const line = (idx, color) => {
    ctx.beginPath();
    series.forEach((p, i) => { const x = (i / (series.length - 1)) * (w - 2) + 1, y = h - 1 - (p[idx] / max) * (h - 3); i ? ctx.lineTo(x, y) : ctx.moveTo(x, y); });
    ctx.strokeStyle = color; ctx.lineWidth = 1.2; ctx.stroke();
  };
  line(1, C.s3); line(0, C.s1);
}

// ---------- overview charts ----------
function initCharts() {
  charts.throughput = new Chart($('#chart-throughput'), {
    type: 'line',
    data: { labels: [], datasets: [
      { label: 'Upload', data: [], borderColor: C.s1, backgroundColor: C.s1 + '1a', fill: true, borderWidth: 2, pointRadius: 0, pointHitRadius: 12, tension: 0.25 },
      { label: 'Download', data: [], borderColor: C.s3, backgroundColor: C.s3 + '1a', fill: true, borderWidth: 2, pointRadius: 0, pointHitRadius: 12, tension: 0.25 },
    ] },
    options: { responsive: true, maintainAspectRatio: false, interaction: { mode: 'index', intersect: false },
      scales: { x: { grid: { display: false }, ticks: { maxTicksLimit: 6, maxRotation: 0 }, border: { color: C.axis } },
                y: { beginAtZero: true, suggestedMax: 10240, grid: gridOpts, border: { display: false }, afterBuildTicks: byteTicks, ticks: { callback: (v) => fmtBytes(v) + '/s' } } },
      plugins: { tooltip: { callbacks: { label: (c) => ` ${c.dataset.label}: ${fmtRate(c.parsed.y)}` } } } },
    plugins: [crosshair],
  });
  charts.top = new Chart($('#chart-top'), {
    type: 'bar',
    data: { labels: [], datasets: [{ label: 'Bytes', data: [], backgroundColor: C.s1, barThickness: 14, borderRadius: 4, borderSkipped: 'start' }] },
    options: { indexAxis: 'y', responsive: true, maintainAspectRatio: false,
      scales: { x: { beginAtZero: true, suggestedMax: 1024, grid: gridOpts, border: { display: false }, afterBuildTicks: byteTicks, ticks: { callback: fmtBytes } }, y: { grid: { display: false }, border: { color: C.axis }, ticks: { color: C.text2 } } },
      plugins: { tooltip: { callbacks: { label: (c) => ` ${fmtBytes(c.parsed.x)}` } } },
      onClick: (e, els) => { if (els.length) openDrawer(S.top[els[0].index]?.pid); } },
  });
  charts.countries = new Chart($('#chart-countries'), {
    type: 'bar',
    data: { labels: [], datasets: [{ label: 'Connections', data: [], backgroundColor: C.s1, barThickness: 14, borderRadius: 4, borderSkipped: 'start' }] },
    options: { indexAxis: 'y', responsive: true, maintainAspectRatio: false,
      scales: { x: { beginAtZero: true, grid: gridOpts, border: { display: false }, ticks: { maxTicksLimit: 4, precision: 0 } }, y: { grid: { display: false }, border: { color: C.axis }, ticks: { color: C.text2 } } },
      plugins: { tooltip: { callbacks: { label: (c) => ` ${c.parsed.x} connections` } } } },
  });
  charts.alerts = new Chart($('#chart-alerts'), {
    type: 'bar',
    data: { labels: [], datasets: SEV_ORDER.map((s) => ({ label: s, data: [], backgroundColor: SEV_COLOR[s], stack: 'a', barThickness: 10, borderRadius: 2, borderSkipped: 'bottom' })) },
    options: { responsive: true, maintainAspectRatio: false, interaction: { mode: 'index', intersect: false },
      scales: { x: { stacked: true, grid: { display: false }, ticks: { maxTicksLimit: 12 }, border: { color: C.axis } }, y: { stacked: true, beginAtZero: true, grid: gridOpts, border: { display: false }, ticks: { precision: 0, maxTicksLimit: 4 } } } },
  });
  $('#alert-legend').innerHTML = SEV_ORDER.map((s) => `<span><i class="sw" style="background:${SEV_COLOR[s]}"></i>${s}</span>`).join('');
  charts.dns = new Chart($('#chart-dns'), {
    type: 'bar',
    data: { labels: [], datasets: [{ data: [], backgroundColor: C.s1, barThickness: 12, borderRadius: 4, borderSkipped: 'start' }] },
    options: { indexAxis: 'y', responsive: true, maintainAspectRatio: false,
      scales: { x: { beginAtZero: true, grid: gridOpts, border: { display: false }, ticks: { precision: 0, maxTicksLimit: 4 } }, y: { grid: { display: false }, border: { color: C.axis }, ticks: { color: C.text2, autoSkip: false } } },
      plugins: { tooltip: { callbacks: { label: (c) => ` ${c.parsed.x} queries` } } } },
  });
  charts.history = new Chart($('#chart-history'), {
    type: 'bar',
    data: { labels: [], datasets: [] },
    options: { responsive: true, maintainAspectRatio: false, interaction: { mode: 'index', intersect: false },
      scales: { x: { stacked: true, grid: { display: false }, ticks: { maxTicksLimit: 12, maxRotation: 0 }, border: { color: C.axis } }, y: { stacked: true, beginAtZero: true, suggestedMax: 1024, grid: gridOpts, border: { display: false }, afterBuildTicks: byteTicks, ticks: { callback: fmtBytes } } },
      plugins: { tooltip: { callbacks: { label: (c) => ` ${c.dataset.label}: ${fmtBytes(c.parsed.y)}` } } } },
  });
  charts.historyAlerts = new Chart($('#chart-history-alerts'), {
    type: 'bar',
    data: { labels: [], datasets: SEV_ORDER.map((s) => ({ label: s, data: [], backgroundColor: SEV_COLOR[s], stack: 'a', barThickness: 10, borderRadius: 2, borderSkipped: 'bottom' })) },
    options: { responsive: true, maintainAspectRatio: false, interaction: { mode: 'index', intersect: false },
      scales: { x: { stacked: true, grid: { display: false }, ticks: { maxTicksLimit: 12, maxRotation: 0 }, border: { color: C.axis } }, y: { stacked: true, beginAtZero: true, grid: gridOpts, border: { display: false }, ticks: { precision: 0, maxTicksLimit: 4 } } } },
  });
  $('#hist-alert-legend').innerHTML = $('#alert-legend').innerHTML;
}

function updateThroughput() {
  const ch = charts.throughput;
  ch.data.labels = S.series.map((s) => timeStr(s.ts));
  ch.data.datasets[0].data = S.series.map((s) => s.bytes_out);
  ch.data.datasets[1].data = S.series.map((s) => s.bytes_in);
  ch.update('none');
}
function updateTop() {
  const ch = charts.top, top = S.top.slice(0, 8);
  ch.data.labels = top.map((t) => t.name);
  ch.data.datasets[0].data = top.map((t) => t.bytes_out + t.bytes_in);
  ch.update('none');
}
function updateCountries(list) {
  const ch = charts.countries;
  ch.data.labels = list.map(([cc]) => `${flag(cc)} ${cc}`);
  ch.data.datasets[0].data = list.map(([, n]) => n);
  ch.update('none');
}

// ---------- overview: alerts feed & ticker ----------
function alertItem(a, full) {
  const procLabel = a.process ? `${esc(a.process)} (${a.pid})` : (a.pid ? `pid ${a.pid}` : 'system');
  return `<li class="sev-${a.severity}${a.acked ? ' acked' : ''}" data-id="${a.id}" data-pid="${a.pid}">
    <span class="sev-bar"></span>
    <div><div class="alert-title">${esc(a.title)}</div>
      ${full ? `<div class="alert-detail">${esc(a.detail)}</div>` : ''}
      <div class="alert-meta">${procLabel}${a.remote ? ' · ' + esc(a.remote) : ''} · <span class="rule">${esc(a.rule)}</span>${a.count > 1 ? ` · ×${a.count}` : ''}</div></div>
    <div class="alert-right"><span class="sev-label">${a.severity}</span><span>${timeStr(a.ts)}</span>${full ? `<span><button class="btn sm ai explain-btn" title="Ask the assistant about this alert">✦</button> ${!a.acked ? `<button class="btn sm ack-btn">ack</button>` : ''}</span>` : ''}</div>
  </li>`;
}
function renderOverviewAlerts() {
  const open = S.alerts.filter((a) => !a.acked).slice(0, 8);
  $('#ov-alerts').innerHTML = open.length ? open.map((a) => alertItem(a, false)).join('') : '<li class="empty">No open alerts</li>';
}
function renderTicker(conns) {
  const el = $('#ticker');
  const fresh = conns.filter((c) => !S.lastConnKeys.has(keyOf(c)));
  S.lastConnKeys = new Set(conns.map(keyOf));
  if (!fresh.length && el.children.length) return;
  for (const c of fresh.slice(0, 20)) {
    S.ticker.unshift(c);
  }
  S.ticker = S.ticker.slice(0, 14);
  el.innerHTML = S.ticker.map((c) => `<div><span class="t-time">${timeStr(c.first_seen)}</span><span class="t-proc">${esc(procName(c.pid))}</span><span class="${c.intel ? 't-intel' : ''}">${esc(c.hostname || c.remote_addr)}:${c.remote_port} ${flag(c.country)}</span><span>${c.proto.toUpperCase()}</span></div>`).join('');
}
const keyOf = (c) => `${c.pid}|${c.proto}|${c.local_port}|${c.remote_addr}|${c.remote_port}`;
const procNames = new Map();
function procName(pid) { return procNames.get(pid) || `pid ${pid}`; }
function procLabel(p) { return p.name ? (p.services?.length && /svchost/i.test(p.name) ? `${p.name} (${p.services.join(', ')})` : p.name) : `pid ${p.pid}`; }
function whereCell(c) {
  if (c.scope !== 'public') return `<span class="muted">${c.scope}</span>`;
  return `${flag(c.country)} ${esc([c.city, c.country].filter(Boolean).join(', '))}${c.owner ? ` <span class="owner">· ${esc(c.owner)}</span>` : ''}`;
}

// ---------- globe ----------
let globe = null, globeHost = null, worldFeatures = null, globeCountries = new Set(), globeIntelCountries = new Set();
let countryLabels = [], globeHoverPaused = false;
const geoObjects = new Map(); // ip -> stable object so globe.gl can diff instead of re-creating
async function initGlobe() {
  try {
    const world = await (await fetch('vendor/countries-110m.json')).json();
    // Antarctica contains the pole, which the h3 hex tiler cannot handle; it is also never a destination.
    worldFeatures = topojson.feature(world, world.objects.countries).features.filter((f) => f.properties?.name !== 'Antarctica');
    // Country name labels at centroids; tiny countries are skipped unless they carry traffic.
    countryLabels = worldFeatures.map((f) => { const [lon, lat] = d3.geoCentroid(f); return { kind: 'country', name: f.properties?.name || '', lat, lon, area: d3.geoArea(f) }; }).filter((c) => c.name);
  } catch (e) { console.warn('world map unavailable', e); worldFeatures = []; }
  const setRotate = () => { if (globe) globe.controls().autoRotate = $('#globe-rotate').checked && !globeHoverPaused; };
  const hoverPause = (obj) => { globeHoverPaused = !!obj; setRotate(); };
  globe = Globe({ animateIn: true })(document.createElement('div'))
    .backgroundColor('rgba(0,0,0,0)')
    .showAtmosphere(true).atmosphereColor('#3987e5').atmosphereAltitude(0.16)
    .hexPolygonsData(worldFeatures).hexPolygonResolution(3).hexPolygonMargin(0.4).hexPolygonUseDots(true)
    .hexPolygonColor((f) => { const n = f.properties?.name; return globeIntelCountries.has(n) ? 'rgba(208,59,59,0.85)' : globeCountries.has(n) ? 'rgba(57,135,229,0.85)' : 'rgba(110,115,125,0.45)'; })
    .hexPolygonLabel((f) => `<div class="globe-tip">${esc(f.properties?.name || '')}</div>`)
    .arcsData([]).arcStartLat('sLat').arcStartLng('sLon').arcEndLat('lat').arcEndLng('lon')
    .arcColor((d) => d.risk >= 60 ? [C.critical, C.critical] : d.risk >= 25 ? [C.serious, C.serious] : [C.s1, C.s3])
    .arcAltitudeAutoScale(0.4).arcStroke(0.45).arcDashLength(0.4).arcDashGap(0.25).arcDashAnimateTime((d) => d.risk >= 25 ? 900 : 1800)
    .pointsData([]).pointLat('lat').pointLng('lon').pointColor((d) => riskColor(d.risk)).pointAltitude((d) => 0.01 + Math.min(0.15, Math.log10(1 + d.bytes_in + d.bytes_out) / 60)).pointRadius(0.32)
    .pointLabel((d) => `<div class="globe-tip"><b>${esc(d.hostname || d.ip)}</b>${d.owner ? ` · ${esc(d.owner)}` : ''}<br>${esc(d.ip)} · ${esc([d.city, d.country_name].filter(Boolean).join(', '))}<br>${esc((d.procs || []).join(', '))}<br>↑ ${fmtBytes(d.bytes_out)} · ↓ ${fmtBytes(d.bytes_in)}${d.intel ? '<br><b style="color:' + C.critical + '">' + esc(d.intel) + '</b>' : ''}</div>`)
    .onPointClick((d) => { setView('connections'); $('#global-search').value = d.ip; refreshView(true); })
    .onPointHover(hoverPause).onHexPolygonHover(hoverPause).onArcHover(hoverPause).onLabelHover(hoverPause)
    .arcsTransitionDuration(0).pointsTransitionDuration(0).labelsTransitionDuration(0)
    .labelsData([]).labelLat('lat').labelLng('lon')
    .labelText((d) => d.kind === 'country' ? d.name : d.text)
    .labelSize((d) => d.kind === 'country' ? 0.55 : 0.8).labelDotRadius((d) => d.kind === 'country' ? 0 : 0.28)
    .labelColor((d) => d.kind === 'country' ? 'rgba(195,194,183,0.55)' : (d.risk >= 25 ? 'rgba(255,200,190,0.95)' : 'rgba(240,239,236,0.95)')).labelResolution(2).labelAltitude((d) => d.kind === 'country' ? 0.006 : 0.014)
    .labelLabel((d) => d.kind === 'country' ? `<div class="globe-tip">${esc(d.name)}</div>` : `<div class="globe-tip"><b>${esc(d.text)}</b><br>${esc(d.hosts.slice(0, 8).join('<br>'))}${d.hosts.length > 8 ? '<br>…' : ''}</div>`)
    .ringsData([]).ringLat('lat').ringLng('lon').ringColor(() => (t) => `rgba(57,135,229,${1 - t})`).ringMaxRadius(3.5).ringPropagationSpeed(1.2).ringRepeatPeriod(1400);
  const mat = globe.globeMaterial();
  mat.color.set('#10141a'); mat.emissive.set('#0a1424'); mat.emissiveIntensity = 0.25; mat.shininess = 4;
  globe.controls().autoRotate = true; globe.controls().autoRotateSpeed = 0.45; globe.controls().enableDamping = true;
  const style = document.createElement('style');
  style.textContent = '.globe-tip{background:#222221;border:1px solid rgba(255,255,255,.12);border-radius:6px;padding:6px 8px;font-size:12px;color:#f0efec;line-height:1.4}';
  document.head.appendChild(style);
  $('#globe-rotate').addEventListener('change', setRotate);
  // Pointer over the globe area pauses rotation so details can be read; leaving resumes it.
  const mount = globe.renderer().domElement;
  mount.addEventListener('pointerenter', () => { globeHoverPaused = true; setRotate(); });
  mount.addEventListener('pointerleave', () => { globeHoverPaused = false; setRotate(); });
  $('#globe-arcs').addEventListener('change', () => updateGlobe());
  $('#globe-labels').addEventListener('change', () => updateGlobe());
  new ResizeObserver(() => resizeGlobe()).observe($('#globe-host-overview'));
  new ResizeObserver(() => resizeGlobe()).observe($('#globe-host-full'));
  window.addEventListener('resize', resizeGlobe);
  mountGlobe($('#globe-host-overview'));
}
function mountGlobe(host) {
  if (!globe || globeHost === host) return;
  const el = globe.renderer().domElement.parentElement;
  el.classList.add('globe-mount');
  host.appendChild(el);
  globeHost = host;
  resizeGlobe();
  requestAnimationFrame(resizeGlobe);
}
function resizeGlobe() {
  if (!globe || !globeHost) return;
  const w = globeHost.clientWidth, h = globeHost.clientHeight;
  if (w > 0 && h > 0) globe.width(w).height(h);
}
function updateGlobe() {
  if (!globe) return;
  // Keep one object per IP across refreshes so the globe updates in place instead of flashing.
  const seen = new Set();
  for (const d of S.geo) {
    if (d.lat == null || d.lon == null) continue;
    seen.add(d.ip);
    const o = geoObjects.get(d.ip);
    if (o) Object.assign(o, d); else geoObjects.set(d.ip, { ...d });
  }
  for (const ip of [...geoObjects.keys()]) if (!seen.has(ip)) geoObjects.delete(ip);
  const dests = [...geoObjects.values()];
  globeCountries = new Set(); globeIntelCountries = new Set();
  const nameByCc = new Map();
  for (const d of dests) { if (d.country_name) { nameByCc.set(d.country, d.country_name); (d.intel ? globeIntelCountries : globeCountries).add(d.country_name); } }
  // world-atlas names differ for a few countries; cover the common ones
  const alias = { 'United States': 'United States of America', 'Czechia': 'Czechia', 'Russia': 'Russia', 'South Korea': 'South Korea', 'Viet Nam': 'Vietnam', 'Türkiye': 'Turkey', 'Iran, Islamic Republic of': 'Iran', 'Korea, Republic of': 'South Korea', 'Taiwan, Province of China': 'Taiwan', 'United Kingdom': 'United Kingdom' };
  for (const n of [...globeCountries]) if (alias[n]) globeCountries.add(alias[n]);
  for (const n of [...globeIntelCountries]) if (alias[n]) globeIntelCountries.add(alias[n]);
  globe.hexPolygonsData(worldFeatures);
  globe.pointsData(dests);
  const home = S.home && S.home.lat != null ? S.home : null;
  const arcsOn = $('#globe-arcs').checked && home;
  const now = Date.now();
  const active = dests.filter((d) => now - d.last_seen < 30000).sort((a, b) => (b.bytes_in + b.bytes_out) - (a.bytes_in + a.bytes_out)).slice(0, 150);
  globe.arcsData(arcsOn ? active.map((d) => ({ ...d, sLat: home.lat, sLon: home.lon })) : []);
  globe.ringsData(home ? [home] : []);
  const labelsOn = $('#globe-labels').checked;
  const activeCountries = new Set([...globeCountries, ...globeIntelCountries]);
  const countries = countryLabels.filter((c) => c.area > 0.002 || activeCountries.has(c.name));
  // One label per city instead of one per IP, so clusters stay readable.
  const cities = new Map();
  for (const d of active) {
    const key = `${d.city || ''}|${d.country || ''}|${d.lat.toFixed(1)}|${d.lon.toFixed(1)}`;
    const c = cities.get(key) || { kind: 'city', lat: d.lat, lon: d.lon, city: d.city, country: d.country, hosts: [], risk: 0, bytes: 0 };
    c.hosts.push(d.hostname || shortIp(d.ip)); c.risk = Math.max(c.risk, d.risk); c.bytes += d.bytes_in + d.bytes_out;
    cities.set(key, c);
  }
  const cityLabels = [...cities.values()].sort((a, b) => b.bytes - a.bytes).slice(0, 30).map((c) => ({ ...c, text: `${c.city || c.country || c.hosts[0]}${c.hosts.length > 1 ? ` · ${c.hosts.length}` : ''}` }));
  globe.labelsData(labelsOn ? [...countries, ...cityLabels] : countries);
  $('#globe-sub').textContent = `${dests.length} destinations · ${active.length} active`;
  $('#globe-home').textContent = home ? `home: ${home.label}` : 'home location unknown';
}
let globeFocused = false;
function focusHome() { if (globe && S.home && S.home.lat != null && !globeFocused) { globe.pointOfView({ lat: S.home.lat, lng: S.home.lon, altitude: 2.1 }, 1200); globeFocused = true; } }

function renderDestTable() {
  const rows = [...S.geo].sort((a, b) => (b.bytes_in + b.bytes_out) - (a.bytes_in + a.bytes_out)).slice(0, 300);
  $('#dest-count').textContent = `${S.geo.length} public hosts`;
  $('#dest-table tbody').innerHTML = rows.map((d) => `<tr class="clickable" data-ip="${esc(d.ip)}"><td title="${esc(d.ip)}">${d.intel ? '<span class="tag intel">intel</span>' : ''}${esc(d.hostname || d.ip)}</td><td>${flag(d.country)} ${esc([d.city, d.country].filter(Boolean).join(', '))}${d.owner ? ` <span class="owner">· ${esc(d.owner)}</span>` : ''}</td><td>${esc((d.procs || []).join(', '))}</td><td class="num">${fmtBytes(d.bytes_out)}</td><td class="num">${fmtBytes(d.bytes_in)}</td><td>${meter(d.risk)}</td></tr>`).join('') || '<tr><td colspan="6" class="empty">No public destinations yet</td></tr>';
  $$('#dest-table tr.clickable').forEach((tr) => tr.addEventListener('click', () => { setView('connections'); $('#global-search').value = tr.dataset.ip; refreshView(true); }));
}

// ---------- connections ----------
function renderConnections() {
  const q = $('#global-search').value.trim().toLowerCase();
  const proto = $('#f-proto').value, sort = $('#f-sort').value, pub = $('#f-public').checked;
  let rows = S.conns.filter((c) => (!pub || c.scope === 'public') && (!proto || c.proto === proto));
  if (q) rows = rows.filter((c) => [procName(c.pid), c.remote_addr, c.hostname, c.country_name, c.city, String(c.pid), String(c.remote_port)].some((v) => v && String(v).toLowerCase().includes(q)));
  rows.sort((a, b) => sort === 'first_seen' ? a.first_seen - b.first_seen : (b[sort] || 0) - (a[sort] || 0));
  $('#conn-count').textContent = `${rows.length} of ${S.conns.length}`;
  const now = Date.now();
  $('#conn-table tbody').innerHTML = rows.slice(0, 600).map((c) => `<tr class="clickable" data-pid="${c.pid}">
    <td>${esc(procName(c.pid))}</td><td class="muted">${c.pid}</td><td>${c.proto.toUpperCase()}</td>
    <td class="mono">${c.intel ? `<span class="tag intel" title="${esc(c.intel)}">intel</span>` : ''}${esc(c.remote_addr)}</td>
    <td title="${esc(c.hostname || '')}">${esc(c.hostname || '')}</td><td>${c.remote_port}</td>
    <td>${whereCell(c)}</td>
    <td class="muted">${esc(c.state)}</td><td class="num">${fmtBytes(c.bytes_out)}</td><td class="num">${fmtBytes(c.bytes_in)}</td>
    <td class="muted">${fmtAge(now - c.first_seen)}</td><td>${meter(c.risk)}</td>
    <td><button class="btn sm ai explain-conn" data-pid="${c.pid}" data-remote="${esc(c.remote_addr)}:${c.remote_port}" title="Ask the assistant">✦</button> <button class="btn sm block-ip" data-ip="${esc(c.remote_addr)}" title="Block this IP in Windows Firewall">block IP</button></td></tr>`).join('') || '<tr><td colspan="13" class="empty">No connections match</td></tr>';
  $$('#conn-table .explain-conn').forEach((b) => b.addEventListener('click', () => askAi({ kind: 'connection', pid: +b.dataset.pid, remote: b.dataset.remote, label: `${procName(+b.dataset.pid)} → ${b.dataset.remote}` })));
  $$('#conn-table tr.clickable').forEach((tr) => tr.addEventListener('click', (e) => { if (!e.target.closest('button')) openDrawer(+tr.dataset.pid); }));
  $$('#conn-table .block-ip').forEach((b) => b.addEventListener('click', () => blockIp(b.dataset.ip)));
}
['#f-proto', '#f-sort', '#f-public'].forEach((s) => $(s).addEventListener('change', renderConnections));
$('#global-search').addEventListener('input', () => { if (S.view === 'connections') renderConnections(); else if (S.view === 'processes') renderProcesses(); else if (S.view === 'dns') renderDns(); else if (S.view === 'alerts') renderAlerts(); else if (S.view === 'inventory') renderInventory(); });

// ---------- processes ----------
function renderProcesses() {
  const q = $('#global-search').value.trim().toLowerCase();
  const sort = $('#p-sort').value, aliveOnly = $('#p-alive').checked;
  let rows = S.procs.filter((p) => !aliveOnly || p.alive);
  if (q) rows = rows.filter((p) => [p.name, p.exe, String(p.pid), p.parent_name, p.user].some((v) => v && String(v).toLowerCase().includes(q)));
  const key = { total: (p) => p.bytes_in + p.bytes_out, risk: (p) => p.risk * 1e12 + p.bytes_out, rate: (p) => p.rate_in + p.rate_out, conns: (p) => p.conn_count };
  if (sort === 'name') rows.sort((a, b) => a.name.localeCompare(b.name)); else rows.sort((a, b) => key[sort](b) - key[sort](a));
  $('#proc-count').textContent = `${rows.length} processes`;
  $('#proc-table tbody').innerHTML = rows.map((p) => `<tr class="clickable" data-pid="${p.pid}">
    <td><b>${esc(p.name || 'pid ' + p.pid)}</b>${p.services?.length ? ` <span class="muted">${esc(p.services.join(', '))}</span>` : ''}${p.alive ? '' : ' <span class="tag">exited</span>'}<div class="muted mono" style="font-size:11px">${esc(p.exe)}</div></td>
    <td class="muted">${p.pid}</td><td>${sigTag(p.meta)}</td><td>${pathTags(p.path_flags)}</td>
    <td><canvas class="pspark" width="90" height="22" data-pid="${p.pid}"></canvas></td>
    <td class="num">${fmtBytes(p.bytes_out)}</td><td class="num">${fmtBytes(p.bytes_in)}</td><td class="num">${p.conn_count}</td><td class="num">${p.dns_count}</td>
    <td>${meter(p.risk)}</td>
    <td><button class="btn sm ai explain" data-pid="${p.pid}" title="Ask the assistant">✦</button> <button class="btn sm kill" data-pid="${p.pid}">kill</button> <button class="btn sm block" data-pid="${p.pid}">block</button></td></tr>`).join('') || '<tr><td colspan="11" class="empty">No processes</td></tr>';
  $$('#proc-table .explain').forEach((b) => b.addEventListener('click', () => { const p = S.procs.find((x) => x.pid === +b.dataset.pid); askAi({ kind: 'process', pid: +b.dataset.pid, label: p ? `${p.name} (${p.pid})` : '' }); }));
  const byPid = new Map(rows.map((p) => [p.pid, p]));
  $$('#proc-table .pspark').forEach((cv) => drawProcSpark(cv, byPid.get(+cv.dataset.pid)?.series));
  $$('#proc-table tr.clickable').forEach((tr) => tr.addEventListener('click', (e) => { if (!e.target.closest('button')) openDrawer(+tr.dataset.pid); }));
  $$('#proc-table .kill').forEach((b) => b.addEventListener('click', () => killPid(+b.dataset.pid)));
  $$('#proc-table .block').forEach((b) => b.addEventListener('click', () => blockPid(+b.dataset.pid)));
}
['#p-sort', '#p-alive'].forEach((s) => $(s).addEventListener('change', renderProcesses));

// ---------- alerts ----------
function renderAlerts() {
  const sev = $('#a-sev').value, un = $('#a-unacked').checked, q = $('#global-search').value.trim().toLowerCase();
  let rows = S.alerts.filter((a) => (!sev || a.severity === sev) && (!un || !a.acked));
  if (q) rows = rows.filter((a) => [a.title, a.detail, a.process, a.exe, a.remote, a.rule].some((v) => v && v.toLowerCase().includes(q)));
  $('#alert-count').textContent = `${rows.length} alerts`;
  $('#alert-list').innerHTML = rows.slice(0, 400).map((a) => alertItem(a, true)).join('') || '<li class="empty">No alerts</li>';
  $$('#alert-list .ack-btn').forEach((b) => b.addEventListener('click', async (e) => {
    const li = e.target.closest('li'); const id = +li.dataset.id;
    await post(`/api/alerts/${id}/ack`); const a = S.alerts.find((x) => x.id === id); if (a) a.acked = true; renderAlerts(); renderOverviewAlerts(); updateSeverityPills();
  }));
  $$('#alert-list li').forEach((li) => li.addEventListener('click', (e) => { if (!e.target.closest('button') && +li.dataset.pid) openDrawer(+li.dataset.pid); }));
  $$('#alert-list .explain-btn').forEach((b) => b.addEventListener('click', (e) => { const li = e.target.closest('li'); const a = S.alerts.find((x) => x.id === +li.dataset.id); askAi({ kind: 'alert', id: +li.dataset.id, label: a ? a.title : '#' + li.dataset.id }); }));
  // 24h histogram
  const now = Date.now(), start = now - 24 * 3600e3, buckets = 24;
  const labels = [], data = Object.fromEntries(SEV_ORDER.map((s) => [s, new Array(buckets).fill(0)]));
  for (let i = 0; i < buckets; i++) labels.push(timeStr(start + i * 3600e3).slice(0, 5));
  for (const a of S.alerts) { if (a.ts < start) continue; const b = Math.min(buckets - 1, Math.floor((a.ts - start) / 3600e3)); data[a.severity][b]++; }
  charts.alerts.data.labels = labels;
  charts.alerts.data.datasets.forEach((d) => { d.data = data[d.label]; });
  charts.alerts.update('none');
}
['#a-sev', '#a-unacked'].forEach((s) => $(s).addEventListener('change', renderAlerts));
$('#ack-all').addEventListener('click', async () => { await post('/api/alerts/ack-all'); S.alerts.forEach((a) => a.acked = true); renderAlerts(); renderOverviewAlerts(); updateSeverityPills(); setUnacked(0); });

// ---------- dns ----------
function renderDns() {
  const q = ($('#d-filter').value || $('#global-search').value).trim().toLowerCase();
  let rows = S.dns;
  if (q) rows = rows.filter((d) => d.query.toLowerCase().includes(q) || (d.process || '').toLowerCase().includes(q));
  $('#dns-count').textContent = `${rows.length} queries`;
  $('#dns-table tbody').innerHTML = rows.slice(0, 400).map((d) => `<tr><td class="muted">${timeStr(d.ts)}</td><td>${esc(d.process || 'pid ' + d.pid)}</td><td class="mono" title="${esc(d.query)}">${d.flags?.includes('intel') ? '<span class="tag intel">intel</span>' : ''}${esc(d.query)}</td><td>${QTYPE[d.qtype] || d.qtype}</td><td class="${d.status ? 'muted' : ''}">${QSTATUS[d.status] || d.status}</td><td class="mono muted" title="${esc(d.results.join(', '))}">${esc(d.results.slice(0, 3).join(', '))}${d.results.length > 3 ? ' …' : ''}</td></tr>`).join('') || '<tr><td colspan="6" class="empty">No DNS activity captured. Packet capture must be active.</td></tr>';
  const counts = new Map();
  for (const d of S.dns) { const base = d.query.split('.').slice(-2).join('.'); counts.set(base, (counts.get(base) || 0) + 1); }
  const top = [...counts].sort((a, b) => b[1] - a[1]).slice(0, 12);
  charts.dns.data.labels = top.map(([k]) => k); charts.dns.data.datasets[0].data = top.map(([, v]) => v); charts.dns.update('none');
}
$('#d-filter').addEventListener('input', renderDns);

// ---------- inventory ----------
const invOpen = new Set();
async function loadInventory(silent) {
  const inv = await api('/api/inventory');
  S.inventory = inv;
  const os = inv.os || {};
  $('#os-sub').textContent = os.caption ? `${os.caption} ${os.display_version || ''}` : 'not scanned yet';
  const age = os.patch_age_days;
  $('#os-kv').innerHTML = os.caption ? `<dt>Build</dt><dd>${esc(os.version)}.${esc(os.ubr)}</dd><dt>Last update installed</dt><dd>${os.last_hotfix ? dateTimeStr(os.last_hotfix).slice(0, 10) : 'unknown'}${age != null ? ` <span class="tag ${age > 45 ? 'flag' : 'ok'}">${age} days ago</span>` : ''}</dd><dt>Last boot</dt><dd>${os.last_boot ? dateTimeStr(os.last_boot) : '-'}</dd><dt>Exploited since update</dt><dd>${os.kev_since_patch?.length ? `<span class="tag kev">${os.kev_since_patch.length} Windows vulnerabilities</span>` : '<span class="tag ok">none catalogued</span>'}</dd>` : '<dd class="muted">Scanning…</dd>';
  $('#os-kev').innerHTML = (os.kev_since_patch || []).slice(0, 12).map((k) => `<li>• <a href="https://nvd.nist.gov/vuln/detail/${esc(k.cve_id)}" target="_blank" rel="noopener">${esc(k.cve_id)}</a> ${esc(k.product)}: ${esc(k.name)} <span class="muted">(added ${esc(k.date_added)}${k.ransomware ? ', ransomware' : ''})</span></li>`).join('');
  const items = inv.items || [];
  const kevItems = items.filter((i) => i.kev.length);
  const unpatched = items.filter((i) => i.kev.some((k) => k.likely_unpatched));
  const withCves = items.filter((i) => i.cves.length);
  $('#inv-kev-count').textContent = `${inv.kev_count.toLocaleString()} KEV entries loaded`;
  $('#inv-summary').innerHTML = `<dt>Items</dt><dd>${items.length} (${items.filter((i) => i.kind === 'app').length} apps, ${items.filter((i) => i.kind === 'service').length} services, ${items.filter((i) => i.kind === 'program').length} programs)</dd><dt>With exploited history</dt><dd>${kevItems.length}</dd><dt>Likely unpatched</dt><dd>${unpatched.length ? `<span class="tag kev">${unpatched.length}</span>` : '<span class="tag ok">0</span>'}</dd><dt>Online CVE check</dt><dd>${inv.online_last ? `${withCves.length} items with CVEs · checked ${dateTimeStr(inv.online_last)}` : (inv.online_enabled ? 'enabled, pending' : 'not run (opt-in)')}</dd><dt>Last scan</dt><dd>${inv.last_scan ? dateTimeStr(inv.last_scan) : '-'}</dd>`;
  $('#inv-progress').textContent = inv.online_running ? `looking up ${inv.online_progress}` : (inv.scanning ? 'scanning…' : '');
  $('#inv-online').disabled = inv.online_running;
  renderInventory();
}
function renderInventory() {
  const inv = S.inventory; if (!inv) return;
  const kind = $('#i-kind').value, flagged = $('#i-flagged').checked, q = $('#global-search').value.trim().toLowerCase();
  let rows = inv.items.filter((i) => (!kind || i.kind === kind) && (!flagged || i.kev.length || i.cves.length));
  if (q) rows = rows.filter((i) => [i.name, i.product, i.company, i.exe, i.version].some((v) => v && v.toLowerCase().includes(q)));
  $('#inv-count').textContent = `${rows.length} items`;
  $('#inv-table tbody').innerHTML = rows.slice(0, 800).map((i) => {
    const unp = i.kev.filter((k) => k.likely_unpatched).length;
    const kev = i.kev.length ? `<span class="tag ${unp ? 'kev' : 'kev-old'}">${i.kev.length} KEV${unp ? ` · ${unp} likely unpatched` : ' · updated since'}</span>` : '';
    const cve = i.cves.length ? `<span class="tag ${i.max_cvss >= 9 ? 'cvss-crit' : i.max_cvss >= 7 ? 'cvss-high' : ''}">${i.cves.length} CVE · max ${i.max_cvss.toFixed(1)}</span>` : (i.cve_checked ? `<span class="tag ok" title="${esc(i.cve_note)}">none found</span>` : '');
    const open = invOpen.has(i.id);
    const detail = open ? `<tr class="inv-detail"><td colspan="8">
        ${i.exe ? `<div class="mono muted">${esc(i.exe)}</div>` : ''}${i.services.length ? `<div class="muted">services: ${esc(i.services.join(', '))}</div>` : ''}${i.cpe ? `<div class="muted">CPE ${esc(i.cpe)} · ${esc(i.cve_note)}</div>` : (i.cve_note ? `<div class="muted">${esc(i.cve_note)}</div>` : '')}
        ${i.kev.length ? `<b>Known exploited vulnerabilities</b><ul>${i.kev.map((k) => `<li><a href="https://nvd.nist.gov/vuln/detail/${esc(k.cve_id)}" target="_blank" rel="noopener">${esc(k.cve_id)}</a> ${esc(k.vendor)} ${esc(k.product)}: ${esc(k.name)} <span class="muted">(catalogued ${esc(k.date_added)}${k.ransomware ? ', used by ransomware' : ''}${k.likely_unpatched ? ', file predates it' : ', file is newer'})</span></li>`).join('')}</ul>` : ''}
        ${i.cves.length ? `<b>Published CVEs for this version</b><ul>${i.cves.slice(0, 25).map((c) => `<li><a href="https://nvd.nist.gov/vuln/detail/${esc(c.cve_id)}" target="_blank" rel="noopener">${esc(c.cve_id)}</a> <span class="tag ${c.cvss >= 9 ? 'cvss-crit' : c.cvss >= 7 ? 'cvss-high' : ''}">CVSS ${c.cvss ?? '-'}</span>${c.kev ? '<span class="tag kev">exploited</span>' : ''} <span class="muted">${esc(c.published)}</span> ${esc(c.summary.slice(0, 220))}</li>`).join('')}${i.cves.length > 25 ? `<li class="muted">… ${i.cves.length - 25} more</li>` : ''}</ul>` : ''}
      </td></tr>` : '';
    return `<tr class="clickable inv-row" data-id="${esc(i.id)}"><td><b>${esc(i.name)}</b>${i.product && i.product !== i.name ? `<div class="muted">${esc(i.product)}</div>` : ''}</td><td class="mono">${esc(i.version || '-')}</td><td>${esc(i.company || '-')}</td><td class="muted">${esc(i.kind)}</td><td>${i.network_active ? '<span class="tag">online</span>' : ''}${i.pids.length ? `<span class="muted">${i.pids.length} proc</span>` : ''}</td><td>${kev}</td><td>${cve}</td><td class="muted">${i.file_mtime ? dateTimeStr(i.file_mtime).slice(0, 10) : '-'}</td></tr>${detail}`;
  }).join('') || '<tr><td colspan="8" class="empty">Inventory not collected yet</td></tr>';
  $$('#inv-table .inv-row').forEach((tr) => tr.addEventListener('click', () => { const id = tr.dataset.id; invOpen.has(id) ? invOpen.delete(id) : invOpen.add(id); renderInventory(); }));
}
['#i-kind', '#i-flagged'].forEach((s) => $(s).addEventListener('change', renderInventory));
$('#inv-rescan').addEventListener('click', async () => { await post('/api/inventory/scan'); toast('Inventory scan started', 'results appear in a few seconds', 'sev-ok'); setTimeout(() => loadInventory(), 6000); });
$('#inv-online').addEventListener('click', async () => {
  if (!confirm('This sends the product names and version numbers of your installed software to cvedb.shodan.io to look up published CVEs. Continue?')) return;
  const r = await post('/api/inventory/cve-lookup');
  toast(r.ok ? 'Online CVE lookup started' : 'Not started', r.ok ? 'progress shows above the table' : r.error, r.ok ? 'sev-ok' : 'sev-high');
});

// ---------- assistant ----------
const chat = { history: [], busy: false };
function chatAdd(role, text, meta, cls = '') {
  const log = $('#chat-log');
  if (log.querySelector('.empty')) log.innerHTML = '';
  const el = document.createElement('div');
  el.className = `msg ${role} ${cls}`;
  el.textContent = text;
  if (meta) { const m = document.createElement('div'); m.className = 'meta'; m.textContent = meta; el.appendChild(m); }
  log.appendChild(el);
  log.scrollTop = log.scrollHeight;
  return el;
}
function aiSel() { const v = $('#ai-provider').value; if (!v) return {}; const i = v.indexOf(':'); return { provider: v.slice(0, i), model: v.slice(i + 1) }; }
async function aiStatus() {
  try {
    const sel = aiSel();
    const st = await api('/api/ai/status' + (sel.provider ? `?provider=${encodeURIComponent(sel.provider)}&model=${encodeURIComponent(sel.model)}` : ''));
    const dd = $('#ai-provider'), cur = dd.value;
    dd.innerHTML = `<option value="">Default · ${esc(st.configured)}</option>` + (st.choices || []).map((c) => `<option value="${esc(c.id)}">${esc(c.label)}</option>`).join('');
    if ([...dd.options].some((o) => o.value === cur)) dd.value = cur;
    $('#ai-status').textContent = st.ready ? `${st.provider} · ${st.model}${st.local ? ' · offline' : ' · online'}` : 'not available';
    $('#ai-status').title = st.note;
    return st;
  } catch { return null; }
}
$('#ai-provider').addEventListener('change', () => { localStorage.setItem('nm-ai-choice', $('#ai-provider').value); aiStatus(); });
try { const saved = localStorage.getItem('nm-ai-choice'); if (saved) { $('#ai-provider').innerHTML += `<option value="${saved}">${saved}</option>`; $('#ai-provider').value = saved; } } catch {}
async function askAi({ kind = 'none', pid, id, remote, question = '', label = '' }) {
  if (chat.busy) return;
  setView('assistant');
  const shown = question || ({ process: `Explain ${label || 'this process'}`, alert: `Explain alert: ${label}`, connection: `Explain connection ${label}`, overview: 'Summarise my network' }[kind] || question);
  chatAdd('user', shown);
  const pending = chatAdd('ai', 'Thinking…', '', 'thinking');
  chat.busy = true; $('#chat-send').disabled = true;
  try {
    const sel = aiSel();
    const body = { kind, pid, id, remote, question, history: chat.history.slice(-8), provider: sel.provider, model: sel.model };
    const r = await post('/api/ai/ask', body);
    pending.remove();
    if (r.ok) {
      chatAdd('ai', r.answer, `${r.provider} · ${r.model}${r.local ? ' · nothing left this PC' : ' · sent to the model service'}`);
      chat.history.push({ role: 'user', content: shown }, { role: 'assistant', content: r.answer });
    } else {
      chatAdd('ai', r.error || 'No answer', '', 'err');
    }
  } catch (e) { pending.remove(); chatAdd('ai', 'Request failed: ' + e.message, '', 'err'); }
  finally { chat.busy = false; $('#chat-send').disabled = false; }
}
$('#chat-form').addEventListener('submit', (e) => { e.preventDefault(); const q = $('#chat-input').value.trim(); if (!q) return; $('#chat-input').value = ''; askAi({ kind: 'none', question: q }); });
$('#ai-summary').addEventListener('click', () => askAi({ kind: 'overview' }));
$('#ai-clear').addEventListener('click', () => { chat.history = []; $('#chat-log').innerHTML = '<div class="empty">Chat cleared.</div>'; });
$('#dr-explain').addEventListener('click', () => { const p = S.procs.find((x) => x.pid === S.drawerPid); closeDrawer(); askAi({ kind: 'process', pid: S.drawerPid ?? p?.pid, label: p ? `${p.name} (${p.pid})` : '' }); });

// ---------- sortable tables (click a header; numbers, bytes and ages sort numerically) ----------
const sortState = {};
function parseCell(td) {
  const t = td.textContent.trim();
  if (!t) return { n: -Infinity, s: '' };
  let m = t.match(/^(-?[\d.,]+)\s*(B|KB|MB|GB|TB)(\/s)?$/i);
  if (m) return { n: parseFloat(m[1].replace(/,/g, '')) * (1024 ** ['B', 'KB', 'MB', 'GB', 'TB'].indexOf(m[2].toUpperCase())), s: t };
  m = t.match(/^(\d+)d(?:\s*(\d+)h)?$/); if (m) return { n: (+m[1]) * 86400 + (+m[2] || 0) * 3600, s: t };
  m = t.match(/^(\d+)h(?:\s*(\d+)m)?$/); if (m) return { n: (+m[1]) * 3600 + (+m[2] || 0) * 60, s: t };
  m = t.match(/^(\d+)m$/); if (m) return { n: +m[1] * 60, s: t };
  m = t.match(/^(\d+)s$/); if (m) return { n: +m[1], s: t };
  const meterVal = td.querySelector('.meter small'); if (meterVal) return { n: +meterVal.textContent, s: t };
  if (/^-?\d+(\.\d+)?$/.test(t.replace(/,/g, ''))) return { n: parseFloat(t.replace(/,/g, '')), s: t };
  return { n: NaN, s: t.toLowerCase() };
}
function applySort(table) {
  const st = sortState[table.id]; if (!st) return;
  const tbody = table.tBodies[0]; if (!tbody) return;
  const rows = Array.from(tbody.rows).filter((r) => !r.classList.contains('inv-detail') && !r.querySelector('.empty'));
  const details = new Map(); Array.from(tbody.rows).forEach((r, i) => { if (r.classList.contains('inv-detail')) details.set(tbody.rows[i - 1], r); });
  rows.sort((a, b) => {
    const A = parseCell(a.cells[st.col]), B = parseCell(b.cells[st.col]);
    let c = (!isNaN(A.n) && !isNaN(B.n)) ? A.n - B.n : A.s.localeCompare(B.s);
    return st.dir === 'asc' ? c : -c;
  });
  rows.forEach((r) => { tbody.appendChild(r); const d = details.get(r); if (d) tbody.appendChild(d); });
  Array.from(table.tHead.rows[0].cells).forEach((th, i) => { th.classList.toggle('sorted-asc', i === st.col && st.dir === 'asc'); th.classList.toggle('sorted-desc', i === st.col && st.dir === 'desc'); });
}
function initSortableTables() {
  $$('table.tbl').forEach((table) => {
    if (!table.id || !table.tHead) return;
    Array.from(table.tHead.rows[0].cells).forEach((th, i) => {
      if (!th.textContent.trim()) return;
      th.classList.add('sortable');
      th.addEventListener('click', () => {
        const st = sortState[table.id];
        sortState[table.id] = { col: i, dir: st && st.col === i && st.dir === 'desc' ? 'asc' : 'desc' };
        applySort(table);
      });
    });
  });
  // Re-apply after every re-render.
  new MutationObserver((muts) => { for (const m of muts) { const t = m.target.closest?.('table.tbl'); if (t && sortState[t.id] && m.type === 'childList' && m.target.tagName === 'TBODY') { queueMicrotask(() => { if (!t.dataset.sorting) { t.dataset.sorting = '1'; applySort(t); delete t.dataset.sorting; } }); } } }).observe(document.body, { childList: true, subtree: true });
}

// ---------- history ----------
$$('#h-range button').forEach((b) => b.addEventListener('click', () => { $$('#h-range button').forEach((x) => x.classList.remove('active')); b.classList.add('active'); S.histHours = +b.dataset.h; loadHistory(); }));
async function loadHistory() {
  const h = S.histHours;
  const [traffic, alerts, conns] = await Promise.all([api(`/api/history/traffic?hours=${h}`), api(`/api/history/alerts?hours=${h}`), api(`/api/history/connections?hours=${h}&limit=500`)]);
  const bucket = traffic.bucket_ms, now = Date.now(), start = Math.floor((now - h * 3600e3) / bucket) * bucket;
  const n = Math.ceil((now - start) / bucket) + 1;
  const labels = []; for (let i = 0; i < n; i++) { const t = start + i * bucket; labels.push(h <= 48 ? timeStr(t).slice(0, 5) : dateTimeStr(t).slice(5, 13)); }
  const totals = new Map();
  for (const r of traffic.rows) totals.set(r.name || r.exe, (totals.get(r.name || r.exe) || 0) + r.bytes_in + r.bytes_out);
  const topNames = [...totals].sort((a, b) => b[1] - a[1]).slice(0, 7).map(([k]) => k);
  const series = new Map(topNames.map((k) => [k, new Array(n).fill(0)])); series.set('Other', new Array(n).fill(0));
  for (const r of traffic.rows) { const i = Math.min(n - 1, Math.max(0, Math.floor((r.ts - start) / bucket))); const k = topNames.includes(r.name || r.exe) ? (r.name || r.exe) : 'Other'; series.get(k)[i] += r.bytes_in + r.bytes_out; }
  charts.history.data.labels = labels;
  charts.history.data.datasets = [...series].filter(([k, v]) => k !== 'Other' || v.some(Boolean)).map(([k, v]) => ({ label: k, data: v, backgroundColor: k === 'Other' ? C.muted : entityColor(k), stack: 'a', barThickness: 'flex', maxBarThickness: 24, borderRadius: 2, borderSkipped: 'bottom' }));
  charts.history.update('none');
  $('#hist-legend').innerHTML = charts.history.data.datasets.map((d) => `<span><i class="sw" style="background:${d.backgroundColor}"></i>${esc(d.label)}</span>`).join('');
  const ab = h <= 48 ? 3600e3 : 24 * 3600e3, astart = Math.floor((now - h * 3600e3) / ab) * ab, an = Math.ceil((now - astart) / ab) + 1;
  const alabels = []; for (let i = 0; i < an; i++) { const t = astart + i * ab; alabels.push(h <= 48 ? timeStr(t).slice(0, 5) : dateTimeStr(t).slice(5, 10)); }
  const ad = Object.fromEntries(SEV_ORDER.map((s) => [s, new Array(an).fill(0)]));
  for (const a of alerts) { const i = Math.min(an - 1, Math.max(0, Math.floor((a.ts - astart) / ab))); ad[a.severity][i]++; }
  charts.historyAlerts.data.labels = alabels; charts.historyAlerts.data.datasets.forEach((d) => { d.data = ad[d.label]; }); charts.historyAlerts.update('none');
  $('#hist-conn-count').textContent = `${conns.length} shown`;
  $('#hist-conn-table tbody').innerHTML = conns.map((c) => `<tr><td class="muted">${dateTimeStr(c.ts_start)}</td><td>${fmtAge(c.ts_end - c.ts_start)}</td><td>${esc(c.name || 'pid ' + c.pid)}</td><td class="mono">${c.intel ? '<span class="tag intel">intel</span>' : ''}${esc(c.raddr)}:${c.rport}</td><td>${esc(c.hostname || '')}</td><td>${flag(c.country)} ${esc(c.country || '')}</td><td class="num">${fmtBytes(c.bytes_out)}</td><td class="num">${fmtBytes(c.bytes_in)}</td><td class="muted">${esc(c.flags)}</td></tr>`).join('') || '<tr><td colspan="9" class="empty">No closed connections recorded yet</td></tr>';
}

// ---------- settings ----------
async function loadSettings() {
  const [intel, cfg, blocks, ov, trusted] = await Promise.all([api('/api/intel'), api('/api/config'), api('/api/blocks'), api('/api/overview'), api('/api/trusted')]);
  $('#trust-table tbody').innerHTML = trusted.map((t) => `<tr><td class="mono">${esc(t.exe)}</td><td class="mono muted">${esc((t.sha256 || '').slice(0, 16))}…</td><td><button class="btn sm untrust" data-exe="${esc(t.exe)}">revoke</button></td></tr>`).join('') || '<tr><td colspan="3" class="empty">No trusted programs</td></tr>';
  $$('#trust-table .untrust').forEach((b) => b.addEventListener('click', async () => { await post('/api/action/untrust', { exe: b.dataset.exe }); loadSettings(); }));
  S.intel = intel; S.config = cfg;
  $('#update-panel').hidden = !intel.update?.update_required;
  $('#update-reasons').innerHTML = (intel.update?.reasons || []).map((r) => `<li>• ${esc(r)}</li>`).join('');
  $('#intel-summary').innerHTML = `<dt>Malicious IPs</dt><dd>${intel.ips.toLocaleString()} addresses + ${intel.cidrs.toLocaleString()} ranges</dd><dt>Malicious domains</dt><dd>${intel.domains.toLocaleString()}</dd><dt>Last refresh</dt><dd>${intel.last_refresh ? dateTimeStr(intel.last_refresh) : '-'}</dd><dt>Next refresh</dt><dd>${intel.next_refresh ? dateTimeStr(intel.next_refresh) : '-'}</dd><dt>Manifest</dt><dd>${cfg.intel.manifest_url || '<span class="muted">none configured (feeds.json in data/feeds is still read)</span>'}</dd>`;
  $('#feed-table tbody').innerHTML = intel.feeds.map((f) => `<tr><td title="${esc(f.url)}">${esc(f.name)}</td><td class="mono">${esc(f.kind)}</td><td class="muted">${esc(f.source)}</td><td class="num">${f.entries.toLocaleString()}</td><td class="muted">${f.updated ? dateTimeStr(f.updated) : '-'}</td><td>${f.error ? `<span class="tag flag" title="${esc(f.error)}">${esc(f.error)}</span>` : '<span class="tag sig-valid">ok</span>'}</td></tr>`).join('');
  $('#block-table tbody').innerHTML = blocks.map((b) => `<tr><td>${esc(b.kind)}</td><td class="mono">${esc(b.target)}</td><td class="muted">${dateTimeStr(b.ts)}</td><td><button class="btn sm unblock" data-rule="${esc(b.rule)}">remove</button></td></tr>`).join('') || '<tr><td colspan="4" class="empty">No blocks</td></tr>';
  $$('#block-table .unblock').forEach((b) => b.addEventListener('click', async () => { const r = await post('/api/action/unblock', { rule: b.dataset.rule }); toast(r.ok ? 'Rule removed' : 'Failed', r.ok ? b.dataset.rule : r.error, r.ok ? 'sev-ok' : 'sev-high'); loadSettings(); }));
  $('#capture-status').innerHTML = `<dt>Administrator</dt><dd>${ov.is_admin ? 'yes' : 'no - restart as administrator for full visibility'}</dd><dt>ETW capture</dt><dd>${ov.etw_active ? `active, ${ov.etw_events.toLocaleString()} events` : esc(ov.etw_error || 'inactive')}</dd><dt>GeoIP database</dt><dd>${ov.geo_available ? 'loaded' : 'missing'}</dd><dt>Home location</dt><dd>${S.home?.label || 'unknown'}</dd><dt>Started</dt><dd>${dateTimeStr(ov.started)}</dd><dt>Project folder</dt><dd class="mono">${esc(cfg.root)}</dd>`;
  $('#config-dump').textContent = JSON.stringify(cfg, null, 2);
  $('#hosts-issues').innerHTML = (intel.hosts_issues || []).map((h) => `<li>⚠ ${esc(h)}</li>`).join('') || '<li>No suspicious entries in the hosts file.</li>';
}
$('#intel-refresh').addEventListener('click', async () => { $('#intel-refresh').textContent = 'Refreshing…'; try { await post('/api/intel/refresh'); } finally { $('#intel-refresh').textContent = 'Refresh now'; loadSettings(); } });
$('#block-ip-btn').addEventListener('click', () => blockIp($('#block-ip-input').value.trim()));

// ---------- actions ----------
async function killPid(pid) {
  const p = S.procs.find((x) => x.pid === pid);
  if (!confirm(`Terminate ${p?.name || 'pid ' + pid} (${pid})?`)) return;
  const r = await post('/api/action/kill', { pid });
  toast(r.ok ? 'Process terminated' : 'Could not terminate', r.ok ? r.message : r.error, r.ok ? 'sev-ok' : 'sev-high');
  refreshView(true);
}
async function blockPid(pid) {
  const p = S.procs.find((x) => x.pid === pid);
  if (!p?.exe) return toast('No executable path known for this process', '', 'sev-high');
  if (!confirm(`Block ${p.exe} in Windows Firewall (in and out)?`)) return;
  const r = await post('/api/action/block-exe', { pid, exe: p.exe });
  toast(r.ok ? 'Firewall rule added' : 'Could not add rule', r.ok ? r.message : r.error, r.ok ? 'sev-ok' : 'sev-high');
}
async function blockIp(ip) {
  if (!ip) return;
  if (!confirm(`Block all traffic to and from ${ip}?`)) return;
  const r = await post('/api/action/block-ip', { ip });
  toast(r.ok ? 'Firewall rule added' : 'Could not add rule', r.ok ? r.message : r.error, r.ok ? 'sev-ok' : 'sev-high');
  if (S.view === 'settings') loadSettings();
}

// ---------- drawer ----------
async function openDrawer(pid) {
  if (!pid && pid !== 0) return;
  S.drawerPid = pid;
  $('#drawer').hidden = false; $('#drawer-backdrop').hidden = false;
  await renderDrawer();
}
async function renderDrawer() {
  let p;
  try { p = await api(`/api/process/${S.drawerPid}`); } catch { $('#dr-body').innerHTML = '<p class="empty">Process no longer tracked.</p>'; return; }
  $('#dr-title').innerHTML = `${esc(p.name || 'pid ' + p.pid)} <span class="muted">· ${p.pid}</span> ${sigTag(p.meta)}${p.services?.length ? `<div class="muted" style="font-size:12px;font-weight:400">hosts: ${esc(p.services.join(', '))}</div>` : ''}`;
  $('#dr-exe').textContent = p.exe || '';
  $('#dr-kill').disabled = !p.alive; $('#dr-block').disabled = !p.exe;
  $('#dr-trust').disabled = !p.exe || !p.meta?.sha256;
  $('#dr-trust').textContent = p.trusted ? 'Trusted ✓ (click to revoke)' : 'Trust this program';
  $('#dr-trust').dataset.trusted = p.trusted ? '1' : '';
  const now = Date.now();
  const conns = p.conns.sort((a, b) => (b.bytes_in + b.bytes_out) - (a.bytes_in + a.bytes_out));
  $('#dr-body').innerHTML = `
    <h3>Risk</h3><div>${meter(p.risk)} <span class="muted">${p.alert_count} alerts raised</span></div>
    <h3>Details</h3><dl class="kv">
      <dt>Parent</dt><dd>${esc(p.parent_name || '-')} (${p.parent_pid})</dd>
      <dt>User</dt><dd>${esc(p.user || '-')}</dd>
      <dt>Started</dt><dd>${p.start_time ? dateTimeStr(p.start_time) : '-'}</dd>
      <dt>Command line</dt><dd class="mono">${esc(p.cmdline || '-')}</dd>
      <dt>Signer</dt><dd>${esc(p.meta?.signer || '-')}</dd>
      <dt>SHA-256</dt><dd class="mono">${esc(p.meta?.sha256 || '-')}${p.meta?.sha256 ? ` <a href="https://www.virustotal.com/gui/file/${p.meta.sha256}" target="_blank" rel="noopener">VirusTotal ↗</a>` : ''}</dd>
      <dt>Location flags</dt><dd>${pathTags(p.path_flags) || '<span class="muted">normal</span>'}</dd>
      <dt>Traffic</dt><dd>↑ ${fmtBytes(p.bytes_out)} · ↓ ${fmtBytes(p.bytes_in)} · now ${fmtRate(p.rate_out)} / ${fmtRate(p.rate_in)}</dd>
      <dt>Network</dt><dd>${p.conn_count} connections (${p.public_conn_count} public), ${p.listen_count} listeners, ${p.dns_count} DNS queries</dd>
    </dl>
    ${p.listeners.length ? `<h3>Listening</h3><div>${p.listeners.map((l) => `<span class="tag">${l.proto.toUpperCase()} ${esc(l.addr)}:${l.port}</span>`).join('')}</div>` : ''}
    <h3>Alerts</h3><ul class="alert-list">${p.alerts.map((a) => alertItem(a, true)).join('') || '<li class="empty">None</li>'}</ul>
    <h3>Connections (${conns.length})</h3>
    <div class="table-wrap"><table class="tbl"><thead><tr><th>Remote</th><th>Port</th><th>Where</th><th class="num">Out</th><th class="num">In</th><th>Age</th></tr></thead><tbody>
      ${conns.slice(0, 100).map((c) => `<tr><td class="mono">${c.intel ? '<span class="tag intel">intel</span>' : ''}${esc(c.hostname || c.remote_addr)}</td><td>${c.remote_port}/${c.proto}</td><td>${whereCell(c)}</td><td class="num">${fmtBytes(c.bytes_out)}</td><td class="num">${fmtBytes(c.bytes_in)}</td><td class="muted">${fmtAge(now - c.first_seen)}</td></tr>`).join('') || '<tr><td colspan="6" class="empty">none</td></tr>'}
    </tbody></table></div>
    <h3>DNS (${p.dns.length})</h3>
    <div class="table-wrap"><table class="tbl"><thead><tr><th>Time</th><th>Query</th><th>Type</th><th>Answers</th></tr></thead><tbody>
      ${p.dns.slice(0, 60).map((d) => `<tr><td class="muted">${timeStr(d.ts)}</td><td class="mono">${esc(d.query)}</td><td>${QTYPE[d.qtype] || d.qtype}</td><td class="mono muted">${esc(d.results.slice(0, 2).join(', '))}</td></tr>`).join('') || '<tr><td colspan="4" class="empty">none captured</td></tr>'}
    </tbody></table></div>
    ${p.beacons.some((b) => b.times.length > 3) ? `<h3>Repeated contacts</h3><dl class="kv">${p.beacons.filter((b) => b.times.length > 3).map((b) => { const iv = b.times.slice(1).map((t, i) => (t - b.times[i]) / 1000); const mean = iv.reduce((a, c) => a + c, 0) / iv.length; return `<dt class="mono">${esc(b.ip)}</dt><dd>${b.times.length} connections, every ${mean.toFixed(0)} s on average</dd>`; }).join('')}</dl>` : ''}`;
  $$('#dr-body .ack-btn').forEach((b) => b.addEventListener('click', async (e) => { const id = +e.target.closest('li').dataset.id; await post(`/api/alerts/${id}/ack`); const a = S.alerts.find((x) => x.id === id); if (a) a.acked = true; renderDrawer(); renderOverviewAlerts(); }));
}
function closeDrawer() { $('#drawer').hidden = true; $('#drawer-backdrop').hidden = true; S.drawerPid = null; }
$('#dr-close').addEventListener('click', closeDrawer);
$('#drawer-backdrop').addEventListener('click', closeDrawer);
document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeDrawer(); });
$('#dr-kill').addEventListener('click', () => killPid(S.drawerPid));
$('#dr-block').addEventListener('click', () => blockPid(S.drawerPid));
$('#dr-trust').addEventListener('click', async () => {
  const p = S.procs.find((x) => x.pid === S.drawerPid) || { exe: $('#dr-exe').textContent };
  const revoke = $('#dr-trust').dataset.trusted === '1';
  const r = await post(revoke ? '/api/action/untrust' : '/api/action/trust', { pid: S.drawerPid, exe: p.exe });
  toast(r.ok ? (revoke ? 'Trust revoked' : 'Program trusted') : 'Not changed', r.ok ? r.message : r.error, r.ok ? 'sev-ok' : 'sev-high');
  renderDrawer();
});

// ---------- refresh loop ----------
let refreshing = false;
async function refreshView(force) {
  if (refreshing && !force) return;
  refreshing = true;
  try {
    const v = S.view;
    if (v === 'overview' || v === 'globe' || v === 'connections') {
      const [procs, conns] = await Promise.all([api('/api/processes'), api('/api/connections')]);
      S.procs = procs; S.conns = conns;
      procs.forEach((p) => { if (p.name) procNames.set(p.pid, procLabel(p)); });
    }
    if (v === 'overview') {
      const [ov, geo] = await Promise.all([api('/api/overview'), api('/api/geo')]);
      S.geo = geo; applyOverview(ov); renderTicker(S.conns); updateGlobe(); focusHome();
      if (!S.alerts.length) { S.alerts = await api('/api/alerts?limit=300'); }
      renderOverviewAlerts(); updateThroughput(); updateTop();
    } else if (v === 'globe') {
      S.geo = await api('/api/geo'); updateGlobe(); focusHome(); renderDestTable();
    } else if (v === 'connections') renderConnections();
    else if (v === 'processes') { S.procs = await api('/api/processes'); S.procs.forEach((p) => { if (p.name) procNames.set(p.pid, procLabel(p)); }); renderProcesses(); }
    else if (v === 'alerts') { S.alerts = await api('/api/alerts?limit=500'); renderAlerts(); }
    else if (v === 'dns') { S.dns = await api('/api/dns?limit=400'); renderDns(); }
    else if (v === 'history') { if (force) await loadHistory(); }
    else if (v === 'inventory') { if (force || S.inventory?.online_running || S.inventory?.scanning || !S.inventory?.last_scan) await loadInventory(); }
    else if (v === 'assistant') { if (force) await aiStatus(); }
    else if (v === 'settings') { if (force) await loadSettings(); }
    if (S.drawerPid != null && !force) renderDrawer();
  } catch (e) { console.warn('refresh failed', e); }
  finally { refreshing = false; }
}

// ---------- boot ----------
(async function boot() {
  initCharts();
  initSortableTables();
  connectWs();
  try { S.series = await api('/api/series'); } catch {}
  try { S.alerts = await api('/api/alerts?limit=300'); } catch {}
  try { S.home = await api('/api/home'); } catch {}
  await initGlobe();
  await refreshView(true);
  setInterval(() => refreshView(false), 2500);
  setInterval(async () => { if (!S.home || S.home.lat == null) { try { S.home = await api('/api/home'); } catch {} } }, 10000);
})();
})();
