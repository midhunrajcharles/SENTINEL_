/**
 * SENTINEL War Room — Agent Visualization
 * agent_visualization.js
 *
 * Renders three "at a glance" components for the War Room dashboard:
 *
 *   1. Threat gauge      — radial dial summarizing the global composite
 *                          threat level (max risk_score across active cases)
 *   2. Agent network      — orchestrator hub + Vanguard/Sherlock/Executor/Sage
 *                          nodes, with animated links when an agent is
 *                          actively processing a case (red when CRITICAL)
 *   3. MCP tool call log  — rolling feed of index=sentinel_audit
 *                          event_type=mcp_call events
 *
 * Also wires the global Emergency Halt control, which sets every
 * non-terminal case in active_cases to HALTED in one action.
 *
 * No emojis — all status indicators are CSS dots / SVG shapes / text labels.
 *
 * Data flow:
 *   war_room.js calls AgentVisualization.update(agentRows, cases) every
 *   POLL_INTERVAL alongside its own rendering.
 *
 * Simple XML note:
 *   Replace the self-contained fetch helpers below with SplunkJS SDK
 *   search primitives if converting to Simple XML.
 */

'use strict';

const AV_AGENTS = ['vanguard', 'sherlock', 'executor', 'sage'];

const AV_CFG = {
  SPLUNK_BASE:  '',
  SEARCH_PATH:  '/en-US/splunkd/services/search/jobs/export',
  KVSTORE_PATH: '/en-US/splunkd/servicesNS/nobody/sentinel/storage/collections/data/',
  SESSION_KEY:  window.SPLUNK_SESSION_KEY || '',
  MCP_POLL_MS:  15_000,
  MCP_LIMIT:    20,
};

/* =========================================================================
   Lightweight REST helpers (mirrors war_room.js, kept independent so this
   module can be dropped onto any SENTINEL page on its own)
   ========================================================================= */

async function avSplunkSearch(spl, earliest = '-15m', latest = 'now', count = '50') {
  const body = new URLSearchParams({
    search: `search ${spl}`,
    earliest_time: earliest,
    latest_time: latest,
    output_mode: 'json',
    count,
  });
  const r = await fetch(`${AV_CFG.SPLUNK_BASE}${AV_CFG.SEARCH_PATH}`, {
    method: 'POST',
    headers: {
      'Authorization': `Splunk ${AV_CFG.SESSION_KEY}`,
      'X-Requested-With': 'XMLHttpRequest',
    },
    body,
  });
  if (!r.ok) return [];
  const text = await r.text();
  return text.trim().split('\n')
    .map(line => { try { return JSON.parse(line).result; } catch { return null; } })
    .filter(Boolean);
}

async function avKvFetch(collection) {
  const url = `${AV_CFG.SPLUNK_BASE}${AV_CFG.KVSTORE_PATH}${collection}`;
  const r = await fetch(url, {
    headers: {
      'Authorization': `Splunk ${AV_CFG.SESSION_KEY}`,
      'X-Requested-With': 'XMLHttpRequest',
    },
  });
  if (!r.ok) throw new Error(`KV Store ${collection}: HTTP ${r.status}`);
  return r.json();
}

async function avKvPost(collection, key, payload) {
  const url = `${AV_CFG.SPLUNK_BASE}${AV_CFG.KVSTORE_PATH}${collection}/${encodeURIComponent(key)}`;
  const r = await fetch(url, {
    method: 'POST',
    headers: {
      'Authorization': `Splunk ${AV_CFG.SESSION_KEY}`,
      'Content-Type': 'application/json',
      'X-Requested-With': 'XMLHttpRequest',
    },
    body: JSON.stringify(payload),
  });
  if (!r.ok) throw new Error(`KV POST ${collection}/${key}: HTTP ${r.status}`);
  return r.json();
}

/* =========================================================================
   Threat gauge
   ========================================================================= */

const TG_RADIUS = 60;
const TG_CIRCUMFERENCE = 2 * Math.PI * TG_RADIUS;

function threatLevel(score) {
  if (score >= 85) return 'critical';
  if (score >= 70) return 'high';
  if (score >= 55) return 'medium';
  return 'low';
}

function renderThreatGauge(score) {
  const fill   = document.getElementById('threat-gauge-fill');
  const scoreEl = document.getElementById('threat-gauge-score');
  const banner = document.getElementById('threat-level-banner');
  if (!fill || !scoreEl || !banner) return;

  const level = threatLevel(score);
  const pct = Math.max(0, Math.min(100, score)) / 100;
  const dash = (pct * TG_CIRCUMFERENCE).toFixed(1);

  fill.setAttribute('stroke-dasharray', `${dash} ${TG_CIRCUMFERENCE.toFixed(1)}`);
  fill.className.baseVal !== undefined
    ? (fill.className.baseVal = `threat-gauge-fill level-${level}`)
    : fill.setAttribute('class', `threat-gauge-fill level-${level}`);

  scoreEl.textContent = String(Math.round(score));
  scoreEl.className = `threat-gauge-score level-${level}`;

  banner.textContent = `THREAT LEVEL: ${level.toUpperCase()}`;
  banner.className = `threat-level-banner level-${level}`;
}

function initThreatGaugeSvg() {
  const wrap = document.getElementById('threat-gauge');
  if (!wrap || wrap.querySelector('svg')) return;

  const size = 140;
  const c = size / 2;
  wrap.innerHTML = `
    <svg viewBox="0 0 ${size} ${size}" role="img" aria-label="Global threat level gauge">
      <circle class="threat-gauge-track" cx="${c}" cy="${c}" r="${TG_RADIUS}"></circle>
      <circle id="threat-gauge-fill" class="threat-gauge-fill level-low"
              cx="${c}" cy="${c}" r="${TG_RADIUS}"
              stroke-dasharray="0 ${TG_CIRCUMFERENCE.toFixed(1)}"></circle>
    </svg>
    <div class="threat-gauge-center">
      <div class="threat-gauge-score level-low" id="threat-gauge-score">0</div>
      <div class="threat-gauge-label">Composite Score</div>
    </div>
  `;
}

/* =========================================================================
   Agent network visualization
   ========================================================================= */

// Hub + 4 agent nodes laid out in a 400x220 viewBox
const AN_LAYOUT = {
  orchestrator: { x: 200, y: 110, r: 26, label: 'ORCHESTRATOR', sub: 'State Machine' },
  vanguard:     { x: 60,  y: 40,  r: 22, label: 'VANGUARD',     sub: 'Triage' },
  sherlock:     { x: 340, y: 40,  r: 22, label: 'SHERLOCK',     sub: 'Investigate' },
  executor:     { x: 60,  y: 180, r: 22, label: 'EXECUTOR',     sub: 'Respond' },
  sage:         { x: 340, y: 180, r: 22, label: 'SAGE',         sub: 'Learn' },
};

function initAgentNetworkSvg() {
  const wrap = document.getElementById('agent-network');
  if (!wrap || wrap.querySelector('svg')) return;

  const links = AV_AGENTS.map(agent => {
    const a = AN_LAYOUT.orchestrator;
    const b = AN_LAYOUT[agent];
    return `<path class="an-link" id="an-link-${agent}" d="M${a.x},${a.y} L${b.x},${b.y}"></path>`;
  }).join('');

  const nodes = ['orchestrator', ...AV_AGENTS].map(key => {
    const n = AN_LAYOUT[key];
    const pulseRing = key !== 'orchestrator'
      ? `<circle class="an-pulse-ring" cx="${n.x}" cy="${n.y}" r="${n.r}"></circle>`
      : '';
    return `
      <g class="an-node online" id="an-node-${key}">
        ${pulseRing}
        <circle cx="${n.x}" cy="${n.y}" r="${n.r}"></circle>
        <text x="${n.x}" y="${n.y - 2}">${n.label}</text>
        <text class="an-sub" x="${n.x}" y="${n.y + 9}">${n.sub}</text>
      </g>`;
  }).join('');

  wrap.innerHTML = `
    <svg viewBox="0 0 400 220" role="img" aria-label="Agent network and orchestration graph">
      ${links}
      ${nodes}
    </svg>
  `;
}

/** status -> node CSS class (online / busy / critical / offline) */
function agentNodeClass(status, isCritical) {
  if (isCritical) return 'critical';
  if (status === 'error' || status === 'offline') return 'offline';
  if (status === 'busy') return 'busy';
  return 'online';
}

function renderAgentNetwork(byAgent, criticalAgents) {
  AV_AGENTS.forEach(agent => {
    const node = document.getElementById(`an-node-${agent}`);
    const link = document.getElementById(`an-link-${agent}`);
    if (!node || !link) return;

    const data = byAgent[agent] || {};
    const decisions = parseInt(data.decisions || 0, 10);
    const errors    = parseInt(data.errors || 0, 10);
    let status = 'idle';
    if (decisions > 3 && errors === decisions) status = 'error';
    else if (decisions > 0) status = 'busy';
    else status = 'online';

    const isCritical = criticalAgents.has(agent);
    const cls = agentNodeClass(status, isCritical);

    node.className.baseVal !== undefined
      ? (node.className.baseVal = `an-node ${cls}${cls !== 'offline' ? ' pulse' : ''}`)
      : node.setAttribute('class', `an-node ${cls}${cls !== 'offline' ? ' pulse' : ''}`);

    let linkCls = 'an-link';
    if (isCritical) linkCls += ' critical';
    else if (status === 'busy') linkCls += ' active';
    link.setAttribute('class', linkCls);
  });
}

/* =========================================================================
   MCP tool call log
   ========================================================================= */

function renderMcpLog(rows) {
  const container = document.getElementById('mcp-log');
  if (!container) return;

  if (!rows || rows.length === 0) {
    container.innerHTML = '<div class="empty-state-sm">No MCP tool calls in the last 15 minutes.</div>';
    return;
  }

  container.innerHTML = rows.map(row => {
    const time = avFormatTime(row._time);
    const tool = row.tool_name || 'unknown_tool';
    const target = row.case_id ? `case ${row.case_id}` : (row.target || '');
    const success = row.success === '1' || row.success === 'true' || row.success === true;
    const statusLabel = success ? 'OK' : 'ERROR';
    const statusCls = success ? 'ok' : 'error';
    const durationMs = row.duration_ms ? `${Math.round(Number(row.duration_ms))}ms` : '';

    return `<div class="mcp-log-entry ${success ? '' : 'error'}">
      <span class="mcp-time">${time}</span>
      <span class="mcp-tool">${avEsc(tool)}</span>
      <span class="mcp-target">${avEsc(target)} ${durationMs ? `· ${durationMs}` : ''}</span>
      <span class="mcp-status ${statusCls}">${statusLabel}</span>
    </div>`;
  }).join('');
}

async function pollMcpLog() {
  try {
    const rows = await avSplunkSearch(
      `index=sentinel_audit event_type=mcp_call earliest=-15m | sort -_time | head ${AV_CFG.MCP_LIMIT} ` +
      '| table _time, agent_name, tool_name, case_id, status_code, success, duration_ms, error',
      '-15m', 'now', String(AV_CFG.MCP_LIMIT)
    );
    renderMcpLog(rows);
  } catch (err) {
    console.warn('AgentVisualization MCP log poll error:', err);
  }
}

/* =========================================================================
   Emergency Halt — stops ALL non-terminal cases at once
   ========================================================================= */

const AV_TERMINAL_STATES = new Set(['CLOSED', 'SUPPRESSED', 'HALTED']);

function initEmergencyHalt() {
  const btn = document.getElementById('btn-emergency-halt');
  const modal = document.getElementById('emergency-halt-modal');
  const confirmBtn = document.getElementById('emergency-halt-confirm');
  const cancelBtn = document.getElementById('emergency-halt-cancel');
  if (!btn || !modal || !confirmBtn || !cancelBtn) return;

  btn.addEventListener('click', () => modal.classList.add('open'));
  cancelBtn.addEventListener('click', () => modal.classList.remove('open'));
  modal.addEventListener('click', e => { if (e.target === modal) modal.classList.remove('open'); });

  confirmBtn.addEventListener('click', async () => {
    modal.classList.remove('open');
    await executeEmergencyHalt(btn);
  });
}

async function executeEmergencyHalt(btn) {
  if (btn) btn.disabled = true;
  try {
    const cases = await avKvFetch('active_cases');
    const targets = (cases || []).filter(c => !AV_TERMINAL_STATES.has((c.status || '').toUpperCase()));

    await Promise.allSettled(targets.map(c => avKvPost('active_cases', c.case_id || c._key, {
      status: 'HALTED',
      halt_flag: true,
      halt_reason: 'Global emergency halt via War Room',
      halt_initiated_by: 'analyst',
    })));

    if (window.WarRoom) {
      window.WarRoom.toast(`Emergency halt issued for ${targets.length} active case${targets.length === 1 ? '' : 's'}`, 'warning');
      await window.WarRoom.fetchAll();
    }
  } catch (err) {
    if (window.WarRoom) window.WarRoom.toast(`Emergency halt failed: ${err.message}`, 'error');
    console.error('Emergency halt error:', err);
  } finally {
    if (btn) btn.disabled = false;
  }
}

/* =========================================================================
   Main update entry point (called by war_room.js on every poll)
   ========================================================================= */

function update(agentRows, cases) {
  const active = (cases || []).filter(c => !AV_TERMINAL_STATES.has((c.status || '').toUpperCase()));
  const globalScore = active.reduce((max, c) => Math.max(max, Number(c.risk_score || 0)), 0);
  renderThreatGauge(globalScore);

  const byAgent = {};
  (agentRows || []).forEach(r => {
    const name = (r.agent_name || '').toLowerCase();
    if (name) byAgent[name] = r;
  });

  const criticalAgents = new Set(
    active
      .filter(c => c.severity === 'critical')
      .map(c => (c.agent || '').toLowerCase())
      .filter(name => AV_AGENTS.includes(name))
  );

  renderAgentNetwork(byAgent, criticalAgents);
}

/* =========================================================================
   Formatting helpers
   ========================================================================= */

function avEsc(str) {
  return String(str ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function avFormatTime(ts) {
  if (!ts) return '—';
  const d = new Date(typeof ts === 'number' ? ts * 1000 : ts);
  return isNaN(d) ? String(ts) : d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

/* =========================================================================
   Init
   ========================================================================= */

function init() {
  initThreatGaugeSvg();
  initAgentNetworkSvg();
  initEmergencyHalt();
  pollMcpLog();
  setInterval(pollMcpLog, AV_CFG.MCP_POLL_MS);
}

document.addEventListener('DOMContentLoaded', init);

window.AgentVisualization = { update, pollMcpLog, renderThreatGauge, renderAgentNetwork };
