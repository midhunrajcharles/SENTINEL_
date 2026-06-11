/**
 * SENTINEL — Agent Health Monitor
 * agent_status.js
 *
 * Manages live status cards for all four SENTINEL agents:
 *   Vanguard · Sherlock · Executor · Sage
 *
 * Data flow:
 *   war_room.js calls AgentStatus.update(rows) every POLL_INTERVAL
 *   Rows come from a SPL search against sentinel_audit (last 1 hour)
 *   Sparkline history is maintained in a 24-value ring buffer per agent
 *
 * Metrics tracked:
 *   - Status: online / busy / idle / offline / error
 *   - Success rate (decisions with outcome != "error")
 *   - Queue depth (from KV Store active_cases count by current_agent)
 *   - Average latency (from audit events)
 *   - MCP error count
 *   - Model inference latency (from latency_ms on model_inference events)
 *   - Last action description
 *   - 24-hour sparkline (activity count per hour)
 *
 * Simple XML note:
 *   Replace AgentStatus.update() call with a SplunkJS search result callback.
 */

'use strict';

/* =========================================================================
   Agent definitions
   ========================================================================= */

const AGENTS = ['vanguard', 'sherlock', 'executor', 'sage'];

// Ring buffer — 24 hourly buckets per agent
const SPARKLINE_BUCKETS = 24;

const _state = {
  history: {
    vanguard: new Array(SPARKLINE_BUCKETS).fill(0),
    sherlock: new Array(SPARKLINE_BUCKETS).fill(0),
    executor: new Array(SPARKLINE_BUCKETS).fill(0),
    sage:     new Array(SPARKLINE_BUCKETS).fill(0),
  },
  sparklineCharts: {},
  lastHourBucket: getCurrentHourBucket(),
  pollTimer: null,
};

function getCurrentHourBucket() {
  return new Date().getHours();
}

/* =========================================================================
   Sparkline initialisation (Chart.js)
   ========================================================================= */

const SPARKLINE_COLORS = {
  vanguard: '#2d7ef7',
  sherlock: '#9b59b6',
  executor: '#e74c3c',
  sage:     '#27ae60',
};

function initSparklines() {
  if (typeof Chart === 'undefined') {
    // Chart.js not yet loaded — retry after brief delay
    setTimeout(initSparklines, 500);
    return;
  }

  AGENTS.forEach(agent => {
    const canvas = document.getElementById(`sparkline-${agent}`);
    if (!canvas) return;

    const color = SPARKLINE_COLORS[agent];
    const ctx   = canvas.getContext('2d');

    _state.sparklineCharts[agent] = new Chart(ctx, {
      type: 'line',
      data: {
        labels:   Array.from({ length: SPARKLINE_BUCKETS }, (_, i) => i),
        datasets: [{
          data:            [..._state.history[agent]],
          borderColor:     color,
          backgroundColor: color + '22',
          fill:            true,
          tension:         0.4,
          pointRadius:     0,
          borderWidth:     1.5,
        }],
      },
      options: {
        animation:   false,
        responsive:  true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false }, tooltip: { enabled: false } },
        scales: {
          x: { display: false },
          y: { display: false, min: 0 },
        },
      },
    });
  });
}

/* =========================================================================
   Main update entry point (called by war_room.js)
   ========================================================================= */

/**
 * Update all agent cards from a rows array produced by the SPL search:
 *
 *   index=sentinel_audit event_type=decision earliest=-1h
 *   | stats count AS decisions, avg(confidence) AS conf,
 *           avg(latency_ms) AS lat, sum(eval(outcome="error")) AS errors
 *     BY agent_name
 */
function update(rows) {
  // Index rows by agent name
  const byAgent = {};
  (rows || []).forEach(r => {
    const name = (r.agent_name || '').toLowerCase();
    if (name) byAgent[name] = r;
  });

  const currentBucket = getCurrentHourBucket();

  // Rotate sparkline buckets if the hour changed
  if (currentBucket !== _state.lastHourBucket) {
    AGENTS.forEach(agent => {
      _state.history[agent].shift();
      _state.history[agent].push(0);
    });
    _state.lastHourBucket = currentBucket;
  }

  AGENTS.forEach(agent => {
    const data = byAgent[agent] || {};
    updateCard(agent, data);
  });
}

function updateCard(agent, data) {
  const decisions  = parseInt(data.decisions  || 0, 10);
  const errors     = parseInt(data.errors     || 0, 10);
  const latencyMs  = parseFloat(data.lat      || data.avg_latency_ms || 0);
  const conf       = parseFloat(data.conf     || data.avg_confidence || 0);
  const queueDepth = parseInt(data.queue_depth || 0, 10);
  const lastAction = data.last_action || data.decision_type || '—';

  // Compute success rate
  const successRate = decisions > 0
    ? (((decisions - errors) / decisions) * 100).toFixed(0) + '%'
    : '—';

  // Determine status
  const status = deriveStatus(agent, data);

  // Update sparkline bucket for this hour
  _state.history[agent][SPARKLINE_BUCKETS - 1] += decisions;

  // Render card elements
  setEl(`${agent}-status-badge`, capitalize(status));
  setBadgeClass(`${agent}-status-badge`, status);
  setCardActive(agent, status === 'busy');

  if (agent === 'executor') {
    setEl('executor-actions',   decisions);
    setEl('executor-success',   successRate);
    setEl('executor-rollbacks', data.rollbacks || 0);
    setEl('executor-errors',    errors);
  } else if (agent === 'sage') {
    setEl('sage-iocs',    data.iocs_submitted || 0);
    setEl('sage-rules',   data.rules_proposed || 0);
    setEl('sage-fp-rate', data.fp_rate ? (parseFloat(data.fp_rate) * 100).toFixed(1) + '%' : '—');
    setEl('sage-next-run', nextRunLabel());
  } else {
    setEl(`${agent}-success`, successRate);
    setEl(`${agent}-queue`,   queueDepth);
    setEl(`${agent}-latency`, formatLatency(latencyMs));
    setEl(`${agent}-errors`,  errors);
  }

  setEl(`${agent}-last-action`, truncate(lastAction, 50));

  // Colour-code latency
  const latEl = document.getElementById(`${agent}-latency`);
  if (latEl) {
    latEl.style.color = latencyMs > 30000 ? 'var(--critical)' :
                        latencyMs > 10000 ? 'var(--high)' : 'var(--text-primary)';
  }

  // Update sparkline
  const chart = _state.sparklineCharts[agent];
  if (chart) {
    chart.data.datasets[0].data = [..._state.history[agent]];
    chart.update('none');
  }
}

/* =========================================================================
   Self-polling (when war_room.js is NOT managing the poll)
   ========================================================================= */

async function selfPoll() {
  try {
    const sessionKey = window.SPLUNK_SESSION_KEY || '';
    const base = window.CFG?.SPLUNK_BASE || '';

    const body = new URLSearchParams({
      search: 'search index=sentinel_audit event_type=decision earliest=-1h ' +
              '| stats count AS decisions, avg(confidence) AS conf, avg(latency_ms) AS lat, ' +
              '        sum(eval(outcome="error")) AS errors, last(decision_type) AS last_action ' +
              '  BY agent_name',
      earliest_time: '-1h',
      latest_time: 'now',
      output_mode: 'json',
      count: '10',
    });

    const r = await fetch(`${base}/en-US/splunkd/services/search/jobs/export`, {
      method: 'POST',
      headers: { 'Authorization': `Splunk ${sessionKey}`, 'X-Requested-With': 'XMLHttpRequest' },
      body,
    });

    if (!r.ok) return;
    const text = await r.text();
    const rows = text.trim().split('\n')
      .map(line => { try { return JSON.parse(line).result; } catch { return null; } })
      .filter(Boolean);

    update(rows);
  } catch (err) {
    console.warn('AgentStatus poll error:', err);
    // Mark all agents as possibly offline
    AGENTS.forEach(agent => setEl(`${agent}-status-badge`, 'OFFLINE'));
  }

  setEl('agent-update-ts', new Date().toLocaleTimeString());
}

/* =========================================================================
   Helpers
   ========================================================================= */

function deriveStatus(agent, data) {
  const decisions = parseInt(data.decisions || 0, 10);
  const errors    = parseInt(data.errors    || 0, 10);
  const queueDepth = parseInt(data.queue_depth || 0, 10);

  // If 100% error rate and > 3 decisions, mark as error
  if (decisions > 3 && errors === decisions) return 'error';
  // Busy if there's an active queue
  if (queueDepth > 0 || data.status === 'BUSY') return 'busy';
  // Online if active in the last poll window
  if (decisions > 0) return 'online';
  // Sage is expected to be idle most of the time
  if (agent === 'sage') return 'idle';
  return 'idle';
}

function formatLatency(ms) {
  if (!ms || ms === 0) return '—';
  if (ms < 1000)  return `${Math.round(ms)}ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
  return `${(ms / 60000).toFixed(1)}m`;
}

function nextRunLabel() {
  const now   = new Date();
  const next6 = new Date(now);
  next6.setHours(6, 0, 0, 0);
  if (now.getHours() >= 6) next6.setDate(next6.getDate() + 1);
  const diffH = Math.round((next6 - now) / 3600000);
  return `in ${diffH}h`;
}

function truncate(str, maxLen) {
  return str && str.length > maxLen ? str.slice(0, maxLen) + '…' : str;
}

function capitalize(s) {
  return s ? s.charAt(0).toUpperCase() + s.slice(1) : '';
}

function setEl(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = value;
}

function setBadgeClass(id, status) {
  const el = document.getElementById(id);
  if (!el) return;
  el.className = `agent-status-badge ${status}`;
}

function setCardActive(agent, active) {
  const card = document.getElementById(`card-${agent}`);
  if (!card) return;
  card.classList.toggle('active', active);
}

/* =========================================================================
   Initialise
   ========================================================================= */

function init() {
  initSparklines();

  // Only start self-polling if war_room.js is NOT present (standalone use)
  if (!window.WarRoom) {
    const POLL_MS = 15_000;
    selfPoll();
    _state.pollTimer = setInterval(selfPoll, POLL_MS);

    document.addEventListener('visibilitychange', () => {
      if (document.hidden) {
        clearInterval(_state.pollTimer);
      } else {
        selfPoll();
        _state.pollTimer = setInterval(selfPoll, POLL_MS);
      }
    });
  }
}

document.addEventListener('DOMContentLoaded', init);

/* =========================================================================
   Public API
   ========================================================================= */

window.AgentStatus = { update, selfPoll, initSparklines };
