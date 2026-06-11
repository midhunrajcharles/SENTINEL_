/**
 * SENTINEL War Room — Main Dashboard Controller
 * war_room.js
 *
 * Responsibilities:
 *   - Polling the Splunk REST API every POLL_INTERVAL ms for live data
 *   - Rendering and sorting the case queue table
 *   - Displaying the active investigation (SPL, activity feed)
 *   - Wiring human-override controls (Halt / Escalate / False-Positive)
 *   - Global metric bar updates
 *   - Keyboard shortcuts
 *   - Toast notifications
 *
 * No frameworks — vanilla ES2017. IE11 not supported (Splunk 9.x drops it).
 *
 * Splunk REST endpoints used:
 *   GET  /en-US/splunkd/servicesNS/nobody/sentinel/storage/collections/data/active_cases
 *   GET  /en-US/splunkd/services/search/jobs/export  (SPL for metrics)
 *   POST /en-US/splunkd/servicesNS/nobody/sentinel/storage/collections/data/active_cases/<id>
 *
 * Simple XML note:
 *   Remove the poll setup and replace with Splunk's mvc.createSearchManager()
 *   or SplunkJS SDK search primitives.
 */

'use strict';

/* =========================================================================
   Configuration
   ========================================================================= */
const CFG = {
  POLL_INTERVAL:   10_000,          // ms — main data refresh cadence
  ACTIVITY_LIMIT:  30,              // max entries in activity feed
  SPLUNK_BASE:     '',              // empty = same-origin; set for cross-origin
  NAMESPACE:       'sentinel',
  KVSTORE_PATH:    '/en-US/splunkd/servicesNS/nobody/sentinel/storage/collections/data/',
  SEARCH_PATH:     '/en-US/splunkd/services/search/jobs/export',
  SENTINEL_API:    '/en-US/splunkd/services/sentinel/',     // approval gate REST surface
  APPROVAL_TICK:   1_000,           // ms — countdown timer refresh cadence
  SESSION_KEY:     window.SPLUNK_SESSION_KEY || '',  // injected by template engine
};

/* Severity thresholds (score → label) */
const SEVERITY = (score) => {
  if (score >= 85) return 'critical';
  if (score >= 70) return 'high';
  if (score >= 55) return 'medium';
  return 'low';
};

/* =========================================================================
   State
   ========================================================================= */
const STATE = {
  cases:          [],       // full list from API
  filteredCases:  [],       // after filter/sort applied
  selectedCaseId: null,
  sortCol:        'case_id',
  sortDir:        'desc',
  pollTimer:      null,
  activityBuffer: [],       // ring buffer for activity feed
  progressTimer:  null,
  approvals:        [],     // pending approval requests from /sentinel/approval/pending
  approvalTickTimer: null,  // per-second countdown re-render
};

/* =========================================================================
   Splunk REST helpers
   ========================================================================= */

/** Fetch JSON from Splunk KV Store collection. */
async function kvFetch(collection) {
  const url = `${CFG.SPLUNK_BASE}${CFG.KVSTORE_PATH}${collection}`;
  const r = await fetch(url, {
    headers: {
      'Authorization': `Splunk ${CFG.SESSION_KEY}`,
      'X-Requested-With': 'XMLHttpRequest',
    },
  });
  if (!r.ok) throw new Error(`KV Store ${collection}: HTTP ${r.status}`);
  return r.json();
}

/** POST an update to a specific KV Store document. */
async function kvPost(collection, key, body) {
  const url = `${CFG.SPLUNK_BASE}${CFG.KVSTORE_PATH}${collection}/${encodeURIComponent(key)}`;
  const r = await fetch(url, {
    method: 'POST',
    headers: {
      'Authorization': `Splunk ${CFG.SESSION_KEY}`,
      'Content-Type':  'application/json',
      'X-Requested-With': 'XMLHttpRequest',
    },
    body: JSON.stringify(body),
  });
  if (!r.ok) throw new Error(`KV POST ${collection}/${key}: HTTP ${r.status}`);
  return r.json();
}

/** GET from a SENTINEL custom REST endpoint (e.g. approval/pending). */
async function sentinelGet(path) {
  const url = `${CFG.SPLUNK_BASE}${CFG.SENTINEL_API}${path}`;
  const r = await fetch(url, {
    headers: {
      'Authorization': `Splunk ${CFG.SESSION_KEY}`,
      'X-Requested-With': 'XMLHttpRequest',
    },
  });
  if (!r.ok) throw new Error(`SENTINEL API ${path}: HTTP ${r.status}`);
  return r.json();
}

/** POST to a SENTINEL custom REST endpoint (e.g. approval/<id>/approve). */
async function sentinelPost(path, body = {}) {
  const url = `${CFG.SPLUNK_BASE}${CFG.SENTINEL_API}${path}`;
  const r = await fetch(url, {
    method: 'POST',
    headers: {
      'Authorization': `Splunk ${CFG.SESSION_KEY}`,
      'Content-Type':  'application/json',
      'X-Requested-With': 'XMLHttpRequest',
    },
    body: JSON.stringify(body),
  });
  const data = await r.json().catch(() => ({}));
  if (!r.ok || data.error) throw new Error(data.error || `SENTINEL API ${path}: HTTP ${r.status}`);
  return data;
}

/** Run a oneshot SPL search and return rows. */
async function splunkSearch(spl, earliest = '-24h', latest = 'now') {
  const body = new URLSearchParams({
    search:        `search ${spl}`,
    earliest_time: earliest,
    latest_time:   latest,
    output_mode:   'json',
    count:         '500',
  });
  const r = await fetch(`${CFG.SPLUNK_BASE}${CFG.SEARCH_PATH}`, {
    method: 'POST',
    headers: {
      'Authorization': `Splunk ${CFG.SESSION_KEY}`,
      'X-Requested-With': 'XMLHttpRequest',
    },
    body,
  });
  if (!r.ok) return [];
  const text = await r.text();
  // Export endpoint returns newline-delimited JSON
  return text.trim().split('\n')
    .map(line => { try { return JSON.parse(line).result; } catch { return null; } })
    .filter(Boolean);
}

/* =========================================================================
   Data fetching & polling
   ========================================================================= */

async function fetchAll() {
  try {
    const [cases, metrics, agentStats, approvals] = await Promise.allSettled([
      kvFetch('active_cases'),
      fetchGlobalMetrics(),
      fetchAgentMetrics(),
      sentinelGet('approval/pending'),
    ]);

    if (cases.status === 'fulfilled') {
      processNewCases(cases.value);
    }
    if (metrics.status === 'fulfilled') {
      renderFooterMetrics(metrics.value);
    }
    if (agentStats.status === 'fulfilled') {
      // agent_status.js handles rendering
      if (window.AgentStatus) window.AgentStatus.update(agentStats.value);
      renderAgentDegradation(agentStats.value);
    }
    if (approvals.status === 'fulfilled') {
      STATE.approvals = approvals.value.pending || [];
      renderApprovalsPanel();
    }

    setLastUpdate();
    updateSystemStatus('online');
  } catch (err) {
    console.error('War Room poll error:', err);
    updateSystemStatus('error');
  }
}

async function fetchGlobalMetrics() {
  const rows = await splunkSearch(
    'index=sentinel_metrics earliest=-24h | stats ' +
    'count AS total, ' +
    'sum(eval(autonomous="true")) AS autonomous, ' +
    'sum(eval(autonomous="false")) AS escalated, ' +
    'avg(mttr_minutes) AS avg_mttr, ' +
    'sum(eval(status="CLOSED" AND resolution!="FALSE_POSITIVE")) AS contained',
    '-24h', 'now'
  );
  const weekly = await splunkSearch(
    'index=sentinel_metrics earliest=-7d | stats ' +
    'sum(eval(status="CLOSED" AND resolution!="FALSE_POSITIVE")) AS contained_week, ' +
    'sum(eval(resolution="FALSE_POSITIVE")) AS fp_week, count AS total_week',
    '-7d', 'now'
  );
  return { daily: rows[0] || {}, weekly: weekly[0] || {} };
}

async function fetchAgentMetrics() {
  return splunkSearch(
    'index=sentinel_audit event_type=decision earliest=-1h ' +
    '| stats count AS decisions, avg(confidence) AS conf, avg(latency_ms) AS lat, ' +
    '        sum(eval(outcome="error")) AS errors BY agent_name',
    '-1h', 'now'
  );
}

function processNewCases(raw) {
  const newIds = new Set(raw.map(c => c.case_id || c._key));
  const oldIds = new Set(STATE.cases.map(c => c.case_id));
  const added  = [...newIds].filter(id => !oldIds.has(id));

  STATE.cases = raw.map(normalizeCase);
  applyFiltersAndSort();
  renderSystemHealth(STATE.cases);

  // Flash new rows
  added.forEach(id => {
    const row = document.querySelector(`tr[data-case-id="${id}"]`);
    if (row) row.classList.add('new-alert');
  });

  if (added.length > 0) {
    toast(`${added.length} new case${added.length > 1 ? 's' : ''} arrived`, 'info');
  }

  // Refresh the selected case's investigation panel
  if (STATE.selectedCaseId) {
    const fresh = STATE.cases.find(c => c.case_id === STATE.selectedCaseId);
    if (fresh) renderInvestigationPanel(fresh);
  }
}

function normalizeCase(raw) {
  return {
    case_id:    raw.case_id    || raw._key || '—',
    alert_type: raw.alert_type || 'UNKNOWN',
    host:       raw.primary_host || raw.host || '—',
    risk_score: Number(raw.risk_score || raw.composite_score || 0),
    status:     (raw.status || 'QUEUED').toUpperCase(),
    agent:      raw.current_agent || '—',
    created:    raw.created_time ? Number(raw.created_time) : Date.now() / 1000,
    severity:   SEVERITY(Number(raw.risk_score || 0)),
    classification: raw.classification || '',
    // Full data for investigation panel
    _raw: raw,
  };
}

/* =========================================================================
   Case queue rendering
   ========================================================================= */

function applyFiltersAndSort() {
  const textFilter   = document.getElementById('queue-filter').value.toLowerCase();
  const statusFilter = document.getElementById('queue-status-filter').value;
  const severityFilter = document.getElementById('queue-severity-filter').value;

  let list = STATE.cases.filter(c => {
    if (textFilter && ![c.case_id, c.alert_type, c.host].join(' ').toLowerCase().includes(textFilter)) return false;
    if (statusFilter && c.status !== statusFilter) return false;
    if (severityFilter && c.severity !== severityFilter) return false;
    return true;
  });

  const col = STATE.sortCol;
  const dir = STATE.sortDir === 'asc' ? 1 : -1;

  list.sort((a, b) => {
    let av = a[col], bv = b[col];
    if (col === 'age') { av = a.created; bv = b.created; }
    if (typeof av === 'number') return (av - bv) * dir;
    return String(av).localeCompare(String(bv)) * dir;
  });

  STATE.filteredCases = list;
  renderCaseTable(list);
  document.getElementById('case-count-badge').textContent = list.length;
}

function renderCaseTable(cases) {
  const tbody = document.getElementById('case-tbody');

  if (cases.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7" style="text-align:center;padding:2rem;color:var(--text-muted)">No cases match the current filter</td></tr>`;
    return;
  }

  const now = Date.now() / 1000;
  tbody.innerHTML = cases.map(c => {
    const age      = formatAge(now - c.created);
    const sel      = c.case_id === STATE.selectedCaseId ? 'selected' : '';
    const scoreClass = c.severity;
    const agentClass = c.agent.toLowerCase().replace(/[^a-z]/g, '');

    return `<tr class="${sel}" data-case-id="${esc(c.case_id)}" data-severity="${c.severity}"
               tabindex="0" role="row" aria-selected="${sel ? 'true' : 'false'}">
      <td class="text-mono" style="font-size:0.72rem; color:var(--text-muted)">${esc(c.case_id.slice(-6))}</td>
      <td class="truncate" title="${esc(c.alert_type)}" style="max-width:110px">${esc(formatAlertType(c.alert_type))}</td>
      <td class="truncate text-mono" title="${esc(c.host)}" style="max-width:90px; font-size:0.72rem">${esc(c.host)}</td>
      <td><span class="score-badge ${scoreClass}">${c.risk_score}</span></td>
      <td><span class="status-chip ${c.status.toLowerCase()}">${c.status}</span></td>
      <td><span class="agent-dot ${agentClass}">${esc(c.agent)}</span></td>
      <td class="text-muted" style="font-size:0.7rem">${age}</td>
    </tr>`;
  }).join('');

  // Row click handlers
  tbody.querySelectorAll('tr[data-case-id]').forEach(row => {
    row.addEventListener('click',   () => selectCase(row.dataset.caseId));
    row.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') selectCase(row.dataset.caseId); });
  });
}

function selectCase(caseId) {
  STATE.selectedCaseId = caseId;
  // Update table selection highlight
  document.querySelectorAll('#case-tbody tr').forEach(r => {
    const sel = r.dataset.caseId === caseId;
    r.classList.toggle('selected', sel);
    r.setAttribute('aria-selected', sel ? 'true' : 'false');
  });

  const c = STATE.cases.find(x => x.case_id === caseId);
  if (c) renderInvestigationPanel(c);
}

/* =========================================================================
   Investigation panel rendering
   ========================================================================= */

function renderInvestigationPanel(c) {
  const raw = c._raw || {};

  // Header
  document.getElementById('inv-empty').classList.add('hidden');
  document.getElementById('override-controls').style.display = 'flex';

  document.getElementById('inv-case-title').textContent =
    `${c.case_id}  ·  ${formatAlertType(c.alert_type)}`;
  document.getElementById('inv-case-sub').textContent =
    `Host: ${c.host}  ·  Score: ${c.risk_score}  ·  ${c.status}  ·  ${c.classification || ''}`;

  // Store for override buttons
  document.getElementById('btn-halt').dataset.caseId     = c.case_id;
  document.getElementById('btn-escalate').dataset.caseId = c.case_id;
  document.getElementById('btn-fp').dataset.caseId       = c.case_id;

  // Current SPL from vanguard_decision or sherlock_report
  const currentSpl = raw.current_spl || raw.vanguard_decision?.spl_used || '';
  const currentPhase = raw.current_phase || '';
  const currentAgent = raw.current_agent || 'vanguard';

  const splSection = document.getElementById('spl-section');
  if (currentSpl) {
    splSection.classList.remove('hidden');
    document.getElementById('spl-agent-tag').textContent = currentAgent;
    document.getElementById('spl-agent-tag').className   = `agent-dot ${currentAgent.toLowerCase()}`;
    document.getElementById('spl-phase-label').textContent = currentPhase || `${currentAgent} processing`;
    document.getElementById('spl-code').innerHTML = highlightSpl(currentSpl);
    animateQueryProgress(raw.query_progress_pct || 0);
  } else {
    splSection.classList.add('hidden');
  }

  // Activity feed — merge audit events from raw
  const actSection = document.getElementById('activity-section');
  const actEvents  = (raw.audit_trail || []).slice(-CFG.ACTIVITY_LIMIT);
  if (actEvents.length > 0) {
    actSection.classList.remove('hidden');
    renderActivityFeed(actEvents);
  }

  // Timeline — from audit trail
  const tlSection = document.getElementById('timeline-section');
  if (actEvents.length > 0) {
    tlSection.classList.remove('hidden');
    if (window.CaseTimeline) window.CaseTimeline.render('case-timeline', actEvents, c.case_id);
  }

  // Reasoning — Chain of Thought explainability trace per agent
  renderReasoningPanel(raw);
}

/* =========================================================================
   Reasoning / Chain-of-Thought panel
   Renders Vanguard's chain_of_thought, Sherlock's investigation_chain, and
   Executor's action_chain as a collapsible, color-coded vertical timeline —
   re-displaying the same explainability fields the agents already wrote to
   the case (and to sentinel_audit via AuditLogger.log_chain_of_thought).
   ========================================================================= */

function renderReasoningPanel(raw) {
  const section   = document.getElementById('reasoning-section');
  const container = document.getElementById('reasoning-timeline');

  const groups = [];

  const vChain = raw.vanguard_decision?.chain_of_thought;
  if (Array.isArray(vChain) && vChain.length) {
    groups.push({ agent: 'vanguard', label: 'Vanguard · Triage Reasoning', steps: vChain });
  }

  const sChain = raw.sherlock_report?.investigation_chain;
  if (Array.isArray(sChain) && sChain.length) {
    groups.push({ agent: 'sherlock', label: 'Sherlock · Investigation Reasoning', steps: sChain });
  }

  const executorLogs = raw.executor_actions;
  const latestExecutorLog = Array.isArray(executorLogs)
    ? executorLogs[executorLogs.length - 1]
    : executorLogs;
  const eChain = latestExecutorLog?.action_chain;
  if (Array.isArray(eChain) && eChain.length) {
    groups.push({ agent: 'executor', label: 'Executor · Response Reasoning', steps: eChain });
  }

  if (!groups.length) {
    section.classList.add('hidden');
    container.innerHTML = '';
    return;
  }

  section.classList.remove('hidden');
  container.innerHTML = groups.map((group, gi) => `
    <div class="reasoning-group">
      <button class="reasoning-group-header" type="button" data-group="${gi}"
              aria-expanded="true" aria-controls="reasoning-group-body-${gi}">
        <span class="agent-name-dot" style="background:${agentColor(group.agent)}" aria-hidden="true"></span>
        <span>${esc(group.label)}</span>
        <span class="badge">${group.steps.length} step${group.steps.length === 1 ? '' : 's'}</span>
        <span class="reasoning-toggle-icon" aria-hidden="true">&#x25BE;</span>
      </button>
      <div class="reasoning-group-body" id="reasoning-group-body-${gi}" role="list">
        ${group.steps.map((step, si) => renderReasoningStep(group.agent, step, si)).join('')}
      </div>
    </div>
  `).join('');

  container.querySelectorAll('.reasoning-group-header').forEach(btn => {
    btn.addEventListener('click', () => {
      const body = document.getElementById(`reasoning-group-body-${btn.dataset.group}`);
      const collapsed = body.classList.toggle('collapsed');
      btn.setAttribute('aria-expanded', String(!collapsed));
      btn.querySelector('.reasoning-toggle-icon').style.transform = collapsed ? 'rotate(-90deg)' : '';
    });
  });
}

function renderReasoningStep(agent, step, idx) {
  const num   = step.step ?? step.sequence ?? (idx + 1);
  const title = step.name || step.phase || (step.action ? `Action: ${formatAlertType(String(step.action))}` : `Step ${num}`);

  const rows = [];
  const add = (label, value) => {
    if (value === undefined || value === null || value === '') return;
    rows.push([label, Array.isArray(value) ? value.join(', ')
              : (typeof value === 'object' ? Object.entries(value).map(([k, v]) => `${k}=${v}`).join('  ·  ')
              : String(value))]);
  };

  add('Observed',            step.observation);
  add('Query',               step.query);
  add('Target',              step.target);
  add('Justification',       step.justification);
  add('Result',              step.result);
  if (step.pre_state || step.post_state) {
    add('State change', `${step.pre_state || 'unknown'}  →  ${step.post_state || 'unknown'}`);
  }
  add('Verification query',  step.verification_query);
  add('Verification result', step.verification_result);
  add('Inferred',            step.inference);
  add('Risk matrix',         step.risk_matrix);
  if (step.rollback_timer) add('Rollback timer', `${step.rollback_timer}s`);
  if (step.human_notified !== undefined) add('Human notified', step.human_notified ? 'Yes' : 'No');
  if (step.requires_manager_approval) add('Approval', 'Manager approval required');

  const isFinal = !!(step.conclusion || (step.action && agent !== 'executor'));
  if (step.conclusion) add('Conclusion', step.conclusion);
  if (step.action && agent !== 'executor') add('Recommended action', step.action);

  return `<div class="reasoning-step ${agent}" role="listitem">
    <div class="reasoning-step-marker">${esc(String(num))}</div>
    <div class="reasoning-step-body">
      <div class="reasoning-step-title">${esc(title)}</div>
      ${rows.map(([label, val]) => `
        <div class="reasoning-step-row${isFinal && (label === 'Conclusion' || label === 'Recommended action') ? ' reasoning-step-conclusion' : ''}">
          <span class="reasoning-step-label">${esc(label)}</span>
          <span>${esc(val)}</span>
        </div>`).join('')}
    </div>
  </div>`;
}

function renderActivityFeed(events) {
  const feed = document.getElementById('activity-feed');
  const items = [...events].reverse().slice(0, CFG.ACTIVITY_LIMIT);

  feed.innerHTML = items.map(ev => {
    const agent   = (ev.agent_name || 'system').toLowerCase();
    const time    = formatTimeShort(ev.timestamp || ev._time);
    const msg     = ev.summary || ev.message || ev.decision_type || JSON.stringify(ev).slice(0, 80);
    const agentLabel = capitalize(agent);
    return `<div class="activity-entry ${agent}" role="listitem">
      <span class="time" title="${ev.timestamp || ''}">${time}</span>
      <span class="msg"><span class="agent-tag" style="color:${agentColor(agent)}">${agentLabel}</span>${esc(msg)}</span>
    </div>`;
  }).join('');
}

function animateQueryProgress(startPct) {
  const bar = document.getElementById('spl-progress-bar');
  const wrap = document.getElementById('spl-progress-bar-wrap');
  clearInterval(STATE.progressTimer);

  let pct = Math.min(99, startPct || 0);
  bar.style.width = pct + '%';
  wrap.setAttribute('aria-valuenow', pct);

  if (pct < 99) {
    STATE.progressTimer = setInterval(() => {
      pct = Math.min(99, pct + (100 - pct) * 0.05);
      bar.style.width = pct + '%';
      wrap.setAttribute('aria-valuenow', Math.round(pct));
      if (pct >= 99) clearInterval(STATE.progressTimer);
    }, 400);
  }
}

/* =========================================================================
   Footer metrics
   ========================================================================= */

function renderFooterMetrics(data) {
  const d = data.daily   || {};
  const w = data.weekly  || {};

  set('metric-total',       d.total        || 0);
  set('metric-autonomous',  d.autonomous   || 0);
  set('metric-escalated',   d.escalated    || 0);
  set('metric-mttr',        d.avg_mttr ? Number(d.avg_mttr).toFixed(1) : '—');
  set('metric-contained',   w.contained_week || 0);

  const active   = STATE.cases.filter(c => !['CLOSED', 'SUPPRESSED'].includes(c.status));
  const critical = active.filter(c => c.severity === 'critical');
  set('metric-active',         active.length);
  set('metric-critical-count', critical.length);

  const totalW = Number(w.total_week || 0);
  const fpW    = Number(w.fp_week    || 0);
  const fpRate = totalW > 0 ? ((fpW / totalW) * 100).toFixed(1) : '—';
  set('metric-fp-rate', fpRate);

  // Rough savings: cases * 1h * $85
  const savings = Math.round(Number(d.total || 0) * 85);
  set('metric-savings', savings > 0 ? savings.toLocaleString() : '—');
}

/* =========================================================================
   System Health — fault tolerance: state timeouts, retries, dead letters
   Reads STUCK / RETRYING / ERROR / DEAD_LETTER cases straight out of
   active_cases (the watchdog leaves them there so analysts can intervene)
   and renders state-distribution chips, an attention list with Retry /
   Acknowledge actions, and a coarse agent-degradation indicator.
   ========================================================================= */

const _HEALTH_STATE_ORDER = [
  'QUEUED', 'TRIAGING', 'INVESTIGATING', 'DECIDING', 'RESPONDING', 'LEARNING',
  'RETRYING', 'STUCK', 'ERROR', 'DEAD_LETTER', 'HALTED', 'CLOSED', 'SUPPRESSED',
];

function renderSystemHealth(cases) {
  const counts = {};
  cases.forEach(c => { counts[c.status] = (counts[c.status] || 0) + 1; });

  const grid = document.getElementById('health-state-grid');
  if (grid) {
    const chips = _HEALTH_STATE_ORDER
      .filter(s => counts[s])
      .map(s => `<span class="status-chip ${s.toLowerCase()}" title="${s} cases">${s} <strong>${counts[s]}</strong></span>`)
      .join('');
    grid.innerHTML = chips || '<span class="text-muted" style="font-size:0.78rem">No active cases</span>';
  }

  renderAttentionList(cases);
}

function renderAttentionList(cases) {
  const list  = document.getElementById('attention-list');
  const empty = document.getElementById('attention-empty');
  const badge = document.getElementById('attention-count-badge');
  if (!list) return;

  const stuck = cases.filter(c => c.status === 'STUCK');
  const dead  = cases.filter(c => c.status === 'DEAD_LETTER');
  const items = [
    ...stuck.map(c => ({ c, kind: 'stuck' })),
    ...dead.map(c  => ({ c, kind: 'dead_letter' })),
  ];

  if (badge) badge.textContent = items.length;
  set('dlq-count-badge', dead.length);

  // Clear previously rendered rows (keep the empty-state placeholder element)
  list.querySelectorAll('.attention-row').forEach(r => r.remove());

  if (items.length === 0) {
    if (empty) empty.style.display = '';
    return;
  }
  if (empty) empty.style.display = 'none';

  items.forEach(({ c, kind }) => {
    const row = document.createElement('div');
    row.className = `attention-row ${kind}`;
    row.dataset.caseId = c.case_id;
    const chipLabel = kind === 'stuck' ? 'STUCK' : 'DEAD LETTER';
    const actionBtn = kind === 'stuck'
      ? `<button class="btn btn-ghost btn-sm btn-retry" data-case-id="${esc(c.case_id)}" data-kind="stuck">Retry</button>`
      : `<button class="btn btn-ghost btn-sm btn-acknowledge" data-case-id="${esc(c.case_id)}" data-kind="dead_letter">Acknowledge</button>`;

    row.innerHTML = `
      <span class="status-chip ${kind}">${chipLabel}</span>
      <span class="text-mono attn-case-id" title="${esc(c.case_id)}">${esc(c.case_id)}</span>
      <span class="truncate attn-type" title="${esc(c.alert_type)}">${esc(formatAlertType(c.alert_type))}</span>
      <span class="text-muted attn-host text-mono" title="${esc(c.host)}">${esc(c.host)}</span>
      ${actionBtn}
    `;
    list.appendChild(row);
  });

  list.querySelectorAll('.btn-retry').forEach(btn => {
    btn.addEventListener('click', () => retryStuckCase(btn.dataset.caseId, btn));
  });
  list.querySelectorAll('.btn-acknowledge').forEach(btn => {
    btn.addEventListener('click', () => acknowledgeDeadLetterCase(btn.dataset.caseId, btn));
  });
}

/** Re-queue a STUCK case — sets it back to QUEUED so the poll cycle picks it up. */
async function retryStuckCase(caseId, btn) {
  if (btn) btn.disabled = true;
  try {
    await kvPost('active_cases', caseId, {
      status: 'QUEUED',
      retry_requested_by: 'analyst',
      retry_requested_at: new Date().toISOString(),
    });
    toast(`Case ${caseId} re-queued for retry`, 'info');
    await fetchAll();
  } catch (err) {
    toast(`Retry failed for ${caseId}: ${err.message}`, 'error');
    if (btn) btn.disabled = false;
  }
}

/** Acknowledge a DEAD_LETTER case — marks it reviewed by a human without changing its status. */
async function acknowledgeDeadLetterCase(caseId, btn) {
  if (btn) btn.disabled = true;
  try {
    await kvPost('active_cases', caseId, {
      acknowledged_by: 'analyst',
      acknowledged_at: new Date().toISOString(),
      acknowledgement_note: 'Reviewed via War Room — pending recover_from_dead_letter or manual closure',
    });
    toast(`Case ${caseId} acknowledged — flagged as reviewed`, 'success');
    await fetchAll();
  } catch (err) {
    toast(`Acknowledge failed for ${caseId}: ${err.message}`, 'error');
    if (btn) btn.disabled = false;
  }
}

function renderAgentDegradation(rows) {
  const grid = document.getElementById('health-agent-grid');
  if (!grid) return;

  const AGENTS = ['vanguard', 'sherlock', 'executor', 'sage'];
  const byAgent = {};
  (rows || []).forEach(r => { byAgent[String(r.agent_name || '').toLowerCase()] = r; });

  grid.innerHTML = AGENTS.map(name => {
    const r = byAgent[name] || {};
    const errors = Number(r.errors || 0);
    let level = 'green', label = 'Healthy';
    if (errors >= 3)      { level = 'red';    label = 'Degraded — check circuit breaker'; }
    else if (errors >= 1) { level = 'yellow'; label = 'Elevated errors'; }

    return `<div class="health-agent-row" title="${esc(label)}">
      <span class="health-dot ${level}" aria-hidden="true"></span>
      <span class="health-agent-name">${capitalize(name)}</span>
      <span class="text-muted health-agent-label truncate">${esc(label)}</span>
      <span class="text-mono health-agent-errors">${errors} err/h</span>
    </div>`;
  }).join('');
}

/* =========================================================================
   Pending Approvals — human-in-the-loop gate panel
   ========================================================================= */

/** Urgency color band — red as the deadline nears or passes, green when there's time to spare. */
function approvalUrgencyClass(secondsRemaining) {
  if (secondsRemaining <= 0)   return 'red';
  if (secondsRemaining < 120)  return 'red';      // < 2 min left — urgent
  if (secondsRemaining < 240)  return 'yellow';   // 2-4 min left — watch
  return 'green';                                  // > 4 min left — plenty of time
}

function formatCountdown(secondsRemaining) {
  if (secondsRemaining <= 0) return 'EXPIRED';
  const m = Math.floor(secondsRemaining / 60);
  const s = secondsRemaining % 60;
  return `${m}:${String(s).padStart(2, '0')}`;
}

function renderApprovalsPanel() {
  const tbody = document.getElementById('approvals-tbody');
  const empty = document.getElementById('approvals-empty');
  const table = document.getElementById('approvals-table');
  const badge = document.getElementById('approvals-count-badge');
  if (!tbody) return;

  const list = STATE.approvals || [];
  badge.textContent = String(list.length);

  if (!list.length) {
    table.style.display = 'none';
    empty.style.display = '';
    tbody.innerHTML = '';
    return;
  }
  table.style.display = '';
  empty.style.display = 'none';

  tbody.innerHTML = list.map(req => {
    const remaining = secondsRemaining(req);
    const urgency = approvalUrgencyClass(remaining);
    return `<tr data-request-id="${esc(req.request_id)}" data-expires="${esc(req.expires_at)}">
      <td class="text-mono">${esc(req.request_id)}</td>
      <td class="text-mono">${esc(req.case_id)}</td>
      <td>${esc(req.action)}</td>
      <td class="text-mono">${esc(req.target)}</td>
      <td><span class="approval-remaining ${urgency}" data-countdown>${formatCountdown(remaining)}</span></td>
      <td>
        <div class="approval-actions">
          <button class="btn-approve" data-action="approve" data-request-id="${esc(req.request_id)}">Approve</button>
          <button class="btn-deny"    data-action="deny"    data-request-id="${esc(req.request_id)}">Deny</button>
        </div>
      </td>
    </tr>`;
  }).join('');

  tbody.querySelectorAll('button[data-action]').forEach(btn => {
    btn.addEventListener('click', () => decideApproval(btn.dataset.requestId, btn.dataset.action, btn));
  });

  startApprovalCountdown();
}

/** Recompute "seconds remaining" client-side from the absolute expiry timestamp. */
function secondsRemaining(req) {
  const expiresMs = Date.parse(req.expires_at);
  if (isNaN(expiresMs)) return Number(req.seconds_remaining || 0);
  return Math.max(0, Math.round((expiresMs - Date.now()) / 1000));
}

/** Re-render just the countdown cells every second — no full table rebuild. */
function startApprovalCountdown() {
  if (STATE.approvalTickTimer) clearInterval(STATE.approvalTickTimer);
  if (!STATE.approvals.length) return;

  STATE.approvalTickTimer = setInterval(() => {
    const rows = document.querySelectorAll('#approvals-tbody tr[data-request-id]');
    if (!rows.length) { clearInterval(STATE.approvalTickTimer); return; }

    rows.forEach(row => {
      const req = STATE.approvals.find(r => r.request_id === row.dataset.requestId);
      if (!req) return;
      const remaining = secondsRemaining(req);
      const cell = row.querySelector('[data-countdown]');
      if (!cell) return;
      cell.textContent = formatCountdown(remaining);
      cell.className = `approval-remaining ${approvalUrgencyClass(remaining)}`;
    });
  }, CFG.APPROVAL_TICK);
}

/** Approve/Deny click handler — calls the direct REST endpoint. */
async function decideApproval(requestId, action, btn) {
  const row = btn.closest('tr');
  row.querySelectorAll('button[data-action]').forEach(b => b.disabled = true);
  try {
    await sentinelPost(`approval/${encodeURIComponent(requestId)}/${action}`, { responder_id: 'analyst' });
    toast(`Request ${requestId} ${action === 'approve' ? 'approved' : 'denied'}`, action === 'approve' ? 'success' : 'warning');
    STATE.approvals = STATE.approvals.filter(r => r.request_id !== requestId);
    renderApprovalsPanel();
    await fetchAll();
  } catch (err) {
    toast(`${capitalize(action)} failed for ${requestId}: ${err.message}`, 'error');
    row.querySelectorAll('button[data-action]').forEach(b => b.disabled = false);
  }
}

/* =========================================================================
   System status indicator
   ========================================================================= */

function updateSystemStatus(state) {
  const dot   = document.getElementById('sys-status-dot');
  const label = document.getElementById('sys-status-label');
  dot.className = `status-dot ${state}`;
  const labels = {
    online:  'ALL SYSTEMS OPERATIONAL',
    busy:    'PROCESSING ACTIVE CASES',
    offline: 'OFFLINE',
    error:   'CONNECTION ERROR',
  };
  label.textContent = labels[state] || state.toUpperCase();
}

function setLastUpdate() {
  const ts = document.getElementById('last-update-ts');
  ts.textContent = `Last update: ${new Date().toLocaleTimeString()}`;
  ts.setAttribute('datetime', new Date().toISOString());
}

/* =========================================================================
   Sort controls
   ========================================================================= */

document.querySelectorAll('.case-table thead th[data-col]').forEach(th => {
  th.addEventListener('click', () => {
    const col = th.dataset.col;
    if (STATE.sortCol === col) {
      STATE.sortDir = STATE.sortDir === 'asc' ? 'desc' : 'asc';
    } else {
      STATE.sortCol = col;
      STATE.sortDir = 'desc';
    }
    document.querySelectorAll('.case-table thead th').forEach(h => {
      h.classList.remove('sort-asc', 'sort-desc');
    });
    th.classList.add(STATE.sortDir === 'asc' ? 'sort-asc' : 'sort-desc');
    th.setAttribute('aria-sort', STATE.sortDir === 'asc' ? 'ascending' : 'descending');
    applyFiltersAndSort();
  });

  // Keyboard accessibility
  th.addEventListener('keydown', e => { if (e.key === 'Enter') th.click(); });
});

document.getElementById('queue-filter').addEventListener('input', applyFiltersAndSort);
document.getElementById('queue-status-filter').addEventListener('change', applyFiltersAndSort);
document.getElementById('queue-severity-filter').addEventListener('change', applyFiltersAndSort);

/* =========================================================================
   Human override controls
   ========================================================================= */

// HALT
document.getElementById('btn-halt').addEventListener('click', () => {
  const caseId = document.getElementById('btn-halt').dataset.caseId;
  document.getElementById('halt-case-id').textContent = caseId;
  openModal('halt-modal');
});

document.getElementById('halt-confirm').addEventListener('click', async () => {
  const caseId = document.getElementById('halt-case-id').textContent;
  closeModal('halt-modal');
  try {
    await kvPost('active_cases', caseId, { status: 'HALTED', halt_flag: true, halt_reason: 'Manual override via War Room', halt_initiated_by: 'analyst' });
    toast(`Case ${caseId} halted`, 'warning');
    await fetchAll();
  } catch (err) {
    toast(`Halt failed: ${err.message}`, 'error');
  }
});

document.getElementById('halt-cancel').addEventListener('click', () => closeModal('halt-modal'));

// ESCALATE
document.getElementById('btn-escalate').addEventListener('click', () => {
  const caseId = document.getElementById('btn-escalate').dataset.caseId;
  document.getElementById('esc-case-id').textContent = caseId;
  openModal('escalate-modal');
});

document.getElementById('esc-confirm').addEventListener('click', async () => {
  const caseId = document.getElementById('esc-case-id').textContent;
  closeModal('escalate-modal');
  try {
    await kvPost('active_cases', caseId, { status: 'HALTED', requires_approval: true, escalated_by: 'analyst', escalated_at: new Date().toISOString() });
    toast(`Case ${caseId} escalated to analyst queue`, 'info');
    await fetchAll();
  } catch (err) {
    toast(`Escalate failed: ${err.message}`, 'error');
  }
});

document.getElementById('esc-cancel').addEventListener('click', () => closeModal('escalate-modal'));

// FALSE POSITIVE
document.getElementById('btn-fp').addEventListener('click', () => {
  const caseId = document.getElementById('btn-fp').dataset.caseId;
  document.getElementById('fp-case-id').textContent = caseId;
  openModal('fp-modal');
});

document.getElementById('fp-confirm').addEventListener('click', async () => {
  const caseId = document.getElementById('fp-case-id').textContent;
  closeModal('fp-modal');
  try {
    await kvPost('active_cases', caseId, { status: 'CLOSED', resolution: 'FALSE_POSITIVE', closed_by: 'analyst', closed_at: new Date().toISOString() });
    toast(`Case ${caseId} marked as false positive — submitted to Sage`, 'success');
    STATE.selectedCaseId = null;
    document.getElementById('override-controls').style.display = 'none';
    document.getElementById('inv-empty').classList.remove('hidden');
    await fetchAll();
  } catch (err) {
    toast(`Could not mark false positive: ${err.message}`, 'error');
  }
});

document.getElementById('fp-cancel').addEventListener('click', () => closeModal('fp-modal'));

// Refresh
document.getElementById('btn-refresh').addEventListener('click', fetchAll);

// Dead Letter Queue — "Review" jumps to the attention list and highlights it
document.getElementById('btn-dlq-review').addEventListener('click', () => {
  const block = document.getElementById('attention-block');
  if (!block) return;
  block.scrollIntoView({ behavior: 'smooth', block: 'center' });
  block.classList.add('highlight-flash');
  setTimeout(() => block.classList.remove('highlight-flash'), 1500);
});

/* =========================================================================
   Keyboard shortcuts
   ========================================================================= */

document.addEventListener('keydown', (e) => {
  // Ignore when focus is in a text field or modal is open
  if (e.target.matches('input, select, textarea, [contenteditable]')) return;
  if (document.querySelector('.modal-backdrop.open')) return;

  switch (e.key.toLowerCase()) {
    case 'h':
      if (STATE.selectedCaseId) document.getElementById('btn-halt').click();
      break;
    case 'e':
      if (STATE.selectedCaseId) document.getElementById('btn-escalate').click();
      break;
    case 'f':
      if (STATE.selectedCaseId) document.getElementById('btn-fp').click();
      break;
    case 'r':
      fetchAll();
      break;
    case '?':
      toast('Shortcuts: H=Halt  E=Escalate  F=False-Positive  R=Refresh', 'info', 5000);
      break;
    case 'escape':
      document.querySelectorAll('.modal-backdrop.open').forEach(m => m.classList.remove('open'));
      break;
  }
});

// Close modals when clicking the backdrop
document.querySelectorAll('.modal-backdrop').forEach(backdrop => {
  backdrop.addEventListener('click', e => {
    if (e.target === backdrop) backdrop.classList.remove('open');
  });
});

/* =========================================================================
   Modal helpers
   ========================================================================= */

function openModal(id) {
  const el = document.getElementById(id);
  el.classList.add('open');
  // Focus first focusable element
  const first = el.querySelector('button, [tabindex]:not([tabindex="-1"])');
  if (first) first.focus();
}

function closeModal(id) {
  document.getElementById(id).classList.remove('open');
}

/* =========================================================================
   Toast notifications
   ========================================================================= */

function toast(message, type = 'info', duration = 3500) {
  const container = document.getElementById('toast-container');
  const el = document.createElement('div');
  el.className = `toast ${type}`;
  el.textContent = message;
  el.setAttribute('role', 'alert');
  container.appendChild(el);

  setTimeout(() => {
    el.classList.add('fade-out');
    setTimeout(() => el.remove(), 320);
  }, duration);
}

/* =========================================================================
   Formatting utilities
   ========================================================================= */

function esc(str) {
  return String(str ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function formatAlertType(s) {
  // RANSOMWARE_POWERSHELL_ENCODED -> Ransomware: Powershell Encoded
  return s.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
}

function formatAge(seconds) {
  if (seconds < 60)   return `${Math.round(seconds)}s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
  return `${(seconds / 3600).toFixed(1)}h`;
}

function formatTimeShort(ts) {
  if (!ts) return '—';
  const d = new Date(typeof ts === 'number' ? ts * 1000 : ts);
  return isNaN(d) ? ts : d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

function capitalize(s) {
  return s ? s.charAt(0).toUpperCase() + s.slice(1) : '';
}

function agentColor(agent) {
  const map = { vanguard: 'var(--agent-vanguard)', sherlock: 'var(--agent-sherlock)', executor: 'var(--agent-executor)', sage: 'var(--agent-sage)' };
  return map[agent] || 'var(--text-secondary)';
}

function set(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = value;
}

/* =========================================================================
   SPL syntax highlighter (minimal, no regex engine)
   ========================================================================= */

function highlightSpl(spl) {
  const keywords = /\b(index|search|stats|eval|where|by|AS|count|sum|avg|max|min|rex|fields|table|sort|head|tail|dedup|rename|join|lookup|inputlookup|tstats|timechart|chart|transaction|bucket|convert|fillnull|mvexpand|spath|not|and|or)\b/gi;
  const pipes    = /\|/g;
  const strs     = /"[^"]*"|'[^']*'/g;
  const fns      = /\b(if|isnull|isnotnull|isnum|match|like|cidrmatch|tostring|tonumber|strftime|strptime|now|len|substr|replace|split|mvcount|mvindex|mvjoin|coalesce)\b/gi;
  const idxs     = /`[^`]+`/g;

  // Order matters — process in safe sequence
  return esc(spl)
    .replace(idxs,     m => `<span class="spl-idx">${m}</span>`)
    .replace(strs,     m => `<span class="spl-str">${m}</span>`)
    .replace(fns,      m => `<span class="spl-fn">${m}</span>`)
    .replace(keywords, m => `<span class="spl-kw">${m}</span>`)
    .replace(pipes,    () => '<span class="spl-pipe">|</span>');
}

/* =========================================================================
   Polling lifecycle
   ========================================================================= */

function startPolling() {
  fetchAll();
  STATE.pollTimer = setInterval(fetchAll, CFG.POLL_INTERVAL);
}

function stopPolling() {
  clearInterval(STATE.pollTimer);
  clearInterval(STATE.approvalTickTimer);
}

// Pause polling when tab is hidden (saves resources / API quota)
document.addEventListener('visibilitychange', () => {
  if (document.hidden) {
    stopPolling();
  } else {
    startPolling();
  }
});

/* =========================================================================
   Boot
   ========================================================================= */

document.addEventListener('DOMContentLoaded', () => {
  startPolling();
});

// Expose for Simple XML / other modules
window.WarRoom = { fetchAll, toast, selectCase, startPolling, stopPolling };
