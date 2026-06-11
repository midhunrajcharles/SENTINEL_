/**
 * SENTINEL — Case Timeline
 * case_timeline.js
 *
 * Renders a vertical, expandable, color-coded event timeline for individual
 * cases. Handles both the inline War Room timeline and the full-page timeline
 * view (/en-US/app/sentinel/case_detail?case_id=…).
 *
 * Public API:
 *   CaseTimeline.render(containerId, events, caseId)
 *   CaseTimeline.renderPage(caseId)    — full-page mode; fetches its own data
 *   CaseTimeline.exportJSON(caseId)
 *   CaseTimeline.exportPDF(caseId)
 *
 * Agent colour palette (matches sentinel_theme.css):
 *   vanguard → --agent-vanguard  (#2d7ef7)
 *   sherlock → --agent-sherlock  (#9b59b6)
 *   executor → --agent-executor  (#e74c3c)
 *   sage     → --agent-sage      (#27ae60)
 *   system   → text-muted
 *
 * Simple XML conversion:
 *   Wrap in a custom HTML panel and load via <dashboard script="case_timeline.js">.
 *   Call CaseTimeline.renderPage(token('case_id')) on page load.
 */

'use strict';

/* =========================================================================
   Constants
   ========================================================================= */

const CT_AGENT_COLORS = {
  vanguard: '#2d7ef7',
  sherlock: '#9b59b6',
  executor: '#e74c3c',
  sage:     '#27ae60',
  system:   '#4a6080',
};

const CT_EVENT_ICONS = {
  decision:   '&#x2713;',   // checkmark
  transition: '&#x2192;',   // arrow
  error:      '&#x26A0;',   // warning
  metric:     '&#x25CF;',   // circle
  enrichment: '&#x1F50E;',  // magnifier
  action:     '&#x26A1;',   // lightning
  default:    '&#x25CB;',   // empty circle
};

/* =========================================================================
   Normalise raw audit events into a consistent shape
   ========================================================================= */

function normaliseEvent(raw, index) {
  const agent      = (raw.agent_name || 'system').toLowerCase();
  const eventType  = raw.event_type || 'default';
  const ts         = raw.timestamp || raw._time || (Date.now() / 1000 - index * 30);
  const timeMs     = typeof ts === 'number' ? ts * 1000 : new Date(ts).getTime();

  return {
    id:          raw._key || raw.event_id || `ev-${index}`,
    agent,
    eventType,
    timeMs,
    timeISO:     new Date(timeMs).toISOString(),
    displayTime: new Date(timeMs).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
    fullTime:    new Date(timeMs).toLocaleString(),
    title:       buildEventTitle(raw, agent, eventType),
    summary:     buildEventSummary(raw, eventType),
    details:     raw,                         // full details for expanded view
    color:       CT_AGENT_COLORS[agent] || CT_AGENT_COLORS.system,
    icon:        CT_EVENT_ICONS[eventType]   || CT_EVENT_ICONS.default,
    severity:    raw.severity || '',
    raw,
  };
}

function buildEventTitle(raw, agent, eventType) {
  if (eventType === 'decision')   return `${capitalize(agent)}: ${raw.decision_type || 'Decision'}`;
  if (eventType === 'transition') return `State: ${raw.from_status || '?'} → ${raw.to_status || '?'}`;
  if (eventType === 'action')     return `${capitalize(agent)}: ${raw.action_type || 'Action'} on ${raw.target || '?'}`;
  if (eventType === 'error')      return `Error in ${capitalize(agent)}: ${raw.error_code || 'Unknown error'}`;
  if (eventType === 'enrichment') return `IOC Enrichment: ${raw.ioc_value || ''}`;
  if (eventType === 'metric')     return `Metric: ${raw.metric_name || ''}`;
  return raw.summary || raw.message || `${capitalize(agent)} event`;
}

function buildEventSummary(raw, eventType) {
  if (eventType === 'decision')   return raw.reasoning || raw.summary || '';
  if (eventType === 'transition') return `Latency: ${raw.latency_ms ? raw.latency_ms + ' ms' : '—'}`;
  if (eventType === 'action')     return `Status: ${raw.outcome || raw.status || '—'}`;
  if (eventType === 'error')      return raw.error_detail || raw.message || '';
  return raw.summary || raw.message || '';
}

function capitalize(s) {
  return s ? s.charAt(0).toUpperCase() + s.slice(1) : '';
}

/* =========================================================================
   Render inline timeline (inside war_room.html)
   ========================================================================= */

function render(containerId, rawEvents, caseId) {
  const container = document.getElementById(containerId);
  if (!container) return;

  // Sort events ascending by time
  const events = rawEvents
    .map((ev, i) => normaliseEvent(ev, i))
    .sort((a, b) => a.timeMs - b.timeMs);

  if (events.length === 0) {
    container.innerHTML = `<div style="color:var(--text-muted);font-size:0.8rem;padding:0.5rem">No timeline events yet</div>`;
    return;
  }

  container.innerHTML = events.map(ev => buildEventCard(ev)).join('');

  // Attach expand/collapse handlers
  container.querySelectorAll('.timeline-event-card').forEach(card => {
    card.addEventListener('click', () => {
      card.classList.toggle('expanded');
      const btn = card.querySelector('.ev-expand-btn');
      if (btn) btn.setAttribute('aria-expanded', card.classList.contains('expanded'));
    });

    card.addEventListener('keydown', e => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        card.click();
      }
    });
  });
}

function buildEventCard(ev) {
  const detailHtml = buildDetailHtml(ev);

  return `
    <div class="timeline-event ${ev.agent}" role="listitem" aria-label="${escHtml(ev.title)}">
      <div class="timeline-event-card" tabindex="0" role="button"
           aria-expanded="false" data-event-id="${escHtml(ev.id)}">
        <div class="ev-header">
          <div>
            <span style="color:${ev.color}; font-size:0.7rem; font-weight:700;
                  text-transform:uppercase; letter-spacing:0.06em; margin-right:0.4rem">
              ${escHtml(capitalize(ev.agent))}
            </span>
            <span class="ev-title">${escHtml(ev.title)}</span>
          </div>
          <span class="ev-time" title="${escHtml(ev.fullTime)}">${escHtml(ev.displayTime)}</span>
        </div>
        ${ev.summary ? `<div class="ev-body">${escHtml(ev.summary)}</div>` : ''}
        <div class="ev-detail" aria-hidden="true">
          ${detailHtml}
        </div>
      </div>
    </div>`;
}

function buildDetailHtml(ev) {
  const parts = [];
  const r = ev.raw;

  // SPL query if present
  const spl = r.spl_query || r.query || r.spl_used || '';
  if (spl) {
    parts.push(`<div style="margin-bottom:0.5rem">
      <div style="font-size:0.62rem; text-transform:uppercase; letter-spacing:0.1em;
           color:var(--text-muted); margin-bottom:0.3rem">SPL Query</div>
      <pre style="background:#050d18; border-radius:4px; padding:0.5rem;
           font-size:0.72rem; color:var(--text-code); overflow-x:auto; white-space:pre-wrap">${escHtml(spl)}</pre>
    </div>`);
  }

  // Query results summary
  const results = r.query_results || r.results || r.result_count;
  if (results !== undefined) {
    parts.push(`<div style="font-size:0.75rem; color:var(--text-secondary)">
      Results: <strong>${typeof results === 'object' ? JSON.stringify(results).slice(0, 80) : results}</strong>
    </div>`);
  }

  // Agent reasoning / confidence
  if (r.reasoning) {
    parts.push(`<div style="margin-top:0.4rem">
      <div style="font-size:0.62rem; text-transform:uppercase; letter-spacing:0.1em;
           color:var(--text-muted); margin-bottom:0.2rem">Agent Reasoning</div>
      <div style="font-size:0.75rem; color:var(--text-secondary); line-height:1.5">${escHtml(r.reasoning)}</div>
    </div>`);
  }

  if (r.confidence !== undefined) {
    parts.push(`<div style="font-size:0.72rem; margin-top:0.3rem">
      Confidence: <strong style="color:${confidenceColor(r.confidence)}">${(r.confidence * 100).toFixed(0)}%</strong>
    </div>`);
  }

  // Action verification
  if (r.verification) {
    const v = r.verification;
    parts.push(`<div style="margin-top:0.4rem; font-size:0.72rem">
      Verification: <strong style="color:${v.verified ? 'var(--low)' : 'var(--critical)'}">${v.verified ? 'CONFIRMED' : 'UNVERIFIED'}</strong>
      ${v.pre_state ? ` &middot; ${escHtml(v.pre_state)} → ${escHtml(v.post_state || '?')}` : ''}
    </div>`);
  }

  // Full JSON dump as fallback
  if (parts.length === 0) {
    const safeJson = JSON.stringify(r, null, 2).slice(0, 500);
    parts.push(`<pre style="font-size:0.68rem; color:var(--text-muted); overflow:auto; max-height:120px">${escHtml(safeJson)}</pre>`);
  }

  // Export row
  parts.push(`<div style="margin-top:0.6rem; padding-top:0.5rem; border-top:1px solid var(--border-subtle);
       display:flex; gap:0.5rem;">
    <button class="btn btn-ghost btn-sm" onclick="CaseTimeline.copyEventJSON('${escHtml(ev.id)}')"
            style="font-size:0.65rem">Copy JSON</button>
  </div>`);

  return parts.join('');
}

function confidenceColor(conf) {
  if (conf >= 0.85) return 'var(--low)';
  if (conf >= 0.65) return 'var(--medium)';
  return 'var(--critical)';
}

/* =========================================================================
   Full-page timeline (case_detail page)
   ========================================================================= */

async function renderPage(caseId) {
  if (!caseId) {
    showPageError('No case ID provided');
    return;
  }

  const container = document.getElementById('page-timeline-container');
  if (!container) return;

  container.innerHTML = '<div style="padding:2rem; color:var(--text-muted)">Loading timeline…</div>';

  try {
    // Fetch audit events for this case from KV Store / search
    const events = await fetchCaseEvents(caseId);
    updatePageHeader(caseId, events);
    render('page-timeline-container', events, caseId);
    updateCaseDetailSidebar(caseId, events);
  } catch (err) {
    showPageError(`Failed to load case ${caseId}: ${err.message}`);
  }
}

async function fetchCaseEvents(caseId) {
  // Try KV Store first (fast path for active cases)
  try {
    const base = window.CFG?.SPLUNK_BASE || '';
    const sessionKey = window.SPLUNK_SESSION_KEY || '';
    const url = `${base}/en-US/splunkd/servicesNS/nobody/sentinel/storage/collections/data/active_cases/${encodeURIComponent(caseId)}`;
    const r = await fetch(url, {
      headers: { 'Authorization': `Splunk ${sessionKey}`, 'X-Requested-With': 'XMLHttpRequest' }
    });
    if (r.ok) {
      const doc = await r.json();
      return doc.audit_trail || [];
    }
  } catch (_) { /* fall through to search */ }

  // Fall back to sentinel_audit index search
  const rows = await splunkSearchEvents(caseId);
  return rows;
}

async function splunkSearchEvents(caseId) {
  const sessionKey = window.SPLUNK_SESSION_KEY || '';
  const base = window.CFG?.SPLUNK_BASE || '';
  const body = new URLSearchParams({
    search: `search index=sentinel_audit case_id="${caseId}" | sort _time | head 200`,
    earliest_time: '-30d',
    latest_time: 'now',
    output_mode: 'json',
    count: '200',
  });
  const r = await fetch(`${base}/en-US/splunkd/services/search/jobs/export`, {
    method: 'POST',
    headers: { 'Authorization': `Splunk ${sessionKey}`, 'X-Requested-With': 'XMLHttpRequest' },
    body,
  });
  if (!r.ok) return [];
  const text = await r.text();
  return text.trim().split('\n')
    .map(line => { try { return JSON.parse(line).result; } catch { return null; } })
    .filter(Boolean);
}

function updatePageHeader(caseId, events) {
  const el = document.getElementById('page-case-title');
  if (el) el.textContent = `Case Timeline — ${caseId}`;
  const countEl = document.getElementById('page-event-count');
  if (countEl) countEl.textContent = `${events.length} events`;
}

function updateCaseDetailSidebar(caseId, events) {
  const agentCounts = {};
  events.forEach(ev => {
    const a = ev.agent_name || 'system';
    agentCounts[a] = (agentCounts[a] || 0) + 1;
  });

  const el = document.getElementById('page-agent-breakdown');
  if (!el) return;
  el.innerHTML = Object.entries(agentCounts).map(([agent, count]) =>
    `<div style="display:flex; justify-content:space-between; font-size:0.78rem; margin-bottom:0.3rem">
      <span style="color:${CT_AGENT_COLORS[agent] || 'var(--text-muted)'}">${capitalize(agent)}</span>
      <span class="text-mono">${count}</span>
    </div>`
  ).join('');
}

function showPageError(msg) {
  const c = document.getElementById('page-timeline-container');
  if (c) c.innerHTML = `<div style="color:var(--critical); padding:2rem">${escHtml(msg)}</div>`;
}

/* =========================================================================
   Export functions
   ========================================================================= */

// Per-event JSON copy (called from inline button)
function copyEventJSON(eventId) {
  const card = document.querySelector(`[data-event-id="${eventId}"]`);
  if (!card) return;
  const text = card.querySelector('pre')?.textContent || eventId;
  navigator.clipboard.writeText(text).then(() => {
    if (window.WarRoom) window.WarRoom.toast('Copied to clipboard', 'success');
  });
}

// Export full case as JSON
function exportJSON(caseId) {
  fetchCaseEvents(caseId).then(events => {
    const data = { case_id: caseId, exported_at: new Date().toISOString(), events };
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    triggerDownload(blob, `SENTINEL_case_${caseId}.json`);
  });
}

// Export case timeline as printable HTML (no pdf dependency)
function exportPDF(caseId) {
  fetchCaseEvents(caseId).then(events => {
    const normalized = events.map((ev, i) => normaliseEvent(ev, i)).sort((a, b) => a.timeMs - b.timeMs);
    const html = buildPrintableReport(caseId, normalized);
    const blob = new Blob([html], { type: 'text/html' });
    const url  = URL.createObjectURL(blob);
    const win  = window.open(url);
    if (win) {
      win.addEventListener('load', () => { win.print(); });
    }
  });
}

function buildPrintableReport(caseId, events) {
  const rows = events.map(ev => `
    <tr style="border-bottom:1px solid #ddd">
      <td style="padding:6px 8px; white-space:nowrap; color:#555; font-family:monospace; font-size:12px">${ev.displayTime}</td>
      <td style="padding:6px 8px; font-weight:600; color:${ev.color}">${capitalize(ev.agent)}</td>
      <td style="padding:6px 8px">${ev.title}</td>
      <td style="padding:6px 8px; color:#555; font-size:12px">${ev.summary}</td>
    </tr>`).join('');

  return `<!DOCTYPE html>
<html><head><meta charset="UTF-8">
<title>SENTINEL Incident Report — ${caseId}</title>
<style>
  body { font-family: Arial, sans-serif; margin: 2cm; color: #222; }
  h1 { font-size: 18px; margin-bottom: 4px; }
  h2 { font-size: 13px; color: #555; margin-bottom: 16px; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  thead th { background: #f0f0f0; padding: 6px 8px; text-align: left; border-bottom: 2px solid #999; }
  @page { margin: 1.5cm; }
  @media print { body { margin: 0; } }
</style>
</head><body>
<h1>SENTINEL Incident Timeline</h1>
<h2>Case: ${escHtml(caseId)} &nbsp;&middot;&nbsp; Exported: ${new Date().toLocaleString()}</h2>
<table>
  <thead><tr><th>Time</th><th>Agent</th><th>Event</th><th>Summary</th></tr></thead>
  <tbody>${rows}</tbody>
</table>
</body></html>`;
}

function triggerDownload(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a   = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 5000);
}

/* =========================================================================
   Utility
   ========================================================================= */

function escHtml(str) {
  return String(str ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/* =========================================================================
   Public API
   ========================================================================= */

window.CaseTimeline = { render, renderPage, exportJSON, exportPDF, copyEventJSON };
