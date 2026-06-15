/**
 * SENTINEL War Room — Mock API for the standalone live demo
 * sentinel_mock_api.js
 *
 * Patches window.fetch so war_room.js, agent_status.js, and
 * agent_visualization.js — which all talk to Splunk's KV Store, the
 * search/jobs/export endpoint, and the sentinel approval REST surface —
 * receive synthetic data instead. Must be loaded BEFORE those scripts.
 *
 * A periodic tick mutates the in-memory case list slightly (query
 * progress, a new activity-feed entry, a new MCP tool call) so the
 * dashboard feels "live" across poll cycles.
 */
'use strict';

(function () {
  const now = () => Date.now() / 1000;
  const BOOT = now();
  const HOST_BY_CASE = {};

  /* =====================================================================
     Seed data — active cases
     ===================================================================== */
  const CASES = [
    {
      case_id: 'CASE-2026-0512',
      alert_type: 'RANSOMWARE_POWERSHELL_ENCODED',
      primary_host: 'WORKSTATION-07',
      risk_score: 92,
      status: 'INVESTIGATING',
      current_agent: 'sherlock',
      current_phase: 'Sherlock collecting process lineage',
      current_spl: 'search index=sentinel_endpoint host="WORKSTATION-07" earliest=-1h\n| search process_name=powershell.exe\n| stats count by parent_process_name, command_line\n| sort -count',
      query_progress_pct: 38,
      classification: 'Likely Ransomware Precursor',
      created_time: BOOT - 540,
      audit_trail: [
        { timestamp: BOOT - 540, agent_name: 'vanguard', summary: 'Alert ingested: encoded PowerShell launched from outlook.exe' },
        { timestamp: BOOT - 480, agent_name: 'vanguard', decision_type: 'ESCALATE_TO_SHERLOCK', summary: 'Composite score 92 — escalating for full investigation' },
        { timestamp: BOOT - 360, agent_name: 'sherlock', summary: 'Pulled process tree for WORKSTATION-07 (last 60m)' },
        { timestamp: BOOT - 180, agent_name: 'sherlock', summary: 'Found lsass.exe memory access from spawned powershell.exe' },
      ],
      vanguard_decision: {
        spl_used: 'search index=sentinel_endpoint host="WORKSTATION-07" process_name=powershell.exe earliest=-15m',
        chain_of_thought: [
          {
            step: 1, name: 'Initial Alert Triage',
            observation: 'powershell.exe spawned by outlook.exe with -enc flag, base64 command line',
            query: 'index=sentinel_endpoint host="WORKSTATION-07" process_name=powershell.exe earliest=-15m',
            justification: 'Office apps spawning encoded PowerShell is a top ransomware-precursor pattern',
            inference: 'High likelihood of malicious macro / dropper execution',
            risk_matrix: { likelihood: 'high', impact: 'critical' },
            conclusion: 'Composite score 92 (critical) — escalate to Sherlock for full investigation',
            action: 'ESCALATE_TO_SHERLOCK',
          },
        ],
      },
      sherlock_report: {
        investigation_chain: [
          {
            step: 1, name: 'Process Lineage Review',
            query: 'index=sentinel_endpoint host="WORKSTATION-07" earliest=-1h | stats count by parent_process_name, command_line',
            observation: 'powershell.exe -nop -w hidden -enc <base64> launched by outlook.exe',
            result: '1 matching process chain, 3 child processes spawned within 90s',
            inference: 'Consistent with malicious macro execution dropping a second-stage payload',
          },
          {
            step: 2, name: 'Credential Access Check',
            query: 'index=sentinel_endpoint host="WORKSTATION-07" target_process_name=lsass.exe earliest=-1h',
            observation: 'powershell.exe opened a handle to lsass.exe with access_mask 0x1010',
            verification_query: 'index=sentinel_endpoint host="WORKSTATION-07" target_process_name=lsass.exe | stats count by access_mask',
            verification_result: '1 access event, access_mask 0x1010 (PROCESS_VM_READ | PROCESS_QUERY_INFORMATION)',
            inference: 'Likely credential-dumping attempt (Mimikatz-style LSASS access)',
          },
        ],
      },
    },
    {
      case_id: 'CASE-2026-0511',
      alert_type: 'SUSPICIOUS_LOGON_ANOMALY',
      primary_host: 'DC-01',
      risk_score: 78,
      status: 'DECIDING',
      current_agent: 'vanguard',
      current_phase: 'Vanguard scoring anomalous logon pattern',
      current_spl: 'search index=sentinel_auth dest="DC-01" earliest=-4h\n| stats dc(src) AS distinct_sources, count by user\n| where distinct_sources > 3',
      query_progress_pct: 71,
      classification: 'Anomalous Authentication',
      created_time: BOOT - 300,
      audit_trail: [
        { timestamp: BOOT - 300, agent_name: 'vanguard', summary: 'Alert ingested: jdoe authenticated from 4 distinct workstations in 10 minutes' },
        { timestamp: BOOT - 180, agent_name: 'vanguard', summary: 'Cross-referencing against baseline login locations for jdoe' },
      ],
      vanguard_decision: {
        spl_used: 'search index=sentinel_auth dest="DC-01" user="jdoe" earliest=-4h',
        chain_of_thought: [
          {
            step: 1, name: 'Baseline Comparison',
            observation: 'jdoe normally authenticates from WORKSTATION-07 only; 4 distinct sources observed in 10 minutes',
            query: 'index=sentinel_auth dest="DC-01" earliest=-4h | stats dc(src) AS distinct_sources by user',
            justification: 'Rapid multi-host authentication is consistent with credential replay / pass-the-hash',
            risk_matrix: { likelihood: 'medium', impact: 'high' },
          },
        ],
      },
    },
    {
      case_id: 'CASE-2026-0510',
      alert_type: 'LATERAL_MOVEMENT_SMB',
      primary_host: 'FILESRV-02',
      risk_score: 88,
      status: 'RESPONDING',
      current_agent: 'executor',
      current_phase: 'Executor isolating host pending approval',
      current_spl: '| makeresults\n| eval action="isolate_host", target="FILESRV-02", status="awaiting_approval"',
      query_progress_pct: 55,
      classification: 'Lateral Movement — SMB',
      created_time: BOOT - 720,
      audit_trail: [
        { timestamp: BOOT - 720, agent_name: 'vanguard', summary: 'Alert ingested: anomalous SMB session from WORKSTATION-07 to FILESRV-02' },
        { timestamp: BOOT - 600, agent_name: 'sherlock', summary: 'Confirmed PsExec-style service creation on FILESRV-02' },
        { timestamp: BOOT - 420, agent_name: 'sherlock', decision_type: 'CONTAIN', summary: 'Recommending host isolation for FILESRV-02' },
        { timestamp: BOOT - 240, agent_name: 'executor', summary: 'Containment action queued — awaiting human approval (CONTAINMENT_APPROVED band)' },
      ],
      executor_actions: [
        {
          action_chain: [
            {
              step: 1, name: 'Containment Plan',
              target: 'FILESRV-02',
              action: 'isolate_host',
              pre_state: 'connected',
              post_state: 'isolated (pending)',
              rollback_timer: 1800,
              human_notified: true,
              requires_manager_approval: true,
              justification: 'Active lateral movement via SMB with service creation — isolate to stop spread',
            },
          ],
        },
      ],
    },
    {
      case_id: 'CASE-2026-0509',
      alert_type: 'PHISHING_CREDENTIAL_HARVEST',
      primary_host: 'MAIL-GW',
      risk_score: 65,
      status: 'QUEUED',
      current_agent: '—',
      classification: '',
      created_time: BOOT - 90,
      audit_trail: [
        { timestamp: BOOT - 90, agent_name: 'vanguard', summary: 'Alert ingested: credential-harvesting link clicked by 3 users' },
      ],
    },
    {
      case_id: 'CASE-2026-0508',
      alert_type: 'DATA_EXFIL_DNS_TUNNEL',
      primary_host: 'WORKSTATION-12',
      risk_score: 95,
      status: 'STUCK',
      current_agent: 'sherlock',
      classification: 'Possible DNS Tunneling',
      created_time: BOOT - 5400,
      audit_trail: [
        { timestamp: BOOT - 5400, agent_name: 'vanguard', summary: 'Alert ingested: high-entropy DNS queries to *.exfil-test.io' },
        { timestamp: BOOT - 5100, agent_name: 'sherlock', summary: 'Investigation started — pulling DNS resolution history' },
        { timestamp: BOOT - 4800, agent_name: 'sherlock', summary: 'MCP tool call timed out (splunk_search) — retrying' },
      ],
    },
    {
      case_id: 'CASE-2026-0507',
      alert_type: 'BRUTE_FORCE_RDP',
      primary_host: 'JUMP-01',
      risk_score: 58,
      status: 'DEAD_LETTER',
      current_agent: 'executor',
      classification: 'Brute Force — RDP',
      created_time: BOOT - 9000,
      audit_trail: [
        { timestamp: BOOT - 9000, agent_name: 'vanguard', summary: 'Alert ingested: 200+ failed RDP logons against JUMP-01' },
        { timestamp: BOOT - 8700, agent_name: 'executor', summary: 'Containment action failed after 3 retries — moved to dead-letter queue' },
      ],
    },
    {
      case_id: 'CASE-2026-0506',
      alert_type: 'MALWARE_DROPPER_TEMP',
      primary_host: 'WORKSTATION-03',
      risk_score: 40,
      status: 'CLOSED',
      current_agent: 'sage',
      classification: 'False Positive — Signed Installer',
      created_time: BOOT - 14400,
      resolution: 'FALSE_POSITIVE',
      audit_trail: [
        { timestamp: BOOT - 14400, agent_name: 'vanguard', summary: 'Alert ingested: unsigned binary written to %TEMP%' },
        { timestamp: BOOT - 13800, agent_name: 'sherlock', summary: 'Binary verified as signed installer for approved software package' },
        { timestamp: BOOT - 13200, agent_name: 'sage', summary: 'Closed as false positive — detection rule tuning proposed' },
      ],
    },
  ];

  CASES.forEach(c => { HOST_BY_CASE[c.case_id] = c.primary_host; });

  /* =====================================================================
     Seed data — pending human-in-the-loop approvals
     ===================================================================== */
  let APPROVALS = [
    {
      request_id: 'APR-2026-0044',
      case_id: 'CASE-2026-0510',
      action: 'isolate_host',
      target: 'FILESRV-02',
      expires_at: new Date((BOOT + 270) * 1000).toISOString(),
    },
  ];

  /* =====================================================================
     Seed data — per-agent metrics (mirrors the sentinel_audit stats search)
     ===================================================================== */
  const AGENT_METRICS = [
    { agent_name: 'vanguard', decisions: 14, conf: 0.81, lat: 1850, errors: 0, last_action: 'ESCALATE_TO_SHERLOCK' },
    { agent_name: 'sherlock', decisions: 6,  conf: 0.74, lat: 9200, errors: 1, last_action: 'INVESTIGATION_COMPLETE' },
    { agent_name: 'executor', decisions: 3,  conf: 0.90, lat: 4100, errors: 0, last_action: 'CONTAIN', rollbacks: 0 },
    { agent_name: 'sage',     decisions: 1,  conf: 0.95, lat: 600,  errors: 0, iocs_submitted: 4, rules_proposed: 1, fp_rate: 0.08 },
  ];

  /* =====================================================================
     Seed data — MCP tool call log
     ===================================================================== */
  const MCP_TOOLS = ['splunk_search', 'kv_store_get', 'kv_store_put', 'isolate_host', 'enrich_threat_intel', 'audit_log_write'];
  let MCP_LOG = [
    { _time: BOOT - 60,  agent_name: 'sherlock', tool_name: 'splunk_search',      case_id: 'CASE-2026-0512', success: true,  duration_ms: 820 },
    { _time: BOOT - 95,  agent_name: 'vanguard', tool_name: 'kv_store_put',       case_id: 'CASE-2026-0511', success: true,  duration_ms: 110 },
    { _time: BOOT - 130, agent_name: 'sherlock', tool_name: 'enrich_threat_intel', case_id: 'CASE-2026-0512', success: true,  duration_ms: 640 },
    { _time: BOOT - 200, agent_name: 'sherlock', tool_name: 'splunk_search',      case_id: 'CASE-2026-0508', success: false, duration_ms: 30000, error: 'search job timeout' },
    { _time: BOOT - 260, agent_name: 'executor', tool_name: 'kv_store_get',       case_id: 'CASE-2026-0510', success: true,  duration_ms: 95 },
  ];

  /* =====================================================================
     fetch interception
     ===================================================================== */
  const realFetch = window.fetch.bind(window);

  function jsonResponse(data) {
    return Promise.resolve(new Response(JSON.stringify(data), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    }));
  }

  function ndjsonResponse(rows) {
    const body = (rows || []).map(r => JSON.stringify({ result: r })).join('\n');
    return Promise.resolve(new Response(body, {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    }));
  }

  function dailyMetrics() {
    const active = CASES.filter(c => !['CLOSED', 'SUPPRESSED'].includes(c.status));
    return {
      total: CASES.length,
      autonomous: CASES.filter(c => ['CLOSED', 'RESPONDING'].includes(c.status)).length,
      escalated: CASES.filter(c => c.status === 'DECIDING' || c.status === 'STUCK').length,
      avg_mttr: 11.4,
      contained: CASES.filter(c => c.status === 'CLOSED' && c.resolution !== 'FALSE_POSITIVE').length,
    };
  }

  function weeklyMetrics() {
    return {
      contained_week: 9,
      fp_week: 1,
      total_week: 23,
    };
  }

  window.fetch = function (url, opts) {
    const u = String(url);
    opts = opts || {};

    /* --- KV Store: active_cases collection / individual docs ----------- */
    if (u.includes('/storage/collections/data/active_cases')) {
      const m = u.match(/active_cases\/([^/?]+)/);
      if (m && opts.method === 'POST') {
        const id = decodeURIComponent(m[1]);
        const patch = JSON.parse(opts.body || '{}');
        const c = CASES.find(c => c.case_id === id);
        if (c) Object.assign(c, patch);
        return jsonResponse({ ok: true, _id: id });
      }
      if (m) {
        const id = decodeURIComponent(m[1]);
        const c = CASES.find(c => c.case_id === id);
        return jsonResponse(c || {});
      }
      return jsonResponse(CASES);
    }

    /* --- Search export (SPL) -------------------------------------------- */
    if (u.includes('/services/search/jobs/export')) {
      const body = new URLSearchParams(opts.body || '');
      const search = body.get('search') || '';
      const earliest = body.get('earliest_time') || '';

      if (search.includes('sentinel_metrics')) {
        return ndjsonResponse([earliest === '-7d' ? weeklyMetrics() : dailyMetrics()]);
      }
      if (search.includes('event_type=mcp_call')) {
        const rows = [...MCP_LOG].sort((a, b) => b._time - a._time).slice(0, 20)
          .map(r => ({ ...r, success: r.success ? '1' : '0' }));
        return ndjsonResponse(rows);
      }
      if (search.includes('event_type=decision')) {
        return ndjsonResponse(AGENT_METRICS);
      }
      if (search.includes('index=sentinel_audit')) {
        // Per-case audit search (full timeline page) — not used by War Room
        return ndjsonResponse([]);
      }
      return ndjsonResponse([]);
    }

    /* --- SENTINEL approval REST surface --------------------------------- */
    if (u.includes('/sentinel/approval/pending')) {
      return jsonResponse({ pending: APPROVALS });
    }
    const apprMatch = u.match(/\/sentinel\/approval\/([^/]+)\/(approve|deny)/);
    if (apprMatch) {
      const requestId = decodeURIComponent(apprMatch[1]);
      const decision = apprMatch[2];
      const req = APPROVALS.find(r => r.request_id === requestId);
      APPROVALS = APPROVALS.filter(r => r.request_id !== requestId);
      if (req && decision === 'approve') {
        const c = CASES.find(c => c.case_id === req.case_id);
        if (c) {
          c.status = 'RESPONDING';
          c.audit_trail.push({
            timestamp: now(), agent_name: 'executor',
            summary: `Approval granted for ${req.action} on ${req.target} — executing containment`,
          });
        }
      }
      return jsonResponse({ ok: true });
    }

    // Fall through to the real network for anything else (e.g. Chart.js CDN)
    return realFetch(url, opts);
  };

  /* =====================================================================
     "Live" tick — gently mutates state every few seconds so repeated
     polls show progress, new activity, and fresh MCP log entries.
     ===================================================================== */
  setInterval(() => {
    const t = now();

    // Advance query progress on the actively-investigating case
    const investigating = CASES.find(c => c.case_id === 'CASE-2026-0512');
    if (investigating && investigating.query_progress_pct < 95) {
      investigating.query_progress_pct = Math.min(95, investigating.query_progress_pct + Math.round(2 + Math.random() * 5));
    }

    // Append a fresh MCP tool call
    const agents = ['vanguard', 'sherlock', 'executor'];
    const agent = agents[Math.floor(Math.random() * agents.length)];
    const tool = MCP_TOOLS[Math.floor(Math.random() * MCP_TOOLS.length)];
    const caseIds = CASES.filter(c => !['CLOSED', 'SUPPRESSED'].includes(c.status)).map(c => c.case_id);
    MCP_LOG.push({
      _time: t,
      agent_name: agent,
      tool_name: tool,
      case_id: caseIds[Math.floor(Math.random() * caseIds.length)],
      success: Math.random() > 0.08,
      duration_ms: Math.round(80 + Math.random() * 2000),
    });
    if (MCP_LOG.length > 50) MCP_LOG = MCP_LOG.slice(-50);

    // Bump the active investigation's audit trail occasionally
    if (investigating && Math.random() > 0.6) {
      investigating.audit_trail.push({
        timestamp: t, agent_name: 'sherlock',
        summary: `Query progress ${investigating.query_progress_pct}% — reviewing additional process telemetry`,
      });
    }
  }, 6000);

  console.info('[SENTINEL DEMO] Mock API active — window.fetch intercepted for Splunk endpoints.');
})();
