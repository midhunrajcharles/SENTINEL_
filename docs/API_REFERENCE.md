# SENTINEL API Reference

Complete reference for all classes, methods, MCP tools, and JSON schemas.

---

## Table of Contents

1. [SentinelOrchestrator](#sentinelorchestrator)
2. [VanguardAgent](#vanguardagent)
3. [SherlockAgent](#sherlock-agent)
4. [ExecutorAgent](#executoragent)
5. [SageAgent](#sageagent)
6. [SplunkMCPClient](#splunkmcpclient)
7. [CaseStateManager](#casestatemanager)
8. [AuditLogger](#auditlogger)
9. [MCP Tool Specifications](#mcp-tool-specifications)
10. [JSON Schemas](#json-schemas)

---

## SentinelOrchestrator

`app/sentinel/bin/sentinel_orchestrator.py`

The main orchestration engine. Drives the case state machine, manages the work queue, and coordinates all four agents.

### Constructor

```python
SentinelOrchestrator(
    state_manager:  CaseStateManager | None = None,
    max_concurrent: int  = 5,
    poll_interval:  int  = 60,
    dry_run:        bool = False,
)
```

| Parameter | Default | Description |
|-----------|---------|-------------|
| `state_manager` | `None` | Injected `CaseStateManager`; creates one from config if `None` |
| `max_concurrent` | `5` | Maximum cases processed simultaneously (bounded semaphore) |
| `poll_interval` | `60` | Seconds between KV Store queue polls |
| `dry_run` | `False` | When `True`, agents run but response actions are no-ops |

### Methods

#### `process_alert(alert_id, alert_type, *, affected_host="", affected_user="", risk_score=0, priority="MEDIUM", raw_data=None) → str`

Creates a case and enqueues it for processing. Returns the `case_id`.

```python
case_id = orch.process_alert(
    alert_id     = "ES-NOTABLE-001",
    alert_type   = "RANSOMWARE_POWERSHELL_ENCODED",
    affected_host= "DESKTOP-ABC123",
    affected_user= "CORP\\jdoe",
    risk_score   = 88,
    priority     = "HIGH",
    raw_data     = {"raw_alert_fields": "..."},
)
```

#### `halt_case(case_id: str, reason: str) → Case`

Immediately transitions a case to `HALTED`, stopping any in-progress agent.
All subsequent agent actions check `case.status == HALTED` before executing.

#### `resume_case(case_id: str) → Case`

Returns a halted case to its previous state and re-enqueues it.

#### `transition(case_id: str, to_status: CaseStatus, detail: str = "") → Case`

Delegates to `CaseStateManager.transition()`. Logs an audit event at every call.

#### `stop() → None`

Sets the internal stop event, causing all worker threads to exit gracefully after their current case completes.

### Constants

```python
MAX_CONCURRENT_CASES  = 5
MAX_RETRIES_PER_CASE  = 3
POLL_INTERVAL_SECONDS = 60
AUTO_RESPOND_SCORE    = 90   # Executor acts without approval above this score

_PRIORITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
```

### State Machine

```
QUEUED ──► TRIAGING ──► INVESTIGATING ──► DECIDING ──► RESPONDING ──► LEARNING ──► CLOSED
              │                                │
              └─ (score < threshold) ─────────► CLOSED (suppressed)
                                               └─ (needs approval) ──► HALTED
Any state ──► ERROR (retry up to 3×) ──► previous state | CLOSED (escalated)
Any state ──► HALTED ──► (analyst resumes) ──► previous state
```

---

## VanguardAgent

`app/sentinel/bin/agent_vanguard.py`

Triage agent. Classifies alerts using Foundation-Sec-1.1-8B-Instruct and rule-based fallbacks.

### Entry Point (called by orchestrator)

```python
result: dict = run(case: Case, audit: AuditLogger) → dict
```

### Constructor

```python
VanguardAgent(mcp_client: SplunkMCPClient, audit: AuditLogger)
```

### Return Schema

```json
{
  "success":         true,
  "decision":        { /* VanguardDecisionPacket — see JSON Schemas */ },
  "risk_score":      88,
  "classification":  "RANSOMWARE_INITIAL_ACCESS",
  "mitre_tactic":    "TA0002",
  "mitre_technique": "T1059.001"
}
```

### Decision Thresholds

```python
class Decision:
    AUTO_DISMISS  = "AUTO_DISMISS"   # score  0–15
    QUEUE_LOW     = "QUEUE_LOW"      # score 16–54
    QUEUE_MED     = "QUEUE_MED"      # score 55–69
    QUEUE_HIGH    = "QUEUE_HIGH"     # score 70–84
    AUTO_ESCALATE = "AUTO_ESCALATE"  # score 85–100

_DECISION_THRESHOLDS = [
    (85, Decision.AUTO_ESCALATE),
    (70, Decision.QUEUE_HIGH),
    (55, Decision.QUEUE_MED),
    (16, Decision.QUEUE_LOW),
    (0,  Decision.AUTO_DISMISS),
]
```

### Asset Criticality Multipliers

```python
_ASSET_MULTIPLIERS = {
    "CRITICAL": 1.5,
    "HIGH":     1.2,
    "MEDIUM":   1.0,
    "LOW":      0.5,
    "UNKNOWN":  1.0,
}
```

The composite score is clamped to `[0, 100]` after multiplier application.

### Standalone Test Mode

```bash
python agent_vanguard.py --test
python agent_vanguard.py --test --scenario ransomware
python agent_vanguard.py --test --scenario insider_threat
python agent_vanguard.py --test --scenario false_positive
```

---

## SherlockAgent

`app/sentinel/bin/agent_sherlock.py`

Investigation agent. Runs a 5-phase deep-dive and produces a structured report.

### Entry Point

```python
result: dict = run(case: Case, audit: AuditLogger) → dict
```

Returns `{"success": bool, "case_id": str, "report": dict}` where `report` is a serialised `SherlockInvestigationReport`.

### Investigation Phases

| Phase | Name | MCP Tools Used |
|-------|------|----------------|
| A | Host Context | `get_asset_context`, `get_process_tree` |
| B | Timeline Reconstruction | `search_spl` (EDR/Sysmon timeline) |
| C | Lateral Movement | `get_network_flows`, `query_es_notable` |
| D | Identity Analysis | `get_user_activity` |
| E | Threat Intelligence | `enrich_threat_intel` |

Phase B uses SAIA to generate SPL if available; falls back to built-in templates.
Phases C and D are skipped when Phase A returns no process telemetry (adaptive investigation).

### Key Data Classes

#### `BlastRadius`

```python
@dataclass
class BlastRadius:
    compromised_hosts:          List[str]
    targeted_hosts:             List[str]
    suspected_hosts:            List[str]
    compromised_users:          List[str]
    affected_services:          List[str]
    data_at_risk:               List[str]
    estimated_dwell_time_minutes: int
```

#### `InvestigationContext` (accumulator)

```python
ctx = InvestigationContext()
ctx.add_host("DESKTOP-ABC123")       # deduplicates
ctx.add_user("CORP\\jdoe")          # lowercases + deduplicates
ctx.add_ioc("185.220.101.42", "ip") # deduplicates by value
ctx.record_source("edr")            # tracks which data sources responded
```

### Exception Hierarchy

```
SherlockError
  ├── SherlockSAIAError    # SAIA endpoint unavailable or returned invalid SPL
  ├── SherlockQueryError   # MCP tool call failed during investigation
  └── SherlockModelError   # Foundation-Sec model unavailable during synthesis
```

---

## ExecutorAgent

`app/sentinel/bin/agent_executor.py`

Response agent. Translates recommended actions into containment and eradication steps.

### Entry Point

```python
result: dict = run(case: Case, audit: AuditLogger) → dict
```

Returns a serialised `ExecutorActionLog` (see JSON Schemas).

### Autonomy Modes

| Mode | Risk Score | Actions Permitted |
|------|-----------|-------------------|
| `FULL_AUTONOMY` | 85–100 | All actions: containment + eradication + documentation |
| `CONTAINMENT_ONLY` | 70–84 | `isolate_host`, `block_ip`, `kill_process`, documentation |
| `MONITORING_ONLY` | 55–69 | Documentation only; no active response |
| `DOCUMENT_ONLY` | < 55 | `create_ticket`, `notify_stakeholders` only |

### Action Sets

```python
_CONTAINMENT_ACTIONS   = {"isolate_host", "block_ip", "kill_process"}
_ERADICATION_ACTIONS   = {"disable_user", "quarantine_file", "revoke_session", "rotate_credentials"}
_DOCUMENTATION_ACTIONS = {"create_ticket", "notify_stakeholders", "trigger_playbook"}
```

### Safety Mechanisms

| Mechanism | Constant | Behaviour |
|-----------|----------|-----------|
| Rate limiter | 10 actions / 3600s | 11th action is `SKIPPED` with reason |
| Cascade guard | 3 failures / 300s | Halts entire case on threshold breach |
| HALT check | — | Checks `case.status == "HALTED"` or `case.halt_flag` before each action |
| Rollback timers | per action type | Schedules automatic undo (see table below) |
| Verification | 5s delay | Re-queries Splunk after each action to confirm effect |

### Default Rollback Timers

| Action | Timer (seconds) | Notes |
|--------|----------------|-------|
| `isolate_host` | 14400 (4h) | Auto-unisolates after 4 hours |
| `block_ip` | 259200 (72h) | Auto-unblocks after 3 days |
| `disable_user` | 86400 (24h) | Auto-enables after 24 hours |
| `kill_process` | 0 | Irreversible — no rollback |
| `quarantine_file` | 14400 (4h) | Auto-restores after 4 hours |
| `revoke_session` | 0 | Irreversible |
| `rotate_credentials` | 0 | Irreversible |

### Exception Hierarchy

```
ExecutorError
  ├── ExecutorRateLimitError        # Rate limit exceeded
  ├── ExecutorCascadeHaltError      # Cascade guard threshold breached
  ├── ExecutorHaltSignalError       # HALT flag set on case
  └── ExecutorAuthorizationError    # Mode does not permit this action type
```

### Test Mode

```python
# _MockExecutorAgent replaces all 8 action handlers with pre-canned responses.
# No live Splunk or EDR platform required.
from agent_executor import _MockExecutorAgent
agent = _MockExecutorAgent(mcp=mock_mcp, config=mock_config)
result = agent.run(case, audit)
```

---

## SageAgent

`app/sentinel/bin/agent_sage.py`

Learning agent. Analyses closed cases, measures efficacy, proposes detection rules, and generates reports.

### Entry Points

```python
# Per-case learning (called by orchestrator after LEARNING state)
result: dict = run(case: Case, audit: AuditLogger) → dict

# Scheduled runs (from inputs.conf cron entries)
result: dict = run_scheduled(mode: str, audit: AuditLogger) → dict
# mode: "daily" | "weekly"

# Direct API
report: EfficacyReport = analyze_detection_efficacy(timeframe: str = "7d")
rule:   ProposedRule   = propose_detection_rule(case_data: dict)
report: WeeklyReport   = generate_weekly_report()
```

### `_TimeSeries` Static Helper

Pure-Python time series utilities (no external dependencies).

```python
_TimeSeries.moving_average(series, window=3) → List[float]
_TimeSeries.linear_trend(series) → Tuple[slope, intercept, r_squared]
_TimeSeries.z_scores(series) → List[float]
_TimeSeries.detect_anomalies(series, threshold=2.0) → List[bool]
_TimeSeries.forecast_linear(series, horizon=1) → List[float]
_TimeSeries.compare_windows(series, window) → {"previous_mean", "recent_mean", "pct_change", "direction"}
_TimeSeries.optimize_threshold(scores, labels, target_tpr=0.90) → Tuple[float, dict]
```

### `_CiscoTimeSeriesClient`

Falls back to `_TimeSeries` built-ins when `base_url` or `token` is empty.

```python
client = _CiscoTimeSeriesClient(base_url="", token="")
client._is_available()       # → False (no endpoint configured)
client.forecast_anomaly(series)           # → {"anomalies": [...], "forecast": [...], "model": "builtin_linear"}
client.optimize_threshold(scores, labels) # → {"optimal_threshold": 72.5, "model": "builtin_sweep"}
client.analyze_trend(series)              # → {"direction": "increasing", "model": "builtin_regression"}
```

### Constants

```python
_MAX_FP_RATE_FOR_PRODUCTION = 0.05   # Rules with FP rate > 5% are not promoted
_MAX_QUERY_TIME_S           = 30.0   # Backtest queries must complete within 30s
_MAX_THRESHOLD_DELTA        = 5      # Max score threshold adjustment per tuning cycle
_INDUSTRY_BASELINE_MTTR_H   = 4.2   # Industry average MTTR (hours) for ROI calculations
_ANALYST_HOURLY_RATE_USD    = 85     # Used for cost-savings estimation in weekly reports
```

---

## SplunkMCPClient

`app/sentinel/bin/mcp_client.py`

Thread-safe, connection-pooled MCP client. All 14 tools are exposed as methods.

### Constructor

```python
SplunkMCPClient(config: ConfigLoader)
```

Reads connection parameters from `sentinel.conf [auth]` and `[mcp]`.

### Circuit Breaker

The client implements a three-state circuit breaker:

| State | Behaviour |
|-------|-----------|
| `CLOSED` | Normal operation — all requests sent |
| `OPEN` | Requests rejected immediately with `MCPCircuitOpenError`; probed every 30s |
| `HALF_OPEN` | One probe sent; success → CLOSED, failure → OPEN |

Tripped when 5 consecutive requests fail within 60 seconds.

### Exception Hierarchy

```
MCPError
  ├── MCPConnectionError   # TCP connection failed
  ├── MCPAuthError         # HTTP 401/403
  ├── MCPTimeoutError      # Request exceeded timeout
  ├── MCPValidationError   # HTTP 422 — tool input schema violation
  ├── MCPCircuitOpenError  # Circuit breaker is OPEN
  └── MCPToolError         # Tool returned an error payload (HTTP 200 with error body)
```

---

## CaseStateManager

`app/sentinel/bin/utils/state_manager.py`

KV Store-backed case persistence with read-through in-memory cache.

### Methods

```python
create_case(alert_id, alert_type, ...) → Case
get_case(case_id)                       → Case | None
transition(case_id, to_status, *, agent_name="", detail="") → Case
update_case(case_id, **kwargs)          → Case
list_cases(status=None, limit=100)      → List[Case]
```

### `Case` Fields

```python
@dataclass
class Case:
    case_id:         str
    alert_id:        str
    alert_type:      str
    status:          CaseStatus
    priority:        str              # CRITICAL | HIGH | MEDIUM | LOW | INFO
    affected_host:   str
    affected_user:   str
    risk_score:      int
    classification:  str
    mitre_tactic:    str
    mitre_technique: str
    retry_count:     int
    created_time:    float            # Unix timestamp
    audit_trail:     List[dict]
    requires_approval:    bool
    approval_granted_by:  str | None
    halt_flag:       bool
    vanguard_result: dict | None      # Set after TRIAGING
    sherlock_report: dict | None      # Set after INVESTIGATING
    executor_log:    dict | None      # Set after RESPONDING
    sage_report:     dict | None      # Set after LEARNING
```

---

## AuditLogger

`app/sentinel/bin/audit_logger.py`

Append-only audit trail. Writes to HEC; falls back to JSONL on disk if HEC is unavailable.

### Methods

```python
log_event(event_type, case_id, agent, details={}, level="INFO") → None
log_transition(case_id, from_status, to_status, agent, reason="") → None
log_action(case_id, action_type, target, result, justification) → None
```

All events include: `timestamp`, `event_id` (UUID), `case_id`, `agent`, `event_type`, plus custom `details`. The HEC write is synchronous; JSONL fallback is also synchronous (no data loss on HEC failure).

---

## MCP Tool Specifications

All 14 tools accept JSON bodies and return JSON. Base URL: `https://localhost:3000`.
All requests require `Authorization: Bearer <agent-token>`.

### Investigation Tools

#### `search_spl`

```
POST /tools/search_spl
```

```json
{
  "spl":        "index=edr process_name=powershell.exe | head 100",
  "earliest":   "-24h",
  "latest":     "now",
  "max_results": 1000
}
```

**Blocked commands:** `sendemail`, `outputlookup`, `outputcsv`, `collect`, `crawl`
**Rate limit:** 5 rps, burst 10
**Safety:** Automatically appends `| head {max_results}` if missing

#### `validate_spl`

```
POST /tools/validate_spl
```

```json
{"spl": "index=edr | stats count by host"}
```

Response: `{"valid": true, "warnings": [], "estimated_scan_cost": "medium"}`
Cached for 3600s per unique SPL string.

#### `get_asset_context`

```
POST /tools/get_asset_context
```

```json
{
  "asset_identifier":   "DESKTOP-ABC123",
  "identifier_type":    "hostname",
  "include_vulnerabilities": false
}
```

Returns asset CMDB record with criticality label (`CRITICAL|HIGH|MEDIUM|LOW|UNKNOWN`).

#### `get_process_tree`

```
POST /tools/get_process_tree
```

```json
{
  "host":      "DESKTOP-ABC123",
  "pid":       "4521",
  "earliest":  "-2h",
  "latest":    "now"
}
```

Returns recursive process ancestry with file/network activity per process node.

#### `get_network_flows`

```
POST /tools/get_network_flows
```

```json
{
  "host":       "DESKTOP-ABC123",
  "time_range": "-24h",
  "direction":  "outbound",
  "min_bytes":  0,
  "max_results": 500
}
```

Auto-selects richest sourcetype (Zeek → NetFlow → firewall logs).

#### `get_user_activity`

```
POST /tools/get_user_activity
```

```json
{
  "username":   "jdoe",
  "time_range": "-24h",
  "event_types": ["logon", "logoff", "privilege_use", "object_access"]
}
```

Computes impossible travel detection and loads UEBA baselines when available.

#### `query_es_notable`

```
POST /tools/query_es_notable
```

```json
{
  "host":       "DESKTOP-ABC123",
  "severity":   ["high", "critical"],
  "earliest":   "-7d",
  "max_results": 50
}
```

#### `get_indexes`

```
GET /tools/get_indexes
```

Returns list of available Splunk indexes. Cached 300s.

#### `run_saved_search`

```
POST /tools/run_saved_search
```

```json
{
  "search_name": "sentinel_ransomware_detection",
  "args":        {"host": "DESKTOP-ABC123"}
}
```

Only searches in the `sentinel` app namespace are allowed by default.

#### `get_knowledge_objects`

```
POST /tools/get_knowledge_objects
```

```json
{"object_type": "datamodel", "filter": "Endpoint"}
```

Fanout across datamodels, field extractions, eventtypes, tags, and macros. Cached 600s.

#### `enrich_threat_intel`

```
POST /tools/enrich_threat_intel
```

```json
{
  "indicator":      "185.220.101.42",
  "indicator_type": "ip"
}
```

Queries configured threat intelligence feeds. Response cached 86400s.

### Response Tools (Executor only)

#### `execute_response_action`

```
POST /tools/execute_response_action
```

```json
{
  "action_type":  "isolate_host",
  "target":       "DESKTOP-ABC123",
  "case_id":      "CASE-2024-001",
  "justification": "Ransomware confirmed on host — isolating to prevent lateral movement.",
  "dry_run":      false
}
```

Supported `action_type` values: `isolate_host`, `unisolate_host`, `block_ip`, `unblock_ip`,
`disable_user`, `enable_user`, `revoke_session`, `rotate_credentials`, `quarantine_file`,
`restore_file`, `kill_process`, `remediate_s3_policy`

Pre-execution safety gate (in order):
1. Distributed lock check
2. Duplicate action suppression (300s dedup window)
3. Dry-run validation
4. Audit log pre-write
5. Agent identity verification

#### `create_ticket`

```
POST /tools/create_ticket
```

```json
{
  "title":       "[SENTINEL CASE-001] RANSOMWARE on DESKTOP-ABC123",
  "description": "...",
  "priority":    "high",
  "case_id":     "CASE-001",
  "platform":    "servicenow"
}
```

Deduplicates by `case_id` + `platform` within a 3600s window.

#### `notify_stakeholders`

```
POST /tools/notify_stakeholders
```

```json
{
  "recipients":   ["#soc-alerts"],
  "message_type": "alert",
  "case_id":      "CASE-001",
  "channels":     ["slack", "pagerduty"]
}
```

---

## JSON Schemas

### VanguardDecisionPacket

```json
{
  "case_id":               "CASE-2024-001",
  "alert_id":              "ES-NOTABLE-001",
  "classification":        "RANSOMWARE_INITIAL_ACCESS",
  "confidence":            0.92,
  "mitre_tactic":          "TA0002",
  "mitre_technique":       "T1059.001",
  "composite_score":       88,
  "decision":              "AUTO_ESCALATE",
  "reasoning":             "Encoded PowerShell executed by Word parent process...",
  "key_indicators":        ["encoded_ps", "office_parent_process", "lsass_access"],
  "false_positive_factors":["legitimate_admin_script"],
  "recommended_actions":   ["isolate_host", "kill_process", "create_ticket"],
  "context": {
    "asset_criticality":   "HIGH",
    "user_risk_score":     72,
    "related_notables":    3
  },
  "model_used":            "foundation-sec-1.1-8b-instruct",
  "model_available":       true,
  "timestamp":             "2024-06-06T10:23:45Z"
}
```

### ExecutorActionLog

```json
{
  "case_id":             "CASE-2024-001",
  "executor_mode":       "FULL_AUTONOMY",
  "risk_score":          88,
  "alert_id":            "ES-NOTABLE-001",
  "classification":      "RANSOMWARE_INITIAL_ACCESS",
  "actions": [
    {
      "action_id":       "ACT-abc123",
      "action_type":     "isolate_host",
      "target":          "DESKTOP-ABC123",
      "status":          "success",
      "execution_time_ms": 1240,
      "verification": {
        "verified":      true,
        "query_used":    "index=network src=DESKTOP-ABC123 earliest=-2m | stats count | where count=0",
        "result":        "confirmed"
      },
      "rollback_timer":  14400,
      "rollback_scheduled": true,
      "human_notified":  false,
      "justification":   "Ransomware confirmed — isolating to stop lateral movement.",
      "skipped_reason":  null,
      "error_detail":    null,
      "timestamp":       "2024-06-06T10:24:02Z"
    }
  ],
  "total_actions":       3,
  "successful_actions":  3,
  "failed_actions":      0,
  "skipped_actions":     0,
  "halted":              false,
  "halt_reason":         null,
  "duration_seconds":    8.4,
  "model_used":          "foundation-sec-1.1-8b-instruct",
  "model_available":     true
}
```

### SherlockInvestigationReport (abbreviated)

```json
{
  "report_id":            "INV-2024-001",
  "case_id":              "CASE-2024-001",
  "classification":       "RANSOMWARE_INITIAL_ACCESS",
  "false_positive_probability": 0.02,
  "phases_completed":     ["A", "B", "C", "D", "E"],
  "executive_summary":    "...",
  "attack_narrative":     "...",
  "blast_radius": {
    "compromised_hosts":  ["DESKTOP-ABC123"],
    "targeted_hosts":     ["DC-01", "FILE-SRV-01"],
    "suspected_hosts":    [],
    "compromised_users":  ["jdoe"],
    "affected_services":  ["file_share"],
    "data_at_risk":       ["\\\\FILE-SRV-01\\Finance"],
    "estimated_dwell_time_minutes": 240
  },
  "iocs_discovered": [
    {"value": "185.220.101.42", "type": "ip", "verdict": "malicious"}
  ],
  "recommended_actions":  ["isolate_host", "disable_user", "quarantine_file"],
  "total_investigation_time_s": 47.2,
  "model_used":           "foundation-sec-1.1-8b-instruct"
}
```

### EfficacyReport (abbreviated)

```json
{
  "timeframe":            "7d",
  "generated_at":         "2024-06-06T06:00:00Z",
  "total_cases":          142,
  "overall_tp_rate":      0.87,
  "overall_fp_rate":      0.13,
  "avg_triage_s":         4.2,
  "avg_investigation_s":  38.1,
  "avg_response_s":       12.7,
  "total_mttr_minutes":   0.92,
  "rules": [/* RuleMetrics objects */],
  "agent_metrics":        { /* per-agent latency and accuracy */ },
  "anomalous_rules":      [/* rules with unusual FP spikes */],
  "summary":              "..."
}
```

### WeeklyReport (abbreviated)

```json
{
  "report_period":           "2024-W23",
  "cases_processed":         142,
  "autonomous_resolutions":  118,
  "human_escalations":       24,
  "metrics": {
    "mttr_hours":            0.92,
    "industry_baseline_h":   4.2,
    "improvement_pct":       78.1
  },
  "detection_improvements":  [/* ProposedRule objects */],
  "threat_intel":            [/* IoC objects */],
  "cost_savings": {
    "analyst_hours_saved":   94.3,
    "usd_saved":             8015.5
  },
  "recommendations":         ["Tune RANSOMWARE_PS_ENCODED threshold from 72 to 75"],
  "tuning_applied":          false,
  "agent_performance": {     /* per-agent latency percentiles */ },
  "generated_at":            "2024-06-10T06:00:00Z"
}
```
