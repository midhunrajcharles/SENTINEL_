# SENTINEL Troubleshooting Guide

Diagnosis and resolution for all known failure modes, with decision trees,
log queries, and workarounds for each scenario.

---

## Quick Diagnostic Reference

Before diving into specific issues, run these checks:

```bash
# 1. MCP Server health
curl -k https://localhost:3000/health
# Expected: {"status":"ok","tools_loaded":14}

# 2. Foundation-Sec model status
curl -k https://localhost:8089/services/ml/models/foundation-sec-1.1-8b-instruct \
    -H "Authorization: Bearer <token>" | python3 -m json.tool | grep state
# Expected: "state": "running"

# 3. HEC connectivity
curl -k https://localhost:8088/services/collector/event \
    -H "Authorization: Splunk <hec-token>" \
    -d '{"event":{"test":"diagnostic"}}'
# Expected: {"text":"Success","code":0}

# 4. Recent SENTINEL errors in Splunk
$SPLUNK_HOME/bin/splunk search \
    'index=_internal sourcetype=splunkd component=SentinelAgent earliest=-15m' \
    -auth admin:changeme | head -20

# 5. Audit trail recent events
$SPLUNK_HOME/bin/splunk search \
    'index=sentinel_audit earliest=-15m | table _time, event_type, case_id, agent, status' \
    -auth admin:changeme | head -20
```

---

## Issue 1: SAIA Activation Delays

### Symptom

```
[INFO]  sentinel.sherlock  saia_available=False  reason="endpoint_not_configured"
[WARN]  sentinel.sherlock  phase=B  method="template_fallback"
        message="SAIA not configured; using built-in SPL templates"
```

Or, after submitting the SAIA request, queries return `401 Unauthorized`:

```
SherlockSAIAError: SAIA request failed: 401 Unauthorized
    endpoint=https://<org>.api.saia.splunk.com/services/assistant/v1/generate
```

### Decision Tree

```
Is saia_endpoint configured in sentinel.conf?
    │
    ├── No → Normal — SAIA not activated yet
    │          Workaround: template fallback (automatic)
    │
    └── Yes → Is the token correct?
                  │
                  ├── No → Copy token from SAIA activation email exactly
                  │         (no leading/trailing spaces)
                  │
                  └── Yes → Is the endpoint URL correct?
                                │
                                ├── No → Check email for exact org-specific URL
                                │
                                └── Yes → Test manually (see below)
                                          Has it been < 3 business days since request?
                                              │
                                              ├── Yes → Wait; provisioning in progress
                                              └── No → Contact Splunk support
```

**Manual SAIA test:**

```bash
curl -X POST https://<your-org>.api.saia.splunk.com/services/assistant/v1/generate \
    -H "Authorization: Bearer <your-saia-token>" \
    -H "Content-Type: application/json" \
    -d '{"question":"Show failed logons in the last hour","context":{"time_range":"-1h"}}' \
    -v 2>&1 | tail -30
```

### Workaround: Cached SPL Query Library

Until SAIA is active, SENTINEL's template fallback handles all standard investigation
patterns. To pre-seed the template cache with organisation-specific SPL for non-standard
alert types, add entries to `app/sentinel/lookups/spl_template_cache.csv`:

```csv
alert_type,phase,spl
CUSTOM_ALERT_TYPE,phase_b,"index=custom_edr host={host} earliest={earliest} | head 200"
CUSTOM_ALERT_TYPE,phase_c,"index=network src={host} earliest={earliest} | head 100"
```

This CSV is loaded at agent startup and used before falling through to the `_default`
template. No code changes required.

---

## Issue 2: Foundation-Sec Latency

### Symptom

Vanguard classification takes > 15 seconds per alert, causing the orchestrator's
worker thread to block and reducing throughput below 5 concurrent cases.

```
[WARN] sentinel.vanguard  model_call_duration_s=18.4
       threshold_exceeded=True  limit_s=15.0
```

Or the model times out entirely:

```
VanguardModelError: Foundation-Sec inference timed out after 30s
    case_id=CASE-2024-001  prompt_tokens=2847
```

### Root Causes and Fixes

**Cause 1: Prompt too large**

The model's context window is 4096 tokens. Prompts approaching this limit take
significantly longer to process. Vanguard's `_build_prompt()` truncates evidence
to 2000 characters, but large process trees can exceed this.

```python
# Verify prompt size before calling the model
prompt = agent._build_prompt(case, asset_ctx, notables)
token_estimate = len(prompt.split()) * 1.3  # rough tokens estimate
if token_estimate > 2000:
    log.warning("prompt_large", token_estimate=token_estimate)
```

Fix: Reduce `max_process_tree_depth` in `sentinel.conf`:

```ini
[vanguard]
max_process_tree_depth = 3     # Default: 5 levels
max_evidence_chars     = 1500  # Default: 2000
```

**Cause 2: Model is loading (first call after restart)**

The first inference call after a Splunk restart can take 60–90 seconds while the
model is loaded into GPU/CPU memory.

```bash
# Check model load state
curl -k https://localhost:8089/services/ml/models/foundation-sec-1.1-8b-instruct \
    -H "Authorization: Bearer <token>" | python3 -m json.tool | grep -E "state|loaded"
```

Fix: Implement a warm-up call in the orchestrator's startup sequence. The
`python sentinel_orchestrator.py --warmup` flag sends a minimal test prompt to
each model and waits for the response before accepting real cases.

**Cause 3: Splunk resource contention**

If Splunk is indexing large volumes simultaneously, inference latency spikes.

```spl
index=_internal sourcetype=splunkd component=IndexProcessor earliest=-15m
| stats avg(eval(tostring(kbps))) AS avg_kbps BY host
```

Fix: Schedule high-volume indexing outside peak hours. Alternatively, increase
the model inference timeout:

```ini
# sentinel.conf [models]
foundation_sec_timeout_s = 45   # Increase from default 30s
```

### Workaround: Pre-Computed Classifications

For high-velocity alert environments where model latency is unacceptable, enable
the classification cache:

```ini
# sentinel.conf [vanguard]
enable_classification_cache = true
cache_ttl_seconds           = 3600   # 1 hour
cache_key_fields            = alert_type, affected_host, process_name
```

When cache is enabled:
1. Vanguard checks the cache for an identical alert_type + host + process_name tuple.
2. Cache hit → returns cached classification (< 1ms).
3. Cache miss → calls Foundation-Sec, stores result.
4. Cache is stored in `sentinel_learning` index (persists across restarts).

**Caveat:** Cached classifications can become stale if the threat landscape changes.
Use with short TTLs (< 2 hours) or only for alert types with stable classification
patterns.

---

## Issue 3: MCP Connection Drops

### Symptom

```
MCPConnectionError: Failed to connect to MCP Server at https://127.0.0.1:3000
MCPCircuitOpenError: Circuit breaker is OPEN — requests suspended for 30s
```

Or intermittent failures:

```
[ERROR] sentinel.mcp_client  tool=search_spl  attempt=3/3
        error="Connection reset by peer"  case_id=CASE-2024-001
```

### Decision Tree

```
Is the MCP Server process running?
    │
    ├── No → Restart it:
    │          $SPLUNK_HOME/bin/splunk restart
    │          Check mcp_server.log for startup errors
    │
    └── Yes → Does curl -k https://localhost:3000/health return {"status":"ok"}?
                  │
                  ├── No → TLS error? Check cert paths in mcp_server.local.conf
                  │         Auth error? Check agent_token_ref is populated
                  │         Firewall? sudo ufw status | grep 3000
                  │
                  └── Yes → Is it intermittent (works sometimes)?
                                │
                                ├── Yes → Circuit breaker tripping?
                                │         Check: grep "circuit" mcp_server.log
                                │         → Tune circuit_failure_threshold (default: 5)
                                │
                                └── No → Splunk REST API failing underneath?
                                          Check: curl -k https://localhost:8089/services/server/info
                                          → May be Splunk resource exhaustion
```

**Check circuit breaker state:**

```python
# From Python REPL or diagnostic script
from mcp_client import SplunkMCPClient
from utils.config_loader import get_config
client = SplunkMCPClient(get_config())
print(client._breaker.state)  # CLOSED | OPEN | HALF_OPEN
print(client._breaker.failure_count)
```

### Workaround: Demo Mode

When the MCP Server is completely unavailable (e.g., Splunk is down for maintenance),
run the orchestrator in demo mode to continue testing agent logic:

```bash
python sentinel_orchestrator.py --demo --dry-run
```

In demo mode:
- All MCP tool calls are replaced with pre-recorded responses from `demo/scenarios/`
- No live Splunk connection required
- Response actions are no-ops (logged but not executed)
- Full audit trail is still generated (written to JSONL if HEC unavailable)

To enable demo mode in code for integration tests:

```python
from agent_vanguard import _MockVanguardAgent  # Uses built-in demo data
from agent_sherlock import _MockSherlockAgent
from agent_executor import _MockExecutorAgent
from agent_sage     import _MockSageAgent
```

Each `_MockAgent` class overrides all MCP calls with realistic but non-live data.

---

## Issue 4: Response Action Failures

### Symptom

```
[ERROR] sentinel.executor  action_type=isolate_host  target=DESKTOP-ABC123
        status=failed  error="MCPToolError: CrowdStrike API returned 404: Device not found"
```

Or cascade guard triggering:

```
ExecutorCascadeHaltError: 3 consecutive action failures in 247s (threshold: 3 in 300s)
    case_id=CASE-2024-001  last_error="EDR platform unreachable"
```

### Decision Tree

```
Single action failure or multiple?
    │
    ├── Single failure
    │       │
    │       ├── 404 (target not found)
    │       │     → Asset not registered in EDR platform
    │       │     → Verify hostname in CrowdStrike/S1 console
    │       │     → Check get_asset_context returns valid record
    │       │
    │       ├── 401/403 (auth failure)
    │       │     → EDR API token expired
    │       │     → Rotate token in sentinel.conf [response]
    │       │     → Verify token has "Contain" permission in CrowdStrike
    │       │
    │       └── 503 (platform unavailable)
    │             → EDR vendor outage — check vendor status page
    │             → Action auto-retries 2× with 3s backoff
    │
    └── Multiple failures → cascade guard tripped
            │
            ├── All failures same error type → platform-wide issue
            │     → Check vendor status
            │     → Halt case: orchestrator.halt_case(case_id, "Platform outage")
            │     → Manually execute containment in EDR console
            │
            └── Mixed errors → Splunk-side issue (MCP server, SPL errors)
                    → Check mcp_server.log
                    → Restart MCP Server if necessary
```

### Workaround: Mock Response APIs

When the EDR platform is unreachable, switch the Executor to use mock response handlers
for testing/demonstration:

```python
# In sentinel.conf [response]
use_mock_response_actions = true
```

When `use_mock_response_actions = true`:
- `_MockExecutorAgent` is used instead of `ExecutorAgent`
- All action handlers return pre-canned success responses
- Rollback timers are still scheduled
- Verification queries still run against live Splunk (or return `verified=True` if mock)
- A `MOCK_RESPONSE_MODE` event is emitted to the audit trail on every action

**Reset cascade guard manually** (after resolving the platform issue):

```python
# Reload the case and clear the cascade guard
orchestrator._cascade_guards[case_id] = _CascadeGuard()
orchestrator.resume_case(case_id)
```

---

## Issue 5: Agent Swarm Deadlock

### Symptom

The orchestrator is running but no cases progress. The work queue is non-empty
but no workers appear to be processing:

```
[WARN] sentinel.orchestrator  queue_depth=8  active_workers=0
       semaphore_available=0  last_case_completed="12 minutes ago"
```

Or Splunk shows all 5 worker threads blocked:

```
[ERROR] sentinel.orchestrator  worker_thread=worker-3
        blocked_at="_slots.acquire()"  duration_s=721
```

### Detection

Run this SPL to identify stalled cases:

```spl
index=sentinel_audit event_type="STATE_TRANSITION"
| eval time_in_state=now()-_time
| where time_in_state > 600   // 10 minutes in a non-terminal state
| stats latest(to_status) AS current_status, max(time_in_state) AS stuck_for_s BY case_id
| where current_status NOT IN ("CLOSED","HALTED","SUPPRESSED","ERROR")
| sort -stuck_for_s
```

### Root Causes and Recovery

**Cause 1: Worker thread died with a lock held**

If a worker thread raises an unhandled exception while holding the semaphore slot,
the slot is never released.

```python
# The orchestrator's _run_worker() uses try/finally to guarantee slot release
def _run_worker(self):
    self._slots.acquire()
    try:
        self._process_next_case()
    finally:
        self._slots.release()   # Always released, even on exception
```

If this is happening (indicates a bug):

```bash
# Thread dump to identify stuck threads
python3 -c "
import requests, json
resp = requests.get('https://localhost:8089/services/server/threadcount',
    auth=('admin','changeme'), verify=False)
print(json.dumps(resp.json(), indent=2))
" | grep -A3 sentinel
```

**Recovery:** Restart the orchestrator. Cases in `TRIAGING/INVESTIGATING/RESPONDING`
will be re-queued after the restart timeout (60s) and retried (up to `MAX_RETRIES_PER_CASE=3`).

**Cause 2: All 5 slots held by cases waiting for MCP**

If MCP responses are very slow (> 120s per call), all 5 worker threads can be
simultaneously blocked waiting for MCP responses.

```spl
index=sentinel_audit event_type="AGENT_STARTED" earliest=-30m
| eval elapsed=now()-_time
| where elapsed > 600
| table case_id, agent, elapsed
```

Fix: Reduce MCP tool timeouts so blocked workers fail fast and retry:

```ini
# mcp_server.local.conf
[rate_limiting]
tool.search_spl.timeout_seconds = 60   # Reduce from 130
```

Alternatively, increase `max_concurrent` if the Splunk instance has capacity:

```python
orchestrator = SentinelOrchestrator(max_concurrent=10)
```

**Cause 3: KV Store lock contention**

Response actions use a distributed lock in the `response_locks` KV Store collection.
If the Executor crashes while holding a lock, subsequent actions on the same target
are blocked indefinitely.

```spl
| inputlookup response_locks
| eval age_minutes=round((now()-locked_at_epoch)/60,1)
| where age_minutes > 30   // Locks older than 30 minutes are stale
| table action_type, target, case_id, locked_by, age_minutes
```

Clear stale locks:

```spl
| inputlookup response_locks
| eval age=now()-locked_at_epoch
| where age > 1800   // Remove locks older than 30 minutes
| outputlookup response_locks
```

**Recovery procedure for full deadlock:**

```bash
# Step 1: Graceful stop (gives workers 60s to finish)
python sentinel_orchestrator.py --stop

# Step 2: If graceful stop hangs after 90s, kill the process
pkill -f sentinel_orchestrator.py

# Step 3: Clear stale KV Store locks (run in Splunk search)
# (use SPL above to clear response_locks)

# Step 4: Check and close stuck cases in KV Store
# Cases in TRIAGING/INVESTIGATING/RESPONDING will auto-retry on next start

# Step 5: Restart
python sentinel_orchestrator.py &
```

---

## Log Locations and Log Level Configuration

| Component | Log Location | Source Type |
|-----------|-------------|------------|
| Orchestrator | `$SPLUNK_HOME/var/log/splunk/sentinel_orchestrator.log` | `sentinel:orchestrator` |
| MCP Server | `mcp_server/logs/mcp_server.log` | `sentinel:mcp:server` |
| Agent output | Splunk internal logs (stdout captured by Splunk) | `sentinel:agent` |
| Audit trail | `sentinel_audit` Splunk index | `sentinel:audit` |
| HEC fallback | `app/sentinel/logs/audit.jsonl` | File |

To increase log verbosity for a specific component:

```ini
# sentinel.conf [logging]
orchestrator_log_level = DEBUG
vanguard_log_level     = DEBUG
sherlock_log_level     = INFO    # Phase-level detail only
executor_log_level     = DEBUG
sage_log_level         = INFO

# mcp_server.local.conf [logging]
level = DEBUG
log_tool_inputs  = true
log_tool_outputs = true   # WARNING: may log sensitive data
```

---

## Common Error Reference

| Error | Likely Cause | Quick Fix |
|-------|-------------|-----------|
| `MCPConnectionError` | MCP Server not running | `$SPLUNK_HOME/bin/splunk restart` |
| `MCPAuthError` | Wrong bearer token | Check `sentinel.conf [auth] mcp_token` |
| `MCPCircuitOpenError` | 5+ consecutive MCP failures | Wait 30s; check MCP Server logs |
| `MCPTimeoutError` | Splunk search taking too long | Reduce time range or add index filter |
| `SherlockSAIAError` | SAIA endpoint unavailable | Normal — template fallback is active |
| `ExecutorRateLimitError` | > 10 actions in 1 hour | Wait for window to reset; check for duplicated cases |
| `ExecutorCascadeHaltError` | 3+ failures in 5 min | Platform outage; manual intervention needed |
| `ExecutorHaltSignalError` | Analyst halted the case | Expected; case is paused |
| `VanguardModelError` | Foundation-Sec 503/504 | Model loading; retry in 60s; fallback rules active |
| `SageQueryError` | Splunk search failed in Sage | Check SPL syntax in Sage templates |
| `ImportError: No module named 'mcp_client'` | Wrong sys.path | Run from repo root; check conftest.py |
| `KV Store: collection not found` | App not initialized | Wait 60s after app install; restart Splunk |
