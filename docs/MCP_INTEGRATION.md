# SENTINEL MCP Integration Guide

How SENTINEL extends the Splunk MCP Server with custom security tools, implements
safety guardrails, and optimises performance for high-frequency investigation workloads.

---

## Overview

The Model Context Protocol (MCP) is the transport layer that lets SENTINEL's agents
call Splunk APIs and external platforms without embedding credentials or HTTP logic in
each agent. The MCP Server acts as a smart proxy: it authenticates agents, validates
tool inputs, enforces rate limits, writes pre-execution audit records, and handles
retries and circuit breaking.

```
┌─────────────────────────────────────────────────────────────────┐
│                     SENTINEL Agents                              │
│  VanguardAgent  SherlockAgent  ExecutorAgent  SageAgent          │
└──────────────────────────┬──────────────────────────────────────┘
                           │ HTTPS + Bearer Token (port 3000)
                           │ MCP Protocol (JSON-RPC 2.0)
┌──────────────────────────▼──────────────────────────────────────┐
│                   Splunk MCP Server                              │
│  ┌─────────────────┐  ┌──────────────────┐  ┌───────────────┐   │
│  │  Investigation  │  │    Response       │  │  Enrichment   │   │
│  │     Tools (9)   │  │    Tools (3)      │  │   Tools (2)   │   │
│  └────────┬────────┘  └────────┬─────────┘  └───────┬───────┘   │
└───────────│────────────────────│────────────────────│───────────┘
            │                    │                    │
   Splunk REST API          EDR/Firewall/IAM     Threat Intel APIs
   (port 8089)              Platforms             (VirusTotal, etc.)
```

---

## How SENTINEL Extends the Default MCP Server

The base Splunk MCP Server exposes generic Splunk REST endpoints. SENTINEL adds three
layers on top:

### 1. Custom Tool Definitions (`mcp_server/custom_tools/`)

Three YAML files define SENTINEL-specific tool behaviour:

| File | Tool Group | Tools |
|------|-----------|-------|
| `investigation_tools.yaml` | investigation | `search_spl`, `validate_spl`, `get_asset_context`, `get_process_tree`, `get_network_flows`, `get_user_activity`, `query_es_notable`, `get_indexes`, `run_saved_search`, `get_knowledge_objects` |
| `response_tools.yaml` | response | `execute_response_action`, `create_ticket`, `notify_stakeholders` |
| `enrichment_tools.yaml` | enrichment | `enrich_threat_intel` |

Each tool definition specifies: handler class, endpoint mapping, rate limits, timeouts,
retry policy, caching behaviour, safety gates, and error handling.

### 2. SPL Safety Layer (`search_spl`)

SENTINEL patches `search_spl` with a security wrapper that runs before every query:

```python
# Pseudocode representation of the safety pipeline
def _safe_search_spl(spl: str, **kwargs):
    spl = _strip_comments(spl)                        # Remove /* */ and -- comments
    _assert_no_blocked_commands(spl)                  # Reject sendemail, outputlookup, etc.
    _assert_time_range_within_limit(kwargs, days=90)  # Prevent runaway searches
    if not _has_head_limit(spl):
        spl = f"{spl} | head {MAX_RESULTS}"           # Auto-cap results
    return _execute(spl, **kwargs)
```

Blocked commands: `sendemail`, `outputlookup`, `outputcsv`, `collect`, `crawl`

### 3. Response Action Safety Gate (`execute_response_action`)

Every response action passes through a five-stage gate before any API call is made:

```
Stage 1: Distributed lock check
   └── Acquire lock in sentinel_response_locks KV Store
   └── Prevents two agents from acting on the same target simultaneously

Stage 2: Duplicate action suppression (300s dedup window)
   └── Hash of (action_type + target + case_id) checked against recent_actions KV Store
   └── Returns suppressed response if duplicate detected

Stage 3: Dry-run validation
   └── If dry_run=true: validates payload schema, simulates response, returns immediately

Stage 4: Audit log pre-write
   └── Writes INTENT record to sentinel_audit index before any external call
   └── Creates immutable evidence that the action was attempted even if it fails

Stage 5: Agent identity verification
   └── Verifies calling agent is executor (token scope check)
   └── Rejects calls from vanguard/sherlock/sage tokens
```

---

## Custom Tool Development Guide

To add a new MCP tool to SENTINEL, follow these steps:

### Step 1: Define the Tool Schema

Add an entry to `mcp_server/custom_tools/investigation_tools.yaml` (or create a new
group YAML):

```yaml
tools:
  - name: get_cloud_trail
    handler: handlers.cloud.CloudTrailHandler
    endpoint: /services/search/jobs
    method: POST

    # Rate limit this tool conservatively
    rate_limit:
      rps: 5
      burst: 10
      strategy: token_bucket
      exceeded_action: queue

    timeout:
      connect_seconds: 5
      read_seconds: 60
      total_seconds: 65

    # Cache cloud trail results for 30 seconds
    cache:
      enabled: true
      ttl_seconds: 30
      key_fields: [account_id, time_range, event_type]

    # The SPL template the handler will render with caller-supplied variables
    spl_template: >
      index=cloud sourcetype=aws:cloudtrail
      {account_filter}
      {event_type_filter}
      earliest={earliest} latest={latest}
      | eval time=strftime(_time,"%Y-%m-%dT%H:%M:%SZ")
      | table time, eventName, userIdentity.arn, sourceIPAddress,
              requestParameters, responseElements, errorCode
      | sort time
      | head {max_results}

    safety:
      max_time_range_days: 30
      auto_limit_results: true

    error_handling:
      on_no_results:
        action: return_empty
        message: "No CloudTrail events found for the specified account and time range."
      on_failure:
        action: return_error
        include_splunk_messages: true
```

### Step 2: Implement the Handler Class

```python
# mcp_server/handlers/cloud.py

from handlers.base import BaseToolHandler, ToolResult
import re


class CloudTrailHandler(BaseToolHandler):
    """Queries AWS CloudTrail events from the Splunk cloud index."""

    tool_name = "get_cloud_trail"

    # JSON Schema for input validation (enforced by MCP Server before handler runs)
    input_schema = {
        "type": "object",
        "properties": {
            "account_id":   {"type": "string", "pattern": r"^\d{12}$"},
            "time_range":   {"type": "string", "default": "-24h"},
            "event_types":  {"type": "array", "items": {"type": "string"}},
            "max_results":  {"type": "integer", "minimum": 1, "maximum": 1000, "default": 200},
        },
        "required": ["account_id"],
    }

    def execute(self, inputs: dict) -> ToolResult:
        account_id   = inputs["account_id"]
        time_range   = inputs.get("time_range", "-24h")
        event_types  = inputs.get("event_types", [])
        max_results  = inputs.get("max_results", 200)

        # Build SPL filter fragments
        account_filter    = f'userIdentity.accountId="{account_id}"'
        event_type_filter = ""
        if event_types:
            quoted = " OR ".join(f'eventName="{e}"' for e in event_types)
            event_type_filter = f"({quoted})"

        spl = self.render_template(
            account_filter    = account_filter,
            event_type_filter = event_type_filter,
            earliest          = time_range,
            latest            = "now",
            max_results       = max_results,
        )

        results = self.splunk_search(spl)
        return ToolResult(data=results, metadata={"account_id": account_id})
```

### Step 3: Register the Tool in JSON Schema Registry

Add the tool input schema to `mcp_server/config/tool_definitions.json`:

```json
{
  "get_cloud_trail": {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "type": "object",
    "properties": {
      "account_id":  {"type": "string"},
      "time_range":  {"type": "string"},
      "event_types": {"type": "array"},
      "max_results": {"type": "integer"}
    },
    "required": ["account_id"]
  }
}
```

### Step 4: Add the Python Client Method

In `app/sentinel/bin/mcp_client.py`, add:

```python
def get_cloud_trail(
    self,
    account_id:   str,
    time_range:   str = "-24h",
    event_types:  list = None,
    max_results:  int = 200,
) -> dict:
    return self._call("get_cloud_trail", {
        "account_id":  account_id,
        "time_range":  time_range,
        "event_types": event_types or [],
        "max_results": max_results,
    })
```

### Step 5: Reload Without Restart

The MCP Server hot-reloads YAML tool definitions when they change on disk:

```bash
touch mcp_server/custom_tools/investigation_tools.yaml
# Server detects the mtime change and reloads within 5 seconds
```

Verify the new tool is registered:

```bash
curl -k https://localhost:3000/tools | python3 -m json.tool | grep get_cloud_trail
```

---

## Security Guardrails Implementation

### Token Scoping

Each agent uses a different bearer token scoped to its permitted tool groups:

```ini
# mcp_server/config/auth_tokens.conf

[vanguard_token]
token    = <generated-token>
agent    = vanguard
permitted_groups = investigation, enrichment
denied_tools     = execute_response_action, create_ticket, notify_stakeholders

[executor_token]
token    = <generated-token>
agent    = executor
permitted_groups = response, investigation
denied_tools     =            # executor has broadest permissions
require_case_id  = true       # all executor calls must include case_id
```

### Input Sanitisation

All tool inputs are validated against JSON Schema before execution. Strings are
sanitised to prevent SPL injection:

```python
# Strings passed into SPL templates are escaped through this function
def _sanitise_spl_value(value: str) -> str:
    # Remove characters that change SPL parser context
    value = re.sub(r'[|`$\\]', '', value)
    # Escape double quotes
    value = value.replace('"', '\\"')
    # Limit field value length
    return value[:256]
```

### Audit Trail for All Mutations

Every call to a mutating tool (`execute_response_action`, `create_ticket`, `notify_stakeholders`)
produces two audit records:

1. **INTENT** — written before the external call (proves the action was attempted)
2. **OUTCOME** — written after the call returns (records success/failure/rollback plan)

```json
{
  "event_type":   "RESPONSE_ACTION_INTENT",
  "case_id":      "CASE-2024-001",
  "agent":        "executor",
  "action_type":  "isolate_host",
  "target":       "DESKTOP-ABC123",
  "justification":"Ransomware confirmed — isolating host.",
  "timestamp":    "2024-06-06T10:24:01.842Z",
  "event_id":     "evt-uuid-here"
}
```

---

## Performance Optimisation Tips

### 1. Use `run_saved_search` Over `search_spl` for Fixed Queries

Pre-built saved searches run faster because Splunk pre-compiles their execution plan
and can use `tstats` acceleration. Convert any SPL template used more than 10×/day
into a saved search with parametrised arguments.

### 2. Exploit the Cache

Idempotent reads are cached by the MCP Server. Cache TTLs by tool:

| Tool | TTL | Why |
|------|-----|-----|
| `get_indexes` | 300s | Index list rarely changes |
| `get_knowledge_objects` | 600s | KO changes require app restart |
| `get_asset_context` | 120s | Asset criticality changes infrequently |
| `validate_spl` | 3600s | Same SPL always produces same result |
| `enrich_threat_intel` | 86400s | TI feeds update at most daily |
| `search_spl` | 0s | Never cached — results depend on live data |

To force a cache bypass (e.g., after a CMDB update):

```python
result = mcp.get_asset_context("DESKTOP-ABC123", bypass_cache=True)
```

### 3. Parallel Phase Execution in Sherlock

SherlockAgent's Phase A calls `get_asset_context` and `get_process_tree` simultaneously
using `concurrent.futures.ThreadPoolExecutor`. When adding new investigation phases,
follow the same pattern:

```python
with ThreadPoolExecutor(max_workers=3) as pool:
    f_asset   = pool.submit(self._mcp.get_asset_context,   host)
    f_process = pool.submit(self._mcp.get_process_tree,    host, pid)
    f_notable = pool.submit(self._mcp.query_es_notable,    host=host)

asset_ctx  = f_asset.result(timeout=35)
process    = f_process.result(timeout=65)
notables   = f_notable.result(timeout=35)
```

### 4. Tune Rate Limits for Your Data Volume

Default rate limits are conservative. For high-volume environments, tune per-tool
limits in `mcp_server.local.conf`:

```ini
[rate_limiting]
# Increase search_spl if Splunk has capacity
tool.search_spl.rps_max    = 10
tool.search_spl.burst_max  = 20

# Keep response action rate low regardless of volume — safety by design
tool.execute_response_action.rps_max   = 2
tool.execute_response_action.burst_max = 4
```

### 5. Circuit Breaker Tuning

If your Splunk instance has intermittent REST API latency, increase the circuit breaker
threshold to avoid false opens:

```python
# In mcp_client.py, the _CircuitBreaker is initialized with:
_breaker = _CircuitBreaker(
    failure_threshold = 5,    # default: 5 consecutive failures
    recovery_timeout  = 30,   # default: 30s before half-open probe
    half_open_max     = 1,    # default: 1 probe before closing
)
```

Override these defaults by passing values via `sentinel.conf [mcp]`:

```ini
[mcp]
circuit_failure_threshold = 10
circuit_recovery_timeout  = 60
```
