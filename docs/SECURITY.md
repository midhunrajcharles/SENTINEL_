# SENTINEL Security Guide

Authentication, API key encryption, audit trail immutability, human override
mechanisms, and compliance considerations.

---

## Authentication and Authorization

### Architecture Overview

SENTINEL uses a layered authentication model. Each boundary has its own credential:

```
Analyst Browser ──(Splunk session token)──► Splunk Web / War Room Dashboard
                                                │
                               (Splunk session token, sentinel_analyst role)
                                                │
                                                ▼
                          SentinelOrchestrator (runs as sentinel_service account)
                                                │
                               (MCP bearer token)
                                                ▼
                          Splunk MCP Server (port 3000)
                                                │
                    ┌──────────────────────────┼───────────────────────────┐
                    │                          │                           │
            (Splunk API token)        (EDR/IAM platform tokens)   (TI API token)
                    ▼                          ▼                           ▼
            Splunk REST API           CrowdStrike / Okta / AD        VirusTotal
            (port 8089)
```

### Splunk Roles

SENTINEL defines two custom Splunk roles in `default/authorize.conf`:

**`sentinel_agent`** — used by the `sentinel_service` service account:

```ini
[role_sentinel_agent]
importRoles = user
srchIndexesAllowed = endpoint, edr, network, identity, proxy, dns, notable, sentinel_audit, sentinel_learning
srchIndexesDefault = endpoint
srchMaxTime = 600
rtSrchJobsQuota = 0
srchJobsQuota = 10
can_delete = true              # Required for KV Store collection management
edit_kvstore = true
use_file_operator = false      # Prevent data exfiltration via file commands
```

**`sentinel_analyst`** — for human analysts using the War Room dashboard:

```ini
[role_sentinel_analyst]
importRoles = user
srchIndexesAllowed = endpoint, edr, network, identity, sentinel_audit
srchIndexesDefault = sentinel_audit
srchMaxTime = 120
rtSrchJobsQuota = 0
srchJobsQuota = 5
```

### MCP Server Token Management

Tokens are stored in `mcp_server/config/auth_tokens.conf` (excluded from source
control via `.gitignore`). Generate tokens with sufficient entropy:

```bash
# Generate a 48-byte URL-safe token
python3 -c "import secrets; print(secrets.token_urlsafe(48))"
```

Token rotation procedure:
1. Generate a new token.
2. Add it to `auth_tokens.conf` as a secondary token (dual-write period).
3. Update `sentinel.conf [auth] mcp_token` on each agent host.
4. Restart agents.
5. Remove the old token from `auth_tokens.conf`.
6. Restart the MCP Server.

Zero downtime is achievable during steps 2–5 because the MCP Server accepts both
the old and new token simultaneously.

---

## API Key Encryption

SENTINEL never stores credentials in plaintext in committed files. The encryption
chain is:

```
sentinel.conf [local] (plaintext) ──► Splunk credential store ──► encrypted at rest
                                                │
                                     AES-256, key derived from Splunk's
                                     splunk.secret file
```

### Encrypting Credentials at Installation

```bash
# Encrypt all credentials in sentinel.conf using Splunk's built-in store
$SPLUNK_HOME/bin/splunk encrypt -file \
    $SPLUNK_HOME/etc/apps/sentinel/local/sentinel.conf

# Verify the file is now encrypted (values show as [REDACTED])
grep -E "(token|password|secret)" \
    $SPLUNK_HOME/etc/apps/sentinel/local/sentinel.conf
```

### Reading Credentials in Agent Code

Agents read credentials through `utils/config_loader.py`, which transparently
decrypts Splunk-managed credentials:

```python
from utils.config_loader import get_config
cfg = get_config()
token = cfg.get("auth", "mcp_token")   # Decrypted automatically
```

Credentials are never logged. The audit logger strips fields matching `*token*`,
`*password*`, `*secret*`, `*key*` from all log payloads.

### Environment Variable Override

For container deployments where `sentinel.conf` is not available, all credentials
can be supplied via environment variables:

```bash
export SENTINEL_MCP_TOKEN="<token>"
export SENTINEL_HOSTED_MODEL_TOKEN="<token>"
export SENTINEL_SAIA_TOKEN="<token>"
export SENTINEL_HEC_TOKEN="<token>"
export SENTINEL_CISCO_TS_TOKEN="<token>"
```

Environment variables take precedence over `sentinel.conf` values. Never pass
secrets as command-line arguments — they appear in `ps` output.

---

## Audit Trail Immutability

### Design Principles

SENTINEL's audit trail is designed to be tamper-evident:

1. **Pre-write before action** — the INTENT record is written to HEC before any
   external API call. Even if the agent crashes mid-action, the intent is preserved.
2. **Append-only** — the `sentinel_audit` index uses Splunk's standard frozen/roll
   mechanism. Events cannot be edited or deleted without `can_delete` + `delete_index`
   capabilities (not granted to `sentinel_agent`).
3. **JSONL fallback** — if HEC is unavailable, events are written to
   `app/sentinel/logs/audit.jsonl`. This file is opened in append mode (`"a"`).
4. **Event IDs** — every audit record includes a UUID `event_id`. Sequence gaps
   in event IDs indicate potential log tampering or loss.
5. **Cryptographic chaining (optional)** — when `audit_chain_hashes = true` in
   `sentinel.conf`, each record includes a SHA-256 of the previous record's `event_id`,
   forming a hash chain that detects record deletion.

### Audit Event Types

| Event Type | Emitted When |
|------------|-------------|
| `CASE_CREATED` | `process_alert()` called |
| `STATE_TRANSITION` | Case moves between states |
| `AGENT_STARTED` | Agent `run()` called |
| `AGENT_COMPLETED` | Agent `run()` returned |
| `RESPONSE_ACTION_INTENT` | Before any response action |
| `RESPONSE_ACTION_OUTCOME` | After response action returns |
| `RESPONSE_ACTION_ROLLBACK` | When rollback timer fires |
| `HALT_SIGNAL_RECEIVED` | Case halted by analyst |
| `HUMAN_OVERRIDE` | Analyst modifies agent decision |
| `MODEL_UNAVAILABLE` | Foundation-Sec falls back to rules |
| `RATE_LIMIT_HIT` | Executor rate limiter engaged |
| `CASCADE_HALT` | Cascade guard engaged |

### Querying the Audit Trail

```spl
# All actions taken on a specific case
index=sentinel_audit case_id="CASE-2024-001"
| table _time, event_type, agent, action_type, target, status
| sort _time

# All HALT events in the past 30 days
index=sentinel_audit event_type="HALT_SIGNAL_RECEIVED"
| stats count BY case_id, analyst, reason

# Response action INTENT vs. OUTCOME mismatch (potential crash during execution)
index=sentinel_audit event_type IN (RESPONSE_ACTION_INTENT, RESPONSE_ACTION_OUTCOME)
| stats count BY case_id, action_id, event_type
| where count < 2   # Only INTENTs without matching OUTCOMEs
```

---

## Human Override Safety Mechanisms

### HALT Signal

Any analyst with the `sentinel_analyst` Splunk role can halt a case at any point:

```python
# Via orchestrator API (War Room triggers this)
orchestrator.halt_case("CASE-2024-001", reason="False positive confirmed by L2 analyst")
```

When `halt_case()` is called:

1. `CaseStateManager.transition(case_id, CaseStatus.HALTED)` writes the new status
   to KV Store immediately.
2. The orchestrator writes a `HALT_SIGNAL_RECEIVED` audit event.
3. The case status is set to `HALTED` in the in-memory cache with TTL=0 (no expiry).
4. Any agent currently processing this case checks `case.status == "HALTED"` at the
   beginning of each action and throws `ExecutorHaltSignalError` on the next check.
5. `ExecutorAgent._check_halt_signal()` is called before every individual action.

The check interval is every action (not every N seconds), so the maximum latency
between a HALT request and the agent stopping is one action execution time
(typically < 5 seconds).

### Approval Gates

High-risk actions require explicit human approval. The approval requirement is set
during the DECIDING state:

| Condition | Approval Required |
|-----------|------------------|
| `risk_score < AUTO_RESPOND_SCORE (90)` AND `mode == FULL_AUTONOMY` | Yes |
| `action_type == "disable_user"` AND `mode == CONTAINMENT_ONLY` | Yes |
| `action_type == "rotate_credentials"` | Always |
| `action_type == "unisolate_host"` | Always |
| `action_type == "restore_file"` | Always |

When approval is required, the orchestrator transitions the case to HALTED with
reason `"Awaiting analyst approval for high-risk action"`. The War Room dashboard
shows a **Approve / Reject** button. Approval is logged as a `HUMAN_OVERRIDE` event.

### Rollback Timer Override

Analysts can cancel or extend a scheduled rollback:

```python
# Via the War Room API — extends the isolate_host rollback by 4 additional hours
orchestrator.extend_rollback("ACT-abc123", additional_seconds=14400)

# Cancels the scheduled rollback entirely (action becomes permanent)
orchestrator.cancel_rollback("ACT-abc123", reason="Incident not resolved; keeping host isolated")
```

Both operations emit `ROLLBACK_MODIFIED` audit events.

---

## Compliance Considerations

### SOC 2 Type II

SENTINEL's design supports the following SOC 2 Trust Services Criteria:

| Criterion | How SENTINEL Addresses It |
|-----------|--------------------------|
| CC6.1 (Logical access) | Role-based access via Splunk roles; MCP token scoping per agent |
| CC6.2 (Credential management) | Splunk AES-256 credential store; token rotation procedure |
| CC7.1 (System monitoring) | Audit trail for all agent actions; Sage weekly efficacy reports |
| CC7.2 (Alert evaluation) | VanguardAgent triage with documented decision thresholds |
| CC7.3 (Incident response) | Full pipeline: classify → investigate → respond → learn |
| CC9.2 (Change monitoring) | Audit events for all system configuration changes |
| A1.2 (Availability) | Circuit breaker, graceful degradation, MCP retry logic |

**Evidence collection for SOC 2 audits:**

```spl
# Generate agent action summary for audit period
index=sentinel_audit earliest="2024-01-01" latest="2024-12-31"
event_type IN (RESPONSE_ACTION_OUTCOME, HUMAN_OVERRIDE, HALT_SIGNAL_RECEIVED)
| stats
    count AS total_events,
    count(eval(event_type=="RESPONSE_ACTION_OUTCOME")) AS automated_actions,
    count(eval(event_type=="HUMAN_OVERRIDE")) AS human_overrides,
    count(eval(event_type=="HALT_SIGNAL_RECEIVED")) AS analyst_halts
| eval approval_rate=round(human_overrides/total_events*100,1)."%"
```

### ISO 27001

SENTINEL supports ISO 27001 Annex A controls:

| Control | Mapping |
|---------|---------|
| A.12.4.1 (Event logging) | Append-only audit trail in `sentinel_audit` index |
| A.12.4.2 (Log protection) | Index-level access controls; no `can_delete` for agents |
| A.12.4.3 (Administrator/operator logs) | `HUMAN_OVERRIDE` and `HALT_SIGNAL_RECEIVED` events |
| A.12.6.1 (Vulnerability management) | Asset criticality feeds into risk score via `get_asset_context` |
| A.16.1.2 (Reporting of events) | `notify_stakeholders` with configurable channels |
| A.16.1.4 (Assessment of events) | VanguardAgent classification with MITRE ATT&CK mapping |
| A.16.1.5 (Response to incidents) | ExecutorAgent automated containment pipeline |

### Data Residency

All data processed by SENTINEL remains within the Splunk instance:
- Foundation-Sec and Cisco Deep Time Series run as hosted models **inside** Splunk
  (no data sent to external AI providers).
- SAIA queries are sent to Splunk's SAIA cloud endpoint. If data residency
  prohibits this, disable SAIA (`saia_endpoint = ""` in `sentinel.conf`) to
  use template-based SPL generation only.
- Threat intelligence enrichment calls external TI APIs (VirusTotal, etc.) with
  indicator values only — no raw event data is transmitted.

### Sensitive Data Handling

SENTINEL may encounter PII in user names, email addresses, and command-line arguments.

| Data Type | How Handled |
|-----------|------------|
| Usernames | Stored in case fields; not masked; access controlled by Splunk roles |
| Email addresses in command lines | Included in investigation context; logged to `sentinel_audit` |
| Passwords in command lines | The SPL safety layer strips fields matching `*password*` before logging |
| Credit card numbers | Not expected in security telemetry; no specific handling |

For GDPR compliance, the `sentinel_audit` index retention can be set to match your
data retention policy. Right-to-erasure requests for audit data should be evaluated
against the legal basis for processing (legitimate security interest).
