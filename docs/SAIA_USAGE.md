# SENTINEL SAIA Usage Guide

How SherlockAgent uses the Splunk AI Assistant (SAIA) for dynamic investigation query
generation, prompt engineering patterns, validation workflow, and fallback strategies.

---

## What is SAIA in SENTINEL?

SAIA (Splunk AI Assistant) is a natural-language-to-SPL service. SherlockAgent uses
SAIA as the primary query generation path in Phase B (Timeline Reconstruction) and
for dynamic queries in Phases C–D when the standard SPL templates don't match the
specific alert context.

```
SherlockAgent._run_phase_b(case, ctx)
    │
    ├── Try: _get_saia().generate_spl(question, context)
    │       │
    │       ├── Success → validate_spl() → execute search_spl()
    │       │
    │       └── Failure (timeout / unavailable / invalid SPL)
    │               │
    │               └── Fallback: _SPL_TEMPLATES[phase][alert_type]
    │
    └── Record: ctx.record_source("saia" if used_saia else "template")
```

---

## How `_SAIAClient` Works

`_SAIAClient` is a thin HTTP wrapper around the SAIA REST endpoint.

```python
# From agent_sherlock.py
class _SAIAClient:
    _ENDPOINT = "/services/assistant/v1/generate"

    def __init__(self, base_url: str, token: str):
        self._base_url = base_url.rstrip("/")
        self._token    = token
        self._session  = requests.Session()

    def generate_spl(self, question: str, context: dict) -> str | None:
        """Returns a validated SPL string, or None if SAIA is unavailable."""
        if not self._base_url or not self._token:
            return None
        try:
            resp = self._session.post(
                f"{self._base_url}{self._ENDPOINT}",
                headers={"Authorization": f"Bearer {self._token}"},
                json={"question": question, "context": context},
                timeout=10,
            )
            resp.raise_for_status()
            return resp.json().get("spl")
        except Exception:
            return None
```

The client is lazy-initialised: `_get_saia()` creates a `_SAIAClient` only on first
call, reading credentials from `sentinel.conf [saia]` at that point.

---

## Prompt Engineering Patterns

SENTINEL passes a structured `context` dictionary alongside each NL question. This
context is what separates SENTINEL's queries from generic SAIA usage — the richer the
context, the more targeted the SPL.

### Pattern 1: Host-Scoped Timeline Query

Used in Phase B when building the attack timeline for a specific host.

```python
question = (
    f"Generate a timeline of all process execution events on host {case.affected_host} "
    f"in the {time_range} window, sorted chronologically. "
    f"Include process name, parent process, command line, and user context."
)

context = {
    "affected_host":     case.affected_host,
    "affected_user":     case.affected_user,
    "time_range":        "-24h",
    "alert_type":        case.alert_type,
    "classification":    case.classification,
    "available_indexes": ["endpoint", "edr", "sysmon"],
    "preferred_sourcetypes": ["XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
                               "crowdstrike:events:sensor"],
}
```

### Pattern 2: Lateral Movement Detection Query

Used in Phase C when looking for spread beyond the initial host.

```python
question = (
    f"Find all authentication events and SMB/RDP/WMI connections originating from "
    f"host {case.affected_host} or user {case.affected_user} in the {time_range} "
    f"window. Flag connections to hosts not typically accessed by this user."
)

context = {
    "affected_host":      case.affected_host,
    "affected_user":      case.affected_user,
    "known_good_hosts":   ctx.baseline_hosts,    # from UEBA baseline
    "time_range":         "-48h",
    "iocs_discovered":    [ioc.value for ioc in ctx.iocs if ioc.ioc_type == "ip"],
}
```

### Pattern 3: Threat-Type-Specific Query

For ransomware investigations, SAIA is asked to look for file extension changes:

```python
question = (
    "Detect file extension changes consistent with ransomware encryption activity. "
    "Look for mass file renames across network shares and local drives. "
    f"Focus on extensions: {', '.join(_RANSOMWARE_EXTENSIONS[:8])}."
)

context = {
    "affected_host":       case.affected_host,
    "time_range":          "-2h",
    "alert_classification": "RANSOMWARE_INITIAL_ACCESS",
    "target_extensions":   list(_RANSOMWARE_EXTENSIONS),
    "available_indexes":   ["endpoint", "file_integrity"],
}
```

### Pattern 4: Identity Anomaly Query

Used in Phase D when investigating insider threat or compromised credentials.

```python
question = (
    f"Identify unusual access patterns for user {case.affected_user}. "
    f"Look for: off-hours access, access to resources not typically accessed, "
    f"large data transfers, and privilege escalation attempts."
)

context = {
    "affected_user":   case.affected_user,
    "time_range":      "-7d",
    "alert_type":      case.alert_type,
    "baseline_hours":  "08:00-18:00",       # user's typical working hours
    "baseline_hosts":  ctx.baseline_hosts,  # from UEBA learning index
}
```

### Guidelines for Effective SAIA Prompts

| Do | Don't |
|----|-------|
| Include specific host/user/time context | Use vague scope ("all events") |
| Name available indexes | Leave SAIA to guess the data source |
| Specify sort order and result limit expectations | Ask for unbounded result sets |
| Include known IOCs to focus the query | Omit context that could narrow scope |
| Use alert classification to inform intent | Ask multiple unrelated questions at once |

---

## Query Validation Workflow

SENTINEL never executes SAIA-generated SPL directly. Every generated query passes
through a three-stage validation pipeline:

```
SAIA generates SPL
       │
       ▼
Stage 1: Structural validation (local, instant)
   • Non-empty string check
   • Starts with index= or | inputlookup or index=* (not raw text)
   • Does not contain blocked commands: sendemail, outputlookup, outputcsv
   • Length check: < 4096 characters
       │
       ▼
Stage 2: Splunk parser validation (MCP validate_spl, ~1–2s)
   • Sends SPL to /services/search/parser
   • Checks for syntax errors and unresolved macro references
   • Receives warnings for: wildcard indexes, JOIN commands, missing fields
   • Warnings are logged but do not block execution
       │
       ▼
Stage 3: Performance heuristics (local, instant)
   • Checks for time range — if missing, prepends earliest=-24h latest=now
   • Checks for result cap — if | head N is absent, appends | head 1000
   • Flags if the query will scan > 90 days (configurable limit)
       │
       ▼
Execute via search_spl (with SPL safety layer applied again server-side)
```

```python
# From agent_sherlock.py — simplified validation pipeline
def _validate_and_execute_saia_spl(self, spl: str, label: str) -> dict:
    # Stage 1: Structural check
    if not spl or len(spl) < 10:
        raise SherlockQueryError(f"{label}: SAIA returned empty SPL")
    for blocked in ("sendemail", "outputlookup", "outputcsv"):
        if blocked.lower() in spl.lower():
            raise SherlockSAIAError(f"{label}: SAIA generated blocked command: {blocked}")

    # Stage 2: Parser validation
    validation = self._mcp.validate_spl(spl)
    if not validation.get("valid"):
        raise SherlockQueryError(f"{label}: SPL syntax error — {validation.get('error')}")

    # Stage 3: Performance guards
    if "earliest=" not in spl and "latest=" not in spl:
        spl = f"{spl} earliest=-24h latest=now"
    if "| head" not in spl:
        spl = f"{spl} | head 1000"

    return self._mcp.search_spl(spl)
```

---

## Fallback Strategies When SAIA Is Unavailable

SAIA unavailability is handled transparently. The fallback hierarchy is:

```
Level 1: SAIA endpoint configured and responsive
         → Use SAIA-generated SPL (best specificity)

Level 2: SAIA endpoint configured but returning errors (timeout, 503, invalid JSON)
         → Use pre-built SPL template for this alert_type + phase combination
         → Log SherlockSAIAError with fallback indicator

Level 3: SAIA not configured (empty saia_endpoint or saia_token)
         → Use pre-built SPL template directly (no error logged — expected behaviour)
         → Investigation continues normally

Level 4: No matching SPL template for this alert_type + phase
         → Use generic phase template (broader scope, less targeted)
         → Log warning: "no specific template for {alert_type} phase {phase}"

Level 5: Generic template fails or returns no results
         → Phase is marked as partial/skipped
         → Investigation continues with remaining phases
         → Final report notes: "Phase B: template fallback, 0 results"
```

### Built-in SPL Templates (sample)

```python
# From agent_sherlock.py — _SPL_TEMPLATES (simplified)
_SPL_TEMPLATES = {
    "phase_b": {
        "RANSOMWARE_POWERSHELL_ENCODED": (
            'index=endpoint OR index=edr host="{host}" '
            'earliest={earliest} latest=now '
            'process_name IN ("powershell.exe","cmd.exe","wscript.exe","cscript.exe") '
            '| eval time=strftime(_time,"%Y-%m-%dT%H:%M:%SZ") '
            '| table time, process_name, parent_process_name, command_line, user '
            '| sort time | head 200'
        ),
        "INSIDER_THREAT_LARGE_UPLOAD": (
            'index=network OR index=proxy user="{user}" '
            'earliest={earliest} latest=now '
            'bytes_out>10485760 '
            '| eval mb_out=round(bytes_out/1048576,2) '
            '| table _time, src_ip, dest_ip, dest_port, url, mb_out '
            '| sort -mb_out | head 100'
        ),
        "_default": (
            'index=endpoint OR index=edr host="{host}" '
            'earliest={earliest} latest=now '
            '| eval time=strftime(_time,"%Y-%m-%dT%H:%M:%SZ") '
            '| table time, process_name, parent_process_name, command_line, user '
            '| sort time | head 500'
        ),
    },
    # ... phases C, D, E have their own template trees
}
```

### Testing Fallback Behaviour

```python
# Unit test verifying fallback when SAIA returns None
def test_phase_b_uses_template_when_saia_returns_none(mock_mcp, mock_audit):
    agent = _make_agent(mock_mcp)
    # Simulate SAIA unavailable
    with patch.object(agent, "_get_saia") as saia_factory:
        saia_factory.return_value.generate_spl.return_value = None
        case = make_case(alert_type="RANSOMWARE_POWERSHELL_ENCODED")
        result = agent.run(case, mock_audit)

    assert result["success"] is True
    # Investigation completed despite SAIA being unavailable
    assert "report" in result
```

### Monitoring SAIA Fallback Rate

Sage's weekly report includes a SAIA utilisation metric:

```json
{
  "agent_performance": {
    "sherlock": {
      "saia_queries_attempted":   142,
      "saia_queries_succeeded":   138,
      "saia_fallback_rate":       0.028,
      "avg_saia_latency_ms":      1840,
      "template_fallback_count":  4
    }
  }
}
```

If `saia_fallback_rate` exceeds 10%, SENTINEL logs a `SAIA_DEGRADED` health event and
Sage includes a recommendation to check the SAIA endpoint in the weekly report.

---

## SAIA Configuration Reference

```ini
# sentinel.conf [saia]
[saia]
saia_token    = <token-from-splunk-saia-portal>
saia_endpoint = https://<your-org>.api.saia.splunk.com

# Optional: per-call timeout override (default: 10s)
saia_timeout_s = 10

# Optional: maximum retries before falling back to templates (default: 1)
saia_max_retries = 1
```

```python
# Environment variable overrides (take precedence over sentinel.conf)
SENTINEL_SAIA_TOKEN    = "<token>"
SENTINEL_SAIA_ENDPOINT = "https://..."
```
