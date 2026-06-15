# SENTINEL — Splunk Integration Proof

For each Splunk AI/platform capability: what SENTINEL uses it for, the code
that implements it, the API surface it calls, the request/response format,
and current status. All six are implemented and exercised by the local test
suite / simulation; all run against documented fallback paths until pointed
at a live Splunk Cloud/Enterprise stack (see [DEPLOYMENT.md](DEPLOYMENT.md)).

---

## 1. Splunk MCP Server

**Used for:** All four agents call MCP tools for read-only investigation
(`search_spl`, `get_asset_context`, `get_process_tree`, `get_network_flows`,
`query_es_notable`, `enrich_threat_intel`, etc.) and gated response actions
(`execute_response_action`, `create_ticket`, `notify_stakeholders`).

**Code:** `app/sentinel/bin/mcp_client.py` — `SplunkMCPClient`
(circuit breaker, exponential-backoff retry, retry queue, per-call audit
logging, `from_config()` classmethod reading `[mcp] server_url` /
`auth_token` from `sentinel.conf`).

**Endpoint:** `POST {server_url}/tools/{tool_name}` (e.g.
`https://localhost:3000/tools/search_spl`), Bearer token auth,
`GET {server_url}/health` for circuit-breaker probes.

**Request/response format:**
```json
// Request
POST /tools/search_spl
Authorization: Bearer <agent_token>
{"tool": "search_spl", "input": {"query": "index=endpoint | head 5", "earliest": "-24h"}}

// Response
{"result": {...tool-specific payload...}, "status": "ok"}
```

**Status:** Implemented, tested locally (circuit breaker, retries, and
fallback paths covered by unit tests), ready for Splunk backend — point
`[mcp] server_url` at a running MCP Server instance configured against the
target Splunk stack.

---

## 2. Splunk AI Assistant (SAIA)

**Used for:** SherlockAgent's primary natural-language → SPL path during
investigation (Phase B/C/D timeline, lateral-movement, and identity queries).

**Code:** `app/sentinel/bin/saia_client.py` — `SAIAClient`
(`from_config()`, `generate_spl()`). On failure or missing token, falls back
to `app/sentinel/lookups/saia_cached_queries.csv` (per-phase, per-alert-type
cached SPL templates).

**Endpoint:** `POST {splunk_host}:8089/services/assistant/v1/generate`,
Bearer token auth.

**Request/response format:**
```json
// Request
POST /services/assistant/v1/generate
Authorization: Bearer <saia_token>
{"prompt": "Show me all processes on this host", "context": {"host": "WORKSTATION-07", "earliest": "-24h"}}

// Response
{"spl": "index=endpoint host=WORKSTATION-07 | head 100", "confidence": 0.91}
```

**Status:** Implemented, tested locally (cached-template fallback verified
by unit tests and `scripts/verify_integration.py` check 4), ready for Splunk
backend — set `[saia] token` once the AI Assistant app is activated on the
target stack.

---

## 3. Foundation-Sec Hosted Model

**Used for:** Vanguard (alert classification + composite risk scoring),
Sherlock (investigation report synthesis), Executor (action justification),
Sage (efficacy analysis) — all via the same hosted-model client.

**Code:** `app/sentinel/bin/hosted_model_client.py` — `HostedModelClient`
(`from_config()`, `generate_json()`, `is_available()`,
`HostedModelUnavailable` / `HostedModelResponseError`). On unavailability,
each agent falls back to its rule-based logic (e.g. Vanguard's 20+ pattern
classifier).

**Endpoint:** `POST {splunk_host}:8089/services/ml/models/foundation-sec-1.1-8b-instruct/predict`
via the Splunk AI Toolkit, Bearer token auth.

**Request/response format:**
```json
// Request
POST /services/ml/models/foundation-sec-1.1-8b-instruct/predict
Authorization: Bearer <hosted_models_api_token>
{"input": {"alert_type": "RANSOMWARE_POWERSHELL_ENCODED", "host": "WORKSTATION-07", "raw_risk_score": 88}, "max_tokens": 256}

// Response
{"output": {"classification": "TRUE_POSITIVE", "mitre_techniques": ["T1059.001"], "risk_score": 92}}
```

**Status:** Implemented, tested locally (retry/backoff and rule-based
fallback covered by unit tests and `scripts/verify_integration.py` check 5
— reports `SKIP` when no endpoint configured), ready for Splunk backend —
set `[hosted_models] foundation_sec_endpoint` / `api_token` once the model is
deployed via AI Toolkit.

---

## 4. Cisco Deep Time Series Hosted Model

**Used for:** Sage's anomaly forecasting, threshold optimization, and
MTTR/FP trend analysis during its daily/weekly sweeps.

**Code:** `app/sentinel/bin/agent_sage.py` — `_CiscoTimeSeriesClient`
(configurable `/v1/time-series/analyze` endpoint). Falls back to the
built-in `_TimeSeries` statistical implementation (moving average + stddev
bands) when `[cisco_ts] url`/`token` are blank.

**Endpoint:** `POST {cisco_ts_url}/v1/time-series/analyze`, Bearer token
auth; health-checked via `GET {cisco_ts_url}/health`.

**Request/response format:**
```json
// Request
POST /v1/time-series/analyze
Authorization: Bearer <cisco_ts_token>
{"series": [{"ts": "2026-06-14T00:00:00Z", "value": 12}, ...], "metric": "mttr_minutes"}

// Response
{"forecast": [{"ts": "2026-06-15T00:00:00Z", "value": 9.5, "lower": 6.0, "upper": 13.0}], "anomalies": []}
```

**Status:** Implemented, tested locally (built-in `_TimeSeries` fallback
covered by unit tests; `scripts/verify_integration.py` check 6 reports `SKIP`
when no endpoint configured — "Sage uses built-in statistical fallback"),
ready for Splunk backend — set `[cisco_ts] url` / `token` if a Deep Time
Series endpoint is available.

---

## 5. Splunk Python SDK

**Used for:** Direct REST access to ad-hoc search jobs, KV Store collections
(`sentinel_cases`, `response_locks`, `baseline_cache`, `recent_actions`,
`agent_state`), saved searches, Enterprise Security notables, and risk
scores — the lower-level REST layer underneath agent-facing helpers.

**Code:** `app/sentinel/bin/utils/splunk_connector.py` — `SplunkConnector`
(wraps `splunklib.client` / `splunklib.results` from the `splunk-sdk`
package, listed in `requirements.txt`). Methods: `search()`, `search_iter()`,
`search_one()`, `get_saved_searches()`, `dispatch_saved_search()`,
`kvstore_get/query/upsert/delete/batch_delete()`, `create_notable()`,
`update_risk_score()`, `get_risk_score()`. Lazy-connects via
`splunklib.client.connect()`, token or username/password auth from
`sentinel.conf`, automatic reconnect on session-TTL expiry.

**Endpoint:** `{scheme}://{host}:{port}` (default `https://localhost:8089`)
— standard Splunk management REST API (`/services/search/jobs`,
`/servicesNS/nobody/sentinel/storage/collections/data/...`, etc.) via the SDK.

**Request/response format:**
```python
conn = SplunkConnector()
results = conn.search("index=endpoint | head 10")  # -> list[dict] (search_results.ResultsReader rows)
conn.kvstore_upsert("agent_state", {"_key": "vanguard", "last_run": "2026-06-14T00:00:00Z"})
```

**Status:** Implemented, tested locally (`splunklib` import is guarded —
module is importable and unit-testable even without the SDK installed; raises
`RuntimeError` only on an actual `connect()` call), ready for Splunk
backend — works against any reachable Splunk Enterprise/Cloud REST endpoint
given `[splunk] host`/`api_token`.

---

## 6. Splunk App Inspect

**Used for:** Pre-certification validation of the packaged `sentinel` app
before installing it on Splunk Cloud (Cloud-vetted apps must pass
`splunk-appinspect` in `precert`/`cloud` mode before ACS will accept them).

**Code:** App packaging metadata lives in `app/sentinel/default/app.conf`
(`[install]`, `[launcher]`, `[ui]` stanzas — `requires_splunk_version =
9.2.0`, default view `sentinel_war_room`). The deployment pipeline
(`docs/DEPLOYMENT.md` Step 7) runs:

```bash
slim package app/sentinel
splunk-appinspect inspect sentinel.tgz --mode precert
acs apps install --stack <stack> --app sentinel.tgz --acs-token '<jwt>'
```

**Endpoint:** `splunk-appinspect` is a local CLI tool (no network call); the
subsequent install goes through the ACS apps API
(`https://admin.splunk.com/<stack>/adminconfig/v2/apps`).

**Request/response format:**
```text
$ splunk-appinspect inspect sentinel.tgz --mode precert
...
Result: PASS (0 failures, 0 errors, N warnings)
```

**Status:** Implemented — `app.conf` is structured for Cloud compliance
(versioned `[install]`, `requires_splunk_version`, `local/` overrides
excluded from the package via `.gitignore`); packaging/inspect commands are
documented and ready to run, pending a Splunk Cloud stack to install onto.
