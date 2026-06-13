# SENTINEL MCP Server

This directory contains the configuration layer for the **Splunk MCP (Model Context Protocol) Server** that powers SENTINEL's agent tool-use capabilities. All four agents communicate exclusively through this server to query Splunk data and execute response actions.

---

## What the MCP Server Does

The Splunk MCP Server acts as a **structured API gateway** between SENTINEL's AI agents and the underlying Splunk platform and external integrations. Agents send tool-call requests in MCP format; the server validates inputs, enforces rate limits and safety gates, executes the underlying API calls, and returns structured JSON responses.

```
Agent (Python)
    │  MCP tool_call { name: "search_spl", input: {...} }
    ▼
MCP Server (Node.js, port 3000)
    │  Validates schema, checks rate limits, acquires locks
    ▼
Splunk REST API / EDR API / ITSM API / Threat Intel API
    │  Raw API response
    ▼
MCP Server
    │  Normalizes, post-processes, caches
    ▼
Agent ← structured JSON response
```

---

## Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| Splunk Enterprise | 9.2+ | With ES and AI Toolkit installed |
| Splunk MCP Server app | 1.0+ | Install from Splunkbase |
| Node.js | 18+ | Runtime for the MCP Server process |
| npm | 9+ | For dependency installation |

---

## Installation

### Step 1 — Install the Splunk MCP Server App

Install **Splunk MCP Server** from Splunkbase via **Apps → Manage Apps → Install from file** or directly from the Splunkbase catalog. The app installs the MCP Server runtime into `$SPLUNK_HOME/etc/apps/splunk_mcp_server/`.

### Step 2 — Install SENTINEL Custom Tool Definitions

The SENTINEL custom tools extend the base MCP Server with security-specific capabilities. Copy the tool definitions into the MCP Server's extension directory:

```bash
# From the sentinel-agentic-soc repo root
cp mcp_server/custom_tools/*.yaml \
    $SPLUNK_HOME/etc/apps/splunk_mcp_server/custom_tools/
```

The MCP Server hot-reloads YAML files from `custom_tools/` on change — no restart required.

### Step 3 — Configure the MCP Server

```bash
cd mcp_server/config/

# Create your local config from the template
cp mcp_server.conf mcp_server.local.conf

# Edit mcp_server.local.conf with your environment values
# Minimum required fields:
#   [splunk] host, port, api_token
#   [auth] agent_token (generate one below)
#   [server] tls_cert_path, tls_key_path
```

Generate a strong agent bearer token:

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

### Step 4 — Configure API Credentials

```bash
# Create your local credentials file (never commit this)
cp auth_tokens.conf auth_tokens.local.conf
chmod 600 auth_tokens.local.conf

# Edit auth_tokens.local.conf and replace every [REDACTED] with real values
# See the comments in auth_tokens.conf for where to obtain each credential
```

Required credentials for core functionality:

| Section | Required For |
|---------|-------------|
| `[splunk]` | All agent tool calls |
| `[mcp_server]` | Agent authentication to MCP Server |
| `[virustotal]` | `enrich_threat_intel` tool |
| `[servicenow]` or `[jira]` | `create_ticket` tool |
| `[slack]` | `notify_stakeholders` tool |
| `[edr_crowdstrike]` / `[edr_defender]` | `execute_response_action` — isolate/quarantine |
| `[identity_azuread]` / `[identity_okta]` | `execute_response_action` — disable user |
| `[firewall_panos]` / `[firewall_cisco_fmc]` | `execute_response_action` — block IP |

### Step 5 — Generate TLS Certificates

```bash
mkdir -p mcp_server/certs/

# Self-signed certificate for development
openssl req -x509 -newkey rsa:4096 \
    -keyout mcp_server/certs/mcp_server.key \
    -out    mcp_server/certs/mcp_server.crt \
    -days 365 -nodes \
    -subj "/CN=sentinel-mcp-server/O=SENTINEL/C=US"

chmod 600 mcp_server/certs/mcp_server.key
```

For production, use a certificate signed by your internal CA and restrict the key file to the MCP Server process user.

### Step 6 — Create the Splunk Service Account

In Splunk Web, create a dedicated service account for the MCP Server:

1. **Settings → Access Controls → Users → New User**
2. Username: `sentinel_service`
3. Assign roles: `sentinel_agent` (custom — see below), `can_delete`

Create the `sentinel_agent` custom role with minimum permissions:

```
Capabilities: search, edit_kvstore, list_inputs, rest_apps_management
Indexes (read): endpoint, network, identity, cloud, sentinel_*
Indexes (write): sentinel_audit, sentinel_cases, sentinel_metrics, sentinel_learning
```

Then generate an API token:

**Settings → Tokens → New Token** → Service account: `sentinel_service` → Copy the token to `auth_tokens.local.conf [splunk].api_token`

### Step 7 — Start the MCP Server

```bash
cd $SPLUNK_HOME/etc/apps/splunk_mcp_server/

# Install Node dependencies (first run only)
npm install

# Start the server (foreground, for testing)
node bin/server.js --config /path/to/sentinel-agentic-soc/mcp_server/config/mcp_server.local.conf

# Or start as a background service (systemd example)
sudo systemctl start splunk-mcp-server
```

### Step 8 — Verify the Server is Running

```bash
# Health check (unauthenticated)
curl -k https://localhost:3000/health
# Expected: {"status":"ok","version":"1.0.0","tools_loaded":14}

# Tool discovery (requires bearer token)
curl -k -H "Authorization: Bearer YOUR_AGENT_TOKEN" https://localhost:3000/tools
# Expected: JSON array of 14 tool definitions
```

---

## File Reference

```
mcp_server/
├── config/
│   ├── mcp_server.conf          # Server configuration template
│   ├── mcp_server.local.conf    # Your local config (gitignored)
│   ├── tool_definitions.json    # JSON Schema registry for all 14 tools
│   ├── auth_tokens.conf         # Credential template (gitignored when local)
│   └── auth_tokens.local.conf   # Your actual credentials (never commit)
│
└── custom_tools/
    ├── investigation_tools.yaml  # Runtime config for 10 investigation tools
    ├── response_tools.yaml       # Runtime config for 3 response tools + safety gates
    └── enrichment_tools.yaml     # Runtime config for threat intel tools + cache
```

---

## Tool Summary

### Investigation Tools (Vanguard + Sherlock + Sage)

| Tool | Description |
|------|-------------|
| `search_spl` | Execute arbitrary SPL queries |
| `get_indexes` | List available Splunk indexes |
| `run_saved_search` | Execute a saved search by name |
| `validate_spl` | Check SPL syntax before execution |
| `get_knowledge_objects` | Retrieve CIM data models and field extractions |
| `query_es_notable` | Query ES notable events |
| `get_asset_context` | Retrieve CMDB data for a host |
| `get_process_tree` | Reconstruct process ancestry from EDR data |
| `get_network_flows` | Retrieve NetFlow/Zeek data for a host |
| `get_user_activity` | Retrieve UEBA timeline for a user |

### Response Tools (Executor only)

| Tool | Description |
|------|-------------|
| `execute_response_action` | Execute containment actions (isolate, block, disable, quarantine) |
| `create_ticket` | Create incidents in ServiceNow or Jira |
| `notify_stakeholders` | Send Slack/PagerDuty/email notifications |

### Enrichment Tools (All agents)

| Tool | Description |
|------|-------------|
| `enrich_threat_intel` | Query VirusTotal, MISP, AbuseIPDB for IOC context |

---

## Adding Custom Tools

1. Add a JSON schema entry to `config/tool_definitions.json` following the existing pattern.
2. Add a YAML runtime configuration block to the appropriate `custom_tools/*.yaml` file.
3. Implement the handler class in the MCP Server's `handlers/` directory.
4. The server hot-reloads YAML files; restart is required for new handler code.

---

## Security Best Practices

**Credential management**
- Never commit `auth_tokens.local.conf` or `mcp_server.local.conf` to source control. Both are in `.gitignore`.
- Rotate the `agent_token` and `readonly_token` every 90 days.
- Use Splunk's built-in credential manager (`$SPLUNK_HOME/bin/splunk encrypt-string`) for production credential storage.
- The `auth_tokens.conf` template uses `[REDACTED]` placeholders — treat any file containing real values as a secret.

**Network exposure**
- Bind the MCP Server to `127.0.0.1` unless agents run on separate hosts. If agents are remote, place the MCP Server behind a TLS-terminating reverse proxy with mutual TLS.
- The `allowed_ips` setting in `[auth]` enforces a network-layer allowlist in addition to bearer token auth.
- Never expose the MCP Server port (3000) to the internet.

**Least-privilege execution**
- The `sentinel_service` Splunk account must not have `admin` or `sc_admin` roles.
- Response tool API credentials (EDR, firewall, identity) should use integration-specific service accounts with only the permissions needed for the specific actions (e.g., CrowdStrike: `device_manager` + `real_time_responder`; Azure AD: `User.ReadWrite.All` only).
- The `execute_response_action` tool requires Executor agent identity verification. Investigation agents cannot call it even with a valid bearer token.

**Audit trail**
- Every tool call that mutates state writes a pre-execution audit event to `sentinel_audit` before the external API call is made. If the server crashes mid-execution, the audit trail records the intent.
- Response locks in the `response_locks` KV Store prevent duplicate containment actions.
- All MCP Server logs are JSON-structured and should be ingested into Splunk via a monitored file input.

**Rate limiting**
- External API rate limits (VirusTotal 4 req/min free, AbuseIPDB 1,000/day free) are enforced in `enrichment_tools.yaml`. Do not increase these beyond your actual API tier.
- The global rate limit (`global_rps_max = 100`) protects Splunk from search storms during high-volume incident periods.

---

## Troubleshooting

**Health endpoint returns 503**

The MCP Server failed to load one or more tool schemas. Check the server log:
```bash
tail -f mcp_server/logs/mcp_server.log | python -m json.tool
```
Look for `"level": "ERROR"` entries with `"context": "tool_registry"`.

**Agent receives `401 Unauthorized`**

The bearer token in the agent's config does not match `agent_token` in `mcp_server.local.conf`. Regenerate and redeploy both.

**`search_spl` returns `Splunk search quota exceeded`**

Too many concurrent searches. Either increase the Splunk `max_searches_per_process` limit or reduce `connection_pool_size` in `[splunk]` section of `mcp_server.conf`.

**`execute_response_action` returns `Safety gate: agent identity rejected`**

The tool was called by a non-Executor agent (Vanguard/Sherlock/Sage). Response tools are restricted to the Executor agent bearer token. Check which agent is making the call.

**VirusTotal returns `429 Too Many Requests`**

Free tier quota (4 req/min) exceeded. The server queues requests up to `queue_max_depth=100`. If the queue is full, requests are rejected. Consider upgrading to a paid VirusTotal tier or reducing the number of IOCs submitted per case.
