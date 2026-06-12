# SENTINEL Setup Guide

Complete installation guide for the SENTINEL Autonomous Agentic SOC Commander.
Estimated total time: 4–6 hours (plus 2–3 business days waiting for SAIA activation).

## Prerequisites

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| OS | Windows Server 2019 / RHEL 8 / Ubuntu 20.04 | Ubuntu 22.04 LTS |
| CPU | 8 cores | 16 cores |
| RAM | 16 GB | 32 GB |
| Disk | 100 GB SSD | 500 GB NVMe |
| Python | 3.9 | 3.11 |
| Splunk Enterprise | 9.0 | 9.3 |
| Network | Outbound HTTPS to Splunkbase, Cisco AI Cloud | Isolated VLAN with egress proxy |

Python dependencies are listed in `app/sentinel/lib/requirements.txt`. Install them into Splunk's bundled Python environment — do not use a system Python that Splunk cannot see.

---

## Step 1: Create a Splunk Account and Download the Free Trial

1. Go to `splunk.com/en_us/download/splunk-enterprise.html` and register for a free account.
2. Download **Splunk Enterprise** for your platform (`.deb`, `.rpm`, or `.msi`).
3. The free license allows 500 MB/day of indexing — sufficient for the SENTINEL demo scenarios.
4. Save your Splunk credentials. You will need them in Step 10.

---

## Step 2: Request a Developer License (6 months)

The free license is limited to 500 MB/day. The Developer License removes this cap for 6 months, which is required if you plan to run realistic data volumes.

1. Log in to your Splunk account at `splunk.com`.
2. Navigate to **My Portal → Licenses → Request Developer License**.
3. Complete the developer program registration form.
4. A `.lic` file will be emailed within 1–2 business days.
5. Keep the `.lic` file — you will install it in Step 3.

---

## Step 3: Install Splunk Enterprise

### Linux

```bash
# Example for Ubuntu/Debian — adjust for your package format
sudo dpkg -i splunk-9.3.0-*.deb
sudo /opt/splunk/bin/splunk start --accept-license --answer-yes
sudo /opt/splunk/bin/splunk enable boot-start -user splunk

# Install the developer license (if obtained in Step 2)
sudo /opt/splunk/bin/splunk add licenses /path/to/developer.lic \
    -auth admin:changeme
```

### Windows

Run the `.msi` installer as Administrator. Accept the license, choose **Customized Installation**, and note the installation path (default: `C:\Program Files\Splunk`).

### Post-install verification

```bash
# Verify Splunk is running
curl -k https://localhost:8089/services/server/info \
    -u admin:changeme | python3 -m json.tool | grep version
```

You should see `"version": "9.x.x"`. The Splunk Web UI is available at `http://localhost:8000`.

---

## Step 4: Install Splunk Enterprise Security (ES)

SENTINEL depends on the ES `notable` index and the Asset Center KV Store.

1. Download **Splunk Enterprise Security** from Splunkbase (requires a Splunk account).
   Filename: `splunk-enterprise-security_*.spl`
2. Install via Splunk Web:
   - **Apps → Manage Apps → Install app from file**
   - Upload the `.spl` file and click **Upload**.
3. After the install prompt restarts Splunk, complete the ES setup wizard:
   - Accept the post-install configuration checks.
   - Enable **Risk-Based Alerting (RBA)** — required for the `risk_score` field.
   - Enable **Asset and Identity Management** — required for `get_asset_context`.
4. Verify ES is running:

```bash
curl -k https://localhost:8089/services/apps/local/SplunkEnterpriseSecuritySuite \
    -u admin:changeme | grep "<s:key name=\"state\">enabled"
```

---

## Step 5: Install Splunk AI Assistant (SAIA)

> **Important:** SAIA requires 2–3 business days for the Splunk team to provision
> your instance. Submit the request immediately — do not wait until other steps are done.

1. Go to `splunk.com/en_us/products/splunk-ai-assistant.html`.
2. Click **Request Early Access** and fill in your Splunk account details.
3. You will receive an email with:
   - Your SAIA endpoint URL (`https://<your-org>.api.saia.splunk.com`)
   - An API token scoped to SPL generation
4. While waiting, continue with Steps 6–9. The SAIA token is only needed in Step 10.
5. To verify activation once you receive it:

```bash
curl -X POST https://<your-org>.api.saia.splunk.com/services/assistant/v1/generate \
    -H "Authorization: Bearer <your-saia-token>" \
    -H "Content-Type: application/json" \
    -d '{"question": "Show failed logins in the last hour", "context": {}}'
```

A valid response returns a JSON object with a `spl` field.

**If SAIA is not yet active:** SENTINEL falls back to pre-built SPL templates in
`agent_sherlock.py`. All investigation phases remain functional; only the NL→SPL
generation is skipped. See [TROUBLESHOOTING.md](TROUBLESHOOTING.md#saia-activation-delays).

---

## Step 6: Install Splunk MCP Server

The MCP Server is the tool execution layer that all four SENTINEL agents communicate with.

1. Download **Splunk MCP Server** from Splunkbase.
   Search for "MCP Server" in the Splunkbase catalog.
2. Install as a Splunk app (same process as Step 4).
3. Copy the SENTINEL MCP configuration into place:

```bash
# From the SENTINEL repository root
cp mcp_server/config/mcp_server.conf \
    $SPLUNK_HOME/etc/apps/splunk_mcp_server/local/mcp_server.local.conf
```

4. Edit `mcp_server.local.conf` and fill in the `[REDACTED]` fields:
   - `[splunk] username` — your Splunk service account (Step 10)
   - `[auth] agent_token_ref` — generate with `python3 -c "import secrets; print(secrets.token_urlsafe(48))"`

5. Copy the SENTINEL custom tool definitions:

```bash
cp mcp_server/custom_tools/*.yaml \
    $SPLUNK_HOME/etc/apps/splunk_mcp_server/custom_tools/
```

6. Restart Splunk to load the new configuration:

```bash
$SPLUNK_HOME/bin/splunk restart
```

7. Verify the MCP Server is responding:

```bash
curl -k https://localhost:3000/health
# Expected: {"status": "ok", "tools_loaded": 14}
```

---

## Step 7: Install AI Toolkit and Enable Hosted Models

SENTINEL uses two hosted models served by Splunk AI Toolkit:
- **Foundation-Sec-1.1-8B-Instruct** — alert classification (VanguardAgent)
- **Cisco Deep Time Series** — anomaly forecasting (SageAgent)

1. In Splunk Web, navigate to **Apps → Splunk AI Toolkit**.
   If not installed, download it from Splunkbase.
2. Go to **AI Toolkit → Hosted Models**.
3. Enable **Foundation-Sec-1.1-8B-Instruct**:
   - Click **Add Model → Foundation Security Models**.
   - Select `foundation-sec-1.1-8b-instruct`.
   - Click **Enable**. The model loads in 2–5 minutes.
4. Enable **Cisco Deep Time Series**:
   - Click **Add Model → Cisco Models**.
   - Select `cisco-deep-time-series`.
   - Click **Enable**.
5. Note the inference endpoints shown on the model detail page:
   ```
   Foundation-Sec:  POST /services/ml/models/foundation-sec-1.1-8b-instruct/predict
   Cisco Deep TS:   POST /services/ml/models/cisco-deep-time-series/predict
   ```
   These are relative to `https://localhost:8089`.
6. Generate an API token with `ml_model_inference` capability:
   ```bash
   $SPLUNK_HOME/bin/splunk create-authtokens \
       -name sentinel_model_token \
       -user sentinel_service \
       -expiry 7776000
   ```

---

## Step 8: Configure HEC (HTTP Event Collector) for Audit Logging

SENTINEL's audit logger writes immutable audit trails to Splunk via HEC.

1. In Splunk Web, go to **Settings → Data Inputs → HTTP Event Collector**.
2. Click **Global Settings** and ensure HEC is **Enabled** on port `8088`.
3. Click **New Token**:
   - **Name:** `sentinel_audit`
   - **Source type:** `sentinel:audit`
   - **Index:** Create a new index called `sentinel_audit` with `frozenTimePeriodInSecs = 31536000` (1 year retention).
   - **Allowed indexes:** `sentinel_audit`
4. Copy the generated token (format: `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`).
5. Verify HEC is working:

```bash
curl -k https://localhost:8088/services/collector/event \
    -H "Authorization: Splunk <your-hec-token>" \
    -d '{"event": {"test": "hec_verification", "sentinel": true}}'
# Expected: {"text":"Success","code":0}
```

---

## Step 9: Install the SENTINEL App

```bash
# Clone or copy the SENTINEL repository to the Splunk apps directory
cp -r /path/to/SENTINEL/app/sentinel \
    $SPLUNK_HOME/etc/apps/sentinel

# Install Python dependencies into the app's lib directory
pip3 install -r $SPLUNK_HOME/etc/apps/sentinel/lib/requirements.txt \
    --target $SPLUNK_HOME/etc/apps/sentinel/lib/

# Restart Splunk to register the new app
$SPLUNK_HOME/bin/splunk restart
```

Verify the app is registered:

```bash
$SPLUNK_HOME/bin/splunk display app sentinel
```

---

## Step 10: Configure API Credentials and Auth Tokens

All credentials are stored in `app/sentinel/local/sentinel.conf` (never committed to source control — this file is `.gitignore`d).

Create `app/sentinel/local/sentinel.conf`:

```ini
[auth]
# MCP Server bearer token (generated in Step 6)
mcp_token = <your-mcp-agent-token>

# Splunk REST API service account token (generated in Step 7)
splunk_api_token = <your-splunk-api-token>

[hec]
# HEC token for audit logging (generated in Step 8)
hec_token = <your-hec-token>
hec_host  = localhost
hec_port  = 8088

[models]
# Hosted model API token (generated in Step 7)
hosted_model_token = <your-model-api-token>
foundation_sec_endpoint = https://localhost:8089/services/ml/models/foundation-sec-1.1-8b-instruct/predict
cisco_ts_endpoint = https://localhost:8089/services/ml/models/cisco-deep-time-series/predict

[saia]
# SAIA token and endpoint (received in Step 5, or leave blank for fallback mode)
saia_token    = <your-saia-token>
saia_endpoint = https://<your-org>.api.saia.splunk.com

[response]
# On-call email for human-override notifications
oncall_email = soc@your-org.internal

# ITSM integration (optional — for create_ticket action)
# servicenow_url   = https://your-org.service-now.com
# servicenow_user  = sentinel_api
# servicenow_token = <servicenow-token>
```

Set file permissions so only the Splunk service account can read it:

```bash
chmod 600 $SPLUNK_HOME/etc/apps/sentinel/local/sentinel.conf
chown splunk:splunk $SPLUNK_HOME/etc/apps/sentinel/local/sentinel.conf
```

Encrypt the credentials using Splunk's built-in credential store:

```bash
$SPLUNK_HOME/bin/splunk encrypt -file \
    $SPLUNK_HOME/etc/apps/sentinel/local/sentinel.conf
```

---

## Step 11: Run Demo Scenarios to Verify Installation

SENTINEL ships with four demo scenarios that exercise the full pipeline without
requiring real threat data.

```bash
# Run the orchestrator in demo mode (single cycle, exits when done)
cd $SPLUNK_HOME/etc/apps/sentinel/bin
python sentinel_orchestrator.py --demo

# Or run a specific scenario
python sentinel_orchestrator.py --demo --scenario ransomware
python sentinel_orchestrator.py --demo --scenario insider_threat
python sentinel_orchestrator.py --demo --scenario supply_chain
python sentinel_orchestrator.py --demo --scenario cloud_breach
```

Each scenario produces output similar to:

```
[SENTINEL DEMO] Injecting alert: RANSOMWARE_POWERSHELL_ENCODED
[VANGUARD]  Risk score: 88 | Decision: AUTO_ESCALATE | Classification: RANSOMWARE_INITIAL_ACCESS
[SHERLOCK]  Phase A complete: 3 hosts in scope | Phase B: 47 timeline events
[SHERLOCK]  Blast radius: 3 hosts, 2 users, 1 service | Dwell time: ~4h
[EXECUTOR]  Mode: FULL_AUTONOMY | Executing: isolate_host, kill_process, quarantine_file
[EXECUTOR]  All 3 actions verified ✓ | Rollback timers scheduled
[SAGE]      IOCs extracted: 2 IPs, 1 domain | Rule proposed: PS_ENCODED_FROM_OFFICE_PARENT
[SENTINEL]  Case CASE-DEMO-001 CLOSED in 142s | MTTR: 2.4 minutes
```

Run the test suite to verify all components are importable:

```bash
cd /path/to/SENTINEL
pytest tests/ -v --tb=short
```

All unit tests should pass. Integration tests are skipped by default
(`SENTINEL_RUN_INTEGRATION=1` enables them — requires live Splunk).

---

## Troubleshooting Common Issues

### MCP Server returns "connection refused"

```
MCPConnectionError: Failed to connect to MCP Server at https://127.0.0.1:3000
```

**Causes and fixes:**
1. MCP Server not started — check `$SPLUNK_HOME/var/log/splunk/mcp_server.log`
2. Wrong port — verify `[server] port` in `mcp_server.local.conf`
3. TLS mismatch — check `tls_cert_path` and `tls_key_path` exist and are readable
4. Firewall blocking loopback — `sudo ufw allow from 127.0.0.1 to any port 3000`

### Foundation-Sec model returns 404

```
HTTPError: 404 Not Found on POST /services/ml/models/foundation-sec-1.1-8b-instruct/predict
```

The model is not enabled. In Splunk Web → AI Toolkit → Hosted Models, verify the model status is **Running** (not Stopped or Loading). Models can take 5 minutes to load after enabling.

### SAIA returns 401 Unauthorized

Check that `saia_token` in `sentinel.conf` matches the token emailed by Splunk. Tokens expire — request a new one from the SAIA portal if it is older than 90 days.

### KV Store "collection not found" errors

```
MCPToolError: KV Store collection 'sentinel_cases' not found
```

The SENTINEL app did not finish initializing. Wait 60 seconds after app install and retry. If the error persists:

```bash
$SPLUNK_HOME/bin/splunk _internal call /servicesNS/nobody/sentinel/storage/collections/config \
    -post:name sentinel_cases -auth admin:changeme
```

### HEC returns "Invalid token"

Verify the token in `sentinel.conf [hec] hec_token` matches what Splunk Web shows
under **Settings → Data Inputs → HTTP Event Collector**. Tokens are case-sensitive.

### Agent import errors in pytest

```
ModuleNotFoundError: No module named 'mcp_client'
```

The `tests/conftest.py` adds `app/sentinel/bin/` to `sys.path` automatically.
If running pytest from outside the SENTINEL repository root, set the path manually:

```bash
cd /path/to/SENTINEL
pytest tests/ -v
```

### "Permission denied" when writing audit log

The Splunk service account must have write access to both the HEC endpoint and the
fallback JSONL path (`app/sentinel/logs/audit.jsonl`). Check file ownership and that
the Splunk service account user matches `chown` in Step 10.
