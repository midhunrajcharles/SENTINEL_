# SENTINEL — Production Deployment Guide (Splunk Cloud)

Everything in `app/sentinel/bin/` is written against real Splunk REST, HEC,
MCP, SAIA, and hosted-model endpoints, gated behind `app/sentinel/local/sentinel.conf`.
The local proof-of-concept runs without any of this configured (fallback
paths kick in everywhere — see [SPLUNK_INTEGRATION.md](SPLUNK_INTEGRATION.md)).
This guide is the path from "fallback mode" to "live Splunk Cloud stack."

**Estimated time: 4 hours** (most of it is waiting on Splunk Cloud
provisioning and ACS propagation, not configuration work).

## Step 1 — Sign up for a Splunk Cloud trial

Go to splunk.com, request the 14-day Splunk Cloud Platform trial. Provisioning
emails typically arrive within 1–4 hours and contain your stack name
(`<stack>.splunkcloud.com`) and initial admin credentials.

## Step 2 — Allowlist your IP via the ACS CLI

Self-service Cloud stacks block REST (`:8089`) and HEC (`:8088`) until your
IP is allowlisted. Find your public IP:

```bash
curl https://api.ipify.org
```

Generate an ACS token in **Settings → Tokens → New Token** (audience
`admin`), install the ACS CLI, then either:

```bash
pip install splunk-acs

acs allow-list add --feature search-api --subnet <your-ip>/32 --stack <stack>
acs allow-list add --feature hec        --subnet <your-ip>/32 --stack <stack>
```

or via Splunk Web: **Settings → IP Allowlist → Add your IP** for "Search
API" and "HEC", or run the equivalent step in `scripts/setup_splunk_cloud.py`:

```bash
python scripts/setup_splunk_cloud.py --stack <stack> \
  --admin-password '<password>' --acs-token '<jwt>' --steps allowlist
```

Allow ~60s for changes to propagate.

## Step 3 — Create the `sentinel_service` account

Self-service Cloud stacks don't expose role/user creation over REST, so do
this in Splunk Web:

1. **Settings → Roles → New Role** — name it `sentinel_agent`. Grant:
   `edit_tokens_own`, `list_inputs`, `edit_local_apps`, capability to read/write
   the `sentinel_*` indexes, and KV Store read/write on the `sentinel` app.
2. **Settings → Users → New User** — name it `sentinel_service`, assign the
   `sentinel_agent` role.

## Step 4 — Generate an auth token

While logged in as `sentinel_service`: **Settings → Tokens → New Token**,
audience = `sentinel_service`, no expiration (or a long one for the trial).
Copy the token — this becomes `[splunk] api_token` in Step 5.

Or via REST API, as an admin (note: omit `not_before` — Splunk Cloud rejects
token requests that set `nbf`):

```bash
curl -k -u sc_admin:<password> \
  https://<stack>.splunkcloud.com:8089/services/authorization/tokens \
  -d name=sentinel_service \
  -d audience=SENTINEL \
  -d expires_on=+7d
```

## Step 5 — Update `sentinel.conf`

Edit `app/sentinel/local/sentinel.conf` (gitignored, never committed):

```ini
[general]
splunk_host = <stack>.splunkcloud.com
verify_ssl  = true

[splunk]
host      = <stack>.splunkcloud.com
api_token = <token from Step 4>

[hec]
url   = https://<stack>.splunkcloud.com:8088
token = <hec token from Step 6>
index = sentinel_audit
```

Leave `[saia]`, `[hosted_models]`, `[cisco_ts]` blank until those services are
activated on your stack — agents fall back to cached/rule-based/statistical
paths automatically (see SPLUNK_INTEGRATION.md).

## Step 6 — Create indexes and HEC token

```bash
python scripts/setup_splunk_cloud.py --stack <stack> \
  --admin-password '<password>' --acs-token '<jwt>' --steps indexes,hec
```

This creates `sentinel_alerts`, `sentinel_audit`, `sentinel_cases`,
`sentinel_metrics`, enables HEC, and prints a HEC token — paste it into
`[hec] token` in Step 5.

## Step 7 — Deploy the SENTINEL app via ACS

Package, validate, and install the app:

```bash
slim package app/sentinel
splunk-appinspect inspect sentinel.tgz --mode precert
acs apps install --stack <stack> --app sentinel.tgz --acs-token '<jwt>'
```

This registers the `sentinel` app, its KV Store collections
(`sentinel_cases`, `response_locks`, `baseline_cache`, `recent_actions`,
`agent_state`), and the `sentinel_war_room` / efficacy dashboards.

## Step 8 — Inject demo data via HEC

```bash
python scripts/inject_synthetic_attack_data.py --scenario ransomware
```

Sends CIM-aligned synthetic events to the indexes created in Step 6. Use
`--scenario all` for the full set (ransomware, insider_threat, brute_force,
supply_chain). If HEC returns 503 during the trial's warm-up, fall back to
`python scripts/inject_via_file.py --scenario ransomware --index main`.

## Step 9 — Start the agent orchestrator

```bash
python app/sentinel/bin/sentinel_orchestrator.py --once
```

Run `python scripts/verify_integration.py` first to confirm each integration
point (Splunk REST, HEC, MCP, SAIA, hosted models, KV Store, audit logging)
reports `PASS` or an expected `SKIP` (optional components without a
configured endpoint).

## Step 10 — Access the dashboard

Open `https://<stack>.splunkcloud.com/en-US/app/sentinel/sentinel_war_room`
for the live case state, agent health, and audit stream — or open
`demo/sentinel_war_room_live.html` locally for the same UI against the local
simulation backend.

---

**Total: ~4 hours**, dominated by Splunk Cloud provisioning (1–4h, mostly
waiting) plus ~30–45 minutes of the steps above once the stack is live.
