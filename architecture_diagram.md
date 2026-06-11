# SENTINEL: Autonomous Agentic SOC Commander
## System Architecture

> **Render the full diagram:** `java -jar plantuml.jar architecture_diagram.puml`
> or open `architecture_diagram.png` for the pre-rendered version.

The ASCII diagram below is a fallback reference. It preserves the column structure and
all data-flow relationships shown in the PlantUML source.

---

```
╔══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╗
║                                    SENTINEL: Autonomous Agentic SOC Commander                                                                               ║
║                         Autonomous Triage  →  Investigation  →  Response  →  Learning                                                                       ║
╚══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╝

╔══════════════════╗          ╔══════════════════════════════╗    ╔══════════════════════════════════════╗    ╔═══════════════════════════════════════╗    ╔══════════════════════════════════════╗
║  DATA SOURCES    ║          ║    SPLUNK PLATFORM           ║    ║       MCP & AI LAYER                 ║    ║       SENTINEL AGENTS                 ║    ║     RESPONSE & OUTPUT                ║
╠══════════════════╣          ╠══════════════════════════════╣    ╠══════════════════════════════════════╣    ╠═══════════════════════════════════════╣    ╠══════════════════════════════════════╣
║                  ║          ║  ┌──────────────────────┐    ║    ║  ┌────────────────────────────────┐  ║    ║  ┌─────────────────────────────────┐  ║    ║  ┌──────────────────────────────┐  ║
║ ┌──────────────┐ ║          ║  │ Splunk Indexes        │    ║    ║  │  Splunk MCP Server  :3000      │  ║    ║  │      SentinelOrchestrator        │  ║    ║  │   CONTAINMENT ACTIONS        │  ║
║ │     EDR      │ ║──────────║─▶│ ─────────────────     │    ║    ║  │  ── Bidirectional ──           │  ║    ║  │  ─────────────────────────────  │  ║    ║  │ ─────────────────────────── │  ║
║ │              │ ║  Sysmon/ ║  │ endpoint / edr        │    ║    ║  │  HTTPS · JSON-RPC 2.0          │  ║    ║  │  Priority queue (heapq)         │  ║    ║  │ isolate_host                 │  ║
║ │ CrowdStrike  │ ║  EDR     ║  │ network / dns         │    ║    ║  │  Bearer token per agent        │  ║    ║  │  BoundedSemaphore: 5 cases      │  ║    ║  │  CrowdStrike contain         │  ║
║ │ SentinelOne  │ ║  events  ║  │ identity / auth       │◀───║────║──│  Circuit breaker (5→OPEN/30s)  │  ║    ║  │  State machine:                 │  ║    ║  │  Defender isolate            │  ║
║ │ Sysmon       │ ║          ║  │ cloud / proxy         │    ║    ║  │  Rate limit: 100 rps global    │  ║    ║  │  QUEUED→TRIAGING→INVESTIGATING  │  ║    ║  │  Rollback: 4 h              │  ║
║ └──────────────┘ ║          ║  │ sentinel_audit        │    ║    ║  │  Cache: LRU 500 entries        │  ║    ║  │  →DECIDING→RESPONDING→LEARNING  │  ║    ║  │                             │  ║
║                  ║          ║  │ sentinel_learning      │    ║    ║  │                                │  ║    ║  │  →CLOSED / ERROR / HALTED       │  ║    ║  │ block_ip                     │  ║
║ ┌──────────────┐ ║          ║  └──────────────────────┘    ║    ║  │  Investigation Tools (R/O):    │  ║    ║  │  Retry: max 3 per case          │  ║    ║  │  Palo Alto DAG               │  ║
║ │   Firewall   │ ║─session──║▶                             ║    ║  │  search_spl  validate_spl      │  ║    ║  │  Auto-respond: score ≥ 90       │  ║    ║  │  Cisco FMC rule              │  ║
║ │              │ ║  logs    ║  ┌──────────────────────┐    ║◀───║──│  get_asset_context             │  ║    ║  │  Poll: every 60s                │  ║    ║  │  Rollback: 72 h             │  ║
║ │ Palo Alto    │ ║          ║  │  Splunk Enterprise   │    ║    ║  │  get_process_tree              │  ║    ║  └─────────────────────────────────┘  ║    ║  │                             │  ║
║ │ Cisco FMC    │ ║          ║  │  ─────────────────── │    ║    ║  │  get_network_flows             │  ║    ║           │                           ║    ║  │ kill_process                 │  ║
║ └──────────────┘ ║          ║  │  Enterprise Security │◀───║────║──│  get_user_activity             │──║────║──▶        │ TRIAGING                  ║    ║  │  CrowdStrike RTR             │  ║
║                  ║          ║  │   RBA / Notables     │    ║    ║  │  query_es_notable              │  ║    ║           ▼                           ║    ║  │  Irreversible (timer=0)      │  ║
║ ┌──────────────┐ ║──auth/── ║  │   Asset Center       │────║────║─▶│  run_saved_search              │  ║    ║  ┌─────────────────────────────────┐  ║    ║  └──────────────────────────────┘  ║
║ │   Identity   │ ║  LDAP    ║  │   MITRE overlay      │    ║    ║  │  get_indexes                   │  ║    ║  │  ① VANGUARD  (Triage)           │  ║    ║                                     ║
║ │              │ ║  events  ║  │                      │    ║    ║  │  get_knowledge_objects         │  ║    ║  │  ──────────────────────────────  │  ║    ║  ┌──────────────────────────────┐  ║
║ │ Active Dir.  │ ║          ║  │  AI Toolkit          │────║────║─▶│  enrich_threat_intel           │  ║    ║  │  Foundation-Sec-1.1-8B infer.   │  ║    ║  │   ERADICATION ACTIONS        │  ║
║ │ Azure Entra  │ ║          ║  │   Foundation-Sec     │    ║    ║  │                                │  ║    ║  │  Asset criticality ×multiplier  │  ║    ║  │ ─────────────────────────── │  ║
║ │ Okta         │ ║          ║  │   Cisco Deep TS      │────║────║─▶│  Response Tools (executor):    │  ║    ║  │  0–15   AUTO_DISMISS             │  ║    ║  │ disable_user                 │  ║
║ └──────────────┘ ║          ║  │                      │    ║    ║  │  execute_response_action       │  ║    ║  │  16–84  QUEUE (LOW/MED/HIGH)     │  ║    ║  │  Azure AD / Okta / AD LDAP   │  ║
║                  ║          ║  │  KV Store            │◀───║────║──│  create_ticket                 │  ║    ║  │  85–100 AUTO_ESCALATE            │  ║    ║  │  Rollback: 24 h             │  ║
║ ┌──────────────┐ ║──Cloud── ║  │  sentinel_cases      │    ║    ║  │  notify_stakeholders           │  ║    ║  │  Fallback: 20+ keyword rules     │  ║    ║  │                             │  ║
║ │    Cloud     │ ║  Trail   ║  │  response_locks       │    ║    ║  └────────────────────────────────┘  ║    ║  └─────────────┬───────────────────┘  ║    ║  │ quarantine_file              │  ║
║ │              │ ║  events  ║  │  baseline_cache       │    ║    ║                    ▲                  ║    ║                │ INVESTIGATING          ║    ║  │  CrowdStrike / Defender / S1 │  ║
║ │ AWS          │ ║          ║  │                      │    ║    ║  ┌─────────────────────────────────┐  ║    ║                ▼                       ║    ║  │  Rollback: 4 h              │  ║
║ │ CloudTrail   │ ║          ║  │  HEC  :8088          │◀───║────║──│  AI Models                      │  ║    ║  ┌─────────────────────────────────┐  ║    ║  │                             │  ║
║ │ Azure Actvty.│ ║          ║  │  Audit ingestion     │    ║    ║  │  ─────────────────────────────  │  ║    ║  │  ② SHERLOCK  (Investigate)      │  ║    ║  │ revoke_session               │  ║
║ └──────────────┘ ║          ║  └──────────────────────┘    ║    ║  │  SAIA                           │  ║    ║  │  ──────────────────────────────  │  ║    ║  │ rotate_credentials           │  ║
║                  ║          ║                               ║    ║  │   NL→SPL (Sherlock phases B–D)  │  ║    ║  │  Phase A: Host Context           │  ║    ║  │  Azure AD / Okta / AWS IAM   │  ║
║ ┌──────────────┐ ║──NetFlow─║▶                             ║    ║  │   Fallback: built-in templates  │  ║    ║  │  Phase B: Timeline  (SAIA)       │  ║    ║  │  Irreversible                │  ║
║ │   Network    │ ║  /Zeek   ║  Notable ──────────────────────────────────────────────────────────────║────║─▶│  Phase C: Lateral Movement       │  ║    ║  └──────────────────────────────┘  ║
║ │              │ ║          ║  Alert   ◀────────────────ES──║────║──│  Foundation-Sec-1.1-8B          │  ║    ║  │  Phase D: Identity Analysis      │  ║    ║                                     ║
║ │ Zeek / Bro   │ ║          ║                               ║    ║  │   Alert classify + MITRE map    │  ║    ║  │  Phase E: Threat Intel           │  ║    ║  ┌──────────────────────────────┐  ║
║ │ NetFlow      │ ║          ║                               ║    ║  │   Synthesis: exec. summary      │  ║    ║  │  Blast Radius calculation        │  ║    ║  │  NOTIFICATIONS & ITSM        │  ║
║ │ Web Proxy    │ ║          ║                               ║    ║  │   Fallback: rule-based classif. │  ║    ║  │  Adaptive: skip on no-data       │  ║    ║  │ ─────────────────────────── │  ║
║ └──────────────┘ ║          ║                               ║    ║  │                                 │  ║    ║  └─────────────┬───────────────────┘  ║    ║  │ Slack / PagerDuty / Email    │  ║
║                  ║          ║                               ║    ║  │  Cisco Deep Time Series         │  ║    ║                │ RESPONDING             ║    ║  │ ServiceNow / Jira ticket     │  ║
╚══════════════════╝          ║                               ║    ║  │   Anomaly forecasting           │  ║    ║                ▼                       ║    ║  │  Dedup: 1/case/platform      │  ║
                              ║                               ║    ║  │   Threshold optimise (max ±5)   │  ║    ║  ┌─────────────────────────────────┐  ║    ║  └──────────────────────────────┘  ║
                              ║                               ║    ║  │   MTTR / FP trend analysis      │  ║    ║  │  ③ EXECUTOR  (Respond)          │  ║    ║                                     ║
                              ║                               ║    ║  │   Fallback: built-in _TimeSeries│  ║    ║  │  ──────────────────────────────  │  ║    ║  ┌──────────────────────────────┐  ║
                              ║                               ║    ║  └─────────────────────────────────┘  ║    ║  │  FULL_AUTONOMY    score ≥ 85    │  ║    ║  │  DASHBOARDS                  │  ║
                              ╚══════════════════════════════╝    ╚══════════════════════════════════════╝    ║  │  CONTAINMENT_ONLY score 70–84   │  ║    ║  │ ─────────────────────────── │  ║
                                                                                                             ║  │  MONITORING_ONLY  score 55–69   │  ║    ║  │ War Room                     │  ║
                                                                                                             ║  │  DOCUMENT_ONLY    score  < 55   │──║────║─▶│  Real-time case state        │  ║
                                                                                                             ║  │  Safety: rate limit 10/hr       │  ║    ║  │  Agent health / latency      │  ║
                                                                                                             ║  │  Safety: cascade 3 fail/5min    │  ║    ║  │  Halt / Approve / Reject     │  ║
                                                                                                             ║  │  Safety: HALT check per action  │  ║    ║  │                             │  ║
                                                                                                             ║  │  Verify: re-query after action  │  ║    ║  │ Efficacy Dashboard           │  ║
                                                                                                             ║  │  Rollback: auto-scheduled       │  ║    ║  │  TP/FP rate · MTTR trends    │  ║
                                                                                                             ║  └─────────────┬───────────────────┘  ║    ║  │  Rule anomaly detection      │  ║
                                                                                                             ║                │ LEARNING               ║    ║  │  Sage weekly reports         │  ║
                                                                                                             ║                ▼                       ║    ║  └──────────────────────────────┘  ║
                                                                                                             ║  ┌─────────────────────────────────┐  ║    ║                                     ║
                                                                                                             ║  │  ④ SAGE  (Learn)                │  ║    ║  ┌──────────────────────────────┐  ║
                                                                                                             ║  │  ──────────────────────────────  │──║────║─▶│  AUDIT & COMPLIANCE          │  ║
                                                                                                             ║  │  Daily: efficacy + IOC harvest  │  ║    ║  │ ─────────────────────────── │  ║
                                                                                                             ║  │  Weekly: full report + tuning   │  ║    ║  │ sentinel_audit index         │  ║
                                                                                                             ║  │  Rule proposal + backtest       │  ║    ║  │  Append-only HEC :8088       │  ║
                                                                                                             ║  │  FP gate: must be ≤ 5%          │  ║    ║  │  Pre-write INTENT record     │  ║
                                                                                                             ║  │  Cost savings: $85/analyst-hr   │  ║    ║  │  UUID event chain (tamper-)  │  ║
                                                                                                             ║  │  MTTR baseline: 4.2h industry   │  ║    ║  │  365-day retention           │  ║
                                                                                                             ║  └─────────────────────────────────┘  ║    ║  │                             │  ║
                                                                                                             ╚═══════════════════════════════════════╝    ║  │ sentinel_learning index      │  ║
                                                                                                                                                          ║  │  Proposed rules + baselines  │  ║
                                                                                                                                                          ║  │  IOC harvest · Sage outputs  │  ║
                                                                                                                                                          ║  └──────────────────────────────┘  ║
                                                                                                                                                          ╚══════════════════════════════════════╝
```

---

## Data Flow Key

```
──────────────────────────────────────────────────────────────────────────────
ARROW          MEANING
──────────────────────────────────────────────────────────────────────────────
  ──────▶      Synchronous request / data flow (blocking)
  - - - ▶      Asynchronous / event-driven / fire-and-forget
  ◀─────▶      Bidirectional request–response
──────────────────────────────────────────────────────────────────────────────
COLOR          DOMAIN
──────────────────────────────────────────────────────────────────────────────
  (green)      Splunk platform component or Splunk internal call
  (blue)       Investigation query / AI inference flow
  (red)        Response action or human override interrupt
  (gold)       Orchestration pipeline state transition
──────────────────────────────────────────────────────────────────────────────
```

---

## Simplified Pipeline View

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                          SENTINEL PIPELINE (happy path)                          │
└─────────────────────────────────────────────────────────────────────────────────┘

  Splunk ES                                                            Closed Case
  Notable Alert                                                             ▲
      │                                                                     │
      ▼                                                                     │
 ┌──────────┐    score     ┌──────────┐   report   ┌──────────┐  actions  │
 │ VANGUARD │─── 85–100 ──▶│ SHERLOCK │───────────▶│ EXECUTOR │──────────▶│
 │          │              │          │             │          │           │
 │ Triage   │   score      │ 5-phase  │             │ Contain  │  ┌────────┤
 │ + Score  │─── < 16 ──▶ │ invest.  │             │ Eradicate│  │ SAGE   │
 │          │  AUTO_DISMISS│          │             │ Document │  │        │
 └──────────┘              └──────────┘             └──────────┘  │ Learn  │
      │                          │                       │         └────────┘
      │ MCP tool calls           │ MCP tool calls        │ MCP response tools
      ▼                          ▼                       ▼
 ┌────────────────────────────────────────────────────────────────────────────┐
 │                    Splunk MCP Server  (14 tools, :3000)                    │
 │         Splunk REST API  ·  SAIA  ·  Foundation-Sec  ·  Cisco Deep TS     │
 └────────────────────────────────────────────────────────────────────────────┘
                                    ▲
                     - - - - - - - -│- - - - - - -
                    ¦    HUMAN OVERRIDE [!]        ¦
                    ¦  halt_case()  /  approve()   ¦
                     - - - - - - - - - - - - - - -
```

---

## State Machine

```
                                     ┌──── ERROR ◀────┐
                                     │    (retry ≤3×) │
                                     ▼                 │
  QUEUED ──▶ TRIAGING ──▶ INVESTIGATING ──▶ DECIDING ──┘
                │               │                │
                │ score < 16    │ no data        │ score < 90
                ▼               ▼                ▼
           SUPPRESSED       (partial)          HALTED ◀── Human override
                                │                │
                                ▼                ▼
                           RESPONDING        (resume)
                                │
                                ▼
                            LEARNING
                                │
                                ▼
                             CLOSED
```

---

## Executor Autonomy Decision Tree

```
                     Risk Score?
                          │
          ┌───────────────┼──────────────────┬──────────────────┐
          │               │                  │                  │
        ≥ 85            70–84             55–69              < 55
          │               │                  │                  │
          ▼               ▼                  ▼                  ▼
   FULL_AUTONOMY   CONTAINMENT_ONLY   MONITORING_ONLY    DOCUMENT_ONLY
          │               │                  │                  │
   All actions:    Containment only:   No active           Log + ticket
   • isolate_host  • isolate_host      response:           only:
   • block_ip      • block_ip          • create_ticket     • create_ticket
   • kill_process  • kill_process      • notify            • notify
   • disable_user  • create_ticket     • enrich TI         (no containment)
   • quarantine    • notify
   • revoke        (no disable_user,
   • create_ticket  quarantine, etc.)
   • notify
```

---

## MCP Tool Taxonomy

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    14 MCP Tools by Group                                  │
├──────────────────────────────┬──────────────────────────────────────────┤
│  INVESTIGATION  (read-only)  │  RESPONSE  (executor-only)               │
│  Available to all agents     │  Pre-execution safety gate required       │
├──────────────────────────────┼──────────────────────────────────────────┤
│  search_spl                  │  execute_response_action                  │
│  validate_spl                │    ├─ isolate_host                        │
│  get_asset_context           │    ├─ block_ip                            │
│  get_process_tree            │    ├─ kill_process                        │
│  get_network_flows           │    ├─ disable_user                        │
│  get_user_activity           │    ├─ quarantine_file                     │
│  query_es_notable            │    └─ revoke_session / rotate_credentials │
│  run_saved_search            │  create_ticket                            │
│  get_indexes                 │    ├─ ServiceNow                          │
│  get_knowledge_objects       │    └─ Jira                                │
│  enrich_threat_intel         │  notify_stakeholders                      │
│                              │    ├─ Slack                               │
│                              │    ├─ PagerDuty                           │
│                              │    └─ Email                               │
└──────────────────────────────┴──────────────────────────────────────────┘

  Safety gate (response tools, in order):
  1. Distributed lock (response_locks KV Store)
  2. Dedup window (300s per action+target+case)
  3. Dry-run validation
  4. Audit pre-write (INTENT record → sentinel_audit)
  5. Agent identity check (executor token scope only)
```

---

## Rollback Timer Reference

```
  Action               Rollback Timer    Platform Undo
  ─────────────────────────────────────────────────────────────────
  isolate_host         4 hours           lift_containment / reconnect
  block_ip             72 hours          remove from DAG / access rule
  disable_user         24 hours          accountEnabled = true / activate
  quarantine_file      4 hours           restore from quarantine vault
  kill_process         ─ irreversible ─  process is gone
  revoke_session       ─ irreversible ─  user must re-authenticate
  rotate_credentials   ─ irreversible ─  new credentials issued
  ─────────────────────────────────────────────────────────────────
  Rollback sweep runs every 5 minutes against response_locks KV Store.
  Failed rollbacks trigger Slack + PagerDuty oncall alert.
  Analysts can extend or cancel rollbacks via War Room UI.
```

---

## Human Override Points

```
  Pipeline Stage        Override Available    Effect
  ──────────────────────────────────────────────────────────────────────
  Any state             halt_case()           → HALTED; all actions stop
  HALTED                resume_case()         → Return to previous state
  DECIDING              approve_action()      → Unblock approval gate
  RESPONDING            War Room [Reject]     → Executor skips action
  Any state             War Room [Assign]     → Change case owner/priority
  CLOSED                reopen()              → Re-queue for investigation
  ──────────────────────────────────────────────────────────────────────
  Approval always required for:
    • score < 90 in FULL_AUTONOMY mode
    • rotate_credentials  (any score, any mode)
    • unisolate_host      (manual rollback)
    • restore_file        (manual rollback)
  All override events logged as HUMAN_OVERRIDE to sentinel_audit.
```
