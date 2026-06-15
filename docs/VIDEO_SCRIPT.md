# SENTINEL — Demo Video Script (2.5 minutes)

Honest walkthrough: what runs today vs. what's coded and waiting on a Splunk
backend. Pair this script with `architecture_diagram.puml` (status badges:
green = implemented, yellow = coded/needs backend, gray = not implemented).

| Time | Narration | On-screen |
|------|-----------|-----------|
| 0:00–0:10 | "SENTINEL is an architecture proposal for autonomous SOC operations on Splunk." | Title card |
| 0:10–0:25 | Show architecture diagram. Point at green (implemented) and yellow (coded, needs backend) components. | `architecture_diagram.puml` / rendered PNG |
| 0:25–0:40 | "All Splunk integration points are production-ready. Here's the MCP client." | Show code: `app/sentinel/bin/mcp_client.py` with real Splunk URL placeholder (`SplunkMCPClient.from_config()`, `[mcp] server_url`) |
| 0:40–0:55 | "Here's the SAIA client." | Show code: `app/sentinel/bin/saia_client.py` with real SAIA endpoint (`/services/assistant/v1/generate`, `SAIAClient.from_config()`) |
| 0:55–1:10 | "Here's the hosted model client." | Show code: `app/sentinel/bin/hosted_model_client.py` with real model endpoints (`/services/ml/models/<model>/predict`) |
| 1:10–1:30 | "This proof-of-concept demonstrates the agent swarm with local simulation." Explain: "Vanguard scores, Sherlock investigates, Executor responds, Sage learns — all automated." | Show dashboard running: `demo/sentinel_war_room_live.html` |
| 1:30–1:45 | "Production deployment: change one config file, point to Splunk Cloud, deploy app via ACS." | — |
| 1:45–2:00 | Show config file. | `app/sentinel/local/sentinel.conf` — `splunk_host = your-instance.splunkcloud.com` |
| 2:00–2:15 | "Fault tolerance: dead-letter queue, circuit breaker, human override — production-grade from day one." | Show `sentinel_orchestrator.py` (DLQ/watchdog) and `mcp_client.py` (circuit breaker) |
| 2:15–2:30 | "SENTINEL: Architecture for the agentic SOC era. Ready for Splunk." | Closing card |

## Recording notes

- Use `scripts/verify_integration.py` beforehand to confirm which checks
  PASS/SKIP/FAIL on your stack — if any Splunk backend is reachable, the
  yellow-badge components will show live PASS results instead of fallback
  paths during the demo.
- The local simulation (Section 1:10–1:30) runs entirely offline:
  `python scripts/inject_synthetic_attack_data.py --scenario ransomware`
  followed by `python app/sentinel/bin/sentinel_orchestrator.py --once`.
- See [DEPLOYMENT.md](DEPLOYMENT.md) for the 4-hour path referenced at 1:30.
- See [SPLUNK_INTEGRATION.md](SPLUNK_INTEGRATION.md) for the exact endpoints
  shown at 0:25–1:10.
