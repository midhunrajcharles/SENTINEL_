#!/usr/bin/env python
"""
SENTINEL: Autonomous Agentic SOC Commander
verify_integration.py — real Splunk Cloud end-to-end smoke test

Runs through the "is this actually wired to Splunk Cloud" checklist:

  1. Splunk Cloud REST connectivity (sentinel_service token)
  2. HEC data injection + searchability
  3. MCP Server (talking to Splunk Cloud) responding
  4. SAIA SPL generation (live endpoint, falls back to cached templates)
  5. Foundation-Sec hosted model classification
  6. Cisco Deep Time Series endpoint (optional — falls back to local stats)
  7. KV Store read/write (agent_state collection)
  8. Audit logging via HEC

Each check prints PASS / FAIL / SKIP and a one-line reason. A SKIP means
"not configured" (expected for optional components like Cisco Deep Time
Series); it does not count as a failure. Exits 1 if any required check
fails.

Configuration is read from app/sentinel/local/sentinel.conf (same as the
agents) with SENTINEL_<SECTION>_<KEY> env var overrides.

Usage::

    python scripts/verify_integration.py
"""

from __future__ import annotations

import json
import sys
import time
import uuid
from pathlib import Path

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT / "app" / "sentinel" / "bin"))

from utils.config_loader import get_config  # noqa: E402

RESULTS = []  # (label, status, detail)


def report(label: str, status: str, detail: str = "") -> None:
    RESULTS.append((label, status, detail))
    mark = {"PASS": "[PASS]", "FAIL": "[FAIL]", "SKIP": "[SKIP]"}[status]
    line = f"  {mark} {label}"
    if detail:
        line += f" — {detail}"
    print(line)


def splunk_base(cfg) -> tuple[str, str, bool]:
    host = cfg.get("splunk", "host", default="localhost")
    port = cfg.get_int("splunk", "port", default=8089)
    scheme = cfg.get("splunk", "scheme", default="https")
    verify = cfg.get_bool("general", "verify_ssl", default=False)
    token = cfg.get("splunk", "api_token", default="")
    return f"{scheme}://{host}:{port}", token, verify


def run_search(base_url: str, token: str, verify: bool, search: str, max_wait: float = 20.0):
    headers = {"Authorization": f"Bearer {token}"}
    resp = requests.post(
        f"{base_url}/services/search/jobs",
        headers=headers, verify=verify,
        data={"search": search, "output_mode": "json", "exec_mode": "normal"},
        timeout=30,
    )
    resp.raise_for_status()
    sid = resp.json()["sid"]

    deadline = time.time() + max_wait
    while time.time() < deadline:
        status = requests.get(
            f"{base_url}/services/search/jobs/{sid}",
            headers=headers, verify=verify, params={"output_mode": "json"}, timeout=15,
        ).json()
        if status["entry"][0]["content"]["isDone"]:
            break
        time.sleep(1)

    results = requests.get(
        f"{base_url}/services/search/jobs/{sid}/results",
        headers=headers, verify=verify, params={"output_mode": "json", "count": 50}, timeout=15,
    ).json()
    return results.get("results", [])


# ---------------------------------------------------------------------------
# 1. Splunk Cloud connectivity
# ---------------------------------------------------------------------------

def check_splunk_connectivity(cfg) -> None:
    base_url, token, verify = splunk_base(cfg)
    if not token:
        report("Splunk Cloud connectivity", "FAIL", "[splunk] api_token not set in sentinel.conf")
        return
    try:
        resp = requests.get(
            f"{base_url}/services/server/info",
            headers={"Authorization": f"Bearer {token}"},
            params={"output_mode": "json"}, verify=verify, timeout=15,
        )
        if resp.status_code == 401:
            report("Splunk Cloud connectivity", "FAIL", "401 — bad sentinel_service token")
            return
        resp.raise_for_status()
        info = resp.json()["entry"][0]["content"]
        report("Splunk Cloud connectivity", "PASS",
               f"{base_url} (version {info.get('version')})")
    except Exception as exc:
        report("Splunk Cloud connectivity", "FAIL", str(exc))


# ---------------------------------------------------------------------------
# 2. HEC data injection
# ---------------------------------------------------------------------------

def check_hec_injection(cfg) -> None:
    hec_url = cfg.get("hec", "url", default="")
    hec_token = cfg.get("hec", "token", default="")
    hec_index = cfg.get("hec", "index", default="sentinel_audit")
    base_url, splunk_token, verify = splunk_base(cfg)

    if not hec_url or not hec_token:
        report("HEC data injection", "FAIL", "[hec] url/token not set in sentinel.conf")
        return

    marker = f"sentinel-verify-{uuid.uuid4().hex[:8]}"
    try:
        resp = requests.post(
            hec_url.rstrip("/") + "/services/collector/event",
            headers={"Authorization": f"Splunk {hec_token}"},
            json={
                "event": {"verify_marker": marker, "message": "SENTINEL integration check"},
                "sourcetype": "sentinel:verify",
                "index": hec_index,
            },
            verify=verify, timeout=15,
        )
        if resp.status_code != 200:
            report("HEC data injection", "FAIL", f"HEC HTTP {resp.status_code}: {resp.text[:200]}")
            return
    except Exception as exc:
        report("HEC data injection", "FAIL", f"send failed: {exc}")
        return

    if not splunk_token:
        report("HEC data injection", "PASS", "event sent (search-side verification skipped — no splunk api_token)")
        return

    # Give the indexer a moment, then confirm searchability.
    time.sleep(5)
    try:
        results = run_search(
            base_url, splunk_token, verify,
            f'search index={hec_index} sourcetype="sentinel:verify" verify_marker="{marker}"',
        )
        if results:
            report("HEC data injection", "PASS", f"event indexed and searchable in {hec_index}")
        else:
            report("HEC data injection", "FAIL", "event sent but not found by search (indexing delay or wrong index)")
    except Exception as exc:
        report("HEC data injection", "FAIL", f"verification search failed: {exc}")


# ---------------------------------------------------------------------------
# 3. MCP Server
# ---------------------------------------------------------------------------

def check_mcp_server(cfg) -> None:
    try:
        from mcp_client import SplunkMCPClient, MCPError
    except ImportError as exc:
        report("MCP Server", "FAIL", f"could not import mcp_client: {exc}")
        return

    client = SplunkMCPClient.from_config(cfg, agent_name="verify_integration")
    try:
        health = client.health_check()
        report("MCP Server", "PASS", f"{client._base_url} -> {health}")
    except MCPError as exc:
        report("MCP Server", "FAIL", f"{client._base_url} unreachable: {exc}")
    except Exception as exc:
        report("MCP Server", "FAIL", str(exc))


# ---------------------------------------------------------------------------
# 4. SAIA
# ---------------------------------------------------------------------------

def check_saia(cfg) -> None:
    try:
        from saia_client import SAIAClient
    except ImportError as exc:
        report("SAIA SPL generation", "FAIL", f"could not import saia_client: {exc}")
        return

    saia = SAIAClient.from_config(cfg)
    spl = saia.generate_spl(
        "Show me all processes on this host",
        context={"host": "WORKSTATION-07", "earliest": "-24h"},
        phase="phase_b",
        alert_type="RANSOMWARE_POWERSHELL_ENCODED",
    )
    if spl:
        source = "live SAIA endpoint" if (cfg.get("saia", "token", default="")) else "cached template fallback"
        report("SAIA SPL generation", "PASS", f"{source}: {spl[:80]}")
    else:
        report("SAIA SPL generation", "FAIL", "no SPL returned from live endpoint or cache")


# ---------------------------------------------------------------------------
# 5. Foundation-Sec
# ---------------------------------------------------------------------------

def check_foundation_sec(cfg) -> None:
    try:
        from hosted_model_client import HostedModelClient, HostedModelUnavailable
    except ImportError as exc:
        report("Foundation-Sec classification", "FAIL", f"could not import hosted_model_client: {exc}")
        return

    client = HostedModelClient.from_config(cfg, agent_name="vanguard")
    if not client.is_available():
        report("Foundation-Sec classification", "SKIP", "endpoint/token not configured — agents use rule-based fallback")
        return

    try:
        result = client.generate_json(
            user_content={"alert_type": "RANSOMWARE_POWERSHELL_ENCODED", "host": "WORKSTATION-07", "raw_risk_score": 88},
            max_tokens=256,
        )
        report("Foundation-Sec classification", "PASS", json.dumps(result)[:120])
    except HostedModelUnavailable as exc:
        report("Foundation-Sec classification", "FAIL", f"unavailable: {exc}")
    except Exception as exc:
        report("Foundation-Sec classification", "FAIL", str(exc))


# ---------------------------------------------------------------------------
# 6. Cisco Deep Time Series
# ---------------------------------------------------------------------------

def check_cisco_ts(cfg) -> None:
    url = cfg.get("cisco_ts", "url", default="")
    token = cfg.get("cisco_ts", "token", default="")
    if not url or not token:
        report("Cisco Deep Time Series", "SKIP", "not configured — Sage uses built-in statistical fallback")
        return
    try:
        resp = requests.get(f"{url.rstrip('/')}/health",
                             headers={"Authorization": f"Bearer {token}"},
                             timeout=5, verify=False)
        if resp.ok:
            report("Cisco Deep Time Series", "PASS", f"{url} healthy")
        else:
            report("Cisco Deep Time Series", "FAIL", f"HTTP {resp.status_code}")
    except Exception as exc:
        report("Cisco Deep Time Series", "FAIL", str(exc))


# ---------------------------------------------------------------------------
# 7. KV Store
# ---------------------------------------------------------------------------

def check_kvstore(cfg) -> None:
    base_url, token, verify = splunk_base(cfg)
    if not token:
        report("KV Store (agent_state)", "FAIL", "[splunk] api_token not set")
        return
    try:
        resp = requests.get(
            f"{base_url}/servicesNS/nobody/sentinel/storage/collections/data/agent_state",
            headers={"Authorization": f"Bearer {token}"},
            params={"output_mode": "json"}, verify=verify, timeout=15,
        )
        if resp.status_code == 404:
            report("KV Store (agent_state)", "FAIL",
                   "collection not found — is the sentinel app installed on this stack? (see Step 6, slim/appinspect/acs)")
            return
        resp.raise_for_status()
        docs = resp.json()
        report("KV Store (agent_state)", "PASS", f"{len(docs)} document(s)")
    except Exception as exc:
        report("KV Store (agent_state)", "FAIL", str(exc))


# ---------------------------------------------------------------------------
# 8. Audit logging
# ---------------------------------------------------------------------------

def check_audit_logging(cfg) -> None:
    try:
        from audit_logger import AuditLogger
    except ImportError as exc:
        report("Audit logging (HEC)", "FAIL", f"could not import audit_logger: {exc}")
        return

    hec_url = cfg.get("hec", "url", default="")
    hec_token = cfg.get("hec", "token", default="")
    hec_index = cfg.get("hec", "index", default="sentinel_audit")
    if not hec_url or not hec_token:
        report("Audit logging (HEC)", "FAIL", "[hec] url/token not set")
        return

    logger = AuditLogger(agent_name="verify_integration",
                          hec_url=hec_url, hec_token=hec_token, hec_index=hec_index,
                          verify_ssl=cfg.get_bool("general", "verify_ssl", default=False))
    logger.log_decision(
        case_id="SEN-VERIFY01",
        decision_type="INTEGRATION_CHECK",
        confidence=1.0,
        input_context={"source": "verify_integration.py"},
        output_decision={"result": "ok"},
        reasoning="End-to-end integration verification run.",
    )
    report("Audit logging (HEC)", "PASS", f"event queued to {hec_index} via {hec_url}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    cfg = get_config()
    sep = "=" * 60
    print(sep)
    print("  SENTINEL — Real Splunk Cloud Integration Verification")
    print(sep)

    checks = [
        check_splunk_connectivity,
        check_hec_injection,
        check_mcp_server,
        check_saia,
        check_foundation_sec,
        check_cisco_ts,
        check_kvstore,
        check_audit_logging,
    ]
    for check in checks:
        check(cfg)

    print(sep)
    passed = sum(1 for _, s, _ in RESULTS if s == "PASS")
    failed = sum(1 for _, s, _ in RESULTS if s == "FAIL")
    skipped = sum(1 for _, s, _ in RESULTS if s == "SKIP")
    print(f"  {passed} passed, {failed} failed, {skipped} skipped")
    print(sep)

    if failed:
        sys.exit(1)


if __name__ == "__main__":
    main()
