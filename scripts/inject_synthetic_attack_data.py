#!/usr/bin/env python
"""
SENTINEL: Autonomous Agentic SOC Commander
inject_synthetic_attack_data.py — Synthetic attack data injector

Sends synthetic, CIM-field-aligned events to Splunk via HTTP Event Collector
(HEC) so the cached SPL templates in
app/sentinel/lookups/saia_cached_queries.csv (and the agent pipeline driven
by sentinel_orchestrator.py) have realistic data to query against in a demo
or test environment.

Each scenario corresponds to one of the alert_type values used throughout
SENTINEL's lookups and test fixtures:

  ransomware      RANSOMWARE_POWERSHELL_ENCODED  (see tests/fixtures INV-004)
  insider_threat  INSIDER_THREAT_LARGE_UPLOAD
  brute_force     BRUTE_FORCE_RDP
  supply_chain    SUPPLY_CHAIN_HASH_MISMATCH

Events are sent as JSON to the HEC /services/collector/event endpoint with
sourcetypes prefixed "sentinel:synthetic:*" so they are easy to find and
remove (``index=<idx> sourcetype=sentinel:synthetic:* | delete``, run as
admin). Field names match the CIM fields referenced by the cached SPL
templates (process_name, parent_process_name, dest, dest_port, bytes_out,
user, query, answer, etc.) so the raw `index=... search ...` style cached
queries return results directly. The `| datamodel ...` style cached queries
additionally require CIM tagging (eventtypes/tags) for these sourcetypes,
which is normally provided by Splunk_TA add-ons and is out of scope here.

Configuration is read from app/sentinel/local/sentinel.conf [hec], with
SENTINEL_HEC_URL / SENTINEL_HEC_TOKEN / SENTINEL_HEC_INDEX env var overrides
(same precedence as audit_logger.py).

Usage::

    python scripts/inject_synthetic_attack_data.py --scenario ransomware
    python scripts/inject_synthetic_attack_data.py --scenario all --index main
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List

import requests

_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT / "app" / "sentinel" / "bin"))

from utils.config_loader import get_config  # noqa: E402

_ENV_HEC_URL   = "SENTINEL_HEC_URL"
_ENV_HEC_TOKEN = "SENTINEL_HEC_TOKEN"
_ENV_HEC_INDEX = "SENTINEL_HEC_INDEX"

_DEFAULT_INDEX = "main"


def _now() -> float:
    return time.time()


def _event(sourcetype: str, host: str, fields: Dict[str, Any],
           index: str, offset_s: float = 0.0) -> Dict[str, Any]:
    return {
        "time":       _now() - offset_s,
        "host":       host,
        "source":     "sentinel:synthetic",
        "sourcetype": sourcetype,
        "index":      index,
        "event":      fields,
    }


# ---------------------------------------------------------------------------
# Scenario: ransomware (RANSOMWARE_POWERSHELL_ENCODED) — see tests/fixtures
# sample_investigations.json INV-004 for the matching investigation report.
# ---------------------------------------------------------------------------

def _scenario_ransomware(index: str) -> List[Dict[str, Any]]:
    host  = "WORKSTATION-07"
    user  = "CORP\\jdoe"
    c2_ip = "185.220.101.42"
    domain = "update-cdn-malicious-domain.com"
    events: List[Dict[str, Any]] = []

    # Phase B: encoded PowerShell launched from Outlook, then LSASS access
    events.append(_event("sentinel:synthetic:endpoint:process", host, {
        "process_name": "powershell.exe",
        "parent_process_name": "outlook.exe",
        "process": "powershell.exe -nop -w hidden -enc JABzAD0ATgBlAHcALQ...",
        "command_line": "powershell.exe -nop -w hidden -enc JABzAD0ATgBlAHcALQ...",
        "user": user,
        "dest": host,
        "action": "allowed",
    }, index, offset_s=3600))

    events.append(_event("sentinel:synthetic:endpoint:process", host, {
        "process_name": "lsass.exe",
        "target_process": "lsass.exe",
        "parent_process_name": "powershell.exe",
        "access_mask": "0x1010",
        "user": user,
        "dest": host,
        "action": "allowed",
    }, index, offset_s=3550))

    # Phase C: outbound C2 beacon traffic
    for i in range(5):
        events.append(_event("sentinel:synthetic:network:traffic", host, {
            "src": host,
            "dest": c2_ip,
            "dest_port": 443,
            "bytes_out": 2048 + i * 128,
            "bytes_in": 512,
            "action": "allowed",
            "transport": "tcp",
        }, index, offset_s=3400 - i * 60))

    # Phase D: DNS resolution to malicious domain
    events.append(_event("sentinel:synthetic:network:resolution", host, {
        "src": host,
        "query": domain,
        "answer": c2_ip,
        "record_type": "A",
    }, index, offset_s=3450))

    # Phase D: successful authentication after compromise
    events.append(_event("sentinel:synthetic:authentication", host, {
        "user": user,
        "src": host,
        "dest": "FILESERVER-01",
        "app": "smb",
        "action": "success",
    }, index, offset_s=3000))

    # Phase E: ransomware file encryption indicators
    for fname in ("Q1_Financials.xlsx.locked", "Project_Plan.docx.locked", "Backup.zip.locked"):
        events.append(_event("sentinel:synthetic:endpoint:filesystem", host, {
            "file_name": fname,
            "file_path": f"C:\\Users\\jdoe\\Documents\\{fname}",
            "action": "modified",
            "user": user,
            "dest": host,
        }, index, offset_s=600))

    return events


# ---------------------------------------------------------------------------
# Scenario: insider_threat (INSIDER_THREAT_LARGE_UPLOAD)
# ---------------------------------------------------------------------------

def _scenario_insider_threat(index: str) -> List[Dict[str, Any]]:
    host = "LAPTOP-EXEC-14"
    user = "CORP\\rwilliams"
    events: List[Dict[str, Any]] = []

    # Phase B: large outbound transfers to a personal cloud storage IP
    for i in range(4):
        events.append(_event("sentinel:synthetic:network:traffic", host, {
            "src_ip": host,
            "dest_ip": "104.16.85.20",
            "dest_port": 443,
            "bytes_out": 25_000_000 + i * 1_000_000,
            "url": f"https://personal-cloud-storage.example.com/upload/batch{i}",
            "user": user,
            "action": "allowed",
        }, index, offset_s=7200 - i * 600))

    # Phase C: USB mass storage writes
    for i in range(3):
        events.append(_event("sentinel:synthetic:endpoint:usb", host, {
            "EventCode": 4663,
            "host": host,
            "user": user,
            "object_file_path": f"E:\\exfil\\confidential_q3_plan_v{i}.pdf",
            "bytes": 4_500_000 + i * 200_000,
        }, index, offset_s=6900 - i * 120))

    # Phase D: bulk SharePoint downloads
    for i in range(20):
        events.append(_event("sentinel:synthetic:o365:management:activity", host, {
            "Operation": "FileDownloaded",
            "UserId": user,
            "ObjectId": f"/sites/Finance/Shared Documents/Q3_Confidential_{i:03d}.xlsx",
        }, index, offset_s=8000 - i * 30))

    return events


# ---------------------------------------------------------------------------
# Scenario: brute_force (BRUTE_FORCE_RDP)
# ---------------------------------------------------------------------------

def _scenario_brute_force(index: str) -> List[Dict[str, Any]]:
    host  = "JUMP-SRV01"
    attacker_ip = "91.108.4.200"
    events: List[Dict[str, Any]] = []

    # Phase B: failed RDP authentication attempts
    for i in range(50):
        events.append(_event("sentinel:synthetic:authentication", host, {
            "user": f"admin{i % 7}",
            "src": attacker_ip,
            "dest": host,
            "app": "rdp",
            "action": "failure",
        }, index, offset_s=1800 - i * 30))

    # No successful login — brute force self-terminated
    return events


# ---------------------------------------------------------------------------
# Scenario: supply_chain (SUPPLY_CHAIN_HASH_MISMATCH)
# ---------------------------------------------------------------------------

def _scenario_supply_chain(index: str) -> List[Dict[str, Any]]:
    bad_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    c2_ip   = "45.155.205.233"
    hosts = ["BUILD-AGENT-03", "DEV-WORKSTATION-11", "DEV-WORKSTATION-19"]
    events: List[Dict[str, Any]] = []

    # Phase B: hosts running the tampered binary
    for host in hosts:
        events.append(_event("sentinel:synthetic:endpoint:filesystem", host, {
            "file_name": "update-agent.exe",
            "file_hash": bad_hash,
            "file_path": "C:\\Program Files\\VendorTool\\update-agent.exe",
            "action": "written",
        }, index, offset_s=5400))

    # Phase C: scheduled task persistence on the build agent
    events.append(_event("sentinel:synthetic:endpoint:registry", hosts[0], {
        "EventCode": 106,
        "host": hosts[0],
        "user": "SYSTEM",
        "TaskName": "\\Microsoft\\Windows\\VendorToolUpdateCheck",
    }, index, offset_s=5300))

    # Phase D: beaconing to C2 over alternate port
    for i in range(6):
        events.append(_event("sentinel:synthetic:network:traffic", hosts[0], {
            "src": hosts[0],
            "dest": c2_ip,
            "dest_port": 8443,
            "bytes_out": 512,
            "bytes_in": 256,
            "action": "allowed",
        }, index, offset_s=5000 - i * 300))

    return events


_SCENARIOS = {
    "ransomware":     _scenario_ransomware,
    "insider_threat": _scenario_insider_threat,
    "brute_force":    _scenario_brute_force,
    "supply_chain":   _scenario_supply_chain,
}


# ---------------------------------------------------------------------------
# HEC submission
# ---------------------------------------------------------------------------

def _hec_config() -> Dict[str, str]:
    cfg = get_config()
    url   = os.environ.get(_ENV_HEC_URL,   cfg.get("hec", "url",   default="https://localhost:8088"))
    token = os.environ.get(_ENV_HEC_TOKEN, cfg.get("hec", "token", default=""))
    index = os.environ.get(_ENV_HEC_INDEX, cfg.get("hec", "index", default=_DEFAULT_INDEX))
    return {"url": url.rstrip("/"), "token": token, "index": index}


def _send_events(events: List[Dict[str, Any]], hec_url: str, hec_token: str, verify_ssl: bool) -> int:
    if not hec_token:
        raise SystemExit(
            "No HEC token configured. Set [hec] token in app/sentinel/local/sentinel.conf "
            "or the SENTINEL_HEC_TOKEN environment variable."
        )

    endpoint = f"{hec_url}/services/collector/event"
    headers  = {
        "Authorization": f"Splunk {hec_token}",
        "Content-Type": "application/json",
        # Required when the HEC token has indexer acknowledgement (useAck) enabled.
        "X-Splunk-Request-Channel": str(uuid.uuid4()),
    }

    # HEC accepts a stream of concatenated JSON objects in a single POST.
    payload = "\n".join(json.dumps(event) for event in events)
    resp = requests.post(endpoint, data=payload, headers=headers, verify=verify_ssl, timeout=30)
    resp.raise_for_status()
    return len(events)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--scenario", choices=sorted(_SCENARIOS) + ["all"], default="all",
        help="Which synthetic attack scenario to inject (default: all)",
    )
    parser.add_argument("--index", default=None, help="Override the target Splunk index")
    parser.add_argument("--hec-url", default=None, help="Override the HEC base URL")
    parser.add_argument("--hec-token", default=None, help="Override the HEC token")
    parser.add_argument("--insecure", action="store_true", default=True,
                         help="Skip TLS verification (default: true for local self-signed Splunk)")
    args = parser.parse_args()

    hec = _hec_config()
    hec_url   = args.hec_url or hec["url"]
    hec_token = args.hec_token or hec["token"]
    index     = args.index or hec["index"]

    scenario_names = sorted(_SCENARIOS) if args.scenario == "all" else [args.scenario]

    total = 0
    for name in scenario_names:
        events = _SCENARIOS[name](index)
        count = _send_events(events, hec_url, hec_token, verify_ssl=not args.insecure)
        print(f"[SENTINEL DEMO] Injected {count} synthetic events for scenario '{name}' into index '{index}'")
        total += count

    print(f"[SENTINEL DEMO] Done — {total} total events injected.")


if __name__ == "__main__":
    main()
