"""
Shared pytest fixtures for SENTINEL unit and integration tests.

Adds app/sentinel/bin to sys.path before any import, then provides
lightweight mocks for MCP, audit, config, and the Case dataclass so
individual test files don't repeat boilerplate.
"""

from __future__ import annotations

import sys
import time
import uuid
from pathlib import Path
from typing import Any, Dict, Optional
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Bootstrap: add agent bin directory to path before any sentinel import
# ---------------------------------------------------------------------------

_ROOT    = Path(__file__).resolve().parent.parent
_BIN_DIR = _ROOT / "app" / "sentinel" / "bin"

if str(_BIN_DIR) not in sys.path:
    sys.path.insert(0, str(_BIN_DIR))

# ---------------------------------------------------------------------------
# Lazy import helpers (avoids module-level import errors in CI without Splunk)
# ---------------------------------------------------------------------------

def _get_case_cls():
    from utils.state_manager import Case
    return Case


def _get_case_status_cls():
    from utils.state_manager import CaseStatus
    return CaseStatus


# ---------------------------------------------------------------------------
# Marks
# ---------------------------------------------------------------------------

def pytest_addoption(parser):
    parser.addoption(
        "--run-slow", action="store_true", default=False,
        help="Run tests marked @pytest.mark.slow (otherwise skipped unless SENTINEL_RUN_INTEGRATION=1)",
    )


def pytest_configure(config):
    config.addinivalue_line("markers", "integration: mark test as requiring a live Splunk instance")
    config.addinivalue_line("markers", "slow: mark test as slow-running")


def pytest_collection_modifyitems(config, items):
    import os
    run_integration = os.environ.get("SENTINEL_RUN_INTEGRATION", "0") == "1"
    run_slow        = run_integration or config.getoption("--run-slow")

    skip_integration = pytest.mark.skip(reason="Integration test — set SENTINEL_RUN_INTEGRATION=1 to run")
    skip_slow        = pytest.mark.skip(reason="Slow test — set SENTINEL_RUN_INTEGRATION=1 or pass --run-slow to run")

    for item in items:
        # Use explicit marker checks (not `in item.keywords`) — keywords also
        # pick up ancestor directory/file names (e.g. every test under
        # tests/integration/ would otherwise match "integration").
        if not run_integration and item.get_closest_marker("integration"):
            item.add_marker(skip_integration)
        if not run_slow and item.get_closest_marker("slow"):
            item.add_marker(skip_slow)


# ---------------------------------------------------------------------------
# Case factory
# ---------------------------------------------------------------------------

@pytest.fixture
def make_case():
    """
    Factory fixture: call make_case(**overrides) to produce a Case object
    with sensible defaults. Patches away the KV Store constructor.
    """
    Case = _get_case_cls()

    def _factory(
        case_id:        Optional[str] = None,
        alert_id:       Optional[str] = None,
        alert_type:     str = "RANSOMWARE_POWERSHELL_ENCODED",
        status:         str = "QUEUED",
        priority:       str = "HIGH",
        affected_host:  str = "DESKTOP-ABC123",
        affected_user:  str = "CORP\\jdoe",
        risk_score:     int = 75,
        classification: str = "",
        mitre_tactic:   str = "",
        mitre_technique:str = "",
        **extra,
    ) -> Any:
        kwargs = dict(
            case_id         = case_id or f"CASE-{uuid.uuid4().hex[:8].upper()}",
            alert_id        = alert_id or f"ALERT-{uuid.uuid4().hex[:8].upper()}",
            alert_type      = alert_type,
            status          = status,
            priority        = priority,
            affected_host   = affected_host,
            affected_user   = affected_user,
            risk_score      = risk_score,
            classification  = classification,
            mitre_tactic    = mitre_tactic,
            mitre_technique = mitre_technique,
        )
        # Allow callers to inject extra fields (e.g. vanguard_result)
        for k, v in extra.items():
            if hasattr(Case, k) or k in Case.__dataclass_fields__:
                kwargs[k] = v
        return Case(**kwargs)

    return _factory


# ---------------------------------------------------------------------------
# Specific case fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def ransomware_case(make_case):
    return make_case(
        alert_id        = "ALERT-20260606-001",
        alert_type      = "RANSOMWARE_POWERSHELL_ENCODED",
        affected_host   = "DESKTOP-ABC123",
        affected_user   = "CORP\\jdoe",
        risk_score      = 97,
        priority        = "CRITICAL",
    )


@pytest.fixture
def insider_threat_case(make_case):
    return make_case(
        alert_id        = "ALERT-20260606-002",
        alert_type      = "DATA_EXFILTRATION_LARGE_TRANSFER",
        affected_host   = "DESKTOP-XYZ789",
        affected_user   = "CORP\\jsmith",
        risk_score      = 82,
        priority        = "HIGH",
    )


@pytest.fixture
def false_positive_case(make_case):
    return make_case(
        alert_id        = "ALERT-20260606-FP",
        alert_type      = "MALWARE_EXECUTION_CERTUTIL",
        affected_host   = "WORKSTATION-02",
        affected_user   = "CORP\\it_admin01",
        risk_score      = 7,
        priority        = "LOW",
    )


@pytest.fixture
def supply_chain_case(make_case):
    return make_case(
        alert_id        = "ALERT-20260606-003",
        alert_type      = "SUPPLY_CHAIN_HASH_MISMATCH",
        affected_host   = "DESKTOP-FLEET-001",
        affected_user   = "SYSTEM",
        risk_score      = 91,
        priority        = "CRITICAL",
    )


@pytest.fixture
def cloud_breach_case(make_case):
    return make_case(
        alert_id        = "ALERT-20260606-004",
        alert_type      = "CLOUD_MISCONFIG_PUBLIC_S3",
        affected_host   = "AWS/us-east-1/s3/corp-finance-reports-2026",
        affected_user   = "mjones",
        risk_score      = 88,
        priority        = "CRITICAL",
    )


# ---------------------------------------------------------------------------
# Mock MCP client
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_mcp():
    """
    A MagicMock SplunkMCPClient pre-loaded with sensible default return
    values for all 14 MCP tools. Individual tests can override any method.
    """
    mcp = MagicMock()

    mcp.get_asset_context.return_value = {
        "host":              "DESKTOP-ABC123",
        "criticality_label": "HIGH",
        "criticality_score": 3,
        "owner":             "jdoe@corp.com",
        "environment":       "production",
        "asset_groups":      ["finance-workstations"],
        "os":                "Windows 10 22H2",
    }

    mcp.get_user_activity.return_value = {
        "user":                     "CORP\\jdoe",
        "impossible_travel_detected": False,
        "risk_score_current":        45,
        "baseline": {
            "typical_login_hours": "08:00-18:00",
            "typical_locations":   ["10.20.1.0/24"],
        },
        "events": [],
    }

    mcp.query_es_notable.return_value = {
        "notables":    [],
        "total_count": 0,
    }

    mcp.enrich_threat_intel.return_value = {
        "ioc":             "185.220.101.42",
        "verdict":         "malicious",
        "malware_families": ["LockBit.3.0"],
        "virustotal": {"detections": 52, "total_engines": 93},
        "abuseipdb":  {"abuse_confidence_score": 88},
    }

    mcp.search_spl.return_value = {"results": [], "job_id": "test-job-001"}

    mcp.validate_spl.return_value = {"valid": True, "warnings": []}

    mcp.get_process_tree.return_value = {
        "host":  "DESKTOP-ABC123",
        "trees": [],
    }

    mcp.get_network_flows.return_value = {
        "host":  "DESKTOP-ABC123",
        "flows": [],
    }

    mcp.execute_response_action.return_value = {
        "success": True,
        "action":  "isolate_host",
        "target":  "DESKTOP-ABC123",
        "status":  "COMPLETED",
        "details": "Host isolation confirmed via EDR",
    }

    mcp.create_ticket.return_value = {
        "success":   True,
        "ticket_id": "INC0012847",
        "url":       "https://servicenow.corp.com/incident/INC0012847",
    }

    mcp.notify_stakeholders.return_value = {
        "success":    True,
        "recipients": ["soc-oncall@corp.com", "ciso@corp.com"],
        "channels":   ["email", "slack"],
    }

    mcp.trigger_playbook.return_value = {
        "success":     True,
        "playbook_id": "RANSOMWARE_RESPONSE",
        "run_id":      "RUN-001",
    }

    mcp.get_indexes.return_value = {
        "indexes": ["sentinel_edr_index", "sentinel_network_index"]
    }

    mcp.run_saved_search.return_value = {"results": [], "job_id": "saved-001"}

    mcp.get_knowledge_objects.return_value = {"objects": []}

    return mcp


# ---------------------------------------------------------------------------
# Mock audit logger
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_audit():
    audit = MagicMock()
    audit.log_event.return_value    = True
    audit.log_decision.return_value = True
    audit.log_action.return_value   = True
    audit.log_error.return_value    = True
    return audit


# ---------------------------------------------------------------------------
# Mock config
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_config():
    return {
        "splunk_host":      "localhost",
        "splunk_port":      8089,
        "splunk_scheme":    "https",
        "splunk_token":     "test-token-abc123",
        "model_endpoint":   "https://localhost:8089/services/ml/models/foundation-sec-1.1-8b-instruct/predict",
        "model_token":      "test-model-token",
        "saia_endpoint":    "https://localhost:8089/services/assistant/v1/generate",
        "saia_token":       "test-saia-token",
        "auto_respond_score": 85,
        "vanguard_dismiss_threshold":  15,
        "vanguard_escalate_threshold": 85,
        "executor_require_approval_below": 85,
    }


# ---------------------------------------------------------------------------
# Sample Splunk ES notable alert data
# ---------------------------------------------------------------------------

@pytest.fixture
def sample_ransomware_alert():
    return {
        "alert_id":    "ALERT-20260606-001",
        "alert_type":  "RANSOMWARE_POWERSHELL_ENCODED",
        "rule_name":   "SENTINEL - Ransomware - PowerShell Encoded Command - Rule",
        "severity":    "critical",
        "host":        "DESKTOP-ABC123",
        "user":        "CORP\\jdoe",
        "src_ip":      "10.20.1.101",
        "dest_ip":     "185.220.101.42",
        "process_name":   "powershell.exe",
        "parent_process": "WINWORD.EXE",
        "process_args":   "powershell.exe -NoP -NonI -W Hidden -Enc JABzAD0A...",
        "risk_score":  97,
        "time":        "2026-06-06T08:00:00Z",
    }


@pytest.fixture
def sample_fp_alert():
    return {
        "alert_id":    "ALERT-20260606-FP",
        "alert_type":  "MALWARE_EXECUTION_CERTUTIL",
        "rule_name":   "SENTINEL - LOLBAS - certutil.exe File Download - Rule",
        "severity":    "low",
        "host":        "WORKSTATION-02",
        "user":        "CORP\\it_admin01",
        "src_ip":      "10.10.1.2",
        "process_name":   "certutil.exe",
        "process_args":   "certutil.exe -verify C:\\Certs\\corp_root_ca.crt",
        "risk_score":  7,
        "time":        "2026-06-06T09:30:00Z",
    }


# ---------------------------------------------------------------------------
# Vanguard decision packet factory
# ---------------------------------------------------------------------------

@pytest.fixture
def make_vanguard_result():
    def _factory(
        score:          int  = 90,
        decision:       str  = "AUTO_ESCALATE",
        classification: str  = "RANSOMWARE_INITIAL_ACCESS",
        confidence:     float = 0.95,
        mitre_tactic:   str  = "TA0001",
        mitre_technique:str  = "T1059.001",
    ) -> Dict[str, Any]:
        return {
            "success":        True,
            "risk_score":     score,
            "classification": classification,
            "mitre_tactic":   mitre_tactic,
            "mitre_technique":mitre_technique,
            "decision": {
                "case_id":         "CASE-TEST",
                "alert_id":        "ALERT-TEST",
                "classification":  classification,
                "confidence":      confidence,
                "mitre_tactic":    mitre_tactic,
                "mitre_technique": mitre_technique,
                "composite_score": score,
                "decision":        decision,
                "reasoning":       "High-confidence ransomware indicators detected.",
                "key_indicators":  ["encoded_powershell", "office_parent_process"],
                "false_positive_factors": [],
                "recommended_actions":    ["isolate_host", "disable_user"],
                "model_used":      "foundation-sec-1.1-8b-instruct",
                "model_available": True,
                "context": {
                    "asset_criticality":   "HIGH",
                    "historical_notables": 2,
                    "threat_intel_verdict": "malicious",
                },
            },
        }
    return _factory


# ---------------------------------------------------------------------------
# Sherlock report factory
# ---------------------------------------------------------------------------

@pytest.fixture
def make_sherlock_result():
    def _factory(
        case_id:         str   = "CASE-TEST",
        fp_probability:  float = 0.03,
        classification:  str   = "RANSOMWARE_INITIAL_ACCESS",
        phases_completed: list = None,
        iocs:            list  = None,
        blast_radius:    dict  = None,
    ) -> Dict[str, Any]:
        return {
            "success":       True,
            "case_id":       case_id,
            "report": {
                "case_id":                  case_id,
                "classification":           classification,
                "false_positive_probability": fp_probability,
                "phases_completed":         phases_completed or ["A", "B", "C", "D", "E"],
                "executive_summary":        "LockBit 3.0 confirmed on DESKTOP-ABC123.",
                "attack_narrative":         "Phishing email led to LSASS dump and lateral movement.",
                "blast_radius": blast_radius or {
                    "compromised_hosts":  ["DESKTOP-ABC123", "FILESERVER01"],
                    "compromised_users":  ["CORP\\jdoe", "CORP\\svc_backup"],
                    "affected_services":  ["\\\\FILESERVER01\\Finance$"],
                    "files_encrypted":    12,
                    "estimated_dwell_time_minutes": 7,
                },
                "threat_assessment": {
                    "malware_family":       "LockBit.3.0",
                    "threat_actor":         "CARBON-SPIDER",
                    "actor_sophistication": "HIGH",
                    "ttp_mapping":          ["T1566.001", "T1059.001", "T1003.001"],
                    "confidence":           0.97,
                    "urgency":              "IMMEDIATE",
                },
                "iocs_discovered": iocs or [
                    {"value": "185.220.101.42",  "type": "ip",     "verdict": "malicious"},
                    {"value": "svchost_injected.dll", "type": "sha256", "verdict": "malicious"},
                ],
                "recommended_actions": [
                    {"action": "isolate_host",  "target": "DESKTOP-ABC123", "priority": 1},
                    {"action": "disable_user",  "target": "CORP\\jdoe",     "priority": 2},
                    {"action": "block_ip",      "target": "185.220.101.42", "priority": 3},
                    {"action": "create_ticket", "target": "ServiceNow",     "priority": 4},
                ],
                "evidence_items": [],
            },
        }
    return _factory
