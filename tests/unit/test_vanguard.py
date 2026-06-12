"""
Unit tests for agent_vanguard.py — VanguardAgent triage pipeline.

Runs without a live Splunk instance: SplunkMCPClient, get_config,
get_audit_logger, and requests.post are all mocked.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

_BIN = Path(__file__).resolve().parent.parent.parent / "app" / "sentinel" / "bin"
if str(_BIN) not in sys.path:
    sys.path.insert(0, str(_BIN))

# Patch heavy deps before the module is imported so module-level side effects
# (get_config(), get_audit_logger()) don't fail without a Splunk environment.
with (
    patch("agent_vanguard.SplunkMCPClient", autospec=False),
    patch("agent_vanguard.get_audit_logger", return_value=MagicMock()),
    patch("agent_vanguard.get_config", return_value=MagicMock()),
):
    from agent_vanguard import (
        VanguardAgent,
        VanguardDecisionPacket,
        Decision,
        _DECISION_THRESHOLDS,
        _ASSET_MULTIPLIERS,
        _FALLBACK_RULES,
        _FALLBACK_DEFAULT,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_FOUNDATION_SEC_RESPONSE = {
    "classification":        "RANSOMWARE_INITIAL_ACCESS",
    "confidence":            0.97,
    "mitre_tactic":          "TA0001",
    "mitre_technique":       "T1059.001",
    "reasoning":             "Encoded PowerShell from Office process.",
    "key_indicators":        ["encoded_powershell", "office_parent_spawn"],
    "false_positive_factors":[],
    "recommended_actions":   ["isolate_host", "disable_user"],
}

_FOUNDATION_SEC_FP_RESPONSE = {
    "classification":        "FALSE_POSITIVE_IT_ADMIN",
    "confidence":            0.91,
    "mitre_tactic":          "",
    "mitre_technique":       "",
    "reasoning":             "certutil -verify on local file; IT admin account.",
    "key_indicators":        [],
    "false_positive_factors":["known_admin", "no_download_flag"],
    "recommended_actions":   ["close_case"],
}


def _make_agent(mock_mcp, mock_audit):
    with patch("agent_vanguard.get_config", return_value=MagicMock()):
        agent = VanguardAgent(mcp_client=mock_mcp, audit=mock_audit)
    return agent


def _make_case(
    case_id:       str = "CASE-TEST-001",
    alert_id:      str = "ALERT-TEST-001",
    alert_type:    str = "RANSOMWARE_POWERSHELL_ENCODED",
    affected_host: str = "DESKTOP-ABC123",
    affected_user: str = "CORP\\jdoe",
    risk_score:    int = 80,
):
    case = MagicMock()
    case.case_id       = case_id
    case.alert_id      = alert_id
    case.alert_type    = alert_type
    case.affected_host = affected_host
    case.affected_user = affected_user
    case.risk_score    = risk_score
    return case


# ---------------------------------------------------------------------------
# Decision threshold tests
# ---------------------------------------------------------------------------

class TestDecisionThresholds:
    @pytest.mark.parametrize("score,expected_decision", [
        (0,   Decision.AUTO_DISMISS),
        (7,   Decision.AUTO_DISMISS),
        (15,  Decision.AUTO_DISMISS),
        (16,  Decision.QUEUE_LOW),
        (30,  Decision.QUEUE_LOW),
        (54,  Decision.QUEUE_LOW),
        (55,  Decision.QUEUE_MED),
        (62,  Decision.QUEUE_MED),
        (69,  Decision.QUEUE_MED),
        (70,  Decision.QUEUE_HIGH),
        (77,  Decision.QUEUE_HIGH),
        (84,  Decision.QUEUE_HIGH),
        (85,  Decision.AUTO_ESCALATE),
        (97,  Decision.AUTO_ESCALATE),
        (100, Decision.AUTO_ESCALATE),
    ])
    def test_decision_boundary(self, score, expected_decision, mock_mcp, mock_audit):
        agent  = _make_agent(mock_mcp, mock_audit)
        result = agent._make_decision(score)
        assert result == expected_decision, (
            f"score={score}: expected {expected_decision!r}, got {result!r}"
        )

    def test_thresholds_list_sorted_descending(self):
        thresholds = [t for t, _ in _DECISION_THRESHOLDS]
        assert thresholds == sorted(thresholds, reverse=True)

    def test_all_five_decisions_represented(self):
        decisions = {d for _, d in _DECISION_THRESHOLDS}
        assert decisions == {
            Decision.AUTO_DISMISS,
            Decision.QUEUE_LOW,
            Decision.QUEUE_MED,
            Decision.QUEUE_HIGH,
            Decision.AUTO_ESCALATE,
        }

    def test_boundary_15_is_auto_dismiss(self, mock_mcp, mock_audit):
        agent = _make_agent(mock_mcp, mock_audit)
        assert agent._make_decision(15) == Decision.AUTO_DISMISS

    def test_boundary_16_is_queue_low(self, mock_mcp, mock_audit):
        agent = _make_agent(mock_mcp, mock_audit)
        assert agent._make_decision(16) == Decision.QUEUE_LOW

    def test_boundary_84_is_queue_high(self, mock_mcp, mock_audit):
        agent = _make_agent(mock_mcp, mock_audit)
        assert agent._make_decision(84) == Decision.QUEUE_HIGH

    def test_boundary_85_is_auto_escalate(self, mock_mcp, mock_audit):
        agent = _make_agent(mock_mcp, mock_audit)
        assert agent._make_decision(85) == Decision.AUTO_ESCALATE


# ---------------------------------------------------------------------------
# Asset multiplier tests
# ---------------------------------------------------------------------------

class TestAssetMultipliers:
    def test_critical_is_1_5(self):
        assert _ASSET_MULTIPLIERS["CRITICAL"] == 1.5

    def test_high_is_1_2(self):
        assert _ASSET_MULTIPLIERS["HIGH"] == 1.2

    def test_medium_is_1_0(self):
        assert _ASSET_MULTIPLIERS["MEDIUM"] == 1.0

    def test_low_is_0_5(self):
        assert _ASSET_MULTIPLIERS["LOW"] == 0.5

    def test_unknown_is_1_0(self):
        assert _ASSET_MULTIPLIERS["UNKNOWN"] == 1.0


# ---------------------------------------------------------------------------
# Composite score calculation tests
# ---------------------------------------------------------------------------

class TestCompositeScore:
    def test_score_in_valid_range_0_to_100(self, mock_mcp, mock_audit):
        agent = _make_agent(mock_mcp, mock_audit)
        score = agent._calculate_composite_score(
            base_confidence=0.99,
            asset_context  ={"criticality_label": "CRITICAL", "criticality_score": 4},
            alert_time     ="2026-06-06T03:00:00Z",
            historical     ={"same_host_notables_30d": 5, "same_rule_fp_rate_90d": 0.0,
                             "same_ioc_seen_before": True, "prior_confirmed_incidents": 2},
        )
        assert 0 <= score <= 100

    def test_score_never_below_zero(self, mock_mcp, mock_audit):
        agent = _make_agent(mock_mcp, mock_audit)
        score = agent._calculate_composite_score(
            base_confidence=0.01,
            asset_context  ={"criticality_label": "LOW", "criticality_score": 1},
            alert_time     ="2026-06-06T10:00:00Z",
            historical     ={"same_host_notables_30d": 0, "same_rule_fp_rate_90d": 0.9,
                             "same_ioc_seen_before": False, "prior_confirmed_incidents": 0},
        )
        assert score >= 0

    def test_higher_confidence_produces_higher_score(self, mock_mcp, mock_audit):
        agent = _make_agent(mock_mcp, mock_audit)
        ctx   = dict(
            asset_context={"criticality_label": "MEDIUM"},
            alert_time   ="2026-06-06T14:00:00Z",
            historical   ={},
        )
        score_high = agent._calculate_composite_score(base_confidence=0.95, **ctx)
        score_low  = agent._calculate_composite_score(base_confidence=0.20, **ctx)
        assert score_high > score_low

    def test_critical_asset_produces_higher_score_than_low_asset(
        self, mock_mcp, mock_audit
    ):
        agent = _make_agent(mock_mcp, mock_audit)
        ctx   = dict(alert_time="2026-06-06T14:00:00Z", historical={})
        score_crit = agent._calculate_composite_score(
            base_confidence=0.70,
            asset_context  ={"criticality_label": "CRITICAL"},
            **ctx,
        )
        score_low  = agent._calculate_composite_score(
            base_confidence=0.70,
            asset_context  ={"criticality_label": "LOW"},
            **ctx,
        )
        assert score_crit > score_low


# ---------------------------------------------------------------------------
# Fallback classification (rule-based) tests
# ---------------------------------------------------------------------------

class TestFallbackClassification:
    def test_encoded_powershell_maps_to_ransomware_initial_access(
        self, mock_mcp, mock_audit
    ):
        agent  = _make_agent(mock_mcp, mock_audit)
        result = agent._fallback_classification(
            alert_data={
                "process_name": "powershell.exe",
                "process_args": "-NoP -NonI -W Hidden -Enc JABzAD0A",
                "alert_type":   "GENERIC_POWERSHELL",
            },
            context={},
        )
        assert result["classification"] == "RANSOMWARE_INITIAL_ACCESS"
        assert result["model_available"] is False

    def test_lateral_movement_maps_correctly(self, mock_mcp, mock_audit):
        agent  = _make_agent(mock_mcp, mock_audit)
        result = agent._fallback_classification(
            alert_data={"alert_type": "LATERAL_MOVEMENT_SMB"}, context={}
        )
        assert result["classification"] == "LATERAL_MOVEMENT"

    def test_lsass_maps_to_credential_dumping(self, mock_mcp, mock_audit):
        agent  = _make_agent(mock_mcp, mock_audit)
        result = agent._fallback_classification(
            alert_data={"alert_type": "LSASS_ACCESS_CREDENTIAL_DUMP"}, context={}
        )
        assert result["classification"] == "CREDENTIAL_DUMPING"

    def test_exfil_maps_to_data_exfiltration(self, mock_mcp, mock_audit):
        agent  = _make_agent(mock_mcp, mock_audit)
        result = agent._fallback_classification(
            alert_data={"alert_type": "DATA_EXFIL_LARGE_TRANSFER_UPLOAD"}, context={}
        )
        assert result["classification"] == "DATA_EXFILTRATION"

    def test_s3_bucket_maps_to_cloud_misconfiguration(self, mock_mcp, mock_audit):
        agent  = _make_agent(mock_mcp, mock_audit)
        result = agent._fallback_classification(
            alert_data={"alert_type": "CLOUD_MISCONFIG_PUBLIC_S3_BUCKET"}, context={}
        )
        assert result["classification"] == "CLOUD_MISCONFIGURATION"

    def test_ransomware_keyword_maps_to_ransomware_initial_access(
        self, mock_mcp, mock_audit
    ):
        agent  = _make_agent(mock_mcp, mock_audit)
        result = agent._fallback_classification(
            alert_data={"alert_type": "RANSOMWARE_POWERSHELL_ENCODED"}, context={}
        )
        assert result["classification"] == "RANSOMWARE_INITIAL_ACCESS"

    def test_brute_force_keyword_maps_correctly(self, mock_mcp, mock_audit):
        agent  = _make_agent(mock_mcp, mock_audit)
        result = agent._fallback_classification(
            alert_data={"alert_type": "BRUTE_FORCE_RDP"}, context={}
        )
        assert result["classification"] == "BRUTE_FORCE"

    def test_scan_maps_to_reconnaissance(self, mock_mcp, mock_audit):
        agent  = _make_agent(mock_mcp, mock_audit)
        result = agent._fallback_classification(
            alert_data={"alert_type": "PORT_SCAN_RECON"}, context={}
        )
        assert result["classification"] == "RECONNAISSANCE"

    def test_unknown_alert_returns_anomalous_behavior(self, mock_mcp, mock_audit):
        agent  = _make_agent(mock_mcp, mock_audit)
        result = agent._fallback_classification(
            alert_data={"alert_type": "COMPLETELY_UNKNOWN_XYZ"}, context={}
        )
        assert result["classification"] == "ANOMALOUS_BEHAVIOR"

    def test_fallback_always_sets_model_available_false(self, mock_mcp, mock_audit):
        agent  = _make_agent(mock_mcp, mock_audit)
        result = agent._fallback_classification({}, {})
        assert result.get("model_available") is False
        assert result.get("model_used")      == "rule_based_fallback"


# ---------------------------------------------------------------------------
# Foundation-Sec model + fallback tests
# ---------------------------------------------------------------------------

class TestFoundationSecFallback:
    def test_model_unavailable_falls_back_to_rule_based(
        self, mock_mcp, mock_audit
    ):
        agent = _make_agent(mock_mcp, mock_audit)
        with patch.object(agent, "_call_foundation_sec",
                          side_effect=Exception("model down")):
            result = agent._classify_alert(
                alert_data={
                    "process_name": "powershell.exe",
                    "process_args": "-enc JABLAH",
                    "alert_type":   "RANSOMWARE_POWERSHELL_ENCODED",
                },
                context={},
            )
        assert result["model_available"] is False
        assert result["model_used"]      == "rule_based_fallback"
        assert result["classification"]  != ""

    def test_model_available_uses_foundation_sec_result(
        self, mock_mcp, mock_audit
    ):
        agent = _make_agent(mock_mcp, mock_audit)
        with patch.object(agent, "_call_foundation_sec",
                          return_value=_FOUNDATION_SEC_RESPONSE):
            result = agent._classify_alert(
                alert_data={"alert_type": "RANSOMWARE_POWERSHELL_ENCODED"},
                context={},
            )
        assert result["model_available"] is True
        assert result["model_used"]      == "foundation-sec-1.1-8b-instruct"
        assert result["classification"]  == "RANSOMWARE_INITIAL_ACCESS"
        assert result["confidence"]      == 0.97

    def test_requests_timeout_triggers_fallback(self, mock_mcp, mock_audit):
        import requests as req
        agent = _make_agent(mock_mcp, mock_audit)
        with patch.object(agent, "_call_foundation_sec",
                          side_effect=req.exceptions.Timeout("timed out")):
            result = agent._classify_alert({}, {})
        assert result["model_available"] is False


# ---------------------------------------------------------------------------
# MCP graceful degradation tests
# ---------------------------------------------------------------------------

class TestMCPGracefulDegradation:
    def _patched_classify(self):
        return {
            "classification":        "ANOMALOUS_BEHAVIOR",
            "confidence":            0.40,
            "mitre_tactic":          "TA0000",
            "mitre_technique":       "T0000",
            "reasoning":             "",
            "key_indicators":        [],
            "false_positive_factors":[],
            "recommended_actions":   [],
            "model_available":       False,
            "model_used":            "rule_based_fallback",
        }

    def test_asset_context_mcp_failure_does_not_crash_run(
        self, mock_mcp, mock_audit
    ):
        from mcp_client import MCPError
        mock_mcp.get_asset_context.side_effect = MCPError("asset offline")
        agent = _make_agent(mock_mcp, mock_audit)
        case  = _make_case()
        with patch.object(agent, "_classify_alert", return_value=self._patched_classify()):
            result = agent.run(case, mock_audit)
        assert result["success"] is True

    def test_user_activity_mcp_failure_does_not_crash_run(
        self, mock_mcp, mock_audit
    ):
        from mcp_client import MCPError
        mock_mcp.get_user_activity.side_effect = MCPError("UEBA offline")
        agent = _make_agent(mock_mcp, mock_audit)
        case  = _make_case()
        with patch.object(agent, "_classify_alert", return_value=self._patched_classify()):
            result = agent.run(case, mock_audit)
        assert result["success"] is True

    def test_threat_intel_mcp_failure_does_not_crash_run(
        self, mock_mcp, mock_audit
    ):
        from mcp_client import MCPError
        mock_mcp.enrich_threat_intel.side_effect = MCPError("TI offline")
        agent = _make_agent(mock_mcp, mock_audit)
        case  = _make_case()
        with patch.object(agent, "_classify_alert", return_value=self._patched_classify()):
            result = agent.run(case, mock_audit)
        assert result["success"] is True


# ---------------------------------------------------------------------------
# run() return shape tests
# ---------------------------------------------------------------------------

class TestRunOutputShape:
    _REQUIRED_KEYS = {
        "success", "decision", "risk_score",
        "classification", "mitre_tactic", "mitre_technique",
    }

    def test_run_returns_all_required_keys(self, mock_mcp, mock_audit):
        agent = _make_agent(mock_mcp, mock_audit)
        case  = _make_case()
        with patch.object(agent, "_classify_alert", return_value={
            **_FOUNDATION_SEC_RESPONSE,
            "model_available": True,
            "model_used":      "foundation-sec-1.1-8b-instruct",
        }):
            result = agent.run(case, mock_audit)
        assert self._REQUIRED_KEYS <= set(result.keys())
        assert result["success"]          is True
        assert isinstance(result["risk_score"],     int)
        assert isinstance(result["classification"], str)
        assert isinstance(result["decision"],       dict)

    def test_run_decision_contains_composite_score_and_decision_string(
        self, mock_mcp, mock_audit
    ):
        agent = _make_agent(mock_mcp, mock_audit)
        case  = _make_case(risk_score=97)
        with patch.object(agent, "_classify_alert", return_value={
            **_FOUNDATION_SEC_RESPONSE,
            "model_available": True,
            "model_used":      "foundation-sec-1.1-8b-instruct",
        }):
            result = agent.run(case, mock_audit)
        pkt = result["decision"]
        assert "composite_score" in pkt
        assert "decision"        in pkt
        assert pkt["decision"] in {
            Decision.AUTO_DISMISS,
            Decision.QUEUE_LOW,
            Decision.QUEUE_MED,
            Decision.QUEUE_HIGH,
            Decision.AUTO_ESCALATE,
        }

    def test_run_returns_success_false_on_unhandled_exception(
        self, mock_mcp, mock_audit
    ):
        agent = _make_agent(mock_mcp, mock_audit)
        case  = _make_case()
        with patch.object(agent, "_gather_context",
                          side_effect=RuntimeError("catastrophic failure")):
            result = agent.run(case, mock_audit)
        assert result["success"] is False
        assert "error" in result

    def test_ransomware_alert_produces_auto_escalate(self, mock_mcp, mock_audit):
        agent = _make_agent(mock_mcp, mock_audit)
        case  = _make_case(alert_type="RANSOMWARE_POWERSHELL_ENCODED", risk_score=97)
        with patch.object(agent, "_call_foundation_sec", return_value={
            "classification":        "RANSOMWARE_INITIAL_ACCESS",
            "confidence":            0.97,
            "mitre_tactic":          "TA0001",
            "mitre_technique":       "T1059.001",
            "reasoning":             "Encoded PowerShell from Office parent.",
            "key_indicators":        ["encoded_ps", "office_parent"],
            "false_positive_factors":[],
            "recommended_actions":   ["isolate_host"],
        }):
            result = agent.run(case, mock_audit)
        assert result["success"] is True
        assert result["decision"]["decision"] == Decision.AUTO_ESCALATE

    def test_false_positive_alert_produces_auto_dismiss(
        self, mock_mcp, mock_audit
    ):
        agent = _make_agent(mock_mcp, mock_audit)
        case  = _make_case(
            alert_type="MALWARE_EXECUTION_CERTUTIL",
            affected_user="CORP\\it_admin01",
            risk_score=7,
        )
        with patch.object(agent, "_call_foundation_sec",
                          return_value=_FOUNDATION_SEC_FP_RESPONSE):
            with patch.object(agent, "_calculate_composite_score", return_value=7):
                result = agent.run(case, mock_audit)
        assert result["success"] is True
        assert result["decision"]["decision"] == Decision.AUTO_DISMISS


# ---------------------------------------------------------------------------
# VanguardDecisionPacket tests
# ---------------------------------------------------------------------------

class TestVanguardDecisionPacket:
    def test_to_dict_contains_all_required_fields(self):
        pkt = VanguardDecisionPacket(
            case_id        ="CASE-001",
            alert_id       ="ALERT-001",
            classification ="RANSOMWARE_INITIAL_ACCESS",
            confidence     =0.97,
            mitre_tactic   ="TA0001",
            mitre_technique="T1059.001",
            composite_score=97,
            decision       =Decision.AUTO_ESCALATE,
            reasoning      ="High-confidence ransomware.",
        )
        d = pkt.to_dict()
        required = {
            "case_id", "alert_id", "classification", "confidence",
            "mitre_tactic", "mitre_technique", "composite_score", "decision",
            "reasoning", "key_indicators", "false_positive_factors",
            "recommended_actions", "context", "model_used", "model_available",
            "timestamp",
        }
        assert required <= set(d.keys())

    def test_to_json_is_valid_json(self):
        pkt = VanguardDecisionPacket(
            case_id="C", alert_id="A", classification="X",
            confidence=0.5, mitre_tactic="TA0001", mitre_technique="T0000",
            composite_score=50, decision=Decision.QUEUE_MED, reasoning="test",
        )
        parsed = json.loads(pkt.to_json())
        assert parsed["case_id"] == "C"
        assert parsed["decision"] == Decision.QUEUE_MED

    def test_default_model_used_is_foundation_sec(self):
        pkt = VanguardDecisionPacket(
            case_id="C", alert_id="A", classification="X",
            confidence=0.5, mitre_tactic="", mitre_technique="",
            composite_score=50, decision=Decision.QUEUE_LOW, reasoning="",
        )
        assert "foundation-sec" in pkt.model_used
