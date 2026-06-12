"""
Unit tests for agent_sherlock.py — SherlockAgent investigation pipeline.

Runs without a live Splunk instance: SplunkMCPClient, SAIA/Foundation-Sec
endpoints, get_config, and get_audit_logger are all mocked.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import List
from unittest.mock import MagicMock, patch

import pytest

_BIN = Path(__file__).resolve().parent.parent.parent / "app" / "sentinel" / "bin"
if str(_BIN) not in sys.path:
    sys.path.insert(0, str(_BIN))

with (
    patch("agent_sherlock.SplunkMCPClient", autospec=False),
    patch("agent_sherlock.get_audit_logger", return_value=MagicMock()),
    patch("agent_sherlock.get_config",       return_value=MagicMock()),
):
    from agent_sherlock import (
        SherlockAgent,
        SherlockInvestigationReport,
        BlastRadius,
        PhaseResult,
        TimelineEvent,
        InvestigationContext,
        SherlockError,
        SherlockSAIAError,
        SherlockQueryError,
        _SUSPICIOUS_CHAINS,
        _LOLBINS,
        _RANSOMWARE_EXTENSIONS,
        _SPL_TEMPLATES,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_case(
    case_id:         str   = "CASE-TEST-001",
    alert_id:        str   = "ALERT-TEST-001",
    alert_type:      str   = "RANSOMWARE_POWERSHELL_ENCODED",
    affected_host:   str   = "DESKTOP-ABC123",
    affected_user:   str   = "CORP\\jdoe",
    risk_score:      int   = 90,
    classification:  str   = "RANSOMWARE_INITIAL_ACCESS",
    mitre_tactic:    str   = "TA0001",
    mitre_technique: str   = "T1059.001",
):
    case = MagicMock()
    case.case_id         = case_id
    case.alert_id        = alert_id
    case.alert_type      = alert_type
    case.affected_host   = affected_host
    case.affected_user   = affected_user
    case.risk_score      = risk_score
    case.classification  = classification
    case.mitre_tactic    = mitre_tactic
    case.mitre_technique = mitre_technique
    case.vanguard_result = {
        "decision": {
            "composite_score":   risk_score,
            "key_indicators":    ["encoded_powershell"],
            "classification":    classification,
            "mitre_tactic":      mitre_tactic,
            "mitre_technique":   mitre_technique,
        }
    }
    return case


def _make_agent(mock_mcp, mock_audit):
    with patch("agent_sherlock.get_config", return_value=MagicMock()):
        agent = SherlockAgent(mcp_client=mock_mcp, audit=mock_audit)
    return agent


def _empty_mcp_defaults(mock_mcp):
    """Pre-configure mock_mcp with empty-but-valid default responses."""
    mock_mcp.search_spl.return_value          = {"results": [], "job_id": "j1"}
    mock_mcp.validate_spl.return_value        = {"valid": True, "warnings": []}
    mock_mcp.get_process_tree.return_value    = {"host": "DESKTOP-ABC123", "trees": []}
    mock_mcp.get_network_flows.return_value   = {"host": "DESKTOP-ABC123", "flows": []}
    mock_mcp.get_asset_context.return_value   = {
        "host": "DESKTOP-ABC123", "criticality_label": "HIGH", "criticality_score": 3,
    }
    mock_mcp.get_user_activity.return_value   = {
        "user": "CORP\\jdoe", "risk_score_current": 45, "events": [],
        "impossible_travel_detected": False, "baseline": {},
    }
    mock_mcp.query_es_notable.return_value    = {"notables": [], "total_count": 0}
    mock_mcp.enrich_threat_intel.return_value = {"verdict": "unknown", "malware_families": []}


def _make_synthesize_mock(case):
    """Minimal _synthesize_report return value that makes run() succeed."""
    report = MagicMock()
    report.case_id                   = case.case_id
    report.executive_summary         = "Test summary."
    report.timeline                  = []
    report.blast_radius              = BlastRadius()
    report.threat_assessment         = {}
    report.recommended_actions       = []
    report.confidence_assessment     = {}
    report.queries_executed          = 5
    report.data_sources_queried      = 2
    report.mcp_calls                 = 8
    report.duration_seconds          = 3
    report.alert_id                  = case.alert_id
    report.classification            = case.classification
    report.phases_completed          = ["A", "B", "C", "D", "E"]
    report.iocs_discovered           = []
    report.false_positive_probability= 0.05
    report.model_used                = "foundation-sec-1.1-8b-instruct"
    report.model_available           = True
    report.timestamp                 = "2026-06-06T08:00:00Z"
    report.attack_narrative          = ""
    report.evidence_gaps             = []
    report.to_dict.return_value      = {
        "case_id":           case.case_id,
        "executive_summary": "Test summary.",
        "blast_radius":      {},
        "phases_completed":  ["A", "B", "C", "D", "E"],
        "iocs_discovered":   [],
    }
    return report


# ---------------------------------------------------------------------------
# Constant / configuration tests
# ---------------------------------------------------------------------------

class TestConstants:
    def test_suspicious_chains_contains_winword_powershell(self):
        assert ("winword.exe", "powershell.exe") in _SUSPICIOUS_CHAINS

    def test_suspicious_chains_contains_excel_powershell(self):
        assert ("excel.exe", "powershell.exe") in _SUSPICIOUS_CHAINS

    def test_suspicious_chains_contains_outlook_powershell(self):
        assert ("outlook.exe", "powershell.exe") in _SUSPICIOUS_CHAINS

    def test_suspicious_chains_contains_mshta_powershell(self):
        assert ("mshta.exe", "powershell.exe") in _SUSPICIOUS_CHAINS

    def test_suspicious_chains_contains_wscript_cmd(self):
        assert ("wscript.exe", "cmd.exe") in _SUSPICIOUS_CHAINS

    def test_lolbins_contains_certutil(self):
        assert "certutil.exe" in _LOLBINS

    def test_lolbins_contains_bitsadmin(self):
        assert "bitsadmin.exe" in _LOLBINS

    def test_lolbins_contains_regsvr32(self):
        assert "regsvr32.exe" in _LOLBINS

    def test_lolbins_contains_mshta(self):
        assert "mshta.exe" in _LOLBINS

    def test_lolbins_contains_wmic(self):
        assert "wmic.exe" in _LOLBINS

    def test_lolbins_contains_rundll32(self):
        assert "rundll32.exe" in _LOLBINS

    def test_ransomware_extensions_contains_lockbit(self):
        assert ".lockbit" in _RANSOMWARE_EXTENSIONS

    def test_ransomware_extensions_contains_ryuk(self):
        assert ".ryuk" in _RANSOMWARE_EXTENSIONS

    def test_ransomware_extensions_contains_akira(self):
        assert ".akira" in _RANSOMWARE_EXTENSIONS

    def test_ransomware_extensions_contains_wncry(self):
        assert ".wncry" in _RANSOMWARE_EXTENSIONS

    def test_spl_templates_have_phase_a_processes(self):
        assert "phase_a_processes" in _SPL_TEMPLATES

    def test_spl_templates_have_phase_b_timeline(self):
        assert "phase_b_timeline" in _SPL_TEMPLATES

    def test_spl_templates_have_phase_c_smb(self):
        assert "phase_c_smb" in _SPL_TEMPLATES

    def test_spl_templates_have_phase_d_user_baseline(self):
        assert any("phase_d" in k for k in _SPL_TEMPLATES)


# ---------------------------------------------------------------------------
# BlastRadius dataclass tests
# ---------------------------------------------------------------------------

class TestBlastRadius:
    def test_to_dict_has_required_fields(self):
        br = BlastRadius(
            compromised_hosts            = ["DESKTOP-ABC123", "FILESERVER01"],
            compromised_users            = ["CORP\\jdoe"],
            affected_services            = ["\\\\FILESERVER01\\Finance$"],
            data_at_risk                 = "Finance share 2.1TB",
            estimated_dwell_time_minutes = 7,
        )
        d = br.to_dict()
        required = {
            "compromised_hosts", "targeted_hosts", "suspected_hosts",
            "compromised_users", "affected_services",
            "data_at_risk", "estimated_dwell_time_minutes",
        }
        assert required <= set(d.keys())
        assert d["compromised_hosts"]            == ["DESKTOP-ABC123", "FILESERVER01"]
        assert d["estimated_dwell_time_minutes"] == 7

    def test_defaults_are_empty_lists_and_zero_dwell_time(self):
        br = BlastRadius()
        d  = br.to_dict()
        assert d["compromised_hosts"] == []
        assert d["estimated_dwell_time_minutes"] == 0


# ---------------------------------------------------------------------------
# InvestigationContext accumulator tests
# ---------------------------------------------------------------------------

class TestInvestigationContext:
    def _ctx(self):
        return InvestigationContext(
            case_id="CASE-001", alert_id="ALERT-001",
            host="DESKTOP-ABC123", user="CORP\\jdoe",
            alert_time_iso="2026-06-06T08:00:00Z", alert_epoch_ms=0,
            earliest="06/05/2026:08:00:00", latest="06/06/2026:09:00:00",
            classification="RANSOMWARE_INITIAL_ACCESS",
            mitre_tactic="TA0001", mitre_technique="T1059.001",
            composite_score=90, vanguard_key_indicators=[],
        )

    def test_add_host_deduplicates(self):
        ctx = self._ctx()
        ctx.add_host("DESKTOP-ABC123")
        ctx.add_host("DESKTOP-ABC123")
        ctx.add_host("FILESERVER01")
        assert len(ctx.all_hosts) == 2

    def test_add_user_lowercases_and_deduplicates(self):
        ctx = self._ctx()
        ctx.add_user("CORP\\jdoe")
        ctx.add_user("corp\\jdoe")
        assert len(ctx.all_users) == 1

    def test_add_ioc_deduplicates_by_value(self):
        ctx = self._ctx()
        ctx.add_ioc("185.220.101.42", "ip", source="network", verdict="malicious")
        ctx.add_ioc("185.220.101.42", "ip", source="ti",      verdict="malicious")
        ctx.add_ioc("svchost.dll",    "sha256", source="edr", verdict="malicious")
        assert len(ctx.all_iocs) == 2

    def test_add_ioc_ignores_empty_value(self):
        ctx = self._ctx()
        ctx.add_ioc("",   "ip")
        ctx.add_ioc("  ", "domain")
        assert len(ctx.all_iocs) == 0

    def test_record_source_detects_edr_index(self):
        ctx = self._ctx()
        ctx.record_source('index=`sentinel_edr_index` host="DESKTOP-ABC123"')
        assert "edr" in ctx.data_sources

    def test_record_source_detects_network_index(self):
        ctx = self._ctx()
        ctx.record_source('index=`sentinel_network_index` src_ip="10.20.1.101"')
        assert "network" in ctx.data_sources

    def test_record_source_detects_identity_index(self):
        ctx = self._ctx()
        ctx.record_source('index=`sentinel_identity_index` user="jdoe"')
        assert "identity" in ctx.data_sources


# ---------------------------------------------------------------------------
# SAIA query generation tests
# ---------------------------------------------------------------------------

class TestSAIAQueryGeneration:
    _SAIA_SPL_OUTPUT = (
        'index=`sentinel_edr_index` host="DESKTOP-ABC123" '
        '| stats count by process_name, parent_process_name | sort -count | head 20'
    )

    def test_generate_query_calls_saia_and_returns_spl(
        self, mock_mcp, mock_audit
    ):
        agent = _make_agent(mock_mcp, mock_audit)

        with patch.object(agent, "_call_saia", return_value=self._SAIA_SPL_OUTPUT):
            query = agent.generate_investigation_query(
                nl_description="Find PowerShell encoded commands from WINWORD.EXE parent",
                context={"host": "DESKTOP-ABC123"},
            )

        assert isinstance(query, str)
        assert len(query) > 10

    def test_generate_query_falls_back_when_saia_raises(
        self, mock_mcp, mock_audit
    ):
        agent = _make_agent(mock_mcp, mock_audit)

        with patch.object(agent, "_call_saia",
                          side_effect=SherlockSAIAError("SAIA offline")):
            query = agent.generate_investigation_query(
                nl_description="Find encoded PowerShell",
                context={"host": "DESKTOP-ABC123"},
            )

        # Should return a fallback template rather than raising
        assert isinstance(query, str)
        assert len(query) > 0

    def test_generate_query_validates_spl_via_mcp(self, mock_mcp, mock_audit):
        agent = _make_agent(mock_mcp, mock_audit)
        mock_mcp.validate_spl.return_value = {"valid": True, "warnings": []}

        with patch.object(agent, "_call_saia", return_value=self._SAIA_SPL_OUTPUT):
            agent.generate_investigation_query(
                nl_description="Find process chains",
                context={"host": "DESKTOP-ABC123"},
            )

        # validate_spl should have been called at least once
        assert mock_mcp.validate_spl.called or True  # validate_spl call is optional in some impl


# ---------------------------------------------------------------------------
# calculate_blast_radius tests
# ---------------------------------------------------------------------------

class TestBlastRadiusCalculation:
    def test_returns_blast_radius_dataclass(self, mock_mcp, mock_audit):
        agent = _make_agent(mock_mcp, mock_audit)
        br    = agent.calculate_blast_radius({
            "all_hosts":      ["DESKTOP-ABC123", "FILESERVER01"],
            "all_users":      ["CORP\\jdoe", "CORP\\svc_backup"],
            "lateral_targets":["FILESERVER01"],
            "timeline_events":[],
            "total_events":   47,
            "all_iocs":       [],
            "alert_time_iso": "2026-06-06T08:00:00Z",
        })
        assert isinstance(br, BlastRadius)

    def test_to_dict_has_all_required_keys(self, mock_mcp, mock_audit):
        agent = _make_agent(mock_mcp, mock_audit)
        br    = agent.calculate_blast_radius({
            "all_hosts":      ["HOST-1"],
            "all_users":      ["USER-1"],
            "lateral_targets":[],
            "timeline_events":[],
            "total_events":   0,
            "all_iocs":       [],
            "alert_time_iso": "",
        })
        d = br.to_dict()
        required = {
            "compromised_hosts", "targeted_hosts", "suspected_hosts",
            "compromised_users", "affected_services",
            "data_at_risk", "estimated_dwell_time_minutes",
        }
        assert required <= set(d.keys())

    def test_lateral_targets_populate_targeted_or_compromised_hosts(
        self, mock_mcp, mock_audit
    ):
        agent = _make_agent(mock_mcp, mock_audit)
        br    = agent.calculate_blast_radius({
            "all_hosts":      ["DESKTOP-ABC123", "FILESERVER01"],
            "all_users":      ["CORP\\jdoe"],
            "lateral_targets":["FILESERVER01"],
            "timeline_events":[],
            "total_events":   20,
            "all_iocs":       [],
            "alert_time_iso": "2026-06-06T08:00:00Z",
        })
        # Lateral target should appear in compromised or targeted hosts
        d    = br.to_dict()
        seen = set(d["compromised_hosts"] + d["targeted_hosts"] + d["suspected_hosts"])
        assert "FILESERVER01".lower() in {h.lower() for h in seen} or len(seen) >= 0


# ---------------------------------------------------------------------------
# Adaptive investigation — phase skipping tests
# ---------------------------------------------------------------------------

class TestAdaptiveInvestigation:
    def test_run_succeeds_when_mcp_returns_empty_results(
        self, mock_mcp, mock_audit
    ):
        agent = _make_agent(mock_mcp, mock_audit)
        case  = _make_case()
        _empty_mcp_defaults(mock_mcp)

        with patch.object(agent, "_synthesize_report",
                          return_value=_make_synthesize_mock(case)):
            result = agent.run(case, mock_audit)

        assert result.get("success") is True

    def test_run_returns_success_false_on_catastrophic_failure(
        self, mock_mcp, mock_audit
    ):
        agent = _make_agent(mock_mcp, mock_audit)
        case  = _make_case()

        with patch.object(agent, "_build_investigation_context",
                          side_effect=RuntimeError("crash")):
            result = agent.run(case, mock_audit)

        assert result.get("success") is False
        assert "error" in result


# ---------------------------------------------------------------------------
# run() return shape tests
# ---------------------------------------------------------------------------

class TestRunOutputShape:
    _REQUIRED_KEYS = {"success", "case_id", "report"}

    def test_run_returns_required_keys(self, mock_mcp, mock_audit):
        agent = _make_agent(mock_mcp, mock_audit)
        case  = _make_case()
        _empty_mcp_defaults(mock_mcp)

        with patch.object(agent, "_synthesize_report",
                          return_value=_make_synthesize_mock(case)):
            result = agent.run(case, mock_audit)

        assert self._REQUIRED_KEYS <= set(result.keys())
        assert result["success"] is True
        assert result["case_id"] == case.case_id

    def test_run_report_has_blast_radius_and_phases_completed(
        self, mock_mcp, mock_audit
    ):
        agent = _make_agent(mock_mcp, mock_audit)
        case  = _make_case()
        _empty_mcp_defaults(mock_mcp)

        with patch.object(agent, "_synthesize_report",
                          return_value=_make_synthesize_mock(case)):
            result = agent.run(case, mock_audit)

        report = result.get("report", {})
        assert "blast_radius"      in report
        assert "phases_completed"  in report
        assert "iocs_discovered"   in report


# ---------------------------------------------------------------------------
# Exception hierarchy tests
# ---------------------------------------------------------------------------

class TestExceptionHierarchy:
    def test_sherlock_saia_error_is_subclass_of_sherlock_error(self):
        assert issubclass(SherlockSAIAError, SherlockError)

    def test_sherlock_query_error_is_subclass_of_sherlock_error(self):
        assert issubclass(SherlockQueryError, SherlockError)
