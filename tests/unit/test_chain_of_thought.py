"""
Unit tests for "Chain of Thought" explainability tracing across SENTINEL agents.

Covers:
  - VanguardAgent.generate_chain_of_thought / _summarize_chain_of_thought
  - SherlockAgent.build_investigation_chain
  - ExecutorAgent.build_action_chain
  - AuditLogger.log_chain_of_thought

These tests verify the *narrative explainability trace* added for SOC audit /
compliance purposes — they assert structure and content of the chain, not
the underlying decision logic (which is covered by test_vanguard.py /
test_sherlock.py / test_executor.py and must remain unchanged).

Runs without a live Splunk instance — all heavy dependencies are mocked.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

_BIN = Path(__file__).resolve().parent.parent.parent / "app" / "sentinel" / "bin"
if str(_BIN) not in sys.path:
    sys.path.insert(0, str(_BIN))

with (
    patch("agent_vanguard.SplunkMCPClient", autospec=False),
    patch("agent_vanguard.get_audit_logger", return_value=MagicMock()),
    patch("agent_vanguard.get_config",       return_value=MagicMock()),
):
    from agent_vanguard import VanguardAgent, Decision, _DECISION_THRESHOLDS

with (
    patch("agent_sherlock.SplunkMCPClient", autospec=False),
    patch("agent_sherlock.get_audit_logger", return_value=MagicMock()),
    patch("agent_sherlock.get_config",       return_value=MagicMock()),
):
    from agent_sherlock import SherlockAgent, PhaseResult, InvestigationContext

with (
    patch("agent_executor.SplunkMCPClient", autospec=False),
    patch("agent_executor.get_audit_logger", return_value=MagicMock()),
    patch("agent_executor.get_config",       return_value=MagicMock()),
):
    from agent_executor import (
        ExecutorAgent,
        ActionResult,
        ActionVerification,
        ActionStatus,
        ExecutorMode,
        _CONTAINMENT_ACTIONS,
        _ERADICATION_ACTIONS,
    )

from audit_logger import AuditLogger, _base_event


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_vanguard_agent(mock_mcp=None, mock_audit=None):
    with patch("agent_vanguard.get_config", return_value=MagicMock()):
        return VanguardAgent(mcp_client=mock_mcp or MagicMock(), audit=mock_audit or MagicMock())


def _make_sherlock_agent(mock_mcp=None):
    with patch("agent_sherlock.get_config", return_value=MagicMock()):
        return SherlockAgent(mcp=mock_mcp or MagicMock())


def _make_executor_agent(mock_mcp=None):
    with patch("agent_executor.get_config", return_value=MagicMock()):
        return ExecutorAgent(mcp=mock_mcp or MagicMock())


def _make_investigation_context(**overrides):
    defaults = dict(
        case_id="SEN-CHAIN-001",
        alert_id="ALERT-CHAIN-001",
        host="DESKTOP-ABC123",
        user="CORP\\jdoe",
        alert_time_iso="2026-06-06T08:00:00Z",
        alert_epoch_ms=1_770_000_000_000,
        earliest="06/06/2026:06:00:00",
        latest="06/06/2026:10:00:00",
        classification="RANSOMWARE_INITIAL_ACCESS",
        mitre_tactic="TA0001",
        mitre_technique="T1059.001",
        composite_score=97,
        vanguard_key_indicators=["encoded_powershell", "office_parent_process"],
    )
    defaults.update(overrides)
    return InvestigationContext(**defaults)


def _make_phase_result(phase, status="complete", queries_run=2, events_found=10,
                        key_findings=None, iocs_found=None, evidence_gaps=None, error=None):
    return PhaseResult(
        phase=phase,
        status=status,
        queries_run=queries_run,
        events_found=events_found,
        key_findings=key_findings if key_findings is not None else [f"Finding for phase {phase}"],
        iocs_found=iocs_found or [],
        evidence_gaps=evidence_gaps or [],
        error=error,
    )


def _make_action_result(action_type, target="DESKTOP-ABC123", status=ActionStatus.SUCCESS.value,
                        verified=True, pre_state="connected", post_state="isolated",
                        rollback_timer=14400, human_notified=True, justification="Confirmed threat"):
    return ActionResult(
        case_id="SEN-CHAIN-001",
        action_id="ACT-TEST0001",
        action_type=action_type,
        target=target,
        status=status,
        execution_time_ms=1500,
        verification=ActionVerification(
            pre_state=pre_state,
            post_state=post_state,
            confirmation_query=f"index=sentinel_edr_index host={target} | stats latest(status)",
            verified=verified,
        ),
        rollback_timer=rollback_timer,
        rollback_scheduled="2026-06-06T12:00:00Z" if rollback_timer else "",
        human_notified=human_notified,
        notification_sent_to=["soc-oncall@corp.com"] if human_notified else [],
        justification=justification,
    )


# ---------------------------------------------------------------------------
# VanguardAgent.generate_chain_of_thought
# ---------------------------------------------------------------------------

class TestVanguardChainOfThought:
    @pytest.fixture
    def agent(self):
        return _make_vanguard_agent()

    @pytest.fixture
    def alert_data(self):
        return {
            "alert_type":    "RANSOMWARE_POWERSHELL_ENCODED",
            "host":          "DESKTOP-ABC123",
            "process_name":  "powershell.exe",
            "process_args":  "-NoP -NonI -W Hidden -Enc JABzAD0A...",
            "time":          "2026-06-06T23:45:00Z",
        }

    @pytest.fixture
    def context(self):
        return {
            "asset": {"criticality_label": "CRITICAL", "owner": "jdoe@corp.com"},
            "historical": {
                "same_rule_fp_rate_90d": 0.05,
                "prior_confirmed_incidents": 2,
                "same_host_notables_30d": 4,
            },
        }

    @pytest.fixture
    def model_result(self):
        return {
            "classification":  "RANSOMWARE_INITIAL_ACCESS",
            "confidence":      0.97,
            "model_used":      "foundation-sec-1.1-8b-instruct",
            "model_available": True,
            "composite_score": 97,
            "decision":        Decision.AUTO_ESCALATE,
        }

    def test_returns_six_steps(self, agent, alert_data, context, model_result):
        chain = agent.generate_chain_of_thought(alert_data, context, model_result)
        assert len(chain) == 6

    def test_steps_are_sequentially_numbered(self, agent, alert_data, context, model_result):
        chain = agent.generate_chain_of_thought(alert_data, context, model_result)
        assert [step["step"] for step in chain] == [1, 2, 3, 4, 5, 6]

    def test_every_step_is_attributed_to_vanguard(self, agent, alert_data, context, model_result):
        chain = agent.generate_chain_of_thought(alert_data, context, model_result)
        assert all(step["agent"] == "vanguard" for step in chain)

    def test_evidentiary_steps_have_observation_and_inference(self, agent, alert_data, context, model_result):
        chain = agent.generate_chain_of_thought(alert_data, context, model_result)
        for step in chain[:5]:
            assert "observation" in step and step["observation"]
            assert "inference"   in step and step["inference"]

    def test_final_step_has_conclusion_and_action(self, agent, alert_data, context, model_result):
        chain = agent.generate_chain_of_thought(alert_data, context, model_result)
        final = chain[-1]
        assert "conclusion" in final and final["conclusion"]
        assert "action"     in final and final["action"]
        assert "observation" not in final

    def test_first_step_observation_references_alert(self, agent, alert_data, context, model_result):
        chain = agent.generate_chain_of_thought(alert_data, context, model_result)
        assert "RANSOMWARE_POWERSHELL_ENCODED" in chain[0]["observation"]
        assert "DESKTOP-ABC123" in chain[0]["observation"]

    def test_asset_step_reflects_criticality_from_context(self, agent, alert_data, context, model_result):
        chain = agent.generate_chain_of_thought(alert_data, context, model_result)
        asset_step = chain[2]
        assert "CRITICAL" in asset_step["observation"]
        assert "1.5" in asset_step["inference"] or "1.50" in asset_step["inference"]

    def test_conclusion_reflects_auto_escalate_decision(self, agent, alert_data, context, model_result):
        chain = agent.generate_chain_of_thought(alert_data, context, model_result)
        final = chain[-1]
        assert "97" in final["conclusion"]
        assert "AUTO_ESCALATE" in final["conclusion"]
        assert "Sherlock" in final["action"]

    def test_conclusion_action_changes_with_decision(self, agent, alert_data, context):
        dismiss_result = {
            "classification": "ANOMALOUS_BEHAVIOR", "confidence": 0.3,
            "model_used": "fallback", "model_available": False,
            "composite_score": 8, "decision": Decision.AUTO_DISMISS,
        }
        chain = agent.generate_chain_of_thought(alert_data, context, dismiss_result)
        final = chain[-1]
        assert "dismiss" in final["action"].lower() or "close" in final["action"].lower()

    def test_does_not_mutate_inputs(self, agent, alert_data, context, model_result):
        alert_copy, ctx_copy, model_copy = dict(alert_data), dict(context), dict(model_result)
        agent.generate_chain_of_thought(alert_data, context, model_result)
        assert alert_data == alert_copy
        assert context == ctx_copy
        assert model_result == model_copy


class TestVanguardSummarizeChainOfThought:
    def test_empty_chain_returns_empty_string(self):
        assert VanguardAgent._summarize_chain_of_thought([]) == ""

    def test_summary_includes_inferences_and_conclusion(self):
        chain = [
            {"step": 1, "agent": "vanguard", "observation": "obs1", "inference": "inference one"},
            {"step": 2, "agent": "vanguard", "observation": "obs2", "inference": "inference two"},
            {"step": 3, "agent": "vanguard", "conclusion": "final conclusion", "action": "do thing"},
        ]
        summary = VanguardAgent._summarize_chain_of_thought(chain)
        assert "inference one" in summary
        assert "inference two" in summary
        assert "final conclusion" in summary

    def test_summary_is_a_single_string(self):
        chain = [{"step": 1, "agent": "vanguard", "observation": "o", "inference": "i"}]
        assert isinstance(VanguardAgent._summarize_chain_of_thought(chain), str)


# ---------------------------------------------------------------------------
# SherlockAgent.build_investigation_chain
# ---------------------------------------------------------------------------

class TestSherlockInvestigationChain:
    @pytest.fixture
    def agent(self):
        return _make_sherlock_agent()

    @pytest.fixture
    def ctx(self):
        ctx = _make_investigation_context()
        ctx.all_hosts       = ["desktop-abc123", "fileserver01"]
        ctx.all_users       = ["corp\\jdoe"]
        ctx.all_iocs        = [{"value": "185.220.101.42", "type": "ip", "verdict": "malicious"}]
        ctx.queries_executed = 12
        ctx.mcp_calls        = 4
        ctx.data_sources     = ["edr", "network", "identity"]
        return ctx

    @pytest.fixture
    def phase_results(self):
        return {
            "A": _make_phase_result("A", key_findings=["Asset criticality: CRITICAL", "LOLBin execution: certutil.exe"]),
            "B": _make_phase_result("B", key_findings=["Ransomware-pattern extension: C:\\docs\\report.locked"]),
            "C": _make_phase_result("C", status="partial", key_findings=["SMB connections to FILESERVER01"]),
            "D": _make_phase_result("D", status="skipped", key_findings=[], evidence_gaps=["No identity data source available."]),
            "E": _make_phase_result("E", status="failed", key_findings=[], error="SAIA timeout"),
        }

    def test_returns_one_entry_per_phase_plus_synthesis(self, agent, ctx, phase_results):
        chain = agent.build_investigation_chain(ctx, phase_results)
        assert len(chain) == len(phase_results) + 1

    def test_steps_are_sequentially_numbered(self, agent, ctx, phase_results):
        chain = agent.build_investigation_chain(ctx, phase_results)
        assert [entry["step"] for entry in chain] == list(range(1, len(chain) + 1))

    def test_phase_entries_have_required_keys(self, agent, ctx, phase_results):
        chain = agent.build_investigation_chain(ctx, phase_results)
        for entry in chain[:-1]:
            for key in ("step", "phase", "name", "query", "result", "inference"):
                assert key in entry
                assert entry[key]

    def test_phase_entries_match_phase_order(self, agent, ctx, phase_results):
        chain = agent.build_investigation_chain(ctx, phase_results)
        assert [entry["phase"] for entry in chain[:-1]] == ["A", "B", "C", "D", "E"]

    def test_skipped_phase_inference_mentions_skip(self, agent, ctx, phase_results):
        chain = agent.build_investigation_chain(ctx, phase_results)
        d_entry = next(e for e in chain if e["phase"] == "D")
        assert "skip" in d_entry["inference"].lower() or "could not run" in d_entry["inference"].lower()

    def test_failed_phase_inference_mentions_failure(self, agent, ctx, phase_results):
        chain = agent.build_investigation_chain(ctx, phase_results)
        e_entry = next(e for e in chain if e["phase"] == "E")
        assert "fail" in e_entry["inference"].lower()

    def test_phase_with_findings_inference_cites_top_finding(self, agent, ctx, phase_results):
        chain = agent.build_investigation_chain(ctx, phase_results)
        a_entry = next(e for e in chain if e["phase"] == "A")
        assert "Asset criticality: CRITICAL" in a_entry["inference"]

    def test_final_step_is_synthesis_with_conclusion_and_action(self, agent, ctx, phase_results):
        chain = agent.build_investigation_chain(ctx, phase_results)
        synthesis = chain[-1]
        assert synthesis["phase"] == "SYNTHESIS"
        assert "conclusion" in synthesis and synthesis["conclusion"]
        assert "action" in synthesis and synthesis["action"]

    def test_synthesis_result_reflects_context_aggregates(self, agent, ctx, phase_results):
        chain = agent.build_investigation_chain(ctx, phase_results)
        synthesis = chain[-1]
        assert "185.220.101.42" not in synthesis["query"]   # query describes aggregation, not raw IOC
        assert "iocs_discovered=1" in synthesis["result"]

    def test_empty_phase_results_returns_empty_chain(self, agent, ctx):
        assert agent.build_investigation_chain(ctx, {}) == []

    def test_does_not_mutate_phase_results_or_context(self, agent, ctx, phase_results):
        findings_before = {p: list(r.key_findings) for p, r in phase_results.items()}
        hosts_before    = list(ctx.all_hosts)
        agent.build_investigation_chain(ctx, phase_results)
        for phase, result in phase_results.items():
            assert result.key_findings == findings_before[phase]
        assert ctx.all_hosts == hosts_before


# ---------------------------------------------------------------------------
# ExecutorAgent.build_action_chain
# ---------------------------------------------------------------------------

class TestExecutorActionChain:
    @pytest.fixture
    def agent(self):
        return _make_executor_agent()

    def test_returns_one_entry_per_action(self, agent):
        actions = [
            _make_action_result("isolate_host"),
            _make_action_result("block_ip", target="185.220.101.42"),
        ]
        chain = agent.build_action_chain(actions, ExecutorMode.FULL_AUTONOMY, risk_score=97)
        assert len(chain) == 2

    def test_sequence_numbers_start_at_one(self, agent):
        actions = [_make_action_result("isolate_host"), _make_action_result("block_ip"), _make_action_result("disable_user")]
        chain = agent.build_action_chain(actions, ExecutorMode.FULL_AUTONOMY, risk_score=97)
        assert [entry["sequence"] for entry in chain] == [1, 2, 3]

    def test_entries_have_required_keys(self, agent):
        actions = [_make_action_result("isolate_host")]
        chain = agent.build_action_chain(actions, ExecutorMode.FULL_AUTONOMY, risk_score=97)
        entry = chain[0]
        for key in (
            "sequence", "action", "target", "justification", "risk_matrix",
            "pre_state", "post_state", "verification_query", "verification_result",
            "rollback_timer", "human_notified",
        ):
            assert key in entry

    def test_entry_reflects_action_result_fields(self, agent):
        actions = [_make_action_result("isolate_host", target="DESKTOP-ABC123",
                                        pre_state="connected", post_state="isolated",
                                        justification="Confirmed ransomware execution")]
        chain = agent.build_action_chain(actions, ExecutorMode.FULL_AUTONOMY, risk_score=97)
        entry = chain[0]
        assert entry["action"]        == "isolate_host"
        assert entry["target"]        == "DESKTOP-ABC123"
        assert entry["pre_state"]     == "connected"
        assert entry["post_state"]    == "isolated"
        assert entry["justification"] == "Confirmed ransomware execution"
        assert entry["rollback_timer"] == 14400
        assert entry["human_notified"] is True

    def test_verified_action_reports_verified_result(self, agent):
        actions = [_make_action_result("isolate_host", verified=True)]
        chain = agent.build_action_chain(actions, ExecutorMode.FULL_AUTONOMY, risk_score=97)
        assert chain[0]["verification_result"] == "VERIFIED"

    def test_unverified_successful_action_reports_unverified(self, agent):
        actions = [_make_action_result("isolate_host", verified=False, status=ActionStatus.SUCCESS.value)]
        chain = agent.build_action_chain(actions, ExecutorMode.FULL_AUTONOMY, risk_score=97)
        assert chain[0]["verification_result"] == "EXECUTED_UNVERIFIED"

    def test_skipped_action_reports_not_executed(self, agent):
        actions = [_make_action_result("disable_user", status=ActionStatus.SKIPPED.value, verified=False)]
        chain = agent.build_action_chain(actions, ExecutorMode.CONTAINMENT_ONLY, risk_score=72)
        assert chain[0]["verification_result"] == "NOT_EXECUTED"

    def test_risk_matrix_includes_mode_and_score(self, agent):
        actions = [_make_action_result("isolate_host")]
        chain = agent.build_action_chain(actions, ExecutorMode.FULL_AUTONOMY, risk_score=97)
        matrix = chain[0]["risk_matrix"]
        assert matrix["executor_mode"]   == "FULL_AUTONOMY"
        assert matrix["case_risk_score"] == 97
        assert matrix["action_class"]    == "containment"

    def test_eradication_action_classified_correctly(self, agent):
        actions = [_make_action_result("disable_user", target="CORP\\jdoe")]
        chain = agent.build_action_chain(actions, ExecutorMode.FULL_AUTONOMY, risk_score=97)
        assert chain[0]["risk_matrix"]["action_class"] == "eradication"

    def test_eradication_under_containment_only_requires_manager_approval(self, agent):
        actions = [_make_action_result("disable_user", status=ActionStatus.SKIPPED.value, verified=False,
                                        justification="Eradication requires approval")]
        chain = agent.build_action_chain(
            actions, ExecutorMode.CONTAINMENT_ONLY, risk_score=72,
            requires_approval=True, approval_granted=False,
        )
        assert chain[0].get("requires_manager_approval") is True

    def test_no_approval_flag_when_approval_already_granted(self, agent):
        actions = [_make_action_result("disable_user")]
        chain = agent.build_action_chain(
            actions, ExecutorMode.CONTAINMENT_ONLY, risk_score=72,
            requires_approval=True, approval_granted=True,
        )
        assert "requires_manager_approval" not in chain[0]

    def test_no_approval_flag_for_containment_actions(self, agent):
        actions = [_make_action_result("isolate_host")]
        chain = agent.build_action_chain(
            actions, ExecutorMode.CONTAINMENT_ONLY, risk_score=72,
            requires_approval=True, approval_granted=False,
        )
        assert "requires_manager_approval" not in chain[0]

    def test_empty_actions_returns_empty_chain(self, agent):
        assert agent.build_action_chain([], ExecutorMode.FULL_AUTONOMY, risk_score=97) == []

    def test_does_not_mutate_action_results(self, agent):
        action = _make_action_result("isolate_host")
        snapshot = action.to_dict()
        agent.build_action_chain([action], ExecutorMode.FULL_AUTONOMY, risk_score=97)
        assert action.to_dict() == snapshot


# ---------------------------------------------------------------------------
# AuditLogger.log_chain_of_thought
# ---------------------------------------------------------------------------

class TestAuditLoggerChainOfThought:
    @pytest.fixture
    def logger(self):
        with patch.object(AuditLogger, "_sender", None):
            return AuditLogger(agent_name="vanguard", hec_token="test-token")

    def test_emits_chain_of_thought_event(self, logger):
        chain = [
            {"step": 1, "agent": "vanguard", "observation": "o1", "inference": "i1"},
            {"step": 2, "agent": "vanguard", "conclusion": "c", "action": "a"},
        ]
        with patch.object(logger, "_emit") as mock_emit:
            logger.log_chain_of_thought(case_id="SEN-001", agent_name="vanguard", chain=chain)

        mock_emit.assert_called_once()
        event = mock_emit.call_args[0][0]
        assert event["event_type"] == "chain_of_thought"
        assert event["case_id"]    == "SEN-001"
        assert event["agent_name"] == "vanguard"
        assert event["step_count"] == 2
        assert event["chain"]      == chain

    def test_chain_is_stored_verbatim(self, logger):
        chain = [{"step": 1, "agent": "sherlock", "phase": "A", "name": "Host Context",
                  "query": "...", "result": "...", "inference": "..."}]
        with patch.object(logger, "_emit") as mock_emit:
            logger.log_chain_of_thought(case_id="SEN-002", agent_name="sherlock", chain=chain)

        event = mock_emit.call_args[0][0]
        assert event["chain"] is chain or event["chain"] == chain

    def test_metadata_defaults_to_empty_dict(self, logger):
        with patch.object(logger, "_emit") as mock_emit:
            logger.log_chain_of_thought(case_id="SEN-003", agent_name="executor", chain=[])

        event = mock_emit.call_args[0][0]
        assert event["metadata"] == {}
        assert event["step_count"] == 0

    def test_base_event_includes_timestamp(self):
        event = _base_event("chain_of_thought", case_id="SEN-004", agent_name="vanguard", chain=[], step_count=0)
        assert "timestamp" in event
        assert isinstance(event["timestamp"], int)
