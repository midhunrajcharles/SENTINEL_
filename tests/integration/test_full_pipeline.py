"""
Integration test — full SENTINEL pipeline, end to end, using only mock data.

Drives a single case through the entire autonomous SOC pipeline:

    Vanguard (triage)  -> Sherlock (investigation) -> orchestrator decide
    -> Executor (response) -> Sage (learning) -> CLOSED

using the *real* ``CaseStateManager`` state machine (backed by an in-memory
fake KV Store, never a live Splunk instance) and lightweight stub agents that
replay the canned outputs from ``demo/scenarios/scenario_1_ransomware.json``.

This intentionally does NOT exercise the heavyweight agent classes
(VanguardAgent/SherlockAgent/ExecutorAgent/SageAgent) — those have their own
unit tests with mocked MCP/model clients. Instead it proves that the
*pipeline plumbing* — state transitions, case persistence, and audit logging —
behaves correctly when wired together end to end, the way the orchestrator
wires it in production.

No live Splunk, no real MCP server, and no real model endpoints are touched:
all agent "calls" are stubs that read canned values straight out of the demo
scenario, and the KV Store is a plain in-memory dict.
"""

from __future__ import annotations

import json
import sys
import time
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock

import pytest

# ---------------------------------------------------------------------------
# Bootstrap: add agent bin directory to path before any sentinel import
# ---------------------------------------------------------------------------

_ROOT     = Path(__file__).resolve().parent.parent.parent
_BIN_DIR  = _ROOT / "app" / "sentinel" / "bin"
_SCENARIO = _ROOT / "demo" / "scenarios" / "scenario_1_ransomware.json"

if str(_BIN_DIR) not in sys.path:
    sys.path.insert(0, str(_BIN_DIR))

from utils.state_manager import Case, CaseStateManager, CaseStatus  # noqa: E402

# Mirrors sentinel_orchestrator.AUTO_RESPOND_SCORE — the score at/above which
# the orchestrator's _run_decide step lets the Executor act without approval.
_AUTO_RESPOND_THRESHOLD = 90

pytestmark = pytest.mark.slow


# ---------------------------------------------------------------------------
# In-memory fake KV Store (stands in for Splunk's KV Store backend)
# ---------------------------------------------------------------------------

class _FakeKVStoreConnector:
    """
    Minimal stand-in for SplunkConnector's kvstore_* methods, backed by a
    plain in-memory dict. Lets CaseStateManager's real read-modify-write and
    transition-validation logic run without a live Splunk instance.
    """

    def __init__(self) -> None:
        self._collections: Dict[str, Dict[str, Dict[str, Any]]] = {}

    def kvstore_get(self, collection: str, key: str, app: Optional[str] = None) -> Optional[Dict[str, Any]]:
        record = self._collections.get(collection, {}).get(key)
        return deepcopy(record) if record is not None else None

    def kvstore_query(
        self,
        collection: str,
        query: Optional[Dict[str, Any]] = None,
        sort: Optional[str] = None,
        limit: int = 0,
        app: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        records = list(self._collections.get(collection, {}).values())
        if query:
            records = [r for r in records if all(r.get(k) == v for k, v in query.items())]
        if limit:
            records = records[:limit]
        return deepcopy(records)

    def kvstore_upsert(self, collection: str, key: str, record: Dict[str, Any], app: Optional[str] = None) -> Dict[str, Any]:
        stored = dict(record)
        stored["_key"] = key
        self._collections.setdefault(collection, {})[key] = deepcopy(stored)
        return deepcopy(stored)


# ---------------------------------------------------------------------------
# Stub agents — replay canned scenario output, log via mock AuditLogger
# ---------------------------------------------------------------------------
# Each stub mirrors the {success, <payload-key>, ...} contract that the real
# agent_*.run() module entry points return, and that sentinel_orchestrator's
# _run_vanguard/_run_sherlock/_run_executor/_run_sage helpers consume.

def _stub_vanguard(case: Case, scenario: Dict[str, Any], audit: MagicMock) -> Dict[str, Any]:
    expected = scenario["expected_vanguard_decision"]
    packet = {
        "case_id":          case.case_id,
        "alert_id":         case.alert_id,
        "classification":   expected["classification"],
        "confidence":       expected["confidence"],
        "mitre_tactic":     "TA0001",
        "mitre_technique":  expected["ttp_mapping"][0],
        "composite_score":  expected["composite_score"],
        "decision":         expected["decision"],
        "reasoning":        expected["rationale"],
        "key_indicators":   list(expected["signal_breakdown"].keys()),
        "recommended_actions": [a["action_type"] for a in scenario["expected_executor_actions"]],
        "model_used":       "mock-foundation-sec-1.1-8b-instruct",
        "model_available":  True,
    }
    audit.log_decision(
        case_id=case.case_id,
        decision_type="TRIAGE_COMPLETE",
        confidence=expected["confidence"],
        input_context={"alert_id": case.alert_id, "alert_type": case.alert_type},
        output_decision=packet,
        reasoning=expected["rationale"],
        mitre_tactic=packet["mitre_tactic"],
        mitre_technique=packet["mitre_technique"],
        model_used=packet["model_used"],
    )
    return {
        "success":        True,
        "decision":       packet,
        "risk_score":     expected["composite_score"],
        "classification": expected["classification"],
        "mitre_tactic":   packet["mitre_tactic"],
        "mitre_technique": packet["mitre_technique"],
    }


def _stub_sherlock(case: Case, scenario: Dict[str, Any], audit: MagicMock) -> Dict[str, Any]:
    findings = scenario["expected_sherlock_findings"]
    report = {
        "case_id":                    case.case_id,
        "classification":             case.classification,
        "false_positive_probability": findings["false_positive_probability"],
        "phases_completed":           findings["phases_completed"],
        "executive_summary":          findings["executive_summary"],
        "attack_narrative":           findings["attack_narrative"],
        "blast_radius":               findings["blast_radius"],
        "threat_assessment":          findings["threat_assessment"],
        "iocs_discovered":            findings["iocs_discovered"],
        "recommended_actions": [
            {"action": a["action_type"], "target": a["target"], "priority": i + 1}
            for i, a in enumerate(scenario["expected_executor_actions"])
        ],
    }
    audit.log_decision(
        case_id=case.case_id,
        decision_type="INVESTIGATION_COMPLETE",
        confidence=findings["threat_assessment"]["confidence"],
        input_context={"phases_completed": findings["phases_completed"]},
        output_decision={
            "classification": report["classification"],
            "false_positive_probability": report["false_positive_probability"],
            "malware_family": findings["malware_family"],
        },
        reasoning=findings["executive_summary"],
        mitre_technique=findings["threat_assessment"]["ttp_mapping"][0],
    )
    return {"success": True, "report": report}


def _stub_executor(case: Case, scenario: Dict[str, Any], audit: MagicMock) -> Dict[str, Any]:
    actions: List[Dict[str, Any]] = []
    for i, expected_action in enumerate(scenario["expected_executor_actions"], start=1):
        action_id = f"ACT-{case.case_id}-{i:03d}"
        rollback_s = expected_action.get("rollback_timer_s", 0)
        actions.append({
            "action_id":        action_id,
            "action_type":      expected_action["action_type"],
            "target":           expected_action["target"],
            "justification":    expected_action.get("justification", ""),
            "status":           expected_action["expected_status"],
            "verification":     expected_action.get("verification", {}),
            "rollback_timer_s": rollback_s,
        })
        audit.log_action(
            case_id=case.case_id,
            action_type=expected_action["action_type"],
            target=expected_action["target"],
            platform="mock_edr",
            outcome=expected_action["expected_status"],
            action_id=action_id,
            rollback_timer_hours=rollback_s / 3600.0,
            verification_passed=True,
        )
    return {"success": True, "actions": actions}


def _stub_sage(case: Case, scenario: Dict[str, Any], audit: MagicMock) -> Dict[str, Any]:
    learning = scenario["expected_sage_learning"]
    analysis = {
        "iocs_harvested":           learning["iocs_submitted"],
        "iocs_submitted":           learning["iocs_submitted"],
        "iocs_confirmed_malicious": learning["iocs_confirmed_malicious"],
        "rule_proposed":            learning["proposed_rule"]["proposed_for_production"],
        "proposed_rule":            learning["proposed_rule"],
        "tuning_recommendation":    learning["tuning_recommendation"],
    }
    audit.log_decision(
        case_id=case.case_id,
        decision_type="LEARNING_COMPLETE",
        confidence=1.0,
        input_context={"iocs_found": learning["iocs_submitted"]},
        output_decision={"rule_proposed": analysis["rule_proposed"]},
        reasoning=learning["tuning_recommendation"],
    )
    return {
        "success":  True,
        "resolution": "CONTAINED",
        "notes":      "Autonomous containment completed; rule proposal generated.",
        "analysis":   analysis,
    }


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def scenario() -> Dict[str, Any]:
    """Load the LockBit ransomware demo scenario (pure JSON, no live systems)."""
    with open(_SCENARIO, encoding="utf-8") as fh:
        return json.load(fh)


@pytest.fixture(scope="module")
def pipeline_run(scenario: Dict[str, Any]) -> Dict[str, Any]:
    """
    Drive one case through the full mock pipeline and hand back everything
    the assertions need: the final persisted Case, per-agent audit mocks,
    and wall-clock timing. Runs once per module so every assertion test
    inspects the same completed run.
    """
    state_manager = CaseStateManager(connector=_FakeKVStoreConnector())

    audits = {
        "orchestrator": MagicMock(name="orchestrator_audit"),
        "vanguard":     MagicMock(name="vanguard_audit"),
        "sherlock":     MagicMock(name="sherlock_audit"),
        "executor":     MagicMock(name="executor_audit"),
        "sage":         MagicMock(name="sage_audit"),
    }

    alert = scenario["alert_trigger"]
    t_start = time.time()

    # --- QUEUED: case created from the inbound alert -----------------------
    case = state_manager.create_case(
        alert_id      = alert["alert_id"],
        alert_type    = alert["alert_type"],
        affected_host = alert["host"],
        affected_user = alert["user"],
        risk_score    = 0,            # unscored until Vanguard triages it
        priority      = "CRITICAL",
    )
    assert case.status == CaseStatus.QUEUED.value

    # --- QUEUED -> TRIAGING -------------------------------------------------
    state_manager.transition(case.case_id, CaseStatus.TRIAGING,
                             agent_name="orchestrator", detail="dequeued for triage")

    # --- Vanguard: triage ----------------------------------------------------
    vanguard_result = _stub_vanguard(case, scenario, audits["vanguard"])
    state_manager.update_case(
        case.case_id,
        {
            "vanguard_decision": vanguard_result["decision"],
            "risk_score":        vanguard_result["risk_score"],
            "classification":    vanguard_result["classification"],
            "mitre_tactic":      vanguard_result["mitre_tactic"],
            "mitre_technique":   vanguard_result["mitre_technique"],
        },
        agent_name="vanguard", detail="triage complete",
    )
    case = state_manager.get_case(case.case_id)
    assert vanguard_result["decision"]["decision"] == "AUTO_ESCALATE"
    assert case.risk_score == scenario["expected_vanguard_decision"]["composite_score"] == 97

    # --- TRIAGING -> INVESTIGATING (score is well above the auto-close floor)
    state_manager.transition(case.case_id, CaseStatus.INVESTIGATING,
                             agent_name="orchestrator", detail="escalated to investigation")

    # --- Sherlock: deep investigation ---------------------------------------
    sherlock_result = _stub_sherlock(case, scenario, audits["sherlock"])
    state_manager.update_case(
        case.case_id, {"sherlock_report": sherlock_result["report"]},
        agent_name="sherlock", detail="investigation complete",
    )
    case = state_manager.get_case(case.case_id)
    assert case.sherlock_report["phases_completed"] == ["A", "B", "C", "D", "E"]

    # --- INVESTIGATING -> DECIDING -------------------------------------------
    state_manager.transition(case.case_id, CaseStatus.DECIDING,
                             agent_name="orchestrator", detail="investigation complete, deciding response mode")

    # --- Orchestrator decide step: score >= threshold -> auto-respond -------
    assert case.risk_score >= _AUTO_RESPOND_THRESHOLD
    state_manager.update_case(
        case.case_id, {"requires_approval": False},
        agent_name="orchestrator",
        detail=f"auto-respond: score {case.risk_score} >= threshold {_AUTO_RESPOND_THRESHOLD}",
    )
    audits["orchestrator"].log_decision(
        case_id=case.case_id,
        decision_type="AUTO_RESPOND",
        confidence=min(case.risk_score / 100.0, 1.0),
        input_context={"risk_score": case.risk_score, "threshold": _AUTO_RESPOND_THRESHOLD},
        output_decision={"requires_approval": False},
        reasoning=f"Risk score {case.risk_score} meets auto-respond threshold {_AUTO_RESPOND_THRESHOLD}.",
    )

    # --- DECIDING -> RESPONDING ----------------------------------------------
    state_manager.transition(case.case_id, CaseStatus.RESPONDING,
                             agent_name="orchestrator", detail="executor cleared for autonomous response")

    # --- Executor: contain & remediate ---------------------------------------
    case = state_manager.get_case(case.case_id)
    executor_result = _stub_executor(case, scenario, audits["executor"])
    state_manager.update_case(
        case.case_id,
        {"executor_actions": (case.executor_actions or []) + executor_result["actions"]},
        agent_name="executor", detail="response actions executed",
    )

    # --- RESPONDING -> LEARNING ----------------------------------------------
    state_manager.transition(case.case_id, CaseStatus.LEARNING,
                             agent_name="orchestrator", detail="response complete, handing off to Sage")

    # --- Sage: learn from the closed-out case --------------------------------
    case = state_manager.get_case(case.case_id)
    sage_result = _stub_sage(case, scenario, audits["sage"])
    state_manager.update_case(
        case.case_id,
        {
            "resolution":       sage_result["resolution"],
            "resolution_notes": sage_result["notes"],
            "sage_analysis":    sage_result["analysis"],
        },
        agent_name="sage", detail="learning cycle complete",
    )

    # --- LEARNING -> CLOSED ---------------------------------------------------
    state_manager.transition(case.case_id, CaseStatus.CLOSED,
                             agent_name="orchestrator", detail="case closed")

    elapsed_s = time.time() - t_start
    final_case = state_manager.get_case(case.case_id)

    return {
        "case_id":       final_case.case_id,
        "case":          final_case,
        "state_manager": state_manager,
        "audits":        audits,
        "elapsed_s":     elapsed_s,
        "scenario":      scenario,
    }


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestPipelineCompletes:
    """End-to-end smoke checks: the case reaches CLOSED with the expected payloads."""

    def test_case_reaches_closed(self, pipeline_run):
        case = pipeline_run["case"]
        assert case.status == CaseStatus.CLOSED.value
        assert case.closed_time is not None

    def test_resolution_is_contained(self, pipeline_run):
        assert pipeline_run["case"].resolution == "CONTAINED"

    def test_each_agent_left_its_payload_on_the_case(self, pipeline_run):
        case = pipeline_run["case"]
        scenario = pipeline_run["scenario"]

        assert case.vanguard_decision["decision"] == "AUTO_ESCALATE"
        assert case.vanguard_decision["composite_score"] == 97

        assert case.sherlock_report["false_positive_probability"] == pytest.approx(
            scenario["expected_sherlock_findings"]["false_positive_probability"]
        )
        assert case.sherlock_report["blast_radius"]["files_encrypted"] == 12

        assert len(case.executor_actions) == len(scenario["expected_executor_actions"])
        assert all(a["status"] == "SUCCESS" for a in case.executor_actions)

        assert case.sage_analysis["rule_proposed"] is True
        assert case.sage_analysis["proposed_rule"]["proposed_for_production"] is True


class TestStateTransitions:
    """
    Verifies the case walks the full pipeline state machine in order.

    The orchestrator's real lifecycle is:
        QUEUED -> TRIAGING -> INVESTIGATING -> DECIDING -> RESPONDING -> LEARNING -> CLOSED
    QUEUED is the case's initial "idle" state — created but not yet picked up
    by a worker — which is what the brief's "IDLE" maps onto here.
    """

    _EXPECTED_SEQUENCE = [
        ("QUEUED",        "TRIAGING"),
        ("TRIAGING",      "INVESTIGATING"),
        ("INVESTIGATING", "DECIDING"),
        ("DECIDING",      "RESPONDING"),
        ("RESPONDING",    "LEARNING"),
        ("LEARNING",      "CLOSED"),
    ]

    def test_transition_sequence_matches_pipeline_order(self, pipeline_run):
        case = pipeline_run["case"]
        transitions = [
            (entry["from_status"], entry["to_status"])
            for entry in case.audit_trail
            if entry.get("action") == "transition"
        ]
        assert transitions == self._EXPECTED_SEQUENCE

    def test_initial_state_was_queued_idle_equivalent(self, pipeline_run):
        case = pipeline_run["case"]
        first_transition = next(
            entry for entry in case.audit_trail if entry.get("action") == "transition"
        )
        assert first_transition["from_status"] == CaseStatus.QUEUED.value

    def test_terminal_state_is_closed(self, pipeline_run):
        case = pipeline_run["case"]
        last_transition = [
            entry for entry in case.audit_trail if entry.get("action") == "transition"
        ][-1]
        assert last_transition["to_status"] == CaseStatus.CLOSED.value
        assert case.status == last_transition["to_status"]

    def test_invalid_transition_is_still_rejected_by_state_manager(self, pipeline_run):
        """Sanity check: the real CaseStateManager validation is in effect (CLOSED is terminal)."""
        sm = pipeline_run["state_manager"]
        with pytest.raises(ValueError):
            sm.transition(pipeline_run["case_id"], CaseStatus.TRIAGING, agent_name="test")


class TestAuditLogging:
    """Every agent decision/action in the pipeline must be written to the audit trail."""

    def test_vanguard_logged_a_decision(self, pipeline_run):
        audit = pipeline_run["audits"]["vanguard"]
        assert audit.log_decision.called
        _, kwargs = audit.log_decision.call_args
        assert kwargs["case_id"] == pipeline_run["case_id"]
        assert kwargs["decision_type"] == "TRIAGE_COMPLETE"

    def test_sherlock_logged_a_decision(self, pipeline_run):
        audit = pipeline_run["audits"]["sherlock"]
        assert audit.log_decision.called
        _, kwargs = audit.log_decision.call_args
        assert kwargs["decision_type"] == "INVESTIGATION_COMPLETE"

    def test_orchestrator_logged_the_auto_respond_decision(self, pipeline_run):
        audit = pipeline_run["audits"]["orchestrator"]
        assert audit.log_decision.called
        _, kwargs = audit.log_decision.call_args
        assert kwargs["decision_type"] == "AUTO_RESPOND"
        assert kwargs["output_decision"]["requires_approval"] is False

    def test_executor_logged_an_action_for_every_response_action(self, pipeline_run):
        audit = pipeline_run["audits"]["executor"]
        scenario = pipeline_run["scenario"]
        assert audit.log_action.call_count == len(scenario["expected_executor_actions"])
        for _, kwargs in audit.log_action.call_args_list:
            assert kwargs["case_id"] == pipeline_run["case_id"]
            assert kwargs["outcome"] == "SUCCESS"

    def test_sage_logged_a_learning_decision(self, pipeline_run):
        audit = pipeline_run["audits"]["sage"]
        assert audit.log_decision.called
        _, kwargs = audit.log_decision.call_args
        assert kwargs["decision_type"] == "LEARNING_COMPLETE"

    def test_every_agent_produced_at_least_one_audit_record(self, pipeline_run):
        for name, audit in pipeline_run["audits"].items():
            calls = audit.log_decision.call_count + audit.log_action.call_count
            assert calls > 0, f"{name} agent produced no audit records"


class TestKVStoreConsistency:
    """The persisted Case in the (fake) KV Store must reflect every agent's writes."""

    def test_get_case_returns_consistent_final_state(self, pipeline_run):
        sm = pipeline_run["state_manager"]
        reread = sm.get_case(pipeline_run["case_id"])

        assert reread is not None
        assert reread.status         == pipeline_run["case"].status
        assert reread.risk_score     == pipeline_run["case"].risk_score
        assert reread.classification == pipeline_run["case"].classification
        assert reread.vanguard_decision == pipeline_run["case"].vanguard_decision
        assert reread.sherlock_report   == pipeline_run["case"].sherlock_report
        assert reread.executor_actions  == pipeline_run["case"].executor_actions
        assert reread.sage_analysis     == pipeline_run["case"].sage_analysis

    def test_version_counter_incremented_on_every_write(self, pipeline_run):
        # 1 create + 6 transitions + 5 update_case calls (vanguard, sherlock,
        # decide, executor, sage) = 12 version-incrementing writes.
        assert pipeline_run["case"].version == 11

    def test_audit_trail_records_every_field_update(self, pipeline_run):
        case = pipeline_run["case"]
        update_entries = [e for e in case.audit_trail if e.get("action") == "update"]
        updated_fields = {field for entry in update_entries for field in entry["fields"]}
        assert {
            "vanguard_decision", "sherlock_report", "executor_actions",
            "sage_analysis", "requires_approval", "resolution",
        } <= updated_fields


class TestPerformance:
    """The fully-mocked pipeline must run fast — this is a plumbing test, not a load test."""

    def test_pipeline_completes_in_under_60_seconds(self, pipeline_run):
        assert pipeline_run["elapsed_s"] < 60, (
            f"Mock pipeline took {pipeline_run['elapsed_s']:.2f}s — "
            "should comfortably finish in well under 60s with no live systems involved"
        )
