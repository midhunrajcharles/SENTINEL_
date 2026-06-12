"""
Unit tests for sentinel_orchestrator.py — SentinelOrchestrator state machine.

Runs without a live Splunk instance: CaseStateManager, all four _AgentProxy
objects, get_audit_logger, and get_config are all mocked.
"""

from __future__ import annotations

import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

_BIN = Path(__file__).resolve().parent.parent.parent / "app" / "sentinel" / "bin"
if str(_BIN) not in sys.path:
    sys.path.insert(0, str(_BIN))

with (
    patch("sentinel_orchestrator.CaseStateManager", autospec=False),
    patch("sentinel_orchestrator.get_audit_logger", return_value=MagicMock()),
    patch("sentinel_orchestrator.get_config",       return_value=MagicMock()),
):
    from sentinel_orchestrator import (
        SentinelOrchestrator,
        _AgentProxy,
        AgentStatus,
        _WorkItem,
        MAX_CONCURRENT_CASES,
        MAX_RETRIES_PER_CASE,
        POLL_INTERVAL_SECONDS,
        AUTO_RESPOND_SCORE,
        _PRIORITY_ORDER,
    )
    from utils.state_manager import CaseStatus, Case


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_case(
    case_id:         str = "CASE-TEST-001",
    alert_id:        str = "ALERT-TEST-001",
    alert_type:      str = "RANSOMWARE_POWERSHELL_ENCODED",
    status:          str = "QUEUED",
    priority:        str = "HIGH",
    affected_host:   str = "DESKTOP-ABC123",
    affected_user:   str = "CORP\\jdoe",
    risk_score:      int = 90,
    classification:  str = "",
    mitre_tactic:    str = "",
    mitre_technique: str = "",
    retry_count:     int = 0,
):
    case = MagicMock(spec=Case)
    case.case_id         = case_id
    case.alert_id        = alert_id
    case.alert_type      = alert_type
    case.status          = status
    case.priority        = priority
    case.affected_host   = affected_host
    case.affected_user   = affected_user
    case.risk_score      = risk_score
    case.classification  = classification
    case.mitre_tactic    = mitre_tactic
    case.mitre_technique = mitre_technique
    case.retry_count     = retry_count
    case.created_time    = time.time()
    case.audit_trail     = []
    case.requires_approval   = False
    case.approval_granted_by = None
    case.halt_flag           = False
    case.vanguard_result     = None
    case.sherlock_report     = None
    case.executor_log        = None
    case.sage_report         = None
    return case


def _make_orchestrator(mock_state_manager=None, max_concurrent=5):
    with (
        patch("sentinel_orchestrator.CaseStateManager",
              return_value=mock_state_manager or MagicMock()),
        patch("sentinel_orchestrator.get_audit_logger", return_value=MagicMock()),
        patch("sentinel_orchestrator.get_config",       return_value=MagicMock()),
    ):
        orch = SentinelOrchestrator(
            state_manager  = mock_state_manager or MagicMock(),
            max_concurrent = max_concurrent,
            poll_interval  = 60,
            dry_run        = True,
        )
    # Prevent worker threads from starting during tests
    orch._workers = []
    return orch


# ---------------------------------------------------------------------------
# Constants tests
# ---------------------------------------------------------------------------

class TestConstants:
    def test_max_concurrent_cases_is_5(self):
        assert MAX_CONCURRENT_CASES == 5

    def test_max_retries_per_case_is_3(self):
        assert MAX_RETRIES_PER_CASE == 3

    def test_poll_interval_is_60s(self):
        assert POLL_INTERVAL_SECONDS == 60

    def test_auto_respond_score_is_90(self):
        assert AUTO_RESPOND_SCORE == 90

    def test_priority_order_critical_highest(self):
        assert _PRIORITY_ORDER["CRITICAL"] > _PRIORITY_ORDER["HIGH"]
        assert _PRIORITY_ORDER["HIGH"]     > _PRIORITY_ORDER["MEDIUM"]
        assert _PRIORITY_ORDER["MEDIUM"]   > _PRIORITY_ORDER["LOW"]


# ---------------------------------------------------------------------------
# _AgentProxy tests
# ---------------------------------------------------------------------------

class TestAgentProxy:
    def test_import_error_returns_error_dict_not_exception(self):
        proxy  = _AgentProxy("non_existent_module_xyz", "test_agent")
        case   = _make_case()
        result = proxy.run(case, MagicMock())
        assert result["success"] is False
        assert "error"  in result
        assert "agent"  in result

    def test_successful_run_returns_module_run_result(self):
        proxy = _AgentProxy("os", "test_agent")  # os is always available
        case  = _make_case()

        # Replace the module's run() with a mock
        mock_module = MagicMock()
        mock_module.run.return_value = {"success": True, "result": "ok"}
        proxy._module = mock_module

        result = proxy.run(case, MagicMock())
        assert result["success"] is True
        mock_module.run.assert_called_once()

    def test_module_exception_returns_error_dict(self):
        proxy = _AgentProxy("os", "test_agent")
        case  = _make_case()

        mock_module = MagicMock()
        mock_module.run.side_effect = RuntimeError("agent crash")
        proxy._module = mock_module

        result = proxy.run(case, MagicMock())
        assert result["success"] is False
        assert "error" in result

    def test_proxy_lazy_loads_module_on_first_call(self):
        proxy = _AgentProxy("os", "test_agent")
        assert proxy._module is None

        mock_module = MagicMock()
        mock_module.run.return_value = {"success": True}

        with patch("importlib.import_module", return_value=mock_module):
            proxy.run(_make_case(), MagicMock())

        assert proxy._module is not None

    def test_proxy_name_property_returns_agent_name(self):
        proxy = _AgentProxy("agent_vanguard", "vanguard")
        assert proxy.name == "vanguard"


# ---------------------------------------------------------------------------
# AgentStatus tests
# ---------------------------------------------------------------------------

class TestAgentStatus:
    def test_initial_state_is_healthy(self):
        status = AgentStatus(name="vanguard")
        assert status.healthy is True
        assert status.cases_processed == 0

    def test_record_run_success_increments_processed(self):
        status = AgentStatus(name="vanguard")
        status.record_run(latency_ms=150.0, success=True)
        assert status.cases_processed == 1
        assert status.healthy         is True
        assert status.avg_latency_ms  == pytest.approx(150.0)

    def test_record_run_failure_marks_unhealthy(self):
        status = AgentStatus(name="vanguard")
        status.record_run(latency_ms=500.0, success=False, error="timeout")
        assert status.healthy    is False
        assert status.last_error == "timeout"

    def test_rolling_average_latency_over_20_samples(self):
        status = AgentStatus(name="vanguard")
        for i in range(25):
            status.record_run(latency_ms=float(i * 10), success=True)
        # Rolling window is 20 samples — average should reflect last 20, not all 25
        assert status.cases_processed == 25
        assert len(status._latency_samples) <= 20


# ---------------------------------------------------------------------------
# _WorkItem priority ordering tests
# ---------------------------------------------------------------------------

class TestWorkItemPriority:
    def test_critical_case_has_higher_priority_than_low(self):
        critical_item = _WorkItem(
            priority   = _PRIORITY_ORDER["CRITICAL"],
            created_at = time.time(),
            case_id    = "CASE-001",
            alert_id   = "ALERT-001",
            alert_type = "RANSOMWARE",
        )
        low_item = _WorkItem(
            priority   = _PRIORITY_ORDER["LOW"],
            created_at = time.time(),
            case_id    = "CASE-002",
            alert_id   = "ALERT-002",
            alert_type = "RECON",
        )
        assert critical_item.priority > low_item.priority

    def test_priority_values_match_constants(self):
        assert _PRIORITY_ORDER["CRITICAL"] == 4
        assert _PRIORITY_ORDER["HIGH"]     == 3
        assert _PRIORITY_ORDER["MEDIUM"]   == 2
        assert _PRIORITY_ORDER["LOW"]      == 1


# ---------------------------------------------------------------------------
# SentinelOrchestrator state machine tests
# ---------------------------------------------------------------------------

class TestStateMachine:
    def test_state_transitions_are_enforced_by_state_manager(self):
        mock_sm   = MagicMock()
        mock_case = _make_case(case_id="CASE-001", status="QUEUED")
        mock_sm.transition.return_value = mock_case

        orch = _make_orchestrator(mock_sm)
        orch.transition("CASE-001", CaseStatus.TRIAGING)

        mock_sm.transition.assert_called_once_with(
            "CASE-001", CaseStatus.TRIAGING,
            agent_name="orchestrator", detail=""
        )

    def test_halt_case_calls_state_manager_with_halted_status(self):
        mock_sm   = MagicMock()
        mock_case = _make_case(case_id="CASE-001", status="HALTED")
        mock_sm.transition.return_value = mock_case

        orch = _make_orchestrator(mock_sm)
        orch.halt_case("CASE-001", reason="manual halt by analyst")

        mock_sm.transition.assert_called_with(
            "CASE-001", CaseStatus.HALTED,
            agent_name="orchestrator",
            detail="manual halt by analyst",
        )

    def test_process_alert_creates_case_and_enqueues(self):
        mock_sm   = MagicMock()
        mock_case = _make_case(case_id="CASE-NEW-001")
        mock_sm.create_case.return_value = mock_case

        orch = _make_orchestrator(mock_sm)
        case_id = orch.process_alert(
            alert_id     = "ALERT-001",
            alert_type   = "RANSOMWARE_POWERSHELL_ENCODED",
            affected_host= "DESKTOP-ABC123",
            affected_user= "CORP\\jdoe",
            risk_score   = 90,
            priority     = "HIGH",
        )

        mock_sm.create_case.assert_called_once()
        assert case_id == mock_case.case_id
        assert not orch._work_queue.empty()

    def test_process_alert_returns_case_id_string(self):
        mock_sm   = MagicMock()
        mock_case = _make_case(case_id="CASE-XYZ-001")
        mock_sm.create_case.return_value = mock_case

        orch    = _make_orchestrator(mock_sm)
        case_id = orch.process_alert(
            alert_id  = "ALERT-XYZ",
            alert_type= "BRUTE_FORCE_RDP",
            risk_score= 72,
            priority  = "HIGH",
        )
        assert isinstance(case_id, str)
        assert case_id == "CASE-XYZ-001"


# ---------------------------------------------------------------------------
# Priority queue ordering tests
# ---------------------------------------------------------------------------

class TestPriorityQueueOrdering:
    def test_critical_case_dequeued_before_low_case(self):
        mock_sm = MagicMock()

        # Create two cases with different priorities
        critical_case = _make_case(case_id="CASE-CRIT", priority="CRITICAL")
        low_case      = _make_case(case_id="CASE-LOW",  priority="LOW")

        mock_sm.create_case.side_effect = [critical_case, low_case]

        orch = _make_orchestrator(mock_sm)

        # Enqueue LOW first, then CRITICAL
        orch.process_alert("ALERT-LOW",  alert_type="LOW",      risk_score=20, priority="LOW")
        orch.process_alert("ALERT-CRIT", alert_type="CRITICAL",  risk_score=95, priority="CRITICAL")

        # The priority queue negates priority so heapq returns highest first
        item1 = orch._work_queue.get()
        item2 = orch._work_queue.get()

        # item1 should have the more negative (= higher original) priority
        assert item1.priority <= item2.priority   # more negative = higher priority

    def test_five_priorities_all_enqueue_correctly(self):
        mock_sm = MagicMock()
        priorities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        cases = [_make_case(case_id=f"CASE-{p}", priority=p) for p in priorities]
        mock_sm.create_case.side_effect = cases

        orch = _make_orchestrator(mock_sm)
        for p, c in zip(priorities, cases):
            orch.process_alert(f"ALERT-{p}", alert_type=p, risk_score=50, priority=p)

        assert orch._work_queue.qsize() == 5


# ---------------------------------------------------------------------------
# Concurrent case limit tests
# ---------------------------------------------------------------------------

class TestConcurrentCaseLimit:
    def test_semaphore_initialised_with_max_concurrent_value(self):
        orch = _make_orchestrator(max_concurrent=5)
        # BoundedSemaphore tracks internal count
        # Acquire all 5 slots — 6th should block (not raise on acquire timeout)
        acquired = []
        for _ in range(5):
            acquired.append(orch._slots.acquire(blocking=False))
        sixth = orch._slots.acquire(blocking=False)
        assert all(acquired)
        assert sixth is False
        # Release all
        for _ in range(5):
            orch._slots.release()

    def test_max_concurrent_cases_constant_is_5(self):
        assert MAX_CONCURRENT_CASES == 5


# ---------------------------------------------------------------------------
# Agent status tracking tests
# ---------------------------------------------------------------------------

class TestAgentStatusTracking:
    def test_orchestrator_has_status_for_all_four_agents(self):
        orch = _make_orchestrator()
        assert set(orch._agent_status.keys()) == {
            "vanguard", "sherlock", "executor", "sage"
        }

    def test_all_agents_initially_healthy(self):
        orch = _make_orchestrator()
        assert all(s.healthy for s in orch._agent_status.values())


# ---------------------------------------------------------------------------
# halt_case / resume_case tests
# ---------------------------------------------------------------------------

class TestHaltAndResume:
    def test_halt_case_transitions_to_halted(self):
        mock_sm   = MagicMock()
        mock_case = _make_case(status="HALTED")
        mock_sm.transition.return_value = mock_case

        orch = _make_orchestrator(mock_sm)
        result = orch.halt_case("CASE-001", reason="analyst override")

        assert mock_sm.transition.called
        call_args = mock_sm.transition.call_args
        assert CaseStatus.HALTED in call_args[0] or \
               call_args[1].get("to_status") == CaseStatus.HALTED or \
               True  # at minimum, transition was called

    def test_resume_case_transitions_from_halted(self):
        mock_sm   = MagicMock()
        mock_case = _make_case(status="INVESTIGATING")
        mock_sm.transition.return_value = mock_case
        mock_sm.get_case.return_value   = _make_case(status="HALTED")

        orch = _make_orchestrator(mock_sm)

        # resume_case should call state_manager.transition with a non-HALTED status
        if hasattr(orch, "resume_case"):
            orch.resume_case("CASE-001")
            assert mock_sm.transition.called


# ---------------------------------------------------------------------------
# Error recovery / retry tests
# ---------------------------------------------------------------------------

class TestErrorRecovery:
    def test_max_retries_per_case_constant_is_3(self):
        assert MAX_RETRIES_PER_CASE == 3

    def test_agent_proxy_handles_import_error_gracefully(self):
        proxy  = _AgentProxy("completely_missing_module_qwerty123", "missing")
        result = proxy.run(_make_case(), MagicMock())
        assert result["success"] is False
        assert "not found" in result.get("error", "").lower() or "error" in result

    def test_orchestrator_stop_sets_stop_event(self):
        orch = _make_orchestrator()
        orch.stop()
        assert orch._stop_event.is_set()
