"""
Unit tests for SENTINEL's fault-tolerance state machine: timeout-armed
transitions and retry tracking in utils.state_manager.CaseStateManager,
plus the orchestrator's watchdog / retry / dead-letter recovery pipeline.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch

import pytest

_BIN = Path(__file__).resolve().parent.parent.parent / "app" / "sentinel" / "bin"
if str(_BIN) not in sys.path:
    sys.path.insert(0, str(_BIN))

from utils.state_manager import CaseStateManager, CaseStatus, Case  # noqa: E402

with (
    patch("sentinel_orchestrator.CaseStateManager", autospec=False),
    patch("sentinel_orchestrator.get_audit_logger", return_value=MagicMock()),
    patch("sentinel_orchestrator.get_config",       return_value=MagicMock()),
):
    from sentinel_orchestrator import (  # noqa: E402
        SentinelOrchestrator,
        _WorkItem,
        MAX_RETRIES_PER_CASE,
        WATCHDOG_INTERVAL_SECONDS,
        DEFAULT_STATE_TIMEOUT_SECONDS,
        _COLLECTION_DEAD_LETTER,
        _agent_for_status,
        _recommend_human_action,
        _RESUMABLE_STATUSES,
    )


# ---------------------------------------------------------------------------
# Fake KV Store connector — enough of the surface for CaseStateManager
# ---------------------------------------------------------------------------

class _FakeConnector:
    def __init__(self):
        self._collections: Dict[str, Dict[str, Dict[str, Any]]] = {}

    def kvstore_get(self, collection, key):
        return self._collections.get(collection, {}).get(key)

    def kvstore_upsert(self, collection, key, record):
        self._collections.setdefault(collection, {})[key] = dict(record)

    def kvstore_query(self, collection, query=None, limit=100):
        records = list(self._collections.get(collection, {}).values())
        return records[:limit]

    def kvstore_delete(self, collection, key):
        self._collections.get(collection, {}).pop(key, None)


def _make_state_manager() -> CaseStateManager:
    return CaseStateManager(connector=_FakeConnector())


def _new_case(sm: CaseStateManager, **kwargs) -> Case:
    defaults = dict(
        alert_id      = "ALERT-TEST-001",
        alert_type    = "RANSOMWARE_POWERSHELL_ENCODED",
        affected_host = "DESKTOP-ABC123",
        affected_user = "CORP\\jdoe",
        risk_score    = 90,
        priority      = "HIGH",
    )
    defaults.update(kwargs)
    return sm.create_case(**defaults)


def _force_case(sm: CaseStateManager, case_id: str, **field_updates) -> Case:
    """Directly mutate & persist case fields, bypassing transition validation —
    used to set up scenarios (e.g. an already-CLOSED case) that the normal
    transition graph wouldn't let us reach in a couple of calls."""
    case = sm.get_case(case_id)
    for key, value in field_updates.items():
        setattr(case, key, value)
    sm._kvstore_write(case)
    sm._cache_set(case)
    return case


# ---------------------------------------------------------------------------
# State timeout tracking
# ---------------------------------------------------------------------------

class TestStateTimeoutTracking:
    def test_set_state_with_timeout_arms_timeout_fields(self):
        sm   = _make_state_manager()
        case = _new_case(sm)
        before = time.time()

        updated = sm.set_state_with_timeout(case.case_id, CaseStatus.TRIAGING, timeout_seconds=300)

        assert updated.status == CaseStatus.TRIAGING.value
        assert updated.timeout_duration_seconds == 300
        assert updated.state_entered_at >= before
        assert updated.state_timeout_at == pytest.approx(updated.state_entered_at + 300)

    def test_set_state_with_timeout_defaults_to_900_seconds(self):
        sm   = _make_state_manager()
        case = _new_case(sm)

        updated = sm.set_state_with_timeout(case.case_id, CaseStatus.TRIAGING)

        assert updated.timeout_duration_seconds == 900
        assert updated.state_timeout_at == pytest.approx(updated.state_entered_at + 900)

    def test_set_state_with_timeout_rejects_invalid_transition(self):
        sm   = _make_state_manager()
        case = _new_case(sm)  # status == QUEUED; QUEUED -> CLOSED is not allowed

        with pytest.raises(ValueError):
            sm.set_state_with_timeout(case.case_id, CaseStatus.CLOSED, timeout_seconds=60)

    def test_set_state_with_timeout_records_audit_entry(self):
        sm   = _make_state_manager()
        case = _new_case(sm)

        updated = sm.set_state_with_timeout(case.case_id, CaseStatus.TRIAGING, timeout_seconds=120,
                                             agent_name="orchestrator", detail="entering triage")

        last = updated.audit_trail[-1]
        assert last["from_status"] == CaseStatus.QUEUED.value
        assert last["to_status"]   == CaseStatus.TRIAGING.value
        assert last["timeout_at"]  == pytest.approx(updated.state_timeout_at)

    def test_check_timeouts_detects_expired_case(self):
        sm   = _make_state_manager()
        case = _new_case(sm)
        sm.set_state_with_timeout(case.case_id, CaseStatus.TRIAGING, timeout_seconds=0.01)

        time.sleep(0.05)

        assert sm.check_timeouts() == [case.case_id]

    def test_check_timeouts_excludes_cases_within_budget(self):
        sm   = _make_state_manager()
        case = _new_case(sm)
        sm.set_state_with_timeout(case.case_id, CaseStatus.TRIAGING, timeout_seconds=DEFAULT_STATE_TIMEOUT_SECONDS)

        assert sm.check_timeouts() == []

    def test_check_timeouts_excludes_cases_with_no_timeout_armed(self):
        sm = _make_state_manager()
        _new_case(sm)  # freshly created — never armed via set_state_with_timeout

        assert sm.check_timeouts() == []

    def test_check_timeouts_excludes_terminal_statuses_even_if_expired(self):
        sm   = _make_state_manager()
        case = _new_case(sm)
        sm.set_state_with_timeout(case.case_id, CaseStatus.TRIAGING, timeout_seconds=0.01)
        time.sleep(0.05)
        _force_case(sm, case.case_id, status=CaseStatus.CLOSED.value)

        assert sm.check_timeouts() == []

    def test_is_timed_out_false_before_expiry(self):
        sm   = _make_state_manager()
        case = _new_case(sm)
        sm.set_state_with_timeout(case.case_id, CaseStatus.TRIAGING, timeout_seconds=DEFAULT_STATE_TIMEOUT_SECONDS)

        assert sm.is_timed_out(case.case_id) is False

    def test_is_timed_out_true_after_expiry(self):
        sm   = _make_state_manager()
        case = _new_case(sm)
        sm.set_state_with_timeout(case.case_id, CaseStatus.TRIAGING, timeout_seconds=0.01)

        time.sleep(0.05)

        assert sm.is_timed_out(case.case_id) is True

    def test_is_timed_out_false_for_terminal_status(self):
        sm   = _make_state_manager()
        case = _new_case(sm)
        sm.set_state_with_timeout(case.case_id, CaseStatus.TRIAGING, timeout_seconds=0.01)
        time.sleep(0.05)
        _force_case(sm, case.case_id, status=CaseStatus.CLOSED.value)

        assert sm.is_timed_out(case.case_id) is False

    def test_is_timed_out_false_for_unknown_case(self):
        sm = _make_state_manager()

        assert sm.is_timed_out("SEN-DOES-NOT-EXIST") is False


# ---------------------------------------------------------------------------
# Retry progression: 0 -> 1 -> 2 -> 3 -> exhausted
# ---------------------------------------------------------------------------

class TestRetryProgression:
    def test_increment_retry_counts_up_one_at_a_time(self):
        sm   = _make_state_manager()
        case = _new_case(sm)
        assert case.retry_count == 0

        assert sm.increment_retry(case.case_id) == 1
        assert sm.increment_retry(case.case_id) == 2
        assert sm.increment_retry(case.case_id) == 3

    def test_increment_retry_persists_and_logs_audit_entry(self):
        sm   = _make_state_manager()
        case = _new_case(sm)

        sm.increment_retry(case.case_id)

        persisted = sm.get_case(case.case_id)
        assert persisted.retry_count == 1
        assert persisted.audit_trail[-1]["action"] == "retry_increment"

    def test_has_exhausted_retries_flips_at_max_retries(self):
        sm   = _make_state_manager()
        case = _new_case(sm)
        assert case.max_retries == MAX_RETRIES_PER_CASE == 3

        for expected_after in (1, 2, 3):
            sm.increment_retry(case.case_id)
            exhausted = sm.has_exhausted_retries(case.case_id)
            assert exhausted == (expected_after >= case.max_retries)

        assert sm.has_exhausted_retries(case.case_id) is True

    def test_has_exhausted_retries_false_when_budget_remains(self):
        sm   = _make_state_manager()
        case = _new_case(sm)
        sm.increment_retry(case.case_id)
        sm.increment_retry(case.case_id)

        assert sm.has_exhausted_retries(case.case_id) is False

    def test_has_exhausted_retries_respects_custom_max_retries(self):
        sm   = _make_state_manager()
        case = _new_case(sm)
        _force_case(sm, case.case_id, max_retries=1)

        sm.increment_retry(case.case_id)

        assert sm.has_exhausted_retries(case.case_id) is True


# ---------------------------------------------------------------------------
# Orchestrator helpers — _make_case / _make_orchestrator (mirrors test_orchestrator.py)
# ---------------------------------------------------------------------------

def _make_case(
    case_id:         str = "SEN-TEST01",
    status:          str = CaseStatus.INVESTIGATING.value,
    retry_count:     int = 0,
    max_retries:     int = MAX_RETRIES_PER_CASE,
    timeout_duration_seconds: int = DEFAULT_STATE_TIMEOUT_SECONDS,
):
    case = MagicMock(spec=Case)
    case.case_id          = case_id
    case.alert_id         = "ALERT-TEST-001"
    case.alert_type       = "RANSOMWARE_POWERSHELL_ENCODED"
    case.status           = status
    case.priority         = "HIGH"
    case.affected_host    = "DESKTOP-ABC123"
    case.affected_user    = "CORP\\jdoe"
    case.risk_score       = 90
    case.retry_count      = retry_count
    case.max_retries      = max_retries
    case.last_error       = ""
    case.created_time     = time.time()
    case.state_entered_at = time.time() - 1000
    case.state_timeout_at = time.time() - 10
    case.timeout_duration_seconds = timeout_duration_seconds
    case.audit_trail      = []
    case.vanguard_decision = {}
    case.sherlock_report   = {}
    case.executor_actions  = []
    case.halt_flag         = False
    return case


def _make_orchestrator(mock_state_manager=None):
    sm = mock_state_manager or MagicMock()
    with (
        patch("sentinel_orchestrator.CaseStateManager", return_value=sm),
        patch("sentinel_orchestrator.get_audit_logger", return_value=MagicMock()),
        patch("sentinel_orchestrator.get_config",       return_value=MagicMock()),
    ):
        orch = SentinelOrchestrator(state_manager=sm, max_concurrent=5, poll_interval=60, dry_run=True)
    orch._workers = []
    return orch


# ---------------------------------------------------------------------------
# Constants / mapping helpers
# ---------------------------------------------------------------------------

class TestFaultToleranceConstants:
    def test_watchdog_interval_is_30_seconds(self):
        assert WATCHDOG_INTERVAL_SECONDS == 30

    def test_default_state_timeout_is_15_minutes(self):
        assert DEFAULT_STATE_TIMEOUT_SECONDS == 900

    def test_max_retries_per_case_is_3(self):
        assert MAX_RETRIES_PER_CASE == 3

    def test_dead_letter_collection_name(self):
        assert _COLLECTION_DEAD_LETTER == "dead_letter_queue"

    def test_agent_for_status_maps_pipeline_stages(self):
        assert _agent_for_status(CaseStatus.TRIAGING)      == "vanguard"
        assert _agent_for_status(CaseStatus.INVESTIGATING) == "sherlock"
        assert _agent_for_status(CaseStatus.RESPONDING)    == "executor"
        assert _agent_for_status(CaseStatus.LEARNING)      == "sage"

    def test_agent_for_status_falls_back_to_orchestrator(self):
        assert _agent_for_status(CaseStatus.QUEUED) == "orchestrator"

    def test_recommend_human_action_mentions_agent_and_recovery_path(self):
        action = _recommend_human_action("sherlock", "INVESTIGATING")
        assert "sherlock" in action
        assert "recover_from_dead_letter" in action


# ---------------------------------------------------------------------------
# Watchdog cycle
# ---------------------------------------------------------------------------

class TestWatchdogCycle:
    def test_run_watchdog_cycle_handles_every_timed_out_case(self):
        sm = MagicMock()
        sm.check_timeouts.return_value = ["SEN-A", "SEN-B"]
        orch = _make_orchestrator(sm)
        orch._handle_timed_out_case = MagicMock()

        handled = orch._run_watchdog_cycle()

        assert handled == 2
        orch._handle_timed_out_case.assert_any_call("SEN-A")
        orch._handle_timed_out_case.assert_any_call("SEN-B")

    def test_run_watchdog_cycle_continues_past_individual_failures(self):
        sm = MagicMock()
        sm.check_timeouts.return_value = ["SEN-A", "SEN-B"]
        orch = _make_orchestrator(sm)
        orch._handle_timed_out_case = MagicMock(side_effect=[RuntimeError("boom"), None])

        handled = orch._run_watchdog_cycle()

        assert handled == 2
        assert orch._handle_timed_out_case.call_count == 2

    def test_run_watchdog_cycle_returns_zero_when_nothing_timed_out(self):
        sm = MagicMock()
        sm.check_timeouts.return_value = []
        orch = _make_orchestrator(sm)
        orch._handle_timed_out_case = MagicMock()

        assert orch._run_watchdog_cycle() == 0
        orch._handle_timed_out_case.assert_not_called()


# ---------------------------------------------------------------------------
# _handle_timed_out_case — branching to retry vs. dead-letter
# ---------------------------------------------------------------------------

class TestHandleTimedOutCase:
    @pytest.mark.parametrize("blocking_status", [
        CaseStatus.STUCK.value, CaseStatus.RETRYING.value, CaseStatus.DEAD_LETTER.value,
        CaseStatus.ERROR.value, CaseStatus.HALTED.value,
        CaseStatus.CLOSED.value, CaseStatus.SUPPRESSED.value,
    ])
    def test_skips_cases_already_mid_recovery_or_terminal(self, blocking_status):
        case = _make_case(status=blocking_status)
        sm = MagicMock()
        sm.get_case.return_value = case
        orch = _make_orchestrator(sm)
        orch._retry_timed_out_case = MagicMock()
        orch._dead_letter_case     = MagicMock()

        orch._handle_timed_out_case(case.case_id)

        sm.transition.assert_not_called()
        orch._retry_timed_out_case.assert_not_called()
        orch._dead_letter_case.assert_not_called()

    def test_returns_immediately_when_case_no_longer_exists(self):
        sm = MagicMock()
        sm.get_case.return_value = None
        orch = _make_orchestrator(sm)
        orch._retry_timed_out_case = MagicMock()
        orch._dead_letter_case     = MagicMock()

        orch._handle_timed_out_case("SEN-GONE")

        sm.transition.assert_not_called()
        orch._retry_timed_out_case.assert_not_called()
        orch._dead_letter_case.assert_not_called()

    def test_routes_to_retry_when_budget_remains(self):
        case = _make_case(status=CaseStatus.INVESTIGATING.value, retry_count=1)
        sm = MagicMock()
        sm.get_case.return_value = case
        sm.has_exhausted_retries.return_value = False
        orch = _make_orchestrator(sm)
        orch._retry_timed_out_case = MagicMock()
        orch._dead_letter_case     = MagicMock()

        orch._handle_timed_out_case(case.case_id)

        sm.transition.assert_called_once()
        assert sm.transition.call_args.args[1] == CaseStatus.STUCK
        orch._retry_timed_out_case.assert_called_once_with(
            case.case_id, CaseStatus.INVESTIGATING.value, "sherlock")
        orch._dead_letter_case.assert_not_called()

    def test_routes_to_dead_letter_when_retries_exhausted(self):
        case = _make_case(status=CaseStatus.RESPONDING.value, retry_count=3)
        sm = MagicMock()
        sm.get_case.return_value = case
        sm.has_exhausted_retries.return_value = True
        orch = _make_orchestrator(sm)
        orch._retry_timed_out_case = MagicMock()
        orch._dead_letter_case     = MagicMock()

        orch._handle_timed_out_case(case.case_id)

        sm.transition.assert_called_once()
        assert sm.transition.call_args.args[1] == CaseStatus.STUCK
        orch._dead_letter_case.assert_called_once()
        args = orch._dead_letter_case.call_args.args
        assert args[0] == case.case_id
        assert args[1] == CaseStatus.RESPONDING.value
        assert args[2] == "executor"
        orch._retry_timed_out_case.assert_not_called()

    def test_logs_state_timeout_error_with_context(self):
        case = _make_case(status=CaseStatus.INVESTIGATING.value, retry_count=0)
        sm = MagicMock()
        sm.get_case.return_value = case
        sm.has_exhausted_retries.return_value = False
        orch = _make_orchestrator(sm)
        orch._retry_timed_out_case = MagicMock()
        orch._dead_letter_case     = MagicMock()

        orch._handle_timed_out_case(case.case_id)

        orch._audit.log_error.assert_called_once()
        kwargs = orch._audit.log_error.call_args.kwargs
        assert kwargs["error_type"] == "STATE_TIMEOUT"
        assert kwargs["context"]["failed_agent"] == "sherlock"
        assert kwargs["context"]["stage"]        == CaseStatus.INVESTIGATING.value


# ---------------------------------------------------------------------------
# _retry_timed_out_case — re-queue for the same agent
# ---------------------------------------------------------------------------

class TestRetryTimedOutCase:
    def test_resumes_into_original_status_when_resumable(self):
        case = _make_case(status=CaseStatus.INVESTIGATING.value, retry_count=0)
        requeued = _make_case(status=CaseStatus.INVESTIGATING.value, retry_count=1)
        sm = MagicMock()
        sm.increment_retry.return_value = 1
        sm.set_state_with_timeout.return_value = requeued
        orch = _make_orchestrator(sm)

        orch._retry_timed_out_case(case.case_id, CaseStatus.INVESTIGATING.value, "sherlock")

        sm.transition.assert_called_once_with(
            case.case_id, CaseStatus.RETRYING, agent_name="watchdog",
            detail="retrying after timeout in INVESTIGATING")
        sm.increment_retry.assert_called_once_with(case.case_id)
        target_status = sm.set_state_with_timeout.call_args.args[1]
        assert target_status == CaseStatus.INVESTIGATING
        assert sm.set_state_with_timeout.call_args.kwargs["timeout_seconds"] == DEFAULT_STATE_TIMEOUT_SECONDS

    def test_falls_back_to_queued_when_original_status_not_resumable(self):
        case = _make_case(status=CaseStatus.ERROR.value, retry_count=0)
        requeued = _make_case(status=CaseStatus.QUEUED.value, retry_count=1)
        sm = MagicMock()
        sm.increment_retry.return_value = 1
        sm.set_state_with_timeout.return_value = requeued
        orch = _make_orchestrator(sm)

        orch._retry_timed_out_case(case.case_id, CaseStatus.ERROR.value, "orchestrator")

        target_status = sm.set_state_with_timeout.call_args.args[1]
        assert target_status == CaseStatus.QUEUED
        assert target_status not in _RESUMABLE_STATUSES or target_status == CaseStatus.QUEUED

    def test_requeues_a_work_item_and_drops_active_tracking(self):
        case = _make_case(status=CaseStatus.DECIDING.value, retry_count=0)
        requeued = _make_case(status=CaseStatus.DECIDING.value, retry_count=1)
        sm = MagicMock()
        sm.increment_retry.return_value = 1
        sm.set_state_with_timeout.return_value = requeued
        orch = _make_orchestrator(sm)
        with orch._active_lock:
            orch._active_cases.add(case.case_id)

        orch._retry_timed_out_case(case.case_id, CaseStatus.DECIDING.value, "orchestrator")

        assert case.case_id not in orch._active_cases
        assert orch._work_queue.qsize() == 1
        item = orch._work_queue.get_nowait()
        assert isinstance(item, _WorkItem)
        assert item.case_id == requeued.case_id

    def test_logs_transition_from_stuck_to_target_status(self):
        case = _make_case(status=CaseStatus.TRIAGING.value, retry_count=0)
        requeued = _make_case(status=CaseStatus.TRIAGING.value, retry_count=1)
        sm = MagicMock()
        sm.increment_retry.return_value = 1
        sm.set_state_with_timeout.return_value = requeued
        orch = _make_orchestrator(sm)

        orch._retry_timed_out_case(case.case_id, CaseStatus.TRIAGING.value, "vanguard")

        orch._audit.log_transition.assert_called_once()
        kwargs = orch._audit.log_transition.call_args.kwargs
        assert kwargs["from_status"] == CaseStatus.STUCK.value
        assert kwargs["to_status"]   == CaseStatus.TRIAGING.value
        assert kwargs["metadata"]["retry_count"]  == 1
        assert kwargs["metadata"]["failed_agent"] == "vanguard"


# ---------------------------------------------------------------------------
# _dead_letter_case — record structure & preserved context
# ---------------------------------------------------------------------------

class TestDeadLetterPreservation:
    _REQUIRED_RECORD_FIELDS = {
        "case_id", "original_status", "failed_agent", "timeout_reason",
        "retry_count", "final_error", "dead_lettered_at",
        "recommended_human_action", "preserved_context",
    }
    _REQUIRED_CONTEXT_FIELDS = {
        "alert_id", "alert_type", "affected_host", "affected_user", "risk_score",
        "vanguard_decision", "sherlock_report", "executor_actions", "audit_trail",
    }

    def _run_dead_letter(self, case):
        sm = MagicMock()
        sm.get_case.return_value = case
        sm.transition.return_value = case
        orch = _make_orchestrator(sm)
        orch._write_dead_letter_record = MagicMock()
        orch._notify_dead_letter       = MagicMock()

        orch._dead_letter_case(case.case_id, CaseStatus.RESPONDING.value, "executor",
                               "Case stuck in RESPONDING for over 900s")
        return orch, sm

    def test_record_has_all_required_top_level_fields(self):
        case = _make_case(status=CaseStatus.RESPONDING.value, retry_count=3)
        case.audit_trail = [{"timestamp": i, "action": "noop"} for i in range(15)]
        orch, _ = self._run_dead_letter(case)

        record = orch._write_dead_letter_record.call_args.args[0]
        assert self._REQUIRED_RECORD_FIELDS.issubset(record.keys())
        assert record["case_id"]        == case.case_id
        assert record["original_status"] == CaseStatus.RESPONDING.value
        assert record["failed_agent"]    == "executor"
        assert record["retry_count"]     == case.retry_count

    def test_preserved_context_has_all_required_fields_and_bounded_audit_trail(self):
        case = _make_case(status=CaseStatus.RESPONDING.value, retry_count=3)
        case.audit_trail = [{"timestamp": i, "action": "noop"} for i in range(15)]
        orch, _ = self._run_dead_letter(case)

        record  = orch._write_dead_letter_record.call_args.args[0]
        context = record["preserved_context"]
        assert self._REQUIRED_CONTEXT_FIELDS.issubset(context.keys())
        assert context["alert_id"]      == case.alert_id
        assert context["affected_host"] == case.affected_host
        assert len(context["audit_trail"]) == 10
        assert context["audit_trail"] == case.audit_trail[-10:]

    def test_final_error_falls_back_to_timeout_reason_when_no_last_error(self):
        case = _make_case(status=CaseStatus.RESPONDING.value, retry_count=3)
        case.last_error = ""
        orch, _ = self._run_dead_letter(case)

        record = orch._write_dead_letter_record.call_args.args[0]
        assert record["final_error"] == "Case stuck in RESPONDING for over 900s"

    def test_final_error_prefers_last_error_when_present(self):
        case = _make_case(status=CaseStatus.RESPONDING.value, retry_count=3)
        case.last_error = "connection refused by executor backend"
        orch, _ = self._run_dead_letter(case)

        record = orch._write_dead_letter_record.call_args.args[0]
        assert record["final_error"] == "connection refused by executor backend"

    def test_transitions_through_error_then_dead_letter(self):
        case = _make_case(status=CaseStatus.RESPONDING.value, retry_count=3)
        orch, sm = self._run_dead_letter(case)

        statuses = [call.args[1] for call in sm.transition.call_args_list]
        assert statuses == [CaseStatus.ERROR, CaseStatus.DEAD_LETTER]

    def test_notifies_stakeholders_after_recording(self):
        case = _make_case(status=CaseStatus.RESPONDING.value, retry_count=3)
        orch, _ = self._run_dead_letter(case)

        orch._notify_dead_letter.assert_called_once()
        notified_case, notified_record = orch._notify_dead_letter.call_args.args
        assert notified_case is case
        assert notified_record["case_id"] == case.case_id

    def test_recommended_human_action_references_agent_and_recovery_method(self):
        case = _make_case(status=CaseStatus.RESPONDING.value, retry_count=3)
        orch, _ = self._run_dead_letter(case)

        record = orch._write_dead_letter_record.call_args.args[0]
        assert "executor" in record["recommended_human_action"]
        assert "recover_from_dead_letter" in record["recommended_human_action"]


# ---------------------------------------------------------------------------
# recover_from_dead_letter — manual operator recovery path
# ---------------------------------------------------------------------------

class TestRecoverFromDeadLetter:
    def test_rejects_case_not_in_dead_letter(self):
        case = _make_case(status=CaseStatus.INVESTIGATING.value)
        sm = MagicMock()
        sm.get_case.return_value = case
        orch = _make_orchestrator(sm)

        with pytest.raises(ValueError):
            orch.recover_from_dead_letter(case.case_id)

    def test_raises_key_error_when_case_missing(self):
        sm = MagicMock()
        sm.get_case.return_value = None
        orch = _make_orchestrator(sm)

        with pytest.raises(KeyError):
            orch.recover_from_dead_letter("SEN-GONE")

    def test_resets_retry_budget_and_requeues_into_original_status(self):
        case = _make_case(status=CaseStatus.DEAD_LETTER.value, retry_count=3)
        recovered = _make_case(status=CaseStatus.INVESTIGATING.value, retry_count=0)
        sm = MagicMock()
        sm.get_case.return_value = case
        sm.set_state_with_timeout.return_value = recovered
        orch = _make_orchestrator(sm)
        orch._read_dead_letter_record   = MagicMock(return_value={"original_status": "INVESTIGATING"})
        orch._remove_dead_letter_record = MagicMock()

        result = orch.recover_from_dead_letter(case.case_id, agent_name="analyst")

        sm.update_case.assert_called_once_with(
            case.case_id, {"retry_count": 0, "last_error": ""},
            agent_name="analyst", detail="dead-letter recovery: retry budget reset")
        target_status = sm.set_state_with_timeout.call_args.args[1]
        assert target_status == CaseStatus.INVESTIGATING
        orch._remove_dead_letter_record.assert_called_once_with(case.case_id)
        assert orch._work_queue.qsize() == 1
        assert result is recovered

    def test_falls_back_to_queued_when_original_status_unresumable(self):
        case = _make_case(status=CaseStatus.DEAD_LETTER.value, retry_count=3)
        recovered = _make_case(status=CaseStatus.QUEUED.value, retry_count=0)
        sm = MagicMock()
        sm.get_case.return_value = case
        sm.set_state_with_timeout.return_value = recovered
        orch = _make_orchestrator(sm)
        orch._read_dead_letter_record   = MagicMock(return_value={"original_status": "ERROR"})
        orch._remove_dead_letter_record = MagicMock()

        orch.recover_from_dead_letter(case.case_id)

        target_status = sm.set_state_with_timeout.call_args.args[1]
        assert target_status == CaseStatus.QUEUED

    def test_falls_back_to_queued_when_no_dead_letter_record_found(self):
        case = _make_case(status=CaseStatus.DEAD_LETTER.value, retry_count=3)
        recovered = _make_case(status=CaseStatus.QUEUED.value, retry_count=0)
        sm = MagicMock()
        sm.get_case.return_value = case
        sm.set_state_with_timeout.return_value = recovered
        orch = _make_orchestrator(sm)
        orch._read_dead_letter_record   = MagicMock(return_value=None)
        orch._remove_dead_letter_record = MagicMock()

        orch.recover_from_dead_letter(case.case_id)

        target_status = sm.set_state_with_timeout.call_args.args[1]
        assert target_status == CaseStatus.QUEUED

    def test_logs_transition_from_dead_letter_to_target(self):
        case = _make_case(status=CaseStatus.DEAD_LETTER.value, retry_count=3)
        recovered = _make_case(status=CaseStatus.TRIAGING.value, retry_count=0)
        sm = MagicMock()
        sm.get_case.return_value = case
        sm.set_state_with_timeout.return_value = recovered
        orch = _make_orchestrator(sm)
        orch._read_dead_letter_record   = MagicMock(return_value={"original_status": "TRIAGING"})
        orch._remove_dead_letter_record = MagicMock()

        orch.recover_from_dead_letter(case.case_id, agent_name="analyst")

        orch._audit.log_transition.assert_called_once()
        kwargs = orch._audit.log_transition.call_args.kwargs
        assert kwargs["from_status"] == CaseStatus.DEAD_LETTER.value
        assert kwargs["to_status"]   == CaseStatus.TRIAGING.value
        assert kwargs["metadata"]["agent"] == "analyst"


# ---------------------------------------------------------------------------
# Watchdog scheduling — the loop polls at WATCHDOG_INTERVAL_SECONDS
# ---------------------------------------------------------------------------

class TestWatchdogScheduling:
    def test_watchdog_thread_is_created_as_daemon(self):
        orch = _make_orchestrator()

        assert orch._watchdog_thread.daemon is True
        assert orch._watchdog_thread.name == "sentinel-watchdog"

    def test_watchdog_loop_runs_a_cycle_then_waits_the_poll_interval(self):
        orch = _make_orchestrator()
        orch._run_watchdog_cycle = MagicMock(return_value=0)

        # Drive exactly one iteration of the loop, then signal it to stop.
        wait_calls = []

        def _fake_wait(timeout=None):
            wait_calls.append(timeout)
            orch._stop_event.set()
            return True

        orch._stop_event.wait = MagicMock(side_effect=_fake_wait)
        orch._stop_event.is_set = MagicMock(side_effect=[False, True])

        orch._watchdog_loop()

        orch._run_watchdog_cycle.assert_called_once()
        assert wait_calls == [WATCHDOG_INTERVAL_SECONDS]

    def test_watchdog_loop_survives_cycle_exceptions(self):
        orch = _make_orchestrator()
        orch._run_watchdog_cycle = MagicMock(side_effect=RuntimeError("kvstore unreachable"))

        wait_calls = []

        def _fake_wait(timeout=None):
            wait_calls.append(timeout)
            orch._stop_event.set()
            return True

        orch._stop_event.wait = MagicMock(side_effect=_fake_wait)
        orch._stop_event.is_set = MagicMock(side_effect=[False, True])

        orch._watchdog_loop()  # must not raise

        orch._run_watchdog_cycle.assert_called_once()
        assert wait_calls == [WATCHDOG_INTERVAL_SECONDS]
