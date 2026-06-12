"""
Unit tests for agent_executor.py — ExecutorAgent response pipeline.

Runs without a live Splunk instance: SplunkMCPClient, get_audit_logger,
and get_config are all mocked. Uses _MockExecutorAgent for end-to-end tests.
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

_BIN = Path(__file__).resolve().parent.parent.parent / "app" / "sentinel" / "bin"
if str(_BIN) not in sys.path:
    sys.path.insert(0, str(_BIN))

with (
    patch("agent_executor.SplunkMCPClient", autospec=False),
    patch("agent_executor.get_audit_logger", return_value=MagicMock()),
    patch("agent_executor.get_config",       return_value=MagicMock()),
):
    from agent_executor import (
        ExecutorAgent,
        _MockExecutorAgent,
        _RateLimiter,
        _CascadeGuard,
        ActionResult,
        ActionVerification,
        ActionStatus,
        ExecutorMode,
        ExecutorError,
        ExecutorRateLimitError,
        ExecutorCascadeHaltError,
        ExecutorHaltSignalError,
        ExecutorAuthorizationError,
        _DEFAULT_ROLLBACK,
        _VERIFICATION_QUERIES,
        _CONTAINMENT_ACTIONS,
        _ERADICATION_ACTIONS,
        _DOCUMENTATION_ACTIONS,
        _RATE_LIMIT_ACTIONS,
        _RATE_LIMIT_WINDOW_S,
        _CASCADE_FAILURE_THRESHOLD,
        _CASCADE_WINDOW_S,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_case(
    case_id:             str  = "CASE-TEST-001",
    alert_id:            str  = "ALERT-TEST-001",
    risk_score:          int  = 90,
    classification:      str  = "RANSOMWARE_INITIAL_ACCESS",
    status:              str  = "RESPONDING",
    requires_approval:   bool = False,
    approval_granted_by: Any  = None,
    halt_flag:           bool = False,
    recommended_actions: list = None,
    blast_radius:        dict = None,
):
    case = MagicMock()
    case.case_id             = case_id
    case.alert_id            = alert_id
    case.risk_score          = risk_score
    case.classification      = classification
    case.status              = status
    case.requires_approval   = requires_approval
    case.approval_granted_by = approval_granted_by
    case.halt_flag           = halt_flag
    case.sherlock_report     = {
        "classification":      classification,
        "recommended_actions": recommended_actions or [],
        "blast_radius":        blast_radius        or {},
    }
    return case


def _make_denying_gate(reason="Test default — ApprovalGate denies eradication without a live responder."):
    """
    Default ApprovalGate stand-in for tests that don't care about the gate:
    denies (mirrors the pre-gate "skip eradication without approval" behavior)
    so existing CONTAINMENT_ONLY assertions keep their meaning without waiting
    on real notify/timeout machinery. Tests that DO care inject their own.
    """
    gate = MagicMock()
    gate.request_approval.return_value = {
        "approved": False, "status": "DENIED", "gate_decision": "CONTAINMENT_APPROVED",
        "request_id": "REQ-TESTDENY", "reason": reason,
    }
    return gate


def _make_agent(mock_mcp=None, approval_gate=None):
    cfg = MagicMock()
    cfg.get.return_value      = ""
    cfg.get_bool.return_value = False
    return ExecutorAgent(mcp=mock_mcp or MagicMock(), config=cfg,
                         approval_gate=approval_gate or _make_denying_gate())


def _make_mock_agent(mock_mcp=None, approval_gate=None):
    cfg = MagicMock()
    cfg.get.return_value      = ""
    cfg.get_bool.return_value = False
    return _MockExecutorAgent(mcp=mock_mcp or MagicMock(), config=cfg,
                              approval_gate=approval_gate or _make_denying_gate())


# ---------------------------------------------------------------------------
# Constants tests
# ---------------------------------------------------------------------------

class TestConstants:
    def test_rate_limit_actions_is_10(self):
        assert _RATE_LIMIT_ACTIONS == 10

    def test_rate_limit_window_is_3600s(self):
        assert _RATE_LIMIT_WINDOW_S == 3600

    def test_cascade_failure_threshold_is_3(self):
        assert _CASCADE_FAILURE_THRESHOLD == 3

    def test_cascade_window_is_300s(self):
        assert _CASCADE_WINDOW_S == 300

    def test_containment_actions(self):
        assert _CONTAINMENT_ACTIONS == {"isolate_host", "block_ip", "kill_process"}

    def test_eradication_actions(self):
        assert _ERADICATION_ACTIONS == {
            "disable_user", "quarantine_file", "revoke_session", "rotate_credentials"
        }

    def test_documentation_actions(self):
        assert _DOCUMENTATION_ACTIONS == {
            "create_ticket", "notify_stakeholders", "trigger_playbook"
        }

    def test_rollback_isolate_host_is_4h(self):
        assert _DEFAULT_ROLLBACK["isolate_host"] == 14_400

    def test_rollback_block_ip_is_72h(self):
        assert _DEFAULT_ROLLBACK["block_ip"] == 259_200

    def test_rollback_disable_user_is_24h(self):
        assert _DEFAULT_ROLLBACK["disable_user"] == 86_400

    def test_rollback_kill_process_is_0(self):
        assert _DEFAULT_ROLLBACK["kill_process"] == 0

    def test_rollback_quarantine_file_is_4h(self):
        assert _DEFAULT_ROLLBACK["quarantine_file"] == 14_400

    def test_rollback_revoke_session_is_0(self):
        assert _DEFAULT_ROLLBACK["revoke_session"] == 0

    def test_rollback_rotate_credentials_is_0(self):
        assert _DEFAULT_ROLLBACK["rotate_credentials"] == 0


# ---------------------------------------------------------------------------
# Exception hierarchy tests
# ---------------------------------------------------------------------------

class TestExceptionHierarchy:
    def test_rate_limit_error_is_executor_error(self):
        assert issubclass(ExecutorRateLimitError, ExecutorError)

    def test_cascade_halt_error_is_executor_error(self):
        assert issubclass(ExecutorCascadeHaltError, ExecutorError)

    def test_halt_signal_error_is_executor_error(self):
        assert issubclass(ExecutorHaltSignalError, ExecutorError)

    def test_authorization_error_is_executor_error(self):
        assert issubclass(ExecutorAuthorizationError, ExecutorError)


# ---------------------------------------------------------------------------
# _determine_mode tests
# ---------------------------------------------------------------------------

class TestDetermineMode:
    @pytest.mark.parametrize("score,expected", [
        (85,  ExecutorMode.FULL_AUTONOMY),
        (97,  ExecutorMode.FULL_AUTONOMY),
        (100, ExecutorMode.FULL_AUTONOMY),
        (70,  ExecutorMode.CONTAINMENT_ONLY),
        (77,  ExecutorMode.CONTAINMENT_ONLY),
        (84,  ExecutorMode.CONTAINMENT_ONLY),
        (55,  ExecutorMode.MONITORING_ONLY),
        (62,  ExecutorMode.MONITORING_ONLY),
        (69,  ExecutorMode.MONITORING_ONLY),
        (0,   ExecutorMode.DOCUMENT_ONLY),
        (42,  ExecutorMode.DOCUMENT_ONLY),
        (54,  ExecutorMode.DOCUMENT_ONLY),
    ])
    def test_mode_from_score(self, score, expected):
        agent = _make_agent()
        assert agent._determine_mode(score) == expected


# ---------------------------------------------------------------------------
# _filter_actions tests
# ---------------------------------------------------------------------------

class TestFilterActions:
    _ALL_ACTIONS = [
        {"action": "isolate_host",        "target": "DESKTOP-ABC123",   "priority": 1},
        {"action": "block_ip",            "target": "185.220.101.42",   "priority": 2},
        {"action": "kill_process",        "target": "HOST:6201",        "priority": 3},
        {"action": "disable_user",        "target": "CORP\\jdoe",       "priority": 4},
        {"action": "quarantine_file",     "target": "C:\\bad.dll",      "priority": 5},
        {"action": "revoke_session",      "target": "CORP\\jdoe",       "priority": 6},
        {"action": "rotate_credentials",  "target": "svc-backup",       "priority": 7},
        {"action": "create_ticket",       "target": "ServiceNow",       "priority": 8},
        {"action": "notify_stakeholders", "target": "soc-oncall",       "priority": 9},
        {"action": "trigger_playbook",    "target": "RANSOMWARE_RESPONSE", "priority": 10},
    ]

    def test_full_autonomy_executes_all_known_actions(self):
        agent = _make_agent()
        exe, skipped = agent._filter_actions(
            self._ALL_ACTIONS, ExecutorMode.FULL_AUTONOMY, 90, False
        )
        assert len(exe)    == len(self._ALL_ACTIONS)
        assert len(skipped) == 0

    def test_document_only_skips_all_active_response_actions(self):
        agent = _make_agent()
        exe, skipped = agent._filter_actions(
            self._ALL_ACTIONS, ExecutorMode.DOCUMENT_ONLY, 42, False
        )
        exe_types = {a["action"] for a in exe}
        assert exe_types <= _DOCUMENTATION_ACTIONS
        assert "isolate_host" not in exe_types
        assert "block_ip"     not in exe_types

    def test_monitoring_only_skips_containment_and_eradication(self):
        agent = _make_agent()
        exe, _ = agent._filter_actions(
            self._ALL_ACTIONS, ExecutorMode.MONITORING_ONLY, 62, False
        )
        exe_types = {a["action"] for a in exe}
        assert "isolate_host" not in exe_types
        assert "disable_user" not in exe_types
        assert exe_types      <= _DOCUMENTATION_ACTIONS

    def test_containment_only_without_approval_skips_eradication(self):
        agent = _make_agent()
        exe, skipped = agent._filter_actions(
            self._ALL_ACTIONS, ExecutorMode.CONTAINMENT_ONLY, 77, approval_granted=False
        )
        exe_types    = {a["action"] for a in exe}
        skipped_types = {a["action"] for a in skipped}
        for action in _ERADICATION_ACTIONS:
            assert action not in exe_types,    f"{action} should be skipped"
            assert action in skipped_types,    f"{action} should be in skipped"

    def test_containment_only_with_approval_allows_eradication(self):
        agent = _make_agent()
        exe, _ = agent._filter_actions(
            self._ALL_ACTIONS, ExecutorMode.CONTAINMENT_ONLY, 77, approval_granted=True
        )
        exe_types = {a["action"] for a in exe}
        for action in _ERADICATION_ACTIONS:
            assert action in exe_types, f"{action} should be allowed with approval"

    def test_filter_preserves_priority_ordering(self):
        agent = _make_agent()
        exe, _ = agent._filter_actions(
            self._ALL_ACTIONS, ExecutorMode.FULL_AUTONOMY, 90, False
        )
        priorities = [int(a.get("priority", 99)) for a in exe]
        assert priorities == sorted(priorities)

    def test_unknown_action_type_skipped_with_reason(self):
        actions = [{"action": "launch_missiles", "target": "nowhere", "priority": 1}]
        agent   = _make_agent()
        exe, skipped = agent._filter_actions(
            actions, ExecutorMode.FULL_AUTONOMY, 90, False
        )
        assert len(exe)             == 0
        assert len(skipped)         == 1
        assert "_skip_reason" in skipped[0]


# ---------------------------------------------------------------------------
# _RateLimiter tests
# ---------------------------------------------------------------------------

class TestRateLimiter:
    def test_allows_up_to_max_actions(self):
        rl = _RateLimiter(max_actions=5, window_s=3600)
        assert all(rl.check_and_record() for _ in range(5))

    def test_blocks_action_after_limit(self):
        rl = _RateLimiter(max_actions=5, window_s=3600)
        for _ in range(5):
            rl.check_and_record()
        assert rl.check_and_record() is False

    def test_sentinel_limit_is_10_actions_per_hour(self):
        rl = _RateLimiter(max_actions=_RATE_LIMIT_ACTIONS,
                          window_s=_RATE_LIMIT_WINDOW_S)
        for _ in range(_RATE_LIMIT_ACTIONS):
            rl.check_and_record()
        assert rl.check_and_record() is False

    def test_current_count_accurate(self):
        rl = _RateLimiter(max_actions=10, window_s=3600)
        rl.check_and_record()
        rl.check_and_record()
        assert rl.current_count == 2


# ---------------------------------------------------------------------------
# _CascadeGuard tests
# ---------------------------------------------------------------------------

class TestCascadeGuard:
    def test_two_failures_do_not_trigger(self):
        cg = _CascadeGuard(threshold=3, window_s=300)
        cg.record_failure()
        cg.record_failure()
        assert cg.triggered is False

    def test_three_failures_trigger_halt(self):
        cg = _CascadeGuard(threshold=3, window_s=300)
        cg.record_failure()
        cg.record_failure()
        result = cg.record_failure()
        assert result        is True
        assert cg.triggered  is True

    def test_reset_clears_triggered(self):
        cg = _CascadeGuard(threshold=3, window_s=300)
        for _ in range(3):
            cg.record_failure()
        cg.reset()
        assert cg.triggered is False

    def test_success_clears_failure_window(self):
        cg = _CascadeGuard(threshold=3, window_s=300)
        cg.record_failure()
        cg.record_failure()
        cg.record_success()   # clears window
        cg.record_failure()
        cg.record_failure()
        assert cg.triggered is False   # only 2 failures after success

    def test_triggered_guard_keeps_returning_true(self):
        cg = _CascadeGuard(threshold=3, window_s=300)
        for _ in range(3):
            cg.record_failure()
        for _ in range(3):
            assert cg.record_failure() is True


# ---------------------------------------------------------------------------
# _check_halt_signal tests
# ---------------------------------------------------------------------------

class TestHaltSignal:
    def test_status_halted_returns_true(self):
        agent = _make_agent()
        case  = _make_case(status="HALTED")
        assert agent._check_halt_signal(case) is True

    def test_halt_flag_true_returns_true(self):
        agent = _make_agent()
        case  = _make_case(halt_flag=True)
        assert agent._check_halt_signal(case) is True

    def test_normal_responding_status_returns_false(self):
        agent = _make_agent()
        case  = _make_case(status="RESPONDING", halt_flag=False)
        assert agent._check_halt_signal(case) is False


# ---------------------------------------------------------------------------
# Rollback scheduling tests
# ---------------------------------------------------------------------------

class TestRollbackSchedule:
    def test_returns_future_iso_timestamp(self):
        agent  = _make_agent()
        before = datetime.now(timezone.utc)
        ts     = agent._schedule_rollback(3600)
        after  = datetime.now(timezone.utc)

        scheduled = datetime.fromisoformat(ts).astimezone(timezone.utc)
        assert scheduled > before + timedelta(seconds=3500)
        assert scheduled < after  + timedelta(seconds=3700)

    def test_zero_timer_returns_empty_string(self):
        assert _make_agent()._schedule_rollback(0)  == ""

    def test_negative_timer_returns_empty_string(self):
        assert _make_agent()._schedule_rollback(-1) == ""


# ---------------------------------------------------------------------------
# Verification query template tests
# ---------------------------------------------------------------------------

class TestVerificationQueries:
    @pytest.mark.parametrize("action_type", [
        "isolate_host", "block_ip", "disable_user", "kill_process", "quarantine_file"
    ])
    def test_template_exists(self, action_type):
        assert action_type in _VERIFICATION_QUERIES

    def test_isolate_host_template_has_target_placeholder(self):
        assert "{target}" in _VERIFICATION_QUERIES["isolate_host"]

    def test_no_template_for_create_ticket_returns_verified_true(self):
        agent = _make_agent()
        v     = agent._verify_action("create_ticket", target="ServiceNow")
        assert v.verified is True

    def test_confirmed_search_result_sets_verified_true(self):
        mock_mcp = MagicMock()
        mock_mcp.search_spl.return_value = {"results": [{"result": "confirmed"}]}
        agent = _make_agent(mock_mcp)
        v     = agent._verify_action("isolate_host", target="DESKTOP-ABC123")
        assert v.verified is True

    def test_empty_search_result_sets_verified_false(self):
        mock_mcp = MagicMock()
        mock_mcp.search_spl.return_value = {"results": []}
        agent = _make_agent(mock_mcp)
        v     = agent._verify_action("isolate_host", target="DESKTOP-ABC123")
        assert v.verified is False


# ---------------------------------------------------------------------------
# End-to-end run() tests with _MockExecutorAgent
# ---------------------------------------------------------------------------

_RANSOMWARE_ACTIONS = [
    {"priority": 1, "action": "isolate_host",       "target": "DESKTOP-ABC123",
     "justification": "Ransomware confirmed",  "urgency": "immediate"},
    {"priority": 2, "action": "disable_user",        "target": "CORP\\jdoe",
     "justification": "Cred dump via LSASS",   "urgency": "immediate"},
    {"priority": 3, "action": "block_ip",            "target": "185.220.101.42",
     "justification": "C2 server",             "urgency": "within_1h"},
    {"priority": 4, "action": "create_ticket",       "target": "ServiceNow",
     "justification": "P1 incident",           "urgency": "within_4h"},
    {"priority": 5, "action": "notify_stakeholders", "target": "soc-oncall",
     "justification": "Critical incident",     "urgency": "immediate"},
]


class TestRunEndToEnd:
    def test_ransomware_full_autonomy_all_actions_succeed(self, mock_audit):
        agent  = _make_mock_agent()
        case   = _make_case(risk_score=97, recommended_actions=_RANSOMWARE_ACTIONS)
        result = agent.run(case, mock_audit)

        assert result["executor_mode"]      == ExecutorMode.FULL_AUTONOMY.value
        assert result["successful_actions"] == 5
        assert result["failed_actions"]     == 0
        assert result["halted"]             is False

    _INSIDER_THREAT_ACTIONS = [
        {"priority": 1, "action": "isolate_host",  "target": "WS-HR-07",
         "justification": "suspicious", "urgency": "within_1h"},
        {"priority": 2, "action": "disable_user",  "target": "CORP\\jsmith",
         "justification": "exfil",     "urgency": "within_4h"},
        {"priority": 3, "action": "create_ticket", "target": "ServiceNow",
         "justification": "doc",       "urgency": "within_4h"},
    ]

    def test_insider_threat_containment_only_routes_disable_user_through_gate_and_denies(
        self, mock_audit
    ):
        """
        Without case-level approval, CONTAINMENT_ONLY no longer hard-skips
        eradication actions — it routes them through the live ApprovalGate.
        Here the gate denies (the injected default-deny stand-in), so
        disable_user stays skipped, but now with the gate's resolution
        recorded as the reason and a request_id attached.
        """
        agent  = _make_mock_agent()
        case   = _make_case(risk_score=77, recommended_actions=self._INSIDER_THREAT_ACTIONS,
                            approval_granted_by=None)
        result = agent.run(case, mock_audit)

        assert result["executor_mode"] == ExecutorMode.CONTAINMENT_ONLY.value
        statuses = {a["action_type"]: a["status"] for a in result["actions"]}
        assert statuses.get("isolate_host")  == ActionStatus.SUCCESS.value
        assert statuses.get("create_ticket") == ActionStatus.SUCCESS.value
        assert statuses.get("disable_user")  == ActionStatus.SKIPPED.value

        disable_user = next(a for a in result["actions"] if a["action_type"] == "disable_user")
        assert "ApprovalGate" in disable_user["skipped_reason"]
        assert "DENIED" in disable_user["skipped_reason"]

        agent._get_approval_gate().request_approval.assert_called_once()
        _, gate_kwargs = agent._get_approval_gate().request_approval.call_args
        assert gate_kwargs["action_type"] == "disable_user"
        assert gate_kwargs["target"]      == "CORP\\jsmith"
        assert gate_kwargs["confidence_score"] == 77

    def test_insider_threat_containment_only_promotes_disable_user_when_gate_approves(
        self, mock_audit
    ):
        """
        When the human approves via the live gate (Slack/email/dashboard),
        the previously-skipped eradication action is promoted back into the
        execution plan and actually runs.
        """
        approving_gate = MagicMock()
        approving_gate.request_approval.return_value = {
            "approved": True, "status": "APPROVED", "gate_decision": "CONTAINMENT_APPROVED",
            "request_id": "REQ-LIVEAPPROVE", "reason": "Human approved — proceeding with action.",
        }
        agent  = _make_mock_agent(approval_gate=approving_gate)
        case   = _make_case(risk_score=77, recommended_actions=self._INSIDER_THREAT_ACTIONS,
                            approval_granted_by=None)
        result = agent.run(case, mock_audit)

        statuses = {a["action_type"]: a["status"] for a in result["actions"]}
        assert statuses.get("disable_user") == ActionStatus.SUCCESS.value
        approving_gate.request_approval.assert_called_once()

    def test_low_confidence_document_only_skips_containment(
        self, mock_audit
    ):
        actions = [
            {"priority": 1, "action": "isolate_host",       "target": "HOST",
             "justification": "low confidence", "urgency": "within_24h"},
            {"priority": 2, "action": "create_ticket",      "target": "SN",
             "justification": "doc",            "urgency": "within_24h"},
            {"priority": 3, "action": "notify_stakeholders","target": "soc",
             "justification": "notify",         "urgency": "within_24h"},
        ]
        agent  = _make_mock_agent()
        case   = _make_case(risk_score=42, recommended_actions=actions)
        result = agent.run(case, mock_audit)

        assert result["executor_mode"] == ExecutorMode.DOCUMENT_ONLY.value
        statuses = {a["action_type"]: a["status"] for a in result["actions"]}
        assert statuses.get("isolate_host")        == ActionStatus.SKIPPED.value
        assert statuses.get("create_ticket")       == ActionStatus.SUCCESS.value
        assert statuses.get("notify_stakeholders") == ActionStatus.SUCCESS.value

    def test_halt_signal_stops_execution_before_any_action(
        self, mock_audit
    ):
        agent  = _make_mock_agent()
        case   = _make_case(
            risk_score          = 90,
            recommended_actions = _RANSOMWARE_ACTIONS,
            status              = "HALTED",
        )
        result = agent.run(case, mock_audit)

        assert result["halted"]             is True
        assert result["successful_actions"] == 0

    def test_pre_triggered_cascade_guard_halts_pipeline(
        self, mock_audit
    ):
        agent = _make_mock_agent()
        for _ in range(_CASCADE_FAILURE_THRESHOLD):
            agent._cascade.record_failure()

        case   = _make_case(risk_score=90, recommended_actions=_RANSOMWARE_ACTIONS)
        result = agent.run(case, mock_audit)

        assert result["halted"]             is True
        assert result["successful_actions"] == 0

    def test_result_has_all_required_keys(self, mock_audit):
        agent  = _make_mock_agent()
        case   = _make_case(risk_score=90, recommended_actions=_RANSOMWARE_ACTIONS)
        result = agent.run(case, mock_audit)

        required = {
            "case_id", "executor_mode", "risk_score", "actions",
            "total_actions", "successful_actions", "failed_actions",
            "skipped_actions", "halted", "halt_reason", "duration_seconds",
        }
        assert required <= set(result.keys())

    def test_isolate_host_result_has_correct_rollback_timer(
        self, mock_audit
    ):
        actions = [
            {"priority": 1, "action": "isolate_host", "target": "HOST",
             "justification": "test", "urgency": "immediate"},
        ]
        agent  = _make_mock_agent()
        case   = _make_case(risk_score=90, recommended_actions=actions)
        result = agent.run(case, mock_audit)

        isolate = next(
            a for a in result["actions"] if a["action_type"] == "isolate_host"
        )
        assert isolate["rollback_timer"]     == _DEFAULT_ROLLBACK["isolate_host"]
        assert isolate["rollback_scheduled"] != ""

    def test_kill_process_result_has_no_rollback(self, mock_audit):
        actions = [
            {"priority": 1, "action": "kill_process", "target": "HOST:6201",
             "justification": "malicious process", "urgency": "immediate"},
        ]
        agent  = _make_mock_agent()
        case   = _make_case(risk_score=90, recommended_actions=actions)
        result = agent.run(case, mock_audit)

        kill = next(
            a for a in result["actions"] if a["action_type"] == "kill_process"
        )
        assert kill["rollback_timer"]     == 0
        assert kill["rollback_scheduled"] == ""

    def test_rate_limiter_blocks_11th_action(self, mock_audit):
        agent = _make_mock_agent()
        # Pre-fill rate limiter
        for _ in range(_RATE_LIMIT_ACTIONS):
            agent._rate_limiter.check_and_record()

        actions = [
            {"priority": 1, "action": "isolate_host", "target": "HOST",
             "justification": "test", "urgency": "immediate"},
        ]
        case   = _make_case(risk_score=90, recommended_actions=actions)
        result = agent.run(case, mock_audit)

        # Action should be skipped due to rate limit
        assert result["skipped_actions"] >= 1
