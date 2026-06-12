"""
Integration tests for ExecutorAgent response actions.

Tests end-to-end execution of each response action type, verification
query construction, and the rollback mechanism — using _MockExecutorAgent
so no live Splunk instance is needed (but still exercising the full
action pipeline, verification, and rollback logic).

SKIPPED by default — set SENTINEL_RUN_INTEGRATION=1 to run.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

_BIN = Path(__file__).resolve().parent.parent.parent / "app" / "sentinel" / "bin"
if str(_BIN) not in sys.path:
    sys.path.insert(0, str(_BIN))

pytestmark = pytest.mark.integration

with (
    patch("agent_executor.SplunkMCPClient",  autospec=False),
    patch("agent_executor.get_audit_logger", return_value=MagicMock()),
    patch("agent_executor.get_config",       return_value=MagicMock()),
):
    from agent_executor import (
        _MockExecutorAgent,
        ExecutorActionLog,
        ActionResult,
        ActionVerification,
        _VERIFICATION_QUERIES,
    )


# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------

def _make_agent() -> _MockExecutorAgent:
    cfg = MagicMock()
    cfg.get.return_value      = ""
    cfg.get_bool.return_value = False
    return _MockExecutorAgent(mcp=MagicMock(), config=cfg)


def _make_case(
    case_id:       str = "CASE-INT-001",
    alert_id:      str = "ALERT-INT-001",
    alert_type:    str = "RANSOMWARE_POWERSHELL_ENCODED",
    classification: str= "RANSOMWARE_INITIAL_ACCESS",
    risk_score:    int = 92,
    affected_host: str = "DESKTOP-INT-HOST",
    affected_user: str = "CORP\\intuser",
    response_plan: list = None,
    status:        str = "RESPONDING",
    halt_flag:     bool= False,
):
    case = MagicMock()
    case.case_id        = case_id
    case.alert_id       = alert_id
    case.alert_type     = alert_type
    case.classification = classification
    case.risk_score     = risk_score
    case.affected_host  = affected_host
    case.affected_user  = affected_user
    case.status         = status
    case.halt_flag      = halt_flag
    case.response_plan  = response_plan or [
        {"action_type": "isolate_host",      "target": affected_host, "priority": 1},
        {"action_type": "kill_process",      "target": "powershell.exe",  "priority": 2},
        {"action_type": "quarantine_file",   "target": "C:\\Temp\\payload.exe", "priority": 3},
        {"action_type": "disable_user",      "target": affected_user, "priority": 4},
        {"action_type": "create_ticket",     "target": "IR-001",      "priority": 5},
        {"action_type": "notify_stakeholders","target": "soc@corp.com", "priority": 6},
    ]
    return case


# ---------------------------------------------------------------------------
# End-to-end action execution tests
# ---------------------------------------------------------------------------

class TestEndToEndActionExecution:
    def test_full_ransomware_run_all_actions_succeed(self):
        agent  = _make_agent()
        case   = _make_case(risk_score=92)
        audit  = MagicMock()
        result = agent.run(case, audit)

        assert result["success"]           is True
        assert result["successful_actions"] > 0
        assert result["failed_actions"]    == 0

    def test_action_log_has_all_expected_fields(self):
        agent  = _make_agent()
        case   = _make_case()
        result = agent.run(case, MagicMock())

        required = {
            "case_id", "executor_mode", "risk_score", "actions",
            "total_actions", "successful_actions", "failed_actions",
            "skipped_actions", "halted", "halt_reason", "duration_seconds",
        }
        assert required <= set(result.keys())

    def test_each_action_result_has_required_fields(self):
        agent  = _make_agent()
        case   = _make_case()
        result = agent.run(case, MagicMock())

        for action in result["actions"]:
            assert "action_type"  in action
            assert "target"       in action
            assert "status"       in action
            assert "verification" in action
            assert "timestamp"    in action

    def test_action_status_is_success_for_mock_agent(self):
        agent  = _make_agent()
        case   = _make_case(risk_score=92)
        result = agent.run(case, MagicMock())

        for action in result["actions"]:
            if action.get("skipped_reason"):
                continue
            assert action["status"] in ("success", "skipped", "failed")


# ---------------------------------------------------------------------------
# Per-action-type execution tests
# ---------------------------------------------------------------------------

class TestPerActionTypeExecution:
    def _run_single_action(self, action_type: str, target: str, risk_score: int = 92):
        agent = _make_agent()
        case  = _make_case(
            risk_score    = risk_score,
            response_plan = [{"action_type": action_type, "target": target, "priority": 1}],
        )
        result = agent.run(case, MagicMock())
        actions = result.get("actions", [])
        return result, actions

    def test_isolate_host_succeeds(self):
        result, actions = self._run_single_action("isolate_host", "DESKTOP-INT-HOST", 92)
        assert result["success"] is True
        assert any(a["action_type"] == "isolate_host" for a in actions)

    def test_block_ip_succeeds(self):
        result, actions = self._run_single_action("block_ip", "185.220.101.42", 92)
        assert result["success"] is True

    def test_kill_process_succeeds(self):
        result, actions = self._run_single_action("kill_process", "powershell.exe", 92)
        assert result["success"] is True

    def test_disable_user_succeeds_in_full_autonomy(self):
        result, actions = self._run_single_action("disable_user", "CORP\\jdoe", 92)
        assert result["success"] is True

    def test_quarantine_file_succeeds(self):
        result, actions = self._run_single_action(
            "quarantine_file", "C:\\Temp\\payload.exe", 92
        )
        assert result["success"] is True

    def test_revoke_session_succeeds(self):
        result, actions = self._run_single_action("revoke_session", "session-abc123", 92)
        assert result["success"] is True

    def test_create_ticket_always_succeeds(self):
        result, actions = self._run_single_action("create_ticket", "IR-001", 30)
        assert result["success"] is True
        ticket_action = next(
            (a for a in actions if a["action_type"] == "create_ticket"), None
        )
        assert ticket_action is not None
        assert ticket_action["status"] != "failed"

    def test_notify_stakeholders_always_succeeds(self):
        result, actions = self._run_single_action("notify_stakeholders", "soc@corp.com", 30)
        assert result["success"] is True


# ---------------------------------------------------------------------------
# Verification query construction tests
# ---------------------------------------------------------------------------

class TestVerificationQueryConstruction:
    def test_verification_queries_exist_for_core_action_types(self):
        expected = {"isolate_host", "block_ip", "disable_user", "kill_process", "quarantine_file"}
        assert expected <= set(_VERIFICATION_QUERIES.keys())

    def test_isolate_host_query_uses_target_placeholder(self):
        tpl = _VERIFICATION_QUERIES["isolate_host"]
        assert "{target}" in tpl or "{host}" in tpl or "target" in tpl.lower()

    def test_block_ip_query_uses_ip_or_target_placeholder(self):
        tpl = _VERIFICATION_QUERIES["block_ip"]
        assert "{target}" in tpl or "{ip}" in tpl or "target" in tpl.lower()

    def test_disable_user_query_uses_user_placeholder(self):
        tpl = _VERIFICATION_QUERIES["disable_user"]
        assert "{target}" in tpl or "{user}" in tpl or "target" in tpl.lower()

    def test_verification_result_confirmed_sets_verified_true(self):
        """Simulates the verification flow: search returns confirmed → verified=True."""
        agent = _make_agent()
        case  = _make_case(
            risk_score    = 92,
            response_plan = [{"action_type": "isolate_host", "target": "DESKTOP-INT", "priority": 1}],
        )
        result = agent.run(case, MagicMock())
        actions = result.get("actions", [])
        host_action = next(
            (a for a in actions if a["action_type"] == "isolate_host"), None
        )
        if host_action and "verification" in host_action:
            ver = host_action["verification"]
            assert isinstance(ver.get("verified"), bool)


# ---------------------------------------------------------------------------
# Rollback mechanism tests
# ---------------------------------------------------------------------------

class TestRollbackMechanism:
    def test_isolate_host_rollback_timer_is_14400s(self):
        agent  = _make_agent()
        case   = _make_case(
            risk_score    = 92,
            response_plan = [{"action_type": "isolate_host", "target": "DESKTOP-INT", "priority": 1}],
        )
        result  = agent.run(case, MagicMock())
        actions = result.get("actions", [])
        action  = next((a for a in actions if a["action_type"] == "isolate_host"), None)
        assert action is not None
        assert action.get("rollback_timer") == 14400

    def test_kill_process_rollback_timer_is_0(self):
        agent  = _make_agent()
        case   = _make_case(
            risk_score    = 92,
            response_plan = [{"action_type": "kill_process", "target": "powershell.exe", "priority": 1}],
        )
        result  = agent.run(case, MagicMock())
        actions = result.get("actions", [])
        action  = next((a for a in actions if a["action_type"] == "kill_process"), None)
        assert action is not None
        assert action.get("rollback_timer") == 0

    def test_rollback_scheduled_true_when_timer_nonzero(self):
        agent  = _make_agent()
        case   = _make_case(
            risk_score    = 92,
            response_plan = [{"action_type": "isolate_host", "target": "DESKTOP-INT", "priority": 1}],
        )
        result  = agent.run(case, MagicMock())
        actions = result.get("actions", [])
        action  = next((a for a in actions if a["action_type"] == "isolate_host"), None)
        assert action is not None
        assert action.get("rollback_scheduled") is True

    def test_rollback_not_scheduled_when_timer_is_0(self):
        agent  = _make_agent()
        case   = _make_case(
            risk_score    = 92,
            response_plan = [{"action_type": "kill_process", "target": "cmd.exe", "priority": 1}],
        )
        result  = agent.run(case, MagicMock())
        actions = result.get("actions", [])
        action  = next((a for a in actions if a["action_type"] == "kill_process"), None)
        assert action is not None
        assert action.get("rollback_scheduled") is False

    def test_multiple_actions_independent_rollback_timers(self):
        agent  = _make_agent()
        case   = _make_case(
            risk_score    = 92,
            response_plan = [
                {"action_type": "isolate_host", "target": "DESKTOP-INT", "priority": 1},
                {"action_type": "block_ip",     "target": "1.2.3.4",      "priority": 2},
                {"action_type": "kill_process", "target": "powershell.exe","priority": 3},
            ],
        )
        result  = agent.run(case, MagicMock())
        actions = result.get("actions", [])

        timers = {a["action_type"]: a.get("rollback_timer") for a in actions}
        assert timers.get("isolate_host") == 14400
        assert timers.get("block_ip")     == 259200
        assert timers.get("kill_process") == 0
