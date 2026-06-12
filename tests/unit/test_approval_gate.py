"""
Unit tests for the SENTINEL human-in-the-loop approval gate.

Covers:
  - ApprovalGate.request_approval confidence-score routing
      (AUTO_APPROVE / CONTAINMENT_APPROVED / MONITORING_ONLY / DOCUMENT_ONLY)
  - The full human-approval workflow: request -> notify -> respond -> resolve
  - Fail-safe timeout-default-deny behavior
  - SlackNotifier message/callback formatting
  - EmailNotifier HTML/text template rendering and reply parsing

Runs without a live Splunk/Slack/SMTP — DEMO_MODE notifiers are used
throughout and `demo_auto_respond` is disabled where the test drives the
response itself.
"""

from __future__ import annotations

import sys
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest

_BIN = Path(__file__).resolve().parent.parent.parent / "app" / "sentinel" / "bin"
if str(_BIN) not in sys.path:
    sys.path.insert(0, str(_BIN))

from approval_gate import ApprovalGate, ApprovalStatus, GateDecision, _classify, _risk_level_for
from webhooks.slack_notifier import SlackNotifier
from webhooks.email_notifier import EmailNotifier


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_gate(**overrides):
    defaults = dict(
        state_manager=None,
        audit=MagicMock(),
        slack=SlackNotifier(demo_mode=True),
        email=EmailNotifier(demo_mode=True, recipients=["soc-oncall@company.com"]),
        demo_mode=True,
        demo_auto_respond=False,
        poll_interval_s=0.05,
    )
    defaults.update(overrides)
    return ApprovalGate(**defaults)


_SAMPLE_PAYLOAD = {
    "case_id":          "SEN-001",
    "request_id":       "REQ-ABCD1234",
    "action":           "disable_user",
    "target":           "jdoe",
    "justification":    "Compromised credentials used for LockBit 3.0 initial access. "
                        "Sherlock found impossible travel (Romania vs NYC).",
    "confidence_score": 97,
    "risk_level":       "CRITICAL",
    "requested_by":     "ExecutorAgent",
    "requested_at":     "2026-06-05T02:48:00Z",
    "expires_at":       "2026-06-05T02:53:00Z",
    "approval_url":     "https://sentinel.local/approve/REQ-ABCD1234",
    "approve_command":  "Reply YES to approve",
    "deny_command":     "Reply NO to deny",
    "status":           "PENDING",
}


# ---------------------------------------------------------------------------
# Confidence-score routing
# ---------------------------------------------------------------------------

class TestRouting:

    def test_classify_thresholds(self):
        assert _classify(100) == GateDecision.AUTO_APPROVE
        assert _classify(85)  == GateDecision.AUTO_APPROVE
        assert _classify(84)  == GateDecision.CONTAINMENT_APPROVED
        assert _classify(70)  == GateDecision.CONTAINMENT_APPROVED
        assert _classify(69)  == GateDecision.MONITORING_ONLY
        assert _classify(55)  == GateDecision.MONITORING_ONLY
        assert _classify(54)  == GateDecision.DOCUMENT_ONLY
        assert _classify(0)   == GateDecision.DOCUMENT_ONLY

    def test_risk_level_mapping(self):
        assert _risk_level_for(95) == "CRITICAL"
        assert _risk_level_for(75) == "HIGH"
        assert _risk_level_for(60) == "MEDIUM"
        assert _risk_level_for(20) == "LOW"

    def test_auto_approve_high_confidence_skips_human(self):
        gate = _make_gate()
        result = gate.request_approval(
            case_id="SEN-100", action_type="isolate_host", target="WIN-PC-01",
            justification="High-confidence ransomware detection.", confidence_score=97,
        )
        assert result["gate_decision"] == "AUTO_APPROVE"
        assert result["approval_required"] is False
        assert result["approved"] is True
        assert result["status"] == ApprovalStatus.AUTO_APPROVED.value
        assert result["request_id"] is None
        assert gate.get_pending_approvals() == []

    def test_containment_approved_non_eradication_auto_approved(self):
        """Isolate/block actions in the 70-84 band proceed without a human."""
        gate = _make_gate()
        result = gate.request_approval(
            case_id="SEN-101", action_type="isolate_host", target="WIN-PC-02",
            justification="Lateral movement detected.", confidence_score=77,
        )
        assert result["gate_decision"] == "CONTAINMENT_APPROVED"
        assert result["approval_required"] is False
        assert result["approved"] is True
        assert result["request_id"] is None

    def test_monitoring_only_band_no_action_no_human(self):
        gate = _make_gate()
        result = gate.request_approval(
            case_id="SEN-102", action_type="disable_user", target="bsmith",
            justification="Suspicious but inconclusive.", confidence_score=62,
        )
        assert result["gate_decision"] == "MONITORING_ONLY"
        assert result["approval_required"] is False
        assert result["approved"] is False
        assert result["request_id"] is None

    def test_document_only_band_logs_only(self):
        gate = _make_gate()
        result = gate.request_approval(
            case_id="SEN-103", action_type="disable_user", target="agreen",
            justification="Low-confidence anomaly.", confidence_score=40,
        )
        assert result["gate_decision"] == "DOCUMENT_ONLY"
        assert result["approval_required"] is False
        assert result["approved"] is False


# ---------------------------------------------------------------------------
# Human-approval workflow — eradication actions in the 70-84 band
# ---------------------------------------------------------------------------

class TestHumanApprovalWorkflow:

    def _start_request(self, gate, **kwargs):
        """Run request_approval (which blocks) on a background thread."""
        holder = {}
        def _run():
            holder["result"] = gate.request_approval(**kwargs)
        t = threading.Thread(target=_run, daemon=True)
        t.start()
        return t, holder

    def _await_pending(self, gate, timeout=2.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            pending = gate.get_pending_approvals()
            if pending:
                return pending[0]
            time.sleep(0.02)
        raise AssertionError("No pending approval request appeared in time")

    def test_eradication_action_requires_human_approval(self):
        gate = _make_gate()
        t, holder = self._start_request(
            gate, case_id="SEN-001", action_type="disable_user", target="jdoe",
            justification="Compromised credentials used for LockBit 3.0 initial access.",
            confidence_score=77, timeout_seconds=10,
        )
        pending = self._await_pending(gate)
        assert pending["case_id"] == "SEN-001"
        assert pending["action"] == "disable_user"
        assert pending["status"] == ApprovalStatus.PENDING.value
        assert pending["request_id"].startswith("REQ-")

        resp = gate.process_approval_response(pending["request_id"], "YES", "analyst.jane")
        assert resp["status"] == ApprovalStatus.APPROVED.value
        assert resp["responder_id"] == "analyst.jane"

        t.join(timeout=5)
        result = holder["result"]
        assert result["approval_required"] is True
        assert result["approved"] is True
        assert result["status"] == ApprovalStatus.APPROVED.value
        assert result["responder_id"] == "analyst.jane"
        assert gate.get_pending_approvals() == []

    def test_human_denial_cancels_action(self):
        gate = _make_gate()
        t, holder = self._start_request(
            gate, case_id="SEN-002", action_type="rotate_credentials", target="svc-account",
            justification="Possible credential theft.", confidence_score=80, timeout_seconds=10,
        )
        pending = self._await_pending(gate)

        resp = gate.process_approval_response(pending["request_id"], "NO", "analyst.bob")
        assert resp["status"] == ApprovalStatus.DENIED.value

        t.join(timeout=5)
        result = holder["result"]
        assert result["approved"] is False
        assert result["status"] == ApprovalStatus.DENIED.value
        assert result["timeout_expired"] is False
        assert "denied" in result["reason"].lower()

    def test_response_normalisation_accepts_synonyms(self):
        gate = _make_gate()
        t, holder = self._start_request(
            gate, case_id="SEN-003", action_type="quarantine_file", target="C:\\evil.exe",
            justification="Confirmed malware binary.", confidence_score=72, timeout_seconds=10,
        )
        pending = self._await_pending(gate)
        resp = gate.process_approval_response(pending["request_id"], "approved", "analyst.amy")
        assert resp["status"] == ApprovalStatus.APPROVED.value
        t.join(timeout=5)
        assert holder["result"]["approved"] is True

    def test_unknown_request_id_returns_error(self):
        gate = _make_gate()
        resp = gate.process_approval_response("REQ-DOESNOTEXIST", "YES", "analyst")
        assert "error" in resp

    def test_double_response_returns_error(self):
        gate = _make_gate()
        t, holder = self._start_request(
            gate, case_id="SEN-004", action_type="disable_user", target="mlee",
            justification="Confirmed compromise.", confidence_score=78, timeout_seconds=10,
        )
        pending = self._await_pending(gate)
        first = gate.process_approval_response(pending["request_id"], "YES", "analyst.a")
        assert first["status"] == ApprovalStatus.APPROVED.value
        second = gate.process_approval_response(pending["request_id"], "NO", "analyst.b")
        assert "error" in second
        t.join(timeout=5)

    def test_cancel_pending_approval(self):
        gate = _make_gate()
        t, holder = self._start_request(
            gate, case_id="SEN-005", action_type="disable_user", target="kgray",
            justification="Investigation ongoing.", confidence_score=74, timeout_seconds=10,
        )
        pending = self._await_pending(gate)
        cancelled = gate.cancel_approval(pending["request_id"], cancelled_by="orchestrator")
        assert cancelled["status"] == ApprovalStatus.CANCELLED.value

        t.join(timeout=5)
        result = holder["result"]
        assert result["approved"] is False
        assert result["status"] == ApprovalStatus.CANCELLED.value


# ---------------------------------------------------------------------------
# Fail-safe timeout behavior — default to DENY
# ---------------------------------------------------------------------------

class TestTimeoutBehavior:

    def test_timeout_defaults_to_deny(self):
        gate = _make_gate()
        t0 = time.time()
        result = gate.request_approval(
            case_id="SEN-200", action_type="disable_user", target="jdoe",
            justification="Needs sign-off but nobody responds.",
            confidence_score=77, timeout_seconds=1,
        )
        elapsed = time.time() - t0

        assert result["approval_required"] is True
        assert result["approved"] is False
        assert result["status"] == ApprovalStatus.TIMEOUT_DENIED.value
        assert result["timeout_expired"] is True
        assert "timed out" in result["reason"].lower() or "fail-safe" in result["reason"].lower()
        assert elapsed >= 1.0
        assert gate.get_pending_approvals() == []

    def test_timeout_writes_audit_trail(self):
        audit = MagicMock()
        gate = _make_gate(audit=audit)
        gate.request_approval(
            case_id="SEN-201", action_type="disable_user", target="asmith",
            justification="No response expected.", confidence_score=77, timeout_seconds=1,
        )
        decisions = [c.kwargs.get("decision") for c in audit.log_approval.call_args_list]
        assert ApprovalStatus.PENDING.value in decisions
        assert ApprovalStatus.TIMEOUT_DENIED.value in decisions

        timeout_call = next(c for c in audit.log_approval.call_args_list
                            if c.kwargs.get("decision") == ApprovalStatus.TIMEOUT_DENIED.value)
        assert timeout_call.kwargs["timeout_expired"] is True
        assert timeout_call.kwargs["case_id"] == "SEN-201"
        assert timeout_call.kwargs["action"] == "disable_user"


# ---------------------------------------------------------------------------
# Demo-mode auto-response simulation
# ---------------------------------------------------------------------------

class TestDemoModeSimulation:

    def test_demo_mode_simulates_a_response(self):
        gate = _make_gate(demo_auto_respond=True, demo_response="YES", demo_response_delay_s=0.1)
        result = gate.request_approval(
            case_id="SEN-300", action_type="disable_user", target="jdoe",
            justification="Demo flow.", confidence_score=77, timeout_seconds=10,
        )
        assert result["approved"] is True
        assert result["status"] == ApprovalStatus.APPROVED.value
        assert result["responder_id"] == "demo-analyst"


# ---------------------------------------------------------------------------
# SlackNotifier — message formatting + interactive callback parsing
# ---------------------------------------------------------------------------

class TestSlackNotifier:

    def test_demo_mode_when_no_webhook_configured(self):
        notifier = SlackNotifier(webhook_url="")
        assert notifier.demo_mode is True

    def test_build_message_contains_required_elements(self):
        notifier = SlackNotifier(demo_mode=True)
        message = notifier.build_message(_SAMPLE_PAYLOAD)

        assert "SEN-001" in message["text"]
        blocks = message["blocks"]

        header = blocks[0]
        assert header["type"] == "header"
        assert "Approval Required" in header["text"]["text"]
        assert "SEN-001" in header["text"]["text"]

        fields_block = next(b for b in blocks if b.get("type") == "section" and "fields" in b)
        field_text = " ".join(f["text"] for f in fields_block["fields"])
        assert "disable_user" in field_text
        assert "jdoe" in field_text
        assert "97%" in field_text
        assert "CRITICAL" in field_text

        actions_block = next(b for b in blocks if b["type"] == "actions")
        action_ids = [el["action_id"] for el in actions_block["elements"]]
        assert "sentinel_approve" in action_ids
        assert "sentinel_deny" in action_ids
        assert "sentinel_view_case" in action_ids

        footer = blocks[-1]
        assert "Expires in 5 minutes" in footer["elements"][0]["text"]
        assert "ExecutorAgent" in footer["elements"][0]["text"]

    def test_send_approval_request_demo_mode_does_not_call_network(self, capsys):
        notifier = SlackNotifier(demo_mode=True)
        result = notifier.send_approval_request(_SAMPLE_PAYLOAD)
        assert result["ok"] is True
        assert result["demo_mode"] is True
        captured = capsys.readouterr()
        assert "DEMO" in captured.out
        assert "SEN-001" in captured.out

    def test_parse_interactive_callback_extracts_decision(self):
        raw = {
            "type": "block_actions",
            "user": {"id": "U123ABC", "username": "analyst.jane"},
            "actions": [
                {"action_id": "sentinel_approve", "value": '{"request_id": "REQ-ABCD1234", "response": "YES"}'}
            ],
        }
        parsed = SlackNotifier.parse_interactive_callback(raw)
        assert parsed == {"request_id": "REQ-ABCD1234", "response": "YES", "responder_id": "U123ABC"}

    def test_parse_interactive_callback_handles_form_wrapper(self):
        import json
        wrapper = {"payload": json.dumps({
            "user": {"id": "U999"},
            "actions": [{"action_id": "sentinel_deny", "value": '{"request_id": "REQ-XYZ", "response": "NO"}'}],
        })}
        parsed = SlackNotifier.parse_interactive_callback(wrapper)
        assert parsed["request_id"] == "REQ-XYZ"
        assert parsed["response"] == "NO"
        assert parsed["responder_id"] == "U999"

    def test_parse_interactive_callback_returns_empty_for_garbage(self):
        assert SlackNotifier.parse_interactive_callback("not json") == {}
        assert SlackNotifier.parse_interactive_callback({"nothing": "useful"}) == {}


# ---------------------------------------------------------------------------
# EmailNotifier — template rendering + reply parsing
# ---------------------------------------------------------------------------

class TestEmailNotifier:

    def test_demo_mode_when_no_smtp_host_configured(self):
        notifier = EmailNotifier(smtp_host="")
        assert notifier.demo_mode is True

    def test_render_html_contains_required_fields(self):
        notifier = EmailNotifier(demo_mode=True, recipients=["soc-oncall@company.com"])
        html = notifier.render_html(_SAMPLE_PAYLOAD)
        assert "SEN-001" in html
        assert "disable_user" in html
        assert "jdoe" in html
        assert "97%" in html
        assert "CRITICAL" in html
        assert "Approve" in html and "Deny" in html

    def test_render_text_contains_required_fields(self):
        notifier = EmailNotifier(demo_mode=True, recipients=["soc-oncall@company.com"])
        text = notifier.render_text(_SAMPLE_PAYLOAD)
        assert "SEN-001" in text
        assert "disable_user -> jdoe" in text
        assert "Reply YES to approve or NO to deny" in text

    def test_build_message_sets_headers(self):
        notifier = EmailNotifier(demo_mode=True, recipients=["soc-oncall@company.com", "ciso@company.com"])
        msg = notifier.build_message(_SAMPLE_PAYLOAD)
        assert "SEN-001" in msg["Subject"]
        assert msg["To"] == "soc-oncall@company.com, ciso@company.com"

    def test_send_approval_request_demo_mode_does_not_open_smtp(self, capsys):
        notifier = EmailNotifier(demo_mode=True, recipients=["soc-oncall@company.com"])
        result = notifier.send_approval_request(_SAMPLE_PAYLOAD)
        assert result["ok"] is True
        assert result["demo_mode"] is True
        captured = capsys.readouterr()
        assert "DEMO" in captured.out
        assert "SEN-001" in captured.out

    @pytest.mark.parametrize("body,expected", [
        ("YES\n\n> original message", "YES"),
        ("yes, approve this", "YES"),
        ("APPROVE - go ahead", "YES"),
        ("NO - do not do this", "NO"),
        ("deny\nplease escalate instead", "NO"),
        ("Hmm, not sure about this one", None),
        ("", None),
    ])
    def test_parse_reply_extracts_decision(self, body, expected):
        assert EmailNotifier.parse_reply(body) == expected
