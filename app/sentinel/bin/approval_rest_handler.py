"""
SENTINEL: Autonomous Agentic SOC Commander
approval_rest_handler.py — REST endpoints for the human-approval gate

Implements the surface the War Room dashboard, Slack interactive callbacks,
and any external SOAR/ChatOps integration use to participate in the
human-in-the-loop approval workflow run by ``approval_gate.ApprovalGate``:

    POST /services/sentinel/approval/request               → create a request
    POST /services/sentinel/approval/respond               → record a response
                                                              (Slack callback or
                                                              generic JSON body)
    GET  /services/sentinel/approval/pending               → list pending requests
    POST /services/sentinel/approval/<request_id>/approve  → direct approval
    POST /services/sentinel/approval/<request_id>/deny     → direct denial

Registered via restmap.conf, e.g.::

    [script:sentinel_approval]
    match                 = /sentinel/approval
    script                = approval_rest_handler.py
    scripttype            = persist
    handler               = approval_rest_handler.ApprovalRestHandler
    requireAuthentication = true
    output_modes          = json
    passPayload           = true
    passSystemAuth        = true

This module performs no analysis of its own — it is a thin, fully-tested
translation layer over ``ApprovalGate`` (see approval_gate.py for the actual
routing/notification/timeout logic), so the dashboard and Slack can drive the
exact same gate the Executor blocks on.

Dependencies: standard library, approval_gate.ApprovalGate, utils.state_manager
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, Optional

from approval_gate import ApprovalGate, get_approval_gate
from webhooks.slack_notifier import SlackNotifier
from utils.state_manager import CaseStateManager
from audit_logger import get_audit_logger

log = logging.getLogger("sentinel.approval_rest_handler")


# ---------------------------------------------------------------------------
# Core handlers — framework-independent, directly unit-testable
# ---------------------------------------------------------------------------

def create_approval_request(gate: ApprovalGate, body: Dict[str, Any]) -> Dict[str, Any]:
    """
    POST /services/sentinel/approval/request

    Body: { case_id, action, target, justification, confidence_score,
            timeout_seconds?, requested_by? }

    NOTE: ``ApprovalGate.request_approval`` *blocks* until the gate resolves
    (auto-decision, human response, or timeout) — exactly what Executor relies
    on. Exposing it over REST is what lets external systems (and the test
    suite) drive the same code path the agent does.
    """
    required = ("case_id", "action", "target", "confidence_score")
    missing = [f for f in required if f not in body]
    if missing:
        return {"error": f"Missing required field(s): {', '.join(missing)}"}

    kwargs: Dict[str, Any] = {
        "case_id":          str(body["case_id"]),
        "action_type":      str(body["action"]),
        "target":           str(body["target"]),
        "justification":    str(body.get("justification", "")),
        "confidence_score": int(body["confidence_score"]),
    }
    if "timeout_seconds" in body:
        kwargs["timeout_seconds"] = int(body["timeout_seconds"])
    if "requested_by" in body:
        kwargs["requested_by"] = str(body["requested_by"])

    return gate.request_approval(**kwargs)


def respond_to_approval(gate: ApprovalGate, body: Dict[str, Any]) -> Dict[str, Any]:
    """
    POST /services/sentinel/approval/respond

    Accepts either:
      - a generic JSON body: { request_id, response, responder_id }
      - a Slack interactive-message callback (form-encoded ``payload=<json>``
        or already-decoded dict with an ``actions`` array)
    """
    parsed = body
    if "request_id" not in parsed or "response" not in parsed:
        slack_parsed = SlackNotifier.parse_interactive_callback(body)
        if slack_parsed.get("request_id"):
            parsed = slack_parsed

    request_id   = str(parsed.get("request_id", ""))
    response     = str(parsed.get("response", ""))
    responder_id = str(parsed.get("responder_id") or parsed.get("user_id") or "unknown")

    if not request_id or not response:
        return {"error": "request_id and response are required (or a valid Slack callback payload)."}

    return gate.process_approval_response(request_id=request_id, response=response, responder_id=responder_id)


def list_pending_approvals(gate: ApprovalGate) -> Dict[str, Any]:
    """GET /services/sentinel/approval/pending"""
    pending = gate.get_pending_approvals()
    return {"pending": pending, "count": len(pending)}


def direct_decision(gate: ApprovalGate, request_id: str, decision: str, body: Dict[str, Any]) -> Dict[str, Any]:
    """
    POST /services/sentinel/approval/<request_id>/approve
    POST /services/sentinel/approval/<request_id>/deny

    ``decision`` is "YES" (approve) or "NO" (deny). ``body`` may carry
    ``responder_id`` / ``approved_by`` to attribute the decision to an analyst.
    """
    responder_id = str(body.get("responder_id") or body.get("approved_by") or body.get("denied_by") or "analyst")
    return gate.process_approval_response(request_id=request_id, response=decision, responder_id=responder_id)


# ---------------------------------------------------------------------------
# Splunk persistent REST handler glue
# ---------------------------------------------------------------------------

try:
    from splunk.persistconn.application import PersistentServerConnectionApplication
except ImportError:                                            # pragma: no cover
    class PersistentServerConnectionApplication:               # type: ignore
        def __init__(self, *_args: Any, **_kwargs: Any) -> None:
            pass


class ApprovalRestHandler(PersistentServerConnectionApplication):
    """Splunk persistent REST handler for the ``/sentinel/approval/*`` surface."""

    def __init__(self, command_line: str, command_arg: str) -> None:
        super().__init__()
        self._state_manager: Optional[CaseStateManager] = None
        self._gate: Optional[ApprovalGate] = None

    def _get_gate(self) -> ApprovalGate:
        if self._gate is None:
            if self._state_manager is None:
                self._state_manager = CaseStateManager()
            self._gate = get_approval_gate(state_manager=self._state_manager, audit=get_audit_logger("approval_gate"))
        return self._gate

    def handle(self, in_string: str) -> Dict[str, Any]:
        try:
            request = json.loads(in_string) if in_string else {}
        except (TypeError, ValueError):
            request = {}

        method = str(request.get("method") or "GET").upper()
        segments = self._path_segments(request)
        body = self._extract_body(request)
        gate = self._get_gate()

        try:
            return self._route(method, segments, body, gate)
        except Exception as exc:
            log.exception("Approval REST handler error (method=%s path=%s)", method, segments)
            return self._json_response(500, {"error": f"Internal error: {exc}"})

    # ------------------------------------------------------------------
    # Routing
    # ------------------------------------------------------------------

    def _route(self, method: str, segments: list, body: Dict[str, Any], gate: ApprovalGate) -> Dict[str, Any]:
        # Strip the leading "approval" segment if present (restmap match prefix)
        tail = [s for s in segments if s.lower() != "approval"]

        if not tail:
            return self._json_response(404, {"error": "approval endpoint required: request | respond | pending | <request_id>/approve|deny"})

        head = tail[0].lower()

        if head == "request" and method == "POST":
            result = create_approval_request(gate, body)
            status = 400 if "error" in result else 200
            return self._json_response(status, result)

        if head == "respond" and method == "POST":
            result = respond_to_approval(gate, body)
            status = 400 if "error" in result else 200
            return self._json_response(status, result)

        if head == "pending" and method == "GET":
            return self._json_response(200, list_pending_approvals(gate))

        if len(tail) == 2 and tail[1].lower() in ("approve", "deny") and method == "POST":
            request_id = tail[0]
            decision = "YES" if tail[1].lower() == "approve" else "NO"
            result = direct_decision(gate, request_id, decision, body)
            status = 400 if "error" in result else 200
            return self._json_response(status, result)

        return self._json_response(
            404,
            {"error": "Unknown approval endpoint or method.",
             "available": [
                 "POST /services/sentinel/approval/request",
                 "POST /services/sentinel/approval/respond",
                 "GET  /services/sentinel/approval/pending",
                 "POST /services/sentinel/approval/<request_id>/approve",
                 "POST /services/sentinel/approval/<request_id>/deny",
             ]},
        )

    # ------------------------------------------------------------------
    # Request parsing helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _path_segments(request: Dict[str, Any]) -> list:
        path = str(request.get("path") or request.get("rest_path") or "")
        return [seg for seg in path.split("/") if seg]

    @staticmethod
    def _extract_body(request: Dict[str, Any]) -> Dict[str, Any]:
        """Decode the JSON request body (Splunk persistconn ``payload`` field)."""
        raw = request.get("payload")
        if raw is None:
            return {}
        if isinstance(raw, dict):
            return raw
        if isinstance(raw, (str, bytes)):
            try:
                decoded = json.loads(raw)
                return decoded if isinstance(decoded, dict) else {}
            except (TypeError, ValueError):
                return {}
        return {}

    @staticmethod
    def _json_response(status: int, payload: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "status":  status,
            "headers": {"Content-Type": "application/json"},
            "payload": json.dumps(payload),
        }
