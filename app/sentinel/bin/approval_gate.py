"""
SENTINEL: Autonomous Agentic SOC Commander
approval_gate.py — Human-in-the-loop approval workflow

Makes the "human-in-the-loop" gate a real, demonstrable workflow rather than
a bare ``if requires_approval`` check: every action ExecutorAgent wants to
take is routed through :class:`ApprovalGate`, which classifies it by
confidence score, and — for actions that need a human — fires real
Slack/email notifications (via ``webhooks.slack_notifier`` /
``webhooks.email_notifier``), waits for a response, and resolves the case
accordingly.

Confidence-score routing (mirrors ExecutorAgent's autonomy matrix):
    >= 85   AUTO_APPROVE        — no human needed, proceed immediately
    70-84   CONTAINMENT_APPROVED — isolate/block auto-approved; eradication
                                   actions require human sign-off
    55-69   MONITORING_ONLY     — no active response; notify only
    <  55   DOCUMENT_ONLY       — log only, no action, no notification

For an eradication action in the 70-84 band:
    1. An ``ApprovalRequest`` is generated (REQ-xxxxxxxx) with an
       ``expires_at`` ``timeout_seconds`` in the future (default 300s).
    2. The request is broadcast to every configured channel — Slack webhook,
       email distribution list (SMS/Teams are stubbed no-ops, logged only).
    3. The gate blocks (polling) until a response arrives or the timeout
       elapses:
         - approved  → action proceeds
         - denied    → action cancelled, case → CLOSED / resolution=HUMAN_DENIED
         - timeout   → fail-safe DENY, case → CLOSED / resolution=HUMAN_DENIED,
                       timeout_expired=True
    4. Every request, response, timeout and denial is written to
       ``sentinel_audit`` via ``AuditLogger.log_approval``.

DEMO_MODE: when no real Slack webhook URL / SMTP host is configured, the
notifiers print the formatted message to console/log instead of calling out,
and (unless disabled) the gate simulates a human response after a short
delay — so the entire flow is demonstrable without external credentials.

Dependencies: standard library, webhooks.slack_notifier, webhooks.email_notifier
"""

from __future__ import annotations

import logging
import os
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

_BIN_DIR = Path(__file__).resolve().parent
if str(_BIN_DIR) not in sys.path:
    sys.path.insert(0, str(_BIN_DIR))

from webhooks.slack_notifier import SlackNotifier
from webhooks.email_notifier import EmailNotifier

log = logging.getLogger("sentinel.approval_gate")

_ENV_APPROVAL_BASE_URL = "SENTINEL_APPROVAL_BASE_URL"
_DEFAULT_APPROVAL_BASE_URL = "https://sentinel.local/approve"

_DEFAULT_TIMEOUT_S      = 300       # 5 minutes — fail-safe default-deny window
_POLL_INTERVAL_S        = 0.5       # how often request_approval polls for a response
_DEMO_RESPONSE_DELAY_S  = 3.0       # DEMO_MODE: simulate a human response after this long

# Actions that ALWAYS require human sign-off in the CONTAINMENT_APPROVED band
# (mirrors agent_executor._ERADICATION_ACTIONS — irreversible / high-impact).
_ERADICATION_ACTIONS = {"disable_user", "quarantine_file", "revoke_session", "rotate_credentials"}


# ---------------------------------------------------------------------------
# Routing tiers / decisions
# ---------------------------------------------------------------------------

class GateDecision(str, Enum):
    AUTO_APPROVE         = "AUTO_APPROVE"
    CONTAINMENT_APPROVED = "CONTAINMENT_APPROVED"
    MONITORING_ONLY      = "MONITORING_ONLY"
    DOCUMENT_ONLY        = "DOCUMENT_ONLY"
    PENDING_APPROVAL     = "PENDING_APPROVAL"


class ApprovalStatus(str, Enum):
    PENDING        = "PENDING"
    APPROVED       = "APPROVED"
    DENIED         = "DENIED"
    TIMEOUT_DENIED = "TIMEOUT_DENIED"
    CANCELLED      = "CANCELLED"
    AUTO_APPROVED  = "AUTO_APPROVED"


def _risk_level_for(confidence_score: int) -> str:
    if confidence_score >= 85:
        return "CRITICAL"
    if confidence_score >= 70:
        return "HIGH"
    if confidence_score >= 55:
        return "MEDIUM"
    return "LOW"


def _classify(confidence_score: int) -> GateDecision:
    if confidence_score >= 85:
        return GateDecision.AUTO_APPROVE
    if confidence_score >= 70:
        return GateDecision.CONTAINMENT_APPROVED
    if confidence_score >= 55:
        return GateDecision.MONITORING_ONLY
    return GateDecision.DOCUMENT_ONLY


def _utc_iso(ts: Optional[float] = None) -> str:
    dt = datetime.fromtimestamp(ts, tz=timezone.utc) if ts is not None else datetime.now(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# Approval request record
# ---------------------------------------------------------------------------

@dataclass
class ApprovalRequest:
    request_id:       str
    case_id:          str
    action:           str
    target:           str
    justification:    str
    confidence_score: int
    risk_level:       str
    requested_by:     str
    requested_at:     float
    timeout_seconds:  int
    status:           str = ApprovalStatus.PENDING.value
    responder_id:     str = ""
    response:         str = ""
    decided_at:       Optional[float] = None
    timeout_expired:  bool = False
    notified_channels: List[str] = field(default_factory=list)

    @property
    def expires_at(self) -> float:
        return self.requested_at + self.timeout_seconds

    @property
    def approval_url(self) -> str:
        base = os.environ.get(_ENV_APPROVAL_BASE_URL, _DEFAULT_APPROVAL_BASE_URL)
        return f"{base.rstrip('/')}/{self.request_id}"

    def to_payload(self) -> Dict[str, Any]:
        """The wire-format approval payload broadcast to every channel."""
        return {
            "case_id":          self.case_id,
            "request_id":       self.request_id,
            "action":           self.action,
            "target":           self.target,
            "justification":    self.justification,
            "confidence_score": self.confidence_score,
            "risk_level":       self.risk_level,
            "requested_by":     self.requested_by,
            "requested_at":     _utc_iso(self.requested_at),
            "expires_at":       _utc_iso(self.expires_at),
            "approval_url":     self.approval_url,
            "approve_command":  "Reply YES to approve",
            "deny_command":     "Reply NO to deny",
            "status":           self.status,
        }

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["expires_at"]   = _utc_iso(self.expires_at)
        d["requested_at"] = _utc_iso(self.requested_at)
        d["decided_at"]   = _utc_iso(self.decided_at) if self.decided_at else None
        d["approval_url"] = self.approval_url
        d["seconds_remaining"] = max(0, int(self.expires_at - time.time()))
        return d


# ---------------------------------------------------------------------------
# ApprovalGate
# ---------------------------------------------------------------------------

class ApprovalGate:
    """
    Routes ExecutorAgent actions through confidence-based autonomy tiers and,
    for actions that need a human, runs the full notify → wait → resolve
    workflow with a real (or DEMO_MODE) Slack/email integration.
    """

    def __init__(
        self,
        state_manager: Optional[Any] = None,
        audit: Optional[Any] = None,
        slack: Optional[SlackNotifier] = None,
        email: Optional[EmailNotifier] = None,
        demo_mode: Optional[bool] = None,
        demo_auto_respond: bool = True,
        demo_response: str = "YES",
        demo_response_delay_s: float = _DEMO_RESPONSE_DELAY_S,
        poll_interval_s: float = _POLL_INTERVAL_S,
    ) -> None:
        self._state_manager = state_manager
        self._audit = audit

        self._slack = slack if slack is not None else SlackNotifier(demo_mode=demo_mode)
        self._email = email if email is not None else EmailNotifier(demo_mode=demo_mode)

        # Overall demo posture: true if either channel is in demo mode (or forced).
        self._demo_mode = self._slack.demo_mode or self._email.demo_mode if demo_mode is None else demo_mode
        self._demo_auto_respond     = demo_auto_respond
        self._demo_response         = demo_response
        self._demo_response_delay_s = demo_response_delay_s
        self._poll_interval_s       = poll_interval_s

        self._lock = threading.RLock()
        self._requests: Dict[str, ApprovalRequest] = {}

    # ------------------------------------------------------------------
    # Audit helper
    # ------------------------------------------------------------------

    def _log_audit(
        self,
        req: ApprovalRequest,
        decision: str,
        decision_time_ms: int = 0,
        timeout_expired: bool = False,
    ) -> None:
        if self._audit is None:
            return
        try:
            self._audit.log_approval(
                case_id=req.case_id,
                request_id=req.request_id,
                action=req.action,
                target=req.target,
                decision=decision,
                requester=req.requested_by,
                responder=req.responder_id,
                decision_time_ms=decision_time_ms,
                timeout_expired=timeout_expired,
                metadata={
                    "confidence_score": req.confidence_score,
                    "risk_level":       req.risk_level,
                    "justification":    req.justification,
                },
            )
        except Exception:
            log.exception("Failed to write approval audit event for %s", req.request_id)

    # ------------------------------------------------------------------
    # Auto-resolved (no human needed) results
    # ------------------------------------------------------------------

    @staticmethod
    def _auto_result(
        gate_decision: GateDecision,
        case_id: str,
        action_type: str,
        target: str,
        confidence_score: int,
        reason: str,
    ) -> Dict[str, Any]:
        return {
            "gate_decision":     gate_decision.value,
            "approval_required": False,
            "approved":          gate_decision in (GateDecision.AUTO_APPROVE, GateDecision.CONTAINMENT_APPROVED),
            "status":            (ApprovalStatus.AUTO_APPROVED.value
                                  if gate_decision in (GateDecision.AUTO_APPROVE, GateDecision.CONTAINMENT_APPROVED)
                                  else gate_decision.value),
            "case_id":           case_id,
            "action":            action_type,
            "target":            target,
            "confidence_score":  confidence_score,
            "risk_level":        _risk_level_for(confidence_score),
            "reason":            reason,
            "request_id":        None,
        }

    # ------------------------------------------------------------------
    # Public API — request_approval
    # ------------------------------------------------------------------

    def request_approval(
        self,
        case_id: str,
        action_type: str,
        target: str,
        justification: str,
        confidence_score: int,
        timeout_seconds: int = _DEFAULT_TIMEOUT_S,
        requested_by: str = "ExecutorAgent",
    ) -> Dict[str, Any]:
        """
        Classify the action by ``confidence_score`` and either auto-resolve it
        or run the full human-approval workflow (notify, wait, resolve).

        Returns a result dict always containing at minimum:
            gate_decision, approval_required, approved, status, request_id
        For human-gated requests it also contains the full lifecycle outcome
        (responder_id, decided_at, timeout_expired, seconds_waited, ...).
        """
        tier = _classify(confidence_score)
        risk_level = _risk_level_for(confidence_score)

        if tier == GateDecision.AUTO_APPROVE:
            return self._auto_result(
                GateDecision.AUTO_APPROVE, case_id, action_type, target, confidence_score,
                f"Confidence {confidence_score}% >= 85 — autonomous execution authorized; no human gate.",
            )

        if tier == GateDecision.MONITORING_ONLY:
            return self._auto_result(
                GateDecision.MONITORING_ONLY, case_id, action_type, target, confidence_score,
                f"Confidence {confidence_score}% in 55-69 — monitoring only; active response suppressed.",
            )

        if tier == GateDecision.DOCUMENT_ONLY:
            return self._auto_result(
                GateDecision.DOCUMENT_ONLY, case_id, action_type, target, confidence_score,
                f"Confidence {confidence_score}% < 55 — document only; logged for analyst review, no action taken.",
            )

        # tier == CONTAINMENT_APPROVED (70-84): containment auto-approved,
        # eradication actions require a human in the loop.
        if action_type not in _ERADICATION_ACTIONS:
            return self._auto_result(
                GateDecision.CONTAINMENT_APPROVED, case_id, action_type, target, confidence_score,
                f"Confidence {confidence_score}% in 70-84 — containment action '{action_type}' "
                "auto-approved; eradication actions still require sign-off.",
            )

        return self._run_human_approval(
            case_id=case_id, action_type=action_type, target=target,
            justification=justification, confidence_score=confidence_score,
            risk_level=risk_level, timeout_seconds=timeout_seconds, requested_by=requested_by,
        )

    # ------------------------------------------------------------------
    # Human-approval workflow
    # ------------------------------------------------------------------

    def _run_human_approval(
        self,
        case_id: str,
        action_type: str,
        target: str,
        justification: str,
        confidence_score: int,
        risk_level: str,
        timeout_seconds: int,
        requested_by: str,
    ) -> Dict[str, Any]:
        req = ApprovalRequest(
            request_id=f"REQ-{uuid.uuid4().hex[:8].upper()}",
            case_id=case_id,
            action=action_type,
            target=target,
            justification=justification,
            confidence_score=confidence_score,
            risk_level=risk_level,
            requested_by=requested_by,
            requested_at=time.time(),
            timeout_seconds=timeout_seconds,
        )

        with self._lock:
            self._requests[req.request_id] = req

        log.info(
            "ApprovalGate: human sign-off required — case=%s request=%s action=%s target=%s "
            "confidence=%d timeout=%ds",
            case_id, req.request_id, action_type, target, confidence_score, timeout_seconds,
        )
        self._log_audit(req, decision=ApprovalStatus.PENDING.value)
        self._pause_case(case_id, req)

        notified = self._broadcast(req)
        with self._lock:
            req.notified_channels = notified

        if self._demo_mode and self._demo_auto_respond:
            self._schedule_demo_response(req)

        return self._wait_for_resolution(req)

    def _broadcast(self, req: ApprovalRequest) -> List[str]:
        """Send the approval request via every configured channel."""
        payload = req.to_payload()
        notified: List[str] = []

        slack_result = self._slack.send_approval_request(payload)
        if slack_result.get("ok"):
            notified.append("slack")

        email_result = self._email.send_approval_request(payload)
        if email_result.get("ok"):
            notified.append("email")

        # SMS / Teams — stubbed integrations, demo-mode console output only
        notified.append(self._notify_sms_stub(payload))
        notified.append(self._notify_teams_stub(payload))

        return [c for c in notified if c]

    @staticmethod
    def _notify_sms_stub(payload: Dict[str, Any]) -> str:
        log.info(
            "[STUB] SMS (Twilio) approval notification — case=%s request=%s "
            "(configure SENTINEL_TWILIO_* to enable; printing instead)",
            payload.get("case_id"), payload.get("request_id"),
        )
        print(
            f"[SENTINEL DEMO][SMS STUB] Approval needed for {payload.get('case_id')} "
            f"({payload.get('action')} -> {payload.get('target')}). "
            f"Reply YES/NO to {payload.get('request_id')}."
        )
        return "sms"

    @staticmethod
    def _notify_teams_stub(payload: Dict[str, Any]) -> str:
        log.info(
            "[STUB] Microsoft Teams Adaptive Card — case=%s request=%s "
            "(configure SENTINEL_TEAMS_WEBHOOK_URL to enable; printing instead)",
            payload.get("case_id"), payload.get("request_id"),
        )
        print(
            f"[SENTINEL DEMO][TEAMS STUB] Adaptive Card — Approval Required: "
            f"{payload.get('action')} on {payload.get('target')} "
            f"(case {payload.get('case_id')}, confidence {payload.get('confidence_score')}%)."
        )
        return "teams"

    def _schedule_demo_response(self, req: ApprovalRequest) -> None:
        """DEMO_MODE: simulate a human clicking Approve/Deny after a short delay."""
        def _respond() -> None:
            time.sleep(self._demo_response_delay_s)
            with self._lock:
                still_pending = self._requests.get(req.request_id)
                if not still_pending or still_pending.status != ApprovalStatus.PENDING.value:
                    return
            log.info(
                "[DEMO_MODE] Simulating human response '%s' for request %s (case %s)",
                self._demo_response, req.request_id, req.case_id,
            )
            self.process_approval_response(
                request_id=req.request_id,
                response=self._demo_response,
                responder_id="demo-analyst",
            )

        threading.Thread(target=_respond, name=f"approval-demo-{req.request_id}", daemon=True).start()

    def _wait_for_resolution(self, req: ApprovalRequest) -> Dict[str, Any]:
        """Poll until the request reaches a terminal status or its timeout fires."""
        while True:
            with self._lock:
                current = self._requests.get(req.request_id, req)
                status = current.status

            if status != ApprovalStatus.PENDING.value:
                return self._build_result(current)

            if time.time() >= req.expires_at:
                self._expire(req)
                with self._lock:
                    current = self._requests.get(req.request_id, req)
                return self._build_result(current)

            time.sleep(self._poll_interval_s)

    def _expire(self, req: ApprovalRequest) -> None:
        """Fail-safe default-deny: timeout elapsed with no human response."""
        with self._lock:
            current = self._requests.get(req.request_id)
            if current is None or current.status != ApprovalStatus.PENDING.value:
                return
            current.status          = ApprovalStatus.TIMEOUT_DENIED.value
            current.timeout_expired = True
            current.decided_at      = time.time()
            current.response        = "NO"
            current.responder_id    = "system:timeout"

        decision_time_ms = int((current.decided_at - current.requested_at) * 1000)
        log.warning(
            "ApprovalGate: request %s for case %s TIMED OUT after %ds — defaulting to DENY (fail-safe).",
            req.request_id, req.case_id, req.timeout_seconds,
        )
        self._log_audit(current, decision=ApprovalStatus.TIMEOUT_DENIED.value,
                        decision_time_ms=decision_time_ms, timeout_expired=True)
        self._resolve_case(current, approved=False, reason="Approval request timed out — action cancelled (fail-safe deny).")

    def _build_result(self, req: ApprovalRequest) -> Dict[str, Any]:
        approved = req.status in (ApprovalStatus.APPROVED.value, ApprovalStatus.AUTO_APPROVED.value)
        gate_decision = GateDecision.PENDING_APPROVAL if req.status == ApprovalStatus.PENDING.value else (
            GateDecision.CONTAINMENT_APPROVED if approved else GateDecision.CONTAINMENT_APPROVED
        )
        decided_at = req.decided_at or time.time()
        return {
            "gate_decision":      "CONTAINMENT_APPROVED" if approved else req.status,
            "approval_required":  True,
            "approved":           approved,
            "status":             req.status,
            "case_id":            req.case_id,
            "action":             req.action,
            "target":             req.target,
            "confidence_score":   req.confidence_score,
            "risk_level":         req.risk_level,
            "request_id":         req.request_id,
            "responder_id":       req.responder_id,
            "response":           req.response,
            "timeout_expired":    req.timeout_expired,
            "seconds_waited":     round(decided_at - req.requested_at, 3),
            "notified_channels":  list(req.notified_channels),
            "reason": (
                "Human approval granted — proceeding with action." if approved else
                "Approval request timed out — defaulted to DENY (fail-safe)." if req.timeout_expired else
                "Human denied the request — action cancelled."
            ),
        }

    # ------------------------------------------------------------------
    # Case lifecycle hooks (best-effort — gate works without a state_manager)
    # ------------------------------------------------------------------

    def _pause_case(self, case_id: str, req: ApprovalRequest) -> None:
        """Record the pending request on the case so the dashboard can show it."""
        if self._state_manager is None:
            return
        try:
            self._state_manager.update_case(
                case_id,
                {"requires_approval": True, "pending_approval_request": req.to_dict()},
                agent_name="approval_gate",
                detail=f"Awaiting human approval for {req.action} on {req.target} ({req.request_id})",
            )
        except Exception:
            log.debug("ApprovalGate: could not annotate case %s with pending request (non-fatal)", case_id, exc_info=True)

    def _resolve_case(self, req: ApprovalRequest, approved: bool, reason: str) -> None:
        """On denial/timeout, close the case out as HUMAN_DENIED. No-op on approval (Executor proceeds)."""
        if self._state_manager is None or approved:
            return
        try:
            from utils.state_manager import CaseStatus  # local import — keeps gate importable standalone
            self._state_manager.update_case(
                req.case_id,
                {
                    "resolution":           "HUMAN_DENIED",
                    "approval_granted_by":  "",
                    "pending_approval_request": None,
                },
                agent_name="approval_gate",
                detail=reason,
            )
            self._state_manager.transition(
                req.case_id, CaseStatus.CLOSED,
                agent_name="approval_gate",
                detail=f"{reason} (request {req.request_id})",
            )
        except Exception:
            log.warning("ApprovalGate: could not transition case %s to CLOSED/HUMAN_DENIED", req.case_id, exc_info=True)

    # ------------------------------------------------------------------
    # Public API — response handling / introspection
    # ------------------------------------------------------------------

    def process_approval_response(self, request_id: str, response: str, responder_id: str) -> Dict[str, Any]:
        """
        Record a human response (Slack callback, dashboard click, email reply,
        or direct REST call) for a pending request.

        ``response`` is normalised to "YES"/"NO" (also accepts APPROVE/APPROVED/
        DENY/DENIED, case-insensitive). Returns the updated request as a dict,
        or ``{"error": ...}`` if the request is unknown or no longer pending.
        """
        normalised = self._normalise_response(response)
        if normalised is None:
            return {"error": f"Unrecognised response '{response}' — expected YES or NO."}

        with self._lock:
            req = self._requests.get(request_id)
            if req is None:
                return {"error": f"Unknown approval request '{request_id}'."}
            if req.status != ApprovalStatus.PENDING.value:
                return {"error": f"Request '{request_id}' already resolved (status={req.status})."}

            approved = normalised == "YES"
            req.status       = ApprovalStatus.APPROVED.value if approved else ApprovalStatus.DENIED.value
            req.response     = normalised
            req.responder_id = responder_id
            req.decided_at   = time.time()

        decision_time_ms = int((req.decided_at - req.requested_at) * 1000)
        log.info(
            "ApprovalGate: request %s for case %s resolved by %s — %s (%dms)",
            request_id, req.case_id, responder_id, req.status, decision_time_ms,
        )
        self._log_audit(req, decision=req.status, decision_time_ms=decision_time_ms)

        if approved:
            self._unpause_case(req)
        else:
            self._resolve_case(req, approved=False, reason=f"Human ({responder_id}) denied the request — action cancelled.")

        return req.to_dict()

    def _unpause_case(self, req: ApprovalRequest) -> None:
        if self._state_manager is None:
            return
        try:
            self._state_manager.update_case(
                req.case_id,
                {
                    "approval_granted_by":  req.responder_id,
                    "approval_granted_time": req.decided_at,
                    "pending_approval_request": None,
                },
                agent_name="approval_gate",
                detail=f"Approved by {req.responder_id} — Executor may proceed ({req.request_id})",
            )
        except Exception:
            log.debug("ApprovalGate: could not annotate case %s with approval grant (non-fatal)", req.case_id, exc_info=True)

    @staticmethod
    def _normalise_response(response: str) -> Optional[str]:
        token = str(response or "").strip().upper()
        if token in ("YES", "Y", "APPROVE", "APPROVED"):
            return "YES"
        if token in ("NO", "N", "DENY", "DENIED"):
            return "NO"
        return None

    def get_pending_approvals(self) -> List[Dict[str, Any]]:
        """List every approval request still awaiting a human response."""
        with self._lock:
            return [req.to_dict() for req in self._requests.values()
                    if req.status == ApprovalStatus.PENDING.value]

    def get_approval(self, request_id: str) -> Optional[Dict[str, Any]]:
        """Look up a single request (any status) by id."""
        with self._lock:
            req = self._requests.get(request_id)
            return req.to_dict() if req else None

    def cancel_approval(self, request_id: str, cancelled_by: str = "system") -> Dict[str, Any]:
        """Cancel a pending request without resolving it as approved or denied."""
        with self._lock:
            req = self._requests.get(request_id)
            if req is None:
                return {"error": f"Unknown approval request '{request_id}'."}
            if req.status != ApprovalStatus.PENDING.value:
                return {"error": f"Request '{request_id}' already resolved (status={req.status})."}

            req.status       = ApprovalStatus.CANCELLED.value
            req.responder_id = cancelled_by
            req.decided_at   = time.time()

        decision_time_ms = int((req.decided_at - req.requested_at) * 1000)
        log.info("ApprovalGate: request %s for case %s cancelled by %s", request_id, req.case_id, cancelled_by)
        self._log_audit(req, decision=ApprovalStatus.CANCELLED.value, decision_time_ms=decision_time_ms)
        return req.to_dict()


# ---------------------------------------------------------------------------
# Process-wide singleton — shared by ExecutorAgent and the REST handler so
# pending requests raised by one are visible (and answerable) via the other.
# ---------------------------------------------------------------------------

_gate_lock: threading.Lock = threading.Lock()
_gate: Optional[ApprovalGate] = None


def get_approval_gate(
    state_manager: Optional[Any] = None,
    audit: Optional[Any] = None,
) -> ApprovalGate:
    """Return the process-wide ApprovalGate singleton, creating it on first use."""
    global _gate
    with _gate_lock:
        if _gate is None:
            _gate = ApprovalGate(state_manager=state_manager, audit=audit)
        return _gate
