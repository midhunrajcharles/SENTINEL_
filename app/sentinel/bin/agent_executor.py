"""
SENTINEL: Autonomous Agentic SOC Commander
agent_executor.py — The Response Agent

ExecutorAgent takes a SherlockInvestigationReport and translates recommended
actions into real containment and eradication steps via MCP response tools.

Risk matrix determines autonomy level:
  FULL_AUTONOMY    (85-100) — execute all recommended actions immediately
  CONTAINMENT_ONLY (70-84)  — isolate/block; hold eradication for approval
  MONITORING_ONLY  (55-69)  — enhance detection; no active response
  DOCUMENT_ONLY    (<55)    — log and notify; no action

Safety mechanisms:
  - Rate limiter:     max 10 actions per hour per agent
  - Cascade guard:    halt if 3+ failures in 5 minutes
  - HALT check:       inspect case.status before every action
  - Rollback timers:  every action schedules automatic undo
  - Verification:     re-query Splunk after every action to confirm effect

Public API:
  ExecutorAgent.run(case, audit) → dict
  ExecutorAgent.execute_action(action_def, case_id, score) → ActionResult

Dependencies: requests, standard library
"""

from __future__ import annotations

import concurrent.futures
import json
import logging
import os
import sys
import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional, Tuple

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

_BIN_DIR = Path(__file__).resolve().parent
if str(_BIN_DIR) not in sys.path:
    sys.path.insert(0, str(_BIN_DIR))

from audit_logger import AuditLogger, get_audit_logger
from approval_gate import ApprovalGate, get_approval_gate
from mcp_client import SplunkMCPClient, MCPError
from utils.config_loader import get_config

log = logging.getLogger("sentinel.executor")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_AGENT_NAME          = "executor"
_ENV_MODEL_TOKEN     = "SENTINEL_HOSTED_MODEL_TOKEN"
_ENV_SPLUNK_HOST     = "SENTINEL_SPLUNK_HOST"
_ENV_SPLUNK_PORT     = "SENTINEL_SPLUNK_PORT"
_ENV_SPLUNK_SCHEME   = "SENTINEL_SPLUNK_SCHEME"
_ENV_SOAR_URL        = "SENTINEL_SOAR_URL"
_ENV_SOAR_TOKEN      = "SENTINEL_SOAR_TOKEN"
_ENV_ONCALL_EMAIL    = "SENTINEL_ONCALL_EMAIL"

_SYSTEM_PROMPT_PATH  = (
    Path(__file__).resolve().parent.parent.parent.parent
    / "models" / "prompts" / "executor_system_prompt.txt"
)

_RATE_LIMIT_ACTIONS       = 10      # max actions per window
_RATE_LIMIT_WINDOW_S      = 3600    # 1 hour
_CASCADE_FAILURE_THRESHOLD = 3      # consecutive failures before halt
_CASCADE_WINDOW_S         = 300     # 5-minute failure window
_ACTION_TIMEOUT_S         = 35.0    # MCP action call timeout
_VERIFY_TIMEOUT_S         = 20.0    # verification SPL timeout
_VERIFY_WAIT_S            = 3.0     # wait before post-action verification

# ---------------------------------------------------------------------------
# Fault tolerance
# ---------------------------------------------------------------------------
_ACTION_EXECUTION_TIMEOUT_SECONDS = 120   # 2 minutes — wall-clock budget per response action
_EMERGENCY_ROLLBACK_DELAY_S       = 5     # how soon to fire a rollback after a timed-out action

# Default rollback timers (seconds)
_DEFAULT_ROLLBACK: Dict[str, int] = {
    "isolate_host":     14_400,   # 4 hours
    "block_ip":         259_200,  # 72 hours
    "disable_user":     86_400,   # 24 hours
    "kill_process":     0,        # no rollback (process is gone)
    "quarantine_file":  14_400,   # 4 hours
    "revoke_session":   0,
    "rotate_credentials": 0,
}

# Actions permitted at each autonomy tier
_CONTAINMENT_ACTIONS = {"isolate_host", "block_ip", "kill_process"}
_ERADICATION_ACTIONS = {"disable_user", "quarantine_file", "revoke_session", "rotate_credentials"}
_DOCUMENTATION_ACTIONS = {"create_ticket", "notify_stakeholders", "trigger_playbook"}

# Verification SPL templates — {target} and {host} are substituted at runtime
_VERIFICATION_QUERIES: Dict[str, str] = {
    "isolate_host": (
        'index=`sentinel_edr_index` host="{target}" '
        '| head 1 | eval verify_status=if(network_status=="isolated","confirmed","pending")'
        '| stats values(verify_status) as result'
    ),
    "block_ip": (
        'index=`sentinel_network_index` (src_ip="{target}" OR dest_ip="{target}") action=blocked '
        '| head 1 | eval verify_status="confirmed" | stats values(verify_status) as result'
    ),
    "disable_user": (
        'index=`sentinel_identity_index` user="{target}" EventCode=4725 '
        '| head 1 | eval verify_status="confirmed" | stats values(verify_status) as result'
    ),
    "kill_process": (
        'index=`sentinel_edr_index` host="{host}" process_name="{target}" '
        'action=terminated | head 1 '
        '| eval verify_status="confirmed" | stats values(verify_status) as result'
    ),
    "quarantine_file": (
        'index=`sentinel_edr_index` host="{host}" file_path="{target}" '
        'quarantine_status=quarantined | head 1 '
        '| eval verify_status="confirmed" | stats values(verify_status) as result'
    ),
}

# Notification recipients config keys
_ONCALL_CHANNELS   = ["slack"]
_ONCALL_EMAIL_LIST = ["soc-oncall@company.com"]

# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class ExecutorError(Exception):
    """Base executor exception."""

class ExecutorRateLimitError(ExecutorError):
    """Action rate limit exceeded."""

class ExecutorCascadeHaltError(ExecutorError):
    """Cascade failure threshold exceeded; all responses halted."""

class ExecutorHaltSignalError(ExecutorError):
    """HALT signal detected in case state; no further actions taken."""

class ExecutorAuthorizationError(ExecutorError):
    """Action requires approval that has not been granted."""

class ExecutorActionTimeoutError(ExecutorError):
    """A response action exceeded its wall-clock execution budget."""

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class ExecutorMode(Enum):
    FULL_AUTONOMY    = "FULL_AUTONOMY"
    CONTAINMENT_ONLY = "CONTAINMENT_ONLY"
    MONITORING_ONLY  = "MONITORING_ONLY"
    DOCUMENT_ONLY    = "DOCUMENT_ONLY"


class ActionStatus(Enum):
    SUCCESS  = "SUCCESS"
    FAILED   = "FAILED"
    SKIPPED  = "SKIPPED"
    HALTED   = "HALTED"
    DRY_RUN  = "DRY_RUN"

# ---------------------------------------------------------------------------
# Safety: rate limiter
# ---------------------------------------------------------------------------

class _RateLimiter:
    """Sliding-window rate limiter — max N actions per window_seconds."""

    def __init__(self, max_actions: int = _RATE_LIMIT_ACTIONS,
                 window_s: float = _RATE_LIMIT_WINDOW_S) -> None:
        self._max    = max_actions
        self._window = window_s
        self._ts:    Deque[float] = deque()
        self._lock   = threading.Lock()

    def check_and_record(self) -> bool:
        """Return True and record the attempt if within limit, False otherwise."""
        now = time.monotonic()
        with self._lock:
            cutoff = now - self._window
            while self._ts and self._ts[0] < cutoff:
                self._ts.popleft()
            if len(self._ts) >= self._max:
                return False
            self._ts.append(now)
            return True

    @property
    def current_count(self) -> int:
        now = time.monotonic()
        with self._lock:
            cutoff = now - self._window
            return sum(1 for t in self._ts if t >= cutoff)

# ---------------------------------------------------------------------------
# Safety: cascade guard
# ---------------------------------------------------------------------------

class _CascadeGuard:
    """
    Triggers a full halt if _threshold failures occur within _window_s seconds.
    Once triggered, all subsequent check() calls return True until reset.
    """

    def __init__(self, threshold: int = _CASCADE_FAILURE_THRESHOLD,
                 window_s: float = _CASCADE_WINDOW_S) -> None:
        self._threshold = threshold
        self._window    = window_s
        self._failures: Deque[float] = deque()
        self._lock = threading.Lock()
        self.triggered = False

    def record_failure(self) -> bool:
        """Record a failure; return True if cascade threshold is now exceeded."""
        now = time.monotonic()
        with self._lock:
            if self.triggered:
                return True
            cutoff = now - self._window
            while self._failures and self._failures[0] < cutoff:
                self._failures.popleft()
            self._failures.append(now)
            if len(self._failures) >= self._threshold:
                self.triggered = True
                log.error(
                    "Cascade guard triggered: %d failures in %.0fs — halting all responses",
                    len(self._failures), self._window,
                )
            return self.triggered

    def record_success(self) -> None:
        with self._lock:
            if not self.triggered:
                self._failures.clear()

    def reset(self) -> None:
        with self._lock:
            self.triggered = False
            self._failures.clear()

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class ActionVerification:
    pre_state:            str = "unknown"
    post_state:           str = "unknown"
    confirmation_source:  str = "splunk_spl"
    confirmation_query:   str = ""
    verified:             bool = False
    error:                str = ""

    def to_dict(self) -> Dict:
        return {
            "pre_state":           self.pre_state,
            "post_state":          self.post_state,
            "confirmation_source": self.confirmation_source,
            "confirmation_query":  self.confirmation_query,
        }


@dataclass
class ActionResult:
    case_id:               str
    action_id:             str
    action_type:           str
    target:                str
    status:                str
    execution_time_ms:     int
    verification:          ActionVerification
    rollback_timer:        int
    rollback_scheduled:    str     # ISO-8601 or ""
    human_notified:        bool
    notification_sent_to:  List[str]
    justification:         str = ""
    skipped_reason:        str = ""
    error_detail:          str = ""
    timestamp:             str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict:
        return {
            "case_id":              self.case_id,
            "action_id":            self.action_id,
            "action_type":          self.action_type,
            "target":               self.target,
            "status":               self.status,
            "execution_time_ms":    self.execution_time_ms,
            "verification":         self.verification.to_dict(),
            "rollback_timer":       self.rollback_timer,
            "rollback_scheduled":   self.rollback_scheduled,
            "human_notified":       self.human_notified,
            "notification_sent_to": self.notification_sent_to,
            "justification":        self.justification,
            "skipped_reason":       self.skipped_reason,
            "error_detail":         self.error_detail,
            "timestamp":            self.timestamp,
        }


@dataclass
class ExecutorActionLog:
    case_id:            str
    executor_mode:      str
    risk_score:         int
    actions:            List[ActionResult]
    total_actions:      int
    successful_actions: int
    failed_actions:     int
    skipped_actions:    int
    halted:             bool
    halt_reason:        str
    duration_seconds:   int
    model_used:         str = ""
    model_available:    bool = False
    timestamp:          str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    # Orchestrator-consumed extensions
    alert_id:           str = ""
    classification:     str = ""
    # Step-by-step "Chain of Thought" explainability trace — one entry per
    # action taken (or deliberately skipped), recording justification, risk
    # assessment, before/after state, verification evidence, rollback timer,
    # and notification posture (SOC audit / compliance trail)
    action_chain:       List[Dict] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "case_id":            self.case_id,
            "executor_mode":      self.executor_mode,
            "risk_score":         self.risk_score,
            "actions":            [a.to_dict() for a in self.actions],
            "total_actions":      self.total_actions,
            "successful_actions": self.successful_actions,
            "failed_actions":     self.failed_actions,
            "skipped_actions":    self.skipped_actions,
            "halted":             self.halted,
            "halt_reason":        self.halt_reason,
            "duration_seconds":   self.duration_seconds,
            "model_used":         self.model_used,
            "model_available":    self.model_available,
            "timestamp":          self.timestamp,
            "alert_id":           self.alert_id,
            "classification":     self.classification,
            "action_chain":       self.action_chain,
        }

# ---------------------------------------------------------------------------
# Executor Agent
# ---------------------------------------------------------------------------

class ExecutorAgent:
    """
    Response agent — translates SherlockInvestigationReport recommendations
    into verified containment and eradication actions via MCP.
    """

    AGENT_NAME = "executor"

    def __init__(
        self,
        mcp:    Optional[SplunkMCPClient] = None,
        config: Any = None,
        approval_gate: Optional[ApprovalGate] = None,
    ) -> None:
        self._cfg         = config or get_config()
        self._mcp         = mcp
        self._prompt:     Optional[str] = None
        self._rate_limiter = _RateLimiter()
        self._cascade     = _CascadeGuard()
        self._approval_gate = approval_gate

    # ------------------------------------------------------------------
    # Lazy accessors
    # ------------------------------------------------------------------

    def _get_mcp(self) -> SplunkMCPClient:
        if self._mcp is None:
            self._mcp = SplunkMCPClient(agent_name=self.AGENT_NAME)
        return self._mcp

    def _get_approval_gate(self) -> ApprovalGate:
        if self._approval_gate is None:
            self._approval_gate = get_approval_gate(audit=get_audit_logger(self.AGENT_NAME))
        return self._approval_gate

    def _load_system_prompt(self) -> str:
        if self._prompt is None:
            try:
                self._prompt = _SYSTEM_PROMPT_PATH.read_text(encoding="utf-8")
            except Exception as exc:
                log.warning("Could not load executor system prompt: %s", exc)
                self._prompt = (
                    "You are Executor, a security response agent. "
                    "Respond with valid JSON action decisions only."
                )
        return self._prompt

    def _get_oncall_email(self) -> str:
        return os.environ.get(
            _ENV_ONCALL_EMAIL,
            self._cfg.get("notifications", "oncall_email", default="soc-oncall@company.com"),
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(self, case: Any, audit: AuditLogger) -> Dict:
        """
        Run the full response pipeline for a case.
        Orchestrator entry point (_AgentProxy interface).
        Returns ExecutorActionLog as dict.
        """
        t0 = int(time.time() * 1000)

        sherlock = getattr(case, "sherlock_report", None) or {}
        if not isinstance(sherlock, dict):
            try:
                sherlock = dict(sherlock)
            except Exception:
                sherlock = {}

        risk_score     = int(getattr(case, "risk_score", 0) or sherlock.get("risk_score", 0))
        classification = (
            getattr(case, "classification", "")
            or sherlock.get("classification", "UNKNOWN")
        )
        alert_id       = getattr(case, "alert_id", "")
        case_id        = case.case_id

        recommended    = sherlock.get("recommended_actions", [])
        blast_radius   = sherlock.get("blast_radius", {})

        log.info(
            "Executor: case=%s score=%d classification=%s actions=%d",
            case_id, risk_score, classification, len(recommended),
        )

        # Determine autonomy mode
        mode = self._determine_mode(risk_score)
        log.info("Executor mode: %s (score=%d)", mode.value, risk_score)

        audit.log_transition(
            case_id=case_id,
            from_status="INVESTIGATING",
            to_status="RESPONDING",
            trigger="executor_start",
            metadata={"mode": mode.value, "risk_score": risk_score},
        )

        # Evaluate approval gate
        requires_approval = getattr(case, "requires_approval", False)
        approval_granted  = bool(getattr(case, "approval_granted_by", None))

        if requires_approval and not approval_granted:
            reason = (
                f"Case requires human approval (score={risk_score}); "
                "approval not granted. Executor halted."
            )
            log.warning("Executor halted: %s", reason)
            audit.log_error(
                case_id=case_id, error_type="APPROVAL_GATE",
                message=reason, is_fatal=False,
            )
            return self._build_log(
                case_id=case_id, mode=mode, risk_score=risk_score,
                actions=[], halted=True, halt_reason=reason,
                t0=t0, alert_id=alert_id, classification=classification,
            ).to_dict()

        # Filter recommended actions by mode
        filtered, skipped = self._filter_actions(recommended, mode, risk_score, approval_granted)

        # Live human-approval gate: any eradication action skipped only because
        # case-level approval wasn't granted gets a real shot at sign-off —
        # ApprovalGate fires the Slack/email workflow and blocks for the
        # response (or fail-safe-denies on timeout). Approved actions are
        # promoted back into the execution plan.
        filtered, skipped = self._gate_check_skipped_eradication(
            filtered, skipped, case_id=case_id, risk_score=risk_score, audit=audit,
        )

        log.info(
            "Action plan: %d to execute, %d skipped by policy",
            len(filtered), len(skipped),
        )

        # Build skipped ActionResult entries (no MCP call)
        action_results: List[ActionResult] = []
        for skip_def in skipped:
            action_results.append(ActionResult(
                case_id=case_id,
                action_id=f"ACT-{uuid.uuid4().hex[:8].upper()}",
                action_type=skip_def.get("action", "unknown"),
                target=skip_def.get("target", ""),
                status=ActionStatus.SKIPPED.value,
                execution_time_ms=0,
                verification=ActionVerification(),
                rollback_timer=0,
                rollback_scheduled="",
                human_notified=False,
                notification_sent_to=[],
                justification=skip_def.get("justification", ""),
                skipped_reason=skip_def.get("_skip_reason", "Below autonomy threshold for this mode"),
            ))

        # Execute approved actions
        halted = False
        halt_reason = ""
        pending_notifications: List[Tuple[str, str, int]] = []  # (action_type, target, priority)

        for action_def in filtered:
            # Cascade guard check before each action
            if self._cascade.triggered:
                halted     = True
                halt_reason = (
                    f"Cascade guard triggered: {_CASCADE_FAILURE_THRESHOLD} failures "
                    f"in {_CASCADE_WINDOW_S}s. All further responses halted."
                )
                log.error("Cascade halt: %s", halt_reason)
                audit.log_error(
                    case_id=case_id, error_type="CASCADE_HALT",
                    message=halt_reason, is_fatal=True,
                    context={"failed_actions": sum(1 for r in action_results if r.status == ActionStatus.FAILED.value)},
                )
                break

            # HALT signal check
            if self._check_halt_signal(case):
                halted     = True
                halt_reason = "HALT signal detected in case state before action execution."
                log.warning("HALT signal detected; aborting response pipeline for %s", case_id)
                break

            result = self._execute_single_action(action_def, case_id, audit)
            action_results.append(result)

            if result.status == ActionStatus.SUCCESS.value:
                self._cascade.record_success()
                priority = int(action_def.get("priority", 99))
                pending_notifications.append((result.action_type, result.target, priority))
            elif result.status == ActionStatus.FAILED.value:
                triggered = self._cascade.record_failure()
                if triggered:
                    audit.log_metric(
                        case_id=case_id, metric_name="executor_cascade_triggered",
                        value=1.0, unit="count",
                    )

        # Notifications — Slack for high-priority, email digest for all
        notified_to = self._send_notifications(
            case_id=case_id,
            case_summary={
                "classification": classification,
                "risk_score":     risk_score,
                "blast_radius":   blast_radius,
            },
            action_results=action_results,
            pending_notifications=pending_notifications,
            audit=audit,
        )

        # Mark high-priority successful actions as notified
        for result in action_results:
            if result.status == ActionStatus.SUCCESS.value:
                result.human_notified     = True
                result.notification_sent_to = notified_to

        total_ms = int(time.time() * 1000) - t0
        action_chain = self.build_action_chain(
            action_results, mode, risk_score,
            requires_approval=requires_approval, approval_granted=approval_granted,
        )
        action_log = self._build_log(
            case_id=case_id, mode=mode, risk_score=risk_score,
            actions=action_results, halted=halted, halt_reason=halt_reason,
            t0=t0, alert_id=alert_id, classification=classification,
            action_chain=action_chain,
        )

        audit.log_chain_of_thought(
            case_id    = case_id,
            agent_name = "executor",
            chain      = action_chain,
        )

        audit.log_decision(
            case_id=case_id,
            decision_type="RESPONSE_COMPLETE",
            confidence=1.0 if not halted else 0.0,
            input_context={
                "mode":           mode.value,
                "risk_score":     risk_score,
                "actions_planned": len(filtered) + len(skipped),
            },
            output_decision={
                "successful":     action_log.successful_actions,
                "failed":         action_log.failed_actions,
                "skipped":        action_log.skipped_actions,
                "halted":         halted,
            },
            reasoning=(
                f"Mode {mode.value}: {action_log.successful_actions} successful, "
                f"{action_log.failed_actions} failed, {action_log.skipped_actions} skipped."
                + (f" HALTED: {halt_reason[:120]}" if halted else "")
            ),
            latency_ms=total_ms,
            metadata={"action_chain": action_chain},
        )

        log.info(
            "Executor complete: case=%s mode=%s success=%d failed=%d skipped=%d halted=%s duration=%dms",
            case_id, mode.value,
            action_log.successful_actions, action_log.failed_actions,
            action_log.skipped_actions, halted, total_ms,
        )
        return action_log.to_dict()

    def build_action_chain(
        self,
        actions:           List["ActionResult"],
        mode:              ExecutorMode,
        risk_score:        int,
        requires_approval: bool = False,
        approval_granted:  bool = False,
    ) -> List[Dict[str, Any]]:
        """
        Build a step-by-step "Chain of Thought" explainability trace for the
        response pipeline — one entry per action taken (or deliberately
        skipped), recording the justification, a risk matrix, before/after
        state, the verification query/result, rollback timer, and whether
        humans were notified.

        Purely narrative: it re-describes the same `ActionResult`/mode/
        risk_score signals already produced by `_filter_actions`,
        `_execute_single_action`, and `_build_log` — it does not execute new
        actions, run new queries, or alter any response/authorization logic.
        Used for SOC audit / compliance trails (see
        AuditLogger.log_chain_of_thought).
        """
        chain: List[Dict[str, Any]] = []

        for sequence, result in enumerate(actions, start=1):
            is_eradication = result.action_type in _ERADICATION_ACTIONS
            action_class = (
                "containment"   if result.action_type in _CONTAINMENT_ACTIONS else
                "eradication"   if is_eradication else
                "documentation" if result.action_type in _DOCUMENTATION_ACTIONS else
                "unknown"
            )

            if result.status == ActionStatus.SKIPPED.value:
                verification_result = "NOT_EXECUTED"
            elif result.verification.verified:
                verification_result = "VERIFIED"
            elif result.status == ActionStatus.SUCCESS.value:
                verification_result = "EXECUTED_UNVERIFIED"
            else:
                verification_result = result.status

            risk_matrix = {
                "executor_mode":            mode.value,
                "case_risk_score":          risk_score,
                "action_class":             action_class,
                "blast_radius_if_skipped": (
                    "n/a — action executed" if result.status != ActionStatus.SKIPPED.value
                    else "elevated — threat condition remains unaddressed"
                ),
                "blast_radius_if_executed": (
                    "contained — confirmed by post-action verification query"
                    if result.verification.verified
                    else "executed but unverified — flagged for analyst follow-up"
                    if result.status == ActionStatus.SUCCESS.value
                    else "n/a — action not executed"
                ),
                "rollback_available":       result.rollback_timer > 0,
            }

            entry: Dict[str, Any] = {
                "sequence":            sequence,
                "action":              result.action_type,
                "target":              result.target,
                "justification":       (
                    result.justification or result.skipped_reason
                    or "No justification recorded for this action."
                ),
                "risk_matrix":         risk_matrix,
                "pre_state":           result.verification.pre_state,
                "post_state":          result.verification.post_state,
                "verification_query":  result.verification.confirmation_query,
                "verification_result": verification_result,
                "rollback_timer":      result.rollback_timer,
                "human_notified":      result.human_notified,
            }

            if is_eradication and mode == ExecutorMode.CONTAINMENT_ONLY and not approval_granted:
                entry["requires_manager_approval"] = True

            chain.append(entry)

        return chain

    def execute_action(
        self,
        action_definition: Dict,
        case_id: str,
        risk_score: int = 100,
    ) -> "ActionResult":
        """
        Public single-action API — can be called directly by the orchestrator
        or from other agents for targeted containment.

        Args:
            action_definition: dict with keys action, target, justification, priority
            case_id:           case this action belongs to
            risk_score:        used to determine rollback timer and notification urgency

        Returns:
            ActionResult dataclass
        """
        audit = get_audit_logger(self.AGENT_NAME)
        return self._execute_single_action(action_definition, case_id, audit)

    # ------------------------------------------------------------------
    # Mode and authorization
    # ------------------------------------------------------------------

    def _determine_mode(self, risk_score: int) -> ExecutorMode:
        if risk_score >= 85:
            return ExecutorMode.FULL_AUTONOMY
        if risk_score >= 70:
            return ExecutorMode.CONTAINMENT_ONLY
        if risk_score >= 55:
            return ExecutorMode.MONITORING_ONLY
        return ExecutorMode.DOCUMENT_ONLY

    def _gate_check_skipped_eradication(
        self,
        filtered: List[Dict],
        skipped: List[Dict],
        case_id: str,
        risk_score: int,
        audit: AuditLogger,
    ) -> Tuple[List[Dict], List[Dict]]:
        """
        Run every eradication action that ``_filter_actions`` parked in
        ``skipped`` purely for lack of case-level approval through the real
        :class:`ApprovalGate` — this is the human-in-the-loop gate made
        tangible: it fires Slack/email notifications and blocks for a
        response (or fail-safe-denies on timeout). Approved actions are
        promoted into ``filtered`` for execution; denied/timed-out ones stay
        skipped with the gate's resolution recorded as the reason.
        """
        promoted: List[Dict] = []
        still_skipped: List[Dict] = []
        gate = self._get_approval_gate()

        for skip_def in skipped:
            action_type = skip_def.get("action", "")
            reason = str(skip_def.get("_skip_reason", ""))
            needs_gate = action_type in _ERADICATION_ACTIONS and "requires human approval" in reason

            if not needs_gate:
                still_skipped.append(skip_def)
                continue

            log.info(
                "Executor: routing skipped eradication action '%s' (target=%s) through ApprovalGate for case=%s",
                action_type, skip_def.get("target", ""), case_id,
            )
            result = gate.request_approval(
                case_id=case_id,
                action_type=action_type,
                target=skip_def.get("target", ""),
                justification=skip_def.get("justification", ""),
                confidence_score=risk_score,
                requested_by=f"{self.AGENT_NAME.capitalize()}Agent",
            )

            if result.get("approved"):
                log.info(
                    "Executor: ApprovalGate approved '%s' on %s (request=%s) — promoting to execution plan",
                    action_type, skip_def.get("target", ""), result.get("request_id"),
                )
                promoted_def = dict(skip_def)
                promoted_def.pop("_skip_reason", None)
                promoted_def["_approval_request_id"] = result.get("request_id")
                promoted.append(promoted_def)
            else:
                gate_skip = dict(skip_def)
                gate_skip["_skip_reason"] = (
                    f"ApprovalGate {result.get('status', 'DENIED')}: {result.get('reason', 'Request denied.')}"
                )
                gate_skip["_approval_request_id"] = result.get("request_id")
                still_skipped.append(gate_skip)
                audit.log_error(
                    case_id=case_id, error_type="APPROVAL_DENIED",
                    message=f"Human approval denied for {action_type} on {skip_def.get('target', '')}: {result.get('reason', '')}",
                    is_fatal=False,
                    context={"request_id": result.get("request_id"), "status": result.get("status")},
                )

        # Preserve original priority ordering when promoted actions are appended
        new_filtered = sorted(filtered + promoted, key=lambda a: int(a.get("priority", 99)))
        return new_filtered, still_skipped

    def _filter_actions(
        self,
        recommended: List[Dict],
        mode: ExecutorMode,
        risk_score: int,
        approval_granted: bool,
    ) -> Tuple[List[Dict], List[Dict]]:
        """
        Returns (execute_list, skipped_list).
        Each skipped item has a _skip_reason key injected.
        """
        execute: List[Dict] = []
        skipped: List[Dict] = []

        for action_def in recommended:
            action_type = action_def.get("action", "")
            reason: Optional[str] = None

            if mode == ExecutorMode.DOCUMENT_ONLY:
                if action_type not in _DOCUMENTATION_ACTIONS:
                    reason = f"DOCUMENT_ONLY mode (score={risk_score}); active response suppressed."

            elif mode == ExecutorMode.MONITORING_ONLY:
                if action_type not in _DOCUMENTATION_ACTIONS:
                    reason = f"MONITORING_ONLY mode (score={risk_score}); active response suppressed."

            elif mode == ExecutorMode.CONTAINMENT_ONLY:
                if action_type in _ERADICATION_ACTIONS and not approval_granted:
                    reason = (
                        f"CONTAINMENT_ONLY mode: eradication action '{action_type}' requires "
                        "human approval that has not been granted."
                    )
                elif action_type not in (_CONTAINMENT_ACTIONS | _DOCUMENTATION_ACTIONS | _ERADICATION_ACTIONS):
                    reason = f"Unknown action type '{action_type}' skipped."

            # FULL_AUTONOMY: all known actions allowed
            elif action_type not in (
                _CONTAINMENT_ACTIONS | _ERADICATION_ACTIONS | _DOCUMENTATION_ACTIONS
            ):
                reason = f"Unknown action type '{action_type}' — skipped for safety."

            if reason:
                copy = dict(action_def)
                copy["_skip_reason"] = reason
                skipped.append(copy)
            else:
                execute.append(action_def)

        # Sort by priority (ascending — 1 is highest)
        execute.sort(key=lambda a: int(a.get("priority", 99)))
        return execute, skipped

    # ------------------------------------------------------------------
    # HALT signal check
    # ------------------------------------------------------------------

    def _check_halt_signal(self, case: Any) -> bool:
        """
        Returns True if the case carries a HALT signal (manual override or
        the orchestrator has set requires_approval mid-flight).
        """
        status = str(getattr(case, "status", "") or "").upper()
        if status == "HALTED":
            return True
        halt_flag = getattr(case, "halt_flag", False)
        return bool(halt_flag)

    # ------------------------------------------------------------------
    # Fault tolerance — per-action wall-clock timeout
    # ------------------------------------------------------------------

    def _run_action_with_timeout(
        self,
        handler,
        *,
        action_type: str,
        timeout: float = _ACTION_EXECUTION_TIMEOUT_SECONDS,
        **kwargs,
    ) -> "ActionResult":
        """
        Run an action handler on a worker thread and enforce a wall-clock
        budget. Raises ExecutorActionTimeoutError if the handler does not
        complete in time — the underlying call is left running (MCP/HTTP
        clients have their own socket timeouts) but the orchestrator is
        freed to mark the action FAILED and move on.
        """
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(handler, **kwargs)
            try:
                return future.result(timeout=timeout)
            except concurrent.futures.TimeoutError:
                raise ExecutorActionTimeoutError(
                    f"Action '{action_type}' exceeded {timeout:g}s execution budget"
                )

    # ------------------------------------------------------------------
    # Single action execution dispatcher
    # ------------------------------------------------------------------

    def _execute_single_action(
        self,
        action_def: Dict,
        case_id:    str,
        audit:      AuditLogger,
    ) -> ActionResult:
        action_type   = action_def.get("action", "")
        target        = action_def.get("target", "")
        justification = action_def.get("justification", "")
        urgency       = action_def.get("urgency", "within_1h")
        priority      = int(action_def.get("priority", 99))
        action_id     = f"ACT-{uuid.uuid4().hex[:8].upper()}"
        t0            = int(time.time() * 1000)

        log.info(
            "Executing action: %s target=%s priority=%d case=%s",
            action_type, target, priority, case_id,
        )

        # Rate limiting
        if not self._rate_limiter.check_and_record():
            msg = (
                f"Rate limit exceeded: {_RATE_LIMIT_ACTIONS} actions per "
                f"{_RATE_LIMIT_WINDOW_S}s. Action {action_type} deferred."
            )
            log.warning(msg)
            audit.log_error(
                case_id=case_id, error_type="RATE_LIMIT",
                message=msg, is_fatal=False,
                context={"action_type": action_type, "target": target},
            )
            return ActionResult(
                case_id=case_id, action_id=action_id,
                action_type=action_type, target=target,
                status=ActionStatus.SKIPPED.value,
                execution_time_ms=0,
                verification=ActionVerification(),
                rollback_timer=0, rollback_scheduled="",
                human_notified=False, notification_sent_to=[],
                justification=justification,
                skipped_reason=msg,
            )

        # Dispatch to action-specific handler
        dispatch: Dict[str, Any] = {
            "isolate_host":        self._isolate_host,
            "block_ip":            self._block_ip,
            "disable_user":        self._disable_user,
            "kill_process":        self._kill_process,
            "quarantine_file":     self._quarantine_file,
            "create_ticket":       self._create_ticket,
            "notify_stakeholders": self._notify_stakeholders,
            "trigger_playbook":    self._trigger_playbook,
        }

        handler = dispatch.get(action_type)
        if handler is None:
            error_msg = f"Unsupported action type: '{action_type}'"
            log.warning(error_msg)
            elapsed = int(time.time() * 1000) - t0
            audit.log_action(
                case_id=case_id, action_type=action_type, target=target,
                platform="unknown", outcome="SKIPPED", action_id=action_id,
                error_detail=error_msg,
            )
            return ActionResult(
                case_id=case_id, action_id=action_id,
                action_type=action_type, target=target,
                status=ActionStatus.SKIPPED.value,
                execution_time_ms=elapsed,
                verification=ActionVerification(),
                rollback_timer=0, rollback_scheduled="",
                human_notified=False, notification_sent_to=[],
                justification=justification, skipped_reason=error_msg,
            )

        try:
            result = self._run_action_with_timeout(
                handler, action_type=action_type,
                action_id=action_id, case_id=case_id,
                target=target, justification=justification,
                urgency=urgency, action_def=action_def,
            )
        except ExecutorActionTimeoutError as exc:
            elapsed   = int(time.time() * 1000) - t0
            error_msg = str(exc)
            log.error("Action %s timed out for target %s after %dms: %s",
                      action_type, target, elapsed, exc)

            rollback_scheduled = ""
            rollback_timer     = 0
            if _DEFAULT_ROLLBACK.get(action_type, 0) > 0:
                # The action may have partially applied before the timeout —
                # fire an emergency rollback rather than leave the target in
                # an unknown, possibly-disruptive state.
                rollback_timer     = _EMERGENCY_ROLLBACK_DELAY_S
                rollback_scheduled = self._schedule_rollback(_EMERGENCY_ROLLBACK_DELAY_S)
                log.warning(
                    "Scheduling emergency rollback for timed-out action %s on %s at %s",
                    action_type, target, rollback_scheduled,
                )

            audit.log_action(
                case_id=case_id, action_type=action_type, target=target,
                platform="mcp", outcome="FAILED", action_id=action_id,
                error_detail=error_msg,
                rollback_timer_hours=rollback_timer / 3600.0 if rollback_timer else 0.0,
                rollback_scheduled_at=rollback_scheduled or None,
            )
            audit.log_error(
                case_id=case_id, error_type="EXECUTOR_ACTION_TIMEOUT",
                message=error_msg, exc=exc,
                context={
                    "action_type":         action_type,
                    "target":              target,
                    "case_id":             case_id,
                    "elapsed_ms":          elapsed,
                    "timeout_seconds":     _ACTION_EXECUTION_TIMEOUT_SECONDS,
                    "rollback_triggered":  bool(rollback_scheduled),
                    "rollback_scheduled_at": rollback_scheduled,
                },
            )
            return ActionResult(
                case_id=case_id, action_id=action_id,
                action_type=action_type, target=target,
                status=ActionStatus.FAILED.value,
                execution_time_ms=elapsed,
                verification=ActionVerification(error=error_msg),
                rollback_timer=rollback_timer, rollback_scheduled=rollback_scheduled,
                human_notified=False, notification_sent_to=[],
                justification=justification, error_detail=error_msg,
            )
        except Exception as exc:
            elapsed    = int(time.time() * 1000) - t0
            error_msg  = f"{type(exc).__name__}: {exc}"
            log.exception("Action %s failed for target %s: %s", action_type, target, exc)
            audit.log_action(
                case_id=case_id, action_type=action_type, target=target,
                platform="mcp", outcome="FAILED", action_id=action_id,
                error_detail=error_msg,
            )
            audit.log_error(
                case_id=case_id, error_type="ACTION_EXCEPTION",
                message=error_msg, exc=exc,
                context={"action_type": action_type, "target": target},
            )
            return ActionResult(
                case_id=case_id, action_id=action_id,
                action_type=action_type, target=target,
                status=ActionStatus.FAILED.value,
                execution_time_ms=elapsed,
                verification=ActionVerification(error=error_msg),
                rollback_timer=0, rollback_scheduled="",
                human_notified=False, notification_sent_to=[],
                justification=justification, error_detail=error_msg,
            )

        result.execution_time_ms = int(time.time() * 1000) - t0
        result.action_id = action_id

        audit.log_action(
            case_id=case_id,
            action_type=action_type,
            target=target,
            platform="mcp",
            outcome=result.status,
            action_id=action_id,
            rollback_timer_hours=result.rollback_timer / 3600.0 if result.rollback_timer else 0.0,
            rollback_scheduled_at=None,
            verification_passed=result.verification.verified,
            error_detail=result.error_detail,
            metadata={"urgency": urgency, "priority": priority},
        )

        log.info(
            "Action %s: status=%s target=%s time=%dms verified=%s",
            action_type, result.status, target,
            result.execution_time_ms, result.verification.verified,
        )
        return result

    # ------------------------------------------------------------------
    # Individual action handlers
    # ------------------------------------------------------------------

    def _isolate_host(
        self, *, action_id: str, case_id: str, target: str,
        justification: str, urgency: str, action_def: Dict, **_
    ) -> ActionResult:
        rollback_s  = int(action_def.get("rollback_timer", _DEFAULT_ROLLBACK["isolate_host"]))
        pre_state   = "connected"

        mcp_result = self._get_mcp().execute_response_action(
            action_type="isolate_host",
            target=target,
            case_id=case_id,
            rollback_timer=rollback_s,
            justification=justification,
            parameters={"urgency": urgency},
        )

        time.sleep(_VERIFY_WAIT_S)
        verification = self._verify_action("isolate_host", target=target, host=target)
        post_state   = "isolated" if verification.verified else "unknown"

        return ActionResult(
            case_id=case_id, action_id=action_id,
            action_type="isolate_host", target=target,
            status=(ActionStatus.SUCCESS if verification.verified else ActionStatus.FAILED).value,
            execution_time_ms=0,
            verification=ActionVerification(
                pre_state=pre_state, post_state=post_state,
                confirmation_source="edr_logs",
                confirmation_query=verification.confirmation_query,
                verified=verification.verified,
            ),
            rollback_timer=rollback_s,
            rollback_scheduled=self._schedule_rollback(rollback_s),
            human_notified=False, notification_sent_to=[],
            justification=justification,
            error_detail="" if verification.verified else "Post-action verification failed",
        )

    def _block_ip(
        self, *, action_id: str, case_id: str, target: str,
        justification: str, urgency: str, action_def: Dict, **_
    ) -> ActionResult:
        rollback_s  = int(action_def.get("rollback_timer", _DEFAULT_ROLLBACK["block_ip"]))
        duration_s  = int(action_def.get("duration", rollback_s))
        reason      = action_def.get("reason", justification)

        self._get_mcp().execute_response_action(
            action_type="block_ip",
            target=target,
            case_id=case_id,
            rollback_timer=duration_s,
            justification=reason,
            parameters={"duration_seconds": duration_s},
        )

        time.sleep(_VERIFY_WAIT_S)
        verification = self._verify_action("block_ip", target=target, host="")
        post_state   = "blocked" if verification.verified else "unknown"

        return ActionResult(
            case_id=case_id, action_id=action_id,
            action_type="block_ip", target=target,
            status=(ActionStatus.SUCCESS if verification.verified else ActionStatus.FAILED).value,
            execution_time_ms=0,
            verification=ActionVerification(
                pre_state="allowed", post_state=post_state,
                confirmation_source="firewall_logs",
                confirmation_query=verification.confirmation_query,
                verified=verification.verified,
            ),
            rollback_timer=duration_s,
            rollback_scheduled=self._schedule_rollback(duration_s),
            human_notified=False, notification_sent_to=[],
            justification=justification,
            error_detail="" if verification.verified else "Post-action verification failed",
        )

    def _disable_user(
        self, *, action_id: str, case_id: str, target: str,
        justification: str, urgency: str, action_def: Dict, **_
    ) -> ActionResult:
        rollback_s    = int(action_def.get("rollback_timer", _DEFAULT_ROLLBACK["disable_user"]))
        mgr_approval  = bool(action_def.get("requires_manager_approval", True))

        self._get_mcp().execute_response_action(
            action_type="disable_user",
            target=target,
            case_id=case_id,
            rollback_timer=rollback_s,
            justification=justification,
            parameters={"requires_manager_notification": mgr_approval},
        )

        time.sleep(_VERIFY_WAIT_S)
        verification = self._verify_action("disable_user", target=target, host="")
        post_state   = "disabled" if verification.verified else "unknown"

        return ActionResult(
            case_id=case_id, action_id=action_id,
            action_type="disable_user", target=target,
            status=(ActionStatus.SUCCESS if verification.verified else ActionStatus.FAILED).value,
            execution_time_ms=0,
            verification=ActionVerification(
                pre_state="enabled", post_state=post_state,
                confirmation_source="identity_logs",
                confirmation_query=verification.confirmation_query,
                verified=verification.verified,
            ),
            rollback_timer=rollback_s,
            rollback_scheduled=self._schedule_rollback(rollback_s),
            human_notified=False, notification_sent_to=[],
            justification=justification,
            error_detail="" if verification.verified else "Post-action verification failed",
        )

    def _kill_process(
        self, *, action_id: str, case_id: str, target: str,
        justification: str, urgency: str, action_def: Dict, **_
    ) -> ActionResult:
        # target format: "HOST:PID" or just PID string — parse accordingly
        host, pid = self._parse_host_pid(target)

        self._get_mcp().execute_response_action(
            action_type="kill_process",
            target=target,
            case_id=case_id,
            rollback_timer=0,
            justification=justification,
            parameters={"host": host, "pid": pid},
        )

        time.sleep(_VERIFY_WAIT_S)
        verification = self._verify_action("kill_process", target=pid or target, host=host)

        return ActionResult(
            case_id=case_id, action_id=action_id,
            action_type="kill_process", target=target,
            status=(ActionStatus.SUCCESS if verification.verified else ActionStatus.FAILED).value,
            execution_time_ms=0,
            verification=ActionVerification(
                pre_state="running", post_state="terminated" if verification.verified else "unknown",
                confirmation_source="edr_logs",
                confirmation_query=verification.confirmation_query,
                verified=verification.verified,
            ),
            rollback_timer=0,
            rollback_scheduled="",
            human_notified=False, notification_sent_to=[],
            justification=justification,
            error_detail="" if verification.verified else "Post-action verification failed",
        )

    def _quarantine_file(
        self, *, action_id: str, case_id: str, target: str,
        justification: str, urgency: str, action_def: Dict, **_
    ) -> ActionResult:
        rollback_s = int(action_def.get("rollback_timer", _DEFAULT_ROLLBACK["quarantine_file"]))
        host       = action_def.get("host", "")

        self._get_mcp().execute_response_action(
            action_type="quarantine_file",
            target=target,
            case_id=case_id,
            rollback_timer=rollback_s,
            justification=justification,
            parameters={"host": host, "file_path": target},
        )

        time.sleep(_VERIFY_WAIT_S)
        verification = self._verify_action("quarantine_file", target=target, host=host)

        return ActionResult(
            case_id=case_id, action_id=action_id,
            action_type="quarantine_file", target=target,
            status=(ActionStatus.SUCCESS if verification.verified else ActionStatus.FAILED).value,
            execution_time_ms=0,
            verification=ActionVerification(
                pre_state="accessible", post_state="quarantined" if verification.verified else "unknown",
                confirmation_source="edr_logs",
                confirmation_query=verification.confirmation_query,
                verified=verification.verified,
            ),
            rollback_timer=rollback_s,
            rollback_scheduled=self._schedule_rollback(rollback_s),
            human_notified=False, notification_sent_to=[],
            justification=justification,
            error_detail="" if verification.verified else "Post-action verification failed",
        )

    def _create_ticket(
        self, *, action_id: str, case_id: str, target: str,
        justification: str, urgency: str, action_def: Dict, **_
    ) -> ActionResult:
        system      = (action_def.get("system") or target or "servicenow").lower()
        title       = action_def.get("title") or f"SENTINEL case {case_id} — automated response"
        description = action_def.get("description") or justification
        priority    = action_def.get("ticket_priority", "P1")
        category    = action_def.get("category", "Security")

        mcp_result = self._get_mcp().create_ticket(
            case_id=case_id,
            system=system,
            title=title,
            description=description,
            priority=priority,
            category=category,
        )

        ticket_id  = (
            mcp_result.get("ticket_id")
            or mcp_result.get("id")
            or "UNKNOWN"
        )
        success    = bool(ticket_id and ticket_id != "UNKNOWN")

        return ActionResult(
            case_id=case_id, action_id=action_id,
            action_type="create_ticket", target=f"{system}:{ticket_id}",
            status=ActionStatus.SUCCESS.value if success else ActionStatus.FAILED.value,
            execution_time_ms=0,
            verification=ActionVerification(
                pre_state="no_ticket",
                post_state=f"ticket_created:{ticket_id}" if success else "failed",
                confirmation_source=system,
                confirmation_query=f"Ticket ID: {ticket_id}",
                verified=success,
            ),
            rollback_timer=0, rollback_scheduled="",
            human_notified=False, notification_sent_to=[],
            justification=justification,
            error_detail="" if success else f"Ticket creation returned no ID",
        )

    def _notify_stakeholders(
        self, *, action_id: str, case_id: str, target: str,
        justification: str, urgency: str, action_def: Dict, **_
    ) -> ActionResult:
        level    = action_def.get("level", "alert")
        message  = action_def.get("message") or justification
        channels = action_def.get("channels") or _ONCALL_CHANNELS
        recipients = action_def.get("recipients") or [self._get_oncall_email()]

        mcp_result = self._get_mcp().notify_stakeholders(
            case_id=case_id,
            level=level if level in {"alert", "update", "resolved", "custom"} else "alert",
            message=message,
            channels=channels,
            recipients=recipients,
            urgency=urgency,
        )
        success = mcp_result.get("sent", False) or mcp_result.get("status") == "sent"

        return ActionResult(
            case_id=case_id, action_id=action_id,
            action_type="notify_stakeholders", target=target or ",".join(channels),
            status=ActionStatus.SUCCESS.value if success else ActionStatus.FAILED.value,
            execution_time_ms=0,
            verification=ActionVerification(
                pre_state="unsent",
                post_state="sent" if success else "failed",
                confirmation_source="notification_api",
                confirmation_query=f"Channels: {channels}",
                verified=success,
            ),
            rollback_timer=0, rollback_scheduled="",
            human_notified=success,
            notification_sent_to=recipients if success else [],
            justification=justification,
            error_detail="" if success else "Notification delivery unconfirmed",
        )

    def _trigger_playbook(
        self, *, action_id: str, case_id: str, target: str,
        justification: str, urgency: str, action_def: Dict, **_
    ) -> ActionResult:
        """
        Trigger an external SOAR playbook. Falls back to a Slack notification
        with playbook request if the SOAR endpoint is unavailable.
        """
        playbook_id = action_def.get("playbook_id") or target
        parameters  = action_def.get("parameters") or {}
        soar_url    = os.environ.get(_ENV_SOAR_URL, self._cfg.get("integrations", "soar_url", default=""))
        soar_token  = os.environ.get(_ENV_SOAR_TOKEN, self._cfg.get("integrations", "soar_token", default=""))

        success     = False
        error_detail = ""
        post_state   = "failed"

        if soar_url and soar_token:
            try:
                session = requests.Session()
                adapter = HTTPAdapter(max_retries=Retry(total=2, backoff_factor=0.5))
                session.mount("https://", adapter)
                session.mount("http://",  adapter)
                resp = session.post(
                    f"{soar_url.rstrip('/')}/playbooks/{playbook_id}/run",
                    json={"case_id": case_id, "parameters": parameters},
                    headers={"Authorization": f"Bearer {soar_token}"},
                    timeout=20.0,
                    verify=False,
                )
                success    = resp.ok
                post_state = "triggered" if success else "failed"
                if not success:
                    error_detail = f"SOAR returned HTTP {resp.status_code}"
            except Exception as exc:
                error_detail = f"SOAR call failed: {exc}"
                log.warning("SOAR playbook trigger failed: %s", exc)
        else:
            # Fallback: notify via MCP
            log.warning(
                "SOAR not configured; falling back to Slack notification for playbook %s",
                playbook_id,
            )
            try:
                self._get_mcp().notify_stakeholders(
                    case_id=case_id,
                    level="alert",
                    message=(
                        f"[SENTINEL] Playbook trigger requested: {playbook_id}\n"
                        f"Case: {case_id} | Justification: {justification}\n"
                        f"Parameters: {json.dumps(parameters, default=str)}"
                    ),
                    channels=_ONCALL_CHANNELS,
                    urgency=urgency,
                )
                success    = True
                post_state = "notification_sent"
            except MCPError as exc:
                error_detail = f"Fallback notification failed: {exc}"

        return ActionResult(
            case_id=case_id, action_id=action_id,
            action_type="trigger_playbook", target=playbook_id,
            status=ActionStatus.SUCCESS.value if success else ActionStatus.FAILED.value,
            execution_time_ms=0,
            verification=ActionVerification(
                pre_state="idle",
                post_state=post_state,
                confirmation_source="soar_api" if soar_url else "slack_notification",
                confirmation_query=f"Playbook: {playbook_id}",
                verified=success,
            ),
            rollback_timer=0, rollback_scheduled="",
            human_notified=success, notification_sent_to=[],
            justification=justification,
            error_detail=error_detail,
        )

    # ------------------------------------------------------------------
    # Post-action verification
    # ------------------------------------------------------------------

    def _verify_action(
        self,
        action_type: str,
        target: str,
        host: str = "",
    ) -> ActionVerification:
        """Re-query Splunk after an action to confirm effect."""
        template = _VERIFICATION_QUERIES.get(action_type)
        if not template:
            return ActionVerification(
                pre_state="n/a", post_state="n/a",
                confirmation_source="none",
                confirmation_query="no verification query defined",
                verified=True,  # assume success for ticket/notify
            )

        query = template.format(target=target, host=host or target)
        try:
            raw = self._get_mcp().search_spl(
                query=query,
                earliest="-5m",
                latest="now",
                max_results=5,
                timeout=_VERIFY_TIMEOUT_S,
            )
            rows = raw if isinstance(raw, list) else raw.get("results", [])
            result_val = ""
            if rows:
                result_val = str(rows[0].get("result", rows[0].get("verify_status", "")))
            verified = result_val.lower() == "confirmed"
            return ActionVerification(
                pre_state="pre-action",
                post_state="confirmed" if verified else "pending",
                confirmation_source="splunk_spl",
                confirmation_query=query,
                verified=verified,
            )
        except MCPError as exc:
            log.warning("Verification query failed for %s/%s: %s", action_type, target, exc)
            return ActionVerification(
                pre_state="unknown",
                post_state="unverified",
                confirmation_source="splunk_spl",
                confirmation_query=query,
                verified=False,
                error=str(exc),
            )

    # ------------------------------------------------------------------
    # Rollback scheduling
    # ------------------------------------------------------------------

    def _schedule_rollback(self, timer_s: int) -> str:
        """Return an ISO-8601 timestamp when the rollback should fire."""
        if timer_s <= 0:
            return ""
        scheduled = datetime.now(timezone.utc) + timedelta(seconds=timer_s)
        return scheduled.isoformat()

    # ------------------------------------------------------------------
    # Notification dispatch
    # ------------------------------------------------------------------

    def _send_notifications(
        self,
        case_id:       str,
        case_summary:  Dict,
        action_results: List[ActionResult],
        pending_notifications: List[Tuple[str, str, int]],
        audit: AuditLogger,
    ) -> List[str]:
        """
        Send Slack alert for high-priority actions and an email digest for all.
        Returns list of notified recipients.
        """
        notified: List[str] = []
        oncall   = self._get_oncall_email()

        successful = [r for r in action_results if r.status == ActionStatus.SUCCESS.value]
        failed     = [r for r in action_results if r.status == ActionStatus.FAILED.value]

        if not successful and not failed:
            return notified

        classification = case_summary.get("classification", "UNKNOWN")
        risk_score     = case_summary.get("risk_score", 0)

        # Slack: immediate alert for critical containment actions
        critical_actions = [
            (at, tgt) for at, tgt, pri in pending_notifications
            if pri <= 2 and at in _CONTAINMENT_ACTIONS
        ]
        if critical_actions:
            try:
                action_summary = "; ".join(f"{at}({tgt})" for at, tgt in critical_actions[:5])
                self._get_mcp().notify_stakeholders(
                    case_id=case_id,
                    level="alert",
                    message=(
                        f"[SENTINEL CRITICAL] Case {case_id} | Score {risk_score} | "
                        f"{classification}\n"
                        f"Actions executed: {action_summary}\n"
                        f"Failed: {len(failed)} | Successful: {len(successful)}"
                    ),
                    channels=["slack"],
                    recipients=[oncall],
                    urgency="high",
                )
                notified.extend(_ONCALL_CHANNELS)
            except MCPError as exc:
                log.warning("Slack notification failed: %s", exc)

        # Email: full digest
        try:
            action_lines = "\n".join(
                f"  [{r.status}] {r.action_type} → {r.target}"
                + (f" (verified: {r.verification.post_state})" if r.verification else "")
                for r in action_results
                if r.status != ActionStatus.SKIPPED.value
            )
            self._get_mcp().notify_stakeholders(
                case_id=case_id,
                level="update",
                message=(
                    f"SENTINEL Response Summary — {case_id}\n"
                    f"Classification: {classification} | Score: {risk_score}\n"
                    f"Successful: {len(successful)} | Failed: {len(failed)}\n\n"
                    f"Actions:\n{action_lines or '(none)'}"
                ),
                channels=["email"],
                recipients=[oncall],
                urgency="normal",
            )
            if oncall not in notified:
                notified.append(oncall)
        except MCPError as exc:
            log.warning("Email digest notification failed: %s", exc)

        return notified

    # ------------------------------------------------------------------
    # Report builder
    # ------------------------------------------------------------------

    def _build_log(
        self,
        case_id:       str,
        mode:          ExecutorMode,
        risk_score:    int,
        actions:       List[ActionResult],
        halted:        bool,
        halt_reason:   str,
        t0:            int,
        alert_id:      str = "",
        classification: str = "",
        action_chain:  Optional[List[Dict]] = None,
    ) -> ExecutorActionLog:
        successful = sum(1 for a in actions if a.status == ActionStatus.SUCCESS.value)
        failed     = sum(1 for a in actions if a.status == ActionStatus.FAILED.value)
        skipped    = sum(1 for a in actions if a.status == ActionStatus.SKIPPED.value)
        duration_s = (int(time.time() * 1000) - t0) // 1000

        return ExecutorActionLog(
            case_id=case_id,
            executor_mode=mode.value,
            risk_score=risk_score,
            actions=actions,
            total_actions=len(actions),
            successful_actions=successful,
            failed_actions=failed,
            skipped_actions=skipped,
            halted=halted,
            halt_reason=halt_reason,
            duration_seconds=duration_s,
            alert_id=alert_id,
            classification=classification,
            action_chain=action_chain or [],
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_host_pid(target: str) -> Tuple[str, str]:
        """Parse 'HOST:PID' or plain PID/name from target string."""
        if ":" in target:
            parts = target.split(":", 1)
            return parts[0].strip(), parts[1].strip()
        return "", target.strip()


# ---------------------------------------------------------------------------
# Module-level entry point  (orchestrator _AgentProxy interface)
# ---------------------------------------------------------------------------

def run(case: Any, audit: Optional[AuditLogger] = None, **_kwargs) -> Dict:
    """Run Executor on a Case and return ExecutorActionLog as dict."""
    return ExecutorAgent().run(case, audit or get_audit_logger(_AGENT_NAME))

