"""
SENTINEL: Autonomous Agentic SOC Commander
sentinel_orchestrator.py — Main orchestration engine

SentinelOrchestrator is the conductor of the four-agent pipeline. It:
  - Drains the case_queue KV Store collection on each polling tick
  - Spawns a worker thread per case (up to MAX_CONCURRENT_CASES)
  - Drives the case state machine: QUEUED → TRIAGING → INVESTIGATING →
    DECIDING → RESPONDING → LEARNING → CLOSED
  - Routes each state to the appropriate agent module
  - Handles retries (max 3 per case), halts, resumes, and emergency stops
  - Emits structured audit events at every state transition

State machine diagram:
  QUEUED ──────────────────────────────────────────────────────► TRIAGING
  TRIAGING ────────────────────────────────────────────────────► INVESTIGATING
  TRIAGING (score < threshold) ──────────────────────────────► CLOSED
  INVESTIGATING ───────────────────────────────────────────────► DECIDING
  DECIDING (auto-respond) ────────────────────────────────────► RESPONDING
  DECIDING (needs approval) ──────────────────────────────────► HALTED
  RESPONDING ──────────────────────────────────────────────────► LEARNING
  LEARNING ────────────────────────────────────────────────────► CLOSED
  Any ──────────────────────────────────────────────────────────► ERROR
  Any ──────────────────────────────────────────────────────────► HALTED
  ERROR (retry available) ─────────────────────────────────────► (previous)
  ERROR (retries exhausted) ──────────────────────────────────► CLOSED (escalated)
  HALTED ──────────────────────────────────────────────────────► (resume target)

Usage as a scripted input:
  python sentinel_orchestrator.py          # poll loop
  python sentinel_orchestrator.py --once   # single poll cycle (cron mode)
  python sentinel_orchestrator.py --demo   # run mock alert demo
"""

from __future__ import annotations

import importlib
import json
import logging
import os
import queue
import sys
import threading
import time
import traceback
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set

# ---------------------------------------------------------------------------
# Bootstrap: make sure our bin/ directory is on sys.path so sibling
# imports work regardless of how Splunk invokes this script.
# ---------------------------------------------------------------------------
_BIN_DIR = Path(__file__).resolve().parent
if str(_BIN_DIR) not in sys.path:
    sys.path.insert(0, str(_BIN_DIR))

from utils.state_manager import CaseStateManager, CaseStatus, Case
from utils.config_loader  import get_config
from audit_logger         import AuditLogger, get_audit_logger

log = logging.getLogger("sentinel.orchestrator")


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAX_CONCURRENT_CASES  = 5
MAX_RETRIES_PER_CASE  = 3
POLL_INTERVAL_SECONDS = 60
AUTO_RESPOND_SCORE    = 90    # Executor acts without approval above this

# Priority ordering — higher number = higher priority in the work queue
_PRIORITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

# ---------------------------------------------------------------------------
# Fault tolerance — watchdog / dead-letter queue
# ---------------------------------------------------------------------------
WATCHDOG_INTERVAL_SECONDS     = 30     # how often the watchdog scans for hung cases
DEFAULT_STATE_TIMEOUT_SECONDS = 900    # 15 minutes — armed on every stage transition
_COLLECTION_DEAD_LETTER       = "dead_letter_queue"

# Which agent owns each pipeline stage — used for dead-letter diagnostics
_STATUS_TO_AGENT = {
    CaseStatus.TRIAGING:      "vanguard",
    CaseStatus.INVESTIGATING: "sherlock",
    CaseStatus.DECIDING:      "orchestrator",
    CaseStatus.RESPONDING:    "executor",
    CaseStatus.LEARNING:      "sage",
}

# Statuses a recovered/retried case may legitimately resume into
_RESUMABLE_STATUSES = (
    CaseStatus.QUEUED, CaseStatus.TRIAGING, CaseStatus.INVESTIGATING,
    CaseStatus.DECIDING, CaseStatus.RESPONDING, CaseStatus.LEARNING,
)


def _agent_for_status(status: CaseStatus) -> str:
    return _STATUS_TO_AGENT.get(status, "orchestrator")


def _recommend_human_action(failed_agent: str, original_status: str) -> str:
    return (
        f"Review manually: the {failed_agent} stage ({original_status}) repeatedly timed "
        f"out and exhausted its retry budget. Check {failed_agent} health/connectivity, "
        f"then either acknowledge and close the case or call recover_from_dead_letter() "
        f"to reset its retry budget and re-queue it."
    )


# ---------------------------------------------------------------------------
# Agent registry — lazy-loaded so missing agents don't crash the orchestrator
# ---------------------------------------------------------------------------

class _AgentProxy:
    """
    Thin wrapper that lazy-imports an agent module and calls its run() entry
    point. If the module is missing, the proxy returns an error result instead
    of raising so the orchestrator can put the case in ERROR state gracefully.
    """

    def __init__(self, module_path: str, agent_name: str) -> None:
        self._module_path = module_path
        self._agent_name  = agent_name
        self._module: Any = None

    def run(self, case: Case, audit: AuditLogger, **kwargs: Any) -> Dict[str, Any]:
        if self._module is None:
            try:
                self._module = importlib.import_module(self._module_path)
            except ImportError as exc:
                return {
                    "success": False,
                    "error":   f"Agent module '{self._module_path}' not found: {exc}",
                    "agent":   self._agent_name,
                }

        try:
            return self._module.run(case=case, audit=audit, **kwargs)
        except Exception as exc:
            tb = traceback.format_exc()
            log.error("Agent %s raised exception: %s\n%s", self._agent_name, exc, tb)
            return {
                "success": False,
                "error":   str(exc),
                "traceback": tb,
                "agent":   self._agent_name,
            }

    @property
    def name(self) -> str:
        return self._agent_name


# ---------------------------------------------------------------------------
# Agent health status
# ---------------------------------------------------------------------------

@dataclass
class AgentStatus:
    name:              str
    healthy:           bool   = True
    last_run_at:       float  = 0.0
    cases_processed:   int    = 0
    current_case_id:   str    = ""
    last_error:        str    = ""
    avg_latency_ms:    float  = 0.0
    _latency_samples:  List[float] = field(default_factory=list, repr=False)

    def record_run(self, latency_ms: float, success: bool, error: str = "") -> None:
        self.last_run_at    = time.time()
        self.cases_processed += 1
        self.healthy        = success
        self.last_error     = error if not success else ""
        self._latency_samples.append(latency_ms)
        # Rolling average over last 20 samples
        if len(self._latency_samples) > 20:
            self._latency_samples.pop(0)
        self.avg_latency_ms = sum(self._latency_samples) / len(self._latency_samples)


# ---------------------------------------------------------------------------
# Priority work item for the internal queue
# ---------------------------------------------------------------------------

@dataclass(order=True)
class _WorkItem:
    priority:   int         = field(compare=True)   # higher = processed first
    created_at: float       = field(compare=False)
    case_id:    str         = field(compare=False)
    alert_id:   str         = field(compare=False)
    alert_type: str         = field(compare=False)
    raw_data:   Dict[str, Any] = field(compare=False, default_factory=dict)

    @classmethod
    def from_case(cls, case: Case) -> "_WorkItem":
        return cls(
            priority   = _PRIORITY_ORDER.get(case.priority, 2),
            created_at = case.created_time,
            case_id    = case.case_id,
            alert_id   = case.alert_id,
            alert_type = case.alert_type,
            raw_data   = {},
        )


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

class SentinelOrchestrator:
    """
    Central state machine driver for the SENTINEL agent pipeline.

    Thread model:
      - Main thread: polling loop (start()) that drains case_queue and
        submits work items to the priority queue.
      - Worker pool: up to MAX_CONCURRENT_CASES daemon threads, each
        driving one case through the full pipeline.
      - No shared mutable state between workers — each case has its own
        lock inside CaseStateManager.
    """

    def __init__(
        self,
        state_manager: Optional[CaseStateManager] = None,
        max_concurrent: int = MAX_CONCURRENT_CASES,
        poll_interval: int  = POLL_INTERVAL_SECONDS,
        dry_run: bool       = False,
    ) -> None:
        self._sm             = state_manager or CaseStateManager()
        self._max_concurrent = max_concurrent
        self._poll_interval  = poll_interval
        self._dry_run        = dry_run

        # Priority queue (negative priority so heapq pops highest first)
        self._work_queue: queue.PriorityQueue = queue.PriorityQueue()
        self._active_cases: Set[str]          = set()
        self._active_lock                     = threading.Lock()

        # Semaphore limits concurrent case workers
        self._slots = threading.BoundedSemaphore(max_concurrent)

        # Worker thread pool (daemon so they don't block clean shutdown)
        self._workers: List[threading.Thread] = []
        for i in range(max_concurrent):
            t = threading.Thread(
                target=self._worker_loop,
                name=f"sentinel-worker-{i}",
                daemon=True,
            )
            self._workers.append(t)

        # Watchdog thread — scans for hung cases every WATCHDOG_INTERVAL_SECONDS
        self._watchdog_thread = threading.Thread(
            target=self._watchdog_loop,
            name="sentinel-watchdog",
            daemon=True,
        )

        # Agent proxies — modules loaded lazily on first use
        self._agents = {
            "vanguard":  _AgentProxy("agent_vanguard",  "vanguard"),
            "sherlock":  _AgentProxy("agent_sherlock",  "sherlock"),
            "executor":  _AgentProxy("agent_executor",  "executor"),
            "sage":      _AgentProxy("agent_sage",      "sage"),
        }

        # Per-agent health tracking
        self._agent_status: Dict[str, AgentStatus] = {
            name: AgentStatus(name=name) for name in self._agents
        }

        self._audit = get_audit_logger("orchestrator")
        self._running = False
        self._stop_event = threading.Event()

        log.info(
            "SentinelOrchestrator initialised",
            extra={
                "max_concurrent": max_concurrent,
                "poll_interval":  poll_interval,
                "dry_run":        dry_run,
            },
        )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """
        Start the polling loop and worker threads.
        Blocks until stop() is called or a KeyboardInterrupt is received.
        """
        self._running = True
        self._stop_event.clear()

        for t in self._workers:
            if not t.is_alive():
                t.start()

        if not self._watchdog_thread.is_alive():
            self._watchdog_thread.start()

        log.info("Orchestrator started — entering poll loop (interval=%ds)",
                 self._poll_interval)

        try:
            while not self._stop_event.is_set():
                cycle_start = time.time()
                try:
                    self._poll_cycle()
                except Exception as exc:
                    log.error("Poll cycle error: %s", exc, exc_info=True)

                elapsed = time.time() - cycle_start
                sleep_for = max(0.0, self._poll_interval - elapsed)
                self._stop_event.wait(timeout=sleep_for)
        except KeyboardInterrupt:
            log.info("KeyboardInterrupt received; shutting down")
        finally:
            self.stop()

    def stop(self) -> None:
        """Signal the orchestrator to stop after the current cycle completes."""
        self._running = False
        self._stop_event.set()
        log.info("Orchestrator stop signal sent")

    def poll_once(self) -> int:
        """
        Run a single poll cycle (for cron/scripted input mode).
        Returns the number of cases enqueued.
        """
        return self._poll_cycle()

    # ------------------------------------------------------------------
    # Alert ingestion
    # ------------------------------------------------------------------

    def process_alert(
        self,
        alert_id: str,
        alert_type: str = "UNKNOWN",
        affected_host: str = "",
        affected_user: str = "",
        risk_score: int = 50,
        priority: str = "MEDIUM",
        raw_data: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Create a case for the given alert and enqueue it for processing.
        Returns the new case_id.

        This is the primary entry point used by the sentinel_trigger alert
        action and by unit tests.
        """
        case = self._sm.create_case(
            alert_id=alert_id,
            alert_type=alert_type,
            affected_host=affected_host,
            affected_user=affected_user,
            risk_score=risk_score,
            priority=priority,
        )

        self._audit.log_transition(
            case_id=case.case_id,
            from_status="CREATED",
            to_status=CaseStatus.QUEUED.value,
            trigger="process_alert",
            metadata={"alert_id": alert_id, "alert_type": alert_type},
        )

        item = _WorkItem.from_case(case)
        if raw_data:
            item.raw_data = raw_data

        # Negate priority so Python's min-heap pops the highest value first
        item.priority = -item.priority
        self._work_queue.put(item)

        log.info(
            "Alert enqueued",
            extra={
                "case_id":    case.case_id,
                "alert_id":   alert_id,
                "alert_type": alert_type,
                "priority":   priority,
                "risk_score": risk_score,
            },
        )
        return case.case_id

    # ------------------------------------------------------------------
    # State transitions
    # ------------------------------------------------------------------

    def transition(
        self,
        case_id: str,
        to_status: CaseStatus,
        agent_name: str = "orchestrator",
        detail: str = "",
    ) -> Case:
        """
        Validate and execute a state transition, writing to KV Store and
        emitting an audit event.
        """
        case = self._sm.transition(case_id, to_status,
                                   agent_name=agent_name, detail=detail)
        self._audit.log_transition(
            case_id=case_id,
            from_status=case.audit_trail[-1]["from_status"] if case.audit_trail else "UNKNOWN",
            to_status=to_status.value,
            trigger=agent_name,
            metadata={"detail": detail},
        )
        return case

    def halt_case(self, case_id: str, reason: str = "manual halt") -> Case:
        """
        Immediately halt processing of a case. The case can be resumed via
        resume_case(). Safe to call from any thread.
        """
        case = self._sm.transition(
            case_id, CaseStatus.HALTED,
            agent_name="orchestrator",
            detail=reason,
        )
        log.warning("Case HALTED: %s — %s", case_id, reason)
        self._audit.log_transition(
            case_id=case_id,
            from_status="(any)",
            to_status=CaseStatus.HALTED.value,
            trigger="halt_case",
            metadata={"reason": reason},
        )
        return case

    def resume_case(
        self,
        case_id: str,
        resume_status: Optional[CaseStatus] = None,
    ) -> Case:
        """
        Resume a halted case. If resume_status is None, the case is re-queued
        at the QUEUED stage and will be re-triaged from scratch.
        """
        case = self._sm.get_case(case_id)
        if case is None:
            raise KeyError(f"Case {case_id} not found")
        if case.status != CaseStatus.HALTED.value:
            raise ValueError(f"Case {case_id} is not HALTED (status: {case.status})")

        target = resume_status or CaseStatus.QUEUED
        updated = self._sm.transition(
            case_id, target,
            agent_name="orchestrator",
            detail="resumed",
        )

        if target == CaseStatus.QUEUED:
            item = _WorkItem.from_case(updated)
            item.priority = -item.priority
            self._work_queue.put(item)
            log.info("Case resumed and re-queued: %s", case_id)
        else:
            log.info("Case resumed to %s: %s", target.value, case_id)

        return updated

    # ------------------------------------------------------------------
    # Fault tolerance — watchdog, retries, and the dead letter queue
    # ------------------------------------------------------------------

    def _watchdog_loop(self) -> None:
        """
        Background thread: every WATCHDOG_INTERVAL_SECONDS, scan for cases
        that have outstayed their state timeout and recover them — either by
        retrying the stage that hung, or by dead-lettering the case once its
        retry budget is exhausted.
        """
        log.info("Watchdog started — scanning every %ds", WATCHDOG_INTERVAL_SECONDS)
        while not self._stop_event.is_set():
            try:
                handled = self._run_watchdog_cycle()
                if handled:
                    log.info("Watchdog cycle handled %d timed-out case(s)", handled)
            except Exception as exc:
                log.error("Watchdog cycle error: %s", exc, exc_info=True)
            self._stop_event.wait(timeout=WATCHDOG_INTERVAL_SECONDS)
        log.info("Watchdog stopped")

    def _run_watchdog_cycle(self) -> int:
        """Detect and recover all currently timed-out cases. Returns the count handled."""
        timed_out = self._sm.check_timeouts()
        for case_id in timed_out:
            try:
                self._handle_timed_out_case(case_id)
            except Exception as exc:
                log.error("Watchdog failed to recover case %s: %s", case_id, exc, exc_info=True)
        return len(timed_out)

    def _handle_timed_out_case(self, case_id: str) -> None:
        """
        A single case has outstayed its state timeout. Mark it STUCK, then
        either retry the stage (if budget remains) or dead-letter it.
        """
        case = self._sm.get_case(case_id)
        if case is None:
            return

        original_status = case.status
        # Already mid-recovery or in a terminal/special state — nothing to do
        if original_status in (
            CaseStatus.STUCK.value, CaseStatus.RETRYING.value, CaseStatus.DEAD_LETTER.value,
            CaseStatus.ERROR.value, CaseStatus.HALTED.value,
            CaseStatus.CLOSED.value, CaseStatus.SUPPRESSED.value,
        ):
            return

        failed_agent   = _agent_for_status(CaseStatus(original_status))
        timeout_reason = (
            f"Case stuck in {original_status} for over "
            f"{case.timeout_duration_seconds}s (no progress since "
            f"{case.state_entered_at})"
        )
        log.warning("Watchdog: case %s timed out in %s — %s", case_id, original_status, timeout_reason)

        try:
            self._sm.transition(case_id, CaseStatus.STUCK,
                                agent_name="watchdog", detail=timeout_reason)
        except ValueError as exc:
            log.warning("Watchdog: could not mark case %s STUCK: %s", case_id, exc)
            return

        self._audit.log_error(
            case_id=case_id, error_type="STATE_TIMEOUT",
            message=timeout_reason, is_fatal=False,
            context={
                "stage": original_status, "failed_agent": failed_agent,
                "timeout_duration_seconds": case.timeout_duration_seconds,
                "retry_count": case.retry_count, "max_retries": case.max_retries,
            },
        )

        if self._sm.has_exhausted_retries(case_id):
            self._dead_letter_case(case_id, original_status, failed_agent, timeout_reason)
        else:
            self._retry_timed_out_case(case_id, original_status, failed_agent)

    def _retry_timed_out_case(self, case_id: str, original_status: str, failed_agent: str) -> None:
        """Bounce a hung case through RETRYING and re-queue it for the same agent."""
        self._sm.transition(case_id, CaseStatus.RETRYING, agent_name="watchdog",
                            detail=f"retrying after timeout in {original_status}")
        new_count = self._sm.increment_retry(case_id)

        try:
            target_status = CaseStatus(original_status)
            if target_status not in _RESUMABLE_STATUSES:
                target_status = CaseStatus.QUEUED
        except ValueError:
            target_status = CaseStatus.QUEUED

        case = self._sm.set_state_with_timeout(
            case_id, target_status,
            timeout_seconds=DEFAULT_STATE_TIMEOUT_SECONDS,
            agent_name="watchdog",
            detail=f"re-queued for {failed_agent} (retry {new_count}/{MAX_RETRIES_PER_CASE})",
        )

        with self._active_lock:
            self._active_cases.discard(case_id)
        item = _WorkItem.from_case(case)
        item.priority = -item.priority
        self._work_queue.put(item)

        log.info("Watchdog: case %s re-queued for %s (retry %d/%d)",
                 case_id, failed_agent, new_count, case.max_retries)
        self._audit.log_transition(
            case_id=case_id, from_status=CaseStatus.STUCK.value,
            to_status=target_status.value, trigger="watchdog",
            metadata={"retry_count": new_count, "failed_agent": failed_agent},
        )

    def _dead_letter_case(self, case_id: str, original_status: str,
                          failed_agent: str, timeout_reason: str) -> None:
        """Retries exhausted — move the case to ERROR → DEAD_LETTER and alert stakeholders."""
        case = self._sm.get_case(case_id)
        if case is None:
            return
        final_error = case.last_error or timeout_reason

        try:
            self._sm.transition(case_id, CaseStatus.ERROR, agent_name="watchdog",
                                detail=f"retries exhausted ({case.retry_count}/{case.max_retries})")
        except ValueError as exc:
            log.warning("Watchdog: could not transition case %s to ERROR: %s", case_id, exc)

        case = self._sm.transition(case_id, CaseStatus.DEAD_LETTER, agent_name="watchdog",
                                   detail="moved to dead letter queue — retries exhausted")

        record = {
            "case_id":                  case_id,
            "original_status":          original_status,
            "failed_agent":             failed_agent,
            "timeout_reason":           timeout_reason,
            "retry_count":              case.retry_count,
            "final_error":              final_error,
            "dead_lettered_at":         time.time(),
            "recommended_human_action": _recommend_human_action(failed_agent, original_status),
            "preserved_context": {
                "alert_id":          case.alert_id,
                "alert_type":        case.alert_type,
                "affected_host":     case.affected_host,
                "affected_user":     case.affected_user,
                "risk_score":        case.risk_score,
                "vanguard_decision": case.vanguard_decision,
                "sherlock_report":   case.sherlock_report,
                "executor_actions":  case.executor_actions,
                "audit_trail":       case.audit_trail[-10:],
            },
        }
        self._write_dead_letter_record(record)

        log.error("Watchdog: case %s DEAD-LETTERED — %s exhausted retries while in %s",
                  case_id, failed_agent, original_status)
        self._audit.log_transition(
            case_id=case_id, from_status=CaseStatus.ERROR.value,
            to_status=CaseStatus.DEAD_LETTER.value, trigger="watchdog",
            metadata={"failed_agent": failed_agent, "retry_count": case.retry_count,
                      "reason": timeout_reason},
        )

        self._notify_dead_letter(case, record)

    def recover_from_dead_letter(self, case_id: str, agent_name: str = "operator") -> Case:
        """
        Manually recover a dead-lettered case: reset its retry budget and
        re-queue it from the stage where it last made progress (or QUEUED if
        that stage can no longer be resumed).
        """
        case = self._sm.get_case(case_id)
        if case is None:
            raise KeyError(f"Case {case_id} not found")
        if case.status != CaseStatus.DEAD_LETTER.value:
            raise ValueError(f"Case {case_id} is not in DEAD_LETTER (status: {case.status})")

        record = self._read_dead_letter_record(case_id) or {}
        try:
            target_status = CaseStatus(record.get("original_status", CaseStatus.QUEUED.value))
            if target_status not in _RESUMABLE_STATUSES:
                target_status = CaseStatus.QUEUED
        except ValueError:
            target_status = CaseStatus.QUEUED

        self._sm.update_case(
            case_id, {"retry_count": 0, "last_error": ""},
            agent_name=agent_name, detail="dead-letter recovery: retry budget reset",
        )
        updated = self._sm.set_state_with_timeout(
            case_id, target_status,
            timeout_seconds=DEFAULT_STATE_TIMEOUT_SECONDS,
            agent_name=agent_name, detail="recovered from dead letter queue",
        )

        item = _WorkItem.from_case(updated)
        item.priority = -item.priority
        self._work_queue.put(item)
        self._remove_dead_letter_record(case_id)

        log.info("Case %s recovered from dead letter queue → %s", case_id, target_status.value)
        self._audit.log_transition(
            case_id=case_id, from_status=CaseStatus.DEAD_LETTER.value,
            to_status=target_status.value, trigger="recover_from_dead_letter",
            metadata={"agent": agent_name},
        )
        return updated

    def _notify_dead_letter(self, case: Case, record: Dict[str, Any]) -> None:
        """Immediately alert on-call stakeholders that a case needs human review."""
        try:
            from agent_executor import ExecutorAgent
            ExecutorAgent().execute_action(
                {
                    "action":        "notify_stakeholders",
                    "target":        "soc-oncall",
                    "level":         "alert",
                    "urgency":       "immediate",
                    "justification": (
                        f"Case {case.case_id} ({case.alert_type}) exhausted its retry budget "
                        f"in the {record['failed_agent']} stage and was moved to the dead "
                        f"letter queue. {record['recommended_human_action']}"
                    ),
                    "message": (
                        f"DEAD LETTER: case {case.case_id} requires human review — "
                        f"{record['timeout_reason']}"
                    ),
                },
                case_id=case.case_id,
                risk_score=case.risk_score or 100,
            )
        except Exception as exc:
            log.error("Failed to notify stakeholders for dead-lettered case %s: %s",
                      case.case_id, exc)

    def _write_dead_letter_record(self, record: Dict[str, Any]) -> None:
        try:
            from utils.splunk_connector import get_connector
            conn = get_connector()
            conn.kvstore_upsert(_COLLECTION_DEAD_LETTER, record["case_id"], dict(record))
        except Exception as exc:
            log.error("Failed to persist dead-letter record for case %s: %s",
                      record.get("case_id"), exc)

    def _read_dead_letter_record(self, case_id: str) -> Optional[Dict[str, Any]]:
        try:
            from utils.splunk_connector import get_connector
            conn = get_connector()
            return conn.kvstore_get(_COLLECTION_DEAD_LETTER, case_id)
        except Exception as exc:
            log.debug("Dead-letter record lookup skipped for %s: %s", case_id, exc)
            return None

    def _remove_dead_letter_record(self, case_id: str) -> None:
        try:
            from utils.splunk_connector import get_connector
            conn = get_connector()
            conn.kvstore_delete(_COLLECTION_DEAD_LETTER, case_id)
        except Exception as exc:
            log.debug("Dead-letter record removal skipped for %s: %s", case_id, exc)

    def get_dead_letter_queue(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Return current dead-letter records for the War Room dashboard."""
        try:
            from utils.splunk_connector import get_connector
            conn = get_connector()
            return conn.kvstore_query(_COLLECTION_DEAD_LETTER, limit=limit)
        except Exception as exc:
            log.debug("Dead-letter queue listing skipped: %s", exc)
            return []

    # ------------------------------------------------------------------
    # Agent status
    # ------------------------------------------------------------------

    def get_agent_status(self) -> Dict[str, Dict[str, Any]]:
        """Return health and performance metrics for all four agents."""
        return {
            name: {
                "name":             s.name,
                "healthy":          s.healthy,
                "last_run_at":      s.last_run_at,
                "cases_processed":  s.cases_processed,
                "current_case_id":  s.current_case_id,
                "last_error":       s.last_error,
                "avg_latency_ms":   round(s.avg_latency_ms, 1),
            }
            for name, s in self._agent_status.items()
        }

    def get_queue_depth(self) -> int:
        return self._work_queue.qsize()

    def get_active_count(self) -> int:
        with self._active_lock:
            return len(self._active_cases)

    # ------------------------------------------------------------------
    # Internal: polling and worker
    # ------------------------------------------------------------------

    def _poll_cycle(self) -> int:
        """
        Drain the case_queue KV Store collection and enqueue work items.
        Also picks up any QUEUED cases that were missed in previous cycles.
        Returns the number of cases enqueued this cycle.
        """
        enqueued = 0

        # 1. Drain the KV Store case_queue (written by alert action)
        try:
            from utils.splunk_connector import get_connector
            conn = get_connector()
            pending = conn.kvstore_query(
                "case_queue",
                query={"status": "PENDING"},
                limit=50,
            )
            for record in pending:
                self._ingest_queue_record(record)
                conn.kvstore_upsert(
                    "case_queue",
                    record["_key"],
                    {**record, "status": "PROCESSING"},
                )
                enqueued += 1
        except Exception as exc:
            # KV Store may not be available in test mode — log and continue
            log.debug("KV Store poll skipped: %s", exc)

        # 2. Pick up any QUEUED cases already in active_cases (retry after restart)
        try:
            queued_cases = self._sm.list_cases(status="QUEUED", limit=50)
            for case in queued_cases:
                with self._active_lock:
                    if case.case_id not in self._active_cases:
                        item = _WorkItem.from_case(case)
                        item.priority = -item.priority
                        self._work_queue.put(item)
                        enqueued += 1
        except Exception as exc:
            log.debug("Case scan skipped: %s", exc)

        if enqueued:
            log.info("Poll cycle: enqueued %d cases (queue_depth=%d)",
                     enqueued, self._work_queue.qsize())
        return enqueued

    def _ingest_queue_record(self, record: Dict[str, Any]) -> None:
        """Convert a case_queue KV Store record into a work item."""
        case_id = self.process_alert(
            alert_id     = record.get("alert_id", ""),
            alert_type   = record.get("alert_type", "UNKNOWN"),
            affected_host= record.get("source_host", ""),
            affected_user= record.get("source_user", ""),
            risk_score   = int(record.get("raw_risk_score", 50)),
            priority     = record.get("priority_override", "") or _infer_priority(
                int(record.get("raw_risk_score", 50))
            ),
        )

    def _worker_loop(self) -> None:
        """Continuously drain the work queue and process cases."""
        while True:
            try:
                item: _WorkItem = self._work_queue.get(timeout=5.0)
            except queue.Empty:
                continue

            # Restore positive priority for logging
            item.priority = abs(item.priority)

            with self._active_lock:
                if item.case_id in self._active_cases:
                    # Another worker already picked this up (duplicate queue entry)
                    self._work_queue.task_done()
                    continue
                self._active_cases.add(item.case_id)

            try:
                self._process_case(item)
            finally:
                with self._active_lock:
                    self._active_cases.discard(item.case_id)
                self._work_queue.task_done()

    def _process_case(self, item: _WorkItem) -> None:
        """
        Drive a single case through the full agent pipeline.
        Each stage calls the appropriate agent and handles success/failure.
        """
        case_id = item.case_id
        log.info("Processing case %s (type=%s priority=%s)",
                 case_id, item.alert_type, item.priority)

        # Fetch fresh case state
        case = self._sm.get_case(case_id)
        if case is None:
            log.error("Case %s not found in KV Store; skipping", case_id)
            return

        # Pipeline stages in order
        pipeline = [
            (CaseStatus.TRIAGING,      CaseStatus.INVESTIGATING, "vanguard",  self._run_vanguard),
            (CaseStatus.INVESTIGATING, CaseStatus.DECIDING,      "sherlock",  self._run_sherlock),
            (CaseStatus.DECIDING,      CaseStatus.RESPONDING,    "orchestrator", self._run_decide),
            (CaseStatus.RESPONDING,    CaseStatus.LEARNING,      "executor",  self._run_executor),
            (CaseStatus.LEARNING,      CaseStatus.CLOSED,        "sage",      self._run_sage),
        ]

        for entry_status, exit_status, agent_name, stage_fn in pipeline:
            case = self._sm.get_case(case_id)
            if case is None:
                log.error("Case %s disappeared mid-pipeline", case_id)
                return

            current = CaseStatus(case.status)

            # Skip stages that are ahead of where the case currently is
            # (handles resume from ERROR or HALTED mid-pipeline)
            if current == CaseStatus.CLOSED or current == CaseStatus.SUPPRESSED:
                return
            if current == CaseStatus.HALTED:
                log.info("Case %s is HALTED; stopping pipeline", case_id)
                return
            if current.value != entry_status.value:
                if _stage_index(current) > _stage_index(entry_status):
                    continue   # already past this stage
                # Case is behind — transition it to the entry status and arm
                # its watchdog timeout for this stage
                try:
                    self._sm.set_state_with_timeout(
                        case_id, entry_status,
                        timeout_seconds=DEFAULT_STATE_TIMEOUT_SECONDS,
                        agent_name="orchestrator", detail="pipeline advance",
                    )
                except Exception:
                    pass

            # Transition into the stage's entry status, arming its timeout
            try:
                self._sm.set_state_with_timeout(
                    case_id, entry_status,
                    timeout_seconds=DEFAULT_STATE_TIMEOUT_SECONDS,
                    agent_name="orchestrator", detail=f"entering {agent_name} stage",
                )
            except ValueError:
                pass   # Already in entry_status from a previous attempt

            success = self._run_stage(
                case_id=case_id,
                agent_name=agent_name,
                stage_fn=stage_fn,
                exit_status=exit_status,
            )
            if not success:
                return   # Error handling inside _run_stage

        log.info("Case %s completed pipeline → CLOSED", case_id)

    def _run_stage(
        self,
        case_id: str,
        agent_name: str,
        stage_fn: Callable,
        exit_status: CaseStatus,
    ) -> bool:
        """
        Execute one pipeline stage with retry logic.
        Returns True if the stage succeeded, False if it exhausted retries.
        """
        audit = get_audit_logger(agent_name)
        status_obj = self._agent_status.get(agent_name)
        if status_obj:
            status_obj.current_case_id = case_id

        for attempt in range(1, MAX_RETRIES_PER_CASE + 1):
            t_start = time.time()
            case = self._sm.get_case(case_id)
            if case is None:
                return False

            try:
                result = stage_fn(case=case, audit=audit)
                latency_ms = (time.time() - t_start) * 1000

                if not result.get("success", True):
                    raise RuntimeError(result.get("error", "Agent returned failure"))

                if status_obj:
                    status_obj.record_run(latency_ms, success=True)
                    status_obj.current_case_id = ""

                # Advance to exit status
                try:
                    self._sm.transition(case_id, exit_status,
                                        agent_name=agent_name,
                                        detail=f"stage complete (attempt {attempt})")
                except ValueError as exc:
                    log.warning("Transition to %s skipped: %s", exit_status.value, exc)

                return True

            except Exception as exc:
                latency_ms = (time.time() - t_start) * 1000
                tb = traceback.format_exc()
                log.error(
                    "Stage %s attempt %d/%d failed for case %s: %s",
                    agent_name, attempt, MAX_RETRIES_PER_CASE, case_id, exc,
                )
                audit.log_error(
                    case_id=case_id,
                    error_type=type(exc).__name__,
                    message=str(exc),
                    exc=exc,
                    context={"stage": agent_name, "attempt": attempt},
                    is_fatal=(attempt == MAX_RETRIES_PER_CASE),
                )
                if status_obj:
                    status_obj.record_run(latency_ms, success=False, error=str(exc))

                if attempt < MAX_RETRIES_PER_CASE:
                    backoff = 2 ** (attempt - 1)
                    log.info("Retrying stage %s in %ds (case %s)",
                             agent_name, backoff, case_id)
                    time.sleep(backoff)
                    # Update retry count in KV Store
                    try:
                        self._sm.update_case(
                            case_id,
                            {"retry_count": attempt, "last_error": str(exc)},
                            agent_name="orchestrator",
                        )
                    except Exception:
                        pass

        # All retries exhausted
        log.error("Case %s: stage %s failed after %d attempts — moving to ERROR",
                  case_id, agent_name, MAX_RETRIES_PER_CASE)
        try:
            self._sm.transition(
                case_id, CaseStatus.ERROR,
                agent_name="orchestrator",
                detail=f"{agent_name} failed after {MAX_RETRIES_PER_CASE} retries",
            )
        except Exception:
            pass
        return False

    # ------------------------------------------------------------------
    # Per-agent stage functions
    # These call the agent module's run() via the proxy, then apply the
    # result back to the case in KV Store.
    # ------------------------------------------------------------------

    def _run_vanguard(self, case: Case, audit: AuditLogger) -> Dict[str, Any]:
        result = self._agents["vanguard"].run(case=case, audit=audit)
        if result.get("success", True):
            updates: Dict[str, Any] = {}
            if "decision" in result:
                updates["vanguard_decision"] = result["decision"]
            if "risk_score" in result:
                updates["risk_score"] = result["risk_score"]
            if "classification" in result:
                updates["classification"] = result["classification"]
            if "mitre_tactic" in result:
                updates["mitre_tactic"] = result["mitre_tactic"]
            if "mitre_technique" in result:
                updates["mitre_technique"] = result["mitre_technique"]
            if updates:
                self._sm.update_case(case.case_id, updates, agent_name="vanguard")

            # Auto-close low-confidence cases
            cfg = get_config()
            close_threshold = cfg.get_int("agents", "vanguard_threshold_close", default=40)
            score = result.get("risk_score", case.risk_score)
            if score < close_threshold:
                log.info("Vanguard: case %s auto-closed (score %d < threshold %d)",
                         case.case_id, score, close_threshold)
                self._sm.update_case(
                    case.case_id,
                    {"resolution": "LOW_CONFIDENCE_AUTO_CLOSE", "status": CaseStatus.CLOSED.value},
                    agent_name="vanguard",
                )
                # Skip remaining pipeline by raising a controlled sentinel
                result["skip_pipeline"] = True

        return result

    def _run_sherlock(self, case: Case, audit: AuditLogger) -> Dict[str, Any]:
        result = self._agents["sherlock"].run(case=case, audit=audit)
        if result.get("success", True) and "report" in result:
            self._sm.update_case(
                case.case_id,
                {"sherlock_report": result["report"]},
                agent_name="sherlock",
            )
        return result

    def _run_decide(self, case: Case, audit: AuditLogger) -> Dict[str, Any]:
        """
        Orchestrator's own decision step: evaluate risk score and determine
        whether to proceed automatically or require human approval.
        """
        cfg = get_config()
        auto_threshold = cfg.get_int(
            "agents", "executor_require_approval_below", default=AUTO_RESPOND_SCORE
        )
        score = case.risk_score

        if score >= auto_threshold:
            log.info("Case %s: AUTO-RESPOND (score %d >= %d)",
                     case.case_id, score, auto_threshold)
            self._sm.update_case(
                case.case_id,
                {"requires_approval": False},
                agent_name="orchestrator",
                detail=f"auto-respond: score {score} >= threshold {auto_threshold}",
            )
            audit.log_decision(
                case_id=case.case_id,
                decision_type="AUTO_RESPOND",
                confidence=min(score / 100.0, 1.0),
                input_context={"risk_score": score, "threshold": auto_threshold},
                output_decision={"requires_approval": False},
                reasoning=f"Risk score {score} meets auto-respond threshold {auto_threshold}.",
            )
        else:
            log.info("Case %s: HUMAN-APPROVE required (score %d < %d)",
                     case.case_id, score, auto_threshold)
            self._sm.update_case(
                case.case_id,
                {"requires_approval": True},
                agent_name="orchestrator",
                detail=f"approval required: score {score} < threshold {auto_threshold}",
            )
            audit.log_decision(
                case_id=case.case_id,
                decision_type="HUMAN_APPROVE",
                confidence=min(score / 100.0, 1.0),
                input_context={"risk_score": score, "threshold": auto_threshold},
                output_decision={"requires_approval": True},
                reasoning=f"Risk score {score} below auto-respond threshold {auto_threshold}. Human approval required.",
            )
            # Halt the pipeline pending approval
            self._sm.transition(
                case.case_id, CaseStatus.HALTED,
                agent_name="orchestrator",
                detail="awaiting human approval",
            )
            return {"success": True, "halted_for_approval": True}

        return {"success": True}

    def _run_executor(self, case: Case, audit: AuditLogger) -> Dict[str, Any]:
        if case.requires_approval and not case.approval_granted_by:
            return {
                "success": False,
                "error":   "Executor cannot proceed — human approval not yet granted.",
            }
        result = self._agents["executor"].run(case=case, audit=audit)
        if result.get("success", True) and "actions" in result:
            existing = case.executor_actions or []
            self._sm.update_case(
                case.case_id,
                {"executor_actions": existing + result["actions"]},
                agent_name="executor",
            )
        return result

    def _run_sage(self, case: Case, audit: AuditLogger) -> Dict[str, Any]:
        result = self._agents["sage"].run(case=case, audit=audit)
        if result.get("success", True):
            updates: Dict[str, Any] = {
                "resolution": result.get("resolution", "CONTAINED"),
                "resolution_notes": result.get("notes", ""),
            }
            if "analysis" in result:
                updates["sage_analysis"] = result["analysis"]
            self._sm.update_case(case.case_id, updates, agent_name="sage")
        return result


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _infer_priority(risk_score: int) -> str:
    if risk_score >= 90:
        return "CRITICAL"
    if risk_score >= 75:
        return "HIGH"
    if risk_score >= 50:
        return "MEDIUM"
    return "LOW"


_STAGE_ORDER = {
    CaseStatus.QUEUED:        0,
    CaseStatus.TRIAGING:      1,
    CaseStatus.INVESTIGATING: 2,
    CaseStatus.DECIDING:      3,
    CaseStatus.RESPONDING:    4,
    CaseStatus.LEARNING:      5,
    CaseStatus.CLOSED:        6,
}

def _stage_index(status: CaseStatus) -> int:
    return _STAGE_ORDER.get(status, -1)


if __name__ == "__main__":
    import argparse

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
        stream=sys.stdout,
    )

    parser = argparse.ArgumentParser(description="SENTINEL Orchestrator")
    parser.add_argument("--once",  action="store_true",
                        help="Run a single poll cycle and exit (cron mode)")
    parser.add_argument("--debug", action="store_true",
                        help="Set log level to DEBUG")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.once:
        orch = SentinelOrchestrator()
        n = orch.poll_once()
        print(f"Poll complete: {n} cases enqueued")
        sys.exit(0)

    # Default: blocking poll loop
    SentinelOrchestrator().start()
