"""
SENTINEL: Autonomous Agentic SOC Commander
audit_logger.py — Immutable agent decision audit trail

AuditLogger writes structured JSON events to the sentinel_audit Splunk index
via HTTP Event Collector (HEC). Every event is append-only — AuditLogger
never updates, patches, or deletes existing audit records.

If HEC is unavailable the logger falls back to a local rotating JSON file
and queues failed events for replay when HEC recovers (via drain()).

Event types:
  decision  — Vanguard/Sherlock/Executor/Sage agent decision with confidence
  action    — Executor containment action with target, result, rollback timer
  mcp_call  — MCP Server tool invocation with latency and status
  error     — Agent runtime error with traceback context
  transition — Case state machine transition
  approval  — Human-in-the-loop approval gate lifecycle (requested, approved,
              denied, timed out, cancelled) — request_id, decision, responder
  chain_of_thought — Full step-by-step explainability trace for an agent
                     decision (SOC audit / compliance / external-tool queries)

HEC configuration:
  Endpoint:     /services/collector/event
  Sourcetype:   sentinel:audit
  Index:        sentinel_audit
  Token:        from SENTINEL_HEC_TOKEN env var or [hec] token in sentinel.conf

Dependencies: requests, standard library
"""

from __future__ import annotations

import gzip
import json
import logging
import os
import queue
import threading
import time
import traceback
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

log = logging.getLogger("sentinel.audit_logger")

# ---------------------------------------------------------------------------
# HEC configuration defaults
# ---------------------------------------------------------------------------

_ENV_HEC_URL   = "SENTINEL_HEC_URL"
_ENV_HEC_TOKEN = "SENTINEL_HEC_TOKEN"
_ENV_HEC_INDEX = "SENTINEL_HEC_INDEX"
_FALLBACK_LOG_PATH = Path(__file__).resolve().parent.parent / "logs" / "audit_fallback.jsonl"


# ---------------------------------------------------------------------------
# Event schema helpers
# ---------------------------------------------------------------------------

def _base_event(
    event_type: str,
    case_id: str,
    agent_name: str,
    **kwargs: Any,
) -> Dict[str, Any]:
    return {
        "timestamp":  int(time.time() * 1000),
        "event_type": event_type,
        "case_id":    case_id,
        "agent_name": agent_name,
        **kwargs,
    }


# ---------------------------------------------------------------------------
# HEC batch sender
# ---------------------------------------------------------------------------

class _HECSender:
    """
    Sends batches of events to Splunk HEC with retry and compression.
    Thread-safe; one instance is shared across all AuditLogger instances.
    """

    _BATCH_SIZE   = 100       # Events per HEC request
    _FLUSH_EVERY  = 5.0       # Seconds between flush cycles
    _MAX_QUEUE    = 10_000    # In-memory queue limit before dropping

    def __init__(
        self,
        hec_url: str,
        hec_token: str,
        hec_index: str = "sentinel_audit",
        verify_ssl: bool = False,
    ) -> None:
        self._url     = hec_url.rstrip("/") + "/services/collector/event"
        self._token   = hec_token
        self._index   = hec_index
        self._verify  = verify_ssl
        self._queue: queue.Queue = queue.Queue(maxsize=self._MAX_QUEUE)
        self._lock    = threading.Lock()
        self._running = False
        self._thread: Optional[threading.Thread] = None

        session = requests.Session()
        retry = Retry(total=3, backoff_factor=1.0, status_forcelist=[500, 502, 503])
        session.mount("https://", HTTPAdapter(max_retries=retry))
        session.mount("http://",  HTTPAdapter(max_retries=retry))
        session.verify = self._verify
        self._session = session

    def enqueue(self, event: Dict[str, Any]) -> bool:
        """Put an event on the internal queue. Returns False if the queue is full."""
        try:
            self._queue.put_nowait(event)
            return True
        except queue.Full:
            log.warning("HEC queue full; dropping audit event (type=%s case=%s)",
                        event.get("event_type"), event.get("case_id"))
            return False

    def start(self) -> None:
        """Start the background flush thread."""
        with self._lock:
            if self._running:
                return
            self._running = True
            self._thread = threading.Thread(
                target=self._flush_loop,
                name="sentinel-hec-flusher",
                daemon=True,
            )
            self._thread.start()
        log.debug("HEC sender started")

    def stop(self, timeout: float = 10.0) -> None:
        """Flush remaining events and stop the background thread."""
        with self._lock:
            self._running = False
        if self._thread:
            self._thread.join(timeout=timeout)
        self._flush_batch()   # Final drain
        log.debug("HEC sender stopped")

    def _flush_loop(self) -> None:
        while self._running:
            time.sleep(self._FLUSH_EVERY)
            self._flush_batch()

    def _flush_batch(self) -> None:
        batch: List[Dict[str, Any]] = []
        try:
            while len(batch) < self._BATCH_SIZE:
                batch.append(self._queue.get_nowait())
        except queue.Empty:
            pass

        if not batch:
            return

        payload = "\n".join(
            json.dumps({"time": e["timestamp"] / 1000.0,
                        "index": self._index,
                        "sourcetype": "sentinel:audit",
                        "event": e})
            for e in batch
        )

        try:
            resp = self._session.post(
                self._url,
                data=gzip.compress(payload.encode("utf-8")),
                headers={
                    "Authorization": f"Splunk {self._token}",
                    "Content-Encoding": "gzip",
                    "Content-Type": "application/json",
                },
                timeout=10,
            )
            if resp.status_code not in (200, 201):
                raise RuntimeError(f"HEC returned HTTP {resp.status_code}: {resp.text[:256]}")
            log.debug("HEC flush: %d events sent", len(batch))
        except Exception as exc:
            log.error("HEC flush failed (%d events lost to fallback): %s", len(batch), exc)
            self._write_fallback(batch)

    @staticmethod
    def _write_fallback(events: List[Dict[str, Any]]) -> None:
        """Append failed events to the local fallback JSONL file."""
        try:
            _FALLBACK_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
            with _FALLBACK_LOG_PATH.open("a", encoding="utf-8") as fh:
                for e in events:
                    fh.write(json.dumps(e) + "\n")
        except Exception as exc:
            log.critical("Fallback log write failed: %s", exc)


# ---------------------------------------------------------------------------
# AuditLogger
# ---------------------------------------------------------------------------

class AuditLogger:
    """
    Append-only structured audit logger for SENTINEL agent decisions and actions.

    Usage::

        logger = AuditLogger(agent_name="vanguard")
        logger.log_decision(
            case_id="SEN-123456AB",
            decision_type="ESCALATE",
            confidence=0.94,
            input_context={"alert_id": "NOT-001", "risk_score": 75},
            output_decision={"route_to": "sherlock", "score": 97},
            reasoning="Asset criticality multiplier elevated score above threshold.",
        )
    """

    # Shared sender singleton (one HEC connection for all agent loggers)
    _sender: Optional[_HECSender] = None
    _sender_lock = threading.Lock()

    def __init__(
        self,
        agent_name: str,
        hec_url: Optional[str] = None,
        hec_token: Optional[str] = None,
        hec_index: Optional[str] = None,
        verify_ssl: bool = False,
    ) -> None:
        self._agent_name = agent_name

        # Initialise shared HEC sender on first AuditLogger instantiation
        with AuditLogger._sender_lock:
            if AuditLogger._sender is None:
                url   = (hec_url   or os.environ.get(_ENV_HEC_URL,   "https://localhost:8088"))
                token = (hec_token or os.environ.get(_ENV_HEC_TOKEN, ""))
                index = (hec_index or os.environ.get(_ENV_HEC_INDEX, "sentinel_audit"))
                if not token:
                    log.warning(
                        "No HEC token configured. Audit events will only go to fallback file. "
                        "Set %s or configure [hec] token in sentinel.conf.", _ENV_HEC_TOKEN
                    )
                AuditLogger._sender = _HECSender(url, token, index, verify_ssl)
                AuditLogger._sender.start()

    # ------------------------------------------------------------------
    # Core emit — all public methods call this
    # ------------------------------------------------------------------

    def _emit(self, event: Dict[str, Any]) -> None:
        """
        Emit an audit event. Appends a local Python log entry at DEBUG level
        and enqueues for HEC transmission.
        """
        log.debug(
            "AUDIT %s case=%s type=%s",
            self._agent_name,
            event.get("case_id", "-"),
            event.get("event_type", "-"),
            extra=event,
        )
        if AuditLogger._sender:
            AuditLogger._sender.enqueue(event)

    # ------------------------------------------------------------------
    # Public logging methods
    # ------------------------------------------------------------------

    def log_decision(
        self,
        case_id: str,
        decision_type: str,
        confidence: float,
        input_context: Dict[str, Any],
        output_decision: Dict[str, Any],
        reasoning: str = "",
        mitre_tactic: str = "",
        mitre_technique: str = "",
        model_used: str = "",
        latency_ms: int = 0,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Log an agent decision event (Vanguard classification, Sherlock findings,
        Executor pre-action check, Sage proposal).

        confidence: float in [0.0, 1.0]
        """
        event = _base_event(
            "decision",
            case_id=case_id,
            agent_name=self._agent_name,
            decision_type=decision_type,
            confidence=round(float(confidence), 4),
            confidence_pct=round(float(confidence) * 100, 1),
            input_context=input_context,
            output_decision=output_decision,
            reasoning=reasoning,
            mitre_tactic=mitre_tactic,
            mitre_technique=mitre_technique,
            model_used=model_used,
            latency_ms=latency_ms,
            metadata=metadata or {},
        )
        self._emit(event)

    def log_action(
        self,
        case_id: str,
        action_type: str,
        target: str,
        platform: str,
        outcome: str,
        action_id: str = "",
        rollback_timer_hours: float = 0.0,
        rollback_scheduled_at: Optional[float] = None,
        verification_passed: Optional[bool] = None,
        error_detail: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Log an Executor containment or remediation action.
        outcome: "SUCCESS" | "FAILURE" | "PENDING" | "ROLLED_BACK" | "DRY_RUN"
        """
        event = _base_event(
            "action",
            case_id=case_id,
            agent_name=self._agent_name,
            action_id=action_id,
            action_type=action_type,
            target=target,
            platform=platform,
            outcome=outcome,
            rollback_timer_hours=rollback_timer_hours,
            rollback_scheduled_at=rollback_scheduled_at,
            verification_passed=verification_passed,
            error_detail=error_detail,
            metadata=metadata or {},
        )
        self._emit(event)

    def log_mcp_call(
        self,
        case_id: str,
        tool_name: str,
        status_code: int,
        duration_ms: int,
        attempt: int = 1,
        cached: bool = False,
        payload_keys: Optional[List[str]] = None,
        error: Optional[str] = None,
    ) -> None:
        """
        Log every MCP Server tool invocation for performance and reliability tracking.
        Called by SplunkMCPClient._log_attempt().
        """
        event = _base_event(
            "mcp_call",
            case_id=case_id,
            agent_name=self._agent_name,
            tool_name=tool_name,
            status_code=status_code,
            duration_ms=duration_ms,
            attempt=attempt,
            cached=cached,
            payload_keys=payload_keys or [],
            success=200 <= status_code < 300,
            error=error,
        )
        self._emit(event)

    def log_error(
        self,
        case_id: str,
        error_type: str,
        message: str,
        exc: Optional[BaseException] = None,
        context: Optional[Dict[str, Any]] = None,
        is_fatal: bool = False,
    ) -> None:
        """
        Log an agent runtime error. Captures the full traceback if an
        exception object is passed.
        """
        tb_str = ""
        if exc is not None:
            tb_str = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))

        event = _base_event(
            "error",
            case_id=case_id,
            agent_name=self._agent_name,
            error_type=error_type,
            message=message,
            traceback=tb_str,
            is_fatal=is_fatal,
            context=context or {},
        )
        # Errors also get a WARNING/ERROR level Python log entry for immediate visibility
        python_level = logging.ERROR if is_fatal else logging.WARNING
        log.log(python_level, "AUDIT ERROR [%s] case=%s: %s",
                self._agent_name, case_id, message,
                extra={"error_type": error_type, "is_fatal": is_fatal})
        self._emit(event)

    def log_transition(
        self,
        case_id: str,
        from_status: str,
        to_status: str,
        trigger: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Log a case state machine transition."""
        event = _base_event(
            "transition",
            case_id=case_id,
            agent_name=self._agent_name,
            from_status=from_status,
            to_status=to_status,
            trigger=trigger,
            metadata=metadata or {},
        )
        self._emit(event)

    def log_approval(
        self,
        case_id: str,
        request_id: str,
        action: str,
        target: str,
        decision: str,
        requester: str = "",
        responder: str = "",
        decision_time_ms: int = 0,
        timeout_expired: bool = False,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Log a human-approval-gate lifecycle event — request raised, response
        received, timeout fired, or denial recorded.

        decision: "PENDING" | "AUTO_APPROVED" | "APPROVED" | "DENIED" | "TIMEOUT_DENIED" | "CANCELLED"
        """
        event = _base_event(
            "approval",
            case_id=case_id,
            agent_name=self._agent_name,
            request_id=request_id,
            action=action,
            target=target,
            decision=decision,
            requester=requester,
            responder=responder,
            decision_time_ms=decision_time_ms,
            timeout_expired=timeout_expired,
            metadata=metadata or {},
        )
        self._emit(event)

    def log_chain_of_thought(
        self,
        case_id: str,
        agent_name: str,
        chain: List[Dict[str, Any]],
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Log the full step-by-step "Chain of Thought" explainability trace for
        an agent decision (Vanguard's chain_of_thought, Sherlock's
        investigation_chain, Executor's action_chain, ...).

        Written as its own append-only ``chain_of_thought`` event — separate
        from (and in addition to) the summarised ``decision``/``action``
        events — so SOC auditors and external compliance tools can pull the
        complete reasoning trail for any case independently, e.g.:

            index=sentinel_audit case_id=SEN-001 event_type=chain_of_thought
            | spath chain{} | mvexpand chain{}
            | spath input=chain{} output=step    path=step
            | spath input=chain{} output=observation path=observation
            | spath input=chain{} output=inference   path=inference
            | table timestamp, agent_name, step, observation, inference

        ``chain`` is a list of step dicts, each typically containing
        ``step``/``agent`` plus either ``observation``/``inference`` (an
        evidentiary step) or ``conclusion``/``action`` (the final step).
        Stored verbatim — this method performs no analysis of its own.
        """
        event = _base_event(
            "chain_of_thought",
            case_id=case_id,
            agent_name=agent_name,
            step_count=len(chain),
            chain=chain,
            metadata=metadata or {},
        )
        self._emit(event)

    def log_enrichment(
        self,
        case_id: str,
        ioc_value: str,
        ioc_type: str,
        verdict: str,
        confidence: float,
        sources: List[str],
        cached: bool = False,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Log a threat intelligence enrichment result from enrich_threat_intel."""
        event = _base_event(
            "enrichment",
            case_id=case_id,
            agent_name=self._agent_name,
            ioc_value=ioc_value,
            ioc_type=ioc_type,
            verdict=verdict,
            confidence=round(float(confidence), 4),
            sources=sources,
            cached=cached,
            metadata=metadata or {},
        )
        self._emit(event)

    def log_metric(
        self,
        case_id: str,
        metric_name: str,
        value: float,
        unit: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Log a single numeric metric for Sage's performance tracking."""
        event = _base_event(
            "metric",
            case_id=case_id,
            agent_name=self._agent_name,
            metric_name=metric_name,
            value=value,
            unit=unit,
            metadata=metadata or {},
        )
        self._emit(event)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    @classmethod
    def flush_and_stop(cls, timeout: float = 15.0) -> None:
        """Flush remaining HEC events and stop the background sender thread."""
        with cls._sender_lock:
            if cls._sender:
                cls._sender.stop(timeout=timeout)
                cls._sender = None


# ---------------------------------------------------------------------------
# Module-level convenience — agents can import a pre-configured logger
# ---------------------------------------------------------------------------

def get_audit_logger(agent_name: str) -> AuditLogger:
    """Return an AuditLogger configured for the named agent."""
    return AuditLogger(agent_name=agent_name)
