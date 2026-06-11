"""
SENTINEL: Autonomous Agentic SOC Commander
state_manager.py — Persistent case state via Splunk KV Store

CaseStateManager is the single source of truth for every case in the pipeline.
It wraps the SplunkConnector's KV Store methods behind a typed, thread-safe
interface with full validation, optimistic concurrency via version counters,
and an in-memory read-through cache to reduce KV Store round-trips.

KV Store collection: active_cases  (defined in collections.conf)
Archive collection:  sentinel_audit (written to index, not KV Store)

Case state machine (from orchestrator.py):
  QUEUED → TRIAGING → INVESTIGATING → DECIDING → RESPONDING → LEARNING → CLOSED
  Any state → ERROR, any state → HALTED
  HALTED → (previous state)   (via resume)
  ERROR  → (previous state)   (via retry)
"""

from __future__ import annotations

import logging
import threading
import time
import uuid
from copy import deepcopy
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List, Optional

from .splunk_connector import get_connector

log = logging.getLogger("sentinel.state_manager")

# KV Store collection names (must match collections.conf)
_COLLECTION_ACTIVE  = "active_cases"
_COLLECTION_ARCHIVE = "case_archive"   # separate collection for closed cases


# ---------------------------------------------------------------------------
# Case status enum
# ---------------------------------------------------------------------------

class CaseStatus(str, Enum):
    QUEUED        = "QUEUED"
    TRIAGING      = "TRIAGING"
    INVESTIGATING = "INVESTIGATING"
    DECIDING      = "DECIDING"
    RESPONDING    = "RESPONDING"
    LEARNING      = "LEARNING"
    CLOSED        = "CLOSED"
    ERROR         = "ERROR"
    HALTED        = "HALTED"
    SUPPRESSED    = "SUPPRESSED"

    # Fault-tolerance states (watchdog-driven)
    RETRYING      = "RETRYING"     # case timed out; being re-queued for the same agent
    STUCK         = "STUCK"        # case timed out and is awaiting watchdog action
    DEAD_LETTER   = "DEAD_LETTER"  # retries exhausted; parked for human review


# Active pipeline states — a case may enter RETRYING from any of these
_ACTIVE_STATES: List[CaseStatus] = [
    CaseStatus.QUEUED, CaseStatus.TRIAGING, CaseStatus.INVESTIGATING,
    CaseStatus.DECIDING, CaseStatus.RESPONDING, CaseStatus.LEARNING,
]

# Terminal statuses — excluded from timeout scans
_TERMINAL_STATUSES = {
    CaseStatus.CLOSED.value, CaseStatus.SUPPRESSED.value, CaseStatus.DEAD_LETTER.value,
}

# Valid forward and backward transitions
_ALLOWED_TRANSITIONS: Dict[CaseStatus, List[CaseStatus]] = {
    CaseStatus.QUEUED:        [CaseStatus.TRIAGING, CaseStatus.SUPPRESSED, CaseStatus.ERROR,
                               CaseStatus.RETRYING, CaseStatus.STUCK],
    CaseStatus.TRIAGING:      [CaseStatus.INVESTIGATING, CaseStatus.CLOSED, CaseStatus.HALTED,
                               CaseStatus.ERROR, CaseStatus.RETRYING, CaseStatus.STUCK],
    CaseStatus.INVESTIGATING: [CaseStatus.DECIDING, CaseStatus.HALTED, CaseStatus.ERROR,
                               CaseStatus.RETRYING, CaseStatus.STUCK],
    CaseStatus.DECIDING:      [CaseStatus.RESPONDING, CaseStatus.HALTED, CaseStatus.ERROR,
                               CaseStatus.RETRYING, CaseStatus.STUCK],
    CaseStatus.RESPONDING:    [CaseStatus.LEARNING, CaseStatus.HALTED, CaseStatus.ERROR,
                               CaseStatus.RETRYING, CaseStatus.STUCK],
    CaseStatus.LEARNING:      [CaseStatus.CLOSED, CaseStatus.HALTED, CaseStatus.ERROR,
                               CaseStatus.RETRYING, CaseStatus.STUCK],
    CaseStatus.CLOSED:        [],                                 # terminal
    CaseStatus.SUPPRESSED:    [],                                 # terminal
    CaseStatus.HALTED:        list(CaseStatus),                  # resume to any valid state
    CaseStatus.ERROR:         [CaseStatus.TRIAGING, CaseStatus.INVESTIGATING,
                               CaseStatus.DECIDING, CaseStatus.RESPONDING,
                               CaseStatus.CLOSED, CaseStatus.RETRYING,
                               CaseStatus.DEAD_LETTER],           # retry, escalate, or dead-letter
    CaseStatus.RETRYING:      _ACTIVE_STATES + [CaseStatus.ERROR, CaseStatus.STUCK,
                                                 CaseStatus.DEAD_LETTER],
    CaseStatus.STUCK:         _ACTIVE_STATES + [CaseStatus.RETRYING, CaseStatus.ERROR,
                                                 CaseStatus.DEAD_LETTER],
    CaseStatus.DEAD_LETTER:   _ACTIVE_STATES,                    # recover_from_dead_letter re-queues
}


# ---------------------------------------------------------------------------
# Case dataclass
# ---------------------------------------------------------------------------

@dataclass
class Case:
    """
    Typed representation of a SENTINEL investigation case.
    Maps 1:1 to a record in the active_cases KV Store collection.
    """
    case_id:          str
    alert_id:         str
    alert_type:       str
    status:           str = CaseStatus.QUEUED.value
    priority:         str = "MEDIUM"

    # Affected resources
    affected_host:    str = ""
    affected_user:    str = ""

    # Scoring
    risk_score:       int = 0
    classification:   str = ""
    mitre_tactic:     str = ""
    mitre_technique:  str = ""

    # Pipeline results (populated by each agent in turn)
    vanguard_decision: Dict[str, Any] = field(default_factory=dict)
    sherlock_report:   Dict[str, Any] = field(default_factory=dict)
    executor_actions:  List[Dict[str, Any]] = field(default_factory=list)
    sage_analysis:     Dict[str, Any] = field(default_factory=dict)

    # Resolution
    resolution:       str = ""
    resolution_notes: str = ""

    # Lifecycle timestamps (epoch seconds as floats)
    created_time:     float = field(default_factory=time.time)
    updated_time:     float = field(default_factory=time.time)
    closed_time:      Optional[float] = None

    # Approval workflow
    requires_approval: bool = False
    approval_granted_by: str = ""
    approval_granted_time: Optional[float] = None

    # Retry tracking
    retry_count:      int = 0
    max_retries:      int = 3
    last_error:       str = ""

    # State-timeout / watchdog tracking (epoch seconds)
    state_entered_at:         Optional[float] = None
    state_timeout_at:         Optional[float] = None
    timeout_duration_seconds: int = 900   # 15 minutes per state by default

    # Optimistic concurrency — incremented on every write
    version:          int = 0

    # Audit trail (list of {timestamp, agent, action, detail} dicts)
    audit_trail:      List[Dict[str, Any]] = field(default_factory=list)

    def to_kvstore_dict(self) -> Dict[str, Any]:
        """Serialise to a flat dict for KV Store storage."""
        import json
        d = asdict(self)
        # KV Store can't store nested dicts/lists directly — JSON-encode them
        for nested_key in (
            "vanguard_decision", "sherlock_report", "executor_actions",
            "sage_analysis", "audit_trail",
        ):
            d[nested_key] = json.dumps(d[nested_key])
        d["_key"] = self.case_id
        return d

    @classmethod
    def from_kvstore_dict(cls, d: Dict[str, Any]) -> "Case":
        """Deserialise from a KV Store record."""
        import json as _json
        data = dict(d)
        data.pop("_key", None)
        data.pop("_user", None)

        for nested_key in (
            "vanguard_decision", "sherlock_report", "sage_analysis",
        ):
            if isinstance(data.get(nested_key), str):
                try:
                    data[nested_key] = _json.loads(data[nested_key])
                except (ValueError, TypeError):
                    data[nested_key] = {}

        for list_key in ("executor_actions", "audit_trail"):
            if isinstance(data.get(list_key), str):
                try:
                    data[list_key] = _json.loads(data[list_key])
                except (ValueError, TypeError):
                    data[list_key] = []

        # Coerce numeric fields that KV Store returns as strings
        for int_key in ("risk_score", "retry_count", "max_retries",
                        "timeout_duration_seconds", "version"):
            if data.get(int_key) is not None:
                try:
                    data[int_key] = int(data[int_key])
                except (ValueError, TypeError):
                    data[int_key] = 0

        for float_key in ("created_time", "updated_time", "closed_time",
                          "approval_granted_time",
                          "state_entered_at", "state_timeout_at"):
            if data.get(float_key) is not None:
                try:
                    data[float_key] = float(data[float_key])
                except (ValueError, TypeError):
                    data[float_key] = None

        if "requires_approval" in data:
            data["requires_approval"] = str(data["requires_approval"]).lower() in (
                "1", "true", "yes",
            )

        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


# ---------------------------------------------------------------------------
# CaseStateManager
# ---------------------------------------------------------------------------

class CaseStateManager:
    """
    Thread-safe persistent case state store backed by Splunk KV Store.

    All public methods acquire the per-case shard lock before any read-modify-write
    to KV Store. A read-through in-memory cache with configurable TTL reduces
    latency for high-frequency status checks from the War Room dashboard.
    """

    _CACHE_TTL_SECONDS = 5.0      # How long a cached case record stays fresh
    _CASE_ID_PREFIX    = "SEN-"

    def __init__(
        self,
        connector=None,
        cache_ttl: float = _CACHE_TTL_SECONDS,
    ) -> None:
        self._conn       = connector     # injected or resolved lazily
        self._cache_ttl  = cache_ttl
        # Per-case lock — created on first access, stored by case_id
        self._case_locks: Dict[str, threading.Lock] = {}
        self._locks_meta_lock = threading.Lock()
        # Read-through cache: case_id → (Case, fetched_at)
        self._cache: Dict[str, tuple[Case, float]] = {}
        self._cache_lock = threading.Lock()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def create_case(
        self,
        alert_id: str,
        alert_type: str,
        affected_host: str = "",
        affected_user: str = "",
        risk_score: int = 0,
        priority: str = "MEDIUM",
    ) -> Case:
        """
        Create a new case and persist it to KV Store.
        Raises ValueError if a case for the same alert_id already exists.
        """
        existing = self._find_by_alert_id(alert_id)
        if existing:
            log.warning(
                "Case already exists for alert %s (case %s); returning existing",
                alert_id, existing.case_id,
            )
            return existing

        case_id = self._generate_case_id()
        case = Case(
            case_id       = case_id,
            alert_id      = alert_id,
            alert_type    = alert_type,
            affected_host = affected_host,
            affected_user = affected_user,
            risk_score    = risk_score,
            priority      = priority.upper(),
        )

        with self._case_lock(case_id):
            self._kvstore_write(case)
            self._cache_set(case)

        log.info(
            "Case created",
            extra={
                "case_id":       case_id,
                "alert_id":      alert_id,
                "alert_type":    alert_type,
                "risk_score":    risk_score,
                "priority":      priority,
            },
        )
        return case

    def get_case(self, case_id: str) -> Optional[Case]:
        """
        Return a Case by ID from cache (if fresh) or KV Store.
        Returns None if not found.
        """
        # Check cache first
        cached = self._cache_get(case_id)
        if cached is not None:
            return cached

        record = self._kvstore_read(case_id)
        if record is None:
            return None

        self._cache_set(record)
        return record

    def update_case(
        self,
        case_id: str,
        updates: Dict[str, Any],
        agent_name: str = "orchestrator",
        detail: str = "",
    ) -> Case:
        """
        Apply a partial update to an existing case.
        Increments version for optimistic concurrency.
        Raises KeyError if the case does not exist.
        Raises ValueError for invalid field names.
        """
        _IMMUTABLE = {"case_id", "alert_id", "created_time", "_key"}
        invalid = set(updates.keys()) & _IMMUTABLE
        if invalid:
            raise ValueError(f"Cannot update immutable fields: {invalid}")

        with self._case_lock(case_id):
            case = self._kvstore_read(case_id)
            if case is None:
                raise KeyError(f"Case {case_id} not found")

            for k, v in updates.items():
                if hasattr(case, k):
                    setattr(case, k, v)
                else:
                    log.warning("Ignoring unknown case field '%s'", k)

            case.updated_time = time.time()
            case.version += 1

            # Append to in-case audit trail
            case.audit_trail.append({
                "timestamp":  case.updated_time,
                "agent":      agent_name,
                "action":     "update",
                "fields":     list(updates.keys()),
                "detail":     detail,
            })

            self._kvstore_write(case)
            self._cache_set(case)

        log.debug(
            "Case updated",
            extra={
                "case_id": case_id,
                "agent":   agent_name,
                "fields":  list(updates.keys()),
                "version": case.version,
            },
        )
        return case

    def transition(
        self,
        case_id: str,
        to_status: CaseStatus,
        agent_name: str = "orchestrator",
        detail: str = "",
    ) -> Case:
        """
        Transition a case to a new status with validation.
        Raises ValueError if the transition is not allowed.
        """
        with self._case_lock(case_id):
            case = self._kvstore_read(case_id)
            if case is None:
                raise KeyError(f"Case {case_id} not found")

            from_status = CaseStatus(case.status)
            allowed = _ALLOWED_TRANSITIONS.get(from_status, [])
            if to_status not in allowed:
                raise ValueError(
                    f"Transition {from_status.value} → {to_status.value} is not allowed. "
                    f"Permitted: {[s.value for s in allowed]}"
                )

            case.status      = to_status.value
            case.updated_time = time.time()
            case.version     += 1

            if to_status == CaseStatus.CLOSED:
                case.closed_time = time.time()

            case.audit_trail.append({
                "timestamp":   case.updated_time,
                "agent":       agent_name,
                "action":      "transition",
                "from_status": from_status.value,
                "to_status":   to_status.value,
                "detail":      detail,
            })

            self._kvstore_write(case)
            self._cache_set(case)

        log.info(
            "Case transitioned",
            extra={
                "case_id":     case_id,
                "from_status": from_status.value,
                "to_status":   to_status.value,
                "agent":       agent_name,
            },
        )
        return case

    # ------------------------------------------------------------------
    # Fault tolerance — state timeouts & retry tracking
    # ------------------------------------------------------------------

    def set_state_with_timeout(
        self,
        case_id: str,
        new_state: CaseStatus,
        timeout_seconds: int = 900,
        agent_name: str = "orchestrator",
        detail: str = "",
    ) -> Case:
        """
        Transition a case to new_state and arm a timeout watchdog for that
        state (default 15 minutes). Records state_entered_at/state_timeout_at
        so check_timeouts() can later detect a hung case.
        Raises ValueError if the transition is not allowed.
        """
        with self._case_lock(case_id):
            case = self._kvstore_read(case_id)
            if case is None:
                raise KeyError(f"Case {case_id} not found")

            from_status = CaseStatus(case.status)
            allowed = _ALLOWED_TRANSITIONS.get(from_status, [])
            if new_state not in allowed:
                raise ValueError(
                    f"Transition {from_status.value} → {new_state.value} is not allowed. "
                    f"Permitted: {[s.value for s in allowed]}"
                )

            now = time.time()
            case.status                   = new_state.value
            case.updated_time             = now
            case.state_entered_at         = now
            case.timeout_duration_seconds = int(timeout_seconds)
            case.state_timeout_at         = now + timeout_seconds
            case.version                 += 1

            if new_state == CaseStatus.CLOSED:
                case.closed_time = now

            case.audit_trail.append({
                "timestamp":   now,
                "agent":       agent_name,
                "action":      "transition",
                "from_status": from_status.value,
                "to_status":   new_state.value,
                "detail":      detail or f"timeout armed for {timeout_seconds}s",
                "timeout_at":  case.state_timeout_at,
            })

            self._kvstore_write(case)
            self._cache_set(case)

        log.info(
            "Case transitioned with timeout",
            extra={
                "case_id":         case_id,
                "from_status":     from_status.value,
                "to_status":       new_state.value,
                "timeout_seconds": timeout_seconds,
                "agent":           agent_name,
            },
        )
        return case

    def check_timeouts(self) -> List[str]:
        """
        Scan active cases for ones whose current-state timeout has elapsed.
        Intended to be polled by the orchestrator's watchdog thread every
        ~30 seconds. Returns the list of timed-out case_ids.
        """
        now = time.time()
        timed_out: List[str] = []
        conn = self._get_connector()
        records = conn.kvstore_query(_COLLECTION_ACTIVE)
        for rec in records:
            try:
                case = Case.from_kvstore_dict(rec)
            except Exception as exc:
                log.error("Failed to deserialise case record during timeout scan: %s — %s",
                          rec.get("_key"), exc)
                continue

            if case.status in _TERMINAL_STATUSES:
                continue
            if case.state_timeout_at is None:
                continue
            if now > case.state_timeout_at:
                timed_out.append(case.case_id)

        return timed_out

    def is_timed_out(self, case_id: str) -> bool:
        """Return True if the given case has exceeded its current-state timeout."""
        case = self.get_case(case_id)
        if case is None or case.state_timeout_at is None:
            return False
        if case.status in _TERMINAL_STATUSES:
            return False
        return time.time() > case.state_timeout_at

    def increment_retry(self, case_id: str) -> int:
        """Increment and persist a case's retry counter. Returns the new count."""
        with self._case_lock(case_id):
            case = self._kvstore_read(case_id)
            if case is None:
                raise KeyError(f"Case {case_id} not found")

            case.retry_count += 1
            case.updated_time = time.time()
            case.version     += 1
            case.audit_trail.append({
                "timestamp": case.updated_time,
                "agent":     "orchestrator",
                "action":    "retry_increment",
                "detail":    f"retry_count -> {case.retry_count}",
            })

            self._kvstore_write(case)
            self._cache_set(case)

        log.info("Case retry incremented",
                 extra={"case_id": case_id, "retry_count": case.retry_count})
        return case.retry_count

    def has_exhausted_retries(self, case_id: str) -> bool:
        """Return True if retry_count has reached or exceeded max_retries."""
        case = self.get_case(case_id)
        if case is None:
            return False
        return case.retry_count >= case.max_retries

    def list_cases(
        self,
        status: Optional[str] = None,
        priority: Optional[str] = None,
        limit: int = 100,
    ) -> List[Case]:
        """
        List cases from KV Store, optionally filtered by status and priority.
        Results are ordered by risk_score descending then created_time ascending.
        """
        query: Dict[str, Any] = {}
        if status:
            query["status"] = status.upper()
        if priority:
            query["priority"] = priority.upper()

        conn = self._get_connector()
        records = conn.kvstore_query(
            _COLLECTION_ACTIVE,
            query=query or None,
            sort="risk_score:-1,created_time:1",
            limit=limit,
        )
        cases = []
        for rec in records:
            try:
                c = Case.from_kvstore_dict(rec)
                self._cache_set(c)
                cases.append(c)
            except Exception as exc:
                log.error("Failed to deserialise case record: %s — %s", rec.get("_key"), exc)
        return cases

    def archive_case(self, case_id: str, agent_name: str = "orchestrator") -> bool:
        """
        Move a CLOSED or SUPPRESSED case from the active_cases collection to
        case_archive. The record remains searchable in the archive collection
        and all events are written to sentinel_audit by AuditLogger.
        Returns True if archived successfully.
        """
        with self._case_lock(case_id):
            case = self._kvstore_read(case_id)
            if case is None:
                log.warning("Archive requested for non-existent case %s", case_id)
                return False
            if case.status not in (CaseStatus.CLOSED.value, CaseStatus.SUPPRESSED.value):
                raise ValueError(
                    f"Cannot archive case {case_id} with status {case.status}. "
                    "Only CLOSED or SUPPRESSED cases can be archived."
                )

            conn = self._get_connector()
            # Write to archive collection
            archive_record = case.to_kvstore_dict()
            archive_record["archived_time"] = time.time()
            archive_record["archived_by"]   = agent_name
            conn.kvstore_upsert(_COLLECTION_ARCHIVE, case_id, archive_record)
            # Remove from active
            conn.kvstore_delete(_COLLECTION_ACTIVE, case_id)
            # Invalidate cache
            self._cache_invalidate(case_id)

        log.info("Case archived", extra={"case_id": case_id, "agent": agent_name})
        return True

    def get_stats(self) -> Dict[str, Any]:
        """Return a summary of case counts by status for the War Room dashboard."""
        conn = self._get_connector()
        records = conn.kvstore_query(_COLLECTION_ACTIVE)
        counts: Dict[str, int] = {}
        for rec in records:
            s = rec.get("status", "UNKNOWN")
            counts[s] = counts.get(s, 0) + 1
        return {
            "total":    len(records),
            "by_status": counts,
            "timestamp": time.time(),
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_connector(self):
        if self._conn is None:
            self._conn = get_connector()
        return self._conn

    def _case_lock(self, case_id: str) -> threading.Lock:
        """Return (creating if necessary) the per-case lock."""
        with self._locks_meta_lock:
            if case_id not in self._case_locks:
                self._case_locks[case_id] = threading.Lock()
            return self._case_locks[case_id]

    def _kvstore_write(self, case: Case) -> None:
        conn = self._get_connector()
        conn.kvstore_upsert(_COLLECTION_ACTIVE, case.case_id, case.to_kvstore_dict())

    def _kvstore_read(self, case_id: str) -> Optional[Case]:
        conn = self._get_connector()
        record = conn.kvstore_get(_COLLECTION_ACTIVE, case_id)
        if record is None:
            return None
        return Case.from_kvstore_dict(record)

    def _find_by_alert_id(self, alert_id: str) -> Optional[Case]:
        conn = self._get_connector()
        records = conn.kvstore_query(
            _COLLECTION_ACTIVE,
            query={"alert_id": alert_id},
            limit=1,
        )
        if records:
            return Case.from_kvstore_dict(records[0])
        return None

    def _generate_case_id(self) -> str:
        """Generate a globally unique, human-readable case ID: SEN-NNNNNN."""
        # Use time-based suffix so IDs sort chronologically
        suffix = str(int(time.time() * 1000))[-6:]
        uid    = uuid.uuid4().hex[:4].upper()
        return f"{self._CASE_ID_PREFIX}{suffix}{uid}"

    def _cache_get(self, case_id: str) -> Optional[Case]:
        with self._cache_lock:
            entry = self._cache.get(case_id)
            if entry is None:
                return None
            case, fetched_at = entry
            if time.time() - fetched_at > self._cache_ttl:
                del self._cache[case_id]
                return None
            return deepcopy(case)

    def _cache_set(self, case: Case) -> None:
        with self._cache_lock:
            self._cache[case.case_id] = (deepcopy(case), time.time())

    def _cache_invalidate(self, case_id: str) -> None:
        with self._cache_lock:
            self._cache.pop(case_id, None)
