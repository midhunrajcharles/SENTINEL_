"""
SENTINEL: Autonomous Agentic SOC Commander
mcp_client.py — Splunk MCP Server Python client

Provides SplunkMCPClient, a thread-safe, connection-pooled client for all
14 SENTINEL MCP tools. Implements exponential-backoff retry, a circuit
breaker, structured audit logging, and graceful degradation so a dead MCP
server never silently drops agent work.

Dependencies: requests (see lib/requirements.txt), standard library only.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ---------------------------------------------------------------------------
# Logging — structured JSON emitted on stdout; Splunk ingests via
# sentinel:orchestrator sourcetype and auto-KV extracts every field.
# ---------------------------------------------------------------------------

class _JSONFormatter(logging.Formatter):
    """Formats log records as single-line JSON for Splunk _json sourcetype."""

    def format(self, record: logging.LogRecord) -> str:
        payload: Dict[str, Any] = {
            "timestamp": int(record.created * 1000),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        # Merge any extra= kwargs passed to the log call
        for key, val in record.__dict__.items():
            if key not in {
                "args", "created", "exc_info", "exc_text", "filename",
                "funcName", "levelname", "levelno", "lineno", "message",
                "module", "msecs", "msg", "name", "pathname", "process",
                "processName", "relativeCreated", "stack_info", "thread",
                "threadName",
            }:
                payload[key] = val
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def _build_logger(name: str = "sentinel.mcp_client") -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(_JSONFormatter())
        logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    return logger


log = _build_logger()


# ---------------------------------------------------------------------------
# Exception hierarchy
# ---------------------------------------------------------------------------

class MCPError(Exception):
    """Base class for all MCP client errors."""
    def __init__(self, message: str, tool: str = "", status_code: int = 0,
                 context: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message)
        self.tool = tool
        self.status_code = status_code
        self.context = context or {}


class MCPConnectionError(MCPError):
    """MCP Server is unreachable or the TCP connection failed."""


class MCPAuthError(MCPError):
    """Bearer token was rejected (HTTP 401/403)."""


class MCPTimeoutError(MCPError):
    """Request to MCP Server exceeded the configured timeout."""


class MCPValidationError(MCPError):
    """The tool input failed JSON Schema validation on the server (HTTP 422)."""


class MCPCircuitOpenError(MCPError):
    """Circuit breaker is open; requests are not being sent to the MCP Server."""


class MCPToolError(MCPError):
    """The MCP Server accepted the call but the tool returned an error payload."""


# ---------------------------------------------------------------------------
# Circuit breaker
# ---------------------------------------------------------------------------

class _CircuitState(Enum):
    CLOSED = "closed"       # Normal operation
    OPEN = "open"           # Failing; reject calls immediately
    HALF_OPEN = "half_open" # Probe sent; waiting for result


@dataclass
class CircuitBreaker:
    """
    Thread-safe circuit breaker.

    Opens after `failure_threshold` consecutive failures.
    After `recovery_timeout_seconds` in OPEN state, moves to HALF_OPEN
    and allows a single probe request through. Success → CLOSED;
    failure → back to OPEN with a reset recovery timer.
    """
    failure_threshold: int = 5
    recovery_timeout_seconds: float = 60.0
    success_threshold: int = 1  # consecutive successes needed to close from half-open

    _state: _CircuitState = field(default=_CircuitState.CLOSED, init=False)
    _failure_count: int = field(default=0, init=False)
    _success_count: int = field(default=0, init=False)
    _opened_at: float = field(default=0.0, init=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False)

    @property
    def state(self) -> _CircuitState:
        with self._lock:
            if self._state is _CircuitState.OPEN:
                if time.monotonic() - self._opened_at >= self.recovery_timeout_seconds:
                    self._state = _CircuitState.HALF_OPEN
                    self._success_count = 0
                    log.info("Circuit breaker moved to HALF_OPEN",
                             extra={"circuit_state": "half_open"})
            return self._state

    def record_success(self) -> None:
        with self._lock:
            self._failure_count = 0
            if self._state is _CircuitState.HALF_OPEN:
                self._success_count += 1
                if self._success_count >= self.success_threshold:
                    self._state = _CircuitState.CLOSED
                    log.info("Circuit breaker CLOSED after successful probe",
                             extra={"circuit_state": "closed"})
            else:
                self._state = _CircuitState.CLOSED

    def record_failure(self) -> None:
        with self._lock:
            self._failure_count += 1
            if (self._state is _CircuitState.HALF_OPEN or
                    self._failure_count >= self.failure_threshold):
                self._state = _CircuitState.OPEN
                self._opened_at = time.monotonic()
                log.error(
                    "Circuit breaker OPENED after %d consecutive failures",
                    self._failure_count,
                    extra={
                        "circuit_state": "open",
                        "failure_count": self._failure_count,
                        "recovery_in_seconds": self.recovery_timeout_seconds,
                    },
                )

    def allow_request(self) -> bool:
        """Returns True if a request should be sent, False if it must be blocked."""
        s = self.state
        if s is _CircuitState.CLOSED:
            return True
        if s is _CircuitState.HALF_OPEN:
            # Allow exactly one probe; guard with a flag so concurrent callers
            # don't all sneak through at the same time.
            with self._lock:
                if self._state is _CircuitState.HALF_OPEN:
                    self._state = _CircuitState.OPEN  # tentatively re-open
                    return True
            return False
        return False  # OPEN


# ---------------------------------------------------------------------------
# Retry helper
# ---------------------------------------------------------------------------

def _make_retry_session(
    total: int = 3,
    backoff_factor: float = 1.0,
    pool_connections: int = 4,
    pool_maxsize: int = 10,
    verify_ssl: bool = False,
) -> requests.Session:
    """
    Build a requests.Session with connection pooling and urllib3-level retries
    for transport-layer failures (connect errors, read errors, redirect loops).
    HTTP-level retries (4xx/5xx) are handled separately in _call() so we can
    apply business logic (circuit breaker, audit logging) on each attempt.
    """
    session = requests.Session()
    retry = Retry(
        total=total,
        backoff_factor=backoff_factor,
        # Only retry on connection/read errors at the transport layer;
        # status-based retries are managed by _call().
        status_forcelist=[],
        allowed_methods=["POST", "GET"],
        raise_on_status=False,
    )
    adapter = HTTPAdapter(
        max_retries=retry,
        pool_connections=pool_connections,
        pool_maxsize=pool_maxsize,
    )
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    session.verify = verify_ssl
    return session


# ---------------------------------------------------------------------------
# Audit queue — persists failed MCP calls for later replay
# ---------------------------------------------------------------------------

@dataclass
class _QueuedCall:
    call_id: str
    tool_name: str
    payload: Dict[str, Any]
    queued_at: float
    attempt_count: int = 0


class _RetryQueue:
    """
    In-memory FIFO queue for MCP calls that failed while the server was down.
    The orchestrator drains this queue on each poll cycle via drain().
    In production this would be backed by the KV Store; here it uses a
    thread-safe deque as a lightweight stand-in.
    """

    def __init__(self, maxsize: int = 500) -> None:
        self._queue: List[_QueuedCall] = []
        self._lock = threading.Lock()
        self._maxsize = maxsize

    def enqueue(self, call: _QueuedCall) -> bool:
        with self._lock:
            if len(self._queue) >= self._maxsize:
                log.warning("Retry queue full; dropping oldest entry",
                            extra={"queue_size": self._maxsize})
                self._queue.pop(0)
            self._queue.append(call)
            return True

    def drain(self) -> List[_QueuedCall]:
        with self._lock:
            items = list(self._queue)
            self._queue.clear()
            return items

    def __len__(self) -> int:
        with self._lock:
            return len(self._queue)


# ---------------------------------------------------------------------------
# Main client
# ---------------------------------------------------------------------------

class SplunkMCPClient:
    """
    Thread-safe client for all 14 SENTINEL MCP tools.

    Configuration is resolved in this priority order:
      1. Constructor kwargs (highest precedence)
      2. Environment variables  (SENTINEL_MCP_URL, SENTINEL_MCP_TOKEN, …)
      3. Defaults

    Usage::

        client = SplunkMCPClient()
        results = client.search_spl("index=endpoint | head 5")
    """

    # Environment variable names
    _ENV_URL   = "SENTINEL_MCP_URL"
    _ENV_TOKEN = "SENTINEL_MCP_TOKEN"
    _ENV_SSL   = "SENTINEL_MCP_VERIFY_SSL"
    _ENV_AGENT = "SENTINEL_AGENT_NAME"

    # Retry parameters for HTTP-level failures
    _MAX_RETRIES      = 3
    _BACKOFF_BASE_S   = 1.0
    _BACKOFF_MAX_S    = 30.0
    _RETRYABLE_CODES  = {429, 500, 502, 503, 504}

    def __init__(
        self,
        base_url: Optional[str] = None,
        token: Optional[str] = None,
        agent_name: Optional[str] = None,
        verify_ssl: Optional[bool] = None,
        timeout: float = 30.0,
        circuit_breaker: Optional[CircuitBreaker] = None,
    ) -> None:
        self._base_url: str = (
            base_url
            or os.environ.get(self._ENV_URL, "https://localhost:3000")
        ).rstrip("/")

        raw_token = token or os.environ.get(self._ENV_TOKEN, "")
        if not raw_token:
            log.warning(
                "No MCP bearer token configured. Set %s or pass token= to constructor.",
                self._ENV_TOKEN,
                extra={"env_var": self._ENV_TOKEN},
            )
        self._token: str = raw_token

        self._agent_name: str = (
            agent_name
            or os.environ.get(self._ENV_AGENT, "unknown_agent")
        )

        _verify_env = os.environ.get(self._ENV_SSL, "false").lower()
        self._verify_ssl: bool = (
            verify_ssl if verify_ssl is not None else _verify_env == "true"
        )

        self._timeout = timeout
        self._circuit = circuit_breaker or CircuitBreaker(
            failure_threshold=5,
            recovery_timeout_seconds=60.0,
        )
        self._retry_queue = _RetryQueue()
        self._session = _make_retry_session(verify_ssl=self._verify_ssl)
        self._lock = threading.Lock()  # guards token refresh

        log.info(
            "SplunkMCPClient initialised",
            extra={
                "mcp_base_url": self._base_url,
                "agent_name": self._agent_name,
                "verify_ssl": self._verify_ssl,
            },
        )

    # ------------------------------------------------------------------
    # Internal transport
    # ------------------------------------------------------------------

    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self._token}",
            "Content-Type": "application/json",
            "X-SENTINEL-Agent": self._agent_name,
        }

    def _call(
        self,
        tool_name: str,
        payload: Dict[str, Any],
        *,
        timeout: Optional[float] = None,
    ) -> Dict[str, Any]:
        """
        Core dispatch method. Wraps a single tool call with:
          - Circuit breaker gate
          - Exponential-backoff retry loop (HTTP-level)
          - Per-call audit logging
          - Graceful degradation into retry queue on total failure
        """
        call_id = str(uuid.uuid4())
        start_ts = time.time()
        url = urljoin(self._base_url + "/", f"tools/{tool_name}")
        effective_timeout = timeout or self._timeout

        log.debug(
            "MCP call start",
            extra={
                "call_id": call_id,
                "tool_name": tool_name,
                "agent_name": self._agent_name,
                "mcp_url": url,
            },
        )

        if not self._circuit.allow_request():
            self._enqueue(call_id, tool_name, payload)
            raise MCPCircuitOpenError(
                f"Circuit breaker is OPEN for MCP Server at {self._base_url}. "
                "Call queued for retry.",
                tool=tool_name,
            )

        last_exc: Optional[Exception] = None

        for attempt in range(1, self._MAX_RETRIES + 1):
            try:
                resp = self._session.post(
                    url,
                    headers=self._headers(),
                    json={"tool": tool_name, "input": payload},
                    timeout=effective_timeout,
                )
            except requests.exceptions.Timeout as exc:
                last_exc = MCPTimeoutError(
                    f"MCP call '{tool_name}' timed out after {effective_timeout}s "
                    f"(attempt {attempt}/{self._MAX_RETRIES})",
                    tool=tool_name,
                )
                self._circuit.record_failure()
                self._log_attempt(call_id, tool_name, payload, attempt,
                                  status_code=0, duration_ms=_elapsed_ms(start_ts),
                                  error=str(last_exc))
                if attempt < self._MAX_RETRIES:
                    self._sleep_backoff(attempt)
                continue

            except requests.exceptions.ConnectionError as exc:
                last_exc = MCPConnectionError(
                    f"Cannot connect to MCP Server at {self._base_url} "
                    f"(attempt {attempt}/{self._MAX_RETRIES}): {exc}",
                    tool=tool_name,
                )
                self._circuit.record_failure()
                self._log_attempt(call_id, tool_name, payload, attempt,
                                  status_code=0, duration_ms=_elapsed_ms(start_ts),
                                  error=str(last_exc))
                if attempt < self._MAX_RETRIES:
                    self._sleep_backoff(attempt)
                continue

            duration = _elapsed_ms(start_ts)

            # --- Auth errors: do not retry, surface immediately ---
            if resp.status_code in (401, 403):
                self._circuit.record_failure()
                err = MCPAuthError(
                    f"MCP authentication failed for tool '{tool_name}' "
                    f"(HTTP {resp.status_code}). Verify SENTINEL_MCP_TOKEN.",
                    tool=tool_name,
                    status_code=resp.status_code,
                )
                self._log_attempt(call_id, tool_name, payload, attempt,
                                  status_code=resp.status_code,
                                  duration_ms=duration, error=str(err))
                raise err

            # --- Input validation error: do not retry ---
            if resp.status_code == 422:
                detail = _safe_json(resp).get("detail", resp.text[:512])
                err = MCPValidationError(
                    f"Tool '{tool_name}' input validation failed: {detail}",
                    tool=tool_name,
                    status_code=422,
                    context={"detail": detail, "payload": payload},
                )
                self._log_attempt(call_id, tool_name, payload, attempt,
                                  status_code=422, duration_ms=duration,
                                  error=str(err))
                raise err

            # --- Retryable server errors ---
            if resp.status_code in self._RETRYABLE_CODES:
                last_exc = MCPConnectionError(
                    f"MCP returned HTTP {resp.status_code} for tool '{tool_name}' "
                    f"(attempt {attempt}/{self._MAX_RETRIES})",
                    tool=tool_name,
                    status_code=resp.status_code,
                )
                self._circuit.record_failure()
                self._log_attempt(call_id, tool_name, payload, attempt,
                                  status_code=resp.status_code,
                                  duration_ms=duration, error=str(last_exc))
                if attempt < self._MAX_RETRIES:
                    retry_after = _retry_after_header(resp)
                    self._sleep_backoff(attempt, override_seconds=retry_after)
                continue

            # --- Non-2xx that we don't know how to handle ---
            if not resp.ok:
                body = _safe_json(resp)
                err = MCPToolError(
                    f"MCP tool '{tool_name}' returned HTTP {resp.status_code}",
                    tool=tool_name,
                    status_code=resp.status_code,
                    context={"response": body},
                )
                self._circuit.record_failure()
                self._log_attempt(call_id, tool_name, payload, attempt,
                                  status_code=resp.status_code,
                                  duration_ms=duration, error=str(err))
                raise err

            # --- Success ---
            self._circuit.record_success()
            result = _safe_json(resp)
            self._log_attempt(call_id, tool_name, payload, attempt,
                              status_code=resp.status_code,
                              duration_ms=duration, error=None)
            log.info(
                "MCP call succeeded",
                extra={
                    "call_id": call_id,
                    "tool_name": tool_name,
                    "agent_name": self._agent_name,
                    "status_code": resp.status_code,
                    "duration_ms": duration,
                    "attempt": attempt,
                },
            )
            return result

        # All retries exhausted
        self._enqueue(call_id, tool_name, payload)
        assert last_exc is not None
        raise last_exc

    def _sleep_backoff(self, attempt: int,
                       override_seconds: Optional[float] = None) -> None:
        delay = override_seconds or min(
            self._BACKOFF_BASE_S * (2 ** (attempt - 1)),
            self._BACKOFF_MAX_S,
        )
        log.debug("Backoff before retry",
                  extra={"delay_seconds": delay, "attempt": attempt})
        time.sleep(delay)

    def _enqueue(self, call_id: str, tool_name: str,
                 payload: Dict[str, Any]) -> None:
        item = _QueuedCall(
            call_id=call_id,
            tool_name=tool_name,
            payload=payload,
            queued_at=time.time(),
        )
        self._retry_queue.enqueue(item)
        log.warning(
            "MCP call queued for retry (MCP server unavailable)",
            extra={
                "call_id": call_id,
                "tool_name": tool_name,
                "queue_depth": len(self._retry_queue),
            },
        )

    def _log_attempt(
        self,
        call_id: str,
        tool_name: str,
        payload: Dict[str, Any],
        attempt: int,
        *,
        status_code: int,
        duration_ms: float,
        error: Optional[str],
    ) -> None:
        level = logging.ERROR if error else logging.DEBUG
        log.log(
            level,
            "MCP attempt %d/%d: tool=%s status=%s duration_ms=%.1f",
            attempt,
            self._MAX_RETRIES,
            tool_name,
            status_code or "no_response",
            duration_ms,
            extra={
                "call_id": call_id,
                "tool_name": tool_name,
                "attempt": attempt,
                "max_attempts": self._MAX_RETRIES,
                "status_code": status_code,
                "duration_ms": duration_ms,
                "agent_name": self._agent_name,
                "error": error,
                # Omit full payload at ERROR level to avoid logging sensitive
                # parameters (IPs, usernames) into the error stream.
                "payload_keys": list(payload.keys()),
            },
        )

    # ------------------------------------------------------------------
    # Health & connectivity
    # ------------------------------------------------------------------

    def health_check(self) -> Dict[str, Any]:
        """
        GET /health — unauthenticated liveness probe.
        Returns the parsed JSON body or raises MCPConnectionError.
        """
        url = urljoin(self._base_url + "/", "health")
        try:
            resp = self._session.get(url, timeout=5.0)
            resp.raise_for_status()
            return _safe_json(resp)
        except requests.exceptions.ConnectionError as exc:
            raise MCPConnectionError(
                f"MCP Server health check failed: {exc}",
                tool="health",
            ) from exc
        except requests.exceptions.Timeout as exc:
            raise MCPTimeoutError(
                "MCP Server health check timed out.",
                tool="health",
            ) from exc

    def drain_retry_queue(self) -> List[Dict[str, Any]]:
        """
        Re-submit all queued calls. Called by the orchestrator on each poll cycle.
        Returns a list of {call_id, tool_name, status} outcome dicts.
        """
        items = self._retry_queue.drain()
        if not items:
            return []

        outcomes = []
        for item in items:
            item.attempt_count += 1
            try:
                result = self._call(item.tool_name, item.payload)
                outcomes.append({
                    "call_id": item.call_id,
                    "tool_name": item.tool_name,
                    "status": "replayed_ok",
                    "result": result,
                })
            except MCPError as exc:
                # Re-enqueue if circuit is still open or server still down;
                # drop permanently if it was an auth or validation error.
                if not isinstance(exc, (MCPAuthError, MCPValidationError)):
                    self._retry_queue.enqueue(item)
                outcomes.append({
                    "call_id": item.call_id,
                    "tool_name": item.tool_name,
                    "status": "replay_failed",
                    "error": str(exc),
                })
        return outcomes

    @property
    def circuit_state(self) -> str:
        return self._circuit.state.value

    @property
    def queue_depth(self) -> int:
        return len(self._retry_queue)

    # ------------------------------------------------------------------
    # Investigation tools
    # ------------------------------------------------------------------

    def search_spl(
        self,
        query: str,
        earliest: str = "-24h",
        latest: str = "now",
        max_results: int = 10_000,
        timeout: Optional[float] = None,
    ) -> Dict[str, Any]:
        """Execute an arbitrary SPL query and return the result set."""
        if not query or not query.strip():
            raise MCPValidationError("query must be a non-empty string.",
                                     tool="search_spl")
        return self._call(
            "search_spl",
            {
                "spl": query.strip(),
                "earliest": earliest,
                "latest": latest,
                "max_results": min(max_results, 10_000),
            },
            timeout=timeout,
        )

    def get_indexes(self, filter: str = "",
                    include_internal: bool = False) -> Dict[str, Any]:
        """List Splunk indexes accessible to the sentinel_service account."""
        return self._call("get_indexes", {
            "filter": filter,
            "include_internal": include_internal,
        })

    def run_saved_search(
        self,
        search_name: str,
        earliest: str = "",
        latest: str = "",
        params: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """Execute a saved search by name, optionally overriding time bounds."""
        if not search_name:
            raise MCPValidationError("search_name is required.",
                                     tool="run_saved_search")
        payload: Dict[str, Any] = {"search_name": search_name}
        if earliest:
            payload["earliest"] = earliest
        if latest:
            payload["latest"] = latest
        if params:
            payload["params"] = params
        return self._call("run_saved_search", payload)

    def validate_spl(
        self,
        query: str,
        check_indexes: bool = True,
        estimate_cost: bool = True,
    ) -> Dict[str, Any]:
        """Validate SPL syntax and return warnings/errors without executing."""
        if not query:
            raise MCPValidationError("query is required.", tool="validate_spl")
        return self._call("validate_spl", {
            "spl": query.strip(),
            "check_indexes": check_indexes,
            "estimate_cost": estimate_cost,
        })

    def get_knowledge_objects(
        self,
        object_type: str = "all",
        filter: str = "",
        sourcetype: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Retrieve CIM data models, field extractions, event types, tags, macros.
        Pass object_type="datamodel" to narrow scope.
        """
        payload: Dict[str, Any] = {
            "object_type": object_type,
            "filter": filter,
        }
        if sourcetype:
            payload["sourcetype"] = sourcetype
        return self._call("get_knowledge_objects", payload)

    def query_es_notable(
        self,
        notable_id: Optional[str] = None,
        host: Optional[str] = None,
        user: Optional[str] = None,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        earliest: str = "-24h",
        latest: str = "now",
        limit: int = 100,
    ) -> Dict[str, Any]:
        """Query Splunk Enterprise Security notable events."""
        payload: Dict[str, Any] = {
            "earliest": earliest,
            "latest": latest,
            "max_results": min(limit, 500),
        }
        if notable_id:
            payload["notable_id"] = notable_id
        if host:
            payload["host"] = host
        if user:
            payload["user"] = user
        if status:
            payload["status"] = status
        if severity:
            payload["severity"] = severity
        return self._call("query_es_notable", payload)

    def get_asset_context(
        self,
        host: str,
        identifier_type: str = "auto",
        include_vulnerabilities: bool = False,
    ) -> Dict[str, Any]:
        """Retrieve CMDB and asset criticality data for a host or IP."""
        if not host:
            raise MCPValidationError("host is required.", tool="get_asset_context")
        return self._call("get_asset_context", {
            "asset_identifier": host,
            "identifier_type": identifier_type,
            "include_vulnerabilities": include_vulnerabilities,
        })

    def get_process_tree(
        self,
        host: str,
        pid: Optional[int] = None,
        process_name: Optional[str] = None,
        depth: int = 3,
        earliest: str = "-2h",
        latest: str = "now",
        include_network: bool = True,
        include_files: bool = True,
    ) -> Dict[str, Any]:
        """Reconstruct process ancestry and children from EDR telemetry."""
        if not host:
            raise MCPValidationError("host is required.", tool="get_process_tree")
        payload: Dict[str, Any] = {
            "host": host,
            "depth": max(1, min(depth, 10)),
            "earliest": earliest,
            "latest": latest,
            "include_network": include_network,
            "include_files": include_files,
        }
        if pid is not None:
            payload["process_id"] = pid
        if process_name:
            payload["process_name"] = process_name
        return self._call("get_process_tree", payload)

    def get_network_flows(
        self,
        host: str,
        src_ip: Optional[str] = None,
        dest_ip: Optional[str] = None,
        port: Optional[int] = None,
        direction: str = "both",
        protocol: str = "any",
        min_bytes: int = 0,
        exclude_internal: bool = False,
        earliest: str = "-1h",
        latest: str = "now",
        max_results: int = 500,
    ) -> Dict[str, Any]:
        """Retrieve NetFlow/Zeek/firewall session records for a host."""
        if not host:
            raise MCPValidationError("host is required.", tool="get_network_flows")
        payload: Dict[str, Any] = {
            "host": src_ip or dest_ip or host,
            "direction": direction,
            "protocol": protocol,
            "min_bytes": min_bytes,
            "exclude_internal": exclude_internal,
            "earliest": earliest,
            "latest": latest,
            "max_results": min(max_results, 10_000),
        }
        if port is not None:
            payload["dest_port"] = port
        return self._call("get_network_flows", payload)

    def get_user_activity(
        self,
        user: str,
        earliest: str = "-24h",
        latest: str = "now",
        event_types: Optional[List[str]] = None,
        include_baseline: bool = True,
        max_events: int = 200,
    ) -> Dict[str, Any]:
        """Retrieve a UEBA timeline for a user with optional baseline comparison."""
        if not user:
            raise MCPValidationError("user is required.", tool="get_user_activity")
        return self._call("get_user_activity", {
            "user": user,
            "earliest": earliest,
            "latest": latest,
            "event_types": event_types or ["all"],
            "include_baseline": include_baseline,
            "max_events": min(max_events, 1_000),
        })

    # ------------------------------------------------------------------
    # Response tools
    # ------------------------------------------------------------------

    def execute_response_action(
        self,
        action_type: str,
        target: str,
        case_id: str,
        platform: str = "auto",
        rollback_timer: int = 14_400,
        justification: str = "",
        parameters: Optional[Dict[str, Any]] = None,
        dry_run: bool = False,
    ) -> Dict[str, Any]:
        """
        Execute a containment or remediation action via EDR/Identity/Firewall APIs.
        rollback_timer is in seconds; 14400 = 4 hours.
        """
        _VALID_ACTIONS = {
            "isolate_host", "unisolate_host", "disable_user", "enable_user",
            "block_ip", "unblock_ip", "quarantine_file", "restore_file",
            "kill_process", "revoke_session", "rotate_credentials",
            "remediate_s3_policy",
        }
        if action_type not in _VALID_ACTIONS:
            raise MCPValidationError(
                f"Unknown action_type '{action_type}'. "
                f"Valid values: {sorted(_VALID_ACTIONS)}",
                tool="execute_response_action",
            )
        if not target:
            raise MCPValidationError("target is required.",
                                     tool="execute_response_action")
        if not case_id:
            raise MCPValidationError("case_id is required for audit trail.",
                                     tool="execute_response_action")

        payload: Dict[str, Any] = {
            "action_type": action_type,
            "target": target,
            "case_id": case_id,
            "platform": platform,
            "rollback_after_hours": rollback_timer / 3600.0,
            "dry_run": dry_run,
            "justification": justification or f"Automated response for case {case_id}",
        }
        if parameters:
            payload.update(parameters)

        log.info(
            "Executing response action",
            extra={
                "action_type": action_type,
                "target": target,
                "case_id": case_id,
                "dry_run": dry_run,
                "agent_name": self._agent_name,
            },
        )
        return self._call("execute_response_action", payload, timeout=35.0)

    def create_ticket(
        self,
        case_id: str,
        system: str = "servicenow",
        title: Optional[str] = None,
        description: Optional[str] = None,
        priority: str = "P3",
        category: str = "Security",
        assignment_group: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create an incident ticket in ServiceNow or Jira."""
        _PRIORITY_MAP = {"P1": 1, "P2": 2, "P3": 3, "P4": 4, "P5": 5}
        priority_int = _PRIORITY_MAP.get(priority.upper(), 3)

        payload: Dict[str, Any] = {
            "case_id": case_id,
            "platform": system.lower(),
            "priority": priority_int,
            "category": category,
        }
        if title:
            payload["title"] = title
        if description:
            payload["additional_notes"] = description
        if assignment_group:
            payload["assignment_group"] = assignment_group

        return self._call("create_ticket", payload)

    def notify_stakeholders(
        self,
        case_id: str,
        level: str,
        message: str = "",
        channels: Optional[List[str]] = None,
        recipients: Optional[List[str]] = None,
        urgency: str = "high",
    ) -> Dict[str, Any]:
        """Send incident notifications over Slack, PagerDuty, or email."""
        _VALID_LEVELS = {"alert", "update", "resolved", "custom"}
        if level not in _VALID_LEVELS:
            raise MCPValidationError(
                f"level must be one of {sorted(_VALID_LEVELS)}",
                tool="notify_stakeholders",
            )
        payload: Dict[str, Any] = {
            "case_id": case_id,
            "channels": channels or ["slack"],
            "message_type": level,
            "urgency": urgency,
        }
        if message:
            payload["custom_message"] = message
        if recipients:
            payload["recipients"] = recipients
        return self._call("notify_stakeholders", payload)

    # ------------------------------------------------------------------
    # Enrichment tools
    # ------------------------------------------------------------------

    def enrich_threat_intel(
        self,
        ioc: str,
        ioc_type: str = "auto",
        sources: Optional[List[str]] = None,
        force_refresh: bool = False,
        check_whitelist: bool = True,
    ) -> Dict[str, Any]:
        """
        Enrich an IOC (IP, domain, hash, URL) via VirusTotal, MISP, AbuseIPDB.
        ioc_type="auto" lets the server infer the type from the value format.
        """
        if not ioc:
            raise MCPValidationError("ioc value is required.",
                                     tool="enrich_threat_intel")

        resolved_type = ioc_type
        if ioc_type == "auto":
            resolved_type = _infer_ioc_type(ioc)

        _VALID_TYPES = {"ip", "domain", "url", "md5", "sha1", "sha256", "auto"}
        if ioc_type not in _VALID_TYPES:
            raise MCPValidationError(
                f"ioc_type must be one of {sorted(_VALID_TYPES)}",
                tool="enrich_threat_intel",
            )

        return self._call("enrich_threat_intel", {
            "ioc_value": ioc,
            "ioc_type": resolved_type,
            "sources": sources or ["all"],
            "force_refresh": force_refresh,
            "check_whitelist": check_whitelist,
        })


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _elapsed_ms(start: float) -> float:
    return round((time.time() - start) * 1000, 1)


def _safe_json(resp: requests.Response) -> Dict[str, Any]:
    try:
        return resp.json()
    except ValueError:
        return {"raw": resp.text[:2048]}


def _retry_after_header(resp: requests.Response) -> Optional[float]:
    val = resp.headers.get("Retry-After")
    if val:
        try:
            return float(val)
        except ValueError:
            pass
    return None


def _infer_ioc_type(value: str) -> str:
    """
    Best-effort IOC type detection from the value's format.
    Preference order: hash lengths → IP → URL → domain.
    """
    import re
    stripped = value.strip().lower()
    if re.fullmatch(r"[0-9a-f]{32}", stripped):
        return "md5"
    if re.fullmatch(r"[0-9a-f]{40}", stripped):
        return "sha1"
    if re.fullmatch(r"[0-9a-f]{64}", stripped):
        return "sha256"
    if re.fullmatch(
        r"(\d{1,3}\.){3}\d{1,3}",
        stripped.split(":")[0],  # strip port if present
    ):
        return "ip"
    if stripped.startswith(("http://", "https://")):
        return "url"
    return "domain"


# ---------------------------------------------------------------------------
# __main__ — connectivity smoke test against a mock/real MCP server
# ---------------------------------------------------------------------------

def _run_smoke_test(client: SplunkMCPClient) -> None:
    """
    Runs a set of lightweight connectivity checks. Exits with code 1 on
    any hard failure. Designed to be run manually before starting agents:

        python mcp_client.py
    """
    sep = "=" * 60
    passed = 0
    failed = 0

    def _check(label: str, fn, *args, **kwargs) -> bool:
        nonlocal passed, failed
        print(f"\n  [{label}]")
        try:
            result = fn(*args, **kwargs)
            snippet = json.dumps(result, indent=2)[:400]
            print(f"    PASS\n    {snippet}")
            passed += 1
            return True
        except MCPCircuitOpenError as exc:
            print(f"    SKIP (circuit open): {exc}")
            return False
        except MCPError as exc:
            print(f"    FAIL: {type(exc).__name__}: {exc}")
            failed += 1
            return False
        except Exception as exc:
            print(f"    ERROR (unexpected): {type(exc).__name__}: {exc}")
            failed += 1
            return False

    print(sep)
    print("  SENTINEL MCP Client — Connectivity Smoke Test")
    print(f"  Target: {client._base_url}")
    print(f"  Agent:  {client._agent_name}")
    print(sep)

    # 1. Health check (unauthenticated)
    print("\n--- 1. Health check ---")
    try:
        health = client.health_check()
        print(f"  PASS: {health}")
        passed += 1
    except MCPError as exc:
        print(f"  FAIL: {exc}")
        print("\n  MCP Server appears to be DOWN. Check that the server is running:")
        print(f"    node dist/index.js --config mcp_server.local.conf")
        failed += 1

    # 2. Tool discovery
    print("\n--- 2. Tool discovery ---")
    _check("GET /tools",
           lambda: client._session.get(
               f"{client._base_url}/tools",
               headers=client._headers(),
               timeout=5.0,
           ).json())

    # 3. SPL validation (safe — does not execute a search)
    print("\n--- 3. SPL validation ---")
    _check("validate_spl",
           client.validate_spl,
           "index=sentinel_cases | head 1")

    # 4. Index listing
    print("\n--- 4. Index listing ---")
    _check("get_indexes", client.get_indexes, filter="sentinel")

    # 5. Knowledge objects
    print("\n--- 5. Knowledge objects ---")
    _check("get_knowledge_objects",
           client.get_knowledge_objects,
           object_type="datamodel", filter="Endpoint")

    # 6. IOC type inference (local — no network call)
    print("\n--- 6. IOC type inference (local) ---")
    tests = [
        ("185.220.101.42",              "ip"),
        ("evil.example.com",            "domain"),
        ("https://bad.example.com/x",   "url"),
        ("d41d8cd98f00b204e9800998ecf8427e", "md5"),
        ("a" * 40,                      "sha1"),
        ("b" * 64,                      "sha256"),
    ]
    all_ok = True
    for val, expected in tests:
        got = _infer_ioc_type(val)
        status = "ok" if got == expected else "FAIL"
        if got != expected:
            all_ok = False
            failed += 1
        print(f"  {status}: '{val[:32]}' → {got} (expected {expected})")
    if all_ok:
        passed += 1

    # 7. Retry queue drain (no-op when queue is empty)
    print("\n--- 7. Retry queue ---")
    outcomes = client.drain_retry_queue()
    print(f"  Queue depth: {client.queue_depth} | Drained: {len(outcomes)}")
    passed += 1

    # Summary
    print(f"\n{sep}")
    print(f"  Results: {passed} passed, {failed} failed")
    print(f"  Circuit breaker state: {client.circuit_state}")
    print(sep)

    if failed:
        sys.exit(1)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="SENTINEL MCP Client smoke test"
    )
    parser.add_argument(
        "--url",
        default=os.environ.get(SplunkMCPClient._ENV_URL, "https://localhost:3000"),
        help="MCP Server base URL",
    )
    parser.add_argument(
        "--token",
        default=os.environ.get(SplunkMCPClient._ENV_TOKEN, ""),
        help="Bearer token (or set SENTINEL_MCP_TOKEN env var)",
    )
    parser.add_argument(
        "--agent",
        default="smoke_test",
        help="Agent name to send in X-SENTINEL-Agent header",
    )
    parser.add_argument(
        "--no-ssl-verify",
        action="store_true",
        default=True,
        help="Disable TLS certificate verification (dev only)",
    )
    args = parser.parse_args()

    client = SplunkMCPClient(
        base_url=args.url,
        token=args.token,
        agent_name=args.agent,
        verify_ssl=not args.no_ssl_verify,
    )
    _run_smoke_test(client)
