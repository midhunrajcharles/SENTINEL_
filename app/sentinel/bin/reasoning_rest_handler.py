"""
SENTINEL: Autonomous Agentic SOC Commander
reasoning_rest_handler.py — REST endpoint exposing agent chain-of-thought traces

Implements:
    GET /services/sentinel/reasoning/<case_id>

Registered via [expose:reasoning] in web.conf (and the companion
restmap.conf [script:sentinel_reasoning] stanza). Returns the full
step-by-step "Chain of Thought" explainability trace recorded by every
agent for the given case — Vanguard's chain_of_thought, Sherlock's
investigation_chain, and Executor's action_chain — so SOC auditors,
compliance tooling, and external dashboards can pull the complete
reasoning trail for any case independently of the War Room UI.

This module performs no analysis of its own: it reads each agent's
decision packet straight off the persisted Case (as written by
agent_vanguard.py / agent_sherlock.py / agent_executor.py) and re-exposes
the chain fields verbatim — mirroring AuditLogger.log_chain_of_thought's
"stored verbatim" guarantee for the audit index.

Response shape::

    {
      "case_id": "SEN-001",
      "found": true,
      "reasoning": {
        "vanguard": {"agent": "vanguard", "chain_of_thought": [...], "reasoning": "..."},
        "sherlock": {"agent": "sherlock", "investigation_chain": [...], "executive_summary": "..."},
        "executor": {"agent": "executor", "action_chain": [...], "halted": false}
      }
    }

Dependencies: standard library, utils.state_manager.CaseStateManager
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, Optional

from utils.state_manager import CaseStateManager

log = logging.getLogger("sentinel.reasoning_rest_handler")


# ---------------------------------------------------------------------------
# Core lookup — framework-independent, directly unit-testable
# ---------------------------------------------------------------------------

def get_reasoning_for_case(
    case_id: str,
    state_manager: Optional[CaseStateManager] = None,
) -> Dict[str, Any]:
    """
    Assemble the full chain-of-thought trace for a case from the agent
    decision packets already persisted on it.

    Read-only — performs no analysis and changes no state. It only
    re-exposes each agent's existing `chain_of_thought` /
    `investigation_chain` / `action_chain` field exactly as that agent
    generated and audit-logged it.

    Returns ``{"case_id": ..., "found": bool, "reasoning": {...}}`` —
    `found` is False (and `reasoning` empty) if the case does not exist.
    Agents that have not yet run on the case (or produced no chain) are
    simply omitted from `reasoning`.
    """
    sm = state_manager if state_manager is not None else CaseStateManager()
    case = sm.get_case(case_id)
    if case is None:
        return {"case_id": case_id, "found": False, "reasoning": {}}

    vanguard     = case.vanguard_decision or {}
    sherlock     = case.sherlock_report or {}
    executor_log = _latest_executor_log(case)

    reasoning: Dict[str, Any] = {}

    if vanguard.get("chain_of_thought"):
        reasoning["vanguard"] = {
            "agent":            "vanguard",
            "chain_of_thought": vanguard.get("chain_of_thought", []),
            "reasoning":        vanguard.get("reasoning", ""),
            "decision":         vanguard.get("decision", ""),
        }

    if sherlock.get("investigation_chain"):
        reasoning["sherlock"] = {
            "agent":               "sherlock",
            "investigation_chain": sherlock.get("investigation_chain", []),
            "executive_summary":   sherlock.get("executive_summary", ""),
        }

    if executor_log.get("action_chain"):
        reasoning["executor"] = {
            "agent":        "executor",
            "action_chain": executor_log.get("action_chain", []),
            "halted":       executor_log.get("halted", False),
            "halt_reason":  executor_log.get("halt_reason", ""),
        }

    return {"case_id": case_id, "found": True, "reasoning": reasoning}


def _latest_executor_log(case: Any) -> Dict[str, Any]:
    """Executor results accumulate as a list — one entry per response cycle."""
    logs = getattr(case, "executor_actions", None) or []
    if not logs:
        return {}
    latest = logs[-1]
    return latest if isinstance(latest, dict) else {}


# ---------------------------------------------------------------------------
# Splunk persistent REST handler glue
# ---------------------------------------------------------------------------

try:
    from splunk.persistconn.application import PersistentServerConnectionApplication
except ImportError:                                            # pragma: no cover
    # Allows import (and unit testing of get_reasoning_for_case) outside a
    # running splunkd — e.g. in CI or local pytest runs.
    class PersistentServerConnectionApplication:               # type: ignore
        def __init__(self, *_args: Any, **_kwargs: Any) -> None:
            pass


class ReasoningRestHandler(PersistentServerConnectionApplication):
    """
    Splunk persistent REST handler for ``GET /services/sentinel/reasoning/<case_id>``.

    Registered via restmap.conf, e.g.::

        [script:sentinel_reasoning]
        match                 = /sentinel/reasoning
        script                = reasoning_rest_handler.py
        scripttype            = persist
        handler               = reasoning_rest_handler.ReasoningRestHandler
        requireAuthentication = true
        output_modes          = json
        passPayload           = true
        passSystemAuth        = true
    """

    def __init__(self, command_line: str, command_arg: str) -> None:
        super().__init__()
        self._state_manager: Optional[CaseStateManager] = None

    def _get_state_manager(self) -> CaseStateManager:
        if self._state_manager is None:
            self._state_manager = CaseStateManager()
        return self._state_manager

    def handle(self, in_string: str) -> Dict[str, Any]:
        """
        Entry point invoked by splunkd for each REST request. ``in_string``
        is a JSON-encoded request descriptor (path, method, query, ...).
        Returns a dict matching the PersistentServerConnectionApplication
        response contract: ``{status, headers, payload}``.
        """
        try:
            request = json.loads(in_string) if in_string else {}
        except (TypeError, ValueError):
            request = {}

        method = str(request.get("method") or "GET").upper()
        if method != "GET":
            return self._json_response(405, {"error": "Method not allowed; use GET."})

        case_id = self._extract_case_id(request)
        if not case_id:
            return self._json_response(
                400,
                {"error": "case_id is required: GET /services/sentinel/reasoning/<case_id>"},
            )

        try:
            result = get_reasoning_for_case(case_id, self._get_state_manager())
        except Exception as exc:
            log.exception("Reasoning lookup failed for case=%s", case_id)
            return self._json_response(500, {"error": f"Internal error: {exc}"})

        if not result["found"]:
            return self._json_response(
                404, {"error": f"Case {case_id} not found.", "case_id": case_id}
            )

        return self._json_response(200, result)

    @staticmethod
    def _extract_case_id(request: Dict[str, Any]) -> str:
        """Pull the case_id from the trailing path segment or a query param."""
        path = str(request.get("path") or request.get("rest_path") or "")
        segments = [seg for seg in path.split("/") if seg]
        if segments and segments[-1].lower() != "reasoning":
            return segments[-1]

        for key, value in (request.get("query") or []):
            if key == "case_id":
                return str(value)
        return ""

    @staticmethod
    def _json_response(status: int, payload: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "status":  status,
            "headers": {"Content-Type": "application/json"},
            "payload": json.dumps(payload),
        }
