"""
SENTINEL: Autonomous Agentic SOC Commander
agent_vanguard.py — Triage Agent (codename: Vanguard)

Vanguard is the first agent in the pipeline. It receives an alert from Splunk
Enterprise Security, gathers enrichment context via the MCP Server, submits
the combined evidence package to Foundation-Sec-1.1-8B-Instruct for
classification, calculates a composite risk score, and emits a structured
VanguardDecisionPacket that the orchestrator uses to route the case.

Entry point (called by SentinelOrchestrator):
    result = run(case=case, audit=audit_logger)

Standalone test mode (no live Splunk required):
    python agent_vanguard.py --test
    python agent_vanguard.py --test --scenario ransomware
"""

from __future__ import annotations

import datetime
import json
import logging
import math
import os
import sys
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests

# ---------------------------------------------------------------------------
# Bootstrap path so sibling imports work when run standalone
# ---------------------------------------------------------------------------
_BIN_DIR = Path(__file__).resolve().parent
if str(_BIN_DIR) not in sys.path:
    sys.path.insert(0, str(_BIN_DIR))

from mcp_client         import SplunkMCPClient, MCPError
from audit_logger       import AuditLogger, get_audit_logger
from utils.config_loader import get_config
from utils.state_manager import Case, CaseStatus

log = logging.getLogger("sentinel.vanguard")

# ---------------------------------------------------------------------------
# Fault tolerance
# ---------------------------------------------------------------------------

# Hard wall-clock budget for the Foundation-Sec hosted-model classification
# call. If exceeded, Vanguard falls back to rule-based classification (see
# _fallback_classification) and records a FOUNDATION_SEC_TIMEOUT audit event
# so SOC leadership can track model-availability incidents over time.
_MODEL_CALL_TIMEOUT_SECONDS = 30

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_PROMPT_PATH = (
    Path(__file__).resolve().parent.parent.parent.parent
    / "models" / "prompts" / "vanguard_system_prompt.txt"
)

# ---------------------------------------------------------------------------
# Decision thresholds
# ---------------------------------------------------------------------------

class Decision:
    AUTO_DISMISS  = "AUTO_DISMISS"   # 0–15
    QUEUE_LOW     = "QUEUE_LOW"      # 16–54
    QUEUE_MED     = "QUEUE_MED"      # 55–69
    QUEUE_HIGH    = "QUEUE_HIGH"     # 70–84
    AUTO_ESCALATE = "AUTO_ESCALATE"  # 85–100

_DECISION_THRESHOLDS = [
    (85, Decision.AUTO_ESCALATE),
    (70, Decision.QUEUE_HIGH),
    (55, Decision.QUEUE_MED),
    (16, Decision.QUEUE_LOW),
    (0,  Decision.AUTO_DISMISS),
]

# Human-readable description of what happens next for each routing decision —
# used only to narrate the chain-of-thought conclusion step (explanatory only).
_DECISION_NEXT_ACTIONS: Dict[str, str] = {
    Decision.AUTO_ESCALATE: "Transition case to INVESTIGATING and dispatch to Sherlock for deep investigation.",
    Decision.QUEUE_HIGH:    "Queue case for high-priority analyst review.",
    Decision.QUEUE_MED:     "Queue case for standard-priority analyst review.",
    Decision.QUEUE_LOW:     "Queue case for low-priority analyst review.",
    Decision.AUTO_DISMISS:  "Auto-dismiss as likely benign; close case with no further action.",
}

# ---------------------------------------------------------------------------
# Asset criticality multipliers
# ---------------------------------------------------------------------------

_ASSET_MULTIPLIERS: Dict[str, float] = {
    "CRITICAL": 1.5,
    "HIGH":     1.2,
    "MEDIUM":   1.0,
    "LOW":      0.5,
    "UNKNOWN":  1.0,
}

# ---------------------------------------------------------------------------
# Rule-based fallback classification table
# Each entry: (condition_fn, classification, mitre_tactic, mitre_technique, confidence)
# Evaluated in order; first match wins.
# ---------------------------------------------------------------------------

def _contains(haystack: str, *needles: str) -> bool:
    h = haystack.lower()
    return any(n.lower() in h for n in needles)

_FALLBACK_RULES: List[Tuple] = [
    # (test_fn taking alert_data dict, classification, tactic, technique, base_confidence)
    (
        lambda a: _contains(a.get("process_args", ""), "-enc", "-encodedcommand")
                  and _contains(a.get("process_name", ""), "powershell", "pwsh"),
        "RANSOMWARE_INITIAL_ACCESS", "TA0001", "T1059.001", 0.72,
    ),
    (
        lambda a: _contains(a.get("alert_type", ""), "lateral", "smb", "psexec", "wmi"),
        "LATERAL_MOVEMENT", "TA0008", "T1021.002", 0.65,
    ),
    (
        lambda a: _contains(a.get("process_name", ""), "mimikatz", "lsass", "procdump")
                  or _contains(a.get("alert_type", ""), "credential", "lsass", "sam_dump"),
        "CREDENTIAL_DUMPING", "TA0006", "T1003.001", 0.70,
    ),
    (
        lambda a: _contains(a.get("alert_type", ""), "exfil", "large_transfer", "upload"),
        "DATA_EXFILTRATION", "TA0010", "T1048", 0.62,
    ),
    (
        lambda a: _contains(a.get("alert_type", ""), "insider", "offhours", "after_hours"),
        "INSIDER_THREAT", "TA0009", "T1078", 0.55,
    ),
    (
        lambda a: _contains(a.get("alert_type", ""), "s3", "cloud", "public_bucket"),
        "CLOUD_MISCONFIGURATION", "TA0001", "T1530", 0.68,
    ),
    (
        lambda a: _contains(a.get("alert_type", ""), "ransomware", "encrypt"),
        "RANSOMWARE_INITIAL_ACCESS", "TA0001", "T1486", 0.75,
    ),
    (
        lambda a: _contains(a.get("alert_type", ""), "brute", "spray", "password"),
        "BRUTE_FORCE", "TA0006", "T1110.003", 0.60,
    ),
    (
        lambda a: _contains(a.get("alert_type", ""), "scan", "recon", "enum"),
        "RECONNAISSANCE", "TA0043", "T1595", 0.50,
    ),
]
_FALLBACK_DEFAULT = ("ANOMALOUS_BEHAVIOR", "TA0000", "T0000", 0.40)


# ---------------------------------------------------------------------------
# VanguardDecisionPacket
# ---------------------------------------------------------------------------

@dataclass
class VanguardDecisionPacket:
    case_id:           str
    alert_id:          str
    classification:    str
    confidence:        float
    mitre_tactic:      str
    mitre_technique:   str
    composite_score:   int
    decision:          str
    reasoning:         str
    chain_of_thought:  List[Dict[str, Any]]  = field(default_factory=list)
    key_indicators:    List[str]             = field(default_factory=list)
    false_positive_factors: List[str]        = field(default_factory=list)
    recommended_actions:    List[str]        = field(default_factory=list)
    context:           Dict[str, Any]        = field(default_factory=dict)
    model_used:        str                   = "foundation-sec-1.1-8b-instruct"
    model_available:   bool                  = True
    timestamp:         str                   = field(
        default_factory=lambda: datetime.datetime.utcnow().isoformat() + "Z"
    )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)


# ---------------------------------------------------------------------------
# VanguardAgent
# ---------------------------------------------------------------------------

class VanguardAgent:
    """
    Triage agent that classifies ES notable events and produces a composite
    risk score and routing decision.

    Instantiate once and call run() for each case.
    """

    def __init__(
        self,
        mcp_client: Optional[SplunkMCPClient] = None,
        audit: Optional[AuditLogger] = None,
    ) -> None:
        self._mcp   = mcp_client or SplunkMCPClient(agent_name="vanguard")
        self._audit = audit or get_audit_logger("vanguard")
        self._cfg   = get_config()
        self._system_prompt = self._load_system_prompt()

        # Hosted model endpoint (resolved lazily from config)
        self._model_endpoint: Optional[str] = None
        self._model_token:    Optional[str] = None

        log.info("VanguardAgent initialised")

    # ------------------------------------------------------------------
    # Orchestrator entry point
    # ------------------------------------------------------------------

    def run(self, case: Case, audit: Optional[AuditLogger] = None) -> Dict[str, Any]:
        """
        Main entry point called by SentinelOrchestrator._run_vanguard().

        Returns a dict with keys: success, decision (VanguardDecisionPacket dict),
        risk_score, classification, mitre_tactic, mitre_technique.
        """
        effective_audit = audit or self._audit
        t_start = time.time()

        log.info("Vanguard processing case %s (alert=%s type=%s)",
                 case.case_id, case.alert_id, case.alert_type)

        try:
            # 1. Build raw alert data from the Case object
            alert_data = self._case_to_alert_data(case)

            # 2. Gather enrichment context via MCP
            context = self._gather_context(alert_data, case)

            # 3. Classify via Foundation-Sec (with rule-based fallback)
            classification = self._classify_alert(
                alert_data, context, case_id=case.case_id, audit=effective_audit,
            )

            # 4. Calculate composite risk score
            score = self._calculate_composite_score(
                base_confidence = classification["confidence"],
                asset_context   = context.get("asset", {}),
                alert_time      = alert_data.get("time", ""),
                historical      = context.get("historical", {}),
            )

            # 5. Routing decision
            decision = self._make_decision(score)

            # 5b. Build an explainable, step-by-step chain-of-thought trace.
            # This is purely narrative — it re-derives and explains the same
            # signals _calculate_composite_score/_make_decision already used,
            # and never influences the score or decision itself.
            model_result = dict(classification)
            model_result["composite_score"] = score
            model_result["decision"]        = decision
            chain_of_thought = self.generate_chain_of_thought(alert_data, context, model_result)
            reasoning_summary = (
                self._summarize_chain_of_thought(chain_of_thought)
                or classification.get("reasoning", "")
            )

            # 6. Build decision packet
            packet = VanguardDecisionPacket(
                case_id             = case.case_id,
                alert_id            = case.alert_id,
                classification      = classification["classification"],
                confidence          = classification["confidence"],
                mitre_tactic        = classification["mitre_tactic"],
                mitre_technique     = classification["mitre_technique"],
                composite_score     = score,
                decision            = decision,
                reasoning           = reasoning_summary,
                chain_of_thought    = chain_of_thought,
                key_indicators      = classification.get("key_indicators", []),
                false_positive_factors = classification.get("false_positive_factors", []),
                recommended_actions = classification.get("recommended_actions", []),
                model_used          = classification.get("model_used",
                                       "foundation-sec-1.1-8b-instruct"),
                model_available     = classification.get("model_available", True),
                context = {
                    "asset_criticality":      context.get("asset", {}).get("criticality_label", "UNKNOWN"),
                    "asset_owner":            context.get("asset", {}).get("owner", ""),
                    "environment":            context.get("asset", {}).get("environment", ""),
                    "historical_notables":    context.get("historical", {}).get("same_host_notables_30d", 0),
                    "same_rule_fp_rate_90d":  context.get("historical", {}).get("same_rule_fp_rate_90d", 0.0),
                    "user_behavior_anomaly":  context.get("user", {}).get("user_risk_score_current", 0),
                    "impossible_travel":      context.get("user", {}).get("impossible_travel_detected", False),
                    "threat_intel_verdict":   context.get("threat_intel", {}).get("ioc_verdict", "not_checked"),
                },
            )

            latency_ms = int((time.time() - t_start) * 1000)

            # 7. Audit log
            effective_audit.log_decision(
                case_id        = case.case_id,
                decision_type  = decision,
                confidence     = packet.confidence,
                input_context  = {
                    "alert_type":  case.alert_type,
                    "alert_id":    case.alert_id,
                    "host":        case.affected_host,
                    "user":        case.affected_user,
                    "raw_score":   case.risk_score,
                },
                output_decision = {
                    "composite_score":  score,
                    "classification":   packet.classification,
                    "decision":         decision,
                    "mitre_tactic":     packet.mitre_tactic,
                    "mitre_technique":  packet.mitre_technique,
                },
                reasoning      = packet.reasoning,
                mitre_tactic   = packet.mitre_tactic,
                mitre_technique= packet.mitre_technique,
                model_used     = packet.model_used,
                latency_ms     = latency_ms,
                metadata       = {"chain_of_thought": chain_of_thought},
            )

            # 7b. Dedicated chain-of-thought audit record — keeps the full
            # explainability trail independently queryable for SOC audit/compliance.
            effective_audit.log_chain_of_thought(
                case_id    = case.case_id,
                agent_name = "vanguard",
                chain      = chain_of_thought,
            )

            log.info(
                "Vanguard decision: case=%s score=%d decision=%s classification=%s confidence=%.2f",
                case.case_id, score, decision, packet.classification, packet.confidence,
            )

            return {
                "success":        True,
                "decision":       packet.to_dict(),
                "risk_score":     score,
                "classification": packet.classification,
                "mitre_tactic":   packet.mitre_tactic,
                "mitre_technique":packet.mitre_technique,
            }

        except Exception as exc:
            latency_ms = int((time.time() - t_start) * 1000)
            log.error("Vanguard failed on case %s: %s", case.case_id, exc, exc_info=True)
            effective_audit.log_error(
                case_id    = case.case_id,
                error_type = type(exc).__name__,
                message    = str(exc),
                exc        = exc,
                context    = {"stage": "vanguard", "latency_ms": latency_ms},
            )
            return {"success": False, "error": str(exc)}

    # ------------------------------------------------------------------
    # Context gathering
    # ------------------------------------------------------------------

    def _gather_context(
        self, alert_data: Dict[str, Any], case: Case
    ) -> Dict[str, Any]:
        """
        Fan-out MCP calls to collect asset, user, and historical context.
        Each call degrades gracefully: on failure, an empty dict is returned
        so the pipeline continues with reduced context rather than failing.
        """
        ctx: Dict[str, Any] = {
            "asset":       {},
            "user":        {},
            "historical":  {},
            "threat_intel": {},
        }

        host = case.affected_host or alert_data.get("hostname", "")
        user = case.affected_user or alert_data.get("username", "")

        # Asset context
        if host:
            try:
                result = self._mcp.get_asset_context(host)
                ctx["asset"] = result
                log.debug("Asset context fetched for %s: criticality=%s",
                          host, result.get("criticality_label"))
            except MCPError as exc:
                log.warning("Asset context unavailable for %s: %s", host, exc)

        # User activity / UEBA
        if user:
            try:
                result = self._mcp.get_user_activity(
                    user, earliest="-24h", include_baseline=True, max_events=50
                )
                ctx["user"] = {
                    "impossible_travel_detected": result.get("impossible_travel_detected", False),
                    "user_risk_score_current":    result.get("risk_score_current", 0),
                    "typical_login_hours":        result.get("baseline", {}).get("typical_login_hours", ""),
                    "typical_locations":          result.get("baseline", {}).get("typical_locations", []),
                    "recent_failed_logins":       sum(
                        1 for e in result.get("events", [])
                        if e.get("result") == "failure"
                        and e.get("event_type") == "authentication"
                    ),
                }
                log.debug("User context fetched for %s: risk=%s travel=%s",
                          user, ctx["user"]["user_risk_score_current"],
                          ctx["user"]["impossible_travel_detected"])
            except MCPError as exc:
                log.warning("User context unavailable for %s: %s", user, exc)

        # Historical ES notables for same host/user
        try:
            host_notables = 0
            user_notables = 0
            if host:
                r = self._mcp.query_es_notable(host=host, earliest="-30d", limit=100)
                host_notables = r.get("total_count", len(r.get("notables", [])))
            if user:
                r = self._mcp.query_es_notable(user=user, earliest="-30d", limit=100)
                user_notables = r.get("total_count", len(r.get("notables", [])))

            # Estimate FP rate: fraction of prior notables that were auto-closed
            # In production this would query the sentinel_metrics index via MCP.
            # For now, use a conservative default.
            ctx["historical"] = {
                "same_host_notables_30d":  host_notables,
                "same_user_notables_30d":  user_notables,
                "same_rule_fp_rate_90d":   0.0,
                "same_ioc_seen_before":    False,
                "prior_confirmed_incidents": 0,
            }
        except MCPError as exc:
            log.warning("Historical context unavailable: %s", exc)

        # Threat intelligence for any network IOC in the alert
        dest_ip = alert_data.get("network_dest", "")
        if dest_ip and _looks_like_external_ip(dest_ip):
            try:
                result = self._mcp.enrich_threat_intel(dest_ip, ioc_type="ip")
                ctx["threat_intel"] = {
                    "ioc_verdict":     result.get("verdict", "unknown"),
                    "vt_detections":   (
                        f"{result.get('virustotal', {}).get('detections', 0)}/"
                        f"{result.get('virustotal', {}).get('total_engines', 0)}"
                    ),
                    "malware_families": result.get("malware_families", []),
                    "abuseipdb_score":  result.get("abuseipdb", {}).get(
                        "abuse_confidence_score", 0
                    ),
                }
                log.debug("Threat intel for %s: verdict=%s",
                          dest_ip, ctx["threat_intel"]["ioc_verdict"])
            except MCPError as exc:
                log.warning("Threat intel unavailable for %s: %s", dest_ip, exc)

        return ctx

    # ------------------------------------------------------------------
    # Foundation-Sec classification
    # ------------------------------------------------------------------

    def _classify_alert(
        self,
        alert_data: Dict[str, Any],
        context: Dict[str, Any],
        case_id: str = "",
        audit: Optional[AuditLogger] = None,
    ) -> Dict[str, Any]:
        """
        Submit the enriched alert package to Foundation-Sec for classification.
        Falls back to rule-based classification if the model is unavailable —
        including when the model call exceeds its _MODEL_CALL_TIMEOUT_SECONDS
        budget, in which case the timeout is also recorded to sentinel_audit
        with full context for SOC visibility into model-availability incidents.
        """
        model_input = self._build_model_input(alert_data, context)

        # Try hosted model first
        t_call = time.time()
        try:
            result = self._call_foundation_sec(model_input)
            result["model_available"] = True
            result["model_used"]      = "foundation-sec-1.1-8b-instruct"
            return result
        except (requests.exceptions.Timeout, requests.exceptions.ConnectTimeout,
                requests.exceptions.ReadTimeout) as exc:
            latency_ms = int((time.time() - t_call) * 1000)
            log.warning(
                "Foundation-Sec call timed out after %dms (budget=%ds): %s; "
                "falling back to rule-based classification.",
                latency_ms, _MODEL_CALL_TIMEOUT_SECONDS, exc,
            )
            (audit or self._audit).log_error(
                case_id    = case_id or alert_data.get("case_id", ""),
                error_type = "FOUNDATION_SEC_TIMEOUT",
                message    = (
                    f"Foundation-Sec model call exceeded "
                    f"{_MODEL_CALL_TIMEOUT_SECONDS}s timeout after {latency_ms}ms"
                ),
                exc        = exc,
                context    = {
                    "stage":            "vanguard_classification",
                    "endpoint":         self._get_model_endpoint(),
                    "model_used":       "foundation-sec-1.1-8b-instruct",
                    "timeout_seconds":  _MODEL_CALL_TIMEOUT_SECONDS,
                    "elapsed_ms":       latency_ms,
                    "alert_type":       alert_data.get("alert_type", "UNKNOWN"),
                    "host":             alert_data.get("host", ""),
                    "fallback":         "rule_based_classification",
                },
            )
        except Exception as exc:
            log.warning(
                "Foundation-Sec unavailable (%s); falling back to rule-based classification.",
                exc,
            )

        # Fallback
        result = self._fallback_classification(alert_data, context)
        result["model_available"] = False
        result["model_used"]      = "rule_based_fallback"
        return result

    def _call_foundation_sec(self, model_input: Dict[str, Any]) -> Dict[str, Any]:
        """
        POST to the Splunk AI Toolkit Hosted Models REST endpoint for
        Foundation-Sec-1.1-8B-Instruct.

        Endpoint: POST /services/ml/models/foundation-sec-1.1-8b-instruct/predict
        Auth:     Splunk API token (from config)
        Body:     { "inputs": [{ "role": "system", "content": <prompt> },
                               { "role": "user",   "content": <json_str> }] }
        Response: { "outputs": "<json string>" }
        """
        endpoint = self._get_model_endpoint()
        token    = self._get_model_token()

        user_content = json.dumps(model_input, indent=2)

        payload = {
            "inputs": [
                {"role": "system", "content": self._system_prompt},
                {"role": "user",   "content": user_content},
            ],
            "parameters": {
                "max_new_tokens":  1024,
                "temperature":     0.1,    # Low temperature for deterministic security decisions
                "top_p":           0.9,
                "do_sample":       False,
            },
        }

        headers = {
            "Authorization": f"Splunk {token}",
            "Content-Type":  "application/json",
        }

        log.debug("Calling Foundation-Sec endpoint: %s", endpoint)
        t_start = time.time()

        resp = requests.post(
            endpoint,
            json=payload,
            headers=headers,
            verify=self._cfg.get_bool("general", "verify_ssl", default=False),
            timeout=_MODEL_CALL_TIMEOUT_SECONDS,
        )

        latency_ms = int((time.time() - t_start) * 1000)
        log.debug("Foundation-Sec responded in %dms (HTTP %d)", latency_ms, resp.status_code)

        if resp.status_code == 401:
            raise RuntimeError("Foundation-Sec authentication failed — check hosted model token.")
        if resp.status_code == 404:
            raise RuntimeError(
                "Foundation-Sec endpoint not found. "
                "Verify Splunk AI Toolkit is installed and the model name is correct."
            )
        if not resp.ok:
            raise RuntimeError(
                f"Foundation-Sec returned HTTP {resp.status_code}: {resp.text[:256]}"
            )

        raw = resp.json()

        # The AI Toolkit wraps the model output in a 'outputs' or 'predictions' field
        raw_output = (
            raw.get("outputs")
            or raw.get("predictions", [{}])[0].get("output", "")
            or ""
        )

        # Strip any accidental markdown fences the model may have added
        raw_output = raw_output.strip()
        if raw_output.startswith("```"):
            raw_output = raw_output.split("```")[1]
            if raw_output.startswith("json"):
                raw_output = raw_output[4:]

        try:
            parsed = json.loads(raw_output)
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                f"Foundation-Sec output is not valid JSON: {exc}\n"
                f"Raw output (first 500 chars): {raw_output[:500]}"
            ) from exc

        return self._validate_model_output(parsed)

    def _validate_model_output(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate and normalise the model's JSON output.
        Fills in defaults for any missing fields rather than raising,
        so a partially valid response still produces a usable packet.
        """
        _VALID_CLASSIFICATIONS = {
            "RANSOMWARE_INITIAL_ACCESS", "RANSOMWARE_ENCRYPTION", "LATERAL_MOVEMENT",
            "CREDENTIAL_DUMPING", "PRIVILEGE_ESCALATION", "PERSISTENCE",
            "COMMAND_AND_CONTROL", "DATA_EXFILTRATION", "INSIDER_THREAT",
            "SUPPLY_CHAIN_ATTACK", "CLOUD_MISCONFIGURATION", "CLOUD_INTRUSION",
            "PHISHING", "EXPLOITATION", "DEFENSE_EVASION", "RECONNAISSANCE",
            "BRUTE_FORCE", "ANOMALOUS_BEHAVIOR", "FALSE_POSITIVE", "UNKNOWN",
        }
        _VALID_PRIORITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}

        classification = raw.get("classification", "UNKNOWN").upper()
        if classification not in _VALID_CLASSIFICATIONS:
            log.warning("Model returned unknown classification '%s'; defaulting to UNKNOWN",
                        classification)
            classification = "UNKNOWN"

        priority = raw.get("recommended_priority", "MEDIUM").upper()
        if priority not in _VALID_PRIORITIES:
            priority = "MEDIUM"

        # Confidence: clamp to [0.0, 1.0]
        try:
            confidence = max(0.0, min(1.0, float(raw.get("confidence", 0.5))))
        except (ValueError, TypeError):
            confidence = 0.5

        # MITRE IDs: basic format validation
        tactic    = raw.get("mitre_tactic", "TA0000")
        technique = raw.get("mitre_technique", "T0000")
        if not str(tactic).startswith("TA"):
            tactic = "TA0000"
        if not str(technique).startswith("T"):
            technique = "T0000"

        return {
            "classification":         classification,
            "confidence":             round(confidence, 4),
            "mitre_tactic":           tactic,
            "mitre_technique":        technique,
            "recommended_priority":   priority,
            "reasoning":              str(raw.get("reasoning", ""))[:2048],
            "key_indicators":         list(raw.get("key_indicators", [])),
            "false_positive_factors": list(raw.get("false_positive_factors", [])),
            "recommended_actions":    list(raw.get("recommended_actions", [])),
            "model_notes":            str(raw.get("model_notes", "")),
        }

    def _fallback_classification(
        self,
        alert_data: Dict[str, Any],
        context: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Rule-based classification used when Foundation-Sec is unavailable.
        Evaluates ordered rules against the alert_data dict.
        """
        for test_fn, classification, tactic, technique, confidence in _FALLBACK_RULES:
            try:
                if test_fn(alert_data):
                    # Boost confidence if threat intel confirms the IOC
                    ti_verdict = context.get("threat_intel", {}).get("ioc_verdict", "unknown")
                    if ti_verdict == "malicious":
                        confidence = min(1.0, confidence + 0.15)
                    elif ti_verdict == "clean":
                        confidence = max(0.0, confidence - 0.20)

                    log.debug("Fallback rule matched: %s (confidence=%.2f)",
                              classification, confidence)
                    return {
                        "classification":         classification,
                        "confidence":             round(confidence, 4),
                        "mitre_tactic":           tactic,
                        "mitre_technique":        technique,
                        "recommended_priority":   _confidence_to_priority(confidence),
                        "reasoning":              (
                            f"Rule-based fallback classification: matched '{classification}' "
                            f"pattern. Foundation-Sec model was unavailable. "
                            f"Manual review recommended."
                        ),
                        "key_indicators":         [
                            f"alert_type={alert_data.get('alert_type', 'UNKNOWN')}",
                            f"process={alert_data.get('process_name', 'unknown')}",
                        ],
                        "false_positive_factors": ["Model unavailable; lower confidence than usual."],
                        "recommended_actions":    ["Manual analyst review required"],
                    }
            except Exception:
                continue

        cls, tactic, technique, confidence = _FALLBACK_DEFAULT
        return {
            "classification":         cls,
            "confidence":             confidence,
            "mitre_tactic":           tactic,
            "mitre_technique":        technique,
            "recommended_priority":   "LOW",
            "reasoning":              "No rule-based pattern matched. Anomalous behavior flagged for review.",
            "key_indicators":         [],
            "false_positive_factors": ["No specific pattern matched; broad catch-all classification."],
            "recommended_actions":    ["Manual analyst review required"],
        }

    # ------------------------------------------------------------------
    # Composite risk scoring
    # ------------------------------------------------------------------

    def _calculate_composite_score(
        self,
        base_confidence: float,
        asset_context:   Dict[str, Any],
        alert_time:      str,
        historical:      Dict[str, Any],
    ) -> int:
        """
        Composite score formula:
            base_score × asset_mult × temporal_mult × historical_mult
        Capped at 100, floored at 1.
        """
        base_score = base_confidence * 100.0

        # --- Asset criticality multiplier ---
        criticality_label = str(
            asset_context.get("criticality_label", "MEDIUM")
        ).upper()
        asset_mult = _ASSET_MULTIPLIERS.get(criticality_label, 1.0)

        # Boost further if production environment
        if asset_context.get("environment", "").lower() == "production":
            asset_mult = min(asset_mult * 1.05, 1.5)

        # --- Temporal risk multiplier ---
        temporal_mult = self._temporal_multiplier(alert_time)

        # --- Historical pattern multiplier ---
        fp_rate      = float(historical.get("same_rule_fp_rate_90d", 0.0))
        prior_incs   = int(historical.get("prior_confirmed_incidents", 0))
        host_notable_count = int(historical.get("same_host_notables_30d", 0))

        if fp_rate >= 0.7:
            # Rule fires false positives most of the time — penalise heavily
            historical_mult = 0.8
        elif prior_incs > 0:
            # Host has prior confirmed incidents — escalate
            historical_mult = 1.2
        elif host_notable_count == 0:
            # First-time pattern for this host — slightly elevated (new = unknown risk)
            historical_mult = 1.1
        else:
            historical_mult = 1.0

        raw_score = base_score * asset_mult * temporal_mult * historical_mult
        final     = max(1, min(100, math.ceil(raw_score)))

        log.debug(
            "Composite score: base=%.1f asset_mult=%.2f temporal_mult=%.2f "
            "historical_mult=%.2f → raw=%.1f → final=%d",
            base_score, asset_mult, temporal_mult, historical_mult, raw_score, final,
        )
        return final

    @staticmethod
    def _temporal_multiplier(alert_time: str) -> float:
        """
        1.3× for off-hours/weekends, 1.15× for early morning (midnight–6 AM),
        1.0× for normal business hours.
        """
        try:
            if "T" in alert_time:
                dt = datetime.datetime.fromisoformat(alert_time.replace("Z", "+00:00"))
            else:
                dt = datetime.datetime.utcnow()
            hour = dt.hour
            dow  = dt.weekday()   # 0=Monday, 6=Sunday

            if dow >= 5:           # Weekend
                return 1.3
            if hour < 6 or hour >= 22:   # Midnight–6 AM or 10 PM–midnight
                return 1.3
            if 6 <= hour < 8:      # Early morning
                return 1.15
        except (ValueError, AttributeError):
            pass
        return 1.0

    # ------------------------------------------------------------------
    # Decision routing
    # ------------------------------------------------------------------

    @staticmethod
    def _make_decision(composite_score: int) -> str:
        for threshold, decision in _DECISION_THRESHOLDS:
            if composite_score >= threshold:
                return decision
        return Decision.AUTO_DISMISS

    # ------------------------------------------------------------------
    # Explainability — Chain of Thought
    # ------------------------------------------------------------------

    def generate_chain_of_thought(
        self,
        alert_data:   Dict[str, Any],
        context:      Dict[str, Any],
        model_result: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """
        Build a step-by-step "Chain of Thought" trace explaining how Vanguard
        moved from raw alert -> classification -> composite score -> routing
        decision.

        This is purely explanatory — it narrates the same signals that
        _calculate_composite_score / _make_decision already computed (asset
        criticality, temporal risk, historical pattern, model confidence) so
        every decision is auditable. It never alters the score or decision.

        ``model_result`` is the classification dict enriched with the final
        ``composite_score`` and ``decision`` (see run()).

        Returns a list of step dicts, each either:
          {step, agent, observation, inference}             — an evidentiary step
          {step, agent, conclusion, action}                 — the final routing step
        """
        chain: List[Dict[str, Any]] = []

        def _step(**fields: Any) -> None:
            chain.append({"step": len(chain) + 1, "agent": "vanguard", **fields})

        # 1. The triggering alert itself
        host = alert_data.get("hostname") or alert_data.get("host") or "unknown host"
        proc = alert_data.get("process_name", "")
        args = str(alert_data.get("process_args", ""))[:80]
        observation = f"Alert: {alert_data.get('alert_type', 'UNKNOWN')} on {host}"
        if proc:
            observation += f" — {proc}" + (f" {args}" if args else "")
        _step(
            observation=observation,
            inference="Establishes the raw signal Vanguard must classify and score.",
        )

        # 2. Classification result (Foundation-Sec model or rule-based fallback)
        confidence     = float(model_result.get("confidence", 0.0))
        model_used     = model_result.get("model_used", "unknown")
        classification = model_result.get("classification", "UNKNOWN")
        source = "Foundation-Sec" if model_result.get("model_available") else "Rule-based fallback"
        _step(
            observation=(
                f"{source} classification: {classification} "
                f"with {confidence:.0%} confidence (model_used={model_used})"
            ),
            inference=(
                f"Confidence of {confidence:.0%} sets the base score "
                f"({confidence:.2f} x 100 = {confidence * 100:.0f}) before "
                f"asset/temporal/historical multipliers are applied."
            ),
        )

        # 3. Asset criticality multiplier
        asset = context.get("asset", {})
        crit  = str(asset.get("criticality_label", "UNKNOWN")).upper()
        asset_mult = _ASSET_MULTIPLIERS.get(crit, 1.0)
        asset_desc = host
        if asset.get("owner"):
            asset_desc += f" (owner: {asset['owner']})"
        if asset_mult > 1.0:
            asset_inference = f"{crit} assets carry a {asset_mult:.2f}x multiplier, raising the score toward escalation."
        elif asset_mult < 1.0:
            asset_inference = f"{crit} assets carry a reduced {asset_mult:.2f}x multiplier, lowering escalation likelihood."
        else:
            asset_inference = f"{crit} assets carry a neutral {asset_mult:.2f}x multiplier — no adjustment."
        _step(
            observation=f"Asset {asset_desc} has criticality {crit}",
            inference=asset_inference,
        )

        # 4. Temporal risk multiplier
        alert_time    = alert_data.get("time", "")
        temporal_mult = self._temporal_multiplier(alert_time)
        when = alert_time or "time unavailable"
        if temporal_mult > 1.0:
            temporal_observation = f"Execution time {when} falls in an off-hours / high-risk window"
        else:
            temporal_observation = f"Execution time {when} falls within normal business hours"
        _step(
            observation=temporal_observation,
            inference=f"Temporal risk multiplier of {temporal_mult:.2f}x applied to the composite score.",
        )

        # 5. Historical pattern
        historical    = context.get("historical", {})
        fp_rate       = float(historical.get("same_rule_fp_rate_90d", 0.0))
        prior_incs    = int(historical.get("prior_confirmed_incidents", 0))
        host_notables = int(historical.get("same_host_notables_30d", 0))
        if fp_rate >= 0.7:
            hist_observation = f"This rule has a {fp_rate:.0%} false-positive rate over the last 90 days"
            hist_inference   = "High historical FP rate applies a 0.80x penalty multiplier."
        elif prior_incs > 0:
            hist_observation = f"{prior_incs} prior confirmed incident(s) recorded for this host"
            hist_inference   = "Prior confirmed incidents apply a 1.20x escalation multiplier."
        elif host_notables == 0:
            hist_observation = "No prior notables recorded for this host in the last 30 days"
            hist_inference   = "First-time pattern for this host applies a slight 1.10x multiplier (unknown risk, treated cautiously)."
        else:
            hist_observation = f"{host_notables} prior notable(s) for this host with no elevated false-positive rate"
            hist_inference   = "Neutral historical pattern — no multiplier adjustment (1.00x)."
        _step(observation=hist_observation, inference=hist_inference)

        # 6. Conclusion — final composite score vs. decision threshold
        score     = model_result.get("composite_score")
        decision  = model_result.get("decision", "")
        threshold = next((t for t, d in _DECISION_THRESHOLDS if d == decision), None)
        if decision == Decision.AUTO_ESCALATE:
            conclusion = f"Composite score {score} exceeds the AUTO_ESCALATE threshold of {threshold}"
        elif threshold is not None:
            conclusion = f"Composite score {score} falls in the {decision} band (threshold {threshold})"
        else:
            conclusion = f"Composite score {score} maps to decision {decision}"
        action = _DECISION_NEXT_ACTIONS.get(decision, "Route the case according to Vanguard's decision.")
        chain.append({
            "step":       len(chain) + 1,
            "agent":      "vanguard",
            "conclusion": conclusion,
            "action":     action,
        })

        return chain

    @staticmethod
    def _summarize_chain_of_thought(chain: List[Dict[str, Any]]) -> str:
        """
        Collapse a chain-of-thought trace into a single human-readable
        ``reasoning`` summary string (used to populate VanguardDecisionPacket.reasoning).
        """
        if not chain:
            return ""
        inferences = [entry["inference"] for entry in chain if entry.get("inference")]
        conclusion = next(
            (entry["conclusion"] for entry in reversed(chain) if entry.get("conclusion")), ""
        )
        summary = " ".join(inferences)
        if conclusion:
            summary = f"{summary} {conclusion}.".strip()
        return summary

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _case_to_alert_data(self, case: Case) -> Dict[str, Any]:
        """Extract a flat alert_data dict from the Case object."""
        vanguard_raw = case.vanguard_decision or {}
        return {
            "alert_id":      case.alert_id,
            "alert_type":    case.alert_type,
            "alert_name":    vanguard_raw.get("alert_name", case.alert_type),
            "severity":      vanguard_raw.get("severity", "medium"),
            "time":          vanguard_raw.get("time", datetime.datetime.utcnow().isoformat() + "Z"),
            "raw_risk_score":case.risk_score,
            "hostname":      case.affected_host,
            "username":      case.affected_user,
            "process_name":  vanguard_raw.get("process_name", ""),
            "process_path":  vanguard_raw.get("process_path", ""),
            "process_args":  vanguard_raw.get("process_args", ""),
            "parent_process":vanguard_raw.get("parent_process", ""),
            "process_hash":  vanguard_raw.get("process_hash", ""),
            "network_dest":  vanguard_raw.get("network_dest", ""),
            "network_ports": vanguard_raw.get("network_ports", ""),
            "file_events":   vanguard_raw.get("file_events", ""),
        }

    def _build_model_input(
        self,
        alert_data: Dict[str, Any],
        context: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Assemble the structured JSON that is sent to Foundation-Sec."""
        asset  = context.get("asset",   {})
        user   = context.get("user",    {})
        hist   = context.get("historical", {})
        ti     = context.get("threat_intel", {})

        return {
            "alert": {
                "alert_id":       alert_data.get("alert_id", ""),
                "alert_name":     alert_data.get("alert_name", ""),
                "alert_type":     alert_data.get("alert_type", ""),
                "severity":       alert_data.get("severity", "medium"),
                "time":           alert_data.get("time", ""),
                "raw_risk_score": alert_data.get("raw_risk_score", 50),
            },
            "host_telemetry": {
                "hostname":       alert_data.get("hostname", ""),
                "ip_address":     asset.get("ip_addresses", [""])[0] if asset.get("ip_addresses") else "",
                "process_name":   alert_data.get("process_name", ""),
                "process_path":   alert_data.get("process_path", ""),
                "process_args":   alert_data.get("process_args", ""),
                "parent_process": alert_data.get("parent_process", ""),
                "process_hash":   alert_data.get("process_hash", ""),
                "network_dest":   alert_data.get("network_dest", ""),
                "network_ports":  alert_data.get("network_ports", ""),
                "file_events":    alert_data.get("file_events", ""),
            },
            "asset_context": {
                "criticality_label":    asset.get("criticality_label", "MEDIUM"),
                "criticality_score":    asset.get("criticality_score", 1.0),
                "owner":                asset.get("owner", ""),
                "environment":          asset.get("environment", "unknown"),
                "business_unit":        asset.get("business_unit", ""),
                "open_vulnerabilities": asset.get("open_vulnerabilities", 0),
                "max_cvss":             asset.get("max_cvss", 0.0),
            },
            "user_context": {
                "username":                   alert_data.get("username", ""),
                "is_privileged":              user.get("is_privileged", False),
                "typical_login_hours":        user.get("typical_login_hours", ""),
                "typical_locations":          user.get("typical_locations", []),
                "impossible_travel_detected": user.get("impossible_travel_detected", False),
                "user_risk_score_current":    user.get("user_risk_score_current", 0),
                "recent_failed_logins":       user.get("recent_failed_logins", 0),
            },
            "historical_context": {
                "same_host_notables_30d":    hist.get("same_host_notables_30d", 0),
                "same_user_notables_30d":    hist.get("same_user_notables_30d", 0),
                "same_rule_fp_rate_90d":     hist.get("same_rule_fp_rate_90d", 0.0),
                "same_ioc_seen_before":      hist.get("same_ioc_seen_before", False),
                "prior_confirmed_incidents": hist.get("prior_confirmed_incidents", 0),
            },
            "threat_intel": {
                "ioc_verdict":      ti.get("ioc_verdict", "not_checked"),
                "vt_detections":    ti.get("vt_detections", "0/0"),
                "malware_families": ti.get("malware_families", []),
                "abuseipdb_score":  ti.get("abuseipdb_score", 0),
            },
        }

    def _load_system_prompt(self) -> str:
        """Load the system prompt from models/prompts/vanguard_system_prompt.txt."""
        if _PROMPT_PATH.exists():
            text = _PROMPT_PATH.read_text(encoding="utf-8").strip()
            log.debug("Loaded system prompt (%d chars) from %s", len(text), _PROMPT_PATH)
            return text
        log.warning("System prompt not found at %s; using minimal inline prompt.", _PROMPT_PATH)
        return (
            "You are a security alert classification system. "
            "Analyze the provided alert JSON and return a JSON object with keys: "
            "classification, confidence, mitre_tactic, mitre_technique, "
            "recommended_priority, reasoning, key_indicators, "
            "false_positive_factors, recommended_actions, model_notes."
        )

    def _get_model_endpoint(self) -> str:
        if self._model_endpoint:
            return self._model_endpoint

        host   = self._cfg.get("general", "splunk_host", default="localhost")
        port   = self._cfg.get_int("general", "splunk_port", default=8089)
        scheme = self._cfg.get("general", "splunk_scheme", default="https")
        ep_override = self._cfg.get("hosted_models", "foundation_sec_endpoint", default="")

        if ep_override:
            self._model_endpoint = ep_override
        else:
            self._model_endpoint = (
                f"{scheme}://{host}:{port}"
                "/services/ml/models/foundation-sec-1.1-8b-instruct/predict"
            )

        return self._model_endpoint

    def _get_model_token(self) -> str:
        if self._model_token:
            return self._model_token
        self._model_token = (
            os.environ.get("SENTINEL_HOSTED_MODEL_TOKEN")
            or self._cfg.get("hosted_models", "api_token", default="")
            or self._cfg.get("splunk", "api_token", default="")
        )
        return self._model_token


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _confidence_to_priority(confidence: float) -> str:
    if confidence >= 0.85:
        return "CRITICAL"
    if confidence >= 0.70:
        return "HIGH"
    if confidence >= 0.50:
        return "MEDIUM"
    return "LOW"


_RFC_1918 = [
    ("10.",),
    ("192.168.",),
    ("172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.",
     "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.",
     "172.28.", "172.29.", "172.30.", "172.31."),
]

def _looks_like_external_ip(value: str) -> bool:
    """Return True if value looks like a routable IPv4 address (not RFC 1918 / localhost)."""
    v = value.strip()
    if not v or v.startswith("127.") or v == "::1":
        return False
    for group in _RFC_1918:
        if any(v.startswith(pfx) for pfx in group):
            return False
    # Basic IPv4 check
    parts = v.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return True
    return False


# ---------------------------------------------------------------------------
# Module entry point (orchestrator compatibility)
# ---------------------------------------------------------------------------

def run(case: Case, audit: Optional[AuditLogger] = None, **_: Any) -> Dict[str, Any]:
    """Module-level entry point called by SentinelOrchestrator via _AgentProxy."""
    agent = VanguardAgent(audit=audit)
    return agent.run(case=case, audit=audit)
