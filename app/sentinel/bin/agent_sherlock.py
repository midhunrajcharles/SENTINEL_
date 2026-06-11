"""
SENTINEL: Autonomous Agentic SOC Commander
agent_sherlock.py — The Investigation Agent

SherlockAgent performs deep-dive incident investigation after Vanguard triage.
It runs a structured 5-phase investigation protocol, uses the Splunk AI Assistant
(SAIA) for adaptive NL→SPL generation (validated with MCP validate_spl before
execution), and produces a SherlockInvestigationReport consumed by the Executor
and Sage agents.

Phases:
  A — Host Context      (asset baseline, logon history, installed software)
  B — Timeline          (event sequencing, process chains, network, file changes)
  C — Lateral Movement  (SMB/RDP/SSH pivots, remote auth, flow patterns)
  D — Identity          (baseline deviation, impossible travel, privilege escalation)
  E — Threat Intel      (IOC enrichment, campaign attribution, TTP mapping)

Public API:
  SherlockAgent.run(case, audit) → dict
  SherlockAgent.generate_investigation_query(nl_description, context) → str
  SherlockAgent.calculate_blast_radius(investigation_results) → dict

SAIA endpoint:  POST /services/assistant/v1/generate
Model endpoint: POST /services/ml/models/foundation-sec-1.1-8b-instruct/predict
Fallback:       keyword-matched SPL templates + rule-based synthesis

Dependencies: requests, standard library
"""

from __future__ import annotations

import concurrent.futures
import json
import logging
import os
import re
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

_BIN_DIR = Path(__file__).resolve().parent
if str(_BIN_DIR) not in sys.path:
    sys.path.insert(0, str(_BIN_DIR))

from audit_logger import AuditLogger, get_audit_logger
from mcp_client import SplunkMCPClient, MCPError
from utils.config_loader import get_config

log = logging.getLogger("sentinel.sherlock")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_AGENT_NAME      = "sherlock"
_ENV_SAIA_TOKEN  = "SENTINEL_SAIA_TOKEN"
_ENV_MODEL_TOKEN = "SENTINEL_HOSTED_MODEL_TOKEN"
_ENV_SPLUNK_HOST = "SENTINEL_SPLUNK_HOST"
_ENV_SPLUNK_PORT = "SENTINEL_SPLUNK_PORT"
_ENV_SPLUNK_SCHEME = "SENTINEL_SPLUNK_SCHEME"

_SYSTEM_PROMPT_PATH = (
    Path(__file__).resolve().parent.parent.parent.parent
    / "models" / "prompts" / "sherlock_system_prompt.txt"
)

_WINDOW_BEFORE_MINUTES = 60
_WINDOW_AFTER_MINUTES  = 60
_MAX_IOC_ENRICHMENTS   = 10
_QUERY_TIMEOUT         = 60
_MODEL_TIMEOUT         = 45

# Per-query fault-tolerance budget — any single MCP call or SAIA query that
# runs longer than this is treated as hung and aborted with SherlockTimeoutError
# so one slow query cannot stall the whole 5-phase investigation indefinitely.
_PER_QUERY_TIMEOUT_SECONDS        = 300   # 5 minutes
# Circuit breaker: after this many consecutive per-query timeouts, Sherlock
# marks itself "degraded" and stops calling SAIA — falling back to the
# pre-built keyword-matched SPL template library for subsequent queries.
_CIRCUIT_BREAKER_THRESHOLD        = 3
# After this long without a fresh timeout, a degraded Sherlock re-attempts
# SAIA on the next query (half-open recovery probe).
_CIRCUIT_BREAKER_COOLDOWN_SECONDS = 300   # 5 minutes

# Data-source labels for metrics tracking — extracted from SPL macro names
_SOURCE_PATTERNS: Dict[str, str] = {
    r"sentinel_edr_index":      "edr",
    r"sentinel_network_index":  "network",
    r"sentinel_identity_index": "identity",
    r"sentinel_cloud_index":    "cloud",
    r"enrich_threat_intel":     "threat_intel",
    r"stream:dns":              "dns",
}

_SUSPICIOUS_CHAINS: List[Tuple[str, str]] = [
    ("winword.exe",  "powershell.exe"),
    ("excel.exe",    "powershell.exe"),
    ("outlook.exe",  "powershell.exe"),
    ("winword.exe",  "cmd.exe"),
    ("excel.exe",    "cmd.exe"),
    ("mshta.exe",    "powershell.exe"),
    ("wscript.exe",  "cmd.exe"),
    ("wscript.exe",  "powershell.exe"),
    ("cscript.exe",  "powershell.exe"),
    ("regsvr32.exe", "powershell.exe"),
    ("msiexec.exe",  "powershell.exe"),
]

_LOLBINS: Set[str] = {
    "certutil.exe", "bitsadmin.exe", "regsvr32.exe", "mshta.exe",
    "wmic.exe", "rundll32.exe", "cmstp.exe", "installutil.exe",
    "msbuild.exe", "odbcconf.exe", "xwizard.exe",
}

_RANSOMWARE_EXTENSIONS: Set[str] = {
    ".encrypted", ".locked", ".locky", ".ryuk", ".akira", ".crypt",
    ".enc", ".ransom", ".wncry", ".wnry", ".cerber", ".sage", ".phobos",
    ".conti", ".revil", ".lockbit",
}

# Human-readable phase names for the investigation_chain explainability trace
_PHASE_NAMES: Dict[str, str] = {
    "A": "Host Context — asset baseline, logon history, process tree",
    "B": "Timeline Reconstruction — event sequencing, process chains, network, file changes",
    "C": "Lateral Movement Analysis — SMB/RDP/SSH pivots, remote auth, flow patterns",
    "D": "Identity & Credential Analysis — baseline deviation, impossible travel, privilege escalation",
    "E": "Threat Intelligence Enrichment — IOC verdicts, campaign attribution, TTP mapping",
}

# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class SherlockError(Exception):
    """Base Sherlock exception."""

class SherlockSAIAError(SherlockError):
    """SAIA unavailable or returned unusable output."""

class SherlockQueryError(SherlockError):
    """SPL query execution failed."""

class SherlockModelError(SherlockError):
    """Synthesis model call failed."""

class SherlockTimeoutError(SherlockError):
    """An MCP call or SAIA query exceeded its allotted time budget."""

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class TimelineEvent:
    time_hms:  str   # "HH:MM:SS"
    event:     str
    source:    str
    epoch_ms:  int = 0     # internal only — used for sorting
    technique: str = ""

    def to_dict(self) -> Dict:
        return {"time": self.time_hms, "event": self.event, "source": self.source}


@dataclass
class BlastRadius:
    compromised_hosts:            List[str] = field(default_factory=list)
    targeted_hosts:               List[str] = field(default_factory=list)
    suspected_hosts:              List[str] = field(default_factory=list)
    compromised_users:            List[str] = field(default_factory=list)
    affected_services:            List[str] = field(default_factory=list)
    data_at_risk:                 str = "Unknown"
    estimated_dwell_time_minutes: int = 0

    def to_dict(self) -> Dict:
        return {
            "compromised_hosts":            self.compromised_hosts,
            "targeted_hosts":               self.targeted_hosts,
            "suspected_hosts":              self.suspected_hosts,
            "compromised_users":            self.compromised_users,
            "affected_services":            self.affected_services,
            "data_at_risk":                 self.data_at_risk,
            "estimated_dwell_time_minutes": self.estimated_dwell_time_minutes,
        }


@dataclass
class PhaseResult:
    phase:         str
    status:        str   # complete | partial | failed | skipped
    queries_run:   int = 0
    events_found:  int = 0
    key_findings:  List[str] = field(default_factory=list)
    iocs_found:    List[Dict] = field(default_factory=list)
    hosts_seen:    List[str] = field(default_factory=list)
    users_seen:    List[str] = field(default_factory=list)
    evidence_gaps: List[str] = field(default_factory=list)
    duration_ms:   int = 0
    error:         Optional[str] = None

    def to_dict(self) -> Dict:
        return {k: v for k, v in self.__dict__.items()}


@dataclass
class InvestigationContext:
    """Mutable accumulator passed through all phase methods."""

    case_id:                 str
    alert_id:                str
    host:                    str
    user:                    str
    alert_time_iso:          str
    alert_epoch_ms:          int
    earliest:                str   # Splunk absolute time string  "MM/DD/YYYY:HH:MM:SS"
    latest:                  str
    classification:          str
    mitre_tactic:            str
    mitre_technique:         str
    composite_score:         int
    vanguard_key_indicators: List[str]

    # Accumulated findings
    all_hosts:             List[str]  = field(default_factory=list)
    all_users:             List[str]  = field(default_factory=list)
    all_iocs:              List[Dict] = field(default_factory=list)
    total_events:          int        = 0
    timeline_events:       List[Dict] = field(default_factory=list)

    # Phase-to-phase context
    asset_context:         Dict       = field(default_factory=dict)
    process_tree:          List[Dict] = field(default_factory=list)
    suspicious_processes:  List[str]  = field(default_factory=list)
    network_flows:         List[Dict] = field(default_factory=list)
    lateral_targets:       List[str]  = field(default_factory=list)
    credential_indicators: List[str]  = field(default_factory=list)

    # Metrics counters
    queries_executed:      int        = 0
    mcp_calls:             int        = 0
    data_sources:          List[str]  = field(default_factory=list)   # unique source labels

    def add_host(self, hostname: str) -> None:
        h = (hostname or "").strip().lower()
        if h and h not in self.all_hosts:
            self.all_hosts.append(h)

    def add_user(self, username: str) -> None:
        u = (username or "").strip().lower()
        if u and u not in self.all_users:
            self.all_users.append(u)

    def add_ioc(self, value: str, ioc_type: str, source: str = "", verdict: str = "unknown") -> None:
        v = (value or "").strip()
        if not v:
            return
        for existing in self.all_iocs:
            if existing.get("value") == v:
                return
        self.all_iocs.append({"value": v, "type": ioc_type, "source": source, "verdict": verdict})

    def record_source(self, spl_or_label: str) -> None:
        """Record which data source was queried (for metrics)."""
        for pattern, label in _SOURCE_PATTERNS.items():
            if re.search(pattern, spl_or_label, re.IGNORECASE):
                if label not in self.data_sources:
                    self.data_sources.append(label)


@dataclass
class SherlockInvestigationReport:
    case_id:                    str
    executive_summary:          str
    timeline:                   List[TimelineEvent]
    blast_radius:               BlastRadius
    threat_assessment:          Dict
    recommended_actions:        List[Dict]
    confidence_assessment:      Dict
    queries_executed:           int
    data_sources_queried:       int
    mcp_calls:                  int
    duration_seconds:           int
    # Extended fields for the orchestrator pipeline
    alert_id:                   str = ""
    classification:             str = ""
    phases_completed:           List[str] = field(default_factory=list)
    iocs_discovered:            List[Dict] = field(default_factory=list)
    model_used:                 str = ""
    model_available:            bool = False
    timestamp:                  str = ""
    # Evidence quality and narrative fields from model synthesis
    attack_narrative:           str = ""
    evidence_gaps:              List[str] = field(default_factory=list)
    false_positive_probability: float = 0.0
    # Step-by-step "Chain of Thought" explainability trace — one entry per
    # investigation phase, recording the query/tool used, the raw result,
    # and Sherlock's inference from it (SOC audit / compliance trail)
    investigation_chain:        List[Dict] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            # --- Spec-required fields ---
            "case_id":           self.case_id,
            "executive_summary": self.executive_summary,
            "attack_narrative":  self.attack_narrative,
            "timeline":          [e.to_dict() for e in self.timeline],
            "blast_radius":      self.blast_radius.to_dict(),
            "threat_assessment": self.threat_assessment,
            "recommended_actions": self.recommended_actions,
            "confidence_assessment": self.confidence_assessment,
            "evidence_gaps":     self.evidence_gaps,
            "false_positive_probability": self.false_positive_probability,
            "investigation_metrics": {
                "queries_executed":     self.queries_executed,
                "data_sources_queried": self.data_sources_queried,
                "mcp_calls":            self.mcp_calls,
                "duration_seconds":     self.duration_seconds,
            },
            # --- Orchestrator-consumed extensions ---
            "alert_id":         self.alert_id,
            "classification":   self.classification,
            "phases_completed": self.phases_completed,
            "iocs_discovered":  self.iocs_discovered,
            "model_used":       self.model_used,
            "model_available":  self.model_available,
            "timestamp":        self.timestamp,
            "investigation_chain": self.investigation_chain,
        }


# ---------------------------------------------------------------------------
# SPL Templates — fallback when SAIA is unavailable
# ---------------------------------------------------------------------------

_SPL_TEMPLATES: Dict[str, str] = {
    # Phase A
    "phase_a_processes": (
        'index=`sentinel_edr_index` host="{host}" earliest="{earliest}" latest="{latest}" '
        "(EventCode=4688 OR process_exec=*) "
        "| stats count, values(process_path) as paths, values(process_hash) as hashes "
        "  by parent_process_name, process_name "
        "| sort -count | head 50"
    ),
    "phase_a_logons": (
        'index=`sentinel_identity_index` host="{host}" earliest="{earliest}" latest="{latest}" '
        "EventCode=4624 "
        "| stats count, values(LogonType) as logon_types, min(_time) as first_seen, "
        "  max(_time) as last_seen by user, src_ip "
        "| sort -count | head 20"
    ),
    "phase_a_file_activity": (
        'index=`sentinel_edr_index` host="{host}" earliest="{earliest}" latest="{latest}" '
        "(action=created OR action=modified OR action=deleted) "
        "| stats count by file_path, action, process_name "
        "| sort -count | head 50"
    ),
    # Phase B
    "phase_b_timeline": (
        'index=`sentinel_edr_index` OR index=`sentinel_network_index` '
        'host="{host}" earliest="{earliest}" latest="{latest}" '
        "| eval _time=coalesce(event_time, _time) "
        "| sort _time "
        "| table _time, sourcetype, action, process_name, dest_ip, user "
        "| head 200"
    ),
    "phase_b_process_chain": (
        'index=`sentinel_edr_index` host="{host}" earliest="{earliest}" latest="{latest}" '
        "| eval chain=parent_process_name.\" → \".process_name "
        "| stats count, values(process_hash) as hashes, values(process_args) as args "
        "  by chain "
        "| sort -count | head 30"
    ),
    "phase_b_network": (
        'index=`sentinel_network_index` (src_host="{host}" OR src_ip="{host}") '
        'earliest="{earliest}" latest="{latest}" '
        "| stats count, values(dest_port) as ports by src_ip, dest_ip, transport "
        "| sort -count | head 50"
    ),
    "phase_b_encoded_commands": (
        'index=`sentinel_edr_index` host="{host}" earliest="{earliest}" latest="{latest}" '
        'process_name="powershell.exe" '
        '(process_args="*-EncodedCommand*" OR process_args="*-enc *" '
        ' OR process_args="*-WindowStyle*Hidden*" OR process_args="*-NonInteractive*") '
        "| table _time, process_args, parent_process_name, user | sort -_time"
    ),
    "phase_b_vss_deletion": (
        'index=`sentinel_edr_index` host="{host}" earliest="{earliest}" latest="{latest}" '
        '(process_args="*vssadmin*delete*" OR process_args="*shadowcopy*delete*" '
        ' OR process_args="*bcdedit*recoveryenabled*no*") '
        "| table _time, process_name, process_args, user | sort -_time"
    ),
    # Phase C
    "phase_c_smb": (
        'index=`sentinel_network_index` src_ip="{host_ip}" earliest="{earliest}" latest="{latest}" '
        "(dest_port=445 OR dest_port=139) "
        "| stats count, values(dest_ip) as targets by src_ip "
        "| where count > 2 | sort -count"
    ),
    "phase_c_remote_auth": (
        'index=`sentinel_identity_index` src_ip="{host_ip}" earliest="{earliest}" latest="{latest}" '
        "LogonType=3 action=success "
        "| stats count, values(dest_host) as targets by user, src_ip "
        "| sort -count"
    ),
    "phase_c_rdp": (
        'index=`sentinel_identity_index` earliest="{earliest}" latest="{latest}" '
        "(LogonType=10 OR EventCode=4624) "
        '(src_ip="{host_ip}" OR dest_host="{host}") '
        "| stats count, values(dest_host) as rdp_targets by src_ip, user "
        "| sort -count"
    ),
    "phase_c_flow_patterns": (
        'index=`sentinel_network_index` src_ip="{host_ip}" earliest="{earliest}" latest="{latest}" '
        "| bucket _time span=5m "
        "| stats count, dc(dest_ip) as unique_dests, sum(bytes_out) as total_bytes "
        "  by _time, src_ip "
        "| where unique_dests > 5 OR total_bytes > 104857600 "
        "| sort -_time"
    ),
    # Phase D
    "phase_d_user_baseline": (
        'index=`sentinel_identity_index` user="{user}" earliest="-30d" latest="{alert_time}" '
        "| stats count, dc(src_ip) as unique_ips, dc(dest_host) as unique_hosts, "
        "  values(src_ip) as src_ips by date_hour, date_wday "
        "| sort -count | head 50"
    ),
    "phase_d_priv_commands": (
        'index=`sentinel_edr_index` host="{host}" user="{user}" '
        'earliest="{earliest}" latest="{latest}" '
        '(process_name="net.exe" OR process_name="whoami.exe" OR '
        ' process_name="nltest.exe" OR process_name="dsquery.exe" OR '
        ' process_name="adfind.exe") '
        "| table _time, process_name, process_args, parent_process_name "
        "| sort -_time"
    ),
    "phase_d_lsass_access": (
        'index=`sentinel_edr_index` host="{host}" earliest="{earliest}" latest="{latest}" '
        '(target_process="lsass.exe" OR process_args="*lsass*") '
        "| table _time, process_name, process_args, user, GrantedAccess "
        "| sort -_time"
    ),
    "phase_d_impossible_travel": (
        'index=`sentinel_identity_index` user="{user}" earliest="{earliest}" latest="{latest}" '
        "action=success "
        "| iplocation src_ip "
        "| stats values(Country) as countries, dc(Country) as country_count, "
        "  values(src_ip) as ips by user "
        "| where country_count > 1"
    ),
    # Phase E
    "phase_e_ioc_spread": (
        'index=`sentinel_edr_index` OR index=`sentinel_network_index` '
        'earliest="{earliest}" latest="{latest}" '
        '"{ioc_value}" '
        "| stats count, values(host) as affected_hosts | head 20"
    ),
    "phase_e_dns_suspicious": (
        'index=`sentinel_network_index` src_ip="{host_ip}" '
        'earliest="{earliest}" latest="{latest}" '
        "sourcetype=stream:dns "
        "| stats count, values(query) as domains by src_ip "
        "| where count > 20 | sort -count"
    ),
}

# Keyword → template mapping for generate_investigation_query() fallback
_NL_KEYWORD_MAP: List[Tuple[List[str], str]] = [
    (["process", "spawn",  "parent",  "child"],    "phase_b_process_chain"),
    (["encoded", "base64", "-enc",    "obfuscat"], "phase_b_encoded_commands"),
    (["timeline", "sequence", "order", "all event"], "phase_b_timeline"),
    (["network", "connection", "traffic", "flow"],  "phase_b_network"),
    (["shadow", "vss",   "bcdedit", "vssadmin"],    "phase_b_vss_deletion"),
    (["smb",    "445",   "lateral",  "pivot"],      "phase_c_smb"),
    (["rdp",    "remote desktop"],                   "phase_c_rdp"),
    (["auth",   "logon", "login",   "session"],     "phase_c_remote_auth"),
    (["lsass",  "credential dump",  "mimikatz"],    "phase_d_lsass_access"),
    (["whoami", "nltest", "discovery", "enum"],     "phase_d_priv_commands"),
    (["impossible travel", "geolocation", "country"], "phase_d_impossible_travel"),
    (["baseline", "normal", "typical behavior"],   "phase_d_user_baseline"),
    (["dns",    "domain",  "beacon", "c2 domain"], "phase_e_dns_suspicious"),
    (["file",   "created", "modified", "deleted"], "phase_a_file_activity"),
    (["logon",  "logoff",  "log on",   "session"], "phase_a_logons"),
    (["process execution", "ran", "executed"],      "phase_a_processes"),
]


# ---------------------------------------------------------------------------
# SAIA Client
# ---------------------------------------------------------------------------

class SAIAClient:
    """Splunk AI Assistant client — natural language → SPL generation."""

    _PATH    = "/services/assistant/v1/generate"
    _TIMEOUT = 30

    def __init__(
        self,
        host:       str,
        port:       int,
        token:      str,
        scheme:     str  = "https",
        verify_ssl: bool = False,
    ) -> None:
        self._base_url = f"{scheme}://{host}:{port}"
        self._token    = token
        self._verify   = verify_ssl
        session = requests.Session()
        adapter = HTTPAdapter(max_retries=Retry(total=2, backoff_factor=0.5))
        session.mount("https://", adapter)
        session.mount("http://",  adapter)
        self._session = session

    def generate_spl(
        self,
        question: str,
        context:  Optional[Dict] = None,
        phase:    str = "",
    ) -> Optional[str]:
        """Return generated SPL string or None on failure."""
        try:
            resp = self._session.post(
                self._base_url + self._PATH,
                json={"question": question, "context": context or {}, "mode": "spl_generation"},
                headers={"Authorization": f"Bearer {self._token}"},
                timeout=self._TIMEOUT,
                verify=self._verify,
            )
            if resp.status_code != 200:
                return None
            data = resp.json()
            spl  = data.get("spl") or data.get("query") or data.get("result", "")
            return spl.strip() if spl and len(spl.strip()) > 10 else None
        except Exception as exc:
            log.debug("SAIA unavailable (%s)", exc)
            return None


# ---------------------------------------------------------------------------
# Sherlock Agent
# ---------------------------------------------------------------------------

class SherlockAgent:
    """Investigation agent — 5-phase deep-dive on confirmed security alerts."""

    AGENT_NAME = "sherlock"

    def __init__(
        self,
        mcp:    Optional[SplunkMCPClient] = None,
        saia:   Optional[SAIAClient]      = None,
        config: Any                        = None,
    ) -> None:
        self._cfg         = config or get_config()
        self._mcp         = mcp
        self._saia        = saia
        self._prompt:      Optional[str] = None
        self._model_url:   Optional[str] = None
        self._model_token: Optional[str] = None

        # Circuit breaker state — tracks consecutive per-query timeouts so a
        # struggling SAIA/MCP backend degrades Sherlock to template-only mode
        # instead of stalling every subsequent query for the full 5 minutes.
        self._consecutive_timeouts = 0
        self._degraded             = False
        self._degraded_since:      Optional[float] = None

    # ------------------------------------------------------------------
    # Fault tolerance — per-query timeout + circuit breaker
    # ------------------------------------------------------------------

    @property
    def is_degraded(self) -> bool:
        """True when the circuit breaker is open (SAIA bypassed for templates)."""
        return self._degraded

    def _run_with_timeout(
        self,
        fn,
        *args: Any,
        op_name: str = "query",
        timeout: float = _PER_QUERY_TIMEOUT_SECONDS,
        **kwargs: Any,
    ) -> Any:
        """
        Execute `fn(*args, **kwargs)` with a hard wall-clock budget.

        Raises SherlockTimeoutError if `fn` has not returned within `timeout`
        seconds. Used to bound every MCP call and SAIA query so a single hung
        backend cannot stall the investigation indefinitely — the orchestrator's
        stage-retry logic depends on Sherlock returning (successfully or with
        an exception) within a bounded time.
        """
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        future = executor.submit(fn, *args, **kwargs)
        try:
            result = future.result(timeout=timeout)
        except concurrent.futures.TimeoutError:
            self._record_query_timeout(op_name, timeout)
            raise SherlockTimeoutError(
                f"{op_name} exceeded {timeout:.0f}s timeout — treating as hung."
            )
        else:
            self._record_query_success()
            return result
        finally:
            executor.shutdown(wait=False)

    def _record_query_timeout(self, op_name: str, timeout: float) -> None:
        self._consecutive_timeouts += 1
        log.warning(
            "Sherlock: %s timed out after %.0fs (consecutive_timeouts=%d)",
            op_name, timeout, self._consecutive_timeouts,
        )
        if self._consecutive_timeouts >= _CIRCUIT_BREAKER_THRESHOLD and not self._degraded:
            self._degraded       = True
            self._degraded_since = time.monotonic()
            log.error(
                "Sherlock: circuit breaker OPEN after %d consecutive query timeouts — "
                "degrading to template-only SPL generation (SAIA bypassed).",
                self._consecutive_timeouts,
            )

    def _record_query_success(self) -> None:
        self._consecutive_timeouts = 0
        if self._degraded:
            self._degraded       = False
            self._degraded_since = None
            log.info("Sherlock: circuit breaker CLOSED — query succeeded; SAIA re-enabled.")

    def _circuit_breaker_should_probe(self) -> bool:
        """
        While degraded, allow one SAIA attempt per cooldown window (half-open
        probe) instead of permanently bypassing it — lets Sherlock recover
        automatically once the backend comes back.
        """
        if not self._degraded or self._degraded_since is None:
            return not self._degraded
        return (time.monotonic() - self._degraded_since) >= _CIRCUIT_BREAKER_COOLDOWN_SECONDS

    # ------------------------------------------------------------------
    # Lazy accessors
    # ------------------------------------------------------------------

    def _get_mcp(self) -> SplunkMCPClient:
        if self._mcp is None:
            self._mcp = SplunkMCPClient(agent_name=self.AGENT_NAME)
        return self._mcp

    def _get_saia(self) -> SAIAClient:
        if self._saia is None:
            host   = os.environ.get(_ENV_SPLUNK_HOST,   self._cfg.get("splunk", "host",   default="localhost"))
            port   = int(os.environ.get(_ENV_SPLUNK_PORT, self._cfg.get("splunk", "port", default="8089")))
            scheme = os.environ.get(_ENV_SPLUNK_SCHEME, self._cfg.get("splunk", "scheme", default="https"))
            token  = os.environ.get(_ENV_SAIA_TOKEN,    self._cfg.get("saia",   "token",  default=""))
            self._saia = SAIAClient(host=host, port=port, token=token, scheme=scheme)
        return self._saia

    def _load_system_prompt(self) -> str:
        if self._prompt is None:
            try:
                self._prompt = _SYSTEM_PROMPT_PATH.read_text(encoding="utf-8")
            except Exception as exc:
                log.warning("Could not load sherlock system prompt: %s", exc)
                self._prompt = "You are Sherlock, a security investigation agent. Respond with valid JSON only."
        return self._prompt

    def _get_model_url(self) -> str:
        if self._model_url is None:
            scheme = os.environ.get(_ENV_SPLUNK_SCHEME, self._cfg.get("splunk", "scheme", default="https"))
            host   = os.environ.get(_ENV_SPLUNK_HOST,   self._cfg.get("splunk", "host",   default="localhost"))
            port   = int(os.environ.get(_ENV_SPLUNK_PORT, self._cfg.get("splunk", "port", default="8089")))
            self._model_url = (
                f"{scheme}://{host}:{port}"
                "/services/ml/models/foundation-sec-1.1-8b-instruct/predict"
            )
        return self._model_url

    def _get_model_token(self) -> str:
        if self._model_token is None:
            self._model_token = os.environ.get(
                _ENV_MODEL_TOKEN,
                self._cfg.get("hosted_models", "api_token", default=""),
            )
        return self._model_token

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(self, case: Any, audit: AuditLogger) -> Dict:
        """
        Run the full 5-phase investigation and return SherlockInvestigationReport dict.
        This is the orchestrator entry point (_AgentProxy interface).
        """
        t0 = int(time.time() * 1000)
        vanguard = getattr(case, "vanguard_decision", None) or {}
        ctx = self._init_context(case, vanguard)

        log.info(
            "Sherlock: case=%s host=%s user=%s classification=%s score=%d",
            ctx.case_id, ctx.host, ctx.user, ctx.classification, ctx.composite_score,
        )

        phase_results:    Dict[str, PhaseResult] = {}
        phases_completed: List[str] = []

        for phase_name, phase_fn in [
            ("A", self._run_phase_a),
            ("B", self._run_phase_b),
            ("C", self._run_phase_c),
            ("D", self._run_phase_d),
            ("E", self._run_phase_e),
        ]:
            t_phase = int(time.time() * 1000)
            try:
                result = phase_fn(ctx)
            except Exception as exc:
                log.exception("Phase %s unhandled exception", phase_name)
                audit.log_error(
                    case_id=ctx.case_id, error_type="PHASE_EXCEPTION",
                    message=f"Phase {phase_name}: {exc}", exc=exc,
                    context={"phase": phase_name},
                )
                result = PhaseResult(phase=phase_name, status="failed", error=str(exc))

            result.duration_ms = int(time.time() * 1000) - t_phase
            phase_results[phase_name] = result
            if result.status in ("complete", "partial"):
                phases_completed.append(phase_name)

            log.info(
                "Phase %s: status=%s events=%d queries=%d duration=%dms",
                phase_name, result.status, result.events_found,
                result.queries_run, result.duration_ms,
            )
            audit.log_metric(
                case_id=ctx.case_id,
                metric_name=f"sherlock_phase_{phase_name.lower()}_events",
                value=float(result.events_found),
                unit="events",
                metadata={"phase": phase_name, "status": result.status},
            )

        # Synthesise report
        synthesis = self._synthesize_report(ctx, phase_results)
        blast     = self._build_blast_radius(ctx, phase_results)
        timeline  = self._build_timeline(ctx, phase_results)
        investigation_chain = self.build_investigation_chain(ctx, phase_results)
        total_ms  = int(time.time() * 1000) - t0

        report = SherlockInvestigationReport(
            case_id=ctx.case_id,
            executive_summary=synthesis.get("executive_summary", "Investigation complete."),
            attack_narrative=synthesis.get("attack_narrative", ""),
            timeline=timeline,
            blast_radius=blast,
            threat_assessment=synthesis.get("threat_assessment", {}),
            recommended_actions=synthesis.get("recommended_actions", []),
            confidence_assessment=synthesis.get("confidence_assessment", {}),
            evidence_gaps=synthesis.get("evidence_gaps", []),
            false_positive_probability=float(synthesis.get("false_positive_probability", 0.0)),
            queries_executed=ctx.queries_executed,
            data_sources_queried=len(ctx.data_sources),
            mcp_calls=ctx.mcp_calls,
            duration_seconds=total_ms // 1000,
            alert_id=ctx.alert_id,
            classification=ctx.classification,
            phases_completed=phases_completed,
            iocs_discovered=ctx.all_iocs,
            model_used=synthesis.get("model_used", ""),
            model_available=synthesis.get("model_available", False),
            timestamp=datetime.now(timezone.utc).isoformat(),
            investigation_chain=investigation_chain,
        )

        audit.log_chain_of_thought(
            case_id    = ctx.case_id,
            agent_name = "sherlock",
            chain      = investigation_chain,
        )

        audit.log_decision(
            case_id=ctx.case_id,
            decision_type="INVESTIGATION_COMPLETE",
            confidence=float(report.confidence_assessment.get("overall", 0.5)),
            input_context={
                "phases_run":       list(phase_results.keys()),
                "phases_completed": phases_completed,
                "iocs_found":       len(ctx.all_iocs),
                "queries_executed": ctx.queries_executed,
                "mcp_calls":        ctx.mcp_calls,
            },
            output_decision={
                "compromised_hosts": blast.compromised_hosts,
                "targeted_hosts":    blast.targeted_hosts,
                "compromised_users": blast.compromised_users,
                "data_at_risk":      blast.data_at_risk,
            },
            reasoning=report.executive_summary[:500],
            mitre_tactic=ctx.mitre_tactic,
            mitre_technique=ctx.mitre_technique,
            model_used=report.model_used,
            latency_ms=total_ms,
            metadata={"investigation_chain": investigation_chain},
        )

        log.info(
            "Sherlock complete: case=%s phases=%s hosts=%d users=%d iocs=%d "
            "queries=%d mcp_calls=%d duration=%ds",
            ctx.case_id, phases_completed,
            len(blast.compromised_hosts) + len(blast.targeted_hosts),
            len(blast.compromised_users), len(ctx.all_iocs),
            ctx.queries_executed, ctx.mcp_calls, report.duration_seconds,
        )
        return report.to_dict()

    def build_investigation_chain(
        self,
        ctx: "InvestigationContext",
        phase_results: Dict[str, "PhaseResult"],
    ) -> List[Dict[str, Any]]:
        """
        Build a step-by-step "Chain of Thought" explainability trace for the
        investigation — one entry per phase, recording the query/tool used,
        the raw result observed, and the inference Sherlock drew from it.

        Purely narrative: it re-describes the same `phase_results`/`ctx`
        signals that `_synthesize_report`/`_build_blast_radius`/
        `_build_timeline` already consume — it does not run new queries,
        compute new findings, or alter investigation logic in any way.
        Used for SOC audit / compliance trails and external-tool queries
        (see AuditLogger.log_chain_of_thought).
        """
        chain: List[Dict[str, Any]] = []

        for step, phase_name in enumerate(("A", "B", "C", "D", "E"), start=1):
            result = phase_results.get(phase_name)
            if result is None:
                continue

            name = _PHASE_NAMES.get(phase_name, f"Phase {phase_name}")

            if result.status == "skipped":
                query = "skipped — prerequisite data unavailable"
            else:
                query = (
                    f"{result.queries_run} quer{'y' if result.queries_run == 1 else 'ies'} "
                    f"executed via MCP/SAIA against host={ctx.host or '?'} "
                    f"user={ctx.user or '?'} window=[{ctx.earliest} .. {ctx.latest}]"
                )

            result_summary = (
                f"status={result.status}; events_found={result.events_found}; "
                f"key_findings={result.key_findings or ['none']}; "
                f"iocs_found={len(result.iocs_found)}; "
                f"evidence_gaps={result.evidence_gaps or ['none']}"
            )

            if result.status == "skipped":
                inference = (
                    f"Phase {phase_name} could not run — "
                    f"{(result.evidence_gaps or ['missing prerequisite data'])[0]}"
                )
            elif result.status == "failed":
                inference = (
                    f"Phase {phase_name} failed to complete "
                    f"({result.error or 'unknown error'}); findings from this "
                    f"phase are treated as evidence gaps, not conclusions."
                )
            elif result.key_findings:
                inference = (
                    f"Phase {phase_name} surfaced {len(result.key_findings)} notable "
                    f"finding(s) — most significant: \"{result.key_findings[0]}\". "
                    f"This feeds the {name.split('—')[0].strip().lower()} assessment "
                    f"in the synthesised report."
                )
            else:
                inference = (
                    f"Phase {phase_name} ran {result.queries_run} quer"
                    f"{'y' if result.queries_run == 1 else 'ies'} and observed "
                    f"{result.events_found} event(s) with no standout indicators — "
                    f"consistent with a lower-severity or contained scenario for this phase."
                )

            chain.append({
                "step":      step,
                "phase":     phase_name,
                "name":      name,
                "query":     query,
                "result":    result_summary,
                "inference": inference,
            })

        if chain:
            final_step = len(chain) + 1
            chain.append({
                "step":       final_step,
                "phase":      "SYNTHESIS",
                "name":       "Report Synthesis & Conclusion",
                "query":      (
                    f"Aggregated {ctx.queries_executed} queries across "
                    f"{len(ctx.data_sources)} data source(s) and {ctx.mcp_calls} MCP call(s) "
                    f"into a unified investigation report."
                ),
                "result": (
                    f"hosts_seen={ctx.all_hosts}; users_seen={ctx.all_users}; "
                    f"iocs_discovered={len(ctx.all_iocs)}; "
                    f"phases_completed={[p['phase'] for p in chain if p['phase'] != 'SYNTHESIS']}"
                ),
                "conclusion": (
                    f"Investigation synthesised across {len(chain)} phase(s) of evidence; "
                    f"{len(ctx.all_iocs)} IOC(s) and {len(ctx.all_hosts)} host(s) "
                    f"identified for the executive summary, blast-radius, and "
                    f"recommended-actions sections of the report."
                ),
                "action": "synthesize_report",
            })

        return chain

    def generate_investigation_query(
        self,
        natural_language_description: str,
        context: Optional[Dict] = None,
    ) -> str:
        """
        Generate a validated SPL query from a natural language description.

        Pipeline:
          1. Attempt SAIA (hosted NL→SPL)
          2. Fall back to keyword-matched template library
          3. Validate with MCP validate_spl() before returning
          4. Return a safe fallback search if validation fails

        Args:
            natural_language_description: e.g.
                "Show me all processes spawned by powershell.exe on HOST-X in the last 2 hours"
            context: optional dict with {host, user, earliest, latest, ...}

        Returns:
            An executable SPL string (never empty).
        """
        ctx_dict = context or {}
        spl: Optional[str] = None
        if self._circuit_breaker_should_probe():
            try:
                spl = self._run_with_timeout(
                    self._get_saia().generate_spl,
                    natural_language_description, ctx_dict, "api",
                    op_name="SAIA generate_spl (api)",
                )
            except SherlockTimeoutError as exc:
                log.warning("generate_investigation_query: %s — falling back to templates", exc)
                spl = None

        if not spl:
            spl = self._match_template_by_keywords(
                natural_language_description, ctx_dict
            )

        if spl:
            spl = self._validate_and_correct_spl(spl)

        if not spl:
            host = ctx_dict.get("host", "*")
            log.warning(
                "generate_investigation_query: all generation paths failed; returning stub search"
            )
            spl = (
                f'index=* host="{host}" | head 100'
                if host != "*"
                else "index=* | head 100"
            )

        return spl

    def calculate_blast_radius(self, investigation_results: Dict) -> Dict:
        """
        Calculate blast radius from a collected investigation results dict.

        Can be called standalone (e.g. by the orchestrator or Sage) with the
        `sherlock_report` dict stored on the Case.  Returns a blast_radius dict
        matching the SherlockInvestigationReport schema.

        Args:
            investigation_results: the full dict returned by run() or a subset
                with keys: compromised_hosts, lateral_targets, all_iocs,
                credential_indicators, classification, user.

        Returns:
            dict matching BlastRadius.to_dict() schema.
        """
        # Accept either a full report dict or a raw context summary
        br = investigation_results.get("blast_radius")
        if isinstance(br, dict):
            return br   # already computed — pass through

        blast = BlastRadius()
        blast.compromised_hosts = list(investigation_results.get("compromised_hosts", []))
        blast.targeted_hosts    = list(investigation_results.get("lateral_targets",   []))
        blast.suspected_hosts   = list(investigation_results.get("suspected_hosts",   []))
        blast.compromised_users = list(investigation_results.get("compromised_users", []))
        blast.affected_services = list(investigation_results.get("affected_services", []))

        classification = investigation_results.get("classification", "")
        cred_indicators = investigation_results.get("credential_indicators", [])

        if classification in ("DATA_EXFILTRATION", "INSIDER_THREAT"):
            blast.data_at_risk = "Sensitive data access confirmed; exfiltration volume unknown."
        elif "lsass_access" in cred_indicators:
            blast.data_at_risk = (
                "Active Directory credentials at risk; assume all domain accounts compromised."
            )
        elif classification.startswith("RANSOMWARE"):
            blast.data_at_risk = (
                "File encryption in progress or imminent; backup integrity at risk."
            )
        else:
            blast.data_at_risk = "Data impact undetermined; further investigation required."

        return blast.to_dict()

    # ------------------------------------------------------------------
    # Context initialisation
    # ------------------------------------------------------------------

    def _init_context(self, case: Any, vanguard: Dict) -> InvestigationContext:
        now_utc  = datetime.now(timezone.utc)
        raw_time = getattr(case, "created_time", None) or now_utc.isoformat()
        try:
            if isinstance(raw_time, (int, float)):
                alert_dt = datetime.fromtimestamp(float(raw_time), tz=timezone.utc)
            else:
                alert_dt = datetime.fromisoformat(str(raw_time).replace("Z", "+00:00"))
        except Exception:
            alert_dt = now_utc

        fmt = "%m/%d/%Y:%H:%M:%S"
        earliest_str = (alert_dt - timedelta(minutes=_WINDOW_BEFORE_MINUTES)).strftime(fmt)
        latest_str   = (alert_dt + timedelta(minutes=_WINDOW_AFTER_MINUTES)).strftime(fmt)

        host = (getattr(case, "affected_host", "") or "").strip()
        user = (getattr(case, "affected_user", "") or "").strip()

        ctx = InvestigationContext(
            case_id=case.case_id,
            alert_id=getattr(case, "alert_id", ""),
            host=host,
            user=user,
            alert_time_iso=alert_dt.isoformat(),
            alert_epoch_ms=int(alert_dt.timestamp() * 1000),
            earliest=earliest_str,
            latest=latest_str,
            classification=(
                vanguard.get("classification")
                or getattr(case, "classification", "UNKNOWN")
            ),
            mitre_tactic=(
                vanguard.get("mitre_tactic")
                or getattr(case, "mitre_tactic", "")
            ),
            mitre_technique=(
                vanguard.get("mitre_technique")
                or getattr(case, "mitre_technique", "")
            ),
            composite_score=(
                vanguard.get("composite_score")
                or getattr(case, "risk_score", 0)
            ),
            vanguard_key_indicators=vanguard.get("key_indicators", []),
        )
        ctx.add_host(host)
        ctx.add_user(user)
        return ctx

    # ------------------------------------------------------------------
    # Phase A — Host Context
    # ------------------------------------------------------------------

    def _run_phase_a(self, ctx: InvestigationContext) -> PhaseResult:
        result = PhaseResult(phase="A", status="failed")
        if not ctx.host:
            result.status = "skipped"
            result.evidence_gaps.append("No affected_host in alert data.")
            return result

        # Query 1: Asset details + patch status via MCP
        try:
            asset = self._get_mcp().get_asset_context(
                host=ctx.host, identifier_type="hostname", include_vulnerabilities=True
            )
            ctx.mcp_calls += 1
            if asset:
                ctx.asset_context = asset
                crit = asset.get("criticality_label", "UNKNOWN")
                result.key_findings.append(f"Asset criticality: {crit}")
                vulns = int(asset.get("open_vulnerabilities", 0))
                if vulns:
                    result.key_findings.append(
                        f"{vulns} unpatched CVE(s); max CVSS {asset.get('max_cvss','?')}"
                    )
                result.queries_run += 1
                ctx.queries_executed += 1
        except MCPError as exc:
            log.warning("Phase A asset_context: %s", exc)
            result.evidence_gaps.append("Asset context unavailable from MCP.")

        # Query 2: Process tree via MCP
        try:
            tree = self._get_mcp().get_process_tree(
                host=ctx.host, depth=4,
                earliest=ctx.earliest, latest=ctx.latest,
            )
            ctx.mcp_calls += 1
            if tree:
                ctx.process_tree = tree if isinstance(tree, list) else [tree]
                result.events_found += len(ctx.process_tree)
                result.queries_run  += 1
                ctx.queries_executed += 1
                for finding in self._detect_suspicious_chains(ctx.process_tree):
                    result.key_findings.append(finding)
                    ctx.suspicious_processes.append(finding)
        except MCPError as exc:
            log.warning("Phase A process_tree: %s", exc)
            result.evidence_gaps.append("Process tree unavailable.")

        # Query 3: Recent logon events
        spl = self._build_query(
            "Show all user logon events with logon type and source IP",
            ctx, "A", "phase_a_logons",
        )
        events = self._execute_query(spl, ctx, "A")
        if events:
            result.events_found += len(events)
            result.queries_run  += 1
            ctx.queries_executed += 1
            for e in events:
                u = e.get("user", "")
                if u:
                    ctx.add_user(u)

        # Query 4: File system changes — detect ransomware patterns
        spl_files = self._build_query(
            "Show files created, modified, or deleted by processes in the investigation window",
            ctx, "A", "phase_a_file_activity",
        )
        file_events = self._execute_query(spl_files, ctx, "A")
        if file_events:
            result.events_found += len(file_events)
            result.queries_run  += 1
            ctx.queries_executed += 1
            ctx.total_events    += len(file_events)
            for e in file_events:
                fp  = e.get("file_path", "")
                ext = Path(fp).suffix.lower() if fp else ""
                if ext in _RANSOMWARE_EXTENSIONS:
                    result.key_findings.append(f"Ransomware-pattern extension: {fp[:80]}")

        # Process execution SPL
        spl_procs = self._build_query(
            "Show all process executions with parent, child, and command line",
            ctx, "A", "phase_a_processes",
        )
        proc_events = self._execute_query(spl_procs, ctx, "A")
        if proc_events:
            result.events_found += len(proc_events)
            result.queries_run  += 1
            ctx.queries_executed += 1
            ctx.total_events    += len(proc_events)
            for e in proc_events:
                h = str(e.get("hashes", "") or e.get("process_hash", ""))
                for sha256 in re.findall(r"\b[a-fA-F0-9]{64}\b", h):
                    ctx.add_ioc(sha256, "hash", "phase_a")
                pname = (e.get("process_name") or "").lower()
                if pname in _LOLBINS:
                    result.key_findings.append(f"LOLBin execution: {pname}")
        else:
            result.evidence_gaps.append("No process execution events; EDR coverage may be absent.")

        result.hosts_seen = [ctx.host]
        result.status = "complete" if result.queries_run >= 2 else "partial"
        return result

    # ------------------------------------------------------------------
    # Phase B — Timeline Reconstruction
    # ------------------------------------------------------------------

    def _run_phase_b(self, ctx: InvestigationContext) -> PhaseResult:
        result = PhaseResult(phase="B", status="failed")

        # Query 1: Full chronological event stream (60 min before + after)
        spl = self._build_query(
            f"Show all events on {ctx.host} in chronological order with source and action",
            ctx, "B", "phase_b_timeline",
        )
        events = self._execute_query(spl, ctx, "B")
        if events:
            result.events_found += len(events)
            result.queries_run  += 1
            ctx.queries_executed += 1
            ctx.total_events    += len(events)
            ctx.timeline_events.extend(events)
        else:
            result.evidence_gaps.append("No timeline events; check index coverage.")

        # Query 2: Process creation chain (parent → child → grandchild)
        spl_chain = self._build_query(
            "Show process parent-child creation chains with process hashes",
            ctx, "B", "phase_b_process_chain",
        )
        chain_events = self._execute_query(spl_chain, ctx, "B")
        if chain_events:
            result.events_found += len(chain_events)
            result.queries_run  += 1
            ctx.queries_executed += 1
            ctx.total_events    += len(chain_events)
            for e in chain_events:
                chain_str = e.get("chain", "")
                for pattern_parent, pattern_child in _SUSPICIOUS_CHAINS:
                    if pattern_parent in chain_str.lower() and pattern_child in chain_str.lower():
                        result.key_findings.append(
                            f"Suspicious process chain: {chain_str} (T1059)"
                        )

        # Query 3: Network connections with timing
        spl_net = self._build_query(
            f"Show all outbound network connections from {ctx.host} with destination and bytes",
            ctx, "B", "phase_b_network",
        )
        net_events = self._execute_query(spl_net, ctx, "B")
        if net_events:
            result.events_found += len(net_events)
            result.queries_run  += 1
            ctx.queries_executed += 1
            ctx.total_events    += len(net_events)
            for e in net_events:
                dest = e.get("dest_ip", "")
                if dest:
                    ctx.add_ioc(dest, "ip", "phase_b")

        # Query 4: Encoded PowerShell and LOLBins
        spl_enc = self._build_query(
            "Find PowerShell with encoded command arguments or hidden window style",
            ctx, "B", "phase_b_encoded_commands",
        )
        enc_events = self._execute_query(spl_enc, ctx, "B")
        if enc_events:
            result.events_found += len(enc_events)
            result.queries_run  += 1
            ctx.queries_executed += 1
            ctx.total_events    += len(enc_events)
            result.key_findings.append(
                f"{len(enc_events)} encoded PowerShell execution(s) (T1059.001)"
            )
            for e in enc_events:
                args = str(e.get("process_args", ""))
                if len(args) > 20:
                    ctx.add_ioc(args[:128], "cmdline", "phase_b")

        # Adaptive: shadow copy deletion if ransomware classification
        if ctx.classification.startswith("RANSOMWARE") or ctx.composite_score > 80:
            spl_vss = self._build_query(
                "Find vssadmin, wmic shadowcopy delete, or bcdedit commands",
                ctx, "B", "phase_b_vss_deletion",
            )
            vss_events = self._execute_query(spl_vss, ctx, "B")
            if vss_events:
                result.events_found += len(vss_events)
                result.queries_run  += 1
                ctx.queries_executed += 1
                ctx.total_events    += len(vss_events)
                result.key_findings.append(
                    f"Shadow copy deletion — {len(vss_events)} event(s) (T1490)"
                )

        # Adaptive: download cradles if encoded commands found
        if enc_events:
            cradle_spl = (
                f'index=`sentinel_edr_index` host="{ctx.host}" '
                f'earliest="{ctx.earliest}" latest="{ctx.latest}" '
                'process_name="powershell.exe" '
                '(process_args="*DownloadString*" OR process_args="*WebClient*" '
                ' OR process_args="*IEX*" OR process_args="*Invoke-Expression*") '
                "| table _time, process_args | sort -_time | head 20"
            )
            cradle_events = self._execute_query(cradle_spl, ctx, "B")
            if cradle_events:
                result.events_found += len(cradle_events)
                result.queries_run  += 1
                ctx.queries_executed += 1
                ctx.total_events    += len(cradle_events)
                result.key_findings.append(
                    f"PowerShell download cradle — {len(cradle_events)} event(s) (T1059.001)"
                )

        result.hosts_seen = [ctx.host]
        result.status = "complete" if result.queries_run >= 3 else "partial"
        return result

    # ------------------------------------------------------------------
    # Phase C — Lateral Movement
    # ------------------------------------------------------------------

    def _run_phase_c(self, ctx: InvestigationContext) -> PhaseResult:
        result  = PhaseResult(phase="C", status="failed")
        host_ip = ctx.asset_context.get("ip_address", ctx.host)

        # Network flows via MCP
        try:
            flows = self._get_mcp().get_network_flows(
                host=ctx.host, earliest=ctx.earliest, latest=ctx.latest,
            )
            ctx.mcp_calls += 1
            if flows:
                ctx.network_flows = flows if isinstance(flows, list) else [flows]
                result.events_found += len(ctx.network_flows)
                result.queries_run  += 1
                ctx.queries_executed += 1
                ctx.total_events    += len(ctx.network_flows)
                ctx.record_source("sentinel_network_index")
                for flow in ctx.network_flows:
                    dest = flow.get("dest_ip", "")
                    if dest and dest != host_ip:
                        ctx.add_ioc(dest, "ip", "phase_c")
        except MCPError as exc:
            log.warning("Phase C network_flows: %s", exc)
            result.evidence_gaps.append("Network flow data unavailable.")

        # SMB lateral movement (T1021.002)
        spl_smb = self._build_query(
            f"Find SMB port 445 connections from {ctx.host} to other internal hosts",
            ctx, "C", "phase_c_smb",
        ).replace("{host_ip}", host_ip)
        smb_events = self._execute_query(spl_smb, ctx, "C")
        if smb_events:
            result.events_found += len(smb_events)
            result.queries_run  += 1
            ctx.queries_executed += 1
            ctx.total_events    += len(smb_events)
            targets: List[str] = []
            for e in smb_events:
                for t in str(e.get("targets", "")).split(","):
                    t = t.strip()
                    if t:
                        targets.append(t)
                        ctx.add_host(t)
                        if t not in ctx.lateral_targets:
                            ctx.lateral_targets.append(t)
            if targets:
                sample = ", ".join(sorted(set(targets))[:5])
                result.key_findings.append(
                    f"SMB lateral movement to {len(set(targets))} host(s) (T1021.002): {sample}"
                )
                result.hosts_seen.extend(set(targets))

        # Remote authentication
        spl_auth = self._build_query(
            f"Find successful network logons from {ctx.host} to other systems",
            ctx, "C", "phase_c_remote_auth",
        ).replace("{host_ip}", host_ip)
        auth_events = self._execute_query(spl_auth, ctx, "C")
        if auth_events:
            result.events_found += len(auth_events)
            result.queries_run  += 1
            ctx.queries_executed += 1
            ctx.total_events    += len(auth_events)
            for e in auth_events:
                for t in str(e.get("targets", "")).split(","):
                    t = t.strip()
                    if t:
                        ctx.add_host(t)
                        if t not in ctx.lateral_targets:
                            ctx.lateral_targets.append(t)
            result.key_findings.append(
                f"Remote auth from {ctx.host}: {len(auth_events)} session(s) (T1078)"
            )

        # Adaptive: network flow pattern analysis
        spl_flow = self._build_query(
            f"Analyse outbound network flow patterns from {ctx.host} for beaconing or bulk transfer",
            ctx, "C", "phase_c_flow_patterns",
        ).replace("{host_ip}", host_ip)
        flow_events = self._execute_query(spl_flow, ctx, "C")
        if flow_events:
            result.events_found += len(flow_events)
            result.queries_run  += 1
            ctx.queries_executed += 1
            ctx.total_events    += len(flow_events)
            large_transfer = any(
                int(e.get("total_bytes", 0)) > 104857600 for e in flow_events
            )
            if large_transfer:
                result.key_findings.append(
                    "Large outbound transfer detected (>100 MB) — potential exfiltration (T1041)"
                )

        if not result.hosts_seen:
            result.hosts_seen = [ctx.host]
        result.status = "complete" if result.queries_run >= 2 else "partial"
        return result

    # ------------------------------------------------------------------
    # Phase D — Identity Compromise
    # ------------------------------------------------------------------

    def _run_phase_d(self, ctx: InvestigationContext) -> PhaseResult:
        result = PhaseResult(phase="D", status="failed")
        if not ctx.user:
            result.evidence_gaps.append("No affected_user; identity phase limited.")

        # User activity via MCP
        if ctx.user:
            try:
                user_data = self._get_mcp().get_user_activity(
                    user=ctx.user, earliest=ctx.earliest, latest=ctx.latest,
                )
                ctx.mcp_calls += 1
                if user_data:
                    result.queries_run  += 1
                    ctx.queries_executed += 1
                    ctx.record_source("sentinel_identity_index")
                    risk = user_data.get("current_risk_score", 0)
                    if risk > 50:
                        result.key_findings.append(
                            f"User {ctx.user} ES risk score: {risk}"
                        )
                    if user_data.get("impossible_travel_detected"):
                        result.key_findings.append(
                            f"Impossible travel detected for {ctx.user} (T1078)"
                        )
                        ctx.credential_indicators.append("impossible_travel")
            except MCPError as exc:
                log.warning("Phase D get_user_activity: %s", exc)
                result.evidence_gaps.append("User activity data unavailable.")

        # User behaviour baseline vs. current
        if ctx.user:
            spl_baseline = self._build_query(
                f"Show {ctx.user}'s historical logon patterns — hours, source IPs, destinations",
                ctx, "D", "phase_d_user_baseline",
            ).replace("{alert_time}", ctx.latest)
            baseline_events = self._execute_query(spl_baseline, ctx, "D")
            if baseline_events:
                result.events_found += len(baseline_events)
                result.queries_run  += 1
                ctx.queries_executed += 1
                ctx.total_events    += len(baseline_events)
                result.key_findings.append(
                    f"Baseline established: {len(baseline_events)} historical activity records."
                )

        # Privilege escalation / enumeration commands
        spl_priv = self._build_query(
            f"Find whoami, nltest, dsquery, or adfind run by {ctx.user or 'any user'} on {ctx.host}",
            ctx, "D", "phase_d_priv_commands",
        )
        priv_events = self._execute_query(spl_priv, ctx, "D")
        if priv_events:
            result.events_found += len(priv_events)
            result.queries_run  += 1
            ctx.queries_executed += 1
            ctx.total_events    += len(priv_events)
            enum_cmds = list({e.get("process_name", "") for e in priv_events})
            result.key_findings.append(
                f"Enumeration tools: {', '.join(enum_cmds)} (T1069/T1087)"
            )

        # LSASS access — credential dumping
        spl_lsass = self._build_query(
            f"Find processes accessing LSASS memory on {ctx.host}",
            ctx, "D", "phase_d_lsass_access",
        )
        lsass_events = self._execute_query(spl_lsass, ctx, "D")
        if lsass_events:
            result.events_found += len(lsass_events)
            result.queries_run  += 1
            ctx.queries_executed += 1
            ctx.total_events    += len(lsass_events)
            result.key_findings.append(
                f"LSASS access — {len(lsass_events)} event(s); credential dumping likely (T1003.001)"
            )
            ctx.credential_indicators.append("lsass_access")

        # Impossible travel (SPL-based cross-check)
        if ctx.user:
            spl_travel = self._build_query(
                f"Find {ctx.user} authenticating from multiple countries",
                ctx, "D", "phase_d_impossible_travel",
            )
            travel_events = self._execute_query(spl_travel, ctx, "D")
            if travel_events:
                result.events_found += len(travel_events)
                result.queries_run  += 1
                ctx.queries_executed += 1
                for e in travel_events:
                    countries = e.get("countries", "")
                    result.key_findings.append(
                        f"Impossible travel confirmed: {ctx.user} from {countries} (T1078)"
                    )
                    if "impossible_travel" not in ctx.credential_indicators:
                        ctx.credential_indicators.append("impossible_travel")

        result.users_seen = [ctx.user] if ctx.user else []
        result.status = "complete" if result.queries_run >= 2 else "partial"
        return result

    # ------------------------------------------------------------------
    # Phase E — Threat Intel
    # ------------------------------------------------------------------

    def _run_phase_e(self, ctx: InvestigationContext) -> PhaseResult:
        result  = PhaseResult(phase="E", status="failed")
        host_ip = ctx.asset_context.get("ip_address", ctx.host)
        enriched = 0

        # IOC enrichment via MCP (VirusTotal + AbuseIPDB + MISP)
        for ioc in ctx.all_iocs[:_MAX_IOC_ENRICHMENTS]:
            try:
                ti = self._get_mcp().enrich_threat_intel(
                    ioc=ioc["value"],
                    ioc_type=ioc["type"],
                    sources=["virustotal", "abuseipdb", "misp"],
                )
                ctx.mcp_calls += 1
                ctx.record_source("enrich_threat_intel")
                if ti:
                    verdict = ti.get("verdict", "unknown")
                    ioc["verdict"]          = verdict
                    ioc["vt_detections"]    = ti.get("vt_detections", "")
                    ioc["malware_families"] = ti.get("malware_families", [])
                    ioc["campaign"]         = ti.get("campaign", "")
                    result.queries_run  += 1
                    ctx.queries_executed += 1
                    enriched += 1
                    if verdict == "malicious":
                        vt = ioc.get("vt_detections", "")
                        result.key_findings.append(
                            f"Malicious IOC confirmed: {ioc['value'][:40]} ({ioc['type']}) — VT:{vt}"
                        )
                        result.iocs_found.append(ioc)
                        for fam in (ioc.get("malware_families") or []):
                            result.key_findings.append(f"Malware family: {fam}")
            except MCPError as exc:
                log.warning("Phase E enrich_threat_intel (%s): %s", ioc["value"][:20], exc)

        if enriched == 0:
            result.evidence_gaps.append(
                "No IOC enrichment completed; threat intel feeds may be unavailable."
            )

        # DNS beacon pattern detection
        spl_dns = _SPL_TEMPLATES["phase_e_dns_suspicious"].format(
            host_ip=host_ip, earliest=ctx.earliest, latest=ctx.latest
        )
        dns_events = self._execute_query(spl_dns, ctx, "E")
        if dns_events:
            result.events_found += len(dns_events)
            result.queries_run  += 1
            ctx.queries_executed += 1
            ctx.total_events    += len(dns_events)
            for e in dns_events:
                for domain in str(e.get("domains", "")).split(","):
                    d = domain.strip()
                    if d:
                        ctx.add_ioc(d, "domain", "phase_e")
            result.key_findings.append(
                f"DNS query clustering: {len(dns_events)} suspicious pattern(s)"
            )

        # IOC spread — how many hosts have seen the same indicator
        malicious = [i for i in ctx.all_iocs if i.get("verdict") == "malicious"]
        if malicious:
            spread_spl = _SPL_TEMPLATES["phase_e_ioc_spread"].format(
                ioc_value=malicious[0]["value"],
                earliest=ctx.earliest,
                latest=ctx.latest,
            )
            spread_events = self._execute_query(spread_spl, ctx, "E")
            if spread_events:
                result.events_found += len(spread_events)
                result.queries_run  += 1
                ctx.queries_executed += 1
                ctx.total_events    += len(spread_events)
                spread_hosts: List[str] = []
                for e in spread_events:
                    for h in str(e.get("affected_hosts", "")).split(","):
                        h = h.strip()
                        if h:
                            spread_hosts.append(h)
                            ctx.add_host(h)
                if spread_hosts:
                    result.key_findings.append(
                        f"IOC present on {len(set(spread_hosts))} additional host(s) — active campaign"
                    )

        result.status = "complete" if result.queries_run >= 1 else "partial"
        return result

    # ------------------------------------------------------------------
    # Query infrastructure
    # ------------------------------------------------------------------

    def _build_query(
        self,
        question:     str,
        ctx:          InvestigationContext,
        phase:        str,
        template_key: str,
    ) -> str:
        """Generate SPL (SAIA → keyword template → generic fallback)."""
        saia_ctx = {
            "host": ctx.host, "user": ctx.user,
            "classification": ctx.classification,
            "earliest": ctx.earliest, "latest": ctx.latest,
            "phase": phase,
        }
        spl: Optional[str] = None
        if self._circuit_breaker_should_probe():
            try:
                spl = self._run_with_timeout(
                    self._get_saia().generate_spl,
                    question, saia_ctx, phase,
                    op_name=f"SAIA generate_spl (phase {phase})",
                )
            except SherlockTimeoutError as exc:
                log.warning("Phase %s: %s — falling back to SPL templates", phase, exc)
                spl = None
        else:
            log.debug(
                "Phase %s: circuit breaker open — bypassing SAIA, using template '%s'",
                phase, template_key,
            )

        if spl:
            spl = self._validate_and_correct_spl(spl, ctx)
            if spl:
                ctx.record_source(spl)
                return spl

        template = _SPL_TEMPLATES.get(template_key, "")
        if template:
            spl = template.format(
                host=ctx.host,
                user=ctx.user or "*",
                earliest=ctx.earliest,
                latest=ctx.latest,
                host_ip=ctx.asset_context.get("ip_address", ctx.host),
                alert_time=ctx.latest,
                ioc_value="",
            )
            ctx.record_source(spl)
            return spl

        return (
            f'index=* host="{ctx.host}" '
            f'earliest="{ctx.earliest}" latest="{ctx.latest}" | head 100'
        )

    def _execute_query(
        self,
        spl: str,
        ctx: InvestigationContext,
        phase: str,
    ) -> List[Dict]:
        """Validate then execute SPL via MCP; returns result rows."""
        if not spl.strip():
            return []

        # Validate with MCP before execution (non-fatal if validation unavailable)
        try:
            validation = self._run_with_timeout(
                self._get_mcp().validate_spl,
                query=spl, check_indexes=True, estimate_cost=False,
                op_name=f"MCP validate_spl (phase {phase})",
            )
            ctx.mcp_calls += 1
            if not validation.get("valid", True):
                log.warning(
                    "Phase %s SPL validation failed: %s — skipping",
                    phase, validation.get("error", "unknown")
                )
                return []
        except (MCPError, SherlockTimeoutError):
            pass   # validation failure is non-fatal; proceed with execution

        try:
            raw = self._run_with_timeout(
                self._get_mcp().search_spl,
                query=spl,
                earliest=ctx.earliest,
                latest=ctx.latest,
                max_results=500,
                op_name=f"MCP search_spl (phase {phase})",
            )
            ctx.mcp_calls += 1
            ctx.record_source(spl)
            rows = raw if isinstance(raw, list) else raw.get("results", [])
            log.debug("Phase %s query: %d rows", phase, len(rows))
            return rows
        except MCPError as exc:
            log.warning("Phase %s query execution failed: %s", phase, exc)
            return []
        except SherlockTimeoutError as exc:
            log.warning("Phase %s query execution timed out: %s", phase, exc)
            return []

    def _validate_and_correct_spl(
        self,
        spl: str,
        ctx: Optional[InvestigationContext] = None,
    ) -> Optional[str]:
        """
        Call MCP validate_spl().  Returns the SPL unchanged if valid,
        the corrected version if MCP provides one, or None if invalid.
        """
        try:
            validation = self._run_with_timeout(
                self._get_mcp().validate_spl,
                query=spl, check_indexes=True, estimate_cost=False,
                op_name="MCP validate_spl",
            )
            if ctx:
                ctx.mcp_calls += 1
            if validation.get("valid", True):
                return spl
            corrected = validation.get("corrected_query")
            if corrected and corrected != spl:
                log.info("SPL auto-corrected by MCP validate_spl")
                return corrected
            return None
        except (MCPError, SherlockTimeoutError):
            return spl   # treat validation failure as passing

    def _match_template_by_keywords(
        self,
        description: str,
        context: Dict,
    ) -> Optional[str]:
        """Match NL description against keyword groups and fill template."""
        desc_lower = description.lower()
        matched_key: Optional[str] = None

        for keywords, template_key in _NL_KEYWORD_MAP:
            if all(kw in desc_lower for kw in keywords[:1]) and any(
                kw in desc_lower for kw in keywords
            ):
                matched_key = template_key
                break

        if not matched_key:
            return None

        template = _SPL_TEMPLATES.get(matched_key, "")
        if not template:
            return None

        host  = context.get("host", "*")
        user  = context.get("user", "*") or "*"
        early = context.get("earliest", "-2h")
        late  = context.get("latest", "now")

        try:
            return template.format(
                host=host, user=user,
                earliest=early, latest=late,
                host_ip=context.get("host_ip", host),
                alert_time=late,
                ioc_value=context.get("ioc_value", ""),
            )
        except KeyError:
            return template   # return as-is if format keys missing

    # ------------------------------------------------------------------
    # Report synthesis
    # ------------------------------------------------------------------

    def _synthesize_report(
        self,
        ctx:           InvestigationContext,
        phase_results: Dict[str, PhaseResult],
    ) -> Dict:
        model_input = {
            "task": "synthesize_report",
            "system_prompt": self._load_system_prompt(),
            "case_id": ctx.case_id,
            "vanguard_packet": {
                "classification":  ctx.classification,
                "mitre_tactic":    ctx.mitre_tactic,
                "mitre_technique": ctx.mitre_technique,
                "composite_score": ctx.composite_score,
                "key_indicators":  ctx.vanguard_key_indicators,
            },
            "investigation_context": {
                "host":                  ctx.host,
                "user":                  ctx.user,
                "alert_time":            ctx.alert_time_iso,
                "total_events":          ctx.total_events,
                "iocs_found":            len(ctx.all_iocs),
                "lateral_targets":       ctx.lateral_targets,
                "credential_indicators": ctx.credential_indicators,
                "suspicious_processes":  ctx.suspicious_processes,
                "malicious_iocs":        [
                    i for i in ctx.all_iocs if i.get("verdict") == "malicious"
                ],
            },
            "phase_summaries": {
                phase: {
                    "status":        pr.status,
                    "key_findings":  pr.key_findings,
                    "events_found":  pr.events_found,
                    "evidence_gaps": pr.evidence_gaps,
                }
                for phase, pr in phase_results.items()
            },
        }

        model_result = self._call_synthesis_model(model_input)
        if model_result:
            ctx.mcp_calls  # model call not tracked in mcp_calls (different service)
            model_result["model_available"] = True
            return model_result

        fallback = self._fallback_synthesis(ctx, phase_results)
        fallback["model_available"] = False
        return fallback

    def _call_synthesis_model(self, model_input: Dict) -> Optional[Dict]:
        token = self._get_model_token()
        if not token:
            return None
        try:
            resp = requests.post(
                self._get_model_url(),
                json={
                    "inputs":     json.dumps(model_input),
                    "parameters": {"max_new_tokens": 2048, "temperature": 0.1},
                },
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type":  "application/json",
                },
                timeout=_MODEL_TIMEOUT,
                verify=False,
            )
            if resp.status_code != 200:
                log.warning("Synthesis model HTTP %d", resp.status_code)
                return None
            raw     = resp.json()
            outputs = raw.get("outputs", [{}])
            output  = (
                raw.get("generated_text")
                or (outputs[0].get("generated_text", "") if outputs else "")
            ).strip()
            # Strip markdown fences if present
            if output.startswith("```"):
                parts = output.split("```")
                output = parts[2] if len(parts) > 2 else parts[-1]
            parsed = json.loads(output.strip())
            parsed["model_used"] = "foundation-sec-1.1-8b-instruct"
            return parsed
        except (json.JSONDecodeError, KeyError, IndexError) as exc:
            log.warning("Synthesis model parse failed: %s", exc)
            return None
        except Exception as exc:
            log.warning("Synthesis model call failed: %s", exc)
            return None

    def _fallback_synthesis(
        self,
        ctx:           InvestigationContext,
        phase_results: Dict[str, PhaseResult],
    ) -> Dict:
        """Rule-based synthesis from structured phase findings (no model needed)."""
        all_findings: List[str] = []
        all_gaps:     List[str] = []
        for pr in phase_results.values():
            all_findings.extend(pr.key_findings)
            all_gaps.extend(pr.evidence_gaps)

        malware_families: List[str] = []
        campaigns: List[str] = []
        ttp_mapping: List[str] = []
        for ioc in ctx.all_iocs:
            for fam in (ioc.get("malware_families") or []):
                if fam not in malware_families:
                    malware_families.append(fam)
            camp = ioc.get("campaign", "")
            if camp and camp not in campaigns:
                campaigns.append(camp)

        if ctx.mitre_technique:
            ttp_mapping.append(ctx.mitre_technique)
        if "lsass_access" in ctx.credential_indicators:
            ttp_mapping.append("T1003.001")
        if ctx.lateral_targets:
            ttp_mapping.append("T1021.002")
        if any("shadow" in f.lower() for f in all_findings):
            ttp_mapping.append("T1490")
        if any("encoded powershell" in f.lower() for f in all_findings):
            ttp_mapping.append("T1059.001")

        has_lateral   = bool(ctx.lateral_targets)
        has_cred_dump = "lsass_access" in ctx.credential_indicators
        is_ransomware = ctx.classification.startswith("RANSOMWARE")

        # Executive summary
        summary_parts = [
            f"{ctx.classification.replace('_', ' ').title()} detected on {ctx.host}."
        ]
        if malware_families:
            summary_parts[0] = f"{malware_families[0]} detected on {ctx.host}."
        if ctx.user:
            summary_parts.append(f"Affected user: {ctx.user}.")
        if has_lateral:
            summary_parts.append(
                f"Lateral movement confirmed to {len(ctx.lateral_targets)} host(s): "
                + ", ".join(ctx.lateral_targets[:3]) + "."
            )
        if has_cred_dump:
            summary_parts.append("Credential theft (LSASS) confirmed.")
        if all_findings:
            summary_parts.append(all_findings[0])

        # Confidence scores
        base_conf = min(0.95, 0.50
                        + len(all_findings) * 0.03
                        + len(ctx.all_iocs) * 0.02
                        + (0.10 if has_cred_dump else 0)
                        + (0.05 if has_lateral   else 0))
        host_conf = min(0.99, base_conf + 0.05) if all_findings else base_conf
        malf_conf = 0.90 if malware_families else 0.25
        lat_conf  = 0.89 if has_lateral else 0.10
        exfil_conf = 0.72 if any("exfil" in f.lower() or "large" in f.lower() for f in all_findings) else 0.30

        # Recommended actions — include urgency per system prompt schema
        actions: List[Dict] = []
        pri = 1
        if is_ransomware or has_cred_dump:
            actions.append({
                "priority": pri, "action": "isolate_host", "target": ctx.host,
                "justification": (
                    "Confirmed ransomware execution" if is_ransomware
                    else "Confirmed credential theft via LSASS access"
                ),
                "urgency": "immediate",
            })
            pri += 1
        if ctx.user and (has_cred_dump or "impossible_travel" in ctx.credential_indicators):
            actions.append({
                "priority": pri, "action": "disable_user", "target": ctx.user,
                "justification": "Compromised credentials confirmed; account must be suspended.",
                "urgency": "immediate",
            })
            pri += 1
        for tgt in ctx.lateral_targets[:3]:
            actions.append({
                "priority": pri, "action": "isolate_host", "target": tgt,
                "justification": f"Lateral movement target from {ctx.host}; at immediate risk.",
                "urgency": "within_1h",
            })
            pri += 1
        for ioc in ctx.all_iocs:
            if ioc.get("verdict") == "malicious" and ioc.get("type") == "ip":
                actions.append({
                    "priority": pri, "action": "block_ip", "target": ioc["value"],
                    "justification": f"C2 server confirmed malicious (VT: {ioc.get('vt_detections','')}).",
                    "urgency": "within_1h",
                })
                pri += 1
                break
        actions.append({
            "priority": pri, "action": "create_ticket", "target": "ServiceNow",
            "justification": "P1 security incident requires formal documentation and tracking.",
            "urgency": "within_4h",
        })

        # Attack narrative (rule-based)
        narrative_parts = [f"Investigation of {ctx.case_id} identified {ctx.classification.replace('_', ' ').lower()} activity on host {ctx.host}."]
        if ctx.vanguard_key_indicators:
            narrative_parts.append(f"Key initial indicators: {'; '.join(ctx.vanguard_key_indicators[:3])}.")
        if has_cred_dump:
            narrative_parts.append("LSASS process memory was accessed, indicating active credential theft.")
        if has_lateral:
            narrative_parts.append(
                f"Lateral movement was observed targeting {len(ctx.lateral_targets)} adjacent host(s): "
                + ", ".join(ctx.lateral_targets[:3]) + "."
            )
        if any("shadow" in f.lower() for f in all_findings):
            narrative_parts.append("Volume shadow copies were deleted, a ransomware pre-encryption step (T1490).")

        # False positive probability
        fp_prob = round(max(0.01, 0.50
                            - len(all_findings) * 0.04
                            - len([i for i in ctx.all_iocs if i.get("verdict") == "malicious"]) * 0.05
                            - (0.10 if has_cred_dump else 0)
                            - (0.10 if "impossible_travel" in ctx.credential_indicators else 0)), 2)

        return {
            "executive_summary": " ".join(summary_parts),
            "attack_narrative": " ".join(narrative_parts),
            "threat_assessment": {
                "malware_family":      malware_families[0] if malware_families else "Unknown",
                "threat_actor":        "Unknown",
                "actor_sophistication": (
                    "advanced_criminal" if malware_families else "unknown"
                ),
                "confidence":          round(malf_conf, 2),
                "ttp_mapping":         list(dict.fromkeys(ttp_mapping)),
                "campaign":            campaigns[0] if campaigns else "Unknown variant",
                "campaign_notes":      (
                    f"Associated campaign: {campaigns[0]}" if campaigns
                    else "No campaign attribution available from current threat intel."
                ),
            },
            "recommended_actions": actions,
            "confidence_assessment": {
                "overall":           round(base_conf, 2),
                "initial_access":    round(min(0.95, base_conf + 0.05 if ctx.vanguard_key_indicators else base_conf), 2),
                "host_compromise":   round(host_conf, 2),
                "malware_family":    round(malf_conf, 2),
                "lateral_movement":  round(lat_conf,  2),
                "data_exfiltration": round(exfil_conf, 2),
                "data_impact":       round(exfil_conf, 2),
                "notes": (
                    f"Confidence driven by {len(all_findings)} phase findings and "
                    f"{len([i for i in ctx.all_iocs if i.get('verdict') == 'malicious'])} confirmed malicious IOC(s). "
                    + (f"Gaps: {'; '.join(all_gaps[:2])}." if all_gaps else "Coverage appears adequate.")
                ),
            },
            "evidence_gaps":              list(dict.fromkeys(all_gaps))[:8],
            "false_positive_probability": fp_prob,
            "model_used":                 "fallback_rule_based",
        }

    # ------------------------------------------------------------------
    # Blast radius builder (internal — used by run())
    # ------------------------------------------------------------------

    def _build_blast_radius(
        self,
        ctx:           InvestigationContext,
        phase_results: Dict[str, PhaseResult],
    ) -> BlastRadius:
        blast = BlastRadius()

        # Primary host: confirmed compromised if phases A or B found evidence
        pa = phase_results.get("A")
        pb = phase_results.get("B")
        if (pa and pa.key_findings) or (pb and pb.key_findings):
            if ctx.host:
                blast.compromised_hosts.append(ctx.host)
        elif ctx.host:
            blast.targeted_hosts.append(ctx.host)

        # Lateral movement targets — differentiate confirmed (targeted_hosts) vs unknown outcome
        for target in ctx.lateral_targets:
            if target not in blast.compromised_hosts and target not in blast.targeted_hosts:
                blast.targeted_hosts.append(target)

        # Additional hosts from phase results with unknown compromise status → suspected
        for pr in phase_results.values():
            for h in pr.hosts_seen:
                if (h and h != ctx.host
                        and h not in blast.compromised_hosts
                        and h not in blast.targeted_hosts
                        and h not in blast.suspected_hosts):
                    blast.suspected_hosts.append(h)

        # Users
        if ctx.user:
            blast.compromised_users.append(ctx.user)

        # Affected services from asset context
        services = ctx.asset_context.get("services", [])
        if isinstance(services, list):
            blast.affected_services = services[:5]

        # Data at risk
        has_cred = "lsass_access" in ctx.credential_indicators
        if ctx.classification in ("DATA_EXFILTRATION", "INSIDER_THREAT"):
            blast.data_at_risk = "Sensitive data access confirmed; exfiltration volume unknown."
        elif has_cred:
            blast.data_at_risk = (
                "Active Directory credentials at risk; assume all domain accounts compromised."
            )
        elif ctx.classification.startswith("RANSOMWARE"):
            blast.data_at_risk = (
                "File encryption in progress or imminent; backup integrity at risk."
            )
        else:
            blast.data_at_risk = "Data impact undetermined; further investigation required."

        # Estimated dwell time: earliest event in timeline vs detection (alert) time
        if ctx.timeline_events:
            try:
                earliest_event_epoch = min(
                    (
                        int(float(e.get("_time", ctx.alert_epoch_ms / 1000)) * 1000)
                        for e in ctx.timeline_events
                        if e.get("_time")
                    ),
                    default=ctx.alert_epoch_ms,
                )
                dwell_ms = ctx.alert_epoch_ms - earliest_event_epoch
                blast.estimated_dwell_time_minutes = max(0, dwell_ms // 60000)
            except Exception:
                pass

        return blast

    # ------------------------------------------------------------------
    # Timeline builder
    # ------------------------------------------------------------------

    def _build_timeline(
        self,
        ctx:           InvestigationContext,
        phase_results: Dict[str, PhaseResult],
    ) -> List[TimelineEvent]:
        events: List[TimelineEvent] = []

        # Raw events from data sources
        for raw in ctx.timeline_events[:150]:
            try:
                raw_time = raw.get("_time") or raw.get("event_time", "")
                if isinstance(raw_time, (int, float)):
                    epoch_ms = int(float(raw_time) * 1000)
                    dt = datetime.fromtimestamp(float(raw_time), tz=timezone.utc)
                else:
                    dt = datetime.fromisoformat(str(raw_time).replace("Z", "+00:00"))
                    epoch_ms = int(dt.timestamp() * 1000)

                source = str(raw.get("sourcetype", "unknown")).split(":")[-1]
                desc   = (
                    raw.get("action")
                    or raw.get("process_name")
                    or raw.get("event_description")
                    or str(raw)[:80]
                )
                events.append(TimelineEvent(
                    time_hms=dt.strftime("%H:%M:%S"),
                    epoch_ms=epoch_ms,
                    event=str(desc),
                    source=source,
                ))
            except Exception:
                continue

        # Synthetic milestone events from phase key findings
        alert_dt = datetime.fromtimestamp(ctx.alert_epoch_ms / 1000, tz=timezone.utc)
        for phase_name, pr in phase_results.items():
            for finding in pr.key_findings[:2]:
                events.append(TimelineEvent(
                    time_hms=alert_dt.strftime("%H:%M:%S"),
                    epoch_ms=ctx.alert_epoch_ms,
                    event=finding,
                    source=f"sherlock:phase_{phase_name.lower()}",
                    technique=ctx.mitre_technique,
                ))

        events.sort(key=lambda e: e.epoch_ms)
        return events

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    def _detect_suspicious_chains(self, process_tree: List[Dict]) -> List[str]:
        findings: List[str] = []
        for node in process_tree:
            parent = (node.get("parent_process_name") or "").lower()
            child  = (node.get("process_name")        or "").lower()
            for sus_parent, sus_child in _SUSPICIOUS_CHAINS:
                if parent == sus_parent and child == sus_child:
                    findings.append(
                        f"Suspicious process chain: {parent} → {child} (T1059)"
                    )
        return findings


# ---------------------------------------------------------------------------
# Module-level entry point  (orchestrator _AgentProxy interface)
# ---------------------------------------------------------------------------

def run(case: Any, audit: Optional[AuditLogger] = None, **_kwargs) -> Dict:
    """Run Sherlock on a Case and return SherlockInvestigationReport as dict."""
    return SherlockAgent().run(case, audit or get_audit_logger(_AGENT_NAME))

