"""
SENTINEL: Autonomous Agentic SOC Commander
agent_sage.py — The Learning Agent

SageAgent closes the feedback loop: it analyses closed cases, measures agent
and detection-rule performance, harvests threat intelligence, proposes new
detection rules, and tunes Vanguard/Sherlock/Executor parameters — all fully
automated.

Scheduled runs:
  Daily  06:00 — Detection efficacy analysis + IOC harvest + per-case learning
  Weekly Monday 06:00 — Full performance report + threshold self-tuning

Public API:
  SageAgent.run(case, audit)                     -> dict   (per-case, orchestrator entry)
  SageAgent.run_scheduled(mode, audit)            -> dict   (daily/weekly cron)
  SageAgent.analyze_detection_efficacy(timeframe) -> EfficacyReport
  SageAgent.propose_detection_rule(case_data)     -> ProposedRule
  SageAgent.generate_weekly_report()              -> WeeklyReport

Models:
  Foundation-Sec-1.1-8B  -- recommendation synthesis + analysis narrative
  Cisco Deep Time Series  -- anomaly detection, threshold optimisation, trend analysis
  SAIA                    -- natural-language -> SPL for proposed rules

Dependencies: requests, standard library
"""

from __future__ import annotations

import json
import logging
import math
import os
import re
import sys
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

_BIN_DIR = Path(__file__).resolve().parent
if str(_BIN_DIR) not in sys.path:
    sys.path.insert(0, str(_BIN_DIR))

from audit_logger import AuditLogger, get_audit_logger
from mcp_client import SplunkMCPClient, MCPError
from utils.config_loader import get_config

log = logging.getLogger("sentinel.sage")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_AGENT_NAME           = "sage"
_ENV_MODEL_TOKEN      = "SENTINEL_HOSTED_MODEL_TOKEN"
_ENV_SPLUNK_HOST      = "SENTINEL_SPLUNK_HOST"
_ENV_SPLUNK_PORT      = "SENTINEL_SPLUNK_PORT"
_ENV_SPLUNK_SCHEME    = "SENTINEL_SPLUNK_SCHEME"
_ENV_TI_URL           = "SENTINEL_TI_URL"
_ENV_TI_TOKEN         = "SENTINEL_TI_TOKEN"
_ENV_SAIA_TOKEN       = "SENTINEL_SAIA_TOKEN"
_ENV_CISCO_TS_URL     = "SENTINEL_CISCO_TS_URL"
_ENV_CISCO_TS_TOKEN   = "SENTINEL_CISCO_TS_TOKEN"

_SYSTEM_PROMPT_PATH = (
    Path(__file__).resolve().parent.parent.parent.parent
    / "models" / "prompts" / "sage_system_prompt.txt"
)

# Analysis windows
_DEFAULT_EFFICACY_WINDOW    = "7d"
_BACKTEST_WINDOW            = "90d"
_TREND_COMPARISON_WEEKS     = 4

# Decision thresholds for proposed rules
_MAX_FP_RATE_FOR_PRODUCTION = 0.05    # 5 %
_MAX_QUERY_TIME_S           = 30.0

# Self-tuning guard rails
_MAX_THRESHOLD_DELTA        = 5       # composite score points per cycle
_MIN_VANGUARD_DISMISS       = 10
_MAX_VANGUARD_DISMISS       = 50

# Industry baseline MTTR (hours) used in improvement-factor calculation
_INDUSTRY_BASELINE_MTTR_H   = 4.2

# Cost model
_ANALYST_HOURLY_RATE_USD    = 85
_ANALYST_TIME_PER_CASE_H    = 1.0    # assumed hours saved per autonomous case

# SPL query templates
_SPL_CLOSED_CASES = (
    'index=sentinel_cases status=CLOSED earliest="{earliest}" latest="now" '
    '| stats count AS total_cases, '
    '  sum(eval(resolution="FALSE_POSITIVE")) AS fp_count, '
    '  sum(eval(resolution!="FALSE_POSITIVE" AND isnotnull(resolution))) AS tp_count, '
    '  avg(risk_score) AS avg_score, '
    '  avg(eval(updated_time-created_time)) AS avg_mttr_s '
    '  BY alert_type'
)

_SPL_MTTR_BREAKDOWN = (
    'index=sentinel_audit event_type=transition earliest="{earliest}" latest="now" '
    '| stats avg(eval(if(to_status="INVESTIGATING",latency_ms,null()))) AS triage_ms, '
    '  avg(eval(if(to_status="DECIDING",latency_ms,null()))) AS investigation_ms, '
    '  avg(eval(if(to_status="LEARNING",latency_ms,null()))) AS response_ms '
    '  BY case_id '
    '| stats avg(triage_ms) AS avg_triage_ms, '
    '  avg(investigation_ms) AS avg_investigation_ms, '
    '  avg(response_ms) AS avg_response_ms'
)

_SPL_AGENT_DECISIONS = (
    'index=sentinel_audit event_type=decision earliest="{earliest}" latest="now" '
    '| stats count AS decisions, '
    '  avg(confidence) AS avg_confidence, '
    '  avg(latency_ms) AS avg_latency_ms '
    '  BY agent_name'
)

_SPL_IOC_HARVEST = (
    'index=sentinel_audit event_type=decision agent_name=sherlock '
    'earliest="{earliest}" latest="now" '
    '| spath input=output_decision '
    '| mvexpand iocs_discovered '
    '| spath input=iocs_discovered '
    '| where verdict="malicious" OR verdict="suspicious" '
    '| stats count BY ioc_value, ioc_type, verdict '
    '| sort -count | head 200'
)

_SPL_RULE_WEEKLY_COUNTS = (
    'index=sentinel_cases earliest="-{weeks}w" latest="now" '
    '| eval week=strftime(_time, "%Y-%W") '
    '| stats count AS weekly_cases BY week, alert_type '
    '| sort week'
)

_SPL_BACKTEST = (
    '{proposed_spl} '
    '| eval week=strftime(_time,"%Y-%W") '
    '| stats count AS matches, dc(host) AS unique_hosts BY week '
    '| sort week'
)

_SPL_HISTORICAL_TP = (
    'index=sentinel_cases status=CLOSED resolution!=FALSE_POSITIVE '
    'alert_type="{alert_type}" earliest="-{days}d" latest="now" '
    '| stats count BY alert_type'
)

# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class SageError(Exception):
    """Base Sage exception."""

class SageQueryError(SageError):
    """SPL query failed."""

class SageModelError(SageError):
    """Model call failed."""

# ---------------------------------------------------------------------------
# Built-in time-series analysis (zero external dependencies)
# ---------------------------------------------------------------------------

class _TimeSeries:
    """
    Lightweight statistical time-series toolkit.
    All methods accept plain Python lists of floats.
    """

    @staticmethod
    def moving_average(series: List[float], window: int = 3) -> List[float]:
        result: List[float] = []
        for i in range(len(series)):
            start = max(0, i - window + 1)
            chunk = series[start : i + 1]
            result.append(sum(chunk) / len(chunk))
        return result

    @staticmethod
    def linear_trend(series: List[float]) -> Tuple[float, float, float]:
        """Return (slope, intercept, r_squared) via OLS."""
        n = len(series)
        if n < 2:
            return 0.0, (series[0] if series else 0.0), 0.0
        xs = list(range(n))
        x_mean = sum(xs) / n
        y_mean = sum(series) / n
        ss_xy = sum((x - x_mean) * (y - y_mean) for x, y in zip(xs, series))
        ss_xx = sum((x - x_mean) ** 2 for x in xs)
        if ss_xx == 0:
            return 0.0, y_mean, 0.0
        slope     = ss_xy / ss_xx
        intercept = y_mean - slope * x_mean
        y_pred    = [slope * x + intercept for x in xs]
        ss_res = sum((y - yp) ** 2 for y, yp in zip(series, y_pred))
        ss_tot = sum((y - y_mean) ** 2 for y in series)
        r_sq   = 1.0 - (ss_res / ss_tot) if ss_tot > 0 else 0.0
        return round(slope, 4), round(intercept, 4), round(r_sq, 4)

    @staticmethod
    def z_scores(series: List[float]) -> List[float]:
        n = len(series)
        if n < 2:
            return [0.0] * n
        mean     = sum(series) / n
        variance = sum((x - mean) ** 2 for x in series) / n
        std      = math.sqrt(variance) if variance > 0 else 1.0
        return [round((x - mean) / std, 3) for x in series]

    @staticmethod
    def detect_anomalies(series: List[float], threshold: float = 2.0) -> List[bool]:
        return [abs(z) > threshold for z in _TimeSeries.z_scores(series)]

    @staticmethod
    def forecast_linear(series: List[float], horizon: int = 1) -> List[float]:
        slope, intercept, _ = _TimeSeries.linear_trend(series)
        n = len(series)
        return [round(slope * (n + i) + intercept, 2) for i in range(horizon)]

    @staticmethod
    def compare_windows(series: List[float], window: int) -> Dict:
        if len(series) < window * 2:
            window = max(1, len(series) // 2)
        recent   = series[-window:] if series else []
        previous = series[-window * 2 : -window] if len(series) >= window * 2 else recent
        prev_mean   = sum(previous) / len(previous) if previous else 0.0
        recent_mean = sum(recent)   / len(recent)   if recent   else 0.0
        if prev_mean == 0:
            pct_change = 100.0 if recent_mean > 0 else 0.0
        else:
            pct_change = round((recent_mean - prev_mean) / prev_mean * 100, 1)
        direction = (
            "increasing" if pct_change >  5 else
            "decreasing" if pct_change < -5 else "stable"
        )
        return {
            "previous_mean": round(prev_mean,   2),
            "recent_mean":   round(recent_mean, 2),
            "pct_change":    pct_change,
            "direction":     direction,
        }

    @staticmethod
    def optimize_threshold(
        scores: List[float],
        labels: List[int],           # 1 = TP, 0 = FP
        target_tpr: float = 0.90,
    ) -> Tuple[float, Dict]:
        """
        Sweep score thresholds descending; return the lowest threshold that
        still achieves `target_tpr` while minimising FPR.
        """
        if not scores or not labels:
            return 50.0, {}
        total_pos = sum(labels)
        total_neg = len(labels) - total_pos
        if total_pos == 0 or total_neg == 0:
            return 50.0, {}

        pairs     = sorted(zip(scores, labels), reverse=True)
        best_thr  = scores[0]
        best_fpr  = 1.0
        best_meta: Dict = {}

        for i, (score, _) in enumerate(pairs):
            above  = pairs[: i + 1]
            tp     = sum(l for _, l in above)
            fp     = len(above) - tp
            tpr    = tp / total_pos
            fpr    = fp / total_neg if total_neg else 0.0
            if tpr >= target_tpr and fpr < best_fpr:
                best_fpr  = fpr
                best_thr  = score
                best_meta = {
                    "threshold": round(score, 1),
                    "tpr":       round(tpr, 3),
                    "fpr":       round(fpr, 3),
                    "precision": round(tp / (tp + fp), 3) if (tp + fp) else 0.0,
                    "f1":        round(
                        2 * tp / (2 * tp + fp + (total_pos - tp)), 3
                    ) if (2 * tp + fp + (total_pos - tp)) else 0.0,
                }
        return round(best_thr, 1), best_meta

# ---------------------------------------------------------------------------
# Cisco Deep Time Series Model client
# ---------------------------------------------------------------------------

class _CiscoTimeSeriesClient:
    """
    Client for Cisco's Deep Time Series Model.
    Falls back to _TimeSeries built-ins when the endpoint is unavailable.
    """

    _PATH    = "/v1/time-series/analyze"
    _TIMEOUT = 20

    def __init__(self, base_url: str = "", token: str = "") -> None:
        self._base_url  = base_url.rstrip("/") if base_url else ""
        self._token     = token
        self._available: Optional[bool] = None
        session = requests.Session()
        adapter = HTTPAdapter(max_retries=Retry(total=2, backoff_factor=0.5))
        session.mount("https://", adapter)
        session.mount("http://",  adapter)
        self._session = session

    def _is_available(self) -> bool:
        if not self._base_url or not self._token:
            return False
        if self._available is not None:
            return self._available
        try:
            resp = self._session.get(
                f"{self._base_url}/health",
                headers={"Authorization": f"Bearer {self._token}"},
                timeout=5.0,
                verify=False,
            )
            self._available = resp.ok
        except Exception:
            self._available = False
        return self._available  # type: ignore[return-value]

    def _post(self, payload: Dict) -> Optional[Dict]:
        try:
            resp = self._session.post(
                self._base_url + self._PATH,
                json=payload,
                headers={"Authorization": f"Bearer {self._token}"},
                timeout=self._TIMEOUT,
                verify=False,
            )
            return resp.json() if resp.ok else None
        except Exception as exc:
            log.debug("Cisco TS model error: %s", exc)
            return None

    def forecast_anomaly(
        self,
        series:  List[float],
        labels:  Optional[List[str]] = None,
        horizon: int = 1,
    ) -> Dict:
        if self._is_available():
            result = self._post({"task": "anomaly_forecast", "series": series,
                                 "labels": labels or [], "horizon": horizon})
            if result:
                return result
        anomalies = _TimeSeries.detect_anomalies(series)
        forecast  = _TimeSeries.forecast_linear(series, horizon)
        slope, _, r_sq = _TimeSeries.linear_trend(series)
        return {
            "anomalies":       anomalies,
            "anomaly_indices": [i for i, a in enumerate(anomalies) if a],
            "forecast":        forecast,
            "trend_slope":     slope,
            "r_squared":       r_sq,
            "model":           "builtin_linear",
            "confidence":      r_sq,
        }

    def optimize_threshold(
        self,
        scores: List[float],
        labels: List[int],
        target_tpr: float = 0.90,
    ) -> Dict:
        if self._is_available():
            result = self._post({"task": "threshold_optimization",
                                 "scores": scores, "labels": labels,
                                 "target_tpr": target_tpr})
            if result:
                return result
        thresh, metrics = _TimeSeries.optimize_threshold(scores, labels, target_tpr)
        return {"optimal_threshold": thresh, "metrics": metrics, "model": "builtin_sweep"}

    def analyze_trend(
        self,
        series:             List[float],
        comparison_window:  int = 4,
    ) -> Dict:
        if self._is_available():
            result = self._post({"task": "trend_analysis", "series": series,
                                 "comparison_window": comparison_window})
            if result:
                return result
        window_analysis    = _TimeSeries.compare_windows(series, comparison_window)
        slope, _, r_sq     = _TimeSeries.linear_trend(series)
        return {**window_analysis, "slope": slope, "r_squared": r_sq,
                "model": "builtin_regression"}

# ---------------------------------------------------------------------------
# SAIA client (inline — avoids circular import with agent_sherlock)
# ---------------------------------------------------------------------------

class _SAIAClient:
    """Splunk AI Assistant — natural language -> SPL generation."""

    _PATH    = "/services/assistant/v1/generate"
    _TIMEOUT = 30

    def __init__(self, host: str, port: int, token: str,
                 scheme: str = "https", verify_ssl: bool = False) -> None:
        self._base_url = f"{scheme}://{host}:{port}"
        self._token    = token
        self._verify   = verify_ssl
        session = requests.Session()
        adapter = HTTPAdapter(max_retries=Retry(total=2, backoff_factor=0.5))
        session.mount("https://", adapter)
        session.mount("http://",  adapter)
        self._session = session

    def generate_spl(self, question: str, context: Optional[Dict] = None) -> Optional[str]:
        if not self._token:
            return None
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
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class RuleMetrics:
    rule_name:          str
    alert_type:         str
    total_alerts:       int
    true_positives:     int
    false_positives:    int
    tp_rate:            float
    fp_rate:            float
    avg_risk_score:     float
    avg_ttd_minutes:    float
    trend:              str          # increasing / stable / decreasing
    trend_pct_change:   float
    anomaly_this_week:  bool
    recommended_action: str          # maintain, tune_exclusions, lower_threshold, raise_threshold, retire

    def to_dict(self) -> Dict:
        return {k: v for k, v in self.__dict__.items()}


@dataclass
class EfficacyReport:
    timeframe:           str
    generated_at:        str
    total_cases:         int
    overall_tp_rate:     float
    overall_fp_rate:     float
    avg_triage_s:        float
    avg_investigation_s: float
    avg_response_s:      float
    total_mttr_minutes:  float
    rules:               List[RuleMetrics] = field(default_factory=list)
    agent_metrics:       Dict              = field(default_factory=dict)
    anomalous_rules:     List[str]         = field(default_factory=list)
    summary:             str               = ""

    def to_dict(self) -> Dict:
        d = {k: v for k, v in self.__dict__.items() if k != "rules"}
        d["rules"] = [r.to_dict() for r in self.rules]
        return d


@dataclass
class IoC:
    value:     str
    ioc_type:  str       # ip, domain, sha256, md5, cmdline
    source:    str       # case_id
    verdict:   str       # malicious, suspicious
    submitted: bool = False
    confirmed: bool = False

    def to_dict(self) -> Dict:
        return {k: v for k, v in self.__dict__.items()}


@dataclass
class ProposedRule:
    rule_id:                 str
    rule_name:               str
    alert_type:              str
    description:             str
    spl:                     str
    rationale:               str
    backtest_tp_count:       int
    backtest_fp_count:       int
    backtest_fp_rate:        float
    backtest_query_time_s:   float
    proposed_for_production: bool
    rejection_reason:        str
    generated_at:            str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict:
        return {k: v for k, v in self.__dict__.items()}


@dataclass
class TuningParameters:
    vanguard_auto_dismiss_threshold:  int
    vanguard_auto_escalate_threshold: int
    executor_require_approval_below:  int
    sherlock_investigation_depth:     int       # 1=shallow  2=standard  3=deep
    rationale:                        str
    previous_values:                  Dict
    updated_at:                       str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict:
        return {k: v for k, v in self.__dict__.items()}


@dataclass
class WeeklyReport:
    report_period:          str
    cases_processed:        int
    autonomous_resolutions: int
    human_escalations:      int
    metrics:                Dict = field(default_factory=dict)
    detection_improvements: Dict = field(default_factory=dict)
    threat_intel:           Dict = field(default_factory=dict)
    cost_savings:           Dict = field(default_factory=dict)
    recommendations:        List[str] = field(default_factory=list)
    tuning_applied:         Dict = field(default_factory=dict)
    agent_performance:      Dict = field(default_factory=dict)
    generated_at:           str  = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict:
        return {k: v for k, v in self.__dict__.items()}

# ---------------------------------------------------------------------------
# SageAgent
# ---------------------------------------------------------------------------

class SageAgent:
    """Learning agent — closes the feedback loop for the SENTINEL pipeline."""

    AGENT_NAME = "sage"

    def __init__(
        self,
        mcp:    Optional[SplunkMCPClient] = None,
        config: Any = None,
    ) -> None:
        self._cfg          = config or get_config()
        self._mcp          = mcp
        self._prompt:      Optional[str]                  = None
        self._ts_client:   Optional[_CiscoTimeSeriesClient] = None
        self._saia_client: Optional[_SAIAClient]          = None

    # ------------------------------------------------------------------
    # Lazy accessors
    # ------------------------------------------------------------------

    def _get_mcp(self) -> SplunkMCPClient:
        if self._mcp is None:
            self._mcp = SplunkMCPClient(agent_name=self.AGENT_NAME)
        return self._mcp

    def _get_ts(self) -> _CiscoTimeSeriesClient:
        if self._ts_client is None:
            url   = os.environ.get(_ENV_CISCO_TS_URL,
                       self._cfg.get("cisco_ts", "url",   default=""))
            token = os.environ.get(_ENV_CISCO_TS_TOKEN,
                       self._cfg.get("cisco_ts", "token", default=""))
            self._ts_client = _CiscoTimeSeriesClient(url, token)
        return self._ts_client

    def _get_saia(self) -> _SAIAClient:
        if self._saia_client is None:
            host   = os.environ.get(_ENV_SPLUNK_HOST,
                        self._cfg.get("splunk", "host",   default="localhost"))
            port   = int(os.environ.get(_ENV_SPLUNK_PORT,
                        self._cfg.get("splunk", "port",   default="8089")))
            scheme = os.environ.get(_ENV_SPLUNK_SCHEME,
                        self._cfg.get("splunk", "scheme", default="https"))
            token  = os.environ.get(_ENV_SAIA_TOKEN,
                        self._cfg.get("saia",   "token",  default=""))
            self._saia_client = _SAIAClient(
                host=host, port=port, token=token, scheme=scheme
            )
        return self._saia_client

    def _load_system_prompt(self) -> str:
        if self._prompt is None:
            try:
                self._prompt = _SYSTEM_PROMPT_PATH.read_text(encoding="utf-8")
            except Exception as exc:
                log.warning("Could not load sage system prompt: %s", exc)
                self._prompt = (
                    "You are Sage, the SENTINEL learning agent. "
                    "Analyse security case data and respond with valid JSON only."
                )
        return self._prompt

    def _get_model_url(self) -> str:
        scheme = os.environ.get(_ENV_SPLUNK_SCHEME,
                    self._cfg.get("splunk", "scheme", default="https"))
        host   = os.environ.get(_ENV_SPLUNK_HOST,
                    self._cfg.get("splunk", "host",   default="localhost"))
        port   = int(os.environ.get(_ENV_SPLUNK_PORT,
                    self._cfg.get("splunk", "port",   default="8089")))
        return (
            f"{scheme}://{host}:{port}"
            "/services/ml/models/foundation-sec-1.1-8b-instruct/predict"
        )

    def _get_model_token(self) -> str:
        return os.environ.get(
            _ENV_MODEL_TOKEN,
            self._cfg.get("hosted_models", "api_token", default=""),
        )

    # ------------------------------------------------------------------
    # Orchestrator entry point — per-case
    # ------------------------------------------------------------------

    def run(self, case: Any, audit: AuditLogger) -> Dict:
        """
        Called by the orchestrator after every case reaches CLOSED state.
        Extracts learning signals, harvests IOCs, records case metrics.
        """
        t0      = int(time.time() * 1000)
        case_id = case.case_id
        log.info(
            "Sage: learning from case=%s classification=%s resolution=%s",
            case_id,
            getattr(case, "classification", "UNKNOWN"),
            getattr(case, "resolution", "UNKNOWN"),
        )

        result: Dict = {
            "case_id":        case_id,
            "iocs_harvested": 0,
            "iocs_submitted": 0,
            "metrics_stored": False,
            "rule_proposed":  False,
            "timestamp":      datetime.now(timezone.utc).isoformat(),
        }

        sherlock = getattr(case, "sherlock_report",   None) or {}
        executor = getattr(case, "executor_actions",  None) or {}
        vanguard = getattr(case, "vanguard_decision", None) or {}

        # 1. Harvest and submit IOCs
        iocs = self._extract_iocs_from_case(case, sherlock)
        if iocs:
            submitted = self._submit_threat_intel(iocs, audit, case_id)
            result["iocs_harvested"] = len(iocs)
            result["iocs_submitted"] = submitted

        # 2. Record case performance metrics to sentinel_learning
        metrics_ok = self._record_case_metrics(case, sherlock, executor, vanguard, audit)
        result["metrics_stored"] = metrics_ok

        # 3. Propose a detection rule if novel + high-confidence
        resolution  = getattr(case, "resolution", "")
        confidence  = float(vanguard.get("confidence", 0.0))

        if (resolution not in ("FALSE_POSITIVE", "SUPPRESSED")
                and confidence >= 0.85
                and sherlock.get("recommended_actions")):
            proposed = self._maybe_propose_rule(case, sherlock, audit)
            if proposed:
                result["rule_proposed"]    = True
                result["proposed_rule_id"] = proposed.rule_id

        total_ms = int(time.time() * 1000) - t0
        result["duration_ms"] = total_ms

        audit.log_decision(
            case_id=case_id,
            decision_type="LEARNING_COMPLETE",
            confidence=1.0,
            input_context={
                "iocs_found": len(iocs),
                "resolution": resolution,
            },
            output_decision=result,
            reasoning=(
                f"Learning cycle complete: {len(iocs)} IOCs harvested, "
                f"metrics stored={metrics_ok}"
            ),
            latency_ms=total_ms,
        )
        log.info(
            "Sage per-case complete: case=%s iocs=%d submitted=%d duration=%dms",
            case_id, result["iocs_harvested"], result["iocs_submitted"], total_ms,
        )
        return result

    # ------------------------------------------------------------------
    # Scheduled runs
    # ------------------------------------------------------------------

    def run_scheduled(
        self,
        mode:  str = "daily",
        audit: Optional[AuditLogger] = None,
    ) -> Dict:
        """
        Entry point for cron-triggered analysis.
        mode='daily'  - efficacy analysis + IOC harvest (06:00 every day)
        mode='weekly' - full performance report + self-tuning (06:00 Monday)
        """
        audit  = audit or get_audit_logger(self.AGENT_NAME)
        t0     = int(time.time() * 1000)
        result: Dict = {"mode": mode, "timestamp": datetime.now(timezone.utc).isoformat()}
        log.info("Sage scheduled run: mode=%s", mode)

        if mode in ("daily", "weekly"):
            efficacy = self.analyze_detection_efficacy("7d")
            result["efficacy"] = efficacy.to_dict()
            self._publish_to_learning_index("efficacy_report", efficacy.to_dict(), audit)
            audit.log_metric(
                case_id="scheduled",
                metric_name="sage_overall_fp_rate",
                value=efficacy.overall_fp_rate,
                unit="ratio",
            )

        if mode == "weekly":
            weekly = self.generate_weekly_report()
            result["weekly_report"] = weekly.to_dict()
            self._publish_to_learning_index("weekly_report", weekly.to_dict(), audit)

            # Self-tuning
            tuning = self._compute_tuning_parameters(efficacy)  # type: ignore[possibly-undefined]
            if tuning:
                self._apply_tuning_parameters(tuning, audit)
                result["tuning"] = tuning.to_dict()

            audit.log_decision(
                case_id="scheduled",
                decision_type="WEEKLY_REPORT_GENERATED",
                confidence=1.0,
                input_context={"mode": mode},
                output_decision={
                    "cases_processed":        weekly.cases_processed,
                    "autonomous_resolutions": weekly.autonomous_resolutions,
                    "mttr_minutes":           weekly.metrics.get("total_mttr_minutes", 0),
                },
                reasoning=(
                    f"Weekly Sage report: {weekly.cases_processed} cases, "
                    f"MTTR {weekly.metrics.get('total_mttr_minutes', '?')} min"
                ),
                latency_ms=int(time.time() * 1000) - t0,
            )

        result["duration_ms"] = int(time.time() * 1000) - t0
        log.info("Sage scheduled complete: mode=%s duration=%dms", mode, result["duration_ms"])
        return result

    # ------------------------------------------------------------------
    # Core: Detection efficacy analysis
    # ------------------------------------------------------------------

    def analyze_detection_efficacy(
        self, timeframe: str = _DEFAULT_EFFICACY_WINDOW
    ) -> EfficacyReport:
        """
        Query closed cases and audit events to compute per-rule and overall
        detection efficacy metrics for the given timeframe.
        """
        earliest = f"-{timeframe}"
        now_iso  = datetime.now(timezone.utc).isoformat()

        cases_by_type: List[Dict] = self._query_spl(
            _SPL_CLOSED_CASES.format(earliest=earliest), "efficacy:closed_cases"
        )
        mttr_rows: List[Dict] = self._query_spl(
            _SPL_MTTR_BREAKDOWN.format(earliest=earliest), "efficacy:mttr"
        )
        avg_triage_s        = self._avg_field(mttr_rows, "avg_triage_ms",        0) / 1000
        avg_investigation_s = self._avg_field(mttr_rows, "avg_investigation_ms", 0) / 1000
        avg_response_s      = self._avg_field(mttr_rows, "avg_response_ms",      0) / 1000

        agent_rows: List[Dict] = self._query_spl(
            _SPL_AGENT_DECISIONS.format(earliest=earliest), "efficacy:agent_decisions"
        )
        agent_metrics = {
            row.get("agent_name", "unknown"): {
                "decisions":      int(float(row.get("decisions",      0))),
                "avg_confidence": round(float(row.get("avg_confidence", 0)), 3),
                "avg_latency_ms": round(float(row.get("avg_latency_ms",  0)), 1),
            }
            for row in agent_rows
        }

        trend_rows: List[Dict] = self._query_spl(
            _SPL_RULE_WEEKLY_COUNTS.format(weeks=_TREND_COMPARISON_WEEKS + 1),
            "efficacy:weekly_trend",
        )
        trend_by_type: Dict[str, List[float]] = {}
        for row in trend_rows:
            atype = row.get("alert_type", "unknown")
            count = float(row.get("weekly_cases", 0))
            trend_by_type.setdefault(atype, []).append(count)

        total_tp = total_fp = total_all = 0
        rules:           List[RuleMetrics] = []
        anomalous_rules: List[str]         = []

        for row in cases_by_type:
            alert_type = row.get("alert_type", "UNKNOWN")
            total      = int(float(row.get("total_cases", 0)))
            fp         = int(float(row.get("fp_count",    0)))
            tp         = int(float(row.get("tp_count",    0)))
            avg_score  = round(float(row.get("avg_score",  0)), 1)
            avg_mttr_s = float(row.get("avg_mttr_s", 0))

            fp_rate = round(fp / total, 3) if total else 0.0
            tp_rate = round(tp / total, 3) if total else 0.0

            weekly          = trend_by_type.get(alert_type, [float(total)])
            trend_d         = self._get_ts().analyze_trend(weekly, _TREND_COMPARISON_WEEKS)
            anomaly_result  = self._get_ts().forecast_anomaly(weekly)
            anomaly_indices = anomaly_result.get("anomaly_indices", [])
            anomaly_this_week = bool(anomaly_indices and
                                     (len(weekly) - 1) in anomaly_indices)
            if anomaly_this_week:
                anomalous_rules.append(alert_type)

            if fp_rate > 0.20:
                recommendation = "lower_threshold_or_add_exclusions"
            elif fp_rate > 0.10:
                recommendation = "tune_exclusions"
            elif tp_rate < 0.50 and total >= 5:
                recommendation = "raise_threshold"
            elif total < 2:
                recommendation = "monitor_coverage"
            else:
                recommendation = "maintain"

            rules.append(RuleMetrics(
                rule_name=f"SENTINEL - {alert_type.replace('_', ' ').title()} - Rule",
                alert_type=alert_type,
                total_alerts=total,
                true_positives=tp,
                false_positives=fp,
                tp_rate=tp_rate,
                fp_rate=fp_rate,
                avg_risk_score=avg_score,
                avg_ttd_minutes=round(avg_mttr_s / 60, 1),
                trend=trend_d.get("direction", "stable"),
                trend_pct_change=trend_d.get("pct_change", 0.0),
                anomaly_this_week=anomaly_this_week,
                recommended_action=recommendation,
            ))
            total_all += total
            total_tp  += tp
            total_fp  += fp

        overall_tp_rate = round(total_tp / total_all, 3) if total_all else 0.0
        overall_fp_rate = round(total_fp / total_all, 3) if total_all else 0.0
        total_mttr_min  = round(
            (avg_triage_s + avg_investigation_s + avg_response_s) / 60, 1
        )
        summary = self._synthesize_efficacy_summary(
            total_cases=total_all,
            tp_rate=overall_tp_rate,
            fp_rate=overall_fp_rate,
            mttr_min=total_mttr_min,
            anomalous_rules=anomalous_rules,
            agent_metrics=agent_metrics,
        )

        return EfficacyReport(
            timeframe=timeframe,
            generated_at=now_iso,
            total_cases=total_all,
            overall_tp_rate=overall_tp_rate,
            overall_fp_rate=overall_fp_rate,
            avg_triage_s=round(avg_triage_s, 1),
            avg_investigation_s=round(avg_investigation_s, 1),
            avg_response_s=round(avg_response_s, 1),
            total_mttr_minutes=total_mttr_min,
            rules=rules,
            agent_metrics=agent_metrics,
            anomalous_rules=anomalous_rules,
            summary=summary,
        )

    # ------------------------------------------------------------------
    # Core: Detection rule proposal
    # ------------------------------------------------------------------

    def propose_detection_rule(self, case_data: Dict) -> Optional[ProposedRule]:
        """
        Generate a new SPL detection rule using SAIA, backtest it against 90 days
        of historical data, and return a ProposedRule if it passes quality gates
        (FP rate < 5 %, query time < 30s).
        """
        classification = case_data.get("classification", "UNKNOWN")
        key_indicators = case_data.get("key_indicators", [])
        malware_family = case_data.get("threat_assessment", {}).get("malware_family", "")
        ttps           = case_data.get("threat_assessment", {}).get("ttp_mapping", [])

        if not key_indicators and not malware_family:
            return None

        nl_desc = (
            f"Generate a Splunk detection rule for "
            f"{malware_family or classification}. "
            f"Key indicators: {'; '.join(str(i) for i in key_indicators[:5])}. "
            f"MITRE techniques: {', '.join(ttps[:3])}. "
            "Use tstats where possible. Include time constraints. "
            "Scope to index=`sentinel_edr_index` or index=`sentinel_network_index`."
        )
        proposed_spl = self._get_saia().generate_spl(
            nl_desc, {"classification": classification}
        )
        if not proposed_spl:
            proposed_spl = self._build_fallback_rule_spl(classification, key_indicators, ttps)
        if not proposed_spl:
            return None

        rule_id   = f"SAGE-RULE-{uuid.uuid4().hex[:6].upper()}"
        rule_name = (
            f"SENTINEL - "
            f"{(malware_family or classification).replace('_', ' ').title()} "
            f"- AI Proposed - {rule_id}"
        )

        backtest_result   = self._backtest_rule(proposed_spl, classification)
        backtest_tp       = backtest_result.get("matched_known_tp", 0)
        backtest_fp       = backtest_result.get("estimated_fp",     0)
        total_backtest    = backtest_tp + backtest_fp
        backtest_fp_rate  = round(backtest_fp / total_backtest, 3) if total_backtest else 0.0
        query_time_s      = backtest_result.get("query_time_s", 999.0)

        passed = (
            backtest_fp_rate <= _MAX_FP_RATE_FOR_PRODUCTION
            and query_time_s <= _MAX_QUERY_TIME_S
            and backtest_tp >= 1
        )
        rejection_reason = ""
        if not passed:
            reasons = []
            if backtest_fp_rate > _MAX_FP_RATE_FOR_PRODUCTION:
                reasons.append(
                    f"FP rate {backtest_fp_rate:.0%} exceeds 5% threshold"
                )
            if query_time_s > _MAX_QUERY_TIME_S:
                reasons.append(
                    f"Query time {query_time_s:.1f}s exceeds 30s limit"
                )
            if backtest_tp < 1:
                reasons.append("No true positives matched in 90-day backtest")
            rejection_reason = "; ".join(reasons)

        log.info(
            "Rule proposal %s: passed=%s fp_rate=%.1f%% query_time=%.1fs tp=%d",
            rule_id, passed, backtest_fp_rate * 100, query_time_s, backtest_tp,
        )
        return ProposedRule(
            rule_id=rule_id,
            rule_name=rule_name,
            alert_type=f"SAGE_PROPOSED_{classification}",
            description=nl_desc[:200],
            spl=proposed_spl,
            rationale=(
                f"Proposed by Sage based on {classification} case analysis. "
                f"Key indicators: {'; '.join(str(i) for i in key_indicators[:3])}. "
                f"TTPs: {', '.join(ttps[:3])}."
            ),
            backtest_tp_count=backtest_tp,
            backtest_fp_count=backtest_fp,
            backtest_fp_rate=backtest_fp_rate,
            backtest_query_time_s=query_time_s,
            proposed_for_production=passed,
            rejection_reason=rejection_reason,
        )

    # ------------------------------------------------------------------
    # Core: Weekly performance report
    # ------------------------------------------------------------------

    def generate_weekly_report(self) -> WeeklyReport:
        """Generate the full Monday weekly performance report."""
        now      = datetime.now(timezone.utc)
        week_ago = now - timedelta(days=7)
        period   = (
            f"{week_ago.strftime('%Y-%m-%d')} to {now.strftime('%Y-%m-%d')}"
        )

        cases_rows = self._query_spl(
            _SPL_CLOSED_CASES.format(earliest="-7d"), "weekly:cases"
        )
        total_cases = sum(int(float(r.get("total_cases", 0))) for r in cases_rows)
        total_fp    = sum(int(float(r.get("fp_count",    0))) for r in cases_rows)

        halted_rows = self._query_spl(
            'index=sentinel_audit event_type=transition to_status=HALTED '
            'earliest="-7d" | stats dc(case_id) AS count',
            "weekly:halted",
        )
        human_escalations = int(float(
            halted_rows[0].get("count", 0) if halted_rows else 0
        ))
        autonomous_resolutions = max(0, total_cases - human_escalations)

        mttr_rows = self._query_spl(
            _SPL_MTTR_BREAKDOWN.format(earliest="-7d"), "weekly:mttr"
        )
        avg_triage_s        = self._avg_field(mttr_rows, "avg_triage_ms",        0) / 1000
        avg_investigation_s = self._avg_field(mttr_rows, "avg_investigation_ms", 0) / 1000
        avg_response_s      = self._avg_field(mttr_rows, "avg_response_ms",      0) / 1000
        total_mttr_min      = round(
            (avg_triage_s + avg_investigation_s + avg_response_s) / 60, 1
        )
        improvement_factor  = round(
            (_INDUSTRY_BASELINE_MTTR_H * 60) / total_mttr_min, 1
        ) if total_mttr_min > 0 else 0.0

        learning_rows = self._query_spl(
            'index=sentinel_learning event_type=rule_proposal earliest="-7d" '
            '| stats count AS rules_proposed, '
            '  sum(eval(proposed_for_production="true")) AS rules_approved',
            "weekly:learning",
        )
        rules_proposed = int(float(learning_rows[0].get("rules_proposed", 0))) if learning_rows else 0
        rules_approved = int(float(learning_rows[0].get("rules_approved", 0))) if learning_rows else 0

        prior_fp_rows = self._query_spl(
            _SPL_CLOSED_CASES.format(earliest="-14d"),
            "weekly:prior_fp",
        )
        prior_total_fp  = sum(int(float(r.get("fp_count", 0))) for r in prior_fp_rows)
        fp_reduction_pct = round(
            (prior_total_fp - total_fp) / prior_total_fp * 100, 1
        ) if prior_total_fp > 0 else 0.0

        ioc_rows = self._query_spl(
            _SPL_IOC_HARVEST.format(earliest="-7d"), "weekly:iocs"
        )
        new_iocs            = len(ioc_rows)
        confirmed_malicious = sum(
            1 for r in ioc_rows if r.get("verdict") == "malicious"
        )

        analyst_hours_saved = round(total_cases * _ANALYST_TIME_PER_CASE_H, 0)
        weekly_savings      = int(analyst_hours_saved * _ANALYST_HOURLY_RATE_USD)
        projected_annual    = weekly_savings * 52

        agent_rows = self._query_spl(
            _SPL_AGENT_DECISIONS.format(earliest="-7d"), "weekly:agents"
        )
        agent_performance = {
            row.get("agent_name", "unknown"): {
                "decisions":      int(float(row.get("decisions",      0))),
                "avg_confidence": round(float(row.get("avg_confidence", 0)), 3),
                "avg_latency_ms": round(float(row.get("avg_latency_ms",  0)), 1),
            }
            for row in agent_rows
        }

        recommendations = self._generate_recommendations(
            total_cases=total_cases,
            fp_rate=round(total_fp / total_cases, 3) if total_cases else 0.0,
            mttr_min=total_mttr_min,
            cases_rows=cases_rows,
            agent_metrics=agent_performance,
        )

        return WeeklyReport(
            report_period=period,
            cases_processed=total_cases,
            autonomous_resolutions=autonomous_resolutions,
            human_escalations=human_escalations,
            metrics={
                "avg_triage_time_seconds":       round(avg_triage_s,        1),
                "avg_investigation_time_seconds": round(avg_investigation_s, 1),
                "avg_response_time_seconds":      round(avg_response_s,      1),
                "total_mttr_minutes":             total_mttr_min,
                "industry_baseline_mttr_hours":   _INDUSTRY_BASELINE_MTTR_H,
                "improvement_factor":             improvement_factor,
            },
            detection_improvements={
                "rules_proposed":                   rules_proposed,
                "rules_approved":                   rules_approved,
                "rules_deployed":                   rules_approved,
                "false_positive_reduction_percent": max(0.0, fp_reduction_pct),
            },
            threat_intel={
                "new_iocs_extracted":      new_iocs,
                "iocs_submitted":          new_iocs,
                "iocs_confirmed_malicious": confirmed_malicious,
            },
            cost_savings={
                "analyst_hours_saved":      int(analyst_hours_saved),
                "estimated_hourly_rate":    _ANALYST_HOURLY_RATE_USD,
                "weekly_savings":           weekly_savings,
                "projected_annual_savings": projected_annual,
            },
            recommendations=recommendations,
            agent_performance=agent_performance,
        )

    # ------------------------------------------------------------------
    # Threat intelligence harvesting
    # ------------------------------------------------------------------

    def _extract_iocs_from_case(self, case: Any, sherlock: Dict) -> List[IoC]:
        iocs: List[IoC] = []
        case_id         = case.case_id
        seen:    set    = set()

        for raw in (sherlock.get("iocs_discovered") or sherlock.get("all_iocs") or []):
            value   = str(raw.get("value",   "")).strip()
            itype   = str(raw.get("type",    "unknown")).strip()
            verdict = str(raw.get("verdict", "unknown")).strip()
            if value and value not in seen and verdict in ("malicious", "suspicious"):
                seen.add(value)
                iocs.append(IoC(value=value, ioc_type=itype,
                                source=case_id, verdict=verdict))

        br = sherlock.get("blast_radius", {})
        for host in br.get("compromised_hosts", []):
            if _looks_like_ip(host) and host not in seen:
                seen.add(host)
                iocs.append(IoC(value=host, ioc_type="ip",
                                source=case_id, verdict="malicious"))

        for sha in re.findall(r"\b[a-fA-F0-9]{64}\b", json.dumps(sherlock)):
            if sha not in seen:
                seen.add(sha)
                iocs.append(IoC(value=sha, ioc_type="sha256",
                                source=case_id, verdict="suspicious"))

        return iocs

    def _submit_threat_intel(
        self, iocs: List[IoC], audit: AuditLogger, case_id: str
    ) -> int:
        ti_url   = os.environ.get(_ENV_TI_URL,
                      self._cfg.get("integrations", "ti_url",   default=""))
        ti_token = os.environ.get(_ENV_TI_TOKEN,
                      self._cfg.get("integrations", "ti_token", default=""))

        session = requests.Session()
        adapter = HTTPAdapter(max_retries=Retry(total=2, backoff_factor=0.3))
        session.mount("https://", adapter)
        session.mount("http://",  adapter)

        submitted = 0
        for ioc in iocs:
            # Check enrichment to confirm/deduplicate
            try:
                enrichment = self._get_mcp().enrich_threat_intel(
                    ioc=ioc.value, ioc_type=ioc.ioc_type, check_whitelist=True,
                )
                ioc.confirmed = enrichment.get("verdict") == "malicious"
            except MCPError:
                pass

            if ti_url and ti_token:
                try:
                    resp = session.post(
                        f"{ti_url.rstrip('/')}/api/v1/iocs/submit",
                        json={
                            "ioc_value":  ioc.value,
                            "ioc_type":   ioc.ioc_type,
                            "verdict":    ioc.verdict,
                            "source":     f"sentinel:{case_id}",
                            "confidence": 0.9 if ioc.confirmed else 0.6,
                        },
                        headers={"Authorization": f"Bearer {ti_token}"},
                        timeout=10.0,
                        verify=False,
                    )
                    if resp.ok:
                        ioc.submitted = True
                        submitted += 1
                except Exception as exc:
                    log.debug("TI submit failed for %s: %s", ioc.value[:20], exc)
            else:
                audit.log_enrichment(
                    case_id=case_id,
                    ioc_value=ioc.value,
                    ioc_type=ioc.ioc_type,
                    verdict=ioc.verdict,
                    confidence=0.9 if ioc.confirmed else 0.6,
                    sources=["sage_harvest"],
                    cached=False,
                )
                ioc.submitted = True
                submitted += 1

        log.info("Threat intel: %d harvested, %d submitted", len(iocs), submitted)
        return submitted

    # ------------------------------------------------------------------
    # Self-tuning
    # ------------------------------------------------------------------

    def _compute_tuning_parameters(
        self, efficacy: EfficacyReport
    ) -> Optional[TuningParameters]:
        """Derive threshold adjustments from efficacy data; return None if unchanged."""
        cfg_dismiss  = int(self._cfg.get("agents", "vanguard_threshold_close",       default="40"))
        cfg_approval = int(self._cfg.get("agents", "executor_require_approval_below", default="90"))

        tuning_rows = self._query_spl(
            'index=sentinel_learning event_type=tuning_parameters '
            '| sort -_time | head 1',
            "tuning:current",
        )
        if tuning_rows:
            current_dismiss  = int(float(
                tuning_rows[0].get("vanguard_auto_dismiss_threshold",  cfg_dismiss)
            ))
            current_approval = int(float(
                tuning_rows[0].get("executor_require_approval_below", cfg_approval)
            ))
        else:
            current_dismiss  = cfg_dismiss
            current_approval = cfg_approval

        new_dismiss         = current_dismiss
        rationale_parts: List[str] = []

        if efficacy.overall_fp_rate > 0.15:
            delta      = min(_MAX_THRESHOLD_DELTA, int((efficacy.overall_fp_rate - 0.15) * 30))
            new_dismiss = min(_MAX_VANGUARD_DISMISS, current_dismiss + delta)
            if new_dismiss != current_dismiss:
                rationale_parts.append(
                    f"Raised auto-dismiss threshold {current_dismiss}->{new_dismiss} "
                    f"(FP rate {efficacy.overall_fp_rate:.0%} > 15%)"
                )
        elif efficacy.overall_fp_rate < 0.05 and efficacy.overall_tp_rate < 0.90:
            delta      = min(_MAX_THRESHOLD_DELTA, 2)
            new_dismiss = max(_MIN_VANGUARD_DISMISS, current_dismiss - delta)
            if new_dismiss != current_dismiss:
                rationale_parts.append(
                    f"Lowered auto-dismiss threshold {current_dismiss}->{new_dismiss} "
                    f"(FP rate healthy but TP rate low)"
                )

        if new_dismiss == current_dismiss and current_approval == cfg_approval:
            log.debug("Tuning: no adjustments warranted this cycle")
            return None

        return TuningParameters(
            vanguard_auto_dismiss_threshold=new_dismiss,
            vanguard_auto_escalate_threshold=85,
            executor_require_approval_below=current_approval,
            sherlock_investigation_depth=2,
            rationale="; ".join(rationale_parts) or "No change required",
            previous_values={
                "vanguard_auto_dismiss_threshold": current_dismiss,
                "executor_require_approval_below": current_approval,
            },
        )

    def _apply_tuning_parameters(
        self, tuning: TuningParameters, audit: AuditLogger
    ) -> None:
        self._publish_to_learning_index("tuning_parameters", tuning.to_dict(), audit)
        audit.log_decision(
            case_id="scheduled",
            decision_type="THRESHOLD_TUNING",
            confidence=0.80,
            input_context={"previous": tuning.previous_values},
            output_decision={
                "vanguard_auto_dismiss_threshold": tuning.vanguard_auto_dismiss_threshold,
                "executor_require_approval_below": tuning.executor_require_approval_below,
            },
            reasoning=tuning.rationale,
            latency_ms=0,
        )
        log.info(
            "Tuning applied: dismiss=%d approval_below=%d",
            tuning.vanguard_auto_dismiss_threshold,
            tuning.executor_require_approval_below,
        )

    # ------------------------------------------------------------------
    # Per-case metric recording
    # ------------------------------------------------------------------

    def _record_case_metrics(
        self,
        case:     Any,
        sherlock: Dict,
        executor: Any,
        vanguard: Dict,
        audit:    AuditLogger,
    ) -> bool:
        try:
            created = float(getattr(case, "created_time", 0) or 0)
            updated = float(getattr(case, "updated_time", 0) or time.time())
            mttr_s  = max(0.0, updated - created)
            payload = {
                "event_type":          "case_metrics",
                "case_id":             case.case_id,
                "classification":      getattr(case, "classification",  "UNKNOWN"),
                "alert_type":          getattr(case, "alert_type",      "UNKNOWN"),
                "resolution":          getattr(case, "resolution",       "UNKNOWN"),
                "risk_score":          getattr(case, "risk_score",       0),
                "mttr_seconds":        round(mttr_s, 1),
                "vanguard_confidence": float(vanguard.get("confidence", 0)),
                "sherlock_phases":     len(sherlock.get("phases_completed", [])),
                "iocs_found":          len(sherlock.get("iocs_discovered",  [])),
                "actions_taken":       len(
                    executor.get("actions", []) if isinstance(executor, dict) else []
                ),
                "model_used":          sherlock.get("model_used", "unknown"),
            }
            self._publish_to_learning_index("case_metrics", payload, audit)
            audit.log_metric(
                case_id=case.case_id,
                metric_name="case_mttr_seconds",
                value=round(mttr_s, 1),
                unit="seconds",
                metadata={
                    "resolution": getattr(case, "resolution", ""),
                    "risk_score": getattr(case, "risk_score",  0),
                },
            )
            return True
        except Exception as exc:
            log.warning("Failed to record case metrics for %s: %s", case.case_id, exc)
            return False

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _query_spl(self, spl: str, label: str = "") -> List[Dict]:
        try:
            raw  = self._get_mcp().search_spl(
                query=spl, earliest="-90d", latest="now", max_results=500
            )
            rows = raw if isinstance(raw, list) else raw.get("results", [])
            log.debug("SPL[%s]: %d rows", label, len(rows))
            return rows
        except MCPError as exc:
            log.warning("SPL query failed [%s]: %s", label, exc)
            return []

    def _backtest_rule(self, proposed_spl: str, alert_type: str) -> Dict:
        t_start    = time.time()
        match_rows = self._query_spl(
            _SPL_BACKTEST.format(proposed_spl=proposed_spl), "backtest:matches"
        )
        query_time  = round(time.time() - t_start, 2)
        total_match = sum(int(float(r.get("matches", 0))) for r in match_rows)

        tp_rows   = self._query_spl(
            _SPL_HISTORICAL_TP.format(alert_type=alert_type, days=90),
            "backtest:tp",
        )
        known_tp  = int(float(tp_rows[0].get("count", 0))) if tp_rows else 0
        est_fp    = max(0, total_match - known_tp)
        return {
            "total_matches":   total_match,
            "matched_known_tp": min(known_tp, total_match),
            "estimated_fp":    est_fp,
            "query_time_s":    query_time,
        }

    def _build_fallback_rule_spl(
        self,
        classification: str,
        key_indicators:  List[Any],
        ttps:            List[str],
    ) -> Optional[str]:
        if "RANSOMWARE" in classification:
            return (
                'index=`sentinel_edr_index` '
                '(process_name="powershell.exe" OR process_name="cmd.exe") '
                '(process_args="*-enc*" OR process_args="*vssadmin*delete*") '
                'NOT [| inputlookup ioc_whitelist_lookup | fields ioc_value | '
                'rename ioc_value AS process_hash] '
                '| eval risk_score=80 '
                '| stats count BY host, user, process_name, process_args, _time'
            )
        if "LATERAL" in classification:
            return (
                'index=`sentinel_network_index` dest_port=445 '
                '| stats count AS smb_connections, dc(dest_ip) AS unique_dests BY src_ip '
                '| where unique_dests > 3 '
                '| eval risk_score=75 '
                '| fields src_ip, smb_connections, unique_dests, risk_score'
            )
        return None

    def _synthesize_efficacy_summary(
        self,
        total_cases:     int,
        tp_rate:         float,
        fp_rate:         float,
        mttr_min:        float,
        anomalous_rules: List[str],
        agent_metrics:   Dict,
    ) -> str:
        model_input = {
            "task": "synthesize_efficacy_summary",
            "system_prompt": self._load_system_prompt(),
            "data": {
                "total_cases":     total_cases,
                "tp_rate":         tp_rate,
                "fp_rate":         fp_rate,
                "mttr_minutes":    mttr_min,
                "anomalous_rules": anomalous_rules,
                "agent_metrics":   agent_metrics,
            },
        }
        result = self._call_model(model_input)
        if result and isinstance(result, dict):
            return result.get("summary", "")
        if isinstance(result, str):
            return result

        parts = [f"Analysed {total_cases} cases over the review period."]
        if fp_rate > 0.15:
            parts.append(
                f"False positive rate of {fp_rate:.0%} exceeds target — tuning recommended."
            )
        elif fp_rate < 0.05:
            parts.append(f"False positive rate {fp_rate:.0%} is within target.")
        if mttr_min > 0:
            factor = round(_INDUSTRY_BASELINE_MTTR_H * 60 / mttr_min, 1)
            parts.append(
                f"MTTR of {mttr_min} min is {factor}x faster than industry baseline."
            )
        if anomalous_rules:
            parts.append(
                f"Anomalous alert volumes detected for: {', '.join(anomalous_rules[:3])}."
            )
        return " ".join(parts)

    def _generate_recommendations(
        self,
        total_cases:   int,
        fp_rate:       float,
        mttr_min:      float,
        cases_rows:    List[Dict],
        agent_metrics: Dict,
    ) -> List[str]:
        model_input = {
            "task": "generate_recommendations",
            "system_prompt": self._load_system_prompt(),
            "data": {
                "total_cases":       total_cases,
                "fp_rate":           fp_rate,
                "mttr_minutes":      mttr_min,
                "cases_breakdown":   cases_rows[:10],
                "agent_metrics":     agent_metrics,
            },
        }
        result = self._call_model(model_input)
        if result and isinstance(result, dict) and result.get("recommendations"):
            return result["recommendations"][:8]

        recs: List[str] = []
        for row in cases_rows:
            tc   = float(row.get("total_cases", 1))
            fp_c = float(row.get("fp_count",    0))
            fp_r = fp_c / max(1, tc)
            at   = row.get("alert_type", "")
            if fp_r > 0.15:
                recs.append(
                    f"{at}: {fp_r:.0%} false positive rate — consider adding "
                    "contextual exclusions or raising the score threshold."
                )
        if mttr_min > 15:
            recs.append(
                f"MTTR of {mttr_min} min is above 15 min target — review Sherlock "
                "investigation depth and MCP query timeouts."
            )
        if fp_rate > 0.10:
            recs.append(
                "Overall false positive rate exceeds 10% — Sage will propose "
                "threshold adjustments in the next tuning cycle."
            )
        vp = agent_metrics.get("vanguard", {})
        if vp and float(vp.get("avg_confidence", 1)) < 0.75:
            recs.append(
                "Vanguard average confidence is below 75% — consider retraining "
                "Foundation-Sec with recent case labels for this environment."
            )
        if not recs:
            recs.append(
                "All key metrics are within target ranges. Continue current "
                "configuration and monitor for seasonal volume changes."
            )
        return recs[:8]

    def _maybe_propose_rule(
        self, case: Any, sherlock: Dict, audit: AuditLogger
    ) -> Optional[ProposedRule]:
        case_data = {
            "classification":  getattr(case, "classification", "UNKNOWN"),
            "key_indicators":  sherlock.get("threat_assessment", {}).get("ttp_mapping", []),
            "threat_assessment": sherlock.get("threat_assessment", {}),
        }
        proposed = self.propose_detection_rule(case_data)
        if proposed:
            self._publish_to_learning_index(
                "rule_proposal",
                {**proposed.to_dict(), "source_case_id": case.case_id},
                audit,
            )
            audit.log_decision(
                case_id=case.case_id,
                decision_type="DETECTION_RULE_PROPOSED",
                confidence=0.80 if proposed.proposed_for_production else 0.50,
                input_context={"case_id": case.case_id},
                output_decision={
                    "rule_id":    proposed.rule_id,
                    "fp_rate":    proposed.backtest_fp_rate,
                    "production": proposed.proposed_for_production,
                },
                reasoning=(
                    f"Rule {proposed.rule_id} proposed: "
                    + (
                        "APPROVED for production"
                        if proposed.proposed_for_production
                        else f"REJECTED: {proposed.rejection_reason}"
                    )
                ),
                latency_ms=0,
            )
        return proposed

    def _call_model(self, model_input: Dict) -> Any:
        token = self._get_model_token()
        if not token:
            return None
        try:
            resp = requests.post(
                self._get_model_url(),
                json={
                    "inputs":     json.dumps(model_input),
                    "parameters": {"max_new_tokens": 1024, "temperature": 0.1},
                },
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type":  "application/json",
                },
                timeout=30.0,
                verify=False,
            )
            if resp.status_code != 200:
                return None
            raw     = resp.json()
            outputs = raw.get("outputs", [{}])
            output  = (
                raw.get("generated_text")
                or (outputs[0].get("generated_text", "") if outputs else "")
            ).strip()
            if output.startswith("```"):
                parts  = output.split("```")
                output = parts[2] if len(parts) > 2 else parts[-1]
            return json.loads(output.strip())
        except Exception as exc:
            log.debug("Model call failed: %s", exc)
            return None

    def _publish_to_learning_index(
        self, event_type: str, data: Dict, audit: AuditLogger
    ) -> bool:
        try:
            audit.log_metric(
                case_id=data.get("case_id", "scheduled"),
                metric_name=f"sage_{event_type}",
                value=1.0,
                unit="event",
                metadata={
                    "learning_payload": json.dumps(data, default=str)[:2048]
                },
            )
            return True
        except Exception as exc:
            log.warning("Failed to publish learning event %s: %s", event_type, exc)
            return False

    @staticmethod
    def _avg_field(rows: List[Dict], field_name: str, default: float) -> float:
        values = [float(r[field_name]) for r in rows if r.get(field_name) is not None]
        return sum(values) / len(values) if values else default


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _looks_like_ip(value: str) -> bool:
    return bool(re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}", value.strip()))


# ---------------------------------------------------------------------------
# Module-level entry point (orchestrator _AgentProxy interface)
# ---------------------------------------------------------------------------

def run(case: Any, audit: Optional[AuditLogger] = None, **_kwargs) -> Dict:
    """Run Sage on a closed Case and return learning metrics as a dict."""
    return SageAgent().run(case, audit or get_audit_logger(_AGENT_NAME))

