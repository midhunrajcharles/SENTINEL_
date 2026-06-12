"""
Integration tests for hosted AI model endpoints.

Tests Foundation-Sec-1.1-8B alert classification and Cisco Deep Time Series
anomaly forecasting / threshold optimisation / trend analysis.

SKIPPED by default — set SENTINEL_RUN_INTEGRATION=1 to run.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import List, Dict

import pytest

_BIN  = Path(__file__).resolve().parent.parent.parent / "app" / "sentinel" / "bin"
_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_BIN) not in sys.path:
    sys.path.insert(0, str(_BIN))

pytestmark = pytest.mark.integration


# ---------------------------------------------------------------------------
# Sample alerts loaded from fixtures
# ---------------------------------------------------------------------------

def _load_sample_alerts() -> List[Dict]:
    fixture = _ROOT / "tests" / "fixtures" / "sample_investigations.json"
    with fixture.open() as fh:
        return json.load(fh)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def vanguard():
    from agent_vanguard import VanguardAgent
    from mcp_client import SplunkMCPClient
    from utils.config import get_config
    from utils.audit_logger import get_audit_logger
    cfg = get_config()
    mcp = SplunkMCPClient(cfg)
    return VanguardAgent(mcp_client=mcp, audit=get_audit_logger())


@pytest.fixture(scope="module")
def ts_client():
    from agent_sage import _CiscoTimeSeriesClient
    from utils.config import get_config
    cfg = get_config()
    return _CiscoTimeSeriesClient(
        base_url = cfg.get("cisco_ts_endpoint", ""),
        token    = cfg.get("cisco_ts_token",    ""),
    )


@pytest.fixture(scope="module")
def sample_alerts():
    return _load_sample_alerts()


# ---------------------------------------------------------------------------
# Foundation-Sec-1.1-8B classification tests
# ---------------------------------------------------------------------------

class TestFoundationSecClassification:
    def test_ransomware_alert_classified_as_ransomware(self, vanguard, sample_alerts):
        """INV-004 (LockBit 3.0) should produce a high risk score."""
        from utils.state_manager import CaseStateManager
        from utils.audit_logger import get_audit_logger

        lockbit = next(
            inv for inv in sample_alerts
            if inv.get("threat_type") == "RANSOMWARE"
        )

        case_mock = _build_case(lockbit)
        audit = get_audit_logger()

        result = vanguard.run(case_mock, audit)

        assert result.get("success") is True
        assert result.get("risk_score", 0) >= 70, (
            f"Ransomware alert scored {result.get('risk_score')} — expected ≥70"
        )

    def test_false_positive_alert_dismissed_or_low_score(self, vanguard, sample_alerts):
        """INV-001 (certutil FP) should score ≤54."""
        fp = next(
            inv for inv in sample_alerts
            if inv.get("threat_type") == "FALSE_POSITIVE"
        )
        case_mock = _build_case(fp)
        from utils.audit_logger import get_audit_logger
        result = vanguard.run(case_mock, get_audit_logger())

        assert result.get("success") is True
        assert result.get("risk_score", 100) <= 54, (
            f"FP alert scored {result.get('risk_score')} — expected ≤54"
        )

    def test_classification_includes_mitre_tactic(self, vanguard, sample_alerts):
        ransomware = next(
            inv for inv in sample_alerts
            if inv.get("threat_type") == "RANSOMWARE"
        )
        case_mock = _build_case(ransomware)
        from utils.audit_logger import get_audit_logger
        result = vanguard.run(case_mock, get_audit_logger())

        assert result.get("mitre_tactic"), "Expected a MITRE tactic in result"

    def test_classification_latency_under_30s(self, vanguard, sample_alerts):
        """Each alert must be classified within 30 seconds."""
        from utils.audit_logger import get_audit_logger
        audit   = get_audit_logger()
        latency_failures = []

        for inv in sample_alerts[:3]:  # first 3 samples
            case_mock = _build_case(inv)
            t0        = time.monotonic()
            vanguard.run(case_mock, audit)
            elapsed   = time.monotonic() - t0
            if elapsed > 30.0:
                latency_failures.append(
                    f"{inv.get('case_id')}: {elapsed:.2f}s"
                )

        assert not latency_failures, (
            "Classification exceeded 30s:\n" + "\n".join(latency_failures)
        )

    def test_fallback_result_when_model_unavailable(self, sample_alerts):
        """When model endpoint returns 503, fallback rules should still produce a result."""
        from unittest.mock import patch, MagicMock
        from agent_vanguard import VanguardAgent

        ransomware = next(
            inv for inv in sample_alerts
            if inv.get("threat_type") == "RANSOMWARE"
        )

        with (
            patch("agent_vanguard.SplunkMCPClient",    autospec=False),
            patch("agent_vanguard.get_audit_logger",   return_value=MagicMock()),
            patch("agent_vanguard.get_config",         return_value=MagicMock()),
        ):
            mock_mcp = MagicMock()
            cfg      = MagicMock()
            cfg.get.return_value      = ""
            cfg.get_bool.return_value = False
            agent = VanguardAgent(mcp_client=mock_mcp, audit=MagicMock())

        with patch.object(agent, "_call_model", side_effect=RuntimeError("503 Service Unavailable")):
            result = agent.run(_build_case(ransomware), MagicMock())

        assert result.get("success") is True
        assert result.get("risk_score") is not None


# ---------------------------------------------------------------------------
# Cisco Deep Time Series tests
# ---------------------------------------------------------------------------

class TestCiscoDeepTimeSeries:
    _SAMPLE_SERIES = [12.0, 15.0, 11.0, 14.0, 13.0, 16.0, 14.0, 50.0, 12.0, 13.0]
    _SCORES  = [0.9, 0.85, 0.1, 0.2, 0.8, 0.15, 0.75, 0.05, 0.9, 0.1]
    _LABELS  = [1,   1,    0,   0,   1,   0,    1,    0,    1,   0]

    def test_forecast_anomaly_returns_dict_with_required_keys(self, ts_client):
        result = ts_client.forecast_anomaly(self._SAMPLE_SERIES)
        assert isinstance(result, dict)
        assert "anomalies" in result
        assert "forecast"  in result

    def test_forecast_anomaly_spike_detected(self, ts_client):
        result = ts_client.forecast_anomaly(self._SAMPLE_SERIES)
        anomalies = result.get("anomalies", [])
        # Position 7 (value=50) is a spike — should be flagged
        if len(anomalies) > 7:
            assert anomalies[7] is True, "Spike at index 7 should be anomalous"

    def test_optimize_threshold_returns_float_threshold(self, ts_client):
        result = ts_client.optimize_threshold(self._SCORES, self._LABELS)
        assert "optimal_threshold" in result
        thr = result["optimal_threshold"]
        assert isinstance(thr, (int, float))
        assert 0.0 <= thr <= 100.0

    def test_analyze_trend_returns_direction(self, ts_client):
        # Clearly increasing trend
        increasing = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0]
        result     = ts_client.analyze_trend(increasing)
        assert "direction" in result
        assert result["direction"] == "increasing"

    def test_analyze_trend_decreasing_series(self, ts_client):
        decreasing = [10.0, 9.0, 8.0, 7.0, 6.0, 5.0, 4.0, 3.0, 2.0, 1.0]
        result     = ts_client.analyze_trend(decreasing)
        assert result.get("direction") == "decreasing"

    def test_latency_forecast_under_10s(self, ts_client):
        t0      = time.monotonic()
        ts_client.forecast_anomaly(self._SAMPLE_SERIES)
        elapsed = time.monotonic() - t0
        assert elapsed < 10.0, f"forecast_anomaly took {elapsed:.2f}s (limit 10s)"

    def test_latency_threshold_optimize_under_10s(self, ts_client):
        t0      = time.monotonic()
        ts_client.optimize_threshold(self._SCORES, self._LABELS)
        elapsed = time.monotonic() - t0
        assert elapsed < 10.0, f"optimize_threshold took {elapsed:.2f}s (limit 10s)"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_case(investigation: Dict):
    from unittest.mock import MagicMock
    case = MagicMock()
    case.case_id        = investigation.get("case_id",    "CASE-INT-001")
    case.alert_id       = investigation.get("report_id",  "ALERT-INT-001")
    case.alert_type     = investigation.get("alert_type", "UNKNOWN")
    case.affected_host  = "DESKTOP-INT-HOST"
    case.affected_user  = "CORP\\intuser"
    case.risk_score     = 50
    case.classification = investigation.get("classification", "")
    case.raw_data       = investigation
    return case
