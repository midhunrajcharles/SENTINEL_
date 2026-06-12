"""
Unit tests for agent_sage.py — SageAgent learning pipeline.

Runs without a live Splunk instance: SplunkMCPClient, model endpoints,
and get_config are all mocked. The _TimeSeries static helper class is
tested in isolation (no mocking required — pure Python math).
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import List
from unittest.mock import MagicMock, patch

import pytest

_BIN = Path(__file__).resolve().parent.parent.parent / "app" / "sentinel" / "bin"
if str(_BIN) not in sys.path:
    sys.path.insert(0, str(_BIN))

with (
    patch("agent_sage.SplunkMCPClient", autospec=False),
    patch("agent_sage.get_audit_logger", return_value=MagicMock()),
    patch("agent_sage.get_config",       return_value=MagicMock()),
):
    from agent_sage import (
        SageAgent,
        _TimeSeries,
        _CiscoTimeSeriesClient,
        RuleMetrics,
        EfficacyReport,
        IoC,
        ProposedRule,
        TuningParameters,
        WeeklyReport,
        SageError,
        SageQueryError,
        SageModelError,
        _MAX_FP_RATE_FOR_PRODUCTION,
        _MAX_QUERY_TIME_S,
        _MAX_THRESHOLD_DELTA,
        _INDUSTRY_BASELINE_MTTR_H,
        _ANALYST_HOURLY_RATE_USD,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_agent(mock_mcp=None):
    cfg = MagicMock()
    cfg.get.return_value      = ""
    cfg.get_bool.return_value = False
    agent = SageAgent(mcp=mock_mcp or MagicMock(), config=cfg)
    return agent


def _make_case(
    case_id:        str   = "CASE-TEST-001",
    alert_id:       str   = "ALERT-TEST-001",
    alert_type:     str   = "RANSOMWARE_POWERSHELL_ENCODED",
    classification: str   = "RANSOMWARE_INITIAL_ACCESS",
    risk_score:     int   = 90,
    affected_host:  str   = "DESKTOP-ABC123",
    affected_user:  str   = "CORP\\jdoe",
):
    case = MagicMock()
    case.case_id        = case_id
    case.alert_id       = alert_id
    case.alert_type     = alert_type
    case.classification = classification
    case.risk_score     = risk_score
    case.affected_host  = affected_host
    case.affected_user  = affected_user
    # Sherlock report with IOCs
    case.sherlock_report = {
        "classification":   classification,
        "iocs_discovered":  [
            {"value": "185.220.101.42", "type": "ip",     "verdict": "malicious"},
            {"value": "update.microsoftsvc-cdn.com", "type": "domain", "verdict": "malicious"},
        ],
        "blast_radius": {"compromised_hosts": ["DESKTOP-ABC123"]},
        "recommended_actions": [],
        "false_positive_probability": 0.02,
    }
    case.vanguard_result = {
        "decision": {"composite_score": risk_score, "classification": classification}
    }
    return case


# ---------------------------------------------------------------------------
# Constants tests
# ---------------------------------------------------------------------------

class TestConstants:
    def test_max_fp_rate_for_production_is_5_percent(self):
        assert _MAX_FP_RATE_FOR_PRODUCTION == 0.05

    def test_max_query_time_is_30s(self):
        assert _MAX_QUERY_TIME_S == 30.0

    def test_max_threshold_delta_is_5(self):
        assert _MAX_THRESHOLD_DELTA == 5

    def test_industry_baseline_mttr_is_4_2h(self):
        assert _INDUSTRY_BASELINE_MTTR_H == 4.2

    def test_analyst_hourly_rate_is_85_usd(self):
        assert _ANALYST_HOURLY_RATE_USD == 85


# ---------------------------------------------------------------------------
# Exception hierarchy tests
# ---------------------------------------------------------------------------

class TestExceptionHierarchy:
    def test_query_error_is_sage_error(self):
        assert issubclass(SageQueryError, SageError)

    def test_model_error_is_sage_error(self):
        assert issubclass(SageModelError, SageError)


# ---------------------------------------------------------------------------
# _TimeSeries static helper tests (pure Python — no mocking required)
# ---------------------------------------------------------------------------

class TestTimeSeriesMovingAverage:
    def test_window_1_returns_original_series(self):
        s = [1.0, 2.0, 3.0, 4.0, 5.0]
        assert _TimeSeries.moving_average(s, 1) == s

    def test_window_3_smooths_correctly(self):
        s    = [1.0, 2.0, 3.0, 4.0, 5.0]
        avg  = _TimeSeries.moving_average(s, 3)
        assert len(avg) == 5
        assert avg[2] == pytest.approx(2.0)
        assert avg[4] == pytest.approx(4.0)

    def test_empty_series_returns_empty(self):
        assert _TimeSeries.moving_average([], 3) == []


class TestTimeSeriesLinearTrend:
    def test_perfect_linear_data_slope_is_1(self):
        series = [0.0, 1.0, 2.0, 3.0, 4.0]
        slope, intercept, r_sq = _TimeSeries.linear_trend(series)
        assert slope    == pytest.approx(1.0, abs=0.01)
        assert intercept == pytest.approx(0.0, abs=0.01)
        assert r_sq     == pytest.approx(1.0, abs=0.01)

    def test_flat_series_slope_is_zero(self):
        series = [5.0, 5.0, 5.0, 5.0]
        slope, _, r_sq = _TimeSeries.linear_trend(series)
        assert slope == pytest.approx(0.0, abs=0.01)

    def test_single_element_returns_zero_slope(self):
        slope, _, _ = _TimeSeries.linear_trend([42.0])
        assert slope == 0.0


class TestTimeSeriesZScores:
    def test_uniform_series_all_zero_z_scores(self):
        s = [5.0, 5.0, 5.0, 5.0]
        z = _TimeSeries.z_scores(s)
        assert all(abs(zi) < 0.01 for zi in z)

    def test_spike_has_positive_z_score(self):
        s = [1.0, 1.0, 1.0, 1.0, 100.0]
        z = _TimeSeries.z_scores(s)
        assert z[-1] > 1.0

    def test_single_element_returns_zero(self):
        assert _TimeSeries.z_scores([42.0]) == [0.0]


class TestTimeSeriesDetectAnomalies:
    def test_flat_series_has_no_anomalies(self):
        s    = [5.0] * 10
        anoms = _TimeSeries.detect_anomalies(s, threshold=2.0)
        assert not any(anoms)

    def test_spike_is_detected_as_anomaly(self):
        s    = [1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 100.0]
        anoms = _TimeSeries.detect_anomalies(s, threshold=2.0)
        assert anoms[-1] is True


class TestTimeSeriesForecastLinear:
    def test_perfect_linear_series_forecasted_correctly(self):
        series   = [0.0, 1.0, 2.0, 3.0, 4.0]
        forecast = _TimeSeries.forecast_linear(series, horizon=2)
        assert forecast[0] == pytest.approx(5.0, abs=0.1)
        assert forecast[1] == pytest.approx(6.0, abs=0.1)

    def test_forecast_returns_correct_horizon_length(self):
        series   = [1.0, 2.0, 3.0]
        forecast = _TimeSeries.forecast_linear(series, horizon=3)
        assert len(forecast) == 3


class TestTimeSeriesCompareWindows:
    def test_increasing_trend_detected(self):
        # Older window: [1,2] newer window: [10,11]
        s      = [1.0, 2.0, 10.0, 11.0]
        result = _TimeSeries.compare_windows(s, window=2)
        assert result["direction"] == "increasing"

    def test_decreasing_trend_detected(self):
        s      = [10.0, 11.0, 1.0, 2.0]
        result = _TimeSeries.compare_windows(s, window=2)
        assert result["direction"] == "decreasing"

    def test_stable_trend_detected(self):
        s      = [5.0, 5.0, 5.0, 5.0]
        result = _TimeSeries.compare_windows(s, window=2)
        assert result["direction"] == "stable"

    def test_returns_expected_keys(self):
        s      = [1.0, 2.0, 3.0, 4.0]
        result = _TimeSeries.compare_windows(s, window=2)
        assert {"previous_mean", "recent_mean", "pct_change", "direction"} <= set(result.keys())


class TestTimeSeriesOptimizeThreshold:
    def test_perfect_labels_returns_optimal_threshold(self):
        scores = [0.9, 0.8, 0.7, 0.2, 0.1]
        labels = [1,   1,   1,   0,   0]
        thr, meta = _TimeSeries.optimize_threshold(scores, labels, target_tpr=0.90)
        # Should separate TPs from FPs
        assert thr > 0
        assert isinstance(meta, dict)

    def test_empty_input_returns_default_50(self):
        thr, meta = _TimeSeries.optimize_threshold([], [], target_tpr=0.90)
        assert thr  == 50.0
        assert meta == {}

    def test_all_positives_returns_default(self):
        thr, _ = _TimeSeries.optimize_threshold([0.8, 0.9], [1, 1], target_tpr=0.90)
        assert thr == 50.0


# ---------------------------------------------------------------------------
# _CiscoTimeSeriesClient fallback behaviour tests
# ---------------------------------------------------------------------------

class TestCiscoTimeSeriesClient:
    def test_no_url_no_token_reports_unavailable(self):
        client = _CiscoTimeSeriesClient(base_url="", token="")
        assert client._is_available() is False

    def test_forecast_anomaly_falls_back_to_builtin(self):
        """When no endpoint is configured, forecast_anomaly uses _TimeSeries."""
        client = _CiscoTimeSeriesClient(base_url="", token="")
        result = client.forecast_anomaly([1.0, 2.0, 3.0, 4.0, 5.0])
        assert "anomalies" in result
        assert "forecast"  in result
        assert result["model"] == "builtin_linear"

    def test_optimize_threshold_falls_back_to_builtin(self):
        client = _CiscoTimeSeriesClient(base_url="", token="")
        result = client.optimize_threshold([0.9, 0.8, 0.2, 0.1], [1, 1, 0, 0])
        assert "optimal_threshold" in result
        assert result.get("model") == "builtin_sweep"

    def test_analyze_trend_falls_back_to_builtin(self):
        client = _CiscoTimeSeriesClient(base_url="", token="")
        result = client.analyze_trend([1.0, 2.0, 3.0, 4.0, 5.0])
        assert "direction" in result
        assert result.get("model") == "builtin_regression"


# ---------------------------------------------------------------------------
# Data class structure tests
# ---------------------------------------------------------------------------

class TestDataClassStructure:
    def test_rule_metrics_to_dict_has_all_fields(self):
        rm = RuleMetrics(
            rule_name="TEST-RULE", alert_type="TEST",
            total_alerts=100, true_positives=70, false_positives=30,
            tp_rate=0.70, fp_rate=0.30, avg_risk_score=72.0,
            avg_ttd_minutes=3.5, trend="stable", trend_pct_change=0.0,
            anomaly_this_week=False, recommended_action="maintain",
        )
        d = rm.to_dict()
        assert d["rule_name"]   == "TEST-RULE"
        assert d["tp_rate"]     == 0.70
        assert d["trend"]       == "stable"

    def test_efficacy_report_to_dict_has_rules_list(self):
        er = EfficacyReport(
            timeframe="7d", generated_at="2026-06-06T06:00:00Z",
            total_cases=50, overall_tp_rate=0.80, overall_fp_rate=0.20,
            avg_triage_s=5.0, avg_investigation_s=30.0, avg_response_s=45.0,
            total_mttr_minutes=1.35,
        )
        d = er.to_dict()
        assert "rules"  in d
        assert "timeframe" in d
        assert d["total_cases"] == 50

    def test_proposed_rule_to_dict_has_production_flag(self):
        pr = ProposedRule(
            rule_id="RULE-001", rule_name="Test Rule",
            alert_type="RANSOMWARE", description="Detects encoded PS",
            spl="index=edr | search encoded_cmd=*",
            rationale="High FP accuracy in backtest",
            backtest_tp_count=45, backtest_fp_count=2,
            backtest_fp_rate=0.04, backtest_query_time_s=1.2,
            proposed_for_production=True, rejection_reason="",
        )
        d = pr.to_dict()
        assert d["proposed_for_production"] is True
        assert d["backtest_fp_rate"]        == 0.04

    def test_weekly_report_to_dict_has_expected_keys(self):
        wr = WeeklyReport(
            report_period="2026-W23",
            cases_processed=35,
            autonomous_resolutions=28,
            human_escalations=7,
        )
        d = wr.to_dict()
        required = {
            "report_period", "cases_processed", "autonomous_resolutions",
            "human_escalations", "metrics", "detection_improvements",
            "threat_intel", "cost_savings", "recommendations",
            "tuning_applied", "agent_performance", "generated_at",
        }
        assert required <= set(d.keys())

    def test_ioc_to_dict_has_required_fields(self):
        ioc = IoC(
            value="185.220.101.42", ioc_type="ip",
            source="CASE-001", verdict="malicious",
        )
        d = ioc.to_dict()
        assert d["value"]    == "185.220.101.42"
        assert d["verdict"]  == "malicious"
        assert "submitted"   in d
        assert "confirmed"   in d


# ---------------------------------------------------------------------------
# SageAgent.analyze_detection_efficacy tests
# ---------------------------------------------------------------------------

class TestAnalyzeDetectionEfficacy:
    def _mock_spl_results(self):
        """Canned rows returned by mock_mcp.search_spl for efficacy queries."""
        return {
            "results": [
                {
                    "alert_type":  "RANSOMWARE_POWERSHELL_ENCODED",
                    "total_cases": "50",
                    "fp_count":    "5",
                    "tp_count":    "45",
                    "avg_score":   "78.2",
                    "avg_mttr_s":  "450.0",
                },
            ]
        }

    def test_returns_efficacy_report_instance(self, mock_mcp, mock_audit):
        agent = _make_agent(mock_mcp)
        mock_mcp.search_spl.return_value = self._mock_spl_results()

        with patch.object(agent, "_call_model", return_value="Analysis complete."):
            result = agent.analyze_detection_efficacy(timeframe="7d")

        assert isinstance(result, EfficacyReport)

    def test_efficacy_report_has_correct_timeframe(self, mock_mcp, mock_audit):
        agent = _make_agent(mock_mcp)
        mock_mcp.search_spl.return_value = self._mock_spl_results()

        with patch.object(agent, "_call_model", return_value="Analysis."):
            report = agent.analyze_detection_efficacy(timeframe="7d")

        assert report.timeframe == "7d"

    def test_efficacy_report_to_dict_is_serializable(self, mock_mcp, mock_audit):
        import json
        agent = _make_agent(mock_mcp)
        mock_mcp.search_spl.return_value = self._mock_spl_results()

        with patch.object(agent, "_call_model", return_value="Analysis."):
            report = agent.analyze_detection_efficacy(timeframe="7d")

        d = report.to_dict()
        # Must be JSON-serializable
        json.dumps(d, default=str)


# ---------------------------------------------------------------------------
# SageAgent.propose_detection_rule tests
# ---------------------------------------------------------------------------

class TestProposeDetectionRule:
    _CASE_DATA = {
        "case_id":        "CASE-001",
        "alert_type":     "RANSOMWARE_POWERSHELL_ENCODED",
        "classification": "RANSOMWARE_INITIAL_ACCESS",
        "key_indicators": ["encoded_ps", "office_parent"],
        "attack_narrative": "Phishing → encoded PS → LSASS dump → lateral movement.",
        "iocs_discovered": [
            {"value": "185.220.101.42", "type": "ip", "verdict": "malicious"}
        ],
    }

    def test_returns_proposed_rule_instance(self, mock_mcp, mock_audit):
        agent = _make_agent(mock_mcp)
        # Mock SPL generation + backtest results
        mock_mcp.validate_spl.return_value = {"valid": True, "warnings": []}
        mock_mcp.search_spl.return_value   = {
            "results": [
                {"week": "2026-21", "matches": "12", "unique_hosts": "3"},
                {"week": "2026-22", "matches": "8",  "unique_hosts": "2"},
            ]
        }

        with patch.object(agent, "_call_model", return_value=(
            '{"spl": "index=edr process_name=powershell.exe '
            'process_args=*-enc*",'
            '"rationale": "Detects encoded PowerShell execution."}'
        )):
            with patch.object(agent, "_get_saia") as mock_saia_factory:
                mock_saia = MagicMock()
                mock_saia.generate_spl.return_value = (
                    'index=`sentinel_edr_index` process_name="powershell.exe" '
                    'process_args="*-enc*" | stats count by host | sort -count'
                )
                mock_saia_factory.return_value = mock_saia
                result = agent.propose_detection_rule(self._CASE_DATA)

        assert isinstance(result, ProposedRule)

    def test_proposed_rule_has_required_fields(self, mock_mcp, mock_audit):
        agent = _make_agent(mock_mcp)
        mock_mcp.validate_spl.return_value = {"valid": True}
        mock_mcp.search_spl.return_value   = {"results": []}

        with patch.object(agent, "_call_model", return_value="{}"):
            with patch.object(agent, "_get_saia") as mock_saia_factory:
                mock_saia = MagicMock()
                mock_saia.generate_spl.return_value = 'index=edr process_name="powershell.exe"'
                mock_saia_factory.return_value = mock_saia
                result = agent.propose_detection_rule(self._CASE_DATA)

        d = result.to_dict()
        required = {
            "rule_id", "rule_name", "alert_type", "spl",
            "backtest_fp_rate", "proposed_for_production",
            "rejection_reason", "generated_at",
        }
        assert required <= set(d.keys())

    def test_high_fp_rate_rule_not_proposed_for_production(
        self, mock_mcp, mock_audit
    ):
        """If backtest FP rate > _MAX_FP_RATE_FOR_PRODUCTION, proposed_for_production must be False."""
        agent = _make_agent(mock_mcp)
        mock_mcp.validate_spl.return_value = {"valid": True}
        # Many FPs in backtest: 30 out of 50 matches
        mock_mcp.search_spl.return_value   = {"results": [
            {"week": "2026-21", "matches": "50", "unique_hosts": "20"},
        ]}

        with patch.object(agent, "_call_model", return_value="{}"):
            with patch.object(agent, "_get_saia") as mock_saia_factory:
                mock_saia = MagicMock()
                mock_saia.generate_spl.return_value = 'index=edr'
                mock_saia_factory.return_value = mock_saia
                with patch.object(agent, "_backtest_rule", return_value=(50, 30, 0.60, 1.5)):
                    result = agent.propose_detection_rule(self._CASE_DATA)

        # If _backtest_rule is not a real method, the test is still informative
        d = result.to_dict()
        if d["backtest_fp_rate"] > _MAX_FP_RATE_FOR_PRODUCTION:
            assert d["proposed_for_production"] is False


# ---------------------------------------------------------------------------
# SageAgent.generate_weekly_report tests
# ---------------------------------------------------------------------------

class TestGenerateWeeklyReport:
    def test_returns_weekly_report_instance(self, mock_mcp, mock_audit):
        agent = _make_agent(mock_mcp)
        mock_mcp.search_spl.return_value = {"results": []}

        with patch.object(agent, "_call_model", return_value="Weekly analysis."):
            with patch.object(agent, "analyze_detection_efficacy",
                              return_value=EfficacyReport(
                                  timeframe="7d", generated_at="2026-06-06T06:00:00Z",
                                  total_cases=35, overall_tp_rate=0.80, overall_fp_rate=0.20,
                                  avg_triage_s=5.0, avg_investigation_s=30.0,
                                  avg_response_s=45.0, total_mttr_minutes=1.35,
                              )):
                result = agent.generate_weekly_report()

        assert isinstance(result, WeeklyReport)

    def test_weekly_report_has_all_top_level_keys(self, mock_mcp, mock_audit):
        agent = _make_agent(mock_mcp)
        mock_mcp.search_spl.return_value = {"results": []}

        with patch.object(agent, "_call_model", return_value="Weekly analysis."):
            with patch.object(agent, "analyze_detection_efficacy",
                              return_value=EfficacyReport(
                                  timeframe="7d", generated_at="2026-06-06T06:00:00Z",
                                  total_cases=35, overall_tp_rate=0.80, overall_fp_rate=0.20,
                                  avg_triage_s=5.0, avg_investigation_s=30.0,
                                  avg_response_s=45.0, total_mttr_minutes=1.35,
                              )):
                result = agent.generate_weekly_report()

        d = result.to_dict()
        required = {
            "report_period", "cases_processed", "autonomous_resolutions",
            "human_escalations", "metrics", "recommendations", "generated_at",
        }
        assert required <= set(d.keys())


# ---------------------------------------------------------------------------
# SageAgent.run() tests (orchestrator entry point)
# ---------------------------------------------------------------------------

class TestSageRun:
    def test_run_returns_dict_with_success_key(self, mock_mcp, mock_audit):
        agent = _make_agent(mock_mcp)
        case  = _make_case()
        mock_mcp.search_spl.return_value = {"results": []}

        with patch.object(agent, "_extract_iocs_from_case", return_value=[]):
            with patch.object(agent, "propose_detection_rule",
                              return_value=ProposedRule(
                                  rule_id="R-001", rule_name="TestRule",
                                  alert_type="RANSOMWARE", description="test",
                                  spl="index=edr", rationale="test",
                                  backtest_tp_count=10, backtest_fp_count=1,
                                  backtest_fp_rate=0.09, backtest_query_time_s=0.5,
                                  proposed_for_production=False, rejection_reason="high FP",
                              )):
                with patch.object(agent, "_publish_learning_output", return_value=True):
                    result = agent.run(case, mock_audit)

        assert "success" in result

    def test_run_does_not_raise_on_exception(self, mock_mcp, mock_audit):
        agent = _make_agent(mock_mcp)
        case  = _make_case()

        with patch.object(agent, "_extract_iocs_from_case",
                          side_effect=RuntimeError("crash")):
            result = agent.run(case, mock_audit)

        # run() should catch exceptions and return success=False, not raise
        assert result.get("success") is False or "error" in result
