"""
Unit tests for agent_sherlock.py — per-query timeout + circuit breaker.

Covers: SherlockTimeoutError on a hung MCP/SAIA call, the consecutive-timeout
counter opening the circuit breaker (degraded mode / template-only fallback),
and cooldown-based half-open recovery once the backend responds again.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

_BIN = Path(__file__).resolve().parent.parent.parent / "app" / "sentinel" / "bin"
if str(_BIN) not in sys.path:
    sys.path.insert(0, str(_BIN))

with (
    patch("agent_sherlock.SplunkMCPClient", autospec=False),
    patch("agent_sherlock.get_audit_logger", return_value=MagicMock()),
    patch("agent_sherlock.get_config",       return_value=MagicMock()),
):
    from agent_sherlock import (
        SherlockAgent,
        SherlockTimeoutError,
        _CIRCUIT_BREAKER_THRESHOLD,
        _CIRCUIT_BREAKER_COOLDOWN_SECONDS,
        _PER_QUERY_TIMEOUT_SECONDS,
    )


def _make_agent():
    with patch("agent_sherlock.get_config", return_value=MagicMock()):
        return SherlockAgent(mcp=MagicMock(), saia=MagicMock())


def _open_circuit(agent):
    for _ in range(_CIRCUIT_BREAKER_THRESHOLD):
        agent._record_query_timeout("op", _PER_QUERY_TIMEOUT_SECONDS)
    assert agent.is_degraded is True


# ---------------------------------------------------------------------------
# _run_with_timeout — per-query wall-clock budget
# ---------------------------------------------------------------------------

class TestRunWithTimeout:
    def test_fast_call_returns_normally_and_keeps_circuit_closed(self):
        agent = _make_agent()

        result = agent._run_with_timeout(lambda: "ok", op_name="fast_op", timeout=5)

        assert result == "ok"
        assert agent._consecutive_timeouts == 0
        assert agent.is_degraded is False

    def test_slow_call_raises_sherlock_timeout_error(self):
        agent = _make_agent()

        def _slow():
            time.sleep(0.3)
            return "too late"

        with pytest.raises(SherlockTimeoutError):
            agent._run_with_timeout(_slow, op_name="slow_op", timeout=0.05)

        assert agent._consecutive_timeouts == 1

    def test_success_after_prior_timeouts_resets_counter(self):
        agent = _make_agent()
        agent._consecutive_timeouts = 2

        agent._run_with_timeout(lambda: "ok", op_name="fast_op", timeout=5)

        assert agent._consecutive_timeouts == 0
        assert agent.is_degraded is False


# ---------------------------------------------------------------------------
# Circuit breaker — opening on consecutive timeouts
# ---------------------------------------------------------------------------

class TestCircuitBreakerOpens:
    def test_threshold_constant_is_three(self):
        assert _CIRCUIT_BREAKER_THRESHOLD == 3

    def test_degrades_after_three_consecutive_timeouts(self):
        agent = _make_agent()
        assert agent.is_degraded is False

        for n in range(1, _CIRCUIT_BREAKER_THRESHOLD + 1):
            agent._record_query_timeout("op", _PER_QUERY_TIMEOUT_SECONDS)
            assert agent._consecutive_timeouts == n

        assert agent.is_degraded is True
        assert agent._degraded_since is not None

    def test_stays_closed_below_threshold(self):
        agent = _make_agent()

        for _ in range(_CIRCUIT_BREAKER_THRESHOLD - 1):
            agent._record_query_timeout("op", _PER_QUERY_TIMEOUT_SECONDS)

        assert agent.is_degraded is False
        assert agent._degraded_since is None

    def test_does_not_re_arm_degraded_since_once_open(self):
        agent = _make_agent()
        _open_circuit(agent)

        first_degraded_since = agent._degraded_since
        agent._record_query_timeout("op", _PER_QUERY_TIMEOUT_SECONDS)

        assert agent._degraded_since == first_degraded_since

    def test_run_with_timeout_opens_circuit_after_three_hangs(self):
        agent = _make_agent()

        def _slow():
            time.sleep(0.3)

        for _ in range(_CIRCUIT_BREAKER_THRESHOLD):
            with pytest.raises(SherlockTimeoutError):
                agent._run_with_timeout(_slow, op_name="hung_query", timeout=0.05)

        assert agent.is_degraded is True


# ---------------------------------------------------------------------------
# Circuit breaker — recovery after cooldown
# ---------------------------------------------------------------------------

class TestCircuitBreakerRecovery:
    def test_success_resets_consecutive_counter(self):
        agent = _make_agent()
        agent._record_query_timeout("op", _PER_QUERY_TIMEOUT_SECONDS)
        agent._record_query_timeout("op", _PER_QUERY_TIMEOUT_SECONDS)

        agent._record_query_success()

        assert agent._consecutive_timeouts == 0
        assert agent.is_degraded is False

    def test_success_closes_an_open_circuit(self):
        agent = _make_agent()
        _open_circuit(agent)

        agent._record_query_success()

        assert agent.is_degraded is False
        assert agent._degraded_since is None
        assert agent._consecutive_timeouts == 0

    def test_should_probe_true_when_circuit_closed(self):
        agent = _make_agent()
        assert agent._circuit_breaker_should_probe() is True

    def test_should_not_probe_immediately_after_opening(self):
        agent = _make_agent()
        _open_circuit(agent)

        assert agent._circuit_breaker_should_probe() is False

    def test_should_probe_after_cooldown_elapses(self):
        agent = _make_agent()
        _open_circuit(agent)
        agent._degraded_since = time.monotonic() - (_CIRCUIT_BREAKER_COOLDOWN_SECONDS + 1)

        assert agent._circuit_breaker_should_probe() is True

    def test_successful_probe_fully_recovers_the_circuit(self):
        agent = _make_agent()
        _open_circuit(agent)
        agent._degraded_since = time.monotonic() - (_CIRCUIT_BREAKER_COOLDOWN_SECONDS + 1)
        assert agent._circuit_breaker_should_probe() is True

        agent._record_query_success()

        assert agent.is_degraded is False
        assert agent._degraded_since is None
        assert agent._circuit_breaker_should_probe() is True
