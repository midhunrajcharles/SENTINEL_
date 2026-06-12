"""
Integration tests for SAIA (Splunk AI Assistant) SPL generation.

Validates NL→SPL generation for 10 common investigation patterns,
validates each result with validate_spl, and checks latency.

SKIPPED by default — set SENTINEL_RUN_INTEGRATION=1 to run.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

_BIN = Path(__file__).resolve().parent.parent.parent / "app" / "sentinel" / "bin"
if str(_BIN) not in sys.path:
    sys.path.insert(0, str(_BIN))

pytestmark = pytest.mark.integration

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def saia_client():
    from agent_sherlock import _SAIAClient
    from utils.config import get_config
    cfg = get_config()
    return _SAIAClient(
        base_url = cfg.get("saia_endpoint", ""),
        token    = cfg.get("saia_token",    ""),
    )


@pytest.fixture(scope="module")
def mcp_client():
    from mcp_client import SplunkMCPClient
    from utils.config import get_config
    cfg = get_config()
    return SplunkMCPClient(cfg)


# ---------------------------------------------------------------------------
# 10 common NL → SPL investigation patterns
# ---------------------------------------------------------------------------

_PATTERNS = [
    (
        "pattern_lateral_movement",
        "Show me all lateral movement events from host DESKTOP-ABC123 in the last 24 hours",
        "earliest=-24h",
    ),
    (
        "pattern_privilege_escalation",
        "Find privilege escalation attempts by user jdoe using net.exe or net1.exe",
        "earliest=-24h",
    ),
    (
        "pattern_encoded_powershell",
        "Detect encoded PowerShell commands launched from Office applications",
        "earliest=-7d",
    ),
    (
        "pattern_ransomware_extension",
        "Search for file extension changes matching ransomware patterns like .locked or .encrypted",
        "earliest=-1h",
    ),
    (
        "pattern_c2_beacon",
        "Find periodic outbound connections that could be C2 beaconing from DESKTOP-ABC123",
        "earliest=-24h",
    ),
    (
        "pattern_credential_dump",
        "Detect LSASS memory access attempts consistent with credential dumping tools",
        "earliest=-24h",
    ),
    (
        "pattern_dns_exfiltration",
        "Identify unusually long DNS queries or high-frequency DNS requests that may indicate DNS tunneling",
        "earliest=-7d",
    ),
    (
        "pattern_persistence_run_key",
        "Find new registry run keys added in the last hour for persistence mechanisms",
        "earliest=-1h",
    ),
    (
        "pattern_lolbin_execution",
        "Detect LOLBin execution including certutil, bitsadmin, or regsvr32 used to download content",
        "earliest=-24h",
    ),
    (
        "pattern_data_exfiltration",
        "Find large data transfers (>100MB) to external IPs from sensitive servers in the last 48 hours",
        "earliest=-48h",
    ),
]


# ---------------------------------------------------------------------------
# Parametrised generation tests
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("pattern_id,question,time_range", _PATTERNS)
def test_saia_generates_spl_for_pattern(
    saia_client, mcp_client, pattern_id, question, time_range
):
    context = {
        "affected_host": "DESKTOP-ABC123",
        "time_range":     time_range,
    }

    t0      = time.monotonic()
    spl     = saia_client.generate_spl(question, context)
    elapsed = time.monotonic() - t0

    assert spl is not None, f"{pattern_id}: SAIA returned None"
    assert len(spl.strip()) > 0, f"{pattern_id}: SAIA returned empty SPL"
    assert elapsed < 5.0, (
        f"{pattern_id}: generation took {elapsed:.2f}s (limit 5s)"
    )


@pytest.mark.parametrize("pattern_id,question,time_range", _PATTERNS)
def test_generated_spl_is_syntactically_valid(
    saia_client, mcp_client, pattern_id, question, time_range
):
    """Each generated SPL must pass validate_spl (syntactic validity check)."""
    context = {
        "affected_host": "DESKTOP-ABC123",
        "time_range":     time_range,
    }
    spl = saia_client.generate_spl(question, context)
    if spl is None:
        pytest.skip(f"{pattern_id}: SAIA returned None, skipping validation")

    validation = mcp_client.validate_spl(spl)
    assert validation.get("valid") is True, (
        f"{pattern_id}: SPL failed validation — warnings: {validation.get('warnings', [])}\n"
        f"SPL: {spl}"
    )


# ---------------------------------------------------------------------------
# Performance benchmark
# ---------------------------------------------------------------------------

def test_all_patterns_generated_under_5s_each(saia_client):
    """Verify no single pattern exceeds the 5s latency budget."""
    failures = []
    for pattern_id, question, time_range in _PATTERNS:
        ctx     = {"affected_host": "DESKTOP-ABC123", "time_range": time_range}
        t0      = time.monotonic()
        saia_client.generate_spl(question, ctx)
        elapsed = time.monotonic() - t0
        if elapsed >= 5.0:
            failures.append(f"{pattern_id}: {elapsed:.2f}s")

    assert not failures, "Patterns exceeded 5s limit:\n" + "\n".join(failures)
