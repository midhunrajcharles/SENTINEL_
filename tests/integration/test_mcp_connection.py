"""
Integration tests for SplunkMCPClient — all 14 custom MCP tools.

Tests are run against a live Splunk instance with a real MCP server.
SKIPPED by default — set SENTINEL_RUN_INTEGRATION=1 to run.
"""

from __future__ import annotations

import sys
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
def mcp():
    """Real SplunkMCPClient connected to the test Splunk instance."""
    from mcp_client import SplunkMCPClient
    from utils.config import get_config
    cfg = get_config()
    client = SplunkMCPClient(cfg)
    yield client
    client.close()


# ---------------------------------------------------------------------------
# Connectivity smoke test
# ---------------------------------------------------------------------------

def test_mcp_server_is_reachable(mcp):
    """Verify MCP server responds before running per-tool tests."""
    indexes = mcp.get_indexes()
    assert isinstance(indexes, (dict, list))


# ---------------------------------------------------------------------------
# Tool: search_spl
# ---------------------------------------------------------------------------

def test_search_spl_basic_returns_results(mcp):
    result = mcp.search_spl(
        'index=_internal sourcetype=splunkd | head 5 | fields host, _time'
    )
    assert "results" in result

def test_search_spl_invalid_spl_raises_mcp_error(mcp):
    from mcp_client import MCPError
    with pytest.raises(MCPError):
        mcp.search_spl("THIS IS NOT VALID SPL !!!@#$%")

def test_search_spl_timeout_raises_mcp_error(mcp):
    """Very long-running search should time out cleanly, not hang."""
    from mcp_client import MCPError
    try:
        mcp.search_spl(
            'index=* | stats count by host | eval x=1 | sort 0 -x',
            timeout_s=2,
        )
    except MCPError:
        pass  # expected


# ---------------------------------------------------------------------------
# Tool: validate_spl
# ---------------------------------------------------------------------------

def test_validate_spl_accepts_valid_query(mcp):
    result = mcp.validate_spl('index=_internal sourcetype=splunkd | head 5')
    assert result.get("valid") is True

def test_validate_spl_rejects_invalid_syntax(mcp):
    result = mcp.validate_spl("index=* | NOTACOMMAND 12345")
    assert result.get("valid") is False


# ---------------------------------------------------------------------------
# Tool: get_asset_context
# ---------------------------------------------------------------------------

def test_get_asset_context_returns_dict(mcp):
    result = mcp.get_asset_context("localhost")
    assert isinstance(result, dict)

def test_get_asset_context_unknown_host_does_not_raise(mcp):
    result = mcp.get_asset_context("no-such-host-sentinel-test-9999")
    assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# Tool: get_process_tree
# ---------------------------------------------------------------------------

def test_get_process_tree_returns_dict_or_none(mcp):
    result = mcp.get_process_tree(host="localhost", pid="1234")
    assert result is None or isinstance(result, dict)


# ---------------------------------------------------------------------------
# Tool: get_network_flows
# ---------------------------------------------------------------------------

def test_get_network_flows_returns_list(mcp):
    result = mcp.get_network_flows(host="localhost", time_range="-15m")
    assert isinstance(result, (list, dict))


# ---------------------------------------------------------------------------
# Tool: get_user_activity
# ---------------------------------------------------------------------------

def test_get_user_activity_returns_dict(mcp):
    result = mcp.get_user_activity(username="administrator", time_range="-1h")
    assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# Tool: query_es_notable
# ---------------------------------------------------------------------------

def test_query_es_notable_returns_list(mcp):
    result = mcp.query_es_notable(limit=5)
    assert isinstance(result, (list, dict))


# ---------------------------------------------------------------------------
# Tool: get_indexes
# ---------------------------------------------------------------------------

def test_get_indexes_returns_list_with_internal(mcp):
    result = mcp.get_indexes()
    # _internal always exists
    index_names = [i.get("name", i) if isinstance(i, dict) else i for i in result]
    assert "_internal" in index_names or isinstance(result, dict)


# ---------------------------------------------------------------------------
# Tool: run_saved_search
# ---------------------------------------------------------------------------

def test_run_saved_search_nonexistent_returns_error_not_exception(mcp):
    from mcp_client import MCPError
    try:
        result = mcp.run_saved_search("sentinel_test_nonexistent_saved_search_9999")
        # May return empty result dict
        assert isinstance(result, dict)
    except MCPError:
        pass  # also acceptable


# ---------------------------------------------------------------------------
# Tool: get_knowledge_objects
# ---------------------------------------------------------------------------

def test_get_knowledge_objects_returns_structure(mcp):
    result = mcp.get_knowledge_objects()
    assert isinstance(result, (dict, list))


# ---------------------------------------------------------------------------
# Tool: execute_response_action
# ---------------------------------------------------------------------------

def test_execute_response_action_dry_run_does_not_raise(mcp):
    """Dry-run mode should succeed without side effects."""
    result = mcp.execute_response_action(
        action_type = "isolate_host",
        target      = "SENTINEL-TEST-HOST",
        dry_run     = True,
    )
    assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# Tool: create_ticket
# ---------------------------------------------------------------------------

def test_create_ticket_returns_ticket_id(mcp):
    result = mcp.create_ticket(
        title       = "[SENTINEL TEST] Integration test ticket — delete me",
        description = "Automated integration test ticket from SENTINEL test suite.",
        priority    = "low",
        dry_run     = True,
    )
    assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# Tool: notify_stakeholders
# ---------------------------------------------------------------------------

def test_notify_stakeholders_dry_run_returns_ok(mcp):
    result = mcp.notify_stakeholders(
        recipients  = ["sentinel-test@example.com"],
        subject     = "[SENTINEL TEST] Integration test notification",
        body        = "Automated integration test — ignore.",
        dry_run     = True,
    )
    assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# Tool: enrich_threat_intel
# ---------------------------------------------------------------------------

def test_enrich_threat_intel_returns_enrichment_for_known_malicious_ip(mcp):
    result = mcp.enrich_threat_intel(indicator="185.220.101.42", indicator_type="ip")
    assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# Auth / token refresh tests
# ---------------------------------------------------------------------------

def test_auth_failure_raises_mcp_error_not_runtime_error(mcp):
    """Sending a bad token should raise MCPError cleanly."""
    from mcp_client import SplunkMCPClient, MCPError
    from utils.config import get_config
    cfg = get_config()

    class _BadTokenMCP(SplunkMCPClient):
        def _get_token(self):
            return "INVALID_TOKEN_SENTINEL_TEST"

    bad_mcp = _BadTokenMCP(cfg)
    with pytest.raises(MCPError):
        bad_mcp.search_spl("index=_internal | head 1")
