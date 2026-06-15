#!/usr/bin/env python
"""
SENTINEL: Autonomous Agentic SOC Commander
splunk_api_server.py — Flask API backing the War Room dashboard with live
Splunk Cloud / Enterprise data.

Reads from the same sentinel.conf used by the agents (via
utils.config_loader / utils.splunk_connector.SplunkConnector), so it picks
up [splunk] host / api_token / username / password automatically — including
the basic-auth fallback while a freshly-issued auth token's `nbf` is still in
the future.

Run with::

    python demo/start_dashboard_server.py
"""

from __future__ import annotations

import json
import logging
import re
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Dict, Optional

import requests
from flask import Flask, Response, jsonify, request, send_from_directory
from flask_cors import CORS

_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT / "app" / "sentinel" / "bin"))

from utils.config_loader import get_config  # noqa: E402
from utils.splunk_connector import SplunkConnector  # noqa: E402
from audit_logger import AuditLogger  # noqa: E402

log = logging.getLogger("sentinel.dashboard_api")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

app = Flask(__name__, static_folder=None)
CORS(app)

_cfg = get_config()
_connector = SplunkConnector()

# Tokens / identifiers embedded in SPL must be restricted to a safe charset
# to avoid SPL injection via query parameters.
_SAFE_TOKEN = re.compile(r"^[A-Za-z0-9_\-:.]{1,128}$")


def _safe_token(value: Optional[str], default: str) -> str:
    if value and _SAFE_TOKEN.match(value):
        return value
    return default


def _audit_logger() -> AuditLogger:
    return AuditLogger(
        agent_name="dashboard_api",
        hec_url=_cfg.get("hec", "url", default="https://localhost:8088"),
        hec_token=_cfg.get("hec", "token", default=""),
        hec_index=_cfg.get("hec", "index", default="sentinel_audit"),
        verify_ssl=_cfg.get_bool("general", "verify_ssl", default=False),
    )


def _hec_send(event: Dict[str, Any], index: str, sourcetype: str) -> bool:
    """Send a single event to HEC (used for case-state updates)."""
    hec_url = _cfg.get("hec", "url", default="")
    hec_token = _cfg.get("hec", "token", default="")
    if not hec_url or not hec_token:
        log.warning("HEC not configured — cannot write to index=%s", index)
        return False
    try:
        resp = requests.post(
            hec_url.rstrip("/") + "/services/collector/event",
            headers={"Authorization": f"Splunk {hec_token}"},
            json={"event": event, "index": index, "sourcetype": sourcetype},
            verify=_cfg.get_bool("general", "verify_ssl", default=False),
            timeout=15,
        )
        return resp.status_code == 200
    except Exception as exc:
        log.error("HEC send to index=%s failed: %s", index, exc)
        return False


# ---------------------------------------------------------------------------
# Request logging
# ---------------------------------------------------------------------------

@app.before_request
def _start_timer() -> None:
    request._start_time = time.time()  # type: ignore[attr-defined]


@app.after_request
def _log_request(response: Response) -> Response:
    duration_ms = int((time.time() - getattr(request, "_start_time", time.time())) * 1000)
    log.info("%s %s -> %s (%dms)", request.method, request.path, response.status_code, duration_ms)
    return response


def _splunk_unavailable(exc: Exception):
    log.error("Splunk request failed: %s", exc)
    return jsonify({
        "error": "Splunk Cloud unreachable",
        "detail": str(exc),
        "fallback": "Check IP allowlist and [splunk] credentials in sentinel.conf",
    }), 503


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------

@app.route("/api/splunk/status")
def splunk_status():
    host = _cfg.get("splunk", "host", default="localhost")
    try:
        service = _connector.connect()
        info = service.info
        version = info.get("version") if hasattr(info, "get") else getattr(info, "version", "unknown")
        return jsonify({"status": "connected", "host": host, "version": version})
    except Exception as exc:
        return jsonify({"status": "disconnected", "host": host, "error": str(exc)})


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------

@app.route("/api/alerts")
def list_alerts():
    status = _safe_token(request.args.get("status"), "new")
    limit = max(1, min(int(request.args.get("limit", 50)), 500))

    spl = (
        f'search index=sentinel_alerts (sentinel_status="{status}" OR status="{status}") '
        f'| head {limit} '
        f'| table _time, alert_id, alert_type, severity, host, user, src_ip, dest_ip, score, status, sentinel_status'
    )
    try:
        rows = _connector.search(spl, earliest="-24h", latest="now", max_results=limit)
    except Exception as exc:
        return _splunk_unavailable(exc)
    return jsonify({"alerts": rows, "count": len(rows), "source": "splunk_cloud"})


@app.route("/api/alerts/<alert_id>")
def get_alert(alert_id: str):
    alert_id = _safe_token(alert_id, "")
    if not alert_id:
        return jsonify({"error": "invalid alert_id"}), 400

    spl = f'search index=sentinel_alerts alert_id="{alert_id}" | head 1'
    try:
        row = _connector.search_one(spl, earliest="-7d", latest="now")
    except Exception as exc:
        return _splunk_unavailable(exc)
    if row is None:
        return jsonify({"error": "not found"}), 404
    return jsonify({"alert": row, "source": "splunk_cloud"})


# ---------------------------------------------------------------------------
# Cases
# ---------------------------------------------------------------------------

@app.route("/api/cases")
def list_cases():
    status = _safe_token(request.args.get("status"), "active")
    limit = max(1, min(int(request.args.get("limit", 20)), 200))

    spl = (
        f'search index=sentinel_cases status="{status}" '
        f'| stats latest(*) as * by case_id '
        f'| head {limit} '
        f'| table case_id, alert_id, status, vanguard_score, created_at, updated_at'
    )
    try:
        rows = _connector.search(spl, earliest="-7d", latest="now", max_results=limit)
    except Exception as exc:
        return _splunk_unavailable(exc)
    return jsonify({"cases": rows, "count": len(rows), "source": "splunk_cloud"})


@app.route("/api/cases/<case_id>")
def get_case(case_id: str):
    case_id = _safe_token(case_id, "")
    if not case_id:
        return jsonify({"error": "invalid case_id"}), 400

    spl = (
        f'search index=sentinel_cases case_id="{case_id}" '
        f'| stats latest(*) as * by case_id | head 1'
    )
    try:
        case = _connector.search_one(spl, earliest="-30d", latest="now")
    except Exception as exc:
        return _splunk_unavailable(exc)
    if case is None:
        return jsonify({"error": "not found"}), 404

    reports_spl = (
        f'search index=sentinel_audit case_id="{case_id}" event_type="decision" '
        f'| sort _time | table _time, agent_name, decision_type, confidence, reasoning'
    )
    try:
        reports = _connector.search(reports_spl, earliest="-30d", latest="now", max_results=50)
    except Exception:
        reports = []

    return jsonify({"case": case, "agent_reports": reports, "source": "splunk_cloud"})


# ---------------------------------------------------------------------------
# Agents
# ---------------------------------------------------------------------------

@app.route("/api/agents")
def list_agents():
    spl = (
        'search index=sentinel_audit action="agent_status" '
        '| stats latest(*) as * by agent | head 10'
    )
    try:
        rows = _connector.search(spl, earliest="-1h", latest="now", max_results=10)
    except Exception as exc:
        return _splunk_unavailable(exc)

    if not rows:
        # Fallback: KV Store agent_state collection (per-agent heartbeat written
        # by sentinel_orchestrator.py)
        try:
            rows = _connector.kvstore_query("agent_state")
        except Exception:
            rows = []

    agents = [{
        "name": r.get("agent") or r.get("name") or r.get("_key", "unknown"),
        "status": r.get("status", "unknown"),
        "current_case": r.get("current_case") or r.get("case_id"),
        "success_count": r.get("success_count", 0),
        "error_count": r.get("error_count", 0),
        "queue_depth": r.get("queue_depth", 0),
    } for r in rows]

    return jsonify({"agents": agents, "source": "splunk_cloud" if rows else "no_data"})


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------

@app.route("/api/metrics")
def get_metrics():
    try:
        mttr_row = _connector.search_one(
            'search index=sentinel_metrics metric="mttr" | head 1 | table value',
            earliest="-7d", latest="now",
        )
        mttr = float(mttr_row.get("value", 0)) if mttr_row else None

        threats_row = _connector.search_one(
            'search index=sentinel_audit action="threat_contained" | stats count',
            earliest="-7d", latest="now",
        )
        threats_contained = int(threats_row.get("count", 0)) if threats_row else 0

        fp_row = _connector.search_one(
            'search index=sentinel_cases '
            '| stats count(eval(status="false_positive")) as fp, count as total',
            earliest="-7d", latest="now",
        )
        fp_rate = None
        if fp_row and int(fp_row.get("total", 0)) > 0:
            fp_rate = round(100.0 * int(fp_row["fp"]) / int(fp_row["total"]), 1)

        auto_row = _connector.search_one(
            'search index=sentinel_cases '
            '| stats count(eval(status="auto_resolved")) as auto, count as total',
            earliest="-7d", latest="now",
        )
        autonomous_rate = None
        if auto_row and int(auto_row.get("total", 0)) > 0:
            autonomous_rate = round(100.0 * int(auto_row["auto"]) / int(auto_row["total"]), 1)

    except Exception as exc:
        return _splunk_unavailable(exc)

    return jsonify({
        "mttr": mttr,
        "threats_contained": threats_contained,
        "fp_rate": fp_rate,
        "autonomous_rate": autonomous_rate,
        "source": "splunk_cloud",
    })


# ---------------------------------------------------------------------------
# Timeline / MCP activity
# ---------------------------------------------------------------------------

@app.route("/api/timeline")
def get_timeline():
    case_id = _safe_token(request.args.get("case_id"), "")
    if not case_id:
        return jsonify({"error": "case_id required"}), 400

    spl = f'search index=sentinel_audit case_id="{case_id}" | sort _time'
    try:
        rows = _connector.search(spl, earliest="-30d", latest="now", max_results=500)
    except Exception as exc:
        return _splunk_unavailable(exc)
    return jsonify({"events": rows, "source": "splunk_cloud"})


@app.route("/api/mcp/activity")
def get_mcp_activity():
    spl = 'search index=sentinel_audit action="mcp_call" | head 50 | sort -_time'
    try:
        rows = _connector.search(spl, earliest="-1h", latest="now", max_results=50)
    except Exception as exc:
        return _splunk_unavailable(exc)
    return jsonify({"calls": rows, "source": "splunk_cloud"})


# ---------------------------------------------------------------------------
# Human override: halt / resume
# ---------------------------------------------------------------------------

@app.route("/api/halt", methods=["POST"])
def halt_case():
    body = request.get_json(silent=True) or {}
    case_id = _safe_token(body.get("case_id"), "")
    reason = str(body.get("reason", ""))[:500]
    if not case_id:
        return jsonify({"error": "case_id required"}), 400

    now = time.time()
    ok = _hec_send(
        {"case_id": case_id, "status": "halted", "reason": reason, "updated_at": now},
        index="sentinel_cases", sourcetype="sentinel:case_update",
    )
    _audit_logger().log_decision(
        case_id=case_id,
        decision_type="HUMAN_HALT",
        confidence=1.0,
        input_context={"reason": reason},
        output_decision={"status": "halted"},
        reasoning=reason or "Halted via dashboard",
    )
    if not ok:
        return jsonify({"status": "halted", "case_id": case_id, "warning": "HEC write failed — audit log only"}), 200
    return jsonify({"status": "halted", "case_id": case_id})


@app.route("/api/resume", methods=["POST"])
def resume_case():
    body = request.get_json(silent=True) or {}
    case_id = _safe_token(body.get("case_id"), "")
    if not case_id:
        return jsonify({"error": "case_id required"}), 400

    # Look up the most recent non-halted status to resume into; default "active"
    prev_status = "active"
    try:
        prior = _connector.search_one(
            f'search index=sentinel_cases case_id="{case_id}" status!="halted" '
            f'| sort -_time | head 1 | table status',
            earliest="-30d", latest="now",
        )
        if prior and prior.get("status"):
            prev_status = prior["status"]
    except Exception:
        pass

    now = time.time()
    ok = _hec_send(
        {"case_id": case_id, "status": prev_status, "updated_at": now},
        index="sentinel_cases", sourcetype="sentinel:case_update",
    )
    _audit_logger().log_decision(
        case_id=case_id,
        decision_type="HUMAN_RESUME",
        confidence=1.0,
        input_context={},
        output_decision={"status": prev_status},
        reasoning="Resumed via dashboard",
    )
    if not ok:
        return jsonify({"status": prev_status, "case_id": case_id, "warning": "HEC write failed — audit log only"}), 200
    return jsonify({"status": prev_status, "case_id": case_id})


# ---------------------------------------------------------------------------
# Server-Sent Events stream
# ---------------------------------------------------------------------------

@app.route("/api/stream")
def stream():
    def _events():
        last_alert_ts = time.time()
        last_case_ts = time.time()
        while True:
            now = time.time()

            try:
                new_alerts = _connector.search(
                    f'search index=sentinel_alerts | where _time > {last_alert_ts} | sort _time',
                    earliest=f"-{int(now - last_alert_ts) + 5}s", latest="now", max_results=50,
                )
            except Exception as exc:
                new_alerts = []
                log.debug("SSE alert poll failed: %s", exc)

            for row in new_alerts:
                yield f"data: {json.dumps({'type': 'alert', 'data': row})}\n\n"

            try:
                case_updates = _connector.search(
                    f'search index=sentinel_cases | where _time > {last_case_ts} | sort _time',
                    earliest=f"-{int(now - last_case_ts) + 5}s", latest="now", max_results=50,
                )
            except Exception as exc:
                case_updates = []
                log.debug("SSE case poll failed: %s", exc)

            for row in case_updates:
                yield f"data: {json.dumps({'type': 'case_update', 'data': row})}\n\n"

            last_alert_ts = now
            last_case_ts = now
            time.sleep(5)

    return Response(_events(), mimetype="text/event-stream")


# ---------------------------------------------------------------------------
# Static dashboard files
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return send_from_directory(Path(__file__).resolve().parent, "sentinel_war_room_live.html")


@app.route("/<path:filename>")
def static_files(filename: str):
    return send_from_directory(Path(__file__).resolve().parent, filename)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=False, threaded=True)
