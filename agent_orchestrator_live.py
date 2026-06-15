"""
SENTINEL Live Data Stack — agent orchestrator
agent_orchestrator_live.py

Four polling loops — one per SENTINEL agent — that pull real rows out of
SQLite, "process" them with a small simulated delay, and write their
decisions back:

  VANGUARD  (every 5s)  : alerts WHERE status='new'      -> triage, score, create case
  SHERLOCK  (every 10s) : cases  WHERE status='triaged'   -> investigate, write report
  EXECUTOR  (every 10s) : cases  WHERE status='investigated' -> respond, log actions
  SAGE      (every 60s) : cases  WHERE status='responded' -> close out, compute metrics

Every state change updates `agent_state` and publishes onto the shared
EventBus (channels: "alerts", "cases", "agents", "metrics") so the
WebSocket layer in live_api_server.py can push it straight to the browser.
"""

from __future__ import annotations

import json
import random
import threading

from sentinel_live_common import BUS, case_to_dict, get_conn, new_id, now, row_to_dict

# ---------------------------------------------------------------------------
# Polling cadence
# ---------------------------------------------------------------------------

VANGUARD_POLL_SEC = 5
SHERLOCK_POLL_SEC = 10
EXECUTOR_POLL_SEC = 10
SAGE_POLL_SEC = 60

# Simulated processing delays (spec: Vanguard 2-5s, Sherlock 10-30s, Executor 5-15s, Sage 5-10s)
VANGUARD_DELAY = (2, 5)
SHERLOCK_DELAY = (10, 20)   # compressed from the 10-30s spec ceiling for a livelier demo
EXECUTOR_DELAY = (5, 15)
SAGE_DELAY = (5, 10)

ASSET_CRITICALITY = {
    "SERVER": 1.25,
    "FILESERVER": 1.3,
    "JUMP": 1.15,
    "DESKTOP": 1.0,
    "LAPTOP": 0.95,
}

SEVERITY_BASE = {"low": 18, "medium": 42, "high": 66, "critical": 88}

ACTION_BY_ALERT_TYPE = {
    "POWERSHELL_EXECUTION": ("isolate_host", "host"),
    "SMB_LATERAL_MOVEMENT": ("isolate_host", "host"),
    "DATA_EXFILTRATION": ("block_egress_ip", "dest_ip"),
    "INSIDER_THREAT": ("disable_account", "user"),
    "CLOUD_MISCONFIG": ("revoke_cloud_session", "user"),
    "C2_BEACON": ("block_egress_ip", "dest_ip"),
    "RANSOMWARE_ENCRYPTION": ("isolate_host", "host"),
    "PRIVILEGE_ESCALATION": ("disable_account", "user"),
    "CREDENTIAL_DUMPING": ("force_password_reset", "user"),
}


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _set_agent_state(conn, agent: str, **fields) -> None:
    sets = ", ".join(f"{k}=?" for k in fields)
    conn.execute(f"UPDATE agent_state SET {sets} WHERE agent_name=?", (*fields.values(), agent))
    conn.commit()
    row = conn.execute("SELECT * FROM agent_state WHERE agent_name=?", (agent,)).fetchone()
    BUS.publish("agents", {"type": "agent_update", "data": row_to_dict(row)})


def _publish_case(conn, case_id: str) -> None:
    row = conn.execute("SELECT * FROM cases WHERE case_id=?", (case_id,)).fetchone()
    if row:
        BUS.publish("cases", {"type": "case_update", "data": case_to_dict(row)})


def _threat_intel_lookup(conn, *iocs: str) -> dict | None:
    best = None
    for ioc in iocs:
        if not ioc:
            continue
        row = conn.execute(
            "SELECT * FROM threat_intel WHERE ioc=? ORDER BY last_seen DESC LIMIT 1", (ioc,)
        ).fetchone()
        if row and (best is None or row["reputation_score"] > best["reputation_score"]):
            best = row
    return row_to_dict(best) if best else None


# ---------------------------------------------------------------------------
# VANGUARD — Triage
# ---------------------------------------------------------------------------

def _asset_criticality(host: str) -> float:
    for prefix, weight in ASSET_CRITICALITY.items():
        if host and host.startswith(prefix):
            return weight
    return 1.0


def _temporal_factor() -> float:
    import datetime
    hour = datetime.datetime.now().hour
    return 1.15 if (hour >= 22 or hour < 6) else 1.0


def vanguard_process(conn, alert: dict) -> None:
    _set_agent_state(conn, "vanguard", status="processing", current_case_id=None,
                      last_action=f"Triaging {alert['alert_id']}", last_action_time=now())

    ti = _threat_intel_lookup(conn, alert["src_ip"], alert["dest_ip"])
    threat_rep = ti["reputation_score"] if ti else 0.25
    threat_factor = 0.7 + threat_rep  # ~0.7 .. 1.69

    base = SEVERITY_BASE.get(alert["severity"], 40)
    criticality = _asset_criticality(alert["host"])
    temporal = _temporal_factor()

    score = round(min(100, base * criticality * temporal * threat_factor), 1)

    if score < 20:
        decision = "DISMISS"
    elif score < 70:
        decision = "QUEUE_FOR_INVESTIGATION"
    elif score < 85:
        decision = "INVESTIGATE_PRIORITY"
    else:
        decision = "AUTO_ESCALATE"

    chain_of_thought = [
        {
            "step": 1, "name": "Initial Alert Triage",
            "observation": f"{alert['alert_type']} on {alert['host']} ({alert['mitre_tactic']} / {alert['mitre_technique']})",
            "query": f"index=sentinel_alerts alert_id=\"{alert['alert_id']}\"",
            "justification": f"Base severity '{alert['severity']}' (={base}), asset criticality x{criticality}, "
                             f"temporal factor x{temporal}",
        },
        {
            "step": 2, "name": "Threat Intelligence Correlation",
            "observation": (f"IOC {ti['ioc']} reputation {ti['reputation_score']} "
                            f"({ti['threat_actor']} / {ti['malware_family']})") if ti
                           else "No matching threat intel for src/dest IP",
            "query": f"| inputlookup threat_intel where ioc IN (\"{alert['src_ip']}\", \"{alert['dest_ip']}\")",
            "risk_matrix": {"threat_reputation": threat_rep},
        },
        {
            "step": 3, "name": "Composite Scoring",
            "result": f"composite_score={score}",
            "conclusion": f"{decision} (score {score})",
            "action": decision,
        },
    ]

    alert_time = alert["_time"]
    conn.execute("UPDATE alerts SET status=? WHERE alert_id=?",
                 ("dismissed" if decision == "DISMISS" else "triaged", alert["alert_id"]))

    case_id = None
    if decision != "DISMISS":
        case_id = new_id("SEN")
        conn.execute(
            """INSERT INTO cases (case_id, alert_id, status, vanguard_score, vanguard_decision, created_at, updated_at)
               VALUES (?,?,?,?,?,?,?)""",
            (case_id, alert["alert_id"], "triaged", score,
             json.dumps({"decision": decision, "chain_of_thought": chain_of_thought, "alert": alert}),
             alert_time, now()),
        )

    queue_depth = conn.execute("SELECT COUNT(*) AS c FROM alerts WHERE status='new'").fetchone()["c"]
    conn.commit()

    BUS.publish("alerts", {"type": "alert_update", "data": {"alert_id": alert["alert_id"], "status": "triaged" if case_id else "dismissed"}})
    if case_id:
        _publish_case(conn, case_id)

    _set_agent_state(
        conn, "vanguard", status="idle", current_case_id=case_id,
        last_action=f"{decision} {alert['alert_id']} (score {score})", last_action_time=now(),
        success_count=conn.execute("SELECT success_count FROM agent_state WHERE agent_name='vanguard'").fetchone()["success_count"] + 1,
        queue_depth=queue_depth,
    )


def vanguard_loop(stop_event: threading.Event) -> None:
    conn = get_conn()
    try:
        while not stop_event.is_set():
            row = conn.execute(
                "SELECT * FROM alerts WHERE status='new' ORDER BY _time ASC LIMIT 1"
            ).fetchone()
            if row:
                alert = row_to_dict(row)
                if stop_event.wait(random.uniform(*VANGUARD_DELAY)):
                    return
                vanguard_process(conn, alert)
                continue
            if stop_event.wait(VANGUARD_POLL_SEC):
                break
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# SHERLOCK — Investigation
# ---------------------------------------------------------------------------

def sherlock_process(conn, case: dict) -> None:
    case_id = case["case_id"]
    vdec = json.loads(case["vanguard_decision"]) if case["vanguard_decision"] else {}
    alert = vdec.get("alert", {})
    host = alert.get("host")
    src_ip = alert.get("src_ip")
    dest_ip = alert.get("dest_ip")
    alert_time = alert.get("_time", now())

    _set_agent_state(conn, "sherlock", status="processing", current_case_id=case_id,
                      last_action=f"Investigating {case_id}", last_action_time=now())

    investigation_chain = []

    # Phase 1: host context
    host_count = conn.execute(
        "SELECT COUNT(*) AS c FROM events WHERE host=? AND _time > ?", (host, now() - 3600)
    ).fetchone()["c"]
    investigation_chain.append({
        "step": 1, "name": "Host Context",
        "query": f"index=sentinel_endpoint host=\"{host}\" earliest=-60m",
        "observation": f"{host_count} endpoint events for {host} in the last 60 minutes",
        "result": f"host_event_count={host_count}",
    })

    # Phase 2: timeline reconstruction (+-60min of alert time)
    window_count = conn.execute(
        "SELECT COUNT(*) AS c FROM events WHERE host=? AND _time BETWEEN ? AND ?",
        (host, alert_time - 3600, alert_time + 3600),
    ).fetchone()["c"]
    investigation_chain.append({
        "step": 2, "name": "Timeline Reconstruction",
        "query": f"index=* host=\"{host}\" earliest={alert_time - 3600} latest={alert_time + 3600}",
        "observation": f"{window_count} events within +/-60m of the triggering alert",
        "result": f"timeline_event_count={window_count}",
    })

    # Phase 3: lateral movement — distinct internal destinations from this host
    lateral = conn.execute(
        """SELECT COUNT(DISTINCT json_extract(fields_json,'$.dest_ip')) AS c
           FROM events WHERE host=? AND sourcetype IN ('network:flow','edr:network_connection')
             AND _time > ?""",
        (host, now() - 3600),
    ).fetchone()["c"]
    investigation_chain.append({
        "step": 3, "name": "Lateral Movement Check",
        "query": f"index=sentinel_network host=\"{host}\" earliest=-60m | stats dc(dest_ip)",
        "observation": f"{lateral} distinct destination(s) contacted from {host} in the last hour",
        "inference": "Multiple distinct internal destinations suggest scanning/lateral movement"
                      if lateral and lateral > 3 else "No significant lateral movement pattern observed",
    })

    # Phase 4: threat intel enrichment
    ti = _threat_intel_lookup(conn, src_ip, dest_ip)
    investigation_chain.append({
        "step": 4, "name": "Threat Intel Enrichment",
        "query": f"| inputlookup threat_intel where ioc IN (\"{src_ip}\", \"{dest_ip}\")",
        "observation": (f"{ti['ioc']} -> {ti['threat_actor']} / {ti['malware_family']} "
                        f"(reputation {ti['reputation_score']})") if ti else "No IOC matches found",
        "conclusion": "Confirms known-malicious infrastructure involvement" if ti and ti["reputation_score"] > 0.7
                      else "No corroborating threat intelligence",
    })

    severity_assessment = "CONFIRMED_MALICIOUS" if (ti and ti["reputation_score"] > 0.7) or (lateral and lateral > 3) \
        else "SUSPICIOUS"

    report = {
        "investigation_chain": investigation_chain,
        "severity_assessment": severity_assessment,
        "host_event_count": host_count,
        "timeline_event_count": window_count,
        "lateral_movement_destinations": lateral,
        "threat_intel": ti,
        "generated_at": now(),
    }

    conn.execute(
        "UPDATE cases SET status='investigated', sherlock_report_json=?, updated_at=? WHERE case_id=?",
        (json.dumps(report), now(), case_id),
    )
    queue_depth = conn.execute("SELECT COUNT(*) AS c FROM cases WHERE status='triaged'").fetchone()["c"]
    conn.commit()

    _publish_case(conn, case_id)
    _set_agent_state(
        conn, "sherlock", status="idle", current_case_id=case_id,
        last_action=f"Investigation complete: {severity_assessment} ({case_id})", last_action_time=now(),
        success_count=conn.execute("SELECT success_count FROM agent_state WHERE agent_name='sherlock'").fetchone()["success_count"] + 1,
        queue_depth=queue_depth,
    )


def sherlock_loop(stop_event: threading.Event) -> None:
    conn = get_conn()
    try:
        while not stop_event.is_set():
            row = conn.execute(
                "SELECT * FROM cases WHERE status='triaged' ORDER BY created_at ASC LIMIT 1"
            ).fetchone()
            if row:
                case = row_to_dict(row)
                if stop_event.wait(random.uniform(*SHERLOCK_DELAY)):
                    return
                sherlock_process(conn, case)
                continue
            if stop_event.wait(SHERLOCK_POLL_SEC):
                break
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# EXECUTOR — Response
# ---------------------------------------------------------------------------

def executor_process(conn, case: dict) -> None:
    case_id = case["case_id"]
    vdec = json.loads(case["vanguard_decision"]) if case["vanguard_decision"] else {}
    alert = vdec.get("alert", {})
    score = case["vanguard_score"] or 0

    _set_agent_state(conn, "executor", status="processing", current_case_id=case_id,
                      last_action=f"Responding to {case_id}", last_action_time=now())

    alert_type = alert.get("alert_type", "")
    action_type, target_field = ACTION_BY_ALERT_TYPE.get(alert_type, ("isolate_host", "host"))
    target = alert.get(target_field) or alert.get("host") or "unknown"

    auto_approved = score > 85
    approval_mode = "auto (score > 85)" if auto_approved else "expedited (analyst SLA auto-approve)"

    exec_time_ms = random.randint(800, 6000)
    pre_state = "active"
    post_state = {
        "isolate_host": "isolated",
        "block_egress_ip": "blocked",
        "disable_account": "disabled",
        "revoke_cloud_session": "session_revoked",
        "force_password_reset": "reset_required",
    }.get(action_type, "remediated")

    conn.execute(
        """INSERT INTO actions (case_id, action_type, target, status, execution_time_ms,
                                 pre_state, post_state, rollback_timer, created_at)
           VALUES (?,?,?,?,?,?,?,?,?)""",
        (case_id, action_type, target, "executed", exec_time_ms, pre_state, post_state, 1800, now()),
    )

    action_chain = [
        {
            "step": 1, "name": "Containment Plan",
            "target": target, "action": action_type,
            "justification": f"Sherlock assessment + Vanguard score {score} -> {approval_mode}",
            "pre_state": pre_state, "post_state": post_state,
            "rollback_timer": 1800,
            "human_notified": not auto_approved,
            "requires_manager_approval": False,
        },
        {
            "step": 2, "name": "Execution",
            "result": f"{action_type} on {target} completed in {exec_time_ms}ms",
            "verification_query": f"index=sentinel_endpoint host=\"{target}\" earliest=-2m",
            "verification_result": f"{target} state={post_state}",
            "conclusion": f"Action {action_type} executed successfully",
        },
    ]
    executor_actions = {"action_chain": action_chain, "approval_mode": approval_mode, "executed_at": now()}

    conn.execute(
        "UPDATE cases SET status='responded', executor_actions_json=?, updated_at=? WHERE case_id=?",
        (json.dumps(executor_actions), now(), case_id),
    )
    queue_depth = conn.execute("SELECT COUNT(*) AS c FROM cases WHERE status='investigated'").fetchone()["c"]
    conn.commit()

    _publish_case(conn, case_id)
    BUS.publish("metrics", {"type": "action_executed", "data": {
        "case_id": case_id, "action_type": action_type, "target": target, "post_state": post_state,
    }})
    _set_agent_state(
        conn, "executor", status="idle", current_case_id=case_id,
        last_action=f"{action_type} -> {target} ({post_state})", last_action_time=now(),
        success_count=conn.execute("SELECT success_count FROM agent_state WHERE agent_name='executor'").fetchone()["success_count"] + 1,
        queue_depth=queue_depth,
    )


def executor_loop(stop_event: threading.Event) -> None:
    conn = get_conn()
    try:
        while not stop_event.is_set():
            row = conn.execute(
                "SELECT * FROM cases WHERE status='investigated' ORDER BY created_at ASC LIMIT 1"
            ).fetchone()
            if row:
                case = row_to_dict(row)
                if stop_event.wait(random.uniform(*EXECUTOR_DELAY)):
                    return
                executor_process(conn, case)
                continue
            if stop_event.wait(EXECUTOR_POLL_SEC):
                break
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# SAGE — Learning / closure
# ---------------------------------------------------------------------------

def sage_process(conn) -> None:
    _set_agent_state(conn, "sage", status="processing", last_action="Reviewing closed cases", last_action_time=now())

    # Close out cases that have been sitting in 'responded' for a bit so the
    # lifecycle completes without human input.
    candidates = conn.execute(
        "SELECT case_id, vanguard_score FROM cases WHERE status='responded' AND updated_at < ?",
        (now() - 20,),
    ).fetchall()

    for row in candidates:
        score = row["vanguard_score"] or 0
        # Higher-confidence cases are overwhelmingly true positives.
        is_false_positive = random.random() < (0.20 if score < 50 else 0.05)
        resolution = "false_positive" if is_false_positive else "true_positive"
        sage_analysis = {
            "resolution": resolution,
            "reviewed_at": now(),
            "notes": "Pattern matches prior confirmed incidents" if not is_false_positive
                     else "Benign administrative activity — tuning detection rule",
        }
        conn.execute(
            "UPDATE cases SET status='closed', sage_analysis_json=?, updated_at=? WHERE case_id=?",
            (json.dumps(sage_analysis), now(), row["case_id"]),
        )
        conn.commit()
        _publish_case(conn, row["case_id"])

    # Recompute rolling metrics over the last hour of closed cases.
    closed = conn.execute(
        "SELECT created_at, updated_at, sage_analysis_json FROM cases WHERE status='closed' AND updated_at > ?",
        (now() - 3600,),
    ).fetchall()

    if closed:
        mttr_minutes = sum((c["updated_at"] - c["created_at"]) for c in closed) / len(closed) / 60.0
        fps = sum(1 for c in closed if c["sage_analysis_json"] and json.loads(c["sage_analysis_json"]).get("resolution") == "false_positive")
        fp_rate = fps / len(closed)
        threats_contained = len(closed) - fps
    else:
        mttr_minutes, fp_rate, threats_contained = 0.0, 0.0, 0

    total_cases = conn.execute("SELECT COUNT(*) AS c FROM cases").fetchone()["c"]
    autonomous = conn.execute("SELECT COUNT(*) AS c FROM cases WHERE status='closed'").fetchone()["c"]
    autonomous_rate = (autonomous / total_cases * 100) if total_cases else 0.0

    for name, value in (
        ("mttr_minutes", mttr_minutes),
        ("fp_rate", fp_rate),
        ("threats_contained", threats_contained),
        ("autonomous_resolution_rate", autonomous_rate),
    ):
        conn.execute("INSERT INTO metrics (metric_name, metric_value, _time) VALUES (?,?,?)", (name, value, now()))
    conn.commit()

    BUS.publish("metrics", {"type": "sage_metrics", "data": {
        "mttr_minutes": round(mttr_minutes, 2),
        "fp_rate": round(fp_rate, 3),
        "threats_contained": threats_contained,
        "autonomous_resolution_rate": round(autonomous_rate, 1),
        "_time": now(),
    }})

    _set_agent_state(
        conn, "sage", status="idle", last_action=f"Closed {len(candidates)} case(s); MTTR {mttr_minutes:.1f}m",
        last_action_time=now(),
        success_count=conn.execute("SELECT success_count FROM agent_state WHERE agent_name='sage'").fetchone()["success_count"] + 1,
    )


def sage_loop(stop_event: threading.Event) -> None:
    conn = get_conn()
    try:
        while not stop_event.is_set():
            if stop_event.wait(random.uniform(*SAGE_DELAY)):
                break
            sage_process(conn)
            if stop_event.wait(SAGE_POLL_SEC):
                break
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Entry point used by start_live_stack.py
# ---------------------------------------------------------------------------

def start_all(stop_event: threading.Event) -> list[threading.Thread]:
    loops = [vanguard_loop, sherlock_loop, executor_loop, sage_loop]
    threads = []
    for loop in loops:
        t = threading.Thread(target=loop, args=(stop_event,), daemon=True, name=loop.__name__)
        t.start()
        threads.append(t)
    return threads


if __name__ == "__main__":
    import time as _time
    from sentinel_live_common import init_db
    init_db()
    stop = threading.Event()
    start_all(stop)
    try:
        while True:
            _time.sleep(1)
    except KeyboardInterrupt:
        stop.set()
