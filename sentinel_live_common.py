"""
SENTINEL Live Data Stack — shared helpers
sentinel_live_common.py

Small foundation module shared by data_generators.py, agent_orchestrator_live.py,
and live_api_server.py — all of which run as threads inside the same process
(started by start_live_stack.py). Provides:

  - A single SQLite connection helper (WAL mode, check_same_thread=False)
  - A thread-safe in-process pub/sub event bus used to push live updates
    from the generators/orchestrator straight out over WebSocket
  - Small ID/time helpers shared across modules
"""

from __future__ import annotations

import json
import os
import queue
import sqlite3
import threading
import time
import uuid

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "sentinel_live.db")
SCHEMA_PATH = os.path.join(BASE_DIR, "database_schema.sql")

AGENT_NAMES = ["vanguard", "sherlock", "executor", "sage"]


def now() -> float:
    return time.time()


def new_id(prefix: str) -> str:
    return f"{prefix}-{int(now())}-{uuid.uuid4().hex[:6]}"


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

def get_conn() -> sqlite3.Connection:
    """Open a new connection. SQLite connections are not shared across
    threads — every thread/loop should call this once and keep its own."""
    conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def init_db(reset: bool = False) -> None:
    """Create tables (idempotent) and seed agent_state / threat_intel rows."""
    if reset and os.path.exists(DB_PATH):
        os.remove(DB_PATH)
        for ext in ("-wal", "-shm"):
            p = DB_PATH + ext
            if os.path.exists(p):
                os.remove(p)

    conn = get_conn()
    try:
        with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
            conn.executescript(f.read())

        # Seed agent_state rows (one per SENTINEL agent)
        for agent in AGENT_NAMES:
            conn.execute(
                """INSERT OR IGNORE INTO agent_state
                   (agent_name, status, last_action_time)
                   VALUES (?, 'idle', ?)""",
                (agent, now()),
            )

        # Seed a handful of threat intel records so Vanguard/Sherlock have
        # something to enrich against from the very first poll.
        seed_ti = [
            ("185.220.101.42", "ip", 0.97, "LockBit", "LockBit C2", "demo_seed"),
            ("45.137.21.9", "ip", 0.88, "FIN7", "Carbanak Loader", "demo_seed"),
            ("203.0.113.55", "ip", 0.74, "Unattributed", "Generic Scanner", "demo_seed"),
            ("update-cdn-secure.net", "domain", 0.91, "SupplyChainActor", "Backdoor Dropper", "demo_seed"),
        ]
        for ioc, ioc_type, score, actor, fam, src in seed_ti:
            cur = conn.execute("SELECT 1 FROM threat_intel WHERE ioc=?", (ioc,))
            if cur.fetchone() is None:
                conn.execute(
                    """INSERT INTO threat_intel
                       (ioc, ioc_type, reputation_score, threat_actor, malware_family,
                        first_seen, last_seen, source)
                       VALUES (?,?,?,?,?,?,?,?)""",
                    (ioc, ioc_type, score, actor, fam, now() - 86400 * 30, now(), src),
                )
        conn.commit()
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Event bus — in-process pub/sub feeding the WebSocket broadcaster
# ---------------------------------------------------------------------------

class EventBus:
    """Fan-out pub/sub. Each subscriber gets its own Queue; publish() pushes
    a copy of the message onto every queue registered for that channel."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._subscribers: dict[str, list[queue.Queue]] = {}

    def subscribe(self, channel: str) -> "queue.Queue":
        q: "queue.Queue" = queue.Queue(maxsize=200)
        with self._lock:
            self._subscribers.setdefault(channel, []).append(q)
        return q

    def unsubscribe(self, channel: str, q: "queue.Queue") -> None:
        with self._lock:
            subs = self._subscribers.get(channel, [])
            if q in subs:
                subs.remove(q)

    def publish(self, channel: str, message: dict) -> None:
        payload = json.dumps(message, default=str)
        with self._lock:
            subs = list(self._subscribers.get(channel, []))
        for q in subs:
            try:
                q.put_nowait(payload)
            except queue.Full:
                # Drop oldest to make room — live feed, not a durable log
                try:
                    q.get_nowait()
                    q.put_nowait(payload)
                except queue.Empty:
                    pass


BUS = EventBus()


# ---------------------------------------------------------------------------
# Misc shared constants
# ---------------------------------------------------------------------------

def row_to_dict(row: sqlite3.Row) -> dict:
    return {k: row[k] for k in row.keys()}


def case_to_dict(row: sqlite3.Row) -> dict:
    """Expand a `cases` row into a JSON-friendly dict, parsing the embedded
    *_json columns into nested objects (or None if empty)."""
    d = row_to_dict(row)
    for col in ("sherlock_report_json", "executor_actions_json", "sage_analysis_json"):
        key = col[: -len("_json")]
        raw = d.get(col)
        if raw:
            try:
                d[key] = json.loads(raw)
            except (TypeError, ValueError):
                d[key] = None
        else:
            d[key] = None
    return d


SEVERITY_ORDER = ["low", "medium", "high", "critical"]

MITRE_MAP = {
    "POWERSHELL_EXECUTION":   ("Execution", "T1059.001"),
    "SMB_LATERAL_MOVEMENT":   ("Lateral Movement", "T1021.002"),
    "DATA_EXFILTRATION":      ("Exfiltration", "T1041"),
    "INSIDER_THREAT":         ("Collection", "T1213"),
    "CLOUD_MISCONFIG":        ("Initial Access", "T1078.004"),
    "C2_BEACON":              ("Command and Control", "T1071.001"),
    "RANSOMWARE_ENCRYPTION":  ("Impact", "T1486"),
    "PRIVILEGE_ESCALATION":   ("Privilege Escalation", "T1068"),
    "CREDENTIAL_DUMPING":     ("Credential Access", "T1003.001"),
}
