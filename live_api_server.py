"""
SENTINEL Live Data Stack — REST + WebSocket API server
live_api_server.py

Two servers, both standard-library only:

  - REST + static file server on port 9090 (http.server.ThreadingHTTPServer)
      GET /api/alerts            ?status=&limit=
      GET /api/alerts/{alert_id}
      GET /api/cases             ?status=&limit=
      GET /api/cases/{case_id}
      GET /api/agents
      GET /api/agents/{agent_name}
      GET /api/actions           ?case_id=
      GET /api/metrics           ?metric=&hours=
      GET /api/threat_intel      ?ioc=
      GET /api/search            ?q=<SPL-lite>
      GET /*                     -> static files (serves demo/, app/, etc.)

  - WebSocket server on port 9091 (raw socket + hashlib handshake, RFC 6455)
      WS /ws/alerts   -> live alert feed
      WS /ws/cases    -> live case state changes
      WS /ws/agents   -> live agent status updates
      WS /ws/metrics  -> live metric updates (+ periodic snapshot every 10s)

A SPL-lite query engine backs /api/search: the first pipeline segment picks
a table via `index=...` plus inline `field=value` filters, then each `|`
stage (`search`, `head`, `tail`, `sort`, `dedup`, `fields`, `stats count
[by field]`, simple `eval field=value`) is applied in Python over the
fetched rows and returned in a Splunk-export-like `{"result": {...}}`
shape.
"""

from __future__ import annotations

import base64
import fnmatch
import hashlib
import json
import mimetypes
import os
import queue
import shlex
import socket
import struct
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

from sentinel_live_common import BASE_DIR, BUS, case_to_dict, get_conn, now, row_to_dict

REST_PORT = 9090
WS_PORT = 9091

WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
WS_CHANNELS = ("alerts", "cases", "agents", "metrics")


# ===========================================================================
# SPL-lite query engine
# ===========================================================================

TABLE_MAP = {
    "alerts": ("alerts", None),
    "sentinel_alerts": ("alerts", None),
    "cases": ("cases", None),
    "actions": ("actions", None),
    "threat_intel": ("threat_intel", None),
    "metrics": ("metrics", None),
    "sentinel_metrics": ("metrics", None),
    "events": ("events", None),
    "sentinel_endpoint": ("events", "sentinel_endpoint"),
    "sentinel_network": ("events", "sentinel_network"),
}

TIME_TABLES = {"alerts": "_time", "events": "_time", "metrics": "_time", "threat_intel": "last_seen"}


def _resolve_table(index_name: str | None) -> tuple[str, str | None]:
    if not index_name:
        return "events", None
    return TABLE_MAP.get(index_name, ("events", index_name))


def _row_to_search_dict(table: str, row: "sqlite3.Row") -> dict:
    d = row_to_dict(row)
    if table == "events" and d.get("fields_json"):
        try:
            d.update(json.loads(d["fields_json"]))
        except (TypeError, ValueError):
            pass
    if table == "cases":
        return case_to_dict(row)
    return d


def _fetch_base_rows(conn, table: str, index_filter: str | None) -> list[dict]:
    order_col = TIME_TABLES.get(table)
    sql = f"SELECT * FROM {table}"
    params: list = []
    if index_filter and table == "events":
        sql += " WHERE index_name=?"
        params.append(index_filter)
    if order_col:
        sql += f" ORDER BY {order_col} DESC"
    else:
        sql += " ORDER BY id DESC"
    sql += " LIMIT 2000"
    rows = conn.execute(sql, params).fetchall()
    return [_row_to_search_dict(table, r) for r in rows]


def _value_matches(actual, expected: str) -> bool:
    actual_s = "" if actual is None else str(actual)
    if "*" in expected:
        return fnmatch.fnmatch(actual_s.lower(), expected.lower())
    return actual_s.lower() == expected.lower()


def _parse_kv_tokens(text: str) -> dict[str, str]:
    filters = {}
    try:
        tokens = shlex.split(text)
    except ValueError:
        tokens = text.split()
    for tok in tokens:
        if "=" in tok:
            k, v = tok.split("=", 1)
            filters[k.strip()] = v.strip().strip('"').strip("'")
    return filters


def _apply_filters(rows: list[dict], filters: dict[str, str]) -> list[dict]:
    if not filters:
        return rows
    out = []
    for r in rows:
        ok = True
        for k, v in filters.items():
            if k not in r or not _value_matches(r.get(k), v):
                ok = False
                break
        if ok:
            out.append(r)
    return out


def _apply_stage(rows: list[dict], stage: str) -> list[dict]:
    stage = stage.strip()
    if not stage:
        return rows
    head_word, _, rest = stage.partition(" ")
    head_word = head_word.lower()

    if head_word == "search":
        return _apply_filters(rows, _parse_kv_tokens(rest))

    if head_word in ("head", "tail"):
        try:
            n = int(rest.strip() or "10")
        except ValueError:
            n = 10
        return rows[:n] if head_word == "head" else rows[-n:]

    if head_word == "dedup":
        field = rest.strip()
        seen = set()
        out = []
        for r in rows:
            key = r.get(field)
            if key not in seen:
                seen.add(key)
                out.append(r)
        return out

    if head_word == "fields":
        cols = [c.strip() for c in rest.split(",") if c.strip()]
        return [{c: r.get(c) for c in cols} for r in rows]

    if head_word == "sort":
        rest = rest.strip()
        desc = rest.startswith("-")
        field = rest.lstrip("-+").strip()
        return sorted(rows, key=lambda r: (r.get(field) is None, r.get(field)), reverse=desc)

    if head_word == "eval":
        # supports: eval newfield="literal" | eval newfield=existingfield
        if "=" in rest:
            field, _, expr = rest.partition("=")
            field = field.strip()
            expr = expr.strip()
            if expr.startswith('"') and expr.endswith('"'):
                literal = expr.strip('"')
                for r in rows:
                    r[field] = literal
            else:
                for r in rows:
                    r[field] = r.get(expr)
        return rows

    if head_word == "stats":
        return _apply_stats(rows, rest)

    # Unknown stage — pass through unchanged rather than erroring out.
    return rows


def _apply_stats(rows: list[dict], rest: str) -> list[dict]:
    rest = rest.strip()
    by_field = None
    agg = rest
    if " by " in rest:
        agg, _, by_field = rest.partition(" by ")
        by_field = by_field.strip()
        agg = agg.strip()

    agg = agg.strip()
    if not by_field:
        return [{"count": len(rows)}] if agg.startswith("count") else rows

    groups: dict = {}
    for r in rows:
        key = r.get(by_field)
        groups.setdefault(key, 0)
        groups[key] += 1
    return [{by_field: k, "count": v} for k, v in groups.items()]


def run_spl(conn, spl: str) -> list[dict]:
    parts = [p.strip() for p in spl.split("|") if p.strip()]
    if not parts:
        return []

    head_filters = _parse_kv_tokens(parts[0])
    index_name = head_filters.pop("index", None)
    table, index_filter = _resolve_table(index_name)

    rows = _fetch_base_rows(conn, table, index_filter)
    rows = _apply_filters(rows, head_filters)

    for stage in parts[1:]:
        rows = _apply_stage(rows, stage)

    return rows


# ===========================================================================
# REST handlers
# ===========================================================================

def _json_bytes(obj) -> bytes:
    return json.dumps(obj, default=str).encode("utf-8")


def _query_param(qs: dict, name: str, default=None):
    vals = qs.get(name)
    return vals[0] if vals else default


def api_alerts(conn, qs: dict, alert_id: str | None) -> tuple[int, bytes]:
    if alert_id:
        row = conn.execute("SELECT * FROM alerts WHERE alert_id=?", (alert_id,)).fetchone()
        if not row:
            return 404, _json_bytes({"error": "alert not found"})
        return 200, _json_bytes(row_to_dict(row))

    status = _query_param(qs, "status")
    limit = int(_query_param(qs, "limit", "50"))
    sql = "SELECT * FROM alerts"
    params: list = []
    if status:
        sql += " WHERE status=?"
        params.append(status)
    sql += " ORDER BY _time DESC LIMIT ?"
    params.append(limit)
    rows = conn.execute(sql, params).fetchall()
    return 200, _json_bytes([row_to_dict(r) for r in rows])


def api_cases(conn, qs: dict, case_id: str | None) -> tuple[int, bytes]:
    if case_id:
        row = conn.execute("SELECT * FROM cases WHERE case_id=?", (case_id,)).fetchone()
        if not row:
            return 404, _json_bytes({"error": "case not found"})
        case = case_to_dict(row)
        case["actions"] = [row_to_dict(r) for r in conn.execute(
            "SELECT * FROM actions WHERE case_id=? ORDER BY created_at ASC", (case_id,)
        ).fetchall()]
        return 200, _json_bytes(case)

    status = _query_param(qs, "status")
    limit = int(_query_param(qs, "limit", "20"))
    sql = "SELECT * FROM cases"
    params: list = []
    if status == "active":
        sql += " WHERE status != 'closed'"
    elif status:
        sql += " WHERE status=?"
        params.append(status)
    sql += " ORDER BY updated_at DESC LIMIT ?"
    params.append(limit)
    rows = conn.execute(sql, params).fetchall()
    return 200, _json_bytes([case_to_dict(r) for r in rows])


def api_agents(conn, agent_name: str | None) -> tuple[int, bytes]:
    if agent_name:
        row = conn.execute("SELECT * FROM agent_state WHERE agent_name=?", (agent_name,)).fetchone()
        if not row:
            return 404, _json_bytes({"error": "agent not found"})
        return 200, _json_bytes(row_to_dict(row))
    rows = conn.execute("SELECT * FROM agent_state").fetchall()
    return 200, _json_bytes([row_to_dict(r) for r in rows])


def api_actions(conn, qs: dict) -> tuple[int, bytes]:
    case_id = _query_param(qs, "case_id")
    sql = "SELECT * FROM actions"
    params: list = []
    if case_id:
        sql += " WHERE case_id=?"
        params.append(case_id)
    sql += " ORDER BY created_at DESC LIMIT 200"
    rows = conn.execute(sql, params).fetchall()
    return 200, _json_bytes([row_to_dict(r) for r in rows])


def api_metrics(conn, qs: dict) -> tuple[int, bytes]:
    metric = _query_param(qs, "metric")
    hours = float(_query_param(qs, "hours", "24"))
    sql = "SELECT * FROM metrics WHERE _time > ?"
    params: list = [now() - hours * 3600]
    if metric:
        sql += " AND metric_name=?"
        params.append(metric)
    sql += " ORDER BY _time ASC LIMIT 2000"
    rows = conn.execute(sql, params).fetchall()
    return 200, _json_bytes([row_to_dict(r) for r in rows])


def api_threat_intel(conn, qs: dict) -> tuple[int, bytes]:
    ioc = _query_param(qs, "ioc")
    sql = "SELECT * FROM threat_intel"
    params: list = []
    if ioc:
        sql += " WHERE ioc=?"
        params.append(ioc)
    sql += " ORDER BY last_seen DESC LIMIT 200"
    rows = conn.execute(sql, params).fetchall()
    return 200, _json_bytes([row_to_dict(r) for r in rows])


def api_search(conn, qs: dict) -> tuple[int, bytes]:
    spl = _query_param(qs, "q", "")
    try:
        rows = run_spl(conn, spl)
    except Exception as exc:  # SPL-lite is best-effort; never 500 the dashboard
        return 200, _json_bytes({"error": str(exc), "results": []})
    return 200, _json_bytes({"results": [{"result": r} for r in rows]})


def api_snapshot(conn) -> dict:
    """Used both for /api/snapshot and as the initial WS payload."""
    alerts = [row_to_dict(r) for r in conn.execute(
        "SELECT * FROM alerts ORDER BY _time DESC LIMIT 50"
    ).fetchall()]
    cases = [case_to_dict(r) for r in conn.execute(
        "SELECT * FROM cases ORDER BY updated_at DESC LIMIT 50"
    ).fetchall()]
    agents = [row_to_dict(r) for r in conn.execute("SELECT * FROM agent_state").fetchall()]

    closed = conn.execute(
        "SELECT created_at, updated_at, sage_analysis_json FROM cases WHERE status='closed' AND updated_at > ?",
        (now() - 86400,),
    ).fetchall()
    if closed:
        mttr_minutes = sum((c["updated_at"] - c["created_at"]) for c in closed) / len(closed) / 60.0
        fps = sum(1 for c in closed if c["sage_analysis_json"]
                  and json.loads(c["sage_analysis_json"]).get("resolution") == "false_positive")
        fp_rate = fps / len(closed)
        threats_contained = len(closed) - fps
    else:
        mttr_minutes, fp_rate, threats_contained = 0.0, 0.0, 0

    total_cases = conn.execute("SELECT COUNT(*) AS c FROM cases").fetchone()["c"]
    autonomous = conn.execute("SELECT COUNT(*) AS c FROM cases WHERE status='closed'").fetchone()["c"]
    autonomous_rate = (autonomous / total_cases * 100) if total_cases else 0.0

    latest_rate_row = conn.execute(
        "SELECT metric_value FROM metrics WHERE metric_name='events_per_sec' ORDER BY _time DESC LIMIT 1"
    ).fetchone()

    return {
        "alerts": alerts,
        "cases": cases,
        "agents": agents,
        "metrics": {
            "mttr_minutes": round(mttr_minutes, 2),
            "fp_rate": round(fp_rate, 3),
            "threats_contained": threats_contained,
            "autonomous_resolution_rate": round(autonomous_rate, 1),
            "cases_today": total_cases,
            "events_per_sec": round(latest_rate_row["metric_value"], 2) if latest_rate_row else 0.0,
        },
        "server_time": now(),
    }


# ===========================================================================
# REST + static HTTP handler
# ===========================================================================

class SentinelHTTPHandler(BaseHTTPRequestHandler):
    server_version = "SentinelLiveAPI/1.0"

    def log_message(self, fmt, *args):  # quieter default logging
        pass

    def _send_json(self, status: int, payload: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)

    def _send_file(self, rel_path: str) -> None:
        rel_path = rel_path.lstrip("/")
        if not rel_path:
            rel_path = "demo/sentinel_war_room_live.html"
        full_path = os.path.normpath(os.path.join(BASE_DIR, rel_path))
        if not full_path.startswith(BASE_DIR) or not os.path.isfile(full_path):
            self._send_json(404, _json_bytes({"error": "not found"}))
            return
        ctype, _ = mimetypes.guess_type(full_path)
        ctype = ctype or "application/octet-stream"
        with open(full_path, "rb") as f:
            data = f.read()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query)
        conn = get_conn()
        try:
            if path == "/api/alerts" or path.startswith("/api/alerts/"):
                alert_id = path[len("/api/alerts/"):] or None if path.startswith("/api/alerts/") else None
                status, body = api_alerts(conn, qs, alert_id)
            elif path == "/api/cases" or path.startswith("/api/cases/"):
                case_id = path[len("/api/cases/"):] or None if path.startswith("/api/cases/") else None
                status, body = api_cases(conn, qs, case_id)
            elif path == "/api/agents" or path.startswith("/api/agents/"):
                agent_name = path[len("/api/agents/"):] or None if path.startswith("/api/agents/") else None
                status, body = api_agents(conn, agent_name)
            elif path == "/api/actions":
                status, body = api_actions(conn, qs)
            elif path == "/api/metrics":
                status, body = api_metrics(conn, qs)
            elif path == "/api/threat_intel":
                status, body = api_threat_intel(conn, qs)
            elif path == "/api/search":
                status, body = api_search(conn, qs)
            elif path == "/api/snapshot":
                status, body = 200, _json_bytes(api_snapshot(conn))
            elif path == "/api/splunk/status":
                status, body = 200, _json_bytes({
                    "status": "simulation",
                    "host": "prd-p-a5voa.splunkcloud.com",
                    "mode": "simulation",
                    "message": "Local simulation — not connected to Splunk Cloud",
                })
            elif path.startswith("/api/"):
                status, body = 404, _json_bytes({"error": "unknown endpoint"})
            else:
                self._send_file(path)
                return
            self._send_json(status, body)
        finally:
            conn.close()


# ===========================================================================
# WebSocket server (raw socket + RFC 6455 handshake)
# ===========================================================================

def _ws_accept_key(key: str) -> str:
    digest = hashlib.sha1((key + WS_GUID).encode("utf-8")).digest()
    return base64.b64encode(digest).decode("utf-8")


def _recv_until_headers(sock: socket.socket) -> bytes | None:
    data = b""
    sock.settimeout(10)
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            return None
        data += chunk
        if len(data) > 16384:
            return None
    return data


def _recv_exact(sock: socket.socket, n: int) -> bytes | None:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def _ws_recv_frame(sock: socket.socket) -> tuple[int | None, bytes]:
    header = _recv_exact(sock, 2)
    if header is None:
        return None, b""
    b0, b1 = header[0], header[1]
    opcode = b0 & 0x0F
    masked = bool(b1 & 0x80)
    length = b1 & 0x7F
    if length == 126:
        ext = _recv_exact(sock, 2)
        if ext is None:
            return None, b""
        length = struct.unpack("!H", ext)[0]
    elif length == 127:
        ext = _recv_exact(sock, 8)
        if ext is None:
            return None, b""
        length = struct.unpack("!Q", ext)[0]
    mask = _recv_exact(sock, 4) if masked else None
    payload = _recv_exact(sock, length) if length else b""
    if payload is None:
        return None, b""
    if mask:
        payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    return opcode, payload


def _ws_send_frame(sock: socket.socket, data: bytes, opcode: int = 0x1) -> None:
    length = len(data)
    if length <= 125:
        header = struct.pack("!BB", 0x80 | opcode, length)
    elif length <= 65535:
        header = struct.pack("!BBH", 0x80 | opcode, 126, length)
    else:
        header = struct.pack("!BBQ", 0x80 | opcode, 127, length)
    sock.sendall(header + data)


def _ws_handle_client(client: socket.socket, addr) -> None:
    try:
        request = _recv_until_headers(client)
        if request is None:
            client.close()
            return

        lines = request.split(b"\r\n")
        try:
            _, path, _ = lines[0].decode("utf-8", "ignore").split(" ")
        except ValueError:
            client.close()
            return

        headers = {}
        for line in lines[1:]:
            if b":" in line:
                k, v = line.split(b":", 1)
                headers[k.decode().strip().lower()] = v.decode().strip()

        key = headers.get("sec-websocket-key")
        if not key:
            client.close()
            return

        accept = _ws_accept_key(key)
        response = (
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Accept: {accept}\r\n\r\n"
        )
        client.sendall(response.encode("utf-8"))
        client.settimeout(None)
    except OSError:
        client.close()
        return

    channel = path.strip("/").split("/")[-1]
    if channel not in WS_CHANNELS:
        try:
            _ws_send_frame(client, b"unknown channel", opcode=0x8)
        except OSError:
            pass
        client.close()
        return

    q = BUS.subscribe(channel)
    stop = threading.Event()

    # Initial snapshot so the dashboard renders immediately on connect.
    conn = get_conn()
    try:
        snap = api_snapshot(conn)
    finally:
        conn.close()
    try:
        _ws_send_frame(client, _json_bytes({"type": "snapshot", "channel": channel, "data": snap[channel] if channel in snap else snap}))
    except OSError:
        stop.set()

    def reader() -> None:
        while not stop.is_set():
            try:
                opcode, payload = _ws_recv_frame(client)
            except OSError:
                stop.set()
                return
            if opcode is None or opcode == 0x8:  # connection closed / close frame
                stop.set()
                return
            if opcode == 0x9:  # ping -> pong
                try:
                    _ws_send_frame(client, payload, opcode=0xA)
                except OSError:
                    stop.set()
                    return
            # text (0x1) / pong (0xA) frames from client are ignored

    threading.Thread(target=reader, daemon=True, name=f"ws-reader-{channel}").start()

    last_metrics_push = now()
    try:
        while not stop.is_set():
            try:
                msg = q.get(timeout=1.0)
            except queue.Empty:
                if channel == "metrics" and now() - last_metrics_push >= 10:
                    conn = get_conn()
                    try:
                        snap = api_snapshot(conn)
                    finally:
                        conn.close()
                    msg = _json_bytes({"type": "metrics_snapshot", "data": snap["metrics"]}).decode("utf-8")
                    last_metrics_push = now()
                else:
                    continue
            try:
                _ws_send_frame(client, msg.encode("utf-8") if isinstance(msg, str) else msg)
            except OSError:
                break
    finally:
        BUS.unsubscribe(channel, q)
        try:
            client.close()
        except OSError:
            pass


def ws_server_loop(stop_event: threading.Event, port: int = WS_PORT) -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(32)
    srv.settimeout(1.0)
    try:
        while not stop_event.is_set():
            try:
                client, addr = srv.accept()
            except socket.timeout:
                continue
            threading.Thread(target=_ws_handle_client, args=(client, addr), daemon=True, name="ws-client").start()
    finally:
        srv.close()


# ===========================================================================
# Entry point used by start_live_stack.py
# ===========================================================================

def start_all(stop_event: threading.Event) -> tuple[ThreadingHTTPServer, list[threading.Thread]]:
    rest_server = ThreadingHTTPServer(("0.0.0.0", REST_PORT), SentinelHTTPHandler)
    rest_thread = threading.Thread(target=rest_server.serve_forever, daemon=True, name="rest_server")
    rest_thread.start()

    ws_thread = threading.Thread(target=ws_server_loop, args=(stop_event,), daemon=True, name="ws_server")
    ws_thread.start()

    def _shutdown_watcher():
        stop_event.wait()
        rest_server.shutdown()

    watcher = threading.Thread(target=_shutdown_watcher, daemon=True, name="rest_shutdown_watcher")
    watcher.start()

    return rest_server, [rest_thread, ws_thread, watcher]


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
