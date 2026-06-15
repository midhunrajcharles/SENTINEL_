"""
SENTINEL Live Data Stack — master launcher
start_live_stack.py

Initializes the SQLite database, starts the data generators, the agent
orchestrator (Vanguard/Sherlock/Executor/Sage), and the REST+WebSocket API
server, then idles until interrupted (Ctrl+C) and shuts everything down
cleanly.

Usage:
    python start_live_stack.py            # use existing sentinel_live.db
    python start_live_stack.py --reset     # wipe and re-create the database
"""

from __future__ import annotations

import sys
import threading
import time

import agent_orchestrator_live
import data_generators
import live_api_server
from sentinel_live_common import DB_PATH, init_db


def main() -> None:
    reset = "--reset" in sys.argv[1:]

    print("=" * 60)
    print(" SENTINEL Live Data Stack")
    print("=" * 60)

    init_db(reset=reset)
    print(f"[Database] SQLite: {DB_PATH}")

    stop_event = threading.Event()

    gen_threads = data_generators.start_all(stop_event)
    print(f"[Data Generators] {len(gen_threads)} active · starting up...")

    agent_threads = agent_orchestrator_live.start_all(stop_event)
    print(f"[Agent Orchestrator] {len(agent_threads)} agents polling")

    rest_server, api_threads = live_api_server.start_all(stop_event)
    print(f"[API Server] REST: http://localhost:{live_api_server.REST_PORT} "
          f"· WS: ws://localhost:{live_api_server.WS_PORT}")

    print("-" * 60)
    print(f" Dashboard: http://localhost:{live_api_server.REST_PORT}/demo/sentinel_war_room_live.html")
    print(" Press Ctrl+C to stop.")
    print("-" * 60)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down SENTINEL Live Data Stack...")
        stop_event.set()
        time.sleep(1.5)
        print("Stopped.")


if __name__ == "__main__":
    main()
