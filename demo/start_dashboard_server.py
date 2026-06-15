#!/usr/bin/env python3
"""
SENTINEL: Autonomous Agentic SOC Commander
start_dashboard_server.py — launcher for the War Room dashboard API.

Usage::

    export SENTINEL_SPLUNK_PASSWORD='<password>'   # if using basic auth
    python demo/start_dashboard_server.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from splunk_api_server import app, _cfg  # noqa: E402

if __name__ == '__main__':
    host = _cfg.get("splunk", "host", default="localhost")
    print("Starting SENTINEL Dashboard API...")
    print(f"Splunk Cloud: {host}")
    print("API: http://localhost:8080")
    print("Dashboard: http://localhost:8080/sentinel_war_room_live.html")
    app.run(host='0.0.0.0', port=8080, debug=False, threaded=True)
