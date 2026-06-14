#!/usr/bin/env python
"""
SENTINEL: Autonomous Agentic SOC Commander
inject_via_file.py — File-based fallback for synthetic attack data injection

Use this when HTTP Event Collector (HEC) is unavailable (e.g. returning
503 "Server is busy"). It reuses the same scenario generators as
inject_synthetic_attack_data.py but writes events to JSON-lines files under
demo_data/, grouped by sourcetype, so they can be ingested via a Splunk
monitor input or `splunk add oneshot` instead of HEC.

Usage::

    python scripts/inject_via_file.py --scenario ransomware --index main
    python scripts/inject_via_file.py --scenario all --index main

For each generated file this prints the equivalent `splunk add oneshot`
command (one-time ingest) and an [monitor://] inputs.conf stanza
(persistent ingest) you can add to app/sentinel/local/inputs.conf.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List

_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT / "scripts"))

from inject_synthetic_attack_data import _SCENARIOS  # noqa: E402

_DEFAULT_INDEX = "main"
_OUTPUT_DIR = _REPO_ROOT / "demo_data"


def _safe_name(sourcetype: str) -> str:
    return sourcetype.replace(":", "_") + ".json"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--scenario", choices=sorted(_SCENARIOS) + ["all"], default="all",
        help="Which synthetic attack scenario to generate (default: all)",
    )
    parser.add_argument("--index", default=_DEFAULT_INDEX, help="Target Splunk index")
    parser.add_argument("--output-dir", default=str(_OUTPUT_DIR),
                         help="Directory to write JSON-lines event files (default: demo_data/)")
    args = parser.parse_args()

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    scenario_names = sorted(_SCENARIOS) if args.scenario == "all" else [args.scenario]

    # Group generated events by sourcetype across all requested scenarios.
    by_sourcetype: Dict[str, List[Dict[str, Any]]] = {}
    total = 0
    for name in scenario_names:
        for env in _SCENARIOS[name](args.index):
            fields = dict(env["event"])
            fields["host"] = env["host"]
            fields["_time"] = env["time"]
            by_sourcetype.setdefault(env["sourcetype"], []).append(fields)
            total += 1

    print(f"[SENTINEL DEMO] Writing {total} events across {len(by_sourcetype)} sourcetypes to {out_dir}")
    print()

    oneshot_cmds = []
    monitor_stanzas = []
    for sourcetype, rows in by_sourcetype.items():
        out_file = out_dir / _safe_name(sourcetype)
        with open(out_file, "w", encoding="utf-8") as fh:
            for row in rows:
                fh.write(json.dumps(row) + "\n")
        print(f"  {out_file}  ({len(rows)} events, sourcetype={sourcetype})")

        oneshot_cmds.append(
            f'splunk add oneshot "{out_file}" -index {args.index} -sourcetype {sourcetype}'
        )
        monitor_stanzas.append(
            f"[monitor://{out_file}]\n"
            f"sourcetype = {sourcetype}\n"
            f"index = {args.index}\n"
            f"disabled = 0\n"
        )

    print()
    print("[SENTINEL DEMO] One-time ingest via Splunk CLI (run from Splunk bin dir, as the Splunk user):")
    for cmd in oneshot_cmds:
        print(f"  {cmd}")

    print()
    print("[SENTINEL DEMO] OR add to app/sentinel/local/inputs.conf for persistent monitoring:")
    print()
    print("\n".join(monitor_stanzas))


if __name__ == "__main__":
    main()
