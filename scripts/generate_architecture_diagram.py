#!/usr/bin/env python
"""
SENTINEL: Autonomous Agentic SOC Commander
generate_architecture_diagram.py — Renders architecture_diagram.png

Uses the Python `graphviz` library (requires the Graphviz `dot` binary on
PATH; install with `pip install graphviz` + the Graphviz system package)
to render the high-level system architecture: Splunk Enterprise (with ES,
ITSI, indexes) at the center, the MCP Server layer connecting the four
agents (with their models), external integrations, the OODA data-flow
arrows (alert -> triage -> investigate -> respond -> learn), the audit
trail path, and the human override / approval gate.

Usage::

    python scripts/generate_architecture_diagram.py
"""

from __future__ import annotations

from pathlib import Path

import graphviz

_REPO_ROOT = Path(__file__).resolve().parent.parent
_OUTPUT = _REPO_ROOT / "architecture_diagram"  # graphviz appends .png


def main() -> None:
    g = graphviz.Digraph("SENTINEL_Architecture", format="png")
    g.attr(
        rankdir="LR", bgcolor="#0D1117", fontname="Helvetica", fontcolor="#E6EDF3",
        label="SENTINEL: Autonomous Agentic SOC Commander\nWhile your analysts sleep, SENTINEL hunts.",
        labelloc="t", fontsize="20", splines="spline",
    )
    g.attr("node", fontname="Helvetica", style="filled", fontcolor="white", color="#333344")
    g.attr("edge", fontname="Helvetica", fontsize="9", fontcolor="#AAAAAA", color="#777777")

    # --- Splunk Enterprise core (center) ---
    with g.subgraph(name="cluster_splunk") as c:
        c.attr(label="Splunk Enterprise", style="filled", color="#2ECC71",
               fillcolor="#0B1F10", fontcolor="#65A637", fontsize="13")
        c.node("ES", "Enterprise Security\n(Notables, RBA)", shape="box", fillcolor="#1A4A22")
        c.node("ITSI", "ITSI\n(Service Health)", shape="box", fillcolor="#1A4A22")
        c.node("IDX", "CIM Indexes\n(endpoint, network,\nauth, audit)", shape="cylinder", fillcolor="#122A18")
        c.edge("IDX", "ES")
        c.edge("IDX", "ITSI")

    # --- MCP Server layer ---
    g.node("MCP", "Splunk MCP Server\n14 Tools • JSON-RPC 2.0",
           shape="box", style="filled,rounded", fillcolor="#FF8C00", fontcolor="black")
    g.edge("MCP", "ES", dir="both", color="#65A637", label="search_spl /\nquery_es_notable")
    g.edge("MCP", "ITSI", dir="both", color="#65A637")

    # --- Agents with their models ---
    with g.subgraph(name="cluster_agents") as c:
        c.attr(label="SENTINEL Agent Swarm", style="filled", color="#4D96FF",
               fillcolor="#0D1828", fontcolor="#4D96FF", fontsize="13")
        c.node("VANG", "Vanguard — Triage\nFoundation-Sec-8B",
               shape="box", style="filled,rounded", fillcolor="#FFD93D", fontcolor="black")
        c.node("SHER", "Sherlock — Investigation\nSAIA (NL→SPL)",
               shape="box", style="filled,rounded", fillcolor="#6BCB77", fontcolor="black")
        c.node("EXEC", "Executor — Response\nMCP + SOAR",
               shape="box", style="filled,rounded", fillcolor="#4D96FF")
        c.node("SAGE", "Sage — Learning\nCisco Deep Time Series",
               shape="box", style="filled,rounded", fillcolor="#9B59B6")

    # OODA data flow: alert -> triage -> investigate -> respond -> learn
    g.edge("ES", "VANG", label="New Notable\n(Observe)", color="#FFAA00", penwidth="2")
    g.edge("VANG", "SHER", label="Risk ≥ 85\n(Orient)", color="#FFAA00", penwidth="2")
    g.edge("SHER", "EXEC", label="Investigation\nReport (Decide)", color="#FFAA00", penwidth="2")
    g.edge("EXEC", "SAGE", label="Outcome\n(Act → Learn)", color="#FFAA00", penwidth="2")
    g.edge("SAGE", "ES", label="Tuned detection\nrules", color="#FFAA00", style="dashed", constraint="false")

    # Agents <-> MCP (bidirectional tool calls)
    for agent in ("VANG", "SHER", "EXEC", "SAGE"):
        g.edge(agent, "MCP", dir="both", color="#FF8C00", style="dotted", constraint="false")

    # --- External integrations ---
    with g.subgraph(name="cluster_external") as c:
        c.attr(label="External Integrations", style="filled", color="#7F8C8D",
               fillcolor="#1C1C1C", fontcolor="#BDC3C7", fontsize="13")
        c.node("VT", "VirusTotal", shape="box", fillcolor="#34495E")
        c.node("ABUSE", "AbuseIPDB", shape="box", fillcolor="#34495E")
        c.node("SNOW", "ServiceNow", shape="box", fillcolor="#34495E")

    g.edge("SHER", "VT", label="enrich_threat_intel", color="#7F8C8D", style="dashed")
    g.edge("SHER", "ABUSE", label="enrich_threat_intel", color="#7F8C8D", style="dashed")
    g.edge("EXEC", "SNOW", label="create_ticket /\nnotify", color="#7F8C8D", style="dashed")

    # --- Audit trail ---
    g.node("AUDIT", "sentinel_audit index\n(HEC, append-only)",
           shape="cylinder", style="filled", fillcolor="#E74C3C")
    for agent in ("VANG", "SHER", "EXEC", "SAGE"):
        g.edge(agent, "AUDIT", color="#E74C3C", style="dashed", constraint="false")

    # --- Human override / approval gate ---
    g.node("HUMAN", "Human Override\n/ Approval Gate\n(Big Red Button)",
           shape="octagon", style="filled", fillcolor="#FF4444")
    g.edge("HUMAN", "EXEC", label="halt_case() /\napprove_action()", color="#FF4444", dir="both")

    out_path = g.render(filename=str(_OUTPUT), cleanup=True)
    print(f"Wrote {out_path}")


if __name__ == "__main__":
    main()
