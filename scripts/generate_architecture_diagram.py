#!/usr/bin/env python
"""
SENTINEL: Autonomous Agentic SOC Commander
generate_architecture_diagram.py — Renders architecture_diagram.png

Draws the high-level system architecture using matplotlib (no external
Graphviz binary required): Splunk Enterprise at the center, the MCP Server
as the control plane connecting the four agents (with their models),
external integrations, data flow arrows, and the audit trail path.

Usage::

    python scripts/generate_architecture_diagram.py
"""

from __future__ import annotations

from pathlib import Path

import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch
from matplotlib.lines import Line2D

_REPO_ROOT = Path(__file__).resolve().parent.parent
_OUTPUT = _REPO_ROOT / "architecture_diagram.png"

# Color palette
SPLUNK_GREEN = "#65A637"
MCP_ORANGE = "#FF8C00"
AGENT_BLUE = "#4D96FF"
EXTERNAL_GREY = "#7F8C8D"
AUDIT_RED = "#E74C3C"
BG = "#0D1117"
TEXT = "#E6EDF3"


def _box(ax, xy, w, h, text, facecolor, fontsize=10, fontweight="bold", textcolor="white"):
    x, y = xy
    box = FancyBboxPatch(
        (x, y), w, h,
        boxstyle="round,pad=0.02,rounding_size=0.08",
        linewidth=1.5, edgecolor="#333344", facecolor=facecolor,
    )
    ax.add_patch(box)
    ax.text(x + w / 2, y + h / 2, text, ha="center", va="center",
            fontsize=fontsize, fontweight=fontweight, color=textcolor, wrap=True)
    return (x, y, w, h)


def _arrow(ax, p1, p2, color="#999999", style="-|>", lw=1.6, ls="solid", connectionstyle="arc3,rad=0.0"):
    arrow = FancyArrowPatch(
        p1, p2, arrowstyle=style, color=color, linewidth=lw,
        linestyle=ls, connectionstyle=connectionstyle, mutation_scale=14, zorder=1,
    )
    ax.add_patch(arrow)


def main() -> None:
    fig, ax = plt.subplots(figsize=(16, 10), dpi=150)
    fig.patch.set_facecolor(BG)
    ax.set_facecolor(BG)
    ax.set_xlim(0, 16)
    ax.set_ylim(0, 10)
    ax.axis("off")

    ax.text(8, 9.6, "SENTINEL: Autonomous Agentic SOC Commander",
            ha="center", va="center", fontsize=18, fontweight="bold", color=TEXT)
    ax.text(8, 9.2, "While your analysts sleep, SENTINEL hunts.",
            ha="center", va="center", fontsize=11, style="italic", color="#888888")

    # --- Splunk Enterprise (center) ---
    splunk = _box(ax, (5.5, 4.0), 5, 1.8,
                   "Splunk Enterprise / ES\nCIM Indexes • Notables • KV Store • HEC",
                   SPLUNK_GREEN, fontsize=11)

    # --- MCP Server (above Splunk, central nervous system) ---
    mcp = _box(ax, (6, 6.2), 4, 1.0,
               "Splunk MCP Server\n14 Tools • JSON-RPC 2.0",
               MCP_ORANGE, fontsize=11)

    # --- Agents (top row, around MCP) ---
    agent_y = 8.0
    agent_w, agent_h = 3.0, 1.0
    vanguard = _box(ax, (0.5, agent_y), agent_w, agent_h,
                     "Vanguard — Triage\nFoundation-Sec-1.1-8B", AGENT_BLUE)
    sherlock = _box(ax, (4.0, agent_y), agent_w, agent_h,
                     "Sherlock — Investigation\nSAIA (NL→SPL)", AGENT_BLUE)
    executor = _box(ax, (9.0, agent_y), agent_w, agent_h,
                     "Executor — Response\nMCP Response Tools", AGENT_BLUE)
    sage = _box(ax, (12.5, agent_y), agent_w, agent_h,
                "Sage — Learning\nCisco Deep Time Series", AGENT_BLUE)

    # Agents <-> MCP
    for box in (vanguard, sherlock, executor, sage):
        x, y, w, h = box
        _arrow(ax, (x + w / 2, y), (x + w / 2, 7.2), color=MCP_ORANGE, style="<|-|>", lw=1.8)

    # MCP <-> Splunk
    _arrow(ax, (8, 6.2), (8, 5.8), color=SPLUNK_GREEN, style="<|-|>", lw=2.2)

    # --- External integrations (left/right of Splunk) ---
    vt = _box(ax, (0.5, 4.3), 2.6, 1.0, "VirusTotal / MISP\n(Threat Intel)", EXTERNAL_GREY, fontsize=9)
    snow = _box(ax, (13.0, 4.3), 2.5, 1.0, "ServiceNow / Jira\n(Tickets, Notify)", EXTERNAL_GREY, fontsize=9)

    _arrow(ax, (3.1, 4.8), (5.5, 4.8), color=EXTERNAL_GREY, style="<|-|>", lw=1.6)
    _arrow(ax, (10.5, 4.8), (13.0, 4.8), color=EXTERNAL_GREY, style="<|-|>", lw=1.6)

    # Sherlock -> Threat Intel (enrichment)
    _arrow(ax, (1.8, 8.0), (1.8, 5.3), color=EXTERNAL_GREY, style="-|>", lw=1.4, ls="dashed",
           connectionstyle="arc3,rad=-0.3")
    # Executor -> ServiceNow (response actions)
    _arrow(ax, (12.0, 8.0), (14.2, 5.3), color=EXTERNAL_GREY, style="-|>", lw=1.4, ls="dashed",
           connectionstyle="arc3,rad=0.3")

    # --- Audit trail (bottom) ---
    audit = _box(ax, (5.5, 1.0), 5, 1.2,
                  "Audit Trail\nsentinel_audit index (HEC, append-only)",
                  AUDIT_RED, fontsize=11)

    _arrow(ax, (8, 4.0), (8, 2.2), color=AUDIT_RED, style="-|>", lw=2.0, ls="dashed")
    ax.text(8.2, 3.1, "every agent\ndecision logged", color=AUDIT_RED, fontsize=8, style="italic")

    # Data sources -> Splunk
    sources = _box(ax, (0.5, 2.6), 2.6, 1.0,
                    "Data Sources\nEDR • Network • Identity • Cloud", EXTERNAL_GREY, fontsize=9)
    _arrow(ax, (3.1, 3.1), (5.5, 4.3), color=SPLUNK_GREEN, style="-|>", lw=1.6)

    # --- Legend ---
    legend_elems = [
        Line2D([0], [0], color=MCP_ORANGE, lw=2.5, label="MCP tool calls (agents ↔ Splunk)"),
        Line2D([0], [0], color=SPLUNK_GREEN, lw=2.5, label="Splunk data flow"),
        Line2D([0], [0], color=AUDIT_RED, lw=2.5, ls="dashed", label="Audit trail (append-only)"),
        Line2D([0], [0], color=EXTERNAL_GREY, lw=2.5, ls="dashed", label="External integrations"),
    ]
    legend = ax.legend(handles=legend_elems, loc="lower right", bbox_to_anchor=(0.99, 0.01),
                        facecolor="#161B22", edgecolor="#333344", labelcolor=TEXT, fontsize=9)

    plt.tight_layout()
    fig.savefig(_OUTPUT, facecolor=BG, bbox_inches="tight")
    print(f"Wrote {_OUTPUT}")


if __name__ == "__main__":
    main()
