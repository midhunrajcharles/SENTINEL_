#!/usr/bin/env python
"""
SENTINEL: Autonomous Agentic SOC Commander
generate_architecture_diagram.py — Renders architecture_diagram.png

Uses matplotlib (more reliable than Graphviz on Windows, no external `dot`
binary required) to draw the high-level system architecture: Splunk
Enterprise at the center, the MCP Server layer, the four-agent pipeline
(Vanguard -> Sherlock -> Executor -> Sage) each labeled with its model,
external integrations, alert-flow arrows, the audit trail, and the human
override gate.

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
HUMAN_RED = "#FF4444"
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
    fig, ax = plt.subplots(figsize=(18, 10), dpi=150)
    fig.patch.set_facecolor(BG)
    ax.set_facecolor(BG)
    ax.set_xlim(0, 18)
    ax.set_ylim(0, 10)
    ax.axis("off")

    ax.text(9, 9.6, "SENTINEL: Autonomous Agentic SOC Commander",
            ha="center", va="center", fontsize=18, fontweight="bold", color=TEXT)
    ax.text(9, 9.2, "While your analysts sleep, SENTINEL hunts.",
            ha="center", va="center", fontsize=11, style="italic", color="#888888")

    # --- Splunk Enterprise (center) ---
    splunk = _box(ax, (6.5, 4.6), 5, 1.4,
                   "Splunk Enterprise\nES Notables • CIM Indexes • KV Store • HEC",
                   SPLUNK_GREEN, fontsize=11)

    # --- MCP Server (between Splunk and agent pipeline) ---
    mcp = _box(ax, (6.5, 6.4), 5, 1.0,
               "Splunk MCP Server\n14 Tools • JSON-RPC 2.0 (central nervous system)",
               MCP_ORANGE, fontsize=11)
    _arrow(ax, (9, 6.0), (9, 6.4), color=SPLUNK_GREEN, style="<|-|>", lw=2.2)

    # --- Agent pipeline (top row): Vanguard -> Sherlock -> Executor -> Sage ---
    agent_y = 8.0
    agent_w, agent_h = 3.6, 1.0
    gap = 0.4
    start_x = (18 - (4 * agent_w + 3 * gap)) / 2

    vanguard = _box(ax, (start_x, agent_y), agent_w, agent_h,
                     "Vanguard — Triage\nFoundation-Sec-8B", AGENT_BLUE)
    sherlock = _box(ax, (start_x + (agent_w + gap), agent_y), agent_w, agent_h,
                     "Sherlock — Investigation\nSAIA + MCP Server", AGENT_BLUE)
    executor = _box(ax, (start_x + 2 * (agent_w + gap), agent_y), agent_w, agent_h,
                     "Executor — Response\nMCP + SOAR", AGENT_BLUE)
    sage = _box(ax, (start_x + 3 * (agent_w + gap), agent_y), agent_w, agent_h,
                "Sage — Learning\nCisco Deep Time Series", AGENT_BLUE)

    # Alert flow arrows: Vanguard -> Sherlock -> Executor -> Sage
    for a, b in ((vanguard, sherlock), (sherlock, executor), (executor, sage)):
        ax1, ay1, aw1, ah1 = a
        ax2, ay2, aw2, ah2 = b
        _arrow(ax, (ax1 + aw1, ay1 + ah1 / 2), (ax2, ay2 + ah2 / 2),
               color="#FFAA00", style="-|>", lw=2.2)

    # Agents <-> MCP
    for box in (vanguard, sherlock, executor, sage):
        x, y, w, h = box
        _arrow(ax, (x + w / 2, y), (x + w / 2, 7.4), color=MCP_ORANGE, style="<|-|>", lw=1.8)

    # --- External integrations (left/right of Splunk) ---
    vt = _box(ax, (0.5, 4.9), 2.8, 1.0, "VirusTotal / AbuseIPDB\n(Threat Intel)", EXTERNAL_GREY, fontsize=9)
    snow = _box(ax, (14.7, 4.9), 2.8, 1.0, "ServiceNow / Jira\n(Tickets, Notify)", EXTERNAL_GREY, fontsize=9)

    _arrow(ax, (3.3, 5.4), (6.5, 5.4), color=EXTERNAL_GREY, style="<|-|>", lw=1.6)
    _arrow(ax, (11.5, 5.4), (14.7, 5.4), color=EXTERNAL_GREY, style="<|-|>", lw=1.6)

    # Sherlock -> Threat Intel (enrichment)
    _arrow(ax, (sherlock[0] + 0.3, agent_y), (1.9, 5.9), color=EXTERNAL_GREY, style="-|>", lw=1.4, ls="dashed",
           connectionstyle="arc3,rad=0.3")
    # Executor -> ServiceNow (response actions)
    _arrow(ax, (executor[0] + executor[2] - 0.3, agent_y), (16.1, 5.9), color=EXTERNAL_GREY, style="-|>", lw=1.4, ls="dashed",
           connectionstyle="arc3,rad=-0.3")

    # --- Audit trail (bottom) ---
    audit = _box(ax, (6.5, 1.0), 5, 1.2,
                  "Audit Trail\nsentinel_audit index (HEC, append-only)",
                  AUDIT_RED, fontsize=11)

    _arrow(ax, (9, 4.6), (9, 2.2), color=AUDIT_RED, style="-|>", lw=2.0, ls="dashed")
    ax.text(9.2, 3.4, "every agent\ndecision logged", color=AUDIT_RED, fontsize=8, style="italic")

    # --- Human override / approval gate ---
    human = _box(ax, (0.5, 1.0), 3.0, 1.2,
                  "Human Override\n/ Approval Gate\n(\"Big Red Button\")", HUMAN_RED, fontsize=10)
    _arrow(ax, (3.5, 1.6), (executor[0] + executor[2] / 2, agent_y),
           color=HUMAN_RED, style="<|-|>", lw=1.8, ls="dashed", connectionstyle="arc3,rad=0.2")
    ax.text(4.5, 3.2, "halt_case() /\napprove_action()", color=HUMAN_RED, fontsize=8, style="italic")

    # Data sources -> Splunk
    sources = _box(ax, (14.7, 1.0), 3.0, 1.2,
                    "Data Sources\nEDR • Network • Identity • Cloud", EXTERNAL_GREY, fontsize=9)
    _arrow(ax, (16.2, 2.2), (11.5, 4.6), color=SPLUNK_GREEN, style="-|>", lw=1.6)

    # --- Legend ---
    legend_elems = [
        Line2D([0], [0], color="#FFAA00", lw=2.5, label="Alert flow (Vanguard → Sherlock → Executor → Sage)"),
        Line2D([0], [0], color=MCP_ORANGE, lw=2.5, label="MCP tool calls (agents ↔ Splunk)"),
        Line2D([0], [0], color=SPLUNK_GREEN, lw=2.5, label="Splunk data flow"),
        Line2D([0], [0], color=AUDIT_RED, lw=2.5, ls="dashed", label="Audit trail (append-only)"),
        Line2D([0], [0], color=HUMAN_RED, lw=2.5, ls="dashed", label="Human override / approval"),
        Line2D([0], [0], color=EXTERNAL_GREY, lw=2.5, ls="dashed", label="External integrations"),
    ]
    ax.legend(handles=legend_elems, loc="lower center", bbox_to_anchor=(0.5, -0.02), ncol=3,
              facecolor="#161B22", edgecolor="#333344", labelcolor=TEXT, fontsize=9)

    plt.tight_layout()
    fig.savefig(_OUTPUT, facecolor=BG, bbox_inches="tight")
    print(f"Wrote {_OUTPUT}")


if __name__ == "__main__":
    main()
