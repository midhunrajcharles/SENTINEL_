"""
SENTINEL: Autonomous Agentic SOC Commander
webhooks/slack_notifier.py — Slack incoming-webhook + interactive-callback bridge

Makes the human-in-the-loop approval gate *visible*: every approval request
that ApprovalGate raises is rendered as a rich Slack Block Kit message with
Approve / Deny / View-Case buttons, posted to an incoming webhook URL, and
interactive callbacks (button clicks) are parsed back into
``ApprovalGate.process_approval_response()`` calls.

DEMO_MODE (default unless a real webhook URL is configured): no network call
is made — the formatted message is printed to the console/log exactly as it
would be posted, so the gate is demonstrable without Slack credentials.

Configuration (env var overrides [integrations] in sentinel.conf):
    SENTINEL_SLACK_WEBHOOK_URL   — incoming webhook URL ("" => DEMO_MODE)
    SENTINEL_SPLUNK_DASHBOARD_URL — base URL for "View Case" links

Dependencies: requests, standard library
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, Optional

import requests

log = logging.getLogger("sentinel.webhooks.slack")

_ENV_WEBHOOK_URL   = "SENTINEL_SLACK_WEBHOOK_URL"
_ENV_DASHBOARD_URL = "SENTINEL_SPLUNK_DASHBOARD_URL"
_DEFAULT_DASHBOARD_URL = "https://sentinel.local/app/sentinel/case_detail"


class SlackNotifier:
    """
    Formats and sends SENTINEL approval requests as interactive Slack messages.

    Test mode: when no webhook URL is configured (or ``demo_mode=True`` is
    forced), :meth:`send_approval_request` prints the rendered Block Kit
    payload to the console/log instead of calling the Slack API — so judges
    can see exactly what *would* be posted without needing a live workspace.
    """

    def __init__(
        self,
        webhook_url: Optional[str] = None,
        dashboard_url: Optional[str] = None,
        demo_mode: Optional[bool] = None,
        timeout_s: float = 5.0,
    ) -> None:
        self._webhook_url  = webhook_url   if webhook_url   is not None else os.environ.get(_ENV_WEBHOOK_URL, "")
        self._dashboard_url = (dashboard_url if dashboard_url is not None
                               else os.environ.get(_ENV_DASHBOARD_URL, _DEFAULT_DASHBOARD_URL))
        self._timeout_s = timeout_s
        # Demo mode kicks in automatically when no webhook URL is configured,
        # unless the caller explicitly forces it on/off.
        self._demo_mode = (not self._webhook_url) if demo_mode is None else demo_mode

    @property
    def demo_mode(self) -> bool:
        return self._demo_mode

    # ------------------------------------------------------------------
    # Outbound: format + send the approval request
    # ------------------------------------------------------------------

    def build_message(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Render an ApprovalGate request payload as a Slack Block Kit message
        with Approve / Deny / View Case interactive buttons.
        """
        case_id        = payload.get("case_id", "")
        request_id     = payload.get("request_id", "")
        action         = payload.get("action", "")
        target         = payload.get("target", "")
        justification  = payload.get("justification", "")
        confidence     = payload.get("confidence_score", 0)
        risk_level     = payload.get("risk_level", "")
        requested_by   = payload.get("requested_by", "")
        approval_url   = payload.get("approval_url", "")
        case_url       = f"{self._dashboard_url}/{case_id}" if case_id else self._dashboard_url

        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"\U0001F6A8 SENTINEL Approval Required — Case {case_id}",
                    "emoji": True,
                },
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Action:*\n{action} → `{target}`"},
                    {"type": "mrkdwn", "text": f"*Confidence:*\n{confidence}%"},
                    {"type": "mrkdwn", "text": f"*Risk Level:*\n{risk_level}"},
                    {"type": "mrkdwn", "text": f"*Request ID:*\n{request_id}"},
                ],
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Justification:*\n{justification}"},
            },
            {
                "type": "actions",
                "block_id": f"sentinel_approval_{request_id}",
                "elements": [
                    {
                        "type": "button",
                        "style": "primary",
                        "text": {"type": "plain_text", "text": "✅ Approve", "emoji": True},
                        "value": json.dumps({"request_id": request_id, "response": "YES"}),
                        "action_id": "sentinel_approve",
                    },
                    {
                        "type": "button",
                        "style": "danger",
                        "text": {"type": "plain_text", "text": "❌ Deny", "emoji": True},
                        "value": json.dumps({"request_id": request_id, "response": "NO"}),
                        "action_id": "sentinel_deny",
                    },
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "\U0001F50D View Case", "emoji": True},
                        "url": case_url,
                        "action_id": "sentinel_view_case",
                    },
                ],
            },
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": (
                            f"Expires in 5 minutes | Requested by {requested_by} | "
                            f"<{approval_url}|Approval link> | "
                            f"Reply *YES* to approve, *NO* to deny"
                        ),
                    }
                ],
            },
        ]

        return {
            "text": f"SENTINEL Approval Required — Case {case_id}: {action} on {target}",
            "blocks": blocks,
        }

    def send_approval_request(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Post the formatted approval request to the configured Slack webhook.

        In DEMO_MODE (no webhook URL configured) this prints the rendered
        message to the console/log and returns a simulated "ok" response —
        no network call is made.

        Returns ``{"ok": bool, "demo_mode": bool, "message": {...}, "error": str|None}``
        """
        message = self.build_message(payload)

        if self._demo_mode:
            log.info(
                "[DEMO_MODE] Slack approval request for %s (request_id=%s) — "
                "would POST to incoming webhook:\n%s",
                payload.get("case_id", ""), payload.get("request_id", ""),
                json.dumps(message, indent=2),
            )
            print(
                "\n========== [SENTINEL DEMO] Slack Approval Request ==========\n"
                f"Channel : (DEMO_MODE — no webhook URL configured)\n"
                f"{json.dumps(message, indent=2)}\n"
                "============================================================\n"
            )
            return {"ok": True, "demo_mode": True, "message": message, "error": None}

        try:
            resp = requests.post(self._webhook_url, json=message, timeout=self._timeout_s)
            resp.raise_for_status()
            return {"ok": True, "demo_mode": False, "message": message, "error": None}
        except requests.RequestException as exc:
            log.warning("Slack webhook delivery failed: %s", exc)
            return {"ok": False, "demo_mode": False, "message": message, "error": str(exc)}

    # ------------------------------------------------------------------
    # Inbound: parse interactive callback payloads
    # ------------------------------------------------------------------

    @staticmethod
    def parse_interactive_callback(raw_payload: Any) -> Dict[str, Any]:
        """
        Parse a Slack "interactive message" callback (button click) into
        ``{"request_id": ..., "response": "YES"|"NO", "responder_id": ...}``.

        Slack posts these as ``application/x-www-form-urlencoded`` with a
        single ``payload`` field containing JSON; ``raw_payload`` may be that
        JSON string, an already-decoded dict, or the outer form dict.
        """
        data = raw_payload
        if isinstance(data, (str, bytes)):
            try:
                data = json.loads(data)
            except (TypeError, ValueError):
                return {}

        if not isinstance(data, dict):
            return {}

        # Outer form-encoded wrapper: {"payload": "<json string>"}
        if "payload" in data and "actions" not in data:
            inner = data.get("payload")
            if isinstance(inner, (str, bytes)):
                try:
                    data = json.loads(inner)
                except (TypeError, ValueError):
                    return {}
            elif isinstance(inner, dict):
                data = inner

        actions = data.get("actions") or []
        if not actions:
            return {}

        action = actions[0]
        try:
            value = json.loads(action.get("value", "{}"))
        except (TypeError, ValueError):
            value = {}

        request_id = value.get("request_id", "")
        response   = value.get("response", "")

        # action_id fallback when the button value didn't carry a response
        if not response:
            action_id = str(action.get("action_id", ""))
            if action_id == "sentinel_approve":
                response = "YES"
            elif action_id == "sentinel_deny":
                response = "NO"

        user = data.get("user") or {}
        responder_id = user.get("id") or user.get("username") or data.get("user_id", "")

        return {
            "request_id":   request_id,
            "response":     response,
            "responder_id": str(responder_id),
        }
