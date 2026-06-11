"""
SENTINEL: Autonomous Agentic SOC Commander
webhooks/email_notifier.py — SMTP approval-request notifications

Renders ApprovalGate requests as an HTML email (mirroring the Slack message
content) and sends it to the on-call distribution list via SMTP, plus a
best-effort parser for YES/NO reply-to responses.

DEMO_MODE (default unless SMTP host is configured): no SMTP connection is
made — the rendered HTML/plaintext is printed to the console/log instead.

Configuration (env var overrides [integrations]/[notifications] in sentinel.conf):
    SENTINEL_SMTP_HOST, SENTINEL_SMTP_PORT, SENTINEL_SMTP_USER, SENTINEL_SMTP_PASSWORD
    SENTINEL_SMTP_FROM, SENTINEL_ONCALL_EMAIL (distribution list, comma-separated)

Dependencies: smtplib/email (standard library)
"""

from __future__ import annotations

import logging
import os
import re
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any, Dict, List, Optional

log = logging.getLogger("sentinel.webhooks.email")

_ENV_SMTP_HOST   = "SENTINEL_SMTP_HOST"
_ENV_SMTP_PORT   = "SENTINEL_SMTP_PORT"
_ENV_SMTP_USER   = "SENTINEL_SMTP_USER"
_ENV_SMTP_PASS   = "SENTINEL_SMTP_PASSWORD"
_ENV_SMTP_FROM   = "SENTINEL_SMTP_FROM"
_ENV_ONCALL      = "SENTINEL_ONCALL_EMAIL"

_DEFAULT_FROM   = "sentinel-noreply@sentinel.local"
_DEFAULT_ONCALL = "soc-oncall@company.com"

# Matches a leading "YES"/"NO"/"APPROVE"/"DENY" (case-insensitive) — the way an
# analyst would reply to an approval-request email from their phone.
_REPLY_PATTERN = re.compile(r"^\s*(YES|NO|APPROVE[D]?|DENY|DENIED)\b", re.IGNORECASE)
_REPLY_APPROVE = {"YES", "APPROVE", "APPROVED"}
_REPLY_DENY    = {"NO", "DENY", "DENIED"}


_HTML_TEMPLATE = """\
<html>
  <body style="font-family: -apple-system, Segoe UI, Roboto, sans-serif; color:#1b1f23;">
    <h2 style="color:#c0392b;">&#128680; SENTINEL Approval Required &mdash; Case {case_id}</h2>
    <table cellpadding="6" style="border-collapse:collapse;">
      <tr><td><b>Action</b></td><td>{action} &rarr; <code>{target}</code></td></tr>
      <tr><td><b>Justification</b></td><td>{justification}</td></tr>
      <tr><td><b>Confidence</b></td><td>{confidence}%</td></tr>
      <tr><td><b>Risk Level</b></td><td>{risk_level}</td></tr>
      <tr><td><b>Request ID</b></td><td>{request_id}</td></tr>
      <tr><td><b>Requested By</b></td><td>{requested_by}</td></tr>
      <tr><td><b>Expires At</b></td><td>{expires_at}</td></tr>
    </table>
    <p>
      <a href="{approval_url}&response=YES"
         style="background:#27ae60;color:#fff;padding:8px 16px;text-decoration:none;border-radius:4px;">
         &#9989; Approve
      </a>
      &nbsp;
      <a href="{approval_url}&response=NO"
         style="background:#c0392b;color:#fff;padding:8px 16px;text-decoration:none;border-radius:4px;">
         &#10060; Deny
      </a>
    </p>
    <p style="color:#586069;font-size:0.85em;">
      Reply <b>YES</b> to approve or <b>NO</b> to deny directly from this email.<br/>
      This request expires at {expires_at} (timeout defaults to DENY).
    </p>
  </body>
</html>
"""

_TEXT_TEMPLATE = """\
SENTINEL Approval Required -- Case {case_id}

Action:        {action} -> {target}
Justification: {justification}
Confidence:    {confidence}%
Risk Level:    {risk_level}
Request ID:    {request_id}
Requested By:  {requested_by}
Expires At:    {expires_at}

Reply YES to approve or NO to deny.
Approval link: {approval_url}
This request defaults to DENY if it expires unanswered.
"""


class EmailNotifier:
    """
    Formats and sends SENTINEL approval requests as HTML email to the
    on-call distribution list, with a DEMO_MODE that prints to console/log
    instead of opening an SMTP connection.
    """

    def __init__(
        self,
        smtp_host: Optional[str] = None,
        smtp_port: Optional[int] = None,
        smtp_user: Optional[str] = None,
        smtp_password: Optional[str] = None,
        sender: Optional[str] = None,
        recipients: Optional[List[str]] = None,
        demo_mode: Optional[bool] = None,
        timeout_s: float = 10.0,
    ) -> None:
        self._host = smtp_host if smtp_host is not None else os.environ.get(_ENV_SMTP_HOST, "")
        self._port = int(smtp_port if smtp_port is not None else os.environ.get(_ENV_SMTP_PORT, "587") or 587)
        self._user = smtp_user if smtp_user is not None else os.environ.get(_ENV_SMTP_USER, "")
        self._password = smtp_password if smtp_password is not None else os.environ.get(_ENV_SMTP_PASS, "")
        self._sender = sender if sender is not None else os.environ.get(_ENV_SMTP_FROM, _DEFAULT_FROM)

        if recipients is not None:
            self._recipients = list(recipients)
        else:
            raw = os.environ.get(_ENV_ONCALL, _DEFAULT_ONCALL)
            self._recipients = [addr.strip() for addr in raw.split(",") if addr.strip()]

        self._timeout_s = timeout_s
        self._demo_mode = (not self._host) if demo_mode is None else demo_mode

    @property
    def demo_mode(self) -> bool:
        return self._demo_mode

    # ------------------------------------------------------------------
    # Templating
    # ------------------------------------------------------------------

    @staticmethod
    def _format_fields(payload: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "case_id":       payload.get("case_id", ""),
            "action":        payload.get("action", ""),
            "target":        payload.get("target", ""),
            "justification": payload.get("justification", ""),
            "confidence":    payload.get("confidence_score", 0),
            "risk_level":    payload.get("risk_level", ""),
            "request_id":    payload.get("request_id", ""),
            "requested_by":  payload.get("requested_by", ""),
            "expires_at":    payload.get("expires_at", ""),
            "approval_url":  payload.get("approval_url", ""),
        }

    def render_html(self, payload: Dict[str, Any]) -> str:
        return _HTML_TEMPLATE.format(**self._format_fields(payload))

    def render_text(self, payload: Dict[str, Any]) -> str:
        return _TEXT_TEMPLATE.format(**self._format_fields(payload))

    def build_message(self, payload: Dict[str, Any]) -> MIMEMultipart:
        case_id = payload.get("case_id", "")
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"[SENTINEL] Approval Required — Case {case_id}: {payload.get('action', '')}"
        msg["From"] = self._sender
        msg["To"] = ", ".join(self._recipients)
        msg.attach(MIMEText(self.render_text(payload), "plain"))
        msg.attach(MIMEText(self.render_html(payload), "html"))
        return msg

    # ------------------------------------------------------------------
    # Sending
    # ------------------------------------------------------------------

    def send_approval_request(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Send the rendered approval-request email to the on-call distribution
        list (or print it in DEMO_MODE).

        Returns ``{"ok": bool, "demo_mode": bool, "recipients": [...], "error": str|None}``
        """
        msg = self.build_message(payload)

        if self._demo_mode:
            log.info(
                "[DEMO_MODE] Email approval request for %s (request_id=%s) to %s:\n%s",
                payload.get("case_id", ""), payload.get("request_id", ""),
                self._recipients, self.render_text(payload),
            )
            print(
                "\n========== [SENTINEL DEMO] Email Approval Request ==========\n"
                f"To      : {', '.join(self._recipients)}\n"
                f"From    : {self._sender}\n"
                f"Subject : {msg['Subject']}\n"
                "------------------------------------------------------------\n"
                f"{self.render_text(payload)}"
                "============================================================\n"
            )
            return {"ok": True, "demo_mode": True, "recipients": self._recipients, "error": None}

        try:
            with smtplib.SMTP(self._host, self._port, timeout=self._timeout_s) as server:
                server.starttls()
                if self._user:
                    server.login(self._user, self._password)
                server.sendmail(self._sender, self._recipients, msg.as_string())
            return {"ok": True, "demo_mode": False, "recipients": self._recipients, "error": None}
        except (smtplib.SMTPException, OSError) as exc:
            log.warning("Email approval request delivery failed: %s", exc)
            return {"ok": False, "demo_mode": False, "recipients": self._recipients, "error": str(exc)}

    # ------------------------------------------------------------------
    # Inbound: parse reply-to responses
    # ------------------------------------------------------------------

    @staticmethod
    def parse_reply(body: str) -> Optional[str]:
        """
        Extract a YES/NO decision from the leading line of an email reply.
        Returns "YES", "NO", or None if no recognizable response is found.
        """
        if not body:
            return None
        for line in body.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            match = _REPLY_PATTERN.match(stripped)
            if match:
                token = match.group(1).upper()
                if token in _REPLY_APPROVE:
                    return "YES"
                if token in _REPLY_DENY:
                    return "NO"
            # Stop at the first non-blank, non-matching line — replies are
            # expected to lead with the decision (quoted thread follows).
            break
        return None
