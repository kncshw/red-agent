"""Human escalation via SMTP email.

Borrowed from oh-soc-agent/_smtp_helpers.py and adapted for red team findings.
Fail-open: if SMTP is unconfigured or unreachable, the finding is still logged
— notification is best-effort.

Required env vars:
    EMAIL_SERVER        — SMTP server hostname
    EMAIL_USERNAME      — SMTP auth username
    EMAIL_PASSWORD      — SMTP auth password

Optional env vars:
    EMAIL_RECIPIENTS    — comma-separated recipients (default: Teams channel)
    EMAIL_SMTP_PORT     — SMTP port (default: 587)
    EMAIL_USE_TLS       — use STARTTLS (default: "true")
"""

from __future__ import annotations

import html as _html
import logging
import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any

log = logging.getLogger(__name__)


def _smtp_config() -> dict[str, Any] | None:
    server   = os.environ.get("EMAIL_SERVER",   "").strip().strip('"')
    username = os.environ.get("EMAIL_USERNAME", "").strip().strip('"')
    password = os.environ.get("EMAIL_PASSWORD", "").strip().strip('"')
    if not server or not username or not password:
        return None

    from_address = f"{username}@fortinet.com" if "@" not in username else username
    recipients_raw = os.environ.get(
        "EMAIL_RECIPIENTS",
        "1e290415.fortinet.onmicrosoft.com@amer.teams.ms",
    ).strip().strip('"')

    return {
        "server":       server,
        "port":         int(os.environ.get("EMAIL_SMTP_PORT", "587")),
        "username":     username,
        "password":     password,
        "from_address": from_address,
        "recipients":   [r.strip() for r in recipients_raw.split(",") if r.strip()],
        "use_tls":      os.environ.get("EMAIL_USE_TLS", "true").lower() in ("true", "1"),
    }


def send_red_team_escalation(
    ip: str,
    port: int,
    application: str,
    escalation_note: str,
    evidence: str,
    auth_status: str = "none",
    target_url: str = "",
) -> bool:
    """Send a red team escalation email. Returns True on success."""
    cfg = _smtp_config()
    if not cfg:
        log.warning("SMTP not configured — escalation logged only (set EMAIL_SERVER/USERNAME/PASSWORD)")
        return False

    no_auth = auth_status.lower() in ("none", "no auth", "")
    if no_auth:
        subject      = f"[RED TEAM ESCALATION] Unauthenticated {application} exposed — {ip}:{port}"
        headline     = "identified an <strong>unauthenticated service exposed on the public internet</strong>"
        auth_badge   = '<span style="background:#d32f2f; color:white; padding:2px 8px; border-radius:3px; font-weight:bold;">NO AUTHENTICATION</span>'
        auth_plain   = "NO AUTHENTICATION"
    else:
        subject      = f"[RED TEAM ESCALATION] High-risk service identified — {application} on {ip}:{port}"
        headline     = f"identified a <strong>high-risk service ({_html.escape(auth_status)} auth)</strong> that requires immediate review"
        auth_badge   = f'<span style="background:#e65100; color:white; padding:2px 8px; border-radius:3px; font-weight:bold;">{_html.escape(auth_status.upper())}</span>'
        auth_plain   = auth_status.upper()
    note_html     = _html.escape(escalation_note).replace("\n", "<br>\n")
    evidence_html = _html.escape(evidence)

    body_html = f"""<html>
<body style="font-family: Segoe UI, Arial, sans-serif; color: #333; line-height: 1.6; max-width: 800px;">

<p>Hello Human,</p>

<p>The red team agent has {headline} that requires your immediate attention.</p>

<h2 style="color: #b71c1c; border-bottom: 2px solid #b71c1c; padding-bottom: 4px;">Finding</h2>
<table style="border-collapse: collapse; width: 100%;">
  <tr><td style="padding:4px 12px; font-weight:bold; width:140px;">Target</td>
      <td style="padding:4px 12px;">
        <a href="{_html.escape(target_url)}" style="font-family:monospace;">
          {_html.escape(target_url)}
        </a>
      </td></tr>
  <tr><td style="padding:4px 12px; font-weight:bold;">Application</td>
      <td style="padding:4px 12px;">{_html.escape(application)}</td></tr>
  <tr><td style="padding:4px 12px; font-weight:bold;">Auth Status</td>
      <td style="padding:4px 12px;">{auth_badge}</td></tr>
  <tr><td style="padding:4px 12px; font-weight:bold;">Evidence</td>
      <td style="padding:4px 12px; font-style:italic;">{evidence_html}</td></tr>
</table>

<h2 style="color: #b71c1c; border-bottom: 2px solid #b71c1c; padding-bottom: 4px;">AI Escalation Note</h2>
<div style="background:#fff3e0; padding:12px; border-left:4px solid #b71c1c; font-size:14px; white-space:pre-wrap;">
{note_html}
</div>

<h2 style="color: #1a237e; border-bottom: 2px solid #1a237e; padding-bottom: 4px;">Suggested Actions</h2>
<ol>
  <li>Verify the finding: <code>curl -sk {_html.escape(target_url)}</code></li>
  <li>Identify the asset owner via NetBox or CMDB</li>
  <li>Apply network ACL to block public access immediately</li>
  <li>Re-scan after remediation to confirm closure</li>
</ol>

<hr style="border:none; border-top:1px solid #ddd; margin-top:20px;">
<p style="color:#999; font-size:12px;">Generated by BIS Red Team Agent (Gemma4-26B-abliterated) | oh-red-agent</p>

</body>
</html>"""

    plain = (
        f"{subject}\n\n"
        f"Target      : {target_url}\n"
        f"Application : {application}\n"
        f"Auth Status : {auth_plain}\n"
        f"Evidence    : {evidence}\n\n"
        f"--- AI Escalation Note ---\n"
        f"{escalation_note}\n\n"
        f"--- Suggested Actions ---\n"
        f"1. Verify: curl -sk {target_url}\n"
        f"2. Identify asset owner via NetBox/CMDB\n"
        f"3. Apply network ACL to block public access immediately\n"
        f"4. Re-scan after remediation to confirm closure\n\n"
        f"Generated by BIS Red Team Agent | oh-red-agent"
    )

    msg = MIMEMultipart("alternative")
    msg["From"]    = cfg["from_address"]
    msg["To"]      = ", ".join(cfg["recipients"])
    msg["Subject"] = subject
    msg.attach(MIMEText(plain, "plain"))
    msg.attach(MIMEText(body_html, "html"))

    try:
        if cfg["use_tls"]:
            smtp = smtplib.SMTP(cfg["server"], cfg["port"], timeout=30)
            smtp.starttls()
        else:
            smtp = smtplib.SMTP_SSL(cfg["server"], cfg["port"], timeout=30)
        smtp.login(cfg["username"], cfg["password"])
        smtp.sendmail(cfg["from_address"], cfg["recipients"], msg.as_string())
        smtp.quit()
        log.info("Escalation email sent for %s:%d (%s) to %s", ip, port, application, cfg["recipients"])
        return True
    except Exception as exc:
        log.warning("Failed to send escalation email for %s:%d: %s", ip, port, exc)
        return False
