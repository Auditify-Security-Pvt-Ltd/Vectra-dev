"""SMTP email service for team invitations.

Supports both SSL (port 465) and STARTTLS (port 587).
Returns a result dict so callers can surface error details to users.
"""
from __future__ import annotations

import os
import smtplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import TypedDict

from utils.logger import get_logger

logger = get_logger(__name__)

_SMTP_HOST    = os.getenv("SMTP_HOST", "")
_SMTP_PORT    = int(os.getenv("SMTP_PORT", "587"))
_SMTP_USER    = os.getenv("SMTP_USER", "")
_SMTP_PASS    = os.getenv("SMTP_PASS", "")
_SMTP_FROM    = os.getenv("SMTP_FROM", "noreply@vectra.io")
_FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:3000")


class EmailResult(TypedDict):
    sent:  bool
    error: str | None


def send_invitation_email(
    *,
    to_email:     str,
    inviter_name: str,
    org_name:     str,
    role:         str,
    token:        str,
) -> EmailResult:
    """Send a team invitation email.

    Returns a dict with ``sent`` (bool) and ``error`` (str | None).
    The accept URL points to the public invitation landing page.
    """
    accept_url   = f"{_FRONTEND_URL}/invite/{token}"
    role_display = role.title()

    if not _SMTP_HOST or not _SMTP_USER:
        logger.info(
            "SMTP not configured — invite link for %s (%s): %s",
            to_email, role_display, accept_url,
        )
        return {"sent": False, "error": "SMTP not configured"}

    html = f"""<!DOCTYPE html>
<html>
<body style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0a0a0a;color:#e5e5e5;margin:0;padding:40px">
  <div style="max-width:520px;margin:0 auto;background:#111;border:1px solid rgba(255,255,255,0.1);border-radius:12px;padding:40px">
    <div style="width:40px;height:40px;background:linear-gradient(135deg,#8b5cf6,#6d28d9);border-radius:10px;margin-bottom:20px">
    </div>
    <h1 style="margin:0 0 8px;font-size:22px;font-weight:700;color:#fff">You&#39;re invited to Vectra</h1>
    <p style="color:#a3a3a3;font-size:15px;line-height:1.6;margin:0 0 8px">
      <strong style="color:#e5e5e5">{inviter_name}</strong> has invited you to join
      <strong style="color:#e5e5e5">{org_name}</strong>.
    </p>
    <p style="color:#a3a3a3;font-size:14px;margin:0 0 28px">
      Your role: <strong style="color:#8b5cf6">{role_display}</strong>
    </p>
    <a href="{accept_url}" style="display:inline-block;background:#8b5cf6;color:#fff;text-decoration:none;padding:13px 30px;border-radius:8px;font-weight:600;font-size:15px;margin-bottom:28px">
      Accept Invitation &#8594;
    </a>
    <p style="color:#666;font-size:13px;margin:0 0 20px">This invitation expires in 72 hours. If you didn&#39;t expect this, you can ignore it.</p>
    <hr style="border:none;border-top:1px solid rgba(255,255,255,0.08);margin:20px 0">
    <p style="color:#555;font-size:12px;margin:0;word-break:break-all">
      Vectra Security Platform &middot; {accept_url}
    </p>
  </div>
</body>
</html>"""

    plain = (
        f"You're invited to join {org_name} on Vectra as {role_display}.\n\n"
        f"Invited by: {inviter_name}\n"
        f"Accept here: {accept_url}\n\n"
        "This invitation expires in 72 hours."
    )

    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"You're invited to join {org_name} on Vectra"
    msg["From"]    = f"Vectra Security <{_SMTP_FROM}>"
    msg["To"]      = to_email
    msg.attach(MIMEText(plain, "plain"))
    msg.attach(MIMEText(html, "html"))

    try:
        if _SMTP_PORT == 465:
            # Direct SSL — used by most cPanel/shared hosting (port 465)
            ctx = ssl.create_default_context()
            with smtplib.SMTP_SSL(_SMTP_HOST, _SMTP_PORT, context=ctx) as srv:
                srv.login(_SMTP_USER, _SMTP_PASS)
                srv.sendmail(_SMTP_FROM, to_email, msg.as_string())
        else:
            # STARTTLS — used by Gmail/Outlook on port 587
            with smtplib.SMTP(_SMTP_HOST, _SMTP_PORT) as srv:
                srv.ehlo()
                srv.starttls()
                srv.ehlo()
                srv.login(_SMTP_USER, _SMTP_PASS)
                srv.sendmail(_SMTP_FROM, to_email, msg.as_string())

        logger.info("Invitation email sent to %s via %s:%s", to_email, _SMTP_HOST, _SMTP_PORT)
        return {"sent": True, "error": None}

    except smtplib.SMTPAuthenticationError as exc:
        msg_text = "SMTP authentication failed — check SMTP_USER / SMTP_PASS"
        logger.error("%s: %s", msg_text, exc)
        return {"sent": False, "error": msg_text}
    except smtplib.SMTPConnectError as exc:
        msg_text = f"Cannot connect to SMTP server {_SMTP_HOST}:{_SMTP_PORT}"
        logger.error("%s: %s", msg_text, exc)
        return {"sent": False, "error": msg_text}
    except ssl.SSLError as exc:
        msg_text = f"SSL error connecting to {_SMTP_HOST}:{_SMTP_PORT} — check SMTP_PORT matches server SSL mode"
        logger.error("%s: %s", msg_text, exc)
        return {"sent": False, "error": msg_text}
    except Exception as exc:
        msg_text = f"Failed to send email: {exc}"
        logger.error("Invitation email to %s failed: %s", to_email, exc)
        return {"sent": False, "error": msg_text}
