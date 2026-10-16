"""SMTP email helper for morning digests and library alerts."""

from __future__ import annotations

import os
import smtplib
from email.message import EmailMessage

from .config import require_env


def send_mail(subject: str, body: str, to: str | None = None) -> None:
    env = require_env("SMTP_HOST", "SMTP_PORT", "SMTP_USER", "SMTP_PASSWORD", "MAIL_FROM", "MAIL_TO")
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = env["MAIL_FROM"]
    msg["To"] = to or env["MAIL_TO"]
    msg.set_content(body)

    port = int(env["SMTP_PORT"])
    with smtplib.SMTP(env["SMTP_HOST"], port, timeout=60) as smtp:
        smtp.starttls()
        smtp.login(env["SMTP_USER"], env["SMTP_PASSWORD"])
        smtp.send_message(msg)


def connection_status() -> str:
    try:
        require_env("SMTP_HOST", "SMTP_PORT", "SMTP_USER", "SMTP_PASSWORD", "MAIL_FROM", "MAIL_TO")
        return f"configured ({os.getenv('MAIL_TO')})"
    except SystemExit as exc:
        return f"error: {exc}"
