from __future__ import annotations

import smtplib
from email.message import EmailMessage

import resend

from app.core.config import settings

RESET_EMAIL_SUBJECT = "Reset your CyberShield password"


def build_reset_email_body(reset_link: str) -> dict[str, str]:
    """Pure builder (no network call) so the copy is unit-testable on its own."""

    text = (
        "CyberShield\n\n"
        "We received a request to reset your password.\n\n"
        f"Reset your password: {reset_link}\n\n"
        f"This link expires in {settings.reset_token_expiry_minutes} minutes.\n\n"
        "If you didn't request this, you can ignore this email — your password won't change."
    )
    html = f"""
    <div style="font-family:Arial,Helvetica,sans-serif;max-width:480px;margin:0 auto;padding:24px;color:#0f172a;">
      <p style="font-weight:700;font-size:18px;margin:0 0 20px;">CyberShield</p>
      <p style="margin:0 0 16px;">We received a request to reset your password.</p>
      <p style="margin:0 0 20px;">
        <a href="{reset_link}" style="display:inline-block;background:#0f172a;color:#ffffff;text-decoration:none;padding:12px 20px;border-radius:6px;font-weight:600;">Reset your password</a>
      </p>
      <p style="color:#475569;margin:0 0 16px;">This link expires in {settings.reset_token_expiry_minutes} minutes.</p>
      <p style="color:#475569;font-size:13px;margin:0;">
        If you didn't request this, you can ignore this email — your password won't change.
      </p>
    </div>
    """
    return {"text": text, "html": html}


def _send_via_resend(*, to_email: str, body: dict[str, str]) -> None:
    if not settings.resend_api_key:
        raise RuntimeError("RESEND_API_KEY is not configured.")

    resend.api_key = settings.resend_api_key
    resend.Emails.send(
        {
            "from": settings.resend_from_email,
            "to": [to_email],
            "subject": RESET_EMAIL_SUBJECT,
            "text": body["text"],
            "html": body["html"],
        }
    )


def _send_via_smtp(*, to_email: str, body: dict[str, str]) -> None:
    """Send through a normal SMTP account (Gmail App Password supported)."""

    if not settings.smtp_username or not settings.smtp_password:
        raise RuntimeError("SMTP_USERNAME/SMTP_PASSWORD are not configured.")

    message = EmailMessage()
    message["Subject"] = RESET_EMAIL_SUBJECT
    message["From"] = settings.smtp_from_email or settings.smtp_username
    message["To"] = to_email
    message.set_content(body["text"])
    message.add_alternative(body["html"], subtype="html")

    with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=15) as smtp:
        if settings.smtp_starttls:
            smtp.starttls()
        smtp.login(settings.smtp_username, settings.smtp_password)
        smtp.send_message(message)


def send_reset_email(*, to_email: str, reset_link: str) -> None:
    """
    Send one password-reset link.

    Delivery order in the default ``auto`` mode:
      1. Resend, when RESEND_API_KEY is configured.
      2. SMTP fallback, when SMTP credentials are configured.

    This lets production use a verified Resend sender while still allowing a
    Gmail account + App Password to deliver reset emails when no custom domain
    is available. The reset token is never logged by this function.
    """

    body = build_reset_email_body(reset_link)
    provider = settings.reset_email_provider.strip().lower()

    if provider not in {"auto", "resend", "smtp"}:
        raise RuntimeError("RESET_EMAIL_PROVIDER must be auto, resend, or smtp.")

    if provider == "resend":
        _send_via_resend(to_email=to_email, body=body)
        return

    if provider == "smtp":
        _send_via_smtp(to_email=to_email, body=body)
        return

    # auto: prefer Resend when configured, but fall back to SMTP if the
    # Resend sandbox rejects delivery to an arbitrary recipient.
    resend_error: Exception | None = None
    if settings.resend_api_key:
        try:
            _send_via_resend(to_email=to_email, body=body)
            return
        except Exception as exc:  # provider/network errors only; token not logged
            resend_error = exc

    if settings.smtp_username and settings.smtp_password:
        _send_via_smtp(to_email=to_email, body=body)
        return

    if resend_error is not None:
        raise RuntimeError("Password-reset email delivery failed.") from resend_error

    raise RuntimeError(
        "No password-reset email provider is configured. Set RESEND_API_KEY "
        "or SMTP_USERNAME/SMTP_PASSWORD."
    )


def get_reset_email_sender():
    """FastAPI dependency indirection so tests can replace email delivery."""

    return send_reset_email
