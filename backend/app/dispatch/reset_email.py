from __future__ import annotations

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


def send_reset_email(*, to_email: str, reset_link: str) -> None:
    """
    Send one password-reset link via Resend. Raises on any failure (missing
    API key, network error, Resend-reported error) — the caller decides how
    to respond; this function never logs the link's token.
    """

    if not settings.resend_api_key:
        raise RuntimeError("RESEND_API_KEY is not configured.")

    resend.api_key = settings.resend_api_key
    body = build_reset_email_body(reset_link)
    resend.Emails.send(
        {
            "from": settings.resend_from_email,
            "to": [to_email],
            "subject": RESET_EMAIL_SUBJECT,
            "text": body["text"],
            "html": body["html"],
        }
    )


def get_reset_email_sender():
    """
    FastAPI dependency indirection for send_reset_email.

    Routes depend on this (not on send_reset_email directly) so tests can
    override it via app.dependency_overrides — the same pattern already used
    for get_otp_email_sender — without making a real Resend call or needing
    an API key in CI.
    """

    return send_reset_email
