from __future__ import annotations

import resend

from app.core.config import settings

OTP_EMAIL_SUBJECT = "CyberShield verification code"


def build_otp_email_body(code: str) -> dict[str, str]:
    """Pure builder (no network call) so the copy is unit-testable on its own."""

    text = (
        "CyberShield\n\n"
        "Your verification code is:\n\n"
        f"{code}\n\n"
        f"This code expires in {settings.otp_expiry_minutes} minutes.\n\n"
        "If you didn't attempt to sign in to CyberShield, you can ignore this email."
    )
    html = f"""
    <div style="font-family:Arial,Helvetica,sans-serif;max-width:480px;margin:0 auto;padding:24px;color:#0f172a;">
      <p style="font-weight:700;font-size:18px;margin:0 0 20px;">CyberShield</p>
      <p style="margin:0 0 8px;">Your verification code is:</p>
      <p style="font-size:32px;font-weight:700;letter-spacing:6px;margin:0 0 20px;">{code}</p>
      <p style="color:#475569;margin:0 0 16px;">This code expires in {settings.otp_expiry_minutes} minutes.</p>
      <p style="color:#475569;font-size:13px;margin:0;">
        If you didn't attempt to sign in to CyberShield, you can ignore this email.
      </p>
    </div>
    """
    return {"text": text, "html": html}


def send_otp_email(*, to_email: str, code: str) -> None:
    """
    Send one OTP code via Resend. Raises on any failure (missing API key,
    network error, Resend-reported error) — the caller decides how to
    respond to the request; this function never logs `code`.
    """

    if not settings.resend_api_key:
        raise RuntimeError("RESEND_API_KEY is not configured.")

    resend.api_key = settings.resend_api_key
    body = build_otp_email_body(code)
    resend.Emails.send(
        {
            "from": settings.resend_from_email,
            "to": [to_email],
            "subject": OTP_EMAIL_SUBJECT,
            "text": body["text"],
            "html": body["html"],
        }
    )


def get_otp_email_sender():
    """
    FastAPI dependency indirection for send_otp_email.

    Routes depend on this (not on send_otp_email directly) so tests can
    override it via app.dependency_overrides — the same pattern already used
    for current_user elsewhere in this codebase — without making a real
    Resend call or needing an API key in CI.
    """

    return send_otp_email
