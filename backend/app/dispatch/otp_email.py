from __future__ import annotations

import resend
import os
from html import escape

from app.core.config import settings

OTP_EMAIL_SUBJECT = "CyberShield SOC | Verification code"


def build_otp_email_body(code: str) -> dict[str, str]:
    safe_code = escape(code)
    expiry_minutes = settings.otp_expiry_minutes

    public_domain = os.getenv("RAILWAY_PUBLIC_DOMAIN", "").strip().rstrip("/")
    if public_domain and not public_domain.startswith(("http://", "https://")):
        public_domain = f"https://{public_domain}"

    if public_domain:
        logo_url = escape(
            f"{public_domain}/assets/CYBERSHIELD.jpg",
            quote=True,
        )
        logo_html = (
            f'<img src="{logo_url}" width="180" alt="CyberShield SOC" '
            'style="display:block;width:180px;max-width:100%;height:auto;'
            'margin:0 auto;border:0;">'
        )
    else:
        logo_html = (
            '<div style="color:#b9e9ff;font-size:25px;font-weight:700;'
            'letter-spacing:2px;">CYBERSHIELD</div>'
        )

    text = (
        "CYBERSHIELD SOC\n"
        "SECURE ACCESS\n\n"
        "Verify your sign-in\n\n"
        "Use this one-time verification code to complete your login:\n\n"
        f"{code}\n\n"
        f"This code expires in {expiry_minutes} minutes.\n"
        "Never share this code with anyone.\n\n"
        "If you did not attempt to sign in to CyberShield, "
        "you can safely ignore this email."
    )

    html = f"""
    <!doctype html>
    <html lang="en">
      <body style="margin:0;padding:0;background-color:#eef3f6;">
        <div style="display:none;max-height:0;overflow:hidden;opacity:0;">
          Your CyberShield verification code expires in {expiry_minutes} minutes.
        </div>

        <table role="presentation" width="100%" cellpadding="0" cellspacing="0"
               style="background-color:#eef3f6;">
          <tr>
            <td align="center" style="padding:32px 14px;">
              <table role="presentation" width="100%" cellpadding="0" cellspacing="0"
                     style="max-width:560px;background-color:#ffffff;
                            border:1px solid #d8e2e8;border-radius:12px;
                            overflow:hidden;">

                <tr>
                  <td align="center"
                      style="background-color:#07192d;padding:24px;
                             border-bottom:4px solid #0fb5a6;">
                    {logo_html}
                    <div style="margin-top:10px;color:#0fb5a6;
                                font-family:Arial,Helvetica,sans-serif;
                                font-size:11px;font-weight:700;
                                letter-spacing:2px;">
                      SECURE ACCESS
                    </div>
                  </td>
                </tr>

                <tr>
                  <td style="padding:34px 36px;
                             font-family:Arial,Helvetica,sans-serif;
                             color:#0b1f3a;">
                    <div style="color:#0b8a7f;font-size:11px;font-weight:700;
                                letter-spacing:1.5px;">
                      SIGN-IN VERIFICATION
                    </div>

                    <h1 style="margin:10px 0 12px;font-size:25px;
                               line-height:1.25;color:#0b1f3a;">
                      Verify your sign-in
                    </h1>

                    <p style="margin:0;color:#526579;font-size:15px;
                              line-height:1.65;">
                      Enter this one-time code in CyberShield to complete
                      your secure login:
                    </p>

                    <div style="margin:26px 0;padding:20px;text-align:center;
                                background-color:#edf9f7;
                                border:1px solid #a8ddd7;border-radius:10px;
                                color:#0b1f3a;font-family:Consolas,Monaco,
                                monospace;font-size:34px;font-weight:700;
                                letter-spacing:8px;">
                      {safe_code}
                    </div>

                    <p style="margin:0;text-align:center;color:#526579;
                              font-size:13px;">
                      This code expires in
                      <strong>{expiry_minutes} minutes</strong>.
                    </p>

                    <div style="margin-top:26px;padding:15px 17px;
                                background-color:#f7fafc;
                                border-left:4px solid #0b8a7f;
                                color:#526579;font-size:13px;line-height:1.55;">
                      <strong style="color:#0b1f3a;">Security notice:</strong>
                      Never share this code. CyberShield administrators will
                      never ask you to provide it.
                    </div>

                    <p style="margin:22px 0 0;color:#718096;
                              font-size:12px;line-height:1.55;">
                      If you did not attempt to sign in to CyberShield,
                      you can safely ignore this email.
                    </p>
                  </td>
                </tr>

                <tr>
                  <td align="center"
                      style="padding:18px;background-color:#0b1f3a;
                             color:#9eb3c7;font-family:Arial,Helvetica,
                             sans-serif;font-size:11px;">
                    CyberShield SOC · Security Operations Platform
                  </td>
                </tr>

              </table>
            </td>
          </tr>
        </table>
      </body>
    </html>
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
