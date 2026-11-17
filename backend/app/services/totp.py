"""Authenticator-app second factor: TOTP (RFC 6238) over HOTP (RFC 4226).

The algorithm is a few lines of stdlib ``hmac``; it is checked against the
RFC test vectors in tests/test_totp_mfa.py. Everything an authenticator app
needs is the default profile: SHA-1, 6 digits, 30-second steps.

Secrets must be readable by the server (it has to compute the same code),
so they are encrypted at rest rather than hashed. Recovery codes are only
ever compared, so they are stored as keyed digests like emailed OTP codes.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app.core.config import settings

ISSUER = "CyberShield SOC"
DIGITS = 6
PERIOD_SECONDS = 30
# Accept the step either side of now: a phone clock up to ~30s out, or a
# code typed as it rolls over, still signs in.
WINDOW_STEPS = 1
RECOVERY_CODE_COUNT = 8

_RECOVERY_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"  # no 0/o, 1/i/l
_RECOVERY_LENGTH = 10


class TotpSecretUnreadable(Exception):
    """The stored secret cannot be decrypted (the server key changed)."""


# --- RFC 4226 / RFC 6238 ---------------------------------------------------


def generate_secret() -> str:
    """A new 160-bit shared secret, base32 as authenticator apps expect."""

    return base64.b32encode(secrets.token_bytes(20)).decode("ascii")


def _key_bytes(secret: str) -> bytes:
    cleaned = secret.replace(" ", "").upper()
    return base64.b32decode(cleaned + "=" * (-len(cleaned) % 8))


def hotp(key: bytes, counter: int, *, digits: int = DIGITS, digest=hashlib.sha1) -> str:
    mac = hmac.new(key, struct.pack(">Q", counter), digest).digest()
    offset = mac[-1] & 0x0F
    number = struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF
    return f"{number % (10 ** digits):0{digits}d}"


def counter_at(timestamp: float | None = None) -> int:
    return int((time.time() if timestamp is None else timestamp) // PERIOD_SECONDS)


def totp(secret: str, *, at: float | None = None) -> str:
    return hotp(_key_bytes(secret), counter_at(at))


def matching_counter(
    secret: str,
    code: str,
    *,
    at: float | None = None,
    last_counter: int | None = None,
) -> int | None:
    """The time step ``code`` is valid for, or None.

    A step at or before ``last_counter`` is refused, so a code that has
    already signed someone in cannot be replayed inside its validity window.
    """

    # isascii: str.isdigit() also accepts digits from other scripts.
    if len(code) != DIGITS or not (code.isascii() and code.isdigit()):
        return None
    key = _key_bytes(secret)
    current = counter_at(at)
    matched = None
    # Check every candidate without an early exit so timing does not reveal
    # which step (if any) matched.
    for counter in range(current - WINDOW_STEPS, current + WINDOW_STEPS + 1):
        if hmac.compare_digest(hotp(key, counter), code) and matched is None:
            matched = counter
    if matched is None or (last_counter is not None and matched <= last_counter):
        return None
    return matched


# --- enrolment -------------------------------------------------------------


def provisioning_uri(secret: str, account: str) -> str:
    """The otpauth:// URI an authenticator app reads from the QR code."""

    label = quote(f"{ISSUER}:{account}", safe="")
    return (
        f"otpauth://totp/{label}?secret={secret}&issuer={quote(ISSUER, safe='')}"
        f"&algorithm=SHA1&digits={DIGITS}&period={PERIOD_SECONDS}"
    )


def qr_svg(data: str) -> str:
    """``data`` as a QR code in a self-contained SVG (black on white)."""

    from reportlab.graphics.barcode.qr import QrCodeWidget

    widget = QrCodeWidget(data, barLevel="M")
    widget.qr.make()
    size = widget.qr.getModuleCount()
    quiet = 4  # modules of quiet zone, as the QR specification requires
    runs = []
    for row in range(size):
        column = 0
        while column < size:
            if not widget.qr.isDark(row, column):
                column += 1
                continue
            start = column
            while column < size and widget.qr.isDark(row, column):
                column += 1
            runs.append(f"M{start + quiet} {row + quiet}h{column - start}v1h-{column - start}z")
    total = size + 2 * quiet
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {total} {total}" '
        f'shape-rendering="crispEdges" role="img" aria-label="Authenticator setup QR code">'
        f'<rect width="{total}" height="{total}" fill="#fff"/>'
        f'<path d="{"".join(runs)}" fill="#000"/></svg>'
    )


# --- storage ---------------------------------------------------------------


def _fernet() -> Fernet:
    key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"cybershield-soc/totp-secret/v1",
    ).derive(settings.otp_secret.encode("utf-8"))
    return Fernet(base64.urlsafe_b64encode(key))


def encrypt_secret(secret: str) -> str:
    return _fernet().encrypt(secret.encode("ascii")).decode("ascii")


def decrypt_secret(stored: str) -> str:
    try:
        return _fernet().decrypt(stored.encode("ascii")).decode("ascii")
    except (InvalidToken, ValueError) as exc:
        raise TotpSecretUnreadable("The stored authenticator secret cannot be read.") from exc


# --- recovery codes --------------------------------------------------------


def generate_recovery_codes(count: int = RECOVERY_CODE_COUNT) -> list[str]:
    """Single-use fallback codes, shown once: ``abcde-fghjk`` (~49 bits)."""

    codes = []
    for _ in range(count):
        raw = "".join(secrets.choice(_RECOVERY_ALPHABET) for _ in range(_RECOVERY_LENGTH))
        codes.append(f"{raw[:5]}-{raw[5:]}")
    return codes


def normalize_recovery_code(code: str) -> str | None:
    cleaned = "".join(char for char in code.lower() if char not in " -")
    if len(cleaned) != _RECOVERY_LENGTH or any(char not in _RECOVERY_ALPHABET for char in cleaned):
        return None
    return cleaned


def hash_recovery_code(normalized: str) -> str:
    return hmac.new(
        settings.otp_secret.encode("utf-8"),
        b"mfa-recovery:" + normalized.encode("ascii"),
        hashlib.sha256,
    ).hexdigest()
