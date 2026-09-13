"""Email normalization, syntax, disposable-domain, and deliverability checks."""

from __future__ import annotations

import re
import socket

from app.core.config import settings


# Practical RFC 5322 subset: dot-atom local part, LDH domain labels, and an
# alphabetic TLD of 2-24 characters. Quoted local parts and address literals
# are intentionally rejected — they have no place in an account directory.
_LOCAL_ATOM = r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+"
_DOMAIN_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
EMAIL_PATTERN = re.compile(
    rf"^{_LOCAL_ATOM}(?:\.{_LOCAL_ATOM})*"
    rf"@{_DOMAIN_LABEL}(?:\.{_DOMAIN_LABEL})*\.[A-Za-z]{{2,24}}$"
)

MAX_EMAIL_LENGTH = 254
MAX_LOCAL_PART_LENGTH = 64

# Well-known disposable/temporary email providers, matched against the domain
# and any subdomain of it.
DISPOSABLE_DOMAINS = frozenset(
    {
        "10minutemail.com",
        "10minutemail.net",
        "20minutemail.com",
        "burnermail.io",
        "dispostable.com",
        "emailondeck.com",
        "fakeinbox.com",
        "getairmail.com",
        "getnada.com",
        "guerrillamail.biz",
        "guerrillamail.com",
        "guerrillamail.de",
        "guerrillamail.net",
        "guerrillamail.org",
        "inboxkitten.com",
        "mail-temp.com",
        "mailcatch.com",
        "maildrop.cc",
        "mailinator.com",
        "mailinator.net",
        "mailnesia.com",
        "mintemail.com",
        "mohmal.com",
        "mytemp.email",
        "sharklasers.com",
        "spamgourmet.com",
        "tempail.com",
        "temp-mail.io",
        "temp-mail.org",
        "tempmail.com",
        "tempmail.dev",
        "tempmail.net",
        "tempmailo.com",
        "throwawaymail.com",
        "trashmail.com",
        "trashmail.net",
        "yopmail.com",
        "yopmail.fr",
        "yopmail.net",
    }
)


def normalize_email(value: str) -> str:
    """Trim surrounding whitespace and lowercase the address for storage."""

    return value.strip().lower()


def mask_email(email: str) -> str:
    """Mask an address for display, e.g. "yugal99@gmail.com" -> "yu***@gmail.com"."""

    local, separator, domain = email.partition("@")
    if not separator:
        return "***"
    visible = local[:2] if len(local) >= 2 else local[:1]
    return f"{visible}***@{domain}"


def email_format_error(email: str) -> str | None:
    """Return a message describing the first structural problem, or None."""

    if not email:
        return "Email address is required."
    if len(email) > MAX_EMAIL_LENGTH:
        return f"Email address must be {MAX_EMAIL_LENGTH} characters or fewer."

    local, separator, domain = email.partition("@")
    if not separator or not local or not domain:
        return "Email address must contain a local part and a domain separated by '@'."
    if len(local) > MAX_LOCAL_PART_LENGTH:
        return f"The part before '@' must be {MAX_LOCAL_PART_LENGTH} characters or fewer."
    if ".." in email:
        return "Email address must not contain consecutive dots."
    if local.startswith(".") or local.endswith("."):
        return "The part before '@' must not start or end with a dot."
    if not EMAIL_PATTERN.match(email):
        return "Email address contains an invalid structure or illegal characters."
    return None


def is_disposable_domain(domain: str) -> bool:
    """True when the domain or any parent domain is a known disposable provider."""

    domain = domain.lower().rstrip(".")
    while domain:
        if domain in DISPOSABLE_DOMAINS:
            return True
        _, _, domain = domain.partition(".")
    return False


def domain_has_mail_service(domain: str, *, timeout_seconds: float = 3.0) -> bool | None:
    """Best-effort deliverability probe.

    Returns True when the domain resolves (an A/AAAA lookup succeeds, which is
    the fallback SMTP delivery target when no MX record exists), False when it
    definitively does not, and None when the environment cannot answer (no
    network, DNS timeout) — callers must treat None as "unknown", not invalid.
    """

    try:
        original_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(timeout_seconds)
        try:
            socket.getaddrinfo(domain, None)
            return True
        finally:
            socket.setdefaulttimeout(original_timeout)
    except socket.gaierror as exc:
        # EAI_NONAME / EAI_NODATA mean the name genuinely has no records;
        # anything else (EAI_AGAIN, etc.) is a transient resolver problem.
        if exc.errno in (socket.EAI_NONAME, getattr(socket, "EAI_NODATA", -5)):
            return False
        return None
    except OSError:
        return None


def email_errors(email: str, *, check_deliverability: bool | None = None) -> list[str]:
    """Validate a normalized email address against every configured rule."""

    format_error = email_format_error(email)
    if format_error:
        return [format_error]

    errors: list[str] = []
    domain = email.rpartition("@")[2]

    if is_disposable_domain(domain):
        errors.append("Disposable or temporary email addresses are not allowed.")

    if check_deliverability is None:
        check_deliverability = settings.email_verify_deliverability
    if check_deliverability and not errors:
        if domain_has_mail_service(domain) is False:
            errors.append("Email domain does not exist or cannot receive mail.")

    return errors
