"""Password policy validation shared by user creation and password resets.

Every rule returns human-readable messages so routes can surface the complete
list of unmet criteria in one response instead of failing one rule at a time.
"""

from __future__ import annotations

import re

from app.core.config import settings


SPECIAL_CHARACTERS = "!@#$%^&*()_+-=[]{}|;:,.<>?"
_SPECIAL_PATTERN = re.compile(f"[{re.escape(SPECIAL_CHARACTERS)}]")

# Words that must never appear inside a CyberShield credential regardless of
# the surrounding characters.
PRODUCT_TERMS = ("cybershield",)

# Lowercased base words matched against the password with digits/specials
# stripped from both ends, so "Password123!" and "!!qwerty99" are both caught.
COMMON_PASSWORD_BASES = frozenset(
    {
        "password",
        "passwort",
        "passw0rd",
        "p@ssword",
        "p@ssw0rd",
        "letmein",
        "welcome",
        "iloveyou",
        "sunshine",
        "princess",
        "dragon",
        "monkey",
        "football",
        "baseball",
        "superman",
        "batman",
        "trustno1",
        "master",
        "shadow",
        "qwerty",
        "qwertyuiop",
        "asdfgh",
        "asdfghjkl",
        "zxcvbnm",
        "admin",
        "administrator",
        "root",
        "login",
        "logon",
        "secret",
        "secure",
        "security",
        "changeme",
        "default",
        "guest",
        "test",
        "temp",
        "temporary",
        "winter",
        "spring",
        "summer",
        "autumn",
    }
)

# Runs of these characters (length >= 4, forward or reverse) mark a password
# as sequential/keyboard-walk guessable.
_SEQUENCES = (
    "abcdefghijklmnopqrstuvwxyz",
    "0123456789",
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
)
_SEQUENCE_RUN_LENGTH = 4


def _strip_decorations(value: str) -> str:
    """Remove leading/trailing digits and special characters for base-word checks."""

    return value.strip("0123456789" + SPECIAL_CHARACTERS)


def _contains_sequential_run(lowered: str) -> bool:
    for sequence in _SEQUENCES:
        for start in range(len(sequence) - _SEQUENCE_RUN_LENGTH + 1):
            run = sequence[start : start + _SEQUENCE_RUN_LENGTH]
            if run in lowered or run[::-1] in lowered:
                return True
    return False


def _has_repeated_character_run(lowered: str) -> bool:
    return re.search(r"(.)\1{3,}", lowered) is not None


def password_policy_errors(password: str) -> list[str]:
    """Return every unmet length/complexity/guessability criterion."""

    errors: list[str] = []
    minimum = settings.password_min_length

    if len(password) < minimum:
        errors.append(f"Password must be at least {minimum} characters long.")
    if not re.search(r"[A-Z]", password):
        errors.append("Password must contain at least one uppercase letter.")
    if not re.search(r"[a-z]", password):
        errors.append("Password must contain at least one lowercase letter.")
    if not re.search(r"[0-9]", password):
        errors.append("Password must contain at least one number.")
    if not _SPECIAL_PATTERN.search(password):
        errors.append(
            f"Password must contain at least one special character ({SPECIAL_CHARACTERS})."
        )

    lowered = password.lower()
    stripped_base = _strip_decorations(lowered)
    starts_with_decorated_base = any(
        lowered.startswith(base)
        and lowered[len(base) : len(base) + 1] in "0123456789" + SPECIAL_CHARACTERS
        for base in COMMON_PASSWORD_BASES
    )
    if (
        lowered in COMMON_PASSWORD_BASES
        or stripped_base in COMMON_PASSWORD_BASES
        or starts_with_decorated_base
    ):
        errors.append("Password is too common and easily guessable.")
    elif _contains_sequential_run(lowered) or _has_repeated_character_run(lowered):
        errors.append(
            "Password must not contain sequential or repeated character runs (e.g. 'abcd', '1234', 'aaaa')."
        )

    return errors


def password_context_errors(
    password: str,
    *,
    username: str | None = None,
    email: str | None = None,
) -> list[str]:
    """Reject passwords derived from the account identity or the product name."""

    errors: list[str] = []
    lowered = password.lower()

    for term in PRODUCT_TERMS:
        if term in lowered:
            errors.append(f"Password must not contain the word '{term}'.")

    if username:
        normalized_username = username.strip().lower()
        if len(normalized_username) >= 3 and normalized_username in lowered:
            errors.append("Password must not contain your username.")

    if email:
        local_part = email.strip().lower().partition("@")[0]
        if len(local_part) >= 3 and local_part in lowered:
            errors.append("Password must not contain the local part of your email address.")

    return errors


def validate_password(
    password: str,
    *,
    username: str | None = None,
    email: str | None = None,
) -> list[str]:
    """Full policy + contextual check. An empty list means the password passes."""

    return password_policy_errors(password) + password_context_errors(
        password, username=username, email=email
    )
