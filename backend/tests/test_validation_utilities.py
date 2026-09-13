"""Unit tests for the shared password-policy and email-validation utilities."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from pydantic import ValidationError


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.schemas.user import UserCreate, UserPasswordReset  # noqa: E402
from app.validation import (  # noqa: E402
    email_errors,
    email_format_error,
    is_disposable_domain,
    normalize_email,
    password_context_errors,
    password_policy_errors,
    validate_password,
)


pytestmark = pytest.mark.no_db


# --------------------------------------------------------------------------
# Password policy: length and complexity
# --------------------------------------------------------------------------


def test_strong_password_passes_every_policy_rule():
    assert password_policy_errors("Correct-Horse-7-Staple!") == []


def test_short_password_reports_length():
    errors = password_policy_errors("Ab1!x")
    assert any("at least 12 characters" in error for error in errors)


@pytest.mark.parametrize(
    ("password", "expected_fragment"),
    [
        ("valid-lower-999!x", "uppercase"),
        ("VALID-UPPER-999!X", "lowercase"),
        ("Valid-NoDigits-Here!", "number"),
        ("Valid2Special2Missing2", "special character"),
    ],
)
def test_missing_complexity_classes_are_each_reported(password, expected_fragment):
    errors = password_policy_errors(password)
    assert any(expected_fragment in error for error in errors), errors


def test_all_unmet_criteria_are_reported_together():
    errors = password_policy_errors("short")
    assert len(errors) >= 4  # length, uppercase, number, special


# --------------------------------------------------------------------------
# Password policy: common/guessable passwords
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "password",
    [
        "Password123!",
        "P@ssw0rd2026!!",
        "Admin123!wide",  # sequential run "123" is not 4 long; base word 'admin...' isn't stripped
        "Qwertyuiop12!",
        "Letmein44444!",
    ],
)
def test_common_or_guessable_passwords_are_blocked(password):
    assert password_policy_errors(password), password


def test_sequential_runs_are_blocked():
    errors = password_policy_errors("Xk9!abcdQr2mZp")
    assert any("sequential" in error for error in errors)

    errors = password_policy_errors("Xk9!4321Qr2mZp")
    assert any("sequential" in error for error in errors)


def test_repeated_character_runs_are_blocked():
    errors = password_policy_errors("Xk9!aaaaQr2mZp")
    assert any("repeated" in error for error in errors)


def test_decorated_dictionary_words_are_still_caught():
    errors = password_policy_errors("!!Welcome99!!")
    assert any("too common" in error for error in errors)


# --------------------------------------------------------------------------
# Password policy: contextual blocks
# --------------------------------------------------------------------------


def test_password_containing_username_is_blocked():
    errors = password_context_errors(
        "Xk-jordanriver-9!", username="JordanRiver", email="jr@example.test"
    )
    assert errors == ["Password must not contain your username."]


def test_password_containing_email_local_part_is_blocked():
    errors = password_context_errors(
        "Xk-j.doe55-Zq9!", username="operator", email="J.Doe55@example.test"
    )
    assert errors == ["Password must not contain the local part of your email address."]


def test_password_containing_product_name_is_blocked():
    errors = password_context_errors("MyCyberShield-99!", username=None, email=None)
    assert errors == ["Password must not contain the word 'cybershield'."]


def test_contextual_check_ignores_very_short_identity_fragments():
    # A 1-2 character local part would match almost anything; it is skipped.
    assert password_context_errors("Xk9!mQr2Zp$Lw", username="ab", email="ab@example.test") == []


def test_validate_password_combines_policy_and_context():
    errors = validate_password("cybershield", username="root", email="root@example.test")
    assert any("uppercase" in error for error in errors)
    assert any("cybershield" in error for error in errors)


# --------------------------------------------------------------------------
# Email: normalization and syntax
# --------------------------------------------------------------------------


def test_normalize_email_trims_and_lowercases():
    assert normalize_email("  Analyst@CyberShield.IO  ") == "analyst@cybershield.io"


@pytest.mark.parametrize(
    "email",
    [
        "analyst@example.com",
        "first.last@sub.example.co.uk",
        "user+tag@example.io",
        "o'brien@example.org",
        "x_y-z@example.travel",
    ],
)
def test_valid_email_structures_are_accepted(email):
    assert email_format_error(email) is None


@pytest.mark.parametrize(
    ("email", "fragment"),
    [
        ("", "required"),
        ("missing-at.example.com", "'@'"),
        ("no-domain@", "'@'"),
        ("@no-local.example.com", "'@'"),
        ("double..dot@example.com", "consecutive dots"),
        (".leading@example.com", "start or end with a dot"),
        ("trailing.@example.com", "start or end with a dot"),
        ("user@example..com", "consecutive dots"),
        ("user@example", "invalid structure"),
        ("user@example.c", "invalid structure"),
        ("user@example.abcdefghijklmnopqrstuvwxyz", "invalid structure"),
        ("user@-bad-label.example.com", "invalid structure"),
        ("us er@example.com", "invalid structure"),
        ('"quoted"@example.com', "invalid structure"),
        (f"{'a' * 65}@example.com", "64 characters or fewer"),
        (f"user@{'a' * 250}.com", "254 characters or fewer"),
    ],
)
def test_invalid_email_structures_report_the_specific_problem(email, fragment):
    error = email_format_error(email)
    assert error is not None and fragment in error, (email, error)


# --------------------------------------------------------------------------
# Email: disposable domains
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "domain",
    ["mailinator.com", "tempmail.com", "10minutemail.com", "inbox.mailinator.com"],
)
def test_disposable_domains_and_their_subdomains_are_detected(domain):
    assert is_disposable_domain(domain) is True


def test_legitimate_domains_are_not_flagged_as_disposable():
    assert is_disposable_domain("example.com") is False
    assert is_disposable_domain("notmailinator.com") is False


def test_email_errors_blocks_disposable_addresses():
    assert email_errors("agent@mailinator.com", check_deliverability=False) == [
        "Disposable or temporary email addresses are not allowed."
    ]
    assert email_errors("agent@example.com", check_deliverability=False) == []


# --------------------------------------------------------------------------
# Schema integration
# --------------------------------------------------------------------------


def _user_payload(**overrides):
    payload = {
        "username": "analyst-two",
        "email": "analyst.two@example.test",
        "password": "Correct-Horse-7-Staple!",
        "role": "Analyst",
    }
    payload.update(overrides)
    return payload


def test_user_create_accepts_a_policy_compliant_account():
    user = UserCreate(**_user_payload())
    assert user.email == "analyst.two@example.test"


def test_user_create_rejects_weak_password_with_descriptive_messages():
    with pytest.raises(ValidationError) as excinfo:
        UserCreate(**_user_payload(password="Password123!"))
    assert "too common" in str(excinfo.value)


def test_user_create_rejects_password_containing_username():
    with pytest.raises(ValidationError) as excinfo:
        UserCreate(**_user_payload(password="Xanalyst-twoZ42!Q"))
    assert "username" in str(excinfo.value)


def test_user_create_rejects_disposable_email():
    with pytest.raises(ValidationError) as excinfo:
        UserCreate(**_user_payload(email="analyst@tempmail.com"))
    assert "Disposable" in str(excinfo.value)


def test_password_reset_schema_enforces_the_policy():
    assert (
        UserPasswordReset(new_password="Replacement-Phrase-42!").new_password
        == "Replacement-Phrase-42!"
    )
    with pytest.raises(ValidationError):
        UserPasswordReset(new_password="weak")
    with pytest.raises(ValidationError) as excinfo:
        UserPasswordReset(new_password="Qwertyuiop999!")
    assert "too common" in str(excinfo.value)
