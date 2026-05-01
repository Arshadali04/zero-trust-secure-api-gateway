"""
tests/unit/test_validators.py
------------------------------
Unit tests for Pydantic schema validators (password strength, username format).
"""

import pytest
from pydantic import ValidationError
from gateway.db.schemas import UserCreate, LoginRequest


VALID_PAYLOAD = {
    "email": "user@example.com",
    "username": "validuser",
    "password": "Secure@Pass1",
    "full_name": "Test User",
}


class TestPasswordStrength:
    def test_valid_password_accepted(self):
        u = UserCreate(**VALID_PAYLOAD)
        assert u.password == "Secure@Pass1"

    def test_too_short_rejected(self):
        bad = {**VALID_PAYLOAD, "password": "Sh@1"}
        with pytest.raises(ValidationError, match="8 characters"):
            UserCreate(**bad)

    def test_no_uppercase_rejected(self):
        bad = {**VALID_PAYLOAD, "password": "secure@pass1"}
        with pytest.raises(ValidationError, match="uppercase"):
            UserCreate(**bad)

    def test_no_lowercase_rejected(self):
        bad = {**VALID_PAYLOAD, "password": "SECURE@PASS1"}
        with pytest.raises(ValidationError, match="lowercase"):
            UserCreate(**bad)

    def test_no_digit_rejected(self):
        bad = {**VALID_PAYLOAD, "password": "Secure@Pass"}
        with pytest.raises(ValidationError, match="digit"):
            UserCreate(**bad)

    def test_no_special_char_rejected(self):
        bad = {**VALID_PAYLOAD, "password": "SecurePass1"}
        with pytest.raises(ValidationError, match="special character"):
            UserCreate(**bad)


class TestUsernameValidator:
    def test_valid_username_accepted(self):
        u = UserCreate(**VALID_PAYLOAD)
        assert u.username == "validuser"

    def test_username_lowercased(self):
        u = UserCreate(**{**VALID_PAYLOAD, "username": "ValidUser"})
        assert u.username == "validuser"

    def test_username_with_numbers_accepted(self):
        u = UserCreate(**{**VALID_PAYLOAD, "username": "user123"})
        assert u.username == "user123"

    def test_username_with_underscore_accepted(self):
        u = UserCreate(**{**VALID_PAYLOAD, "username": "user_name"})
        assert u.username == "user_name"

    def test_username_with_hyphen_rejected(self):
        bad = {**VALID_PAYLOAD, "username": "user-name"}
        with pytest.raises(ValidationError, match="letters, digits"):
            UserCreate(**bad)

    def test_username_with_space_rejected(self):
        bad = {**VALID_PAYLOAD, "username": "user name"}
        with pytest.raises(ValidationError):
            UserCreate(**bad)

    def test_username_too_short_rejected(self):
        bad = {**VALID_PAYLOAD, "username": "ab"}
        with pytest.raises(ValidationError):
            UserCreate(**bad)


class TestEmailValidator:
    def test_valid_email_accepted(self):
        req = LoginRequest(email="valid@example.com", password="Password@1")
        assert req.email == "valid@example.com"

    def test_invalid_email_rejected(self):
        with pytest.raises(ValidationError):
            LoginRequest(email="not-an-email", password="Password@1")
