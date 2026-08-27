"""
tests/unit/test_security.py
----------------------------
Unit tests for gateway.core.security.SecurityManager.
No database or HTTP required.
"""

import time

from gateway.core.security import SecurityManager


class TestPasswordHashing:
    def test_hash_is_not_plaintext(self):
        hashed = SecurityManager.hash_password("MyPassword1!")
        assert hashed != "MyPassword1!"

    def test_correct_password_verifies(self):
        hashed = SecurityManager.hash_password("Correct@1")
        assert SecurityManager.verify_password("Correct@1", hashed) is True

    def test_wrong_password_fails(self):
        hashed = SecurityManager.hash_password("Correct@1")
        assert SecurityManager.verify_password("Wrong@1", hashed) is False

    def test_empty_password_does_not_match(self):
        hashed = SecurityManager.hash_password("SomePass1!")
        assert SecurityManager.verify_password("", hashed) is False

    def test_different_hashes_for_same_password(self):
        """Argon2 / bcrypt produce salted hashes — two calls differ."""
        h1 = SecurityManager.hash_password("Same@Pass1")
        h2 = SecurityManager.hash_password("Same@Pass1")
        assert h1 != h2  # different salts

    def test_both_verify_true_despite_different_hashes(self):
        h1 = SecurityManager.hash_password("Same@Pass1")
        h2 = SecurityManager.hash_password("Same@Pass1")
        assert SecurityManager.verify_password("Same@Pass1", h1) is True
        assert SecurityManager.verify_password("Same@Pass1", h2) is True


class TestJWTTokens:
    def test_create_and_verify_token(self):
        token = SecurityManager.create_access_token(data={"sub": "user@example.com"})
        payload = SecurityManager.verify_token(token)
        assert payload is not None
        assert payload["sub"] == "user@example.com"

    def test_tampered_token_is_rejected(self):
        token = SecurityManager.create_access_token(data={"sub": "user@example.com"})
        tampered = token[:-5] + "XXXXX"
        assert SecurityManager.verify_token(tampered) is None

    def test_token_contains_exp(self):
        token = SecurityManager.create_access_token(data={"sub": "x@x.com"})
        payload = SecurityManager.verify_token(token)
        assert "exp" in payload
        assert payload["exp"] > time.time()

    def test_custom_payload_fields_preserved(self):
        token = SecurityManager.create_access_token(data={"sub": "a@b.com", "role": "admin"})
        payload = SecurityManager.verify_token(token)
        assert payload["role"] == "admin"

    def test_wrong_secret_rejects_token(self):
        token = SecurityManager.create_access_token(data={"sub": "x@x.com"})
        result = SecurityManager.verify_token(token, secret_key="wrong-secret")
        assert result is None
