"""
tests/unit/test_api_keys.py
---------------------------
Unit tests for:
  - API key generation, prefix, hashing, and format
  - Brute-force guard: threshold and cooldown behaviour
  - Scope helpers
"""


from gateway.core.security import (
    generate_api_key,
    hash_api_key,
    API_KEY_PREFIX,
    API_KEY_RANDOM_LENGTH,
)
from gateway.core.apikeys import (
    is_ip_blocked,
    record_failure,
    reset_ip,
    FAIL_LIMIT,
    serialize_scopes,
    deserialize_scopes,
    scopes_allow,
)


# ─────────────────────────────────────────────────────────────────────────────
# Key generation
# ─────────────────────────────────────────────────────────────────────────────

class TestAPIKeyGeneration:
    def test_prefix_matches_constant(self):
        prefix, _, _ = generate_api_key()
        assert prefix == API_KEY_PREFIX

    def test_plaintext_starts_with_prefix(self):
        _, plaintext, _ = generate_api_key()
        assert plaintext.startswith(API_KEY_PREFIX)

    def test_plaintext_length(self):
        _, plaintext, _ = generate_api_key()
        expected_len = len(API_KEY_PREFIX) + API_KEY_RANDOM_LENGTH
        assert len(plaintext) == expected_len

    def test_plaintext_is_alphanumeric(self):
        _, plaintext, _ = generate_api_key()
        suffix = plaintext[len(API_KEY_PREFIX):]
        assert suffix.isalnum()

    def test_hash_is_hex_sha256(self):
        _, plaintext, key_hash = generate_api_key()
        assert len(key_hash) == 64
        assert all(c in "0123456789abcdef" for c in key_hash)

    def test_hash_is_deterministic(self):
        key = "ztg_live_abc123"
        assert hash_api_key(key) == hash_api_key(key)

    def test_different_keys_produce_different_hashes(self):
        _, key1, h1 = generate_api_key()
        _, key2, h2 = generate_api_key()
        assert key1 != key2
        assert h1 != h2


# ─────────────────────────────────────────────────────────────────────────────
# Brute-force guard
# ─────────────────────────────────────────────────────────────────────────────

class TestBruteForceGuard:
    def setup_method(self):
        reset_ip("test_ip")
        reset_ip("test_ip_2")

    def test_no_block_before_threshold(self):
        for _ in range(FAIL_LIMIT - 1):
            assert record_failure("test_ip") is False
        assert is_ip_blocked("test_ip") is False

    def test_block_at_threshold(self):
        for _ in range(FAIL_LIMIT - 1):
            record_failure("test_ip")
        assert record_failure("test_ip") is True
        assert is_ip_blocked("test_ip") is True

    def test_independent_ips(self):
        for _ in range(FAIL_LIMIT):
            record_failure("test_ip_2")
        assert is_ip_blocked("test_ip") is False

    def test_reset_clears_history(self):
        for _ in range(FAIL_LIMIT - 1):
            record_failure("test_ip")
        reset_ip("test_ip")
        assert is_ip_blocked("test_ip") is False


# ─────────────────────────────────────────────────────────────────────────────
# Scopes
# ─────────────────────────────────────────────────────────────────────────────

class TestScopes:
    def test_all_grants_anything(self):
        assert scopes_allow(["all"], "data") is True
        assert scopes_allow(["all"], "payments") is True

    def test_wildcard_grants_anything(self):
        assert scopes_allow(["*"], "data") is True

    def test_exact_match(self):
        assert scopes_allow(["proxy:data"], "data") is True

    def test_mismatch_denied(self):
        assert scopes_allow(["proxy:data"], "payments") is False

    def test_empty_denied(self):
        assert scopes_allow([], "data") is False

    def test_mixed_scopes(self):
        assert scopes_allow(["proxy:data", "proxy:payments"], "payments") is True
        assert scopes_allow(["proxy:data", "proxy:payments"], "logs") is False


class TestScopeSerialisation:
    def test_roundtrip(self):
        assert deserialize_scopes(serialize_scopes(["a", "b"])) == ["a", "b"]

    def test_empty_defaults(self):
        assert deserialize_scopes(None) == []
        assert deserialize_scopes("") == []
