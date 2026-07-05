"""Unit tests for PKCE (Proof Key for Code Exchange) utilities.

Tests the code_verifier generation and code_challenge computation
per RFC 7636 and OAuth 2.1 requirements.
"""

from __future__ import annotations

import base64
import hashlib
import re
import string

import pytest

from src.core.pkce import compute_code_challenge, generate_code_verifier


class TestGenerateCodeVerifier:
    """Tests for generate_code_verifier function."""

    def test_default_verifier_length_within_bounds(self):
        """Verifier with default length is between 43 and 128 characters."""
        verifier = generate_code_verifier()
        assert 43 <= len(verifier) <= 128

    def test_verifier_uses_base64url_alphabet(self):
        """Verifier only uses unreserved characters (base64url alphabet)."""
        verifier = generate_code_verifier()
        # RFC 7636 §4.1: ALPHA / DIGIT / "-" / "." / "_" / "~"
        # base64url uses A-Z, a-z, 0-9, -, _ (no padding)
        allowed = set(string.ascii_letters + string.digits + "-_")
        assert all(c in allowed for c in verifier), (
            f"Verifier contains disallowed characters: "
            f"{set(verifier) - allowed}"
        )

    def test_verifier_has_no_padding(self):
        """Verifier does not contain base64 padding characters."""
        verifier = generate_code_verifier()
        assert "=" not in verifier

    def test_verifier_is_unique_per_call(self):
        """Each call produces a different verifier (high entropy)."""
        verifiers = {generate_code_verifier() for _ in range(100)}
        assert len(verifiers) == 100

    def test_verifier_minimum_length_boundary(self):
        """Verifier generated with minimum valid byte count is >= 43 chars."""
        # 32 bytes → 43 base64url chars (ceil(32*4/3) = 43)
        verifier = generate_code_verifier(length=32)
        assert len(verifier) >= 43

    def test_verifier_maximum_length_boundary(self):
        """Verifier generated with maximum valid byte count is <= 128 chars."""
        # 96 bytes → 128 base64url chars
        verifier = generate_code_verifier(length=96)
        assert len(verifier) <= 128

    def test_verifier_rejects_too_short_length(self):
        """ValueError raised when length produces < 43 chars."""
        with pytest.raises(ValueError, match="must be between 43 and 128"):
            generate_code_verifier(length=10)

    def test_verifier_rejects_too_long_length(self):
        """ValueError raised when length produces > 128 chars."""
        with pytest.raises(ValueError, match="must be between 43 and 128"):
            generate_code_verifier(length=200)


class TestComputeCodeChallenge:
    """Tests for compute_code_challenge function."""

    def test_challenge_is_base64url_sha256_of_verifier(self):
        """Challenge equals base64url(SHA256(verifier)) without padding."""
        verifier = generate_code_verifier()
        challenge = compute_code_challenge(verifier)

        # Manually compute expected challenge
        digest = hashlib.sha256(verifier.encode("ascii")).digest()
        expected = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

        assert challenge == expected

    def test_challenge_is_43_characters(self):
        """SHA256 → base64url always produces 43 chars (256 bits / 6 bits per char ≈ 43)."""
        verifier = generate_code_verifier()
        challenge = compute_code_challenge(verifier)
        assert len(challenge) == 43

    def test_challenge_uses_base64url_alphabet(self):
        """Challenge only uses base64url characters (no padding)."""
        verifier = generate_code_verifier()
        challenge = compute_code_challenge(verifier)
        allowed = set(string.ascii_letters + string.digits + "-_")
        assert all(c in allowed for c in challenge)

    def test_challenge_has_no_padding(self):
        """Challenge does not contain '=' padding."""
        verifier = generate_code_verifier()
        challenge = compute_code_challenge(verifier)
        assert "=" not in challenge

    def test_same_verifier_produces_same_challenge(self):
        """Deterministic: same verifier always yields same challenge."""
        verifier = generate_code_verifier()
        c1 = compute_code_challenge(verifier)
        c2 = compute_code_challenge(verifier)
        assert c1 == c2

    def test_different_verifiers_produce_different_challenges(self):
        """Different verifiers produce different challenges."""
        v1 = generate_code_verifier()
        v2 = generate_code_verifier()
        assert compute_code_challenge(v1) != compute_code_challenge(v2)

    def test_challenge_rejects_empty_verifier(self):
        """ValueError raised for empty verifier."""
        with pytest.raises(ValueError, match="must not be empty"):
            compute_code_challenge("")

    def test_challenge_rejects_too_short_verifier(self):
        """ValueError raised for verifier shorter than 43 chars."""
        with pytest.raises(ValueError, match="outside valid range"):
            compute_code_challenge("short")

    def test_challenge_rejects_too_long_verifier(self):
        """ValueError raised for verifier longer than 128 chars."""
        with pytest.raises(ValueError, match="outside valid range"):
            compute_code_challenge("a" * 129)

    def test_rfc7636_appendix_b_reference_vector(self):
        """Validate against a known test vector from RFC 7636 Appendix B.

        The RFC specifies:
          code_verifier = dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
          code_challenge = E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
        """
        verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        expected_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        assert compute_code_challenge(verifier) == expected_challenge
