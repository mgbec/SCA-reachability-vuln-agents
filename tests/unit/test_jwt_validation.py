"""Unit tests for JWT validation logic.

Tests the validate_jwt function covering:
- Missing/empty token → "missing_token" (Requirement 3.4)
- Valid token → success with decoded claims (Requirement 3.2)
- Expired token → "expired_token" (Requirement 3.3)
- Invalid signature → "invalid_signature" (Requirement 3.3)
- Wrong issuer → "unrecognized_issuer" (Requirement 3.3)
- Wrong audience → "disallowed_audience" (Requirement 3.3)
"""

import time

import jwt as pyjwt
import pytest

from src.core.jwt_validation import ValidationResult, validate_jwt


# Test constants
SECRET_KEY = "test-secret-key-for-hmac-256"
ISSUER = "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_TestPool"
AUDIENCE = "test-client-id-123"


def _create_valid_token(
    issuer: str = ISSUER,
    audience: str = AUDIENCE,
    subject: str = "user-sub-123",
    exp_offset: int = 3600,
    secret: str = SECRET_KEY,
    algorithm: str = "HS256",
) -> str:
    """Helper to create a valid JWT token for testing."""
    now = int(time.time())
    payload = {
        "iss": issuer,
        "aud": audience,
        "sub": subject,
        "exp": now + exp_offset,
        "iat": now,
        "scope": "openid profile",
    }
    return pyjwt.encode(payload, secret, algorithm=algorithm)


class TestMissingToken:
    """Tests for Requirement 3.4: missing token returns missing_token error."""

    def test_none_token(self):
        result = validate_jwt(None, ISSUER, AUDIENCE, SECRET_KEY)
        assert result.is_valid is False
        assert result.error_reason == "missing_token"
        assert result.claims is None

    def test_empty_string_token(self):
        result = validate_jwt("", ISSUER, AUDIENCE, SECRET_KEY)
        assert result.is_valid is False
        assert result.error_reason == "missing_token"
        assert result.claims is None

    def test_whitespace_only_token(self):
        result = validate_jwt("   ", ISSUER, AUDIENCE, SECRET_KEY)
        assert result.is_valid is False
        assert result.error_reason == "missing_token"
        assert result.claims is None


class TestValidToken:
    """Tests for Requirement 3.2: valid token passes all checks."""

    def test_valid_token_returns_success(self):
        token = _create_valid_token()
        result = validate_jwt(token, ISSUER, AUDIENCE, SECRET_KEY)

        assert result.is_valid is True
        assert result.error_reason is None
        assert result.claims is not None
        assert result.claims["sub"] == "user-sub-123"
        assert result.claims["iss"] == ISSUER
        assert result.claims["aud"] == AUDIENCE

    def test_valid_token_preserves_custom_claims(self):
        now = int(time.time())
        payload = {
            "iss": ISSUER,
            "aud": AUDIENCE,
            "sub": "user-456",
            "exp": now + 3600,
            "iat": now,
            "custom_claim": "custom_value",
        }
        token = pyjwt.encode(payload, SECRET_KEY, algorithm="HS256")
        result = validate_jwt(token, ISSUER, AUDIENCE, SECRET_KEY)

        assert result.is_valid is True
        assert result.claims["custom_claim"] == "custom_value"


class TestExpiredToken:
    """Tests for Requirement 3.3: expired token returns expired_token error."""

    def test_expired_token(self):
        token = _create_valid_token(exp_offset=-3600)  # Expired 1 hour ago
        result = validate_jwt(token, ISSUER, AUDIENCE, SECRET_KEY)

        assert result.is_valid is False
        assert result.error_reason == "expired_token"
        assert result.claims is None


class TestInvalidSignature:
    """Tests for Requirement 3.3: invalid signature returns invalid_signature error."""

    def test_wrong_signing_key(self):
        token = _create_valid_token(secret="correct-key")
        result = validate_jwt(token, ISSUER, AUDIENCE, "wrong-key")

        assert result.is_valid is False
        assert result.error_reason == "invalid_signature"
        assert result.claims is None

    def test_malformed_token(self):
        result = validate_jwt("not.a.valid.jwt", ISSUER, AUDIENCE, SECRET_KEY)

        assert result.is_valid is False
        assert result.error_reason == "invalid_signature"
        assert result.claims is None

    def test_corrupted_token(self):
        token = _create_valid_token()
        # Corrupt the signature portion
        parts = token.split(".")
        parts[2] = "corrupted_signature_data"
        corrupted = ".".join(parts)

        result = validate_jwt(corrupted, ISSUER, AUDIENCE, SECRET_KEY)

        assert result.is_valid is False
        assert result.error_reason == "invalid_signature"
        assert result.claims is None


class TestUnrecognizedIssuer:
    """Tests for Requirement 3.3: wrong issuer returns unrecognized_issuer error."""

    def test_wrong_issuer(self):
        token = _create_valid_token(issuer="https://evil-issuer.example.com")
        result = validate_jwt(token, ISSUER, AUDIENCE, SECRET_KEY)

        assert result.is_valid is False
        assert result.error_reason == "unrecognized_issuer"
        assert result.claims is None


class TestDisallowedAudience:
    """Tests for Requirement 3.3: wrong audience returns disallowed_audience error."""

    def test_wrong_audience(self):
        token = _create_valid_token(audience="wrong-client-id")
        result = validate_jwt(token, ISSUER, AUDIENCE, SECRET_KEY)

        assert result.is_valid is False
        assert result.error_reason == "disallowed_audience"
        assert result.claims is None


class TestValidationResultDataclass:
    """Tests that ValidationResult is properly structured."""

    def test_success_result(self):
        result = ValidationResult(is_valid=True, claims={"sub": "user-1"})
        assert result.is_valid is True
        assert result.error_reason is None
        assert result.claims == {"sub": "user-1"}

    def test_failure_result(self):
        result = ValidationResult(is_valid=False, error_reason="expired_token")
        assert result.is_valid is False
        assert result.error_reason == "expired_token"
        assert result.claims is None
