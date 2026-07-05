"""JWT validation logic for inbound agent authentication.

Implements JWT bearer token validation for the JWT_Authorizer, verifying
token signature, expiration, issuer, and audience/client claims. Returns
specific error reasons on failure to enable meaningful HTTP 401 responses.

Requirements: 3.2, 3.3, 3.4
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import jwt
from jwt.exceptions import (
    DecodeError,
    ExpiredSignatureError,
    InvalidAudienceError,
    InvalidIssuerError,
    InvalidSignatureError,
)


# Default algorithms supported for JWT verification
DEFAULT_ALGORITHMS: list[str] = ["HS256", "RS256", "ES256"]


@dataclass
class ValidationResult:
    """Result of JWT token validation.

    Attributes:
        is_valid: Whether the JWT passed all validation checks.
        error_reason: Specific reason for validation failure, if any.
            One of: "missing_token", "expired_token", "invalid_signature",
            "unrecognized_issuer", "disallowed_audience"
        claims: Decoded JWT payload claims on success, None on failure.
    """

    is_valid: bool
    error_reason: Optional[str] = None
    claims: Optional[dict] = None


def validate_jwt(
    token: str,
    issuer: str,
    audience: str,
    signing_key,
    algorithms: list[str] | None = None,
) -> ValidationResult:
    """Validate a JWT bearer token for inbound authentication.

    Verifies the token's signature, expiration, issuer, and audience claims.
    Returns a ValidationResult with decoded claims on success, or a specific
    error reason on failure.

    Args:
        token: The JWT bearer token string to validate.
        issuer: Expected token issuer (iss claim).
        audience: Expected token audience (aud claim).
        signing_key: Key used to verify the token signature. Can be a string
            (HMAC secret) or an RSA/EC public key object.
        algorithms: List of acceptable signing algorithms. Defaults to
            ["HS256", "RS256", "ES256"].

    Returns:
        ValidationResult with:
            - is_valid=True and decoded claims on success
            - is_valid=False with specific error_reason on failure
    """
    # Check for missing/empty token
    if not token or not token.strip():
        return ValidationResult(
            is_valid=False,
            error_reason="missing_token",
        )

    if algorithms is None:
        algorithms = DEFAULT_ALGORITHMS

    try:
        decoded_claims = jwt.decode(
            token,
            signing_key,
            algorithms=algorithms,
            issuer=issuer,
            audience=audience,
            options={
                "require": ["exp", "iss", "aud"],
                "verify_exp": True,
                "verify_iss": True,
                "verify_aud": True,
                "verify_signature": True,
            },
        )
        return ValidationResult(
            is_valid=True,
            claims=decoded_claims,
        )

    except ExpiredSignatureError:
        return ValidationResult(
            is_valid=False,
            error_reason="expired_token",
        )

    except InvalidSignatureError:
        return ValidationResult(
            is_valid=False,
            error_reason="invalid_signature",
        )

    except InvalidIssuerError:
        return ValidationResult(
            is_valid=False,
            error_reason="unrecognized_issuer",
        )

    except InvalidAudienceError:
        return ValidationResult(
            is_valid=False,
            error_reason="disallowed_audience",
        )

    except DecodeError:
        # Malformed token that can't be decoded at all — treat as invalid signature
        return ValidationResult(
            is_valid=False,
            error_reason="invalid_signature",
        )

    except Exception:
        # Catch-all for unexpected JWT errors — treat as invalid signature
        return ValidationResult(
            is_valid=False,
            error_reason="invalid_signature",
        )
