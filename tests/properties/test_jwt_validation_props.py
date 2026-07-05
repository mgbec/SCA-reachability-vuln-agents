"""Property-based tests for JWT validation correctness.

**Validates: Requirements 3.2, 3.3**

Property 19: JWT Validation Correctness
Tests that valid JWTs pass validation; violation of any property (signature,
expiration, issuer, audience) rejects with matching error reason.
"""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from hypothesis import given, assume
from hypothesis import strategies as st

from src.core.jwt_validation import validate_jwt


# --- Strategies ---

# Random string subjects
subjects = st.text(
    min_size=3, max_size=50,
    alphabet=st.characters(whitelist_categories=("Ll", "Lu", "Nd")),
)

# Random issuer URLs
issuers = st.builds(
    lambda domain, path: f"https://{domain}.example.com/{path}",
    domain=st.text(min_size=3, max_size=15, alphabet=st.characters(whitelist_categories=("Ll",))),
    path=st.text(min_size=2, max_size=10, alphabet=st.characters(whitelist_categories=("Ll", "Nd"))),
)

# Random audience strings
audiences = st.text(
    min_size=3, max_size=40,
    alphabet=st.characters(whitelist_categories=("Ll", "Lu", "Nd")),
)

# Random HS256 signing keys (32-64 bytes)
signing_keys = st.binary(min_size=32, max_size=64).map(lambda b: b.hex())

# Positive expiration offsets (seconds in the future)
future_exp_offsets = st.integers(min_value=120, max_value=7200)

# Negative expiration offsets (seconds in the past)
past_exp_offsets = st.integers(min_value=60, max_value=7200)


def _build_valid_token(subject, issuer, audience, key, exp_offset_seconds):
    """Helper to build a valid JWT token with given claims."""
    now = datetime.now(tz=timezone.utc)
    payload = {
        "sub": subject,
        "iss": issuer,
        "aud": audience,
        "exp": now + timedelta(seconds=exp_offset_seconds),
        "iat": now,
    }
    return jwt.encode(payload, key, algorithm="HS256")


# --- Property Tests ---


@pytest.mark.property
@given(
    subject=subjects,
    issuer=issuers,
    audience=audiences,
    key=signing_keys,
    exp_offset=future_exp_offsets,
)
def test_valid_jwt_passes_validation(subject, issuer, audience, key, exp_offset):
    """For any valid claims (correct issuer, audience, future expiration, correct key),
    validate_jwt returns is_valid=True.

    **Validates: Requirements 3.2, 3.3**
    """
    token = _build_valid_token(subject, issuer, audience, key, exp_offset)

    result = validate_jwt(
        token=token,
        issuer=issuer,
        audience=audience,
        signing_key=key,
        algorithms=["HS256"],
    )

    assert result.is_valid is True
    assert result.error_reason is None
    assert result.claims is not None
    assert result.claims["sub"] == subject
    assert result.claims["iss"] == issuer
    assert result.claims["aud"] == audience


@pytest.mark.property
@given(
    subject=subjects,
    issuer=issuers,
    audience=audiences,
    key=signing_keys,
    past_offset=past_exp_offsets,
)
def test_expired_token_returns_expired_reason(subject, issuer, audience, key, past_offset):
    """For any expired token (exp in past), validate_jwt returns error_reason 'expired_token'.

    **Validates: Requirements 3.2, 3.3**
    """
    now = datetime.now(tz=timezone.utc)
    payload = {
        "sub": subject,
        "iss": issuer,
        "aud": audience,
        "exp": now - timedelta(seconds=past_offset),
        "iat": now - timedelta(seconds=past_offset + 60),
    }
    token = jwt.encode(payload, key, algorithm="HS256")

    result = validate_jwt(
        token=token,
        issuer=issuer,
        audience=audience,
        signing_key=key,
        algorithms=["HS256"],
    )

    assert result.is_valid is False
    assert result.error_reason == "expired_token"
    assert result.claims is None


@pytest.mark.property
@given(
    subject=subjects,
    issuer=issuers,
    audience=audiences,
    correct_key=signing_keys,
    wrong_key=signing_keys,
    exp_offset=future_exp_offsets,
)
def test_wrong_key_returns_invalid_signature(
    subject, issuer, audience, correct_key, wrong_key, exp_offset
):
    """For any token signed with a different key, validate_jwt returns
    error_reason 'invalid_signature'.

    **Validates: Requirements 3.2, 3.3**
    """
    # Ensure keys are actually different
    assume(correct_key != wrong_key)

    token = _build_valid_token(subject, issuer, audience, correct_key, exp_offset)

    result = validate_jwt(
        token=token,
        issuer=issuer,
        audience=audience,
        signing_key=wrong_key,
        algorithms=["HS256"],
    )

    assert result.is_valid is False
    assert result.error_reason == "invalid_signature"
    assert result.claims is None


@pytest.mark.property
@given(
    subject=subjects,
    token_issuer=issuers,
    expected_issuer=issuers,
    audience=audiences,
    key=signing_keys,
    exp_offset=future_exp_offsets,
)
def test_wrong_issuer_returns_unrecognized_issuer(
    subject, token_issuer, expected_issuer, audience, key, exp_offset
):
    """For any token with a mismatched issuer, validate_jwt returns
    error_reason 'unrecognized_issuer'.

    **Validates: Requirements 3.2, 3.3**
    """
    # Ensure issuers are actually different
    assume(token_issuer != expected_issuer)

    token = _build_valid_token(subject, token_issuer, audience, key, exp_offset)

    result = validate_jwt(
        token=token,
        issuer=expected_issuer,
        audience=audience,
        signing_key=key,
        algorithms=["HS256"],
    )

    assert result.is_valid is False
    assert result.error_reason == "unrecognized_issuer"
    assert result.claims is None


@pytest.mark.property
@given(
    subject=subjects,
    issuer=issuers,
    token_audience=audiences,
    expected_audience=audiences,
    key=signing_keys,
    exp_offset=future_exp_offsets,
)
def test_wrong_audience_returns_disallowed_audience(
    subject, issuer, token_audience, expected_audience, key, exp_offset
):
    """For any token with a mismatched audience, validate_jwt returns
    error_reason 'disallowed_audience'.

    **Validates: Requirements 3.2, 3.3**
    """
    # Ensure audiences are actually different
    assume(token_audience != expected_audience)

    token = _build_valid_token(subject, issuer, token_audience, key, exp_offset)

    result = validate_jwt(
        token=token,
        issuer=issuer,
        audience=expected_audience,
        signing_key=key,
        algorithms=["HS256"],
    )

    assert result.is_valid is False
    assert result.error_reason == "disallowed_audience"
    assert result.claims is None
