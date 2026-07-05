"""Property-based tests for Identity Context round-trip integrity.

**Validates: Requirements 6.1, 6.2**

Property 1: Identity Context Round-Trip
For any valid user claims and agent identity, build_identity_context followed
by validate_identity_context returns is_valid=True and preserves all user
identity fields unchanged.
"""

from datetime import datetime, timedelta, timezone

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from src.core.identity_context import build_identity_context, validate_identity_context
from src.core.models import WorkloadIdentity
from tests.properties import agent_arns, hmac_keys, user_claims


def _future_user_claims():
    """Generate user claims with expires_at guaranteed to be in the future.

    The standard user_claims() strategy generates timestamps between 2024-2026
    which may already be expired. This wrapper ensures expires_at is always
    at least 1 hour in the future from the current time so that validation
    does not reject the context due to expiration.
    """
    now = datetime.now(timezone.utc)
    future_min = now + timedelta(hours=1)
    future_max = now + timedelta(days=365)

    return st.fixed_dictionaries({
        "subject": st.uuids().map(str),
        "issuer": st.builds(
            lambda region, pool_id: f"https://cognito-idp.{region}.amazonaws.com/{pool_id}",
            region=st.sampled_from(["us-east-1", "us-west-2", "eu-west-1"]),
            pool_id=st.from_regex(r"[a-z]{2}-[a-z]+-[0-9]_[A-Za-z0-9]{9}", fullmatch=True),
        ),
        "audience": st.text(
            min_size=5, max_size=40,
            alphabet=st.characters(whitelist_categories=("Ll", "Lu", "Nd")),
        ),
        "scopes": st.lists(
            st.sampled_from(["openid", "profile", "security_events", "repo"]),
            min_size=1, max_size=4,
        ),
        "issued_at": st.just(now - timedelta(minutes=5)),
        "expires_at": st.datetimes(
            min_value=future_min.replace(tzinfo=None),
            max_value=future_max.replace(tzinfo=None),
        ).map(lambda dt: dt.replace(tzinfo=timezone.utc)),
    })


def _workload_identities():
    """Generate WorkloadIdentity instances from agent ARNs."""
    return st.builds(
        lambda arn, name: WorkloadIdentity(arn=arn, name=name),
        arn=agent_arns(),
        name=st.sampled_from(["orchestrator-agent", "scanner-agent", "analysis-agent"]),
    )


@pytest.mark.property
class TestIdentityContextRoundTrip:
    """Property 1: Identity Context Round-Trip.

    For any valid user_claims dict, agent WorkloadIdentity, and hmac_key,
    build_identity_context followed by validate_identity_context should
    return is_valid=True and preserve all user identity fields.

    **Validates: Requirements 6.1, 6.2**
    """

    @given(
        claims=_future_user_claims(),
        agent=_workload_identities(),
        key=hmac_keys,
    )
    @settings(max_examples=50)
    def test_build_then_validate_is_valid(self, claims, agent, key):
        """Round-trip: build → validate always succeeds for valid inputs."""
        context = build_identity_context(claims, agent, key)
        result = validate_identity_context(context, key)

        assert result.is_valid is True, (
            f"Expected valid context but got tamper_type={result.tamper_type}, "
            f"error={result.error_message}"
        )

    @given(
        claims=_future_user_claims(),
        agent=_workload_identities(),
        key=hmac_keys,
    )
    @settings(max_examples=50)
    def test_build_preserves_user_identity_fields(self, claims, agent, key):
        """Round-trip preserves all original user identity fields unchanged."""
        context = build_identity_context(claims, agent, key)

        # Verify all user identity fields are preserved from input claims
        assert context.user_identity.subject == claims["subject"]
        assert context.user_identity.issuer == claims["issuer"]
        assert context.user_identity.audience == claims["audience"]
        assert context.user_identity.scopes == claims["scopes"]
        assert context.user_identity.issued_at == claims["issued_at"]
        assert context.user_identity.expires_at == claims["expires_at"]

    @given(
        claims=_future_user_claims(),
        agent=_workload_identities(),
        key=hmac_keys,
    )
    @settings(max_examples=50)
    def test_build_preserves_source_agent(self, claims, agent, key):
        """Round-trip preserves the source agent identity unchanged."""
        context = build_identity_context(claims, agent, key)

        assert context.source_agent.arn == agent.arn
        assert context.source_agent.name == agent.name



# --- Property 2: Identity Context Tamper Detection ---

import dataclasses

from src.core.models import IdentityContext, UserIdentity

# Fields that can be tampered with for Property 2
TAMPER_FIELDS = [
    "user_identity.subject",
    "user_identity.issuer",
    "source_agent.arn",
    "signature",
]


def _tamper_identity_context(context: IdentityContext, field_to_tamper: str) -> IdentityContext:
    """Create a tampered copy of an IdentityContext by modifying the specified field.

    Since UserIdentity and WorkloadIdentity are frozen dataclasses, we reconstruct
    them with modified values to simulate post-construction tampering.
    """
    if field_to_tamper == "user_identity.subject":
        tampered_user = UserIdentity(
            subject=context.user_identity.subject + "-tampered",
            issuer=context.user_identity.issuer,
            audience=context.user_identity.audience,
            scopes=context.user_identity.scopes,
            issued_at=context.user_identity.issued_at,
            expires_at=context.user_identity.expires_at,
            token_reference=context.user_identity.token_reference,
        )
        return dataclasses.replace(context, user_identity=tampered_user)

    elif field_to_tamper == "user_identity.issuer":
        tampered_user = UserIdentity(
            subject=context.user_identity.subject,
            issuer=context.user_identity.issuer + "/tampered",
            audience=context.user_identity.audience,
            scopes=context.user_identity.scopes,
            issued_at=context.user_identity.issued_at,
            expires_at=context.user_identity.expires_at,
            token_reference=context.user_identity.token_reference,
        )
        return dataclasses.replace(context, user_identity=tampered_user)

    elif field_to_tamper == "source_agent.arn":
        tampered_agent = WorkloadIdentity(
            arn=context.source_agent.arn + "-tampered",
            name=context.source_agent.name,
        )
        return dataclasses.replace(context, source_agent=tampered_agent)

    elif field_to_tamper == "signature":
        return dataclasses.replace(context, signature=context.signature + "AAAA")

    else:
        raise ValueError(f"Unknown tamper field: {field_to_tamper}")


@pytest.mark.property
class TestIdentityContextTamperDetection:
    """Property 2: Identity Context Tamper Detection.

    Test that modifying any field after construction causes validation to reject
    with tamper_type "signature_mismatch".

    **Validates: Requirements 6.2, 6.4, 6.5**
    """

    @given(
        claims=_future_user_claims(),
        agent=_workload_identities(),
        key=hmac_keys,
        field_to_tamper=st.sampled_from(TAMPER_FIELDS),
    )
    @settings(max_examples=50)
    def test_tampered_field_causes_signature_mismatch(self, claims, agent, key, field_to_tamper):
        """Modifying any signed field after build causes validation to reject
        with tamper_type 'signature_mismatch'."""
        # Build a valid identity context
        context = build_identity_context(claims, agent, key)

        # Tamper with the specified field
        tampered_context = _tamper_identity_context(context, field_to_tamper)

        # Validate the tampered context - it should be rejected
        result = validate_identity_context(tampered_context, key)

        assert not result.is_valid, (
            f"Tampered field '{field_to_tamper}' was not detected. "
            f"Context should be rejected after modification."
        )
        assert result.tamper_type == "signature_mismatch", (
            f"Expected tamper_type 'signature_mismatch' for field '{field_to_tamper}', "
            f"got '{result.tamper_type}'"
        )
