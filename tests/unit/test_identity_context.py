"""Unit tests for identity context construction and validation.

Tests cover: building identity contexts, HMAC signature verification,
expiration detection, and malformed structure detection.

Requirements: 6.1, 6.2, 6.4, 6.5
"""

from datetime import datetime, timedelta, timezone

import pytest

from src.core.identity_context import (
    ValidationResult,
    build_identity_context,
    validate_identity_context,
)
from src.core.constants import IDENTITY_CONTEXT_VERSION
from src.core.models import (
    DelegationEntry,
    IdentityContext,
    UserIdentity,
    WorkloadIdentity,
)


@pytest.fixture
def valid_user_claims():
    """User claims with expiration set far in the future."""
    return {
        "subject": "user-abc-123",
        "issuer": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_TestPool",
        "audience": "test-client-id",
        "scopes": ["openid", "profile"],
        "issued_at": datetime(2025, 6, 1, 10, 0, 0, tzinfo=timezone.utc),
        "expires_at": datetime(2099, 6, 1, 11, 0, 0, tzinfo=timezone.utc),
    }


@pytest.fixture
def source_agent():
    return WorkloadIdentity(
        arn="arn:aws:bedrock-agentcore:us-east-1:123456789012:workload-identity/directory/default/workload-identity/orchestrator-agent",
        name="orchestrator-agent",
    )


@pytest.fixture
def hmac_key():
    return b"test-hmac-secret-key-256bits-long!!"


class TestBuildIdentityContext:
    """Tests for build_identity_context function."""

    @pytest.mark.unit
    def test_build_sets_version(self, valid_user_claims, source_agent, hmac_key):
        ctx = build_identity_context(valid_user_claims, source_agent, hmac_key)
        assert ctx.version == IDENTITY_CONTEXT_VERSION

    @pytest.mark.unit
    def test_build_generates_correlation_id(self, valid_user_claims, source_agent, hmac_key):
        ctx = build_identity_context(valid_user_claims, source_agent, hmac_key)
        assert ctx.correlation_id
        # UUID v4 format check
        parts = ctx.correlation_id.split("-")
        assert len(parts) == 5

    @pytest.mark.unit
    def test_build_sets_source_agent(self, valid_user_claims, source_agent, hmac_key):
        ctx = build_identity_context(valid_user_claims, source_agent, hmac_key)
        assert ctx.source_agent == source_agent

    @pytest.mark.unit
    def test_build_propagates_user_identity(self, valid_user_claims, source_agent, hmac_key):
        ctx = build_identity_context(valid_user_claims, source_agent, hmac_key)
        assert ctx.user_identity.subject == valid_user_claims["subject"]
        assert ctx.user_identity.issuer == valid_user_claims["issuer"]
        assert ctx.user_identity.audience == valid_user_claims["audience"]
        assert ctx.user_identity.scopes == valid_user_claims["scopes"]
        assert ctx.user_identity.issued_at == valid_user_claims["issued_at"]
        assert ctx.user_identity.expires_at == valid_user_claims["expires_at"]

    @pytest.mark.unit
    def test_build_creates_delegation_chain_entry(self, valid_user_claims, source_agent, hmac_key):
        ctx = build_identity_context(valid_user_claims, source_agent, hmac_key)
        assert len(ctx.delegation_chain) == 1
        assert ctx.delegation_chain[0].agent_arn == source_agent.arn

    @pytest.mark.unit
    def test_build_produces_non_empty_signature(self, valid_user_claims, source_agent, hmac_key):
        ctx = build_identity_context(valid_user_claims, source_agent, hmac_key)
        assert ctx.signature
        assert len(ctx.signature) > 0

    @pytest.mark.unit
    def test_build_different_keys_produce_different_signatures(
        self, valid_user_claims, source_agent
    ):
        ctx1 = build_identity_context(valid_user_claims, source_agent, b"key-one-aaaaaaaaaaaaaaaa")
        ctx2 = build_identity_context(valid_user_claims, source_agent, b"key-two-bbbbbbbbbbbbbbbb")
        # Signatures differ because HMAC keys differ (correlation_ids also differ, but
        # even if they were the same, different keys produce different sigs)
        assert ctx1.signature != ctx2.signature


class TestValidateIdentityContext:
    """Tests for validate_identity_context function."""

    @pytest.mark.unit
    def test_valid_context_passes(self, valid_user_claims, source_agent, hmac_key):
        ctx = build_identity_context(valid_user_claims, source_agent, hmac_key)
        result = validate_identity_context(ctx, hmac_key)
        assert result.is_valid is True
        assert result.tamper_type is None
        assert result.error_message is None

    @pytest.mark.unit
    def test_tampered_signature_detected(self, valid_user_claims, source_agent, hmac_key):
        ctx = build_identity_context(valid_user_claims, source_agent, hmac_key)
        ctx.signature = "dGFtcGVyZWQ="  # base64("tampered")
        result = validate_identity_context(ctx, hmac_key)
        assert result.is_valid is False
        assert result.tamper_type == "signature_mismatch"

    @pytest.mark.unit
    def test_wrong_key_detected_as_signature_mismatch(
        self, valid_user_claims, source_agent, hmac_key
    ):
        ctx = build_identity_context(valid_user_claims, source_agent, hmac_key)
        wrong_key = b"wrong-key-should-not-validate!!"
        result = validate_identity_context(ctx, wrong_key)
        assert result.is_valid is False
        assert result.tamper_type == "signature_mismatch"

    @pytest.mark.unit
    def test_expired_identity_detected(self, source_agent, hmac_key):
        expired_claims = {
            "subject": "user-expired",
            "issuer": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_Pool",
            "audience": "client-id",
            "scopes": ["openid"],
            "issued_at": datetime(2020, 1, 1, tzinfo=timezone.utc),
            "expires_at": datetime(2020, 1, 1, 1, 0, 0, tzinfo=timezone.utc),
        }
        ctx = build_identity_context(expired_claims, source_agent, hmac_key)
        result = validate_identity_context(ctx, hmac_key)
        assert result.is_valid is False
        assert result.tamper_type == "expired_identity"

    @pytest.mark.unit
    def test_malformed_structure_missing_version(self, valid_user_claims, source_agent, hmac_key):
        ctx = build_identity_context(valid_user_claims, source_agent, hmac_key)
        ctx.version = ""
        result = validate_identity_context(ctx, hmac_key)
        assert result.is_valid is False
        assert result.tamper_type == "malformed_structure"
        assert "version" in result.error_message

    @pytest.mark.unit
    def test_malformed_structure_missing_correlation_id(
        self, valid_user_claims, source_agent, hmac_key
    ):
        ctx = build_identity_context(valid_user_claims, source_agent, hmac_key)
        ctx.correlation_id = ""
        result = validate_identity_context(ctx, hmac_key)
        assert result.is_valid is False
        assert result.tamper_type == "malformed_structure"

    @pytest.mark.unit
    def test_malformed_structure_missing_signature(self, valid_user_claims, source_agent, hmac_key):
        ctx = build_identity_context(valid_user_claims, source_agent, hmac_key)
        ctx.signature = ""
        result = validate_identity_context(ctx, hmac_key)
        assert result.is_valid is False
        assert result.tamper_type == "malformed_structure"

    @pytest.mark.unit
    def test_tampered_subject_detected(self, valid_user_claims, source_agent, hmac_key):
        ctx = build_identity_context(valid_user_claims, source_agent, hmac_key)
        # Tamper with user identity subject — since UserIdentity is frozen,
        # we need to reconstruct the context with a modified user identity
        tampered_identity = UserIdentity(
            subject="attacker-injected-subject",
            issuer=ctx.user_identity.issuer,
            audience=ctx.user_identity.audience,
            scopes=ctx.user_identity.scopes,
            issued_at=ctx.user_identity.issued_at,
            expires_at=ctx.user_identity.expires_at,
            token_reference=ctx.user_identity.token_reference,
        )
        ctx.user_identity = tampered_identity
        result = validate_identity_context(ctx, hmac_key)
        assert result.is_valid is False
        assert result.tamper_type == "signature_mismatch"

    @pytest.mark.unit
    def test_tampered_source_agent_detected(self, valid_user_claims, source_agent, hmac_key):
        ctx = build_identity_context(valid_user_claims, source_agent, hmac_key)
        ctx.source_agent = WorkloadIdentity(
            arn="arn:aws:bedrock-agentcore:us-east-1:999999999999:workload-identity/directory/default/workload-identity/evil-agent",
            name="evil-agent",
        )
        result = validate_identity_context(ctx, hmac_key)
        assert result.is_valid is False
        assert result.tamper_type == "signature_mismatch"
