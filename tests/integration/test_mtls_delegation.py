"""Integration tests for mTLS and delegation between agents.

Tests that:
- Connections are rejected without valid certificates and accepted with valid ones
- Identity propagation works correctly across agent boundaries
- Audit trail records delegation events

Requirements: 6.3, 14.2, 14.3, 14.4
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.agents.analysis import AnalysisAgent, AnalysisConfig, AnalysisRequest
from src.agents.scanner import ScannerAgent, ScannerConfig, ScanRequest, ScanResult
from src.core.identity_context import build_identity_context
from src.core.models import (
    DelegationEntry,
    IdentityContext,
    UserIdentity,
    WorkloadIdentity,
)
from src.core.structured_logging import AuthEvent, emit_auth_log


# ---------------------------------------------------------------------------
# Shared test fixtures
# ---------------------------------------------------------------------------

HMAC_KEY = b"test-integration-hmac-key-for-signing-256bit-key!"

ORCHESTRATOR_ARN = (
    "arn:aws:bedrock-agentcore:us-east-1:123456789012:"
    "workload-identity/directory/default/workload-identity/orchestrator-agent"
)
SCANNER_ARN = (
    "arn:aws:bedrock-agentcore:us-east-1:123456789012:"
    "workload-identity/directory/default/workload-identity/scanner-agent"
)
ANALYSIS_ARN = (
    "arn:aws:bedrock-agentcore:us-east-1:123456789012:"
    "workload-identity/directory/default/workload-identity/analysis-agent"
)


@pytest.fixture
def orchestrator_workload():
    """Orchestrator agent workload identity."""
    return WorkloadIdentity(arn=ORCHESTRATOR_ARN, name="orchestrator-agent")


@pytest.fixture
def valid_user_claims():
    """Valid user claims for identity context construction."""
    now = datetime.now(timezone.utc)
    return {
        "subject": "user-sub-12345",
        "issuer": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_TestPool",
        "audience": "test-client-id",
        "scopes": ["openid", "profile", "security_events"],
        "issued_at": now - timedelta(minutes=5),
        "expires_at": now + timedelta(hours=1),
        "token_reference": "jti-test-ref-001",
    }


@pytest.fixture
def valid_identity_context(orchestrator_workload, valid_user_claims):
    """A properly signed identity context from the orchestrator."""
    return build_identity_context(
        user_claims=valid_user_claims,
        source_agent=orchestrator_workload,
        hmac_key=HMAC_KEY,
    )


@pytest.fixture
def valid_cert_info():
    """Valid mTLS certificate info from the orchestrator agent."""
    return {
        "subject_cn": "orchestrator-agent",
        "issuer_cn": "AgentCore Internal CA",
        "not_after": (datetime.now(timezone.utc) + timedelta(days=365)).isoformat(),
        "is_revoked": False,
        "ca_verified": True,
    }


@pytest.fixture
def expired_cert_info():
    """Expired mTLS certificate info."""
    return {
        "subject_cn": "orchestrator-agent",
        "issuer_cn": "AgentCore Internal CA",
        "not_after": (datetime.now(timezone.utc) - timedelta(days=1)).isoformat(),
        "is_revoked": False,
        "ca_verified": True,
    }


@pytest.fixture
def revoked_cert_info():
    """Revoked mTLS certificate info."""
    return {
        "subject_cn": "orchestrator-agent",
        "issuer_cn": "AgentCore Internal CA",
        "not_after": (datetime.now(timezone.utc) + timedelta(days=365)).isoformat(),
        "is_revoked": True,
        "ca_verified": True,
    }


@pytest.fixture
def untrusted_ca_cert_info():
    """Certificate issued by an untrusted CA."""
    return {
        "subject_cn": "rogue-agent",
        "issuer_cn": "Rogue CA",
        "not_after": (datetime.now(timezone.utc) + timedelta(days=365)).isoformat(),
        "is_revoked": False,
        "ca_verified": False,
    }


@pytest.fixture
def scanner_agent():
    """ScannerAgent configured with the shared HMAC key."""
    config = ScannerConfig(
        ca_cert_path="/opt/certs/ca.pem",
        hmac_key=HMAC_KEY,
        github_oauth_client_id="test-client-id",
        github_oauth_client_secret="test-client-secret",
        github_oauth_callback_url="https://scanner/callback",
        identity_directory_endpoint="https://identity.local",
    )
    return ScannerAgent(config)


@pytest.fixture
def analysis_agent():
    """AnalysisAgent configured with the shared HMAC key."""
    config = AnalysisConfig(
        ca_cert_path="/opt/certs/ca.pem",
        hmac_key=HMAC_KEY,
        m2m_client_id="analysis-client-id",
        m2m_client_secret="analysis-client-secret",
        m2m_token_endpoint="https://auth.local/oauth2/token",
        vuln_db_endpoints={
            "nvd": "https://services.nvd.nist.gov/rest/json/cves/2.0",
        },
    )
    return AnalysisAgent(config)


# ---------------------------------------------------------------------------
# Test class: mTLS certificate validation
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestMTLSCertificateValidation:
    """Tests that connections are rejected without valid cert and accepted with valid cert.

    Validates Requirements 14.2, 14.3:
    - Agent runtimes require valid X.509 client certificates
    - Invalid/missing/expired/revoked certs are rejected
    """

    def test_scanner_rejects_no_certificate(
        self, scanner_agent, valid_identity_context
    ):
        """Connection is rejected when no client certificate is presented."""
        result = scanner_agent._validate_caller_mtls({})
        assert result is False

    def test_scanner_rejects_empty_cert_info(
        self, scanner_agent, valid_identity_context
    ):
        """Connection is rejected when cert_info dict is empty."""
        result = scanner_agent._validate_caller_mtls({})
        assert result is False

    def test_scanner_rejects_untrusted_ca(
        self, scanner_agent, untrusted_ca_cert_info
    ):
        """Connection is rejected when certificate is from an untrusted CA."""
        result = scanner_agent._validate_caller_mtls(untrusted_ca_cert_info)
        assert result is False

    def test_scanner_rejects_expired_certificate(
        self, scanner_agent, expired_cert_info
    ):
        """Connection is rejected when client certificate has expired."""
        result = scanner_agent._validate_caller_mtls(expired_cert_info)
        assert result is False

    def test_scanner_rejects_revoked_certificate(
        self, scanner_agent, revoked_cert_info
    ):
        """Connection is rejected when client certificate is revoked."""
        result = scanner_agent._validate_caller_mtls(revoked_cert_info)
        assert result is False

    def test_scanner_accepts_valid_certificate(
        self, scanner_agent, valid_cert_info
    ):
        """Connection is accepted when client certificate is valid."""
        result = scanner_agent._validate_caller_mtls(valid_cert_info)
        assert result is True

    def test_analysis_rejects_no_certificate(self, analysis_agent):
        """Analysis agent rejects connection with no certificate."""
        result = analysis_agent._validate_mtls_certificate({})
        assert result.is_valid is False
        assert result.tamper_type == "invalid_certificate"

    def test_analysis_rejects_expired_certificate(
        self, analysis_agent, expired_cert_info
    ):
        """Analysis agent rejects expired certificates."""
        # AnalysisAgent uses 'issuer' key instead of 'issuer_cn'
        cert = {
            "issuer": expired_cert_info["issuer_cn"],
            "subject": expired_cert_info["subject_cn"],
            "not_after": expired_cert_info["not_after"],
        }
        result = analysis_agent._validate_mtls_certificate(cert)
        assert result.is_valid is False
        assert result.tamper_type == "expired_certificate"

    def test_analysis_rejects_missing_issuer(self, analysis_agent):
        """Analysis agent rejects certificate with missing issuer."""
        cert = {
            "subject": "orchestrator-agent",
            "not_after": (
                datetime.now(timezone.utc) + timedelta(days=365)
            ).isoformat(),
        }
        result = analysis_agent._validate_mtls_certificate(cert)
        assert result.is_valid is False
        assert result.tamper_type == "invalid_certificate"

    def test_analysis_accepts_valid_certificate(self, analysis_agent):
        """Analysis agent accepts a valid certificate."""
        cert = {
            "issuer": "AgentCore Internal CA",
            "subject": "orchestrator-agent",
            "not_after": (
                datetime.now(timezone.utc) + timedelta(days=365)
            ).isoformat(),
        }
        result = analysis_agent._validate_mtls_certificate(cert)
        assert result.is_valid is True


# ---------------------------------------------------------------------------
# Test class: Identity propagation across agent boundaries
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestIdentityPropagation:
    """Tests that identity is correctly propagated and validated across agents.

    Validates Requirements 6.3, 14.2:
    - Identity context is verified at each agent boundary
    - Tampered contexts are rejected with proper error types
    - Valid contexts pass through successfully
    """

    def test_scanner_validates_identity_context_successfully(
        self, scanner_agent, valid_identity_context
    ):
        """Scanner validates a properly signed identity context."""
        result = scanner_agent._validate_identity_context(valid_identity_context)
        assert result.is_valid is True

    def test_scanner_rejects_tampered_identity_context(
        self, scanner_agent, valid_identity_context
    ):
        """Scanner rejects an identity context with a tampered signature."""
        # Tamper with the signature
        tampered = IdentityContext(
            version=valid_identity_context.version,
            correlation_id=valid_identity_context.correlation_id,
            source_agent=valid_identity_context.source_agent,
            user_identity=valid_identity_context.user_identity,
            delegation_chain=valid_identity_context.delegation_chain,
            signature="tampered-signature-value",
        )
        result = scanner_agent._validate_identity_context(tampered)
        assert result.is_valid is False
        assert result.tamper_type == "signature_mismatch"

    def test_scanner_rejects_expired_user_identity(
        self, scanner_agent, orchestrator_workload
    ):
        """Scanner rejects identity context with expired user identity."""
        now = datetime.now(timezone.utc)
        expired_claims = {
            "subject": "user-sub-expired",
            "issuer": "https://cognito-idp.us-east-1.amazonaws.com/pool",
            "audience": "client-id",
            "scopes": ["openid"],
            "issued_at": now - timedelta(hours=2),
            "expires_at": now - timedelta(minutes=5),  # expired
            "token_reference": "jti-expired",
        }
        expired_context = build_identity_context(
            user_claims=expired_claims,
            source_agent=orchestrator_workload,
            hmac_key=HMAC_KEY,
        )
        result = scanner_agent._validate_identity_context(expired_context)
        assert result.is_valid is False
        assert result.tamper_type == "expired_identity"

    def test_analysis_validates_full_caller_identity(
        self, analysis_agent, valid_identity_context
    ):
        """Analysis agent validates both mTLS cert and identity context."""
        valid_cert = {
            "issuer": "AgentCore Internal CA",
            "subject": "orchestrator-agent",
            "not_after": (
                datetime.now(timezone.utc) + timedelta(days=365)
            ).isoformat(),
        }
        result = analysis_agent._validate_caller(valid_cert, valid_identity_context)
        assert result.is_valid is True

    def test_analysis_rejects_invalid_cert_with_valid_identity(
        self, analysis_agent, valid_identity_context
    ):
        """Analysis rejects request when mTLS cert is invalid, even if identity is valid."""
        result = analysis_agent._validate_caller({}, valid_identity_context)
        assert result.is_valid is False
        assert result.tamper_type == "invalid_certificate"

    def test_analysis_rejects_valid_cert_with_tampered_identity(
        self, analysis_agent, valid_identity_context
    ):
        """Analysis rejects request when identity context is tampered."""
        valid_cert = {
            "issuer": "AgentCore Internal CA",
            "subject": "orchestrator-agent",
            "not_after": (
                datetime.now(timezone.utc) + timedelta(days=365)
            ).isoformat(),
        }
        tampered = IdentityContext(
            version=valid_identity_context.version,
            correlation_id=valid_identity_context.correlation_id,
            source_agent=valid_identity_context.source_agent,
            user_identity=valid_identity_context.user_identity,
            delegation_chain=valid_identity_context.delegation_chain,
            signature="definitely-not-valid",
        )
        result = analysis_agent._validate_caller(valid_cert, tampered)
        assert result.is_valid is False
        assert result.tamper_type == "signature_mismatch"

    def test_analysis_rejects_invalid_workload_identity_arn(
        self, analysis_agent
    ):
        """Analysis rejects context with an invalid source agent ARN format."""
        now = datetime.now(timezone.utc)
        bad_workload = WorkloadIdentity(
            arn="invalid-arn-format", name="rogue-agent"
        )
        user_identity = UserIdentity(
            subject="user-sub",
            issuer="https://issuer.local",
            audience="aud",
            scopes=["openid"],
            issued_at=now - timedelta(minutes=1),
            expires_at=now + timedelta(hours=1),
            token_reference="jti",
        )
        context = IdentityContext(
            version="1.0",
            correlation_id=str(uuid.uuid4()),
            source_agent=bad_workload,
            user_identity=user_identity,
            delegation_chain=[
                DelegationEntry(agent_arn=bad_workload.arn, delegated_at=now)
            ],
            signature="some-sig",
        )
        valid_cert = {
            "issuer": "AgentCore Internal CA",
            "subject": "orchestrator-agent",
            "not_after": (now + timedelta(days=365)).isoformat(),
        }
        result = analysis_agent._validate_caller(valid_cert, context)
        assert result.is_valid is False
        assert result.tamper_type == "invalid_workload_identity"

    def test_identity_preserves_user_claims_across_boundary(
        self, scanner_agent, valid_identity_context, valid_user_claims
    ):
        """User identity claims are preserved intact after validation."""
        result = scanner_agent._validate_identity_context(valid_identity_context)
        assert result.is_valid is True
        # Verify the user identity claims survive propagation
        ctx = valid_identity_context
        assert ctx.user_identity.subject == valid_user_claims["subject"]
        assert ctx.user_identity.issuer == valid_user_claims["issuer"]
        assert ctx.user_identity.audience == valid_user_claims["audience"]
        assert ctx.user_identity.scopes == valid_user_claims["scopes"]

    def test_identity_context_delegation_chain_records_source(
        self, valid_identity_context
    ):
        """Delegation chain records the source agent that initiated propagation."""
        chain = valid_identity_context.delegation_chain
        assert len(chain) >= 1
        assert chain[0].agent_arn == ORCHESTRATOR_ARN


# ---------------------------------------------------------------------------
# Test class: Scanner Agent end-to-end invoke with auth layers
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.asyncio
class TestScannerAgentInvokeAuth:
    """Integration tests for the Scanner Agent invoke endpoint auth flow.

    Tests the full authentication stack: mTLS -> workload identity -> user identity.
    Validates Requirements 14.2, 14.3, 14.4.
    """

    async def test_invoke_rejects_request_without_cert(
        self, scanner_agent, valid_identity_context
    ):
        """Scanner invoke rejects request when no mTLS cert is presented."""
        request = ScanRequest(
            repository="owner/repo",
            commit_sha="abc123",
            identity_context=valid_identity_context,
            caller_cert_info={},  # No cert
        )
        result = await scanner_agent.invoke(request)
        assert result.success is False
        assert result.error_type == "mtls_validation_failed"

    async def test_invoke_rejects_request_with_untrusted_cert(
        self, scanner_agent, valid_identity_context, untrusted_ca_cert_info
    ):
        """Scanner invoke rejects request from untrusted CA."""
        request = ScanRequest(
            repository="owner/repo",
            commit_sha="abc123",
            identity_context=valid_identity_context,
            caller_cert_info=untrusted_ca_cert_info,
        )
        result = await scanner_agent.invoke(request)
        assert result.success is False
        assert result.error_type == "mtls_validation_failed"

    async def test_invoke_rejects_tampered_identity(
        self, scanner_agent, valid_cert_info, valid_identity_context
    ):
        """Scanner invoke rejects request with tampered identity context."""
        tampered = IdentityContext(
            version=valid_identity_context.version,
            correlation_id=valid_identity_context.correlation_id,
            source_agent=valid_identity_context.source_agent,
            user_identity=valid_identity_context.user_identity,
            delegation_chain=valid_identity_context.delegation_chain,
            signature="forged-signature",
        )
        request = ScanRequest(
            repository="owner/repo",
            commit_sha="abc123",
            identity_context=tampered,
            caller_cert_info=valid_cert_info,
        )
        result = await scanner_agent.invoke(request)
        assert result.success is False
        assert "identity" in result.error_type


# ---------------------------------------------------------------------------
# Test class: Audit trail records delegation events
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestAuditTrailDelegation:
    """Tests that delegation events are properly recorded in the audit trail.

    Validates Requirements 6.3, 14.4:
    - Identity propagation is logged with source/target/user/timestamp
    - mTLS validation events are logged
    """

    def test_audit_event_records_identity_propagation(
        self, valid_identity_context
    ):
        """An IDENTITY_PROPAGATION audit event captures all required fields."""
        now = datetime.now(timezone.utc)
        event = AuthEvent(
            correlation_id=valid_identity_context.correlation_id,
            agent_identity=SCANNER_ARN,
            event_type="IDENTITY_PROPAGATION",
            timestamp=now,
            trace_id="trace-" + str(uuid.uuid4()),
            span_id="span-" + str(uuid.uuid4())[:16],
            outcome="success",
            details={
                "source_agent": ORCHESTRATOR_ARN,
                "target_agent": SCANNER_ARN,
                "user_identity": valid_identity_context.user_identity.subject,
                "delegated_scopes": valid_identity_context.user_identity.scopes,
            },
        )
        # Verify all required fields are populated
        assert event.correlation_id
        assert event.agent_identity == SCANNER_ARN
        assert event.event_type == "IDENTITY_PROPAGATION"
        assert event.timestamp == now
        assert event.trace_id
        assert event.span_id
        assert event.outcome == "success"
        assert event.details["source_agent"] == ORCHESTRATOR_ARN
        assert event.details["target_agent"] == SCANNER_ARN
        assert event.details["user_identity"] == "user-sub-12345"

    def test_audit_event_records_mtls_validation_success(self):
        """An MTLS_VALIDATION audit event captures successful cert validation."""
        now = datetime.now(timezone.utc)
        event = AuthEvent(
            correlation_id=str(uuid.uuid4()),
            agent_identity=SCANNER_ARN,
            event_type="MTLS_VALIDATION",
            timestamp=now,
            trace_id="trace-" + str(uuid.uuid4()),
            span_id="span-" + str(uuid.uuid4())[:16],
            outcome="success",
            details={
                "certificate_subject": "orchestrator-agent",
                "certificate_expiry": (
                    now + timedelta(days=365)
                ).isoformat(),
            },
        )
        assert event.event_type == "MTLS_VALIDATION"
        assert event.outcome == "success"
        assert event.details["certificate_subject"] == "orchestrator-agent"

    def test_audit_event_records_mtls_validation_failure(self):
        """An MTLS_VALIDATION audit event captures rejected cert validation."""
        now = datetime.now(timezone.utc)
        event = AuthEvent(
            correlation_id=str(uuid.uuid4()),
            agent_identity=SCANNER_ARN,
            event_type="MTLS_VALIDATION",
            timestamp=now,
            trace_id="trace-" + str(uuid.uuid4()),
            span_id="span-" + str(uuid.uuid4())[:16],
            outcome="failure",
            details={
                "certificate_subject": "rogue-agent",
                "certificate_expiry": (
                    now - timedelta(days=1)
                ).isoformat(),
                "rejection_reason": "certificate_expired",
            },
        )
        assert event.event_type == "MTLS_VALIDATION"
        assert event.outcome == "failure"
        assert event.details["rejection_reason"] == "certificate_expired"

    def test_audit_event_records_delegation_with_correlation_id(
        self, valid_identity_context
    ):
        """Delegation audit events include the correlation ID from the originating request."""
        event = AuthEvent(
            correlation_id=valid_identity_context.correlation_id,
            agent_identity=ORCHESTRATOR_ARN,
            event_type="IDENTITY_PROPAGATION",
            timestamp=datetime.now(timezone.utc),
            trace_id="trace-123",
            span_id="span-456",
            outcome="success",
            details={
                "source_agent": ORCHESTRATOR_ARN,
                "target_agent": SCANNER_ARN,
                "user_identity": valid_identity_context.user_identity.subject,
            },
        )
        # Correlation ID from the identity context flows into the audit event
        assert event.correlation_id == valid_identity_context.correlation_id

    @patch("src.core.structured_logging.get_emitter")
    def test_emit_auth_log_records_delegation_event(
        self, mock_get_emitter, valid_identity_context
    ):
        """emit_auth_log is callable with delegation event and succeeds."""
        mock_emitter = MagicMock()
        mock_get_emitter.return_value = mock_emitter

        now = datetime.now(timezone.utc)
        event = AuthEvent(
            correlation_id=valid_identity_context.correlation_id,
            agent_identity=SCANNER_ARN,
            event_type="IDENTITY_PROPAGATION",
            timestamp=now,
            trace_id="trace-abc",
            span_id="span-def",
            outcome="success",
            details={
                "source_agent": ORCHESTRATOR_ARN,
                "target_agent": SCANNER_ARN,
                "user_identity": valid_identity_context.user_identity.subject,
            },
        )
        emit_auth_log(event)
        mock_emitter.emit_auth_log.assert_called_once_with(event)


# ---------------------------------------------------------------------------
# Test class: End-to-end delegation flow validation
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestDelegationFlowEndToEnd:
    """Tests the combined mTLS + identity validation flow end-to-end.

    Validates that the full auth stack works in sequence:
    mTLS cert validation -> workload identity check -> user identity check
    """

    def test_full_auth_stack_scanner_pass(
        self, scanner_agent, valid_cert_info, valid_identity_context
    ):
        """Full auth stack passes when all layers are valid (Scanner)."""
        # Step 1: mTLS passes
        mtls_ok = scanner_agent._validate_caller_mtls(valid_cert_info)
        assert mtls_ok is True

        # Step 2: Identity context passes
        id_result = scanner_agent._validate_identity_context(
            valid_identity_context
        )
        assert id_result.is_valid is True

    def test_full_auth_stack_analysis_pass(
        self, analysis_agent, valid_identity_context
    ):
        """Full auth stack passes when all layers are valid (Analysis)."""
        valid_cert = {
            "issuer": "AgentCore Internal CA",
            "subject": "orchestrator-agent",
            "not_after": (
                datetime.now(timezone.utc) + timedelta(days=365)
            ).isoformat(),
        }
        result = analysis_agent._validate_caller(valid_cert, valid_identity_context)
        assert result.is_valid is True

    def test_auth_fails_at_first_layer_short_circuits(
        self, scanner_agent, valid_identity_context
    ):
        """Auth fails at mTLS layer and does not proceed to identity validation."""
        # mTLS fails with empty cert info
        mtls_ok = scanner_agent._validate_caller_mtls({})
        assert mtls_ok is False
        # If mTLS fails, the invoke method would short-circuit before
        # checking identity - this is tested in TestScannerAgentInvokeAuth

    def test_different_hmac_keys_cause_rejection(
        self, orchestrator_workload, valid_user_claims
    ):
        """Identity context signed with a different key is rejected."""
        different_key = b"a-completely-different-hmac-key-for-signing!!"
        context = build_identity_context(
            user_claims=valid_user_claims,
            source_agent=orchestrator_workload,
            hmac_key=different_key,
        )
        # Scanner uses HMAC_KEY, but context is signed with different_key
        scanner_config = ScannerConfig(
            ca_cert_path="/opt/certs/ca.pem",
            hmac_key=HMAC_KEY,
        )
        scanner = ScannerAgent(scanner_config)
        result = scanner._validate_identity_context(context)
        assert result.is_valid is False
        assert result.tamper_type == "signature_mismatch"
