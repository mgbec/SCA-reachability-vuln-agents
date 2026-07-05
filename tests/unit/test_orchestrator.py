"""Unit tests for the Orchestrator Agent.

Tests the OrchestratorAgent class covering:
- JWT validation (valid, expired, missing token) (Requirement 3.1, 3.2)
- Identity context construction from JWT claims (Requirement 6.1)
- Correlation ID propagation (Requirement 11.2, 11.3)
- mTLS client configuration for delegation (Requirement 14.1)
- Full pipeline coordination (scan → analyze → score → recommend)
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import jwt as pyjwt
import httpx
import pytest

from src.agents.orchestrator import (
    AnalysisResult,
    InvokeRequest,
    InvokeResponse,
    OrchestratorAgent,
    OrchestratorConfig,
    PipelineResult,
    ScanResult,
)


# Test constants
SECRET_KEY = "test-secret-key-for-hmac-256"
HMAC_KEY = b"test-hmac-key-for-identity-context-signing"
ISSUER = "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_TestPool"
AUDIENCE = "test-client-id-123"
AGENT_ARN = "arn:aws:bedrock-agentcore:us-east-1:123456789:workload-identity/directory/default/workload-identity/orchestrator-agent"


def _make_config() -> OrchestratorConfig:
    """Create a test OrchestratorConfig."""
    return OrchestratorConfig(
        scanner_endpoint="https://scanner:8443",
        analysis_endpoint="https://analysis:8443",
        cognito_issuer=ISSUER,
        cognito_audience=AUDIENCE,
        signing_key=SECRET_KEY,
        hmac_key=HMAC_KEY,
        client_cert_path="/tmp/certs/orchestrator.pem",
        client_key_path="/tmp/certs/orchestrator-key.pem",
        ca_cert_path="/tmp/certs/ca.pem",
        agent_name="orchestrator-agent",
        agent_arn=AGENT_ARN,
    )


def _create_valid_token(
    issuer: str = ISSUER,
    audience: str = AUDIENCE,
    subject: str = "user-sub-123",
    exp_offset: int = 3600,
) -> str:
    """Helper to create a valid JWT token for testing."""
    now = int(time.time())
    payload = {
        "iss": issuer,
        "aud": audience,
        "sub": subject,
        "exp": now + exp_offset,
        "iat": now,
        "jti": "token-ref-abc",
        "scope": "openid profile",
    }
    return pyjwt.encode(payload, SECRET_KEY, algorithm="HS256")


class TestOrchestratorInit:
    """Tests for OrchestratorAgent initialization."""

    def test_creates_agent_with_config(self):
        config = _make_config()
        agent = OrchestratorAgent(config)
        assert agent.config is config
        assert agent.workload_identity.arn == AGENT_ARN
        assert agent.workload_identity.name == "orchestrator-agent"


class TestJWTValidation:
    """Tests for _validate_inbound_jwt method (Requirements 3.1, 3.2)."""

    def test_valid_bearer_token(self):
        config = _make_config()
        agent = OrchestratorAgent(config)
        token = _create_valid_token()
        authorization = f"Bearer {token}"

        result = agent._validate_inbound_jwt(authorization)
        assert result.is_valid is True
        assert result.claims["sub"] == "user-sub-123"
        assert result.claims["iss"] == ISSUER
        assert result.claims["aud"] == AUDIENCE

    def test_missing_authorization_header(self):
        config = _make_config()
        agent = OrchestratorAgent(config)

        result = agent._validate_inbound_jwt("")
        assert result.is_valid is False
        assert result.error_reason == "missing_token"

    def test_invalid_bearer_prefix(self):
        config = _make_config()
        agent = OrchestratorAgent(config)
        token = _create_valid_token()

        result = agent._validate_inbound_jwt(f"Basic {token}")
        assert result.is_valid is False
        assert result.error_reason == "missing_token"

    def test_expired_token(self):
        config = _make_config()
        agent = OrchestratorAgent(config)
        token = _create_valid_token(exp_offset=-3600)

        result = agent._validate_inbound_jwt(f"Bearer {token}")
        assert result.is_valid is False
        assert result.error_reason == "expired_token"

    def test_wrong_issuer(self):
        config = _make_config()
        agent = OrchestratorAgent(config)
        token = _create_valid_token(issuer="https://evil.example.com")

        result = agent._validate_inbound_jwt(f"Bearer {token}")
        assert result.is_valid is False
        assert result.error_reason == "unrecognized_issuer"

    def test_wrong_audience(self):
        config = _make_config()
        agent = OrchestratorAgent(config)
        token = _create_valid_token(audience="wrong-client")

        result = agent._validate_inbound_jwt(f"Bearer {token}")
        assert result.is_valid is False
        assert result.error_reason == "disallowed_audience"


class TestIdentityContextConstruction:
    """Tests for _build_identity_context method (Requirement 6.1)."""

    def test_builds_context_from_jwt_claims(self):
        config = _make_config()
        agent = OrchestratorAgent(config)

        now = int(time.time())
        user_claims = {
            "sub": "user-sub-123",
            "iss": ISSUER,
            "aud": AUDIENCE,
            "scope": "openid profile",
            "iat": now,
            "exp": now + 3600,
            "jti": "token-ref-abc",
        }
        correlation_id = "test-corr-id-123"

        context = agent._build_identity_context(user_claims, correlation_id)

        assert context.version == "1.0"
        assert context.correlation_id == correlation_id
        assert context.source_agent.arn == AGENT_ARN
        assert context.source_agent.name == "orchestrator-agent"
        assert context.user_identity.subject == "user-sub-123"
        assert context.user_identity.issuer == ISSUER
        assert context.user_identity.audience == AUDIENCE
        assert "openid" in context.user_identity.scopes
        assert "profile" in context.user_identity.scopes
        assert context.signature != ""
        assert len(context.delegation_chain) == 1
        assert context.delegation_chain[0].agent_arn == AGENT_ARN

    def test_context_handles_scope_as_list(self):
        config = _make_config()
        agent = OrchestratorAgent(config)

        now = int(time.time())
        user_claims = {
            "sub": "user-456",
            "iss": ISSUER,
            "aud": AUDIENCE,
            "scope": ["openid", "email"],
            "iat": now,
            "exp": now + 3600,
            "jti": "jti-456",
        }

        context = agent._build_identity_context(user_claims, "corr-id")
        assert "openid" in context.user_identity.scopes
        assert "email" in context.user_identity.scopes


class TestCorrelationIdPropagation:
    """Tests for correlation ID handling (Requirements 11.2, 11.3)."""

    @pytest.mark.asyncio
    async def test_extracts_existing_correlation_id(self):
        config = _make_config()
        agent = OrchestratorAgent(config)
        token = _create_valid_token()

        request = InvokeRequest(
            authorization=f"Bearer {token}",
            headers={"X-Correlation-ID": "550e8400-e29b-41d4-a716-446655440000"},
            body={"action": "scan"},
        )

        # Mock the delegation to avoid actual HTTP calls
        with patch.object(agent, "_delegate_to_scanner", new_callable=AsyncMock) as mock_scan:
            mock_scan.return_value = ScanResult(success=True, sbom={"test": True})
            response = await agent.invoke(request)

        assert response.headers.get("X-Correlation-ID") == "550e8400-e29b-41d4-a716-446655440000"

    @pytest.mark.asyncio
    async def test_generates_correlation_id_when_missing(self):
        config = _make_config()
        agent = OrchestratorAgent(config)
        token = _create_valid_token()

        request = InvokeRequest(
            authorization=f"Bearer {token}",
            headers={},
            body={"action": "scan"},
        )

        with patch.object(agent, "_delegate_to_scanner", new_callable=AsyncMock) as mock_scan:
            mock_scan.return_value = ScanResult(success=True, sbom={"test": True})
            response = await agent.invoke(request)

        # Should generate a UUID v4 format correlation ID
        corr_id = response.headers.get("X-Correlation-ID")
        assert corr_id is not None
        assert len(corr_id) == 36  # UUID format


class TestInvokeEndpoint:
    """Tests for the main invoke handler."""

    @pytest.mark.asyncio
    async def test_rejects_missing_auth(self):
        config = _make_config()
        agent = OrchestratorAgent(config)

        request = InvokeRequest(
            authorization="",
            headers={},
            body={},
        )

        response = await agent.invoke(request)
        assert response.status_code == 401
        assert response.body["error"] == "missing_token"

    @pytest.mark.asyncio
    async def test_rejects_expired_token(self):
        config = _make_config()
        agent = OrchestratorAgent(config)
        token = _create_valid_token(exp_offset=-3600)

        request = InvokeRequest(
            authorization=f"Bearer {token}",
            headers={},
            body={},
        )

        response = await agent.invoke(request)
        assert response.status_code == 401
        assert response.body["error"] == "expired_token"

    @pytest.mark.asyncio
    async def test_scan_action_delegates_to_scanner(self):
        config = _make_config()
        agent = OrchestratorAgent(config)
        token = _create_valid_token()

        request = InvokeRequest(
            authorization=f"Bearer {token}",
            headers={},
            body={"action": "scan", "repository": "owner/repo"},
        )

        with patch.object(agent, "_delegate_to_scanner", new_callable=AsyncMock) as mock_scan:
            mock_scan.return_value = ScanResult(
                success=True,
                sbom={"components": []},
                scan_results={"alerts": []},
            )
            response = await agent.invoke(request)

        assert response.status_code == 200
        assert response.body["action"] == "scan"
        mock_scan.assert_called_once()

    @pytest.mark.asyncio
    async def test_analyze_action_delegates_to_analysis(self):
        config = _make_config()
        agent = OrchestratorAgent(config)
        token = _create_valid_token()

        request = InvokeRequest(
            authorization=f"Bearer {token}",
            headers={},
            body={"action": "analyze", "sbom": {}},
        )

        with patch.object(agent, "_delegate_to_analysis", new_callable=AsyncMock) as mock_analysis:
            mock_analysis.return_value = AnalysisResult(
                success=True,
                enriched_sbom={"enriched": True},
                scored_findings=[{"cve": "CVE-2021-1234"}],
                recommendations=[{"dependency": "lodash"}],
            )
            response = await agent.invoke(request)

        assert response.status_code == 200
        assert response.body["action"] == "analyze"
        mock_analysis.assert_called_once()

    @pytest.mark.asyncio
    async def test_full_pipeline_action(self):
        config = _make_config()
        agent = OrchestratorAgent(config)
        token = _create_valid_token()

        request = InvokeRequest(
            authorization=f"Bearer {token}",
            headers={},
            body={"action": "full_pipeline", "repository": "owner/repo"},
        )

        with patch.object(agent, "_delegate_to_scanner", new_callable=AsyncMock) as mock_scan, \
             patch.object(agent, "_delegate_to_analysis", new_callable=AsyncMock) as mock_analysis:
            mock_scan.return_value = ScanResult(
                success=True,
                sbom={"components": []},
                scan_results={"alerts": []},
                source_artifacts={"files": []},
            )
            mock_analysis.return_value = AnalysisResult(
                success=True,
                enriched_sbom={"enriched": True},
                scored_findings=[{"cve": "CVE-2021-1234", "score": 7.2}],
                recommendations=[{"dependency": "lodash", "version": "4.17.21"}],
            )
            response = await agent.invoke(request)

        assert response.status_code == 200
        assert response.body["action"] == "full_pipeline"
        assert response.body["result"]["analysis"]["enriched_sbom"] == {"enriched": True}
        assert len(response.body["result"]["analysis"]["scored_findings"]) == 1
        assert len(response.body["result"]["analysis"]["recommendations"]) == 1

    @pytest.mark.asyncio
    async def test_pipeline_fails_at_scan_stage(self):
        config = _make_config()
        agent = OrchestratorAgent(config)
        token = _create_valid_token()

        request = InvokeRequest(
            authorization=f"Bearer {token}",
            headers={},
            body={"action": "full_pipeline", "repository": "owner/repo"},
        )

        with patch.object(agent, "_delegate_to_scanner", new_callable=AsyncMock) as mock_scan:
            mock_scan.return_value = ScanResult(
                success=False,
                error="Scanner Agent unreachable",
            )
            response = await agent.invoke(request)

        assert response.status_code == 502
        assert response.error == "Scanner Agent unreachable"


class TestSerializeIdentityContext:
    """Tests for identity context serialization to dict."""

    def test_serializes_context_to_dict(self):
        config = _make_config()
        agent = OrchestratorAgent(config)

        now = int(time.time())
        user_claims = {
            "sub": "user-sub-123",
            "iss": ISSUER,
            "aud": AUDIENCE,
            "scope": "openid",
            "iat": now,
            "exp": now + 3600,
            "jti": "jti-123",
        }

        context = agent._build_identity_context(user_claims, "corr-123")
        serialized = agent._serialize_identity_context(context)

        assert serialized["version"] == "1.0"
        assert serialized["correlation_id"] == "corr-123"
        assert serialized["source_agent"]["arn"] == AGENT_ARN
        assert serialized["source_agent"]["name"] == "orchestrator-agent"
        assert serialized["user_identity"]["subject"] == "user-sub-123"
        assert serialized["signature"] != ""
        assert len(serialized["delegation_chain"]) == 1


class TestMTLSClientCreation:
    """Tests for mTLS client configuration (Requirement 14.1)."""

    def test_creates_client_with_cert_paths(self):
        from unittest.mock import patch, MagicMock

        config = _make_config()
        agent = OrchestratorAgent(config)

        # Mock httpx.AsyncClient to avoid needing actual cert files
        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client_cls.return_value = MagicMock()
            client = agent._create_mtls_client()

            # Verify it was called with the correct mTLS parameters
            mock_client_cls.assert_called_once_with(
                cert=(config.client_cert_path, config.client_key_path),
                verify=config.ca_cert_path,
                timeout=httpx.Timeout(30.0),
            )
            assert client is not None
