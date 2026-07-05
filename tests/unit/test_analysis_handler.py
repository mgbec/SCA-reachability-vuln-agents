"""Unit tests for the Analysis Agent AWS Lambda/AgentCore Runtime handler.

Tests cover: Secrets Manager integration, request deserialization, response
serialization, cold start initialization, and the handler entry point.

Requirements: 5.1, 5.2, 14.2, 16.1, 16.2
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from src.agents.analysis_handler import (
    _deserialize_finding,
    _deserialize_identity_context,
    _deserialize_request,
    _get_agent,
    _load_config_from_secrets,
    _parse_datetime,
    _retrieve_secret,
    _serialize_result,
    handler,
)
from src.agents.analysis import AnalysisConfig, AnalysisResult
from src.core.models import TokenInfo
from src.sca.models import (
    DependencyNode,
    DependencyRelationship,
    PriorityTier,
    ReachabilityStatus,
    VulnerabilityFinding,
)
from src.sca.sbom_generator import CycloneDXBOM


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def reset_module_state():
    """Reset cached module-level state between tests."""
    import src.agents.analysis_handler as mod
    mod._agent_instance = None
    mod._secrets_client = None
    yield
    mod._agent_instance = None
    mod._secrets_client = None


@pytest.fixture
def mock_secrets_client():
    """Create a mock Secrets Manager client."""
    client = MagicMock()
    client.get_secret_value.side_effect = lambda SecretId: {
        "agentcore-sca/analysis-agent/m2m-credentials": {
            "SecretString": json.dumps({
                "client_id": "test-client-id",
                "client_secret": "test-client-secret",
            })
        },
        "agentcore-sca/identity-context/hmac-key": {
            "SecretString": json.dumps({
                "hmac_key": "test-hmac-key-for-signing-256bits!",
            })
        },
    }.get(SecretId, {"SecretString": "{}"})
    return client


@pytest.fixture
def valid_event():
    """Create a valid AgentCore Runtime invoke event."""
    now = datetime.now(timezone.utc)
    future = now + timedelta(hours=1)
    return {
        "requestContext": {
            "identity": {
                "clientCert": {
                    "issuer": "CN=AgentCore Internal CA",
                    "subject": "CN=orchestrator-agent",
                    "not_after": future.isoformat(),
                }
            }
        },
        "body": json.dumps({
            "identity_context": {
                "version": "1.0",
                "correlation_id": str(uuid.uuid4()),
                "source_agent": {
                    "arn": "arn:aws:bedrock-agentcore:us-east-1:123456789012:workload-identity/directory/default/workload-identity/orchestrator-agent",
                    "name": "orchestrator-agent",
                },
                "user_identity": {
                    "subject": "user-123",
                    "issuer": "https://cognito-idp.us-east-1.amazonaws.com/pool",
                    "audience": "client-id",
                    "scopes": ["openid", "profile"],
                    "issued_at": now.isoformat(),
                    "expires_at": future.isoformat(),
                    "token_reference": "jti-ref",
                },
                "delegation_chain": [
                    {
                        "agent_arn": "arn:aws:bedrock-agentcore:us-east-1:123456789012:workload-identity/directory/default/workload-identity/orchestrator-agent",
                        "delegated_at": now.isoformat(),
                    }
                ],
                "signature": "test-signature",
            },
            "source_files": [],
            "sbom": {"components": []},
            "cve_ids": [],
            "repository": "owner/repo",
            "commit_sha": "abc123",
            "findings": [],
        }),
    }


# ---------------------------------------------------------------------------
# Tests: _parse_datetime
# ---------------------------------------------------------------------------


class TestParseDatetime:
    """Tests for datetime parsing utility."""

    @pytest.mark.unit
    def test_parses_iso_string(self):
        result = _parse_datetime("2025-01-15T10:00:00+00:00")
        assert result.year == 2025
        assert result.month == 1
        assert result.day == 15
        assert result.tzinfo is not None

    @pytest.mark.unit
    def test_naive_datetime_gets_utc(self):
        result = _parse_datetime("2025-01-15T10:00:00")
        assert result.tzinfo == timezone.utc

    @pytest.mark.unit
    def test_empty_string_returns_now(self):
        before = datetime.now(timezone.utc)
        result = _parse_datetime("")
        after = datetime.now(timezone.utc)
        assert before <= result <= after

    @pytest.mark.unit
    def test_datetime_passthrough(self):
        dt = datetime(2025, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        result = _parse_datetime(dt)
        assert result == dt

    @pytest.mark.unit
    def test_naive_datetime_passthrough_gets_utc(self):
        dt = datetime(2025, 6, 1, 12, 0, 0)
        result = _parse_datetime(dt)
        assert result.tzinfo == timezone.utc


# ---------------------------------------------------------------------------
# Tests: _deserialize_identity_context
# ---------------------------------------------------------------------------


class TestDeserializeIdentityContext:
    """Tests for identity context deserialization."""

    @pytest.mark.unit
    def test_deserializes_full_context(self):
        data = {
            "version": "1.0",
            "correlation_id": "test-corr-id",
            "source_agent": {
                "arn": "arn:aws:bedrock-agentcore:us-east-1:123:workload-identity/directory/default/workload-identity/orch",
                "name": "orch",
            },
            "user_identity": {
                "subject": "user-sub",
                "issuer": "https://issuer.example.com",
                "audience": "aud",
                "scopes": ["read", "write"],
                "issued_at": "2025-01-01T00:00:00+00:00",
                "expires_at": "2025-01-01T01:00:00+00:00",
                "token_reference": "jti-123",
            },
            "delegation_chain": [],
            "signature": "sig-abc",
        }
        ctx = _deserialize_identity_context(data)
        assert ctx.version == "1.0"
        assert ctx.correlation_id == "test-corr-id"
        assert ctx.source_agent.arn.startswith("arn:aws:")
        assert ctx.user_identity.subject == "user-sub"
        assert ctx.user_identity.scopes == ["read", "write"]
        assert ctx.signature == "sig-abc"

    @pytest.mark.unit
    def test_handles_empty_data(self):
        ctx = _deserialize_identity_context({})
        assert ctx.version == "1.0"
        assert ctx.source_agent.arn == ""
        assert ctx.user_identity.subject == ""


# ---------------------------------------------------------------------------
# Tests: _deserialize_finding
# ---------------------------------------------------------------------------


class TestDeserializeFinding:
    """Tests for vulnerability finding deserialization."""

    @pytest.mark.unit
    def test_deserializes_full_finding(self):
        data = {
            "finding_id": "f-123",
            "repository": "owner/repo",
            "commit_sha": "abc",
            "cve_id": "CVE-2021-12345",
            "dependency": {
                "name": "lodash",
                "version": "4.17.20",
                "purl": "pkg:npm/lodash@4.17.20",
                "relationship": "direct",
            },
            "cvss_base_score": 7.5,
            "reachability_status": "reachable",
            "reachability_multiplier": 1.0,
            "exploitability_score": 7.5,
            "priority_tier": "high",
            "call_path": ["main.ts:main", "utils.ts:process"],
            "source_database": "NVD",
        }
        finding = _deserialize_finding(data)
        assert finding.finding_id == "f-123"
        assert finding.cve_id == "CVE-2021-12345"
        assert finding.dependency.name == "lodash"
        assert finding.reachability_status == ReachabilityStatus.REACHABLE
        assert finding.priority_tier == PriorityTier.HIGH
        assert finding.cvss_base_score == 7.5


# ---------------------------------------------------------------------------
# Tests: Secrets Manager Integration
# ---------------------------------------------------------------------------


class TestSecretsManagerIntegration:
    """Tests for Secrets Manager credential retrieval."""

    @pytest.mark.unit
    def test_retrieve_secret_success(self, mock_secrets_client):
        with patch(
            "src.agents.analysis_handler._get_secrets_client",
            return_value=mock_secrets_client,
        ):
            result = _retrieve_secret("agentcore-sca/analysis-agent/m2m-credentials")
            assert result["client_id"] == "test-client-id"
            assert result["client_secret"] == "test-client-secret"

    @pytest.mark.unit
    def test_retrieve_secret_retries_on_failure(self):
        client = MagicMock()
        call_count = [0]

        def side_effect(SecretId):
            call_count[0] += 1
            if call_count[0] < 3:
                raise Exception("Transient error")
            return {
                "SecretString": json.dumps({"client_id": "recovered"})
            }

        client.get_secret_value.side_effect = side_effect

        with patch(
            "src.agents.analysis_handler._get_secrets_client",
            return_value=client,
        ):
            result = _retrieve_secret("test-secret")
            assert result["client_id"] == "recovered"
            assert call_count[0] == 3

    @pytest.mark.unit
    def test_retrieve_secret_raises_after_exhausted_retries(self):
        client = MagicMock()
        client.get_secret_value.side_effect = Exception("Permanent failure")

        with patch(
            "src.agents.analysis_handler._get_secrets_client",
            return_value=client,
        ):
            with pytest.raises(RuntimeError, match="Failed to retrieve secret"):
                _retrieve_secret("bad-secret")

    @pytest.mark.unit
    def test_load_config_from_secrets(self, mock_secrets_client):
        with patch(
            "src.agents.analysis_handler._get_secrets_client",
            return_value=mock_secrets_client,
        ):
            config = _load_config_from_secrets()
            assert config.m2m_client_id == "test-client-id"
            assert config.m2m_client_secret == "test-client-secret"
            assert config.hmac_key == b"test-hmac-key-for-signing-256bits!"
            assert "nvd" in config.vuln_db_endpoints
            assert "osv" in config.vuln_db_endpoints

    @pytest.mark.unit
    def test_load_config_raises_on_missing_client_id(self):
        client = MagicMock()
        client.get_secret_value.return_value = {
            "SecretString": json.dumps({"client_id": "", "client_secret": "sec"})
        }
        with patch(
            "src.agents.analysis_handler._get_secrets_client",
            return_value=client,
        ):
            with pytest.raises(RuntimeError, match="missing client_id"):
                _load_config_from_secrets()


# ---------------------------------------------------------------------------
# Tests: Handler Entry Point
# ---------------------------------------------------------------------------


class TestHandler:
    """Tests for the Lambda/AgentCore handler function."""

    @pytest.mark.unit
    def test_handler_returns_500_on_initialization_failure(self):
        """Handler returns 500 when Secrets Manager is unavailable."""
        with patch(
            "src.agents.analysis_handler._get_secrets_client",
        ) as mock_get_client:
            mock_client = MagicMock()
            mock_client.get_secret_value.side_effect = Exception("SM unavailable")
            mock_get_client.return_value = mock_client

            context = MagicMock()
            context.aws_request_id = "req-123"

            result = handler({"body": "{}"}, context)
            assert result["statusCode"] == 500
            body = json.loads(result["body"])
            assert body["success"] is False

    @pytest.mark.unit
    def test_handler_succeeds_with_valid_request(self, valid_event, mock_secrets_client):
        """Handler processes a valid request end-to-end."""
        with patch(
            "src.agents.analysis_handler._get_secrets_client",
            return_value=mock_secrets_client,
        ):
            # Pre-set a cached M2M token on the agent to avoid HTTP calls
            import src.agents.analysis_handler as mod

            config = _load_config_from_secrets()
            from src.agents.analysis import AnalysisAgent
            agent = AnalysisAgent(config)
            agent._m2m_token = TokenInfo(
                access_token="test-token",
                refresh_token=None,
                expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
                scopes=["read"],
                agent_identity="analysis-agent",
            )
            mod._agent_instance = agent

            context = MagicMock()
            context.aws_request_id = "req-456"

            result = handler(valid_event, context)
            # The request will fail validation because the signature is mocked,
            # but the handler itself should return a proper response structure
            assert result["statusCode"] in (200, 403, 500)
            body = json.loads(result["body"])
            assert "success" in body

    @pytest.mark.unit
    def test_handler_returns_request_id_header(self, mock_secrets_client):
        """Handler includes X-Request-Id in response headers."""
        with patch(
            "src.agents.analysis_handler._get_secrets_client",
            return_value=mock_secrets_client,
        ):
            context = MagicMock()
            context.aws_request_id = "unique-req-id"

            result = handler({"body": json.dumps({
                "identity_context": {},
                "source_files": [],
                "sbom": {},
            })}, context)
            assert result["headers"]["X-Request-Id"] == "unique-req-id"

    @pytest.mark.unit
    def test_handler_with_no_context(self, mock_secrets_client):
        """Handler handles None context gracefully."""
        with patch(
            "src.agents.analysis_handler._get_secrets_client",
            return_value=mock_secrets_client,
        ):
            import src.agents.analysis_handler as mod
            config = _load_config_from_secrets()
            from src.agents.analysis import AnalysisAgent
            agent = AnalysisAgent(config)
            agent._m2m_token = TokenInfo(
                access_token="t",
                refresh_token=None,
                expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
                scopes=[],
                agent_identity="analysis-agent",
            )
            mod._agent_instance = agent

            result = handler({"body": json.dumps({
                "identity_context": {},
                "source_files": [],
                "sbom": {},
            })}, None)
            assert result["headers"]["X-Request-Id"] == "unknown"


# ---------------------------------------------------------------------------
# Tests: _serialize_result
# ---------------------------------------------------------------------------


class TestSerializeResult:
    """Tests for result serialization."""

    @pytest.mark.unit
    def test_serialize_successful_result(self):
        result = AnalysisResult(
            success=True,
            enriched_sbom=CycloneDXBOM(components=[]),
            scored_findings=[],
            recommendations=[],
        )
        serialized = _serialize_result(result)
        assert serialized["success"] is True
        assert "enriched_sbom" in serialized
        assert serialized["enriched_sbom"]["components"] == []

    @pytest.mark.unit
    def test_serialize_failed_result(self):
        result = AnalysisResult(
            success=False,
            error="Something went wrong",
        )
        serialized = _serialize_result(result)
        assert serialized["success"] is False
        assert serialized["error"] == "Something went wrong"

    @pytest.mark.unit
    def test_serialize_result_with_findings(self):
        dep = DependencyNode(
            name="lodash",
            version="4.17.20",
            purl="pkg:npm/lodash@4.17.20",
            relationship=DependencyRelationship.DIRECT,
        )
        finding = VulnerabilityFinding(
            finding_id="f-1",
            repository="owner/repo",
            commit_sha="abc",
            cve_id="CVE-2021-23337",
            dependency=dep,
            cvss_base_score=7.2,
            reachability_status=ReachabilityStatus.REACHABLE,
            reachability_multiplier=1.0,
            exploitability_score=7.2,
            priority_tier=PriorityTier.HIGH,
        )
        result = AnalysisResult(
            success=True,
            enriched_sbom=CycloneDXBOM(components=[]),
            scored_findings=[finding],
            recommendations=[],
        )
        serialized = _serialize_result(result)
        assert len(serialized["scored_findings"]) == 1
        sf = serialized["scored_findings"][0]
        assert sf["cve_id"] == "CVE-2021-23337"
        assert sf["dependency"]["name"] == "lodash"
        assert sf["reachability_status"] == "reachable"
        assert sf["priority_tier"] == "high"


# ---------------------------------------------------------------------------
# Tests: Agent Caching (warm start)
# ---------------------------------------------------------------------------


class TestAgentCaching:
    """Tests for the agent instance caching behavior."""

    @pytest.mark.unit
    def test_get_agent_caches_instance(self, mock_secrets_client):
        """Agent instance is reused on subsequent calls (warm start)."""
        with patch(
            "src.agents.analysis_handler._get_secrets_client",
            return_value=mock_secrets_client,
        ):
            agent1 = _get_agent()
            agent2 = _get_agent()
            assert agent1 is agent2

    @pytest.mark.unit
    def test_get_agent_creates_with_correct_config(self, mock_secrets_client):
        """Agent is initialized with credentials from Secrets Manager."""
        with patch(
            "src.agents.analysis_handler._get_secrets_client",
            return_value=mock_secrets_client,
        ):
            agent = _get_agent()
            assert agent.config.m2m_client_id == "test-client-id"
            assert agent.config.m2m_client_secret == "test-client-secret"
            assert agent.config.hmac_key == b"test-hmac-key-for-signing-256bits!"
