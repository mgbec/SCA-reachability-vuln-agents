"""Unit tests for the Analysis Agent.

Tests cover: caller validation (mTLS + workload identity + user identity),
M2M token acquisition with proactive refresh and retry, call graph integration,
exploitability scoring, SBOM enrichment, and fix recommendation generation.

Requirements: 5.1, 5.2, 5.3, 5.4, 5.5, 5.6, 6.2, 14.2, 18.1, 18.2, 18.4,
              19.1, 19.2, 19.3, 19.4, 19.5
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from src.agents.analysis import (
    AnalysisAgent,
    AnalysisConfig,
    AnalysisRequest,
    AnalysisResult,
)
from src.core.identity_context import build_identity_context
from src.core.models import (
    IdentityContext,
    TokenInfo,
    UserIdentity,
    WorkloadIdentity,
)
from src.sca.call_graph import CallGraph, FunctionNode, SourceFile
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


@pytest.fixture
def analysis_config():
    return AnalysisConfig(
        ca_cert_path="/etc/certs/ca.pem",
        hmac_key=b"test-hmac-secret-key-256bits-long!!",
        m2m_client_id="analysis-client-id",
        m2m_client_secret="analysis-client-secret",
        m2m_token_endpoint="https://token.example.com/oauth2/token",
        vuln_db_endpoints={
            "nvd": "https://nvd.example.com/api/v2/cves",
            "osv": "https://osv.example.com/api/v1/vulns",
        },
    )


@pytest.fixture
def agent(analysis_config):
    return AnalysisAgent(analysis_config)


@pytest.fixture
def valid_cert_info():
    return {
        "issuer": "CN=AgentCore Internal CA",
        "subject": "CN=orchestrator-agent",
        "not_after": (datetime.now(timezone.utc) + timedelta(days=365)).isoformat(),
    }


@pytest.fixture
def source_agent():
    return WorkloadIdentity(
        arn="arn:aws:bedrock-agentcore:us-east-1:123456789012:workload-identity/directory/default/workload-identity/orchestrator-agent",
        name="orchestrator-agent",
    )


@pytest.fixture
def valid_user_claims():
    return {
        "subject": "user-abc-123",
        "issuer": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_TestPool",
        "audience": "test-client-id",
        "scopes": ["openid", "profile"],
        "issued_at": datetime(2025, 6, 1, 10, 0, 0, tzinfo=timezone.utc),
        "expires_at": datetime(2099, 6, 1, 11, 0, 0, tzinfo=timezone.utc),
    }


@pytest.fixture
def hmac_key():
    return b"test-hmac-secret-key-256bits-long!!"


@pytest.fixture
def valid_identity_context(valid_user_claims, source_agent, hmac_key):
    return build_identity_context(valid_user_claims, source_agent, hmac_key)


@pytest.fixture
def sample_sbom():
    return CycloneDXBOM(components=[])


@pytest.fixture
def sample_finding():
    dep = DependencyNode(
        name="lodash",
        version="4.17.20",
        purl="pkg:npm/lodash@4.17.20",
        relationship=DependencyRelationship.DIRECT,
    )
    return VulnerabilityFinding(
        finding_id=str(uuid.uuid4()),
        repository="owner/repo",
        commit_sha="abc123",
        cve_id="CVE-2021-23337",
        dependency=dep,
        cvss_base_score=7.2,
        reachability_status=ReachabilityStatus.REACHABLE,
        reachability_multiplier=1.0,
        exploitability_score=7.2,
        priority_tier=PriorityTier.HIGH,
        call_path=["src/index.ts:main", "src/utils.ts:process"],
        source_database="NVD",
    )


# ---------------------------------------------------------------------------
# Tests: Caller Validation
# ---------------------------------------------------------------------------


class TestCallerValidation:
    """Tests for _validate_caller method."""

    @pytest.mark.unit
    def test_valid_caller_passes(
        self, agent, valid_cert_info, valid_identity_context
    ):
        result = agent._validate_caller(valid_cert_info, valid_identity_context)
        assert result.is_valid is True

    @pytest.mark.unit
    def test_no_certificate_rejects(self, agent, valid_identity_context):
        result = agent._validate_caller({}, valid_identity_context)
        assert result.is_valid is False
        assert "No client certificate" in result.error_message

    @pytest.mark.unit
    def test_missing_issuer_rejects(self, agent, valid_identity_context):
        cert = {"subject": "CN=test", "not_after": "2099-01-01T00:00:00+00:00"}
        result = agent._validate_caller(cert, valid_identity_context)
        assert result.is_valid is False
        assert "issuer" in result.error_message.lower()

    @pytest.mark.unit
    def test_expired_certificate_rejects(self, agent, valid_identity_context):
        cert = {
            "issuer": "CN=AgentCore Internal CA",
            "subject": "CN=orchestrator-agent",
            "not_after": (datetime.now(timezone.utc) - timedelta(days=1)).isoformat(),
        }
        result = agent._validate_caller(cert, valid_identity_context)
        assert result.is_valid is False
        assert "expired" in result.error_message.lower()

    @pytest.mark.unit
    def test_invalid_workload_arn_rejects(
        self, agent, valid_cert_info, valid_user_claims, hmac_key
    ):
        bad_agent = WorkloadIdentity(arn="invalid-arn", name="bad-agent")
        ctx = build_identity_context(valid_user_claims, bad_agent, hmac_key)
        result = agent._validate_caller(valid_cert_info, ctx)
        assert result.is_valid is False
        assert "ARN" in result.error_message

    @pytest.mark.unit
    def test_empty_workload_arn_rejects(
        self, agent, valid_cert_info, valid_user_claims, hmac_key
    ):
        bad_agent = WorkloadIdentity(arn="", name="empty-agent")
        ctx = build_identity_context(valid_user_claims, bad_agent, hmac_key)
        result = agent._validate_caller(valid_cert_info, ctx)
        assert result.is_valid is False

    @pytest.mark.unit
    def test_tampered_identity_context_rejects(
        self, agent, valid_cert_info, valid_identity_context
    ):
        # Tamper with the signature
        valid_identity_context.signature = "dGFtcGVyZWQ="
        result = agent._validate_caller(valid_cert_info, valid_identity_context)
        assert result.is_valid is False
        assert result.tamper_type == "signature_mismatch"


# ---------------------------------------------------------------------------
# Tests: M2M Token Acquisition
# ---------------------------------------------------------------------------


class TestM2MTokenAcquisition:
    """Tests for _acquire_m2m_token method."""

    @pytest.mark.unit
    def test_uses_cached_token_when_valid(self, agent):
        future_expiry = datetime.now(timezone.utc) + timedelta(hours=1)
        agent._m2m_token = TokenInfo(
            access_token="cached-token-123",
            refresh_token=None,
            expires_at=future_expiry,
            scopes=["read"],
            agent_identity="analysis-agent",
        )
        token = agent._acquire_m2m_token()
        assert token == "cached-token-123"

    @pytest.mark.unit
    def test_refreshes_when_within_60_seconds(self, agent):
        # Token expiring in 30 seconds — should trigger refresh
        near_expiry = datetime.now(timezone.utc) + timedelta(seconds=30)
        agent._m2m_token = TokenInfo(
            access_token="old-token",
            refresh_token=None,
            expires_at=near_expiry,
            scopes=["read"],
            agent_identity="analysis-agent",
        )

        new_token = TokenInfo(
            access_token="new-token-456",
            refresh_token=None,
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            scopes=["read"],
            agent_identity="analysis-agent",
        )

        with patch.object(agent, "_request_m2m_token", return_value=new_token):
            token = agent._acquire_m2m_token()
            assert token == "new-token-456"

    @pytest.mark.unit
    def test_retries_on_failure(self, agent):
        call_count = 0

        def failing_then_success():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise RuntimeError("Transient failure")
            return TokenInfo(
                access_token="success-token",
                refresh_token=None,
                expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
                scopes=["read"],
                agent_identity="analysis-agent",
            )

        with patch.object(agent, "_request_m2m_token", side_effect=failing_then_success):
            token = agent._acquire_m2m_token()
            assert token == "success-token"
            assert call_count == 3

    @pytest.mark.unit
    def test_raises_after_all_retries_exhausted(self, agent):
        with patch.object(
            agent, "_request_m2m_token", side_effect=RuntimeError("Always fails")
        ):
            with pytest.raises(RuntimeError, match="Failed to acquire M2M token"):
                agent._acquire_m2m_token()


# ---------------------------------------------------------------------------
# Tests: Call Graph Building
# ---------------------------------------------------------------------------


class TestCallGraphBuilding:
    """Tests for _build_call_graph method."""

    @pytest.mark.unit
    def test_empty_source_files_returns_empty_graph(self, agent):
        graph = agent._build_call_graph([])
        assert len(graph.nodes) == 0
        assert len(graph.edges) == 0

    @pytest.mark.unit
    def test_build_call_graph_returns_call_graph_type(self, agent):
        # Even without tree-sitter grammars, should return a CallGraph
        source_files = [
            SourceFile(path="app.py", content="def main(): pass", language="python")
        ]
        graph = agent._build_call_graph(source_files)
        assert isinstance(graph, CallGraph)


# ---------------------------------------------------------------------------
# Tests: Reachability Determination
# ---------------------------------------------------------------------------


class TestReachabilityDetermination:
    """Tests for _determine_reachability method."""

    @pytest.mark.unit
    def test_empty_graph_returns_empty_map(self, agent):
        graph = CallGraph()
        result = agent._determine_reachability(graph)
        assert result == {}

    @pytest.mark.unit
    def test_single_entry_point_is_reachable(self, agent):
        graph = CallGraph()
        node = FunctionNode(
            id="main.py:main", name="main", file_path="main.py", line=1
        )
        graph.add_node(node)
        result = agent._determine_reachability(graph)
        assert result["main.py:main"] == ReachabilityStatus.REACHABLE


# ---------------------------------------------------------------------------
# Tests: Score Computation
# ---------------------------------------------------------------------------


class TestScoreComputation:
    """Tests for _compute_scores method."""

    @pytest.mark.unit
    def test_computes_correct_exploitability_score(self, agent, sample_finding):
        findings = [sample_finding]
        scored = agent._compute_scores(findings)
        assert len(scored) == 1
        # CVSS 7.2 * reachable multiplier 1.0 = 7.2
        assert scored[0].exploitability_score == pytest.approx(7.2)
        assert scored[0].priority_tier == PriorityTier.HIGH

    @pytest.mark.unit
    def test_unreachable_reduces_score(self, agent):
        dep = DependencyNode(
            name="lodash", version="4.17.20",
            purl="pkg:npm/lodash@4.17.20",
            relationship=DependencyRelationship.DIRECT,
        )
        finding = VulnerabilityFinding(
            finding_id=str(uuid.uuid4()),
            repository="owner/repo",
            commit_sha="abc123",
            cve_id="CVE-2021-23337",
            dependency=dep,
            cvss_base_score=9.8,
            reachability_status=ReachabilityStatus.UNREACHABLE,
            reachability_multiplier=0.2,
            exploitability_score=0.0,
            priority_tier=PriorityTier.LOW,
        )
        scored = agent._compute_scores([finding])
        # 9.8 * 0.2 = 1.96
        assert scored[0].exploitability_score == pytest.approx(1.96)
        assert scored[0].priority_tier == PriorityTier.LOW

    @pytest.mark.unit
    def test_findings_sorted_by_score_descending(self, agent):
        dep = DependencyNode(
            name="pkg", version="1.0.0",
            purl="pkg:npm/pkg@1.0.0",
            relationship=DependencyRelationship.DIRECT,
        )
        findings = [
            VulnerabilityFinding(
                finding_id=str(uuid.uuid4()),
                repository="owner/repo", commit_sha="abc",
                cve_id="CVE-A", dependency=dep,
                cvss_base_score=3.0,
                reachability_status=ReachabilityStatus.REACHABLE,
                reachability_multiplier=1.0,
                exploitability_score=3.0,
                priority_tier=PriorityTier.LOW,
            ),
            VulnerabilityFinding(
                finding_id=str(uuid.uuid4()),
                repository="owner/repo", commit_sha="abc",
                cve_id="CVE-B", dependency=dep,
                cvss_base_score=9.5,
                reachability_status=ReachabilityStatus.REACHABLE,
                reachability_multiplier=1.0,
                exploitability_score=9.5,
                priority_tier=PriorityTier.CRITICAL,
            ),
        ]
        scored = agent._compute_scores(findings)
        assert scored[0].exploitability_score >= scored[1].exploitability_score

    @pytest.mark.unit
    def test_empty_findings_returns_empty(self, agent):
        scored = agent._compute_scores([])
        assert scored == []


# ---------------------------------------------------------------------------
# Tests: SBOM Enrichment
# ---------------------------------------------------------------------------


class TestSBOMEnrichment:
    """Tests for _enrich_sbom method."""

    @pytest.mark.unit
    def test_enrich_empty_sbom(self, agent, sample_sbom):
        result = agent._enrich_sbom(sample_sbom, {}, {})
        assert result.components == []


# ---------------------------------------------------------------------------
# Tests: Fix Recommendations
# ---------------------------------------------------------------------------


class TestFixRecommendations:
    """Tests for _generate_recommendations method."""

    @pytest.mark.unit
    def test_generates_one_recommendation_per_dependency(self, agent):
        dep = DependencyNode(
            name="lodash", version="4.17.20",
            purl="pkg:npm/lodash@4.17.20",
            relationship=DependencyRelationship.DIRECT,
        )
        findings = [
            VulnerabilityFinding(
                finding_id=str(uuid.uuid4()),
                repository="owner/repo", commit_sha="abc",
                cve_id="CVE-2021-23337", dependency=dep,
                cvss_base_score=7.2,
                reachability_status=ReachabilityStatus.REACHABLE,
                reachability_multiplier=1.0,
                exploitability_score=7.2,
                priority_tier=PriorityTier.HIGH,
            ),
            VulnerabilityFinding(
                finding_id=str(uuid.uuid4()),
                repository="owner/repo", commit_sha="abc",
                cve_id="CVE-2020-28500", dependency=dep,
                cvss_base_score=5.3,
                reachability_status=ReachabilityStatus.REACHABLE,
                reachability_multiplier=1.0,
                exploitability_score=5.3,
                priority_tier=PriorityTier.MEDIUM,
            ),
        ]
        recommendations = agent._generate_recommendations(findings)
        # One recommendation for "lodash" covering both CVEs
        assert len(recommendations) == 1
        assert "CVE-2021-23337" in recommendations[0].resolved_cves
        assert "CVE-2020-28500" in recommendations[0].resolved_cves


# ---------------------------------------------------------------------------
# Tests: Full invoke flow
# ---------------------------------------------------------------------------


class TestInvokeFlow:
    """Tests for the full async invoke method."""

    @pytest.mark.unit
    def test_invoke_rejects_invalid_caller(self, agent, sample_sbom):
        request = AnalysisRequest(
            cert_info={},  # No cert
            identity_context=IdentityContext(
                version="1.0",
                correlation_id=str(uuid.uuid4()),
                source_agent=WorkloadIdentity(arn="", name=""),
                user_identity=UserIdentity(
                    subject="u", issuer="i", audience="a",
                    scopes=["s"], issued_at=datetime.now(timezone.utc),
                    expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
                    token_reference="ref",
                ),
                signature="sig",
            ),
            source_files=[],
            sbom=sample_sbom,
        )
        result = asyncio.run(agent.invoke(request))
        assert result.success is False
        assert "Caller validation failed" in result.error

    @pytest.mark.unit
    def test_invoke_succeeds_with_valid_request(
        self, agent, valid_cert_info, valid_identity_context, sample_sbom, sample_finding
    ):
        # Mock token acquisition to avoid HTTP calls
        future_expiry = datetime.now(timezone.utc) + timedelta(hours=1)
        agent._m2m_token = TokenInfo(
            access_token="test-token",
            refresh_token=None,
            expires_at=future_expiry,
            scopes=["read"],
            agent_identity="analysis-agent",
        )

        request = AnalysisRequest(
            cert_info=valid_cert_info,
            identity_context=valid_identity_context,
            source_files=[],
            sbom=sample_sbom,
            cve_ids=[],
            repository="owner/repo",
            commit_sha="abc123",
            findings=[sample_finding],
        )
        result = asyncio.run(agent.invoke(request))
        assert result.success is True
        assert result.enriched_sbom is not None
        assert len(result.scored_findings) == 1
        assert result.exploitability_result is not None
        assert result.exploitability_result.repository == "owner/repo"

    @pytest.mark.unit
    def test_invoke_fails_on_token_acquisition_error(
        self, agent, valid_cert_info, valid_identity_context, sample_sbom
    ):
        # No cached token and mock to always fail
        agent._m2m_token = None

        with patch.object(
            agent, "_request_m2m_token", side_effect=RuntimeError("Connection refused")
        ):
            request = AnalysisRequest(
                cert_info=valid_cert_info,
                identity_context=valid_identity_context,
                source_files=[],
                sbom=sample_sbom,
            )
            result = asyncio.run(agent.invoke(request))
            assert result.success is False
            assert "M2M token acquisition failed" in result.error
