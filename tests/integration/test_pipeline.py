"""Integration tests for the full vulnerability analysis pipeline.

Tests the end-to-end pipeline: scan → analyze → score → recommend.
Verifies SBOM generation, exploitability scoring, fix recommendations,
and that findings are sorted by exploitability score.

Requirements: 17.1, 17.2, 18.1, 18.5, 19.1, 19.5
"""

from __future__ import annotations

import time
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import jwt as pyjwt
import pytest

from src.agents.orchestrator import (
    AnalysisResult,
    InvokeRequest,
    OrchestratorAgent,
    OrchestratorConfig,
    PipelineResult,
    ScanResult,
)
from src.sca.fix_recommendations import (
    generate_fix_recommendations,
)
from src.sca.manifest_parser import parse_manifest
from src.sca.models import (
    DependencyNode,
    DependencyRelationship,
    FixRecommendation,
    PriorityTier,
    ReachabilityStatus,
    VulnerabilityFinding,
)
from src.sca.sbom_generator import (
    CycloneDXBOM,
    enrich_sbom,
    generate_sbom,
    to_json,
)
from src.sca.scoring import (
    classify_priority_tier,
    compute_exploitability_score,
    sort_findings_by_score,
)


# --- Test constants ---

SECRET_KEY = "test-secret-key-for-pipeline-integration"
HMAC_KEY = b"test-hmac-key-for-pipeline-integration-signing"
ISSUER = "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_TestPool"
AUDIENCE = "test-client-id-pipeline"
AGENT_ARN = (
    "arn:aws:bedrock-agentcore:us-east-1:123456789012:"
    "workload-identity/directory/default/workload-identity/orchestrator-agent"
)
REPO = "acme/vulnerable-app"
COMMIT_SHA = "abc123def456"


def _make_orchestrator_config() -> OrchestratorConfig:
    """Create an OrchestratorConfig for integration testing."""
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


def _create_valid_jwt() -> str:
    """Create a valid JWT for pipeline tests."""
    now = int(time.time())
    payload = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": "user-sub-pipeline-test",
        "exp": now + 3600,
        "iat": now,
        "jti": "token-ref-pipeline",
        "scope": "openid profile security_events repo",
    }
    return pyjwt.encode(payload, SECRET_KEY, algorithm="HS256")


# --- Sample data factories ---


def _sample_dependency_tree() -> list[DependencyNode]:
    """Create a realistic dependency tree for pipeline testing."""
    return [
        DependencyNode(
            name="lodash",
            version="4.17.20",
            purl="pkg:npm/lodash@4.17.20",
            relationship=DependencyRelationship.DIRECT,
        ),
        DependencyNode(
            name="express",
            version="4.17.1",
            purl="pkg:npm/express@4.17.1",
            relationship=DependencyRelationship.DIRECT,
        ),
        DependencyNode(
            name="minimist",
            version="0.2.1",
            purl="pkg:npm/minimist@0.2.1",
            relationship=DependencyRelationship.TRANSITIVE,
        ),
        DependencyNode(
            name="axios",
            version="0.21.1",
            purl="pkg:npm/axios@0.21.1",
            relationship=DependencyRelationship.DIRECT,
        ),
        DependencyNode(
            name="debug",
            version="2.6.8",
            purl="pkg:npm/debug@2.6.8",
            relationship=DependencyRelationship.TRANSITIVE,
        ),
    ]


def _sample_reachability_map() -> dict[str, ReachabilityStatus]:
    """Reachability results simulating call graph analysis."""
    return {
        "pkg:npm/lodash@4.17.20": ReachabilityStatus.REACHABLE,
        "pkg:npm/express@4.17.1": ReachabilityStatus.REACHABLE,
        "pkg:npm/minimist@0.2.1": ReachabilityStatus.UNREACHABLE,
        "pkg:npm/axios@0.21.1": ReachabilityStatus.INDETERMINATE,
        "pkg:npm/debug@2.6.8": ReachabilityStatus.UNREACHABLE,
    }


def _sample_vulnerability_map() -> dict[str, list[dict]]:
    """Vulnerability data simulating NVD/OSV/GHSA queries."""
    return {
        "pkg:npm/lodash@4.17.20": [
            {"id": "CVE-2021-23337", "ratings": [{"score": 7.2}]},
            {"id": "CVE-2020-28500", "ratings": [{"score": 5.3}]},
        ],
        "pkg:npm/minimist@0.2.1": [
            {"id": "CVE-2021-44906", "ratings": [{"score": 9.8}]},
        ],
        "pkg:npm/axios@0.21.1": [
            {"id": "CVE-2021-3749", "ratings": [{"score": 7.5}]},
        ],
    }


def _sample_findings() -> list[VulnerabilityFinding]:
    """Create findings from the sample data simulating the full pipeline output."""
    dep_lodash = DependencyNode(
        name="lodash",
        version="4.17.20",
        purl="pkg:npm/lodash@4.17.20",
        relationship=DependencyRelationship.DIRECT,
    )
    dep_minimist = DependencyNode(
        name="minimist",
        version="0.2.1",
        purl="pkg:npm/minimist@0.2.1",
        relationship=DependencyRelationship.TRANSITIVE,
    )
    dep_axios = DependencyNode(
        name="axios",
        version="0.21.1",
        purl="pkg:npm/axios@0.21.1",
        relationship=DependencyRelationship.DIRECT,
    )

    findings = [
        VulnerabilityFinding(
            finding_id=str(uuid.uuid4()),
            repository=REPO,
            commit_sha=COMMIT_SHA,
            cve_id="CVE-2021-23337",
            dependency=dep_lodash,
            cvss_base_score=7.2,
            reachability_status=ReachabilityStatus.REACHABLE,
            reachability_multiplier=1.0,
            exploitability_score=7.2,
            priority_tier=PriorityTier.HIGH,
            call_path=["src/index.ts:main", "src/utils.ts:processInput"],
            source_database="NVD",
        ),
        VulnerabilityFinding(
            finding_id=str(uuid.uuid4()),
            repository=REPO,
            commit_sha=COMMIT_SHA,
            cve_id="CVE-2020-28500",
            dependency=dep_lodash,
            cvss_base_score=5.3,
            reachability_status=ReachabilityStatus.REACHABLE,
            reachability_multiplier=1.0,
            exploitability_score=5.3,
            priority_tier=PriorityTier.MEDIUM,
            call_path=["src/index.ts:main", "src/format.ts:trim"],
            source_database="NVD",
        ),
        VulnerabilityFinding(
            finding_id=str(uuid.uuid4()),
            repository=REPO,
            commit_sha=COMMIT_SHA,
            cve_id="CVE-2021-44906",
            dependency=dep_minimist,
            cvss_base_score=9.8,
            reachability_status=ReachabilityStatus.UNREACHABLE,
            reachability_multiplier=0.2,
            exploitability_score=1.96,
            priority_tier=PriorityTier.LOW,
            call_path=[],
            source_database="NVD",
        ),
        VulnerabilityFinding(
            finding_id=str(uuid.uuid4()),
            repository=REPO,
            commit_sha=COMMIT_SHA,
            cve_id="CVE-2021-3749",
            dependency=dep_axios,
            cvss_base_score=7.5,
            reachability_status=ReachabilityStatus.INDETERMINATE,
            reachability_multiplier=0.6,
            exploitability_score=4.5,
            priority_tier=PriorityTier.MEDIUM,
            call_path=[],
            source_database="OSV",
        ),
    ]
    return findings


class _MockVulnDB:
    """Mock vulnerability database that returns known fix versions."""

    def __init__(self, fix_map: dict[str, str | None] | None = None):
        self._fix_map = fix_map or {
            "CVE-2021-23337": "4.17.21",
            "CVE-2020-28500": "4.17.21",
            "CVE-2021-44906": "1.2.8",
            "CVE-2021-3749": "0.21.2",
        }

    def get_fix_version(self, cve_id: str) -> str | None:
        return self._fix_map.get(cve_id)


# ---------------------------------------------------------------------------
# Integration Test Class: Full Pipeline (scan → analyze → score → recommend)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestFullVulnerabilityAnalysisPipeline:
    """Integration tests for the full vulnerability analysis pipeline.

    Tests the complete flow: manifest parsing → SBOM generation →
    reachability enrichment → exploitability scoring → fix recommendations.

    Requirements: 17.1, 17.2, 18.1, 18.5, 19.1, 19.5
    """

    def test_manifest_parsing_to_sbom_generation(self):
        """Test scan stage: parse manifests and generate SBOM.

        Validates: Requirements 17.1, 17.2
        """
        # Stage 1: Parse a package.json manifest
        manifest_content = """{
            "name": "vulnerable-app",
            "version": "1.0.0",
            "dependencies": {
                "lodash": "^4.17.20",
                "express": "^4.17.1",
                "axios": "^0.21.1"
            },
            "devDependencies": {
                "jest": "^27.0.0"
            }
        }"""

        parse_result = parse_manifest("package.json", manifest_content)

        assert len(parse_result.parse_errors) == 0
        assert len(parse_result.dependencies) == 4  # 3 deps + 1 devDep

        # Stage 2: Generate SBOM from parsed dependencies
        sbom = generate_sbom(parse_result.dependencies, REPO, COMMIT_SHA)

        assert sbom.bom_format == "CycloneDX"
        assert sbom.spec_version == "1.5"
        assert sbom.metadata["repository"] == REPO
        assert sbom.metadata["commit_sha"] == COMMIT_SHA
        assert len(sbom.components) == 4

        # Verify each component has name, version, purl, classification
        for comp in sbom.components:
            assert comp.name != ""
            assert comp.version != ""
            assert comp.purl != ""
            assert comp.relationship in (
                DependencyRelationship.DIRECT,
                DependencyRelationship.TRANSITIVE,
            )

    def test_sbom_enrichment_with_reachability_and_vulns(self):
        """Test SBOM enrichment with reachability and CVE associations.

        Validates: Requirements 17.2, 18.1
        """
        dep_tree = _sample_dependency_tree()
        sbom = generate_sbom(dep_tree, REPO, COMMIT_SHA)

        reachability_map = _sample_reachability_map()
        vulnerability_map = _sample_vulnerability_map()

        enriched = enrich_sbom(sbom, reachability_map, vulnerability_map)

        # All components should have reachability status after enrichment
        for comp in enriched.components:
            assert comp.reachability_status is not None
            assert comp.reachability_status in (
                ReachabilityStatus.REACHABLE,
                ReachabilityStatus.UNREACHABLE,
                ReachabilityStatus.INDETERMINATE,
            )

        # Check specific reachability assignments
        lodash_comp = next(
            c for c in enriched.components if c.name == "lodash"
        )
        assert lodash_comp.reachability_status == ReachabilityStatus.REACHABLE
        assert "CVE-2021-23337" in lodash_comp.vulnerabilities
        assert "CVE-2020-28500" in lodash_comp.vulnerabilities

        minimist_comp = next(
            c for c in enriched.components if c.name == "minimist"
        )
        assert minimist_comp.reachability_status == ReachabilityStatus.UNREACHABLE
        assert "CVE-2021-44906" in minimist_comp.vulnerabilities

        axios_comp = next(
            c for c in enriched.components if c.name == "axios"
        )
        assert axios_comp.reachability_status == ReachabilityStatus.INDETERMINATE
        assert "CVE-2021-3749" in axios_comp.vulnerabilities

    def test_exploitability_scoring_across_reachability_statuses(self):
        """Test scoring produces correct scores based on reachability.

        Validates: Requirements 18.1, 18.5
        """
        # Reachable: score = CVSS * 1.0
        score_reachable = compute_exploitability_score(7.2, "reachable")
        assert score_reachable == pytest.approx(7.2)

        # Unreachable: score = CVSS * 0.2
        score_unreachable = compute_exploitability_score(9.8, "unreachable")
        assert score_unreachable == pytest.approx(1.96)

        # Indeterminate: score = CVSS * 0.6
        score_indeterminate = compute_exploitability_score(7.5, "indeterminate")
        assert score_indeterminate == pytest.approx(4.5)

        # Verify tier classification
        assert classify_priority_tier(score_reachable) == "high"
        assert classify_priority_tier(score_unreachable) == "low"
        assert classify_priority_tier(score_indeterminate) == "medium"

    def test_findings_sorted_by_exploitability_score(self):
        """Test that findings are sorted in descending exploitability order.

        Validates: Requirement 18.5
        """
        findings = _sample_findings()
        sorted_findings = sort_findings_by_score(findings)

        # Verify descending order
        for i in range(len(sorted_findings) - 1):
            assert (
                sorted_findings[i].exploitability_score
                >= sorted_findings[i + 1].exploitability_score
            ), (
                f"Finding at index {i} (score={sorted_findings[i].exploitability_score}) "
                f"should be >= finding at index {i+1} "
                f"(score={sorted_findings[i+1].exploitability_score})"
            )

        # Verify expected order: 7.2, 5.3, 4.5, 1.96
        assert sorted_findings[0].cve_id == "CVE-2021-23337"  # 7.2
        assert sorted_findings[1].cve_id == "CVE-2020-28500"  # 5.3
        assert sorted_findings[2].cve_id == "CVE-2021-3749"   # 4.5
        assert sorted_findings[3].cve_id == "CVE-2021-44906"  # 1.96

    def test_fix_recommendations_generated_and_grouped(self):
        """Test fix recommendations are generated and grouped by dependency.

        Validates: Requirements 19.1, 19.5
        """
        findings = _sample_findings()
        vuln_db = _MockVulnDB()

        recommendations = generate_fix_recommendations(findings, vuln_db)

        # Should be grouped by dependency: lodash, minimist, axios
        assert len(recommendations) == 3

        dep_names = [r.dependency.name for r in recommendations]
        assert "lodash" in dep_names
        assert "minimist" in dep_names
        assert "axios" in dep_names

        # lodash: 2 CVEs resolved by single upgrade to 4.17.21
        lodash_rec = next(r for r in recommendations if r.dependency.name == "lodash")
        assert lodash_rec.fix_available is True
        assert lodash_rec.recommended_version == "4.17.21"
        assert "CVE-2021-23337" in lodash_rec.resolved_cves
        assert "CVE-2020-28500" in lodash_rec.resolved_cves
        assert lodash_rec.is_breaking_change is False  # same major (4 -> 4)

        # minimist: breaking change (0.x -> 1.x)
        minimist_rec = next(
            r for r in recommendations if r.dependency.name == "minimist"
        )
        assert minimist_rec.fix_available is True
        assert minimist_rec.recommended_version == "1.2.8"
        assert minimist_rec.is_breaking_change is True
        assert minimist_rec.current_major == 0
        assert minimist_rec.target_major == 1

        # axios: non-breaking patch upgrade
        axios_rec = next(r for r in recommendations if r.dependency.name == "axios")
        assert axios_rec.fix_available is True
        assert axios_rec.recommended_version == "0.21.2"
        assert axios_rec.is_breaking_change is False

    def test_end_to_end_pipeline_data_flow(self):
        """Test the full pipeline data flow from manifest to recommendations.

        Exercises the complete integration path:
        1. Parse manifest → dependency tree
        2. Generate SBOM from dependencies
        3. Enrich SBOM with reachability + vulnerabilities
        4. Compute exploitability scores for each finding
        5. Sort findings by score
        6. Generate fix recommendations

        Validates: Requirements 17.1, 17.2, 18.1, 18.5, 19.1, 19.5
        """
        # Step 1: Parse manifest
        manifest_content = """{
            "name": "test-app",
            "version": "2.0.0",
            "dependencies": {
                "lodash": "^4.17.20",
                "express": "^4.17.1",
                "minimist": "^0.2.1",
                "axios": "^0.21.1"
            }
        }"""
        parse_result = parse_manifest("package.json", manifest_content)
        assert len(parse_result.parse_errors) == 0
        dep_tree = parse_result.dependencies

        # Step 2: Generate initial SBOM
        sbom = generate_sbom(dep_tree, REPO, COMMIT_SHA)
        assert len(sbom.components) == 4

        # Step 3: Simulate reachability analysis and vuln DB queries
        reachability_map = {
            "pkg:npm/lodash@4.17.20": ReachabilityStatus.REACHABLE,
            "pkg:npm/express@4.17.1": ReachabilityStatus.REACHABLE,
            "pkg:npm/minimist@0.2.1": ReachabilityStatus.UNREACHABLE,
            "pkg:npm/axios@0.21.1": ReachabilityStatus.INDETERMINATE,
        }
        vulnerability_map = {
            "pkg:npm/lodash@4.17.20": [
                {"id": "CVE-2021-23337"},
                {"id": "CVE-2020-28500"},
            ],
            "pkg:npm/minimist@0.2.1": [
                {"id": "CVE-2021-44906"},
            ],
            "pkg:npm/axios@0.21.1": [
                {"id": "CVE-2021-3749"},
            ],
        }

        # Step 4: Enrich SBOM
        enriched_sbom = enrich_sbom(sbom, reachability_map, vulnerability_map)

        # Verify enrichment
        lodash_comp = next(
            c for c in enriched_sbom.components if c.name == "lodash"
        )
        assert lodash_comp.reachability_status == ReachabilityStatus.REACHABLE

        # Step 5: Compute exploitability scores and create findings
        findings: list[VulnerabilityFinding] = []
        vuln_data = [
            ("CVE-2021-23337", "lodash", "4.17.20", "pkg:npm/lodash@4.17.20",
             DependencyRelationship.DIRECT, 7.2, ReachabilityStatus.REACHABLE),
            ("CVE-2020-28500", "lodash", "4.17.20", "pkg:npm/lodash@4.17.20",
             DependencyRelationship.DIRECT, 5.3, ReachabilityStatus.REACHABLE),
            ("CVE-2021-44906", "minimist", "0.2.1", "pkg:npm/minimist@0.2.1",
             DependencyRelationship.TRANSITIVE, 9.8, ReachabilityStatus.UNREACHABLE),
            ("CVE-2021-3749", "axios", "0.21.1", "pkg:npm/axios@0.21.1",
             DependencyRelationship.DIRECT, 7.5, ReachabilityStatus.INDETERMINATE),
        ]

        for cve_id, name, version, purl, rel, cvss, reach_status in vuln_data:
            multiplier = {
                ReachabilityStatus.REACHABLE: 1.0,
                ReachabilityStatus.UNREACHABLE: 0.2,
                ReachabilityStatus.INDETERMINATE: 0.6,
            }[reach_status]
            score = compute_exploitability_score(cvss, reach_status.value)
            tier = classify_priority_tier(score)

            findings.append(VulnerabilityFinding(
                finding_id=str(uuid.uuid4()),
                repository=REPO,
                commit_sha=COMMIT_SHA,
                cve_id=cve_id,
                dependency=DependencyNode(
                    name=name, version=version, purl=purl, relationship=rel,
                ),
                cvss_base_score=cvss,
                reachability_status=reach_status,
                reachability_multiplier=multiplier,
                exploitability_score=score,
                priority_tier=PriorityTier(tier),
            ))

        # Step 6: Sort findings by exploitability score
        sorted_findings = sort_findings_by_score(findings)

        # Verify sorted order (descending)
        assert sorted_findings[0].exploitability_score == pytest.approx(7.2)
        assert sorted_findings[1].exploitability_score == pytest.approx(5.3)
        assert sorted_findings[2].exploitability_score == pytest.approx(4.5)
        assert sorted_findings[3].exploitability_score == pytest.approx(1.96)

        # Step 7: Generate fix recommendations
        vuln_db = _MockVulnDB()
        recommendations = generate_fix_recommendations(sorted_findings, vuln_db)

        # Verify grouped by dependency (3 unique deps)
        assert len(recommendations) == 3

        # Verify each recommendation resolves its associated CVEs
        for rec in recommendations:
            assert len(rec.resolved_cves) >= 1
            assert rec.dependency.name in ("lodash", "minimist", "axios")

        # Verify lodash groups both CVEs into one recommendation
        lodash_rec = next(
            r for r in recommendations if r.dependency.name == "lodash"
        )
        assert set(lodash_rec.resolved_cves) == {
            "CVE-2021-23337", "CVE-2020-28500"
        }
        assert lodash_rec.recommended_version == "4.17.21"

    def test_no_fix_available_produces_mitigation_note(self):
        """Test that missing fix versions produce mitigation recommendations.

        Validates: Requirement 19.1
        """
        dep = DependencyNode(
            name="vulnerable-lib",
            version="1.0.0",
            purl="pkg:npm/vulnerable-lib@1.0.0",
            relationship=DependencyRelationship.DIRECT,
        )
        finding = VulnerabilityFinding(
            finding_id=str(uuid.uuid4()),
            repository=REPO,
            commit_sha=COMMIT_SHA,
            cve_id="CVE-2099-00001",
            dependency=dep,
            cvss_base_score=8.0,
            reachability_status=ReachabilityStatus.REACHABLE,
            reachability_multiplier=1.0,
            exploitability_score=8.0,
            priority_tier=PriorityTier.HIGH,
        )

        # VulnDB that returns no fix for this CVE
        no_fix_db = _MockVulnDB(fix_map={"CVE-2099-00001": None})
        recommendations = generate_fix_recommendations([finding], no_fix_db)

        assert len(recommendations) == 1
        rec = recommendations[0]
        assert rec.fix_available is False
        assert rec.recommended_version is None
        assert rec.mitigation_note is not None
        assert "No fix available" in rec.mitigation_note


@pytest.mark.integration
class TestOrchestratorPipelineEndToEnd:
    """Integration tests for the Orchestrator's full pipeline with mocked agents.

    Tests the Orchestrator Agent coordinating the full workflow by mocking
    the Scanner and Analysis Agent HTTP endpoints.

    Requirements: 17.1, 17.2, 18.1, 18.5, 19.1, 19.5
    """

    @pytest.mark.asyncio
    async def test_orchestrator_full_pipeline_success(self):
        """Test Orchestrator runs scan → analyze → score → recommend successfully.

        Validates: Requirements 17.1, 17.2, 18.1, 18.5, 19.1, 19.5
        """
        config = _make_orchestrator_config()
        agent = OrchestratorAgent(config)
        token = _create_valid_jwt()

        # Mock Scanner Agent response
        scanner_response_data = {
            "sbom": {
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                "components": [
                    {
                        "name": "lodash",
                        "version": "4.17.20",
                        "purl": "pkg:npm/lodash@4.17.20",
                    },
                    {
                        "name": "minimist",
                        "version": "0.2.1",
                        "purl": "pkg:npm/minimist@0.2.1",
                    },
                ],
            },
            "scan_results": {
                "vulnerabilities": [
                    {"cve_id": "CVE-2021-23337", "package": "lodash"},
                    {"cve_id": "CVE-2021-44906", "package": "minimist"},
                ],
            },
            "source_artifacts": {"files": ["src/index.ts", "src/utils.ts"]},
        }

        # Mock Analysis Agent response (sorted by exploitability score)
        analysis_response_data = {
            "enriched_sbom": {
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                "components": [
                    {
                        "name": "lodash",
                        "version": "4.17.20",
                        "purl": "pkg:npm/lodash@4.17.20",
                        "reachability_status": "reachable",
                        "vulnerabilities": ["CVE-2021-23337"],
                    },
                    {
                        "name": "minimist",
                        "version": "0.2.1",
                        "purl": "pkg:npm/minimist@0.2.1",
                        "reachability_status": "unreachable",
                        "vulnerabilities": ["CVE-2021-44906"],
                    },
                ],
            },
            "scored_findings": [
                {
                    "cve_id": "CVE-2021-23337",
                    "exploitability_score": 7.2,
                    "priority_tier": "high",
                    "reachability_status": "reachable",
                },
                {
                    "cve_id": "CVE-2021-44906",
                    "exploitability_score": 1.96,
                    "priority_tier": "low",
                    "reachability_status": "unreachable",
                },
            ],
            "recommendations": [
                {
                    "dependency": "lodash",
                    "recommended_version": "4.17.21",
                    "is_breaking_change": False,
                    "resolved_cves": ["CVE-2021-23337"],
                },
                {
                    "dependency": "minimist",
                    "recommended_version": "1.2.8",
                    "is_breaking_change": True,
                    "resolved_cves": ["CVE-2021-44906"],
                },
            ],
        }

        # Create mock httpx responses
        mock_scanner_response = httpx.Response(
            status_code=200,
            json=scanner_response_data,
            request=httpx.Request("POST", "https://scanner:8443/invoke"),
        )
        mock_analysis_response = httpx.Response(
            status_code=200,
            json=analysis_response_data,
            request=httpx.Request("POST", "https://analysis:8443/invoke"),
        )

        # Patch the mTLS client to return mocked responses
        async def mock_post(url, **kwargs):
            if "scanner" in url:
                return mock_scanner_response
            elif "analysis" in url:
                return mock_analysis_response
            raise httpx.ConnectError("Unknown endpoint")

        mock_client = AsyncMock()
        mock_client.post = mock_post
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)

        with patch.object(
            agent, "_create_mtls_client", return_value=mock_client
        ):
            request = InvokeRequest(
                authorization=f"Bearer {token}",
                headers={"X-Correlation-ID": str(uuid.uuid4())},
                body={
                    "action": "full_pipeline",
                    "repository": REPO,
                    "branch": "main",
                },
            )
            response = await agent.invoke(request)

        # Verify pipeline success
        assert response.status_code == 200
        assert response.error is None

        body = response.body
        assert body["action"] == "full_pipeline"
        assert "correlation_id" in body
        assert "result" in body

        result = body["result"]
        analysis = result["analysis"]

        # Verify enriched SBOM returned
        assert "enriched_sbom" in analysis
        assert analysis["enriched_sbom"]["bomFormat"] == "CycloneDX"

        # Verify scored findings sorted by exploitability score
        scored = analysis["scored_findings"]
        assert len(scored) == 2
        assert scored[0]["exploitability_score"] >= scored[1]["exploitability_score"]
        assert scored[0]["priority_tier"] == "high"
        assert scored[1]["priority_tier"] == "low"

        # Verify fix recommendations present
        recs = analysis["recommendations"]
        assert len(recs) == 2
        rec_deps = [r["dependency"] for r in recs]
        assert "lodash" in rec_deps
        assert "minimist" in rec_deps

    @pytest.mark.asyncio
    async def test_orchestrator_pipeline_scanner_failure(self):
        """Test pipeline handles Scanner Agent failure gracefully.

        Validates: error propagation in pipeline.
        """
        config = _make_orchestrator_config()
        agent = OrchestratorAgent(config)
        token = _create_valid_jwt()

        # Mock Scanner Agent returning error
        mock_scanner_response = httpx.Response(
            status_code=502,
            json={"error": "github_oauth_failed"},
            request=httpx.Request("POST", "https://scanner:8443/invoke"),
        )

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_scanner_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)

        with patch.object(
            agent, "_create_mtls_client", return_value=mock_client
        ):
            request = InvokeRequest(
                authorization=f"Bearer {token}",
                headers={},
                body={
                    "action": "full_pipeline",
                    "repository": REPO,
                    "branch": "main",
                },
            )
            response = await agent.invoke(request)

        # Pipeline should fail with non-200 status
        assert response.status_code == 502
        assert response.error is not None

    @pytest.mark.asyncio
    async def test_orchestrator_pipeline_invalid_jwt_rejected(self):
        """Test pipeline rejects requests with invalid JWT.

        Validates: auth prerequisite for pipeline.
        """
        config = _make_orchestrator_config()
        agent = OrchestratorAgent(config)

        request = InvokeRequest(
            authorization="Bearer invalid-token",
            headers={},
            body={
                "action": "full_pipeline",
                "repository": REPO,
                "branch": "main",
            },
        )
        response = await agent.invoke(request)

        assert response.status_code == 401
        assert response.error is not None


@pytest.mark.integration
class TestSBOMSerializationIntegration:
    """Integration tests for SBOM serialization round-trip.

    Validates: Requirement 17.2
    """

    def test_sbom_serializes_to_valid_cyclonedx_json(self):
        """Test SBOM serialization produces valid CycloneDX JSON structure."""
        import json

        dep_tree = _sample_dependency_tree()
        sbom = generate_sbom(dep_tree, REPO, COMMIT_SHA)
        reachability_map = _sample_reachability_map()
        vulnerability_map = _sample_vulnerability_map()
        enriched = enrich_sbom(sbom, reachability_map, vulnerability_map)

        json_str = to_json(enriched)
        parsed = json.loads(json_str)

        # Verify top-level CycloneDX structure
        assert parsed["bomFormat"] == "CycloneDX"
        assert parsed["specVersion"] == "1.5"
        assert parsed["serialNumber"].startswith("urn:uuid:")
        assert parsed["version"] == 1
        assert "metadata" in parsed
        assert "components" in parsed

        # Verify components have required fields
        for comp in parsed["components"]:
            assert "name" in comp
            assert "version" in comp
            assert "purl" in comp
            assert "type" in comp
            assert comp["type"] == "library"
            assert "properties" in comp

            # Verify reachability property present
            props = {p["name"]: p["value"] for p in comp["properties"]}
            assert "cdx:dependency:relationship" in props
            assert "sca:reachability:status" in props
            assert props["sca:reachability:status"] in (
                "reachable", "unreachable", "indeterminate"
            )

        # Verify lodash component has vulnerabilities
        lodash_comp = next(
            c for c in parsed["components"] if c["name"] == "lodash"
        )
        assert "vulnerabilities" in lodash_comp
        vuln_ids = [v["id"] for v in lodash_comp["vulnerabilities"]]
        assert "CVE-2021-23337" in vuln_ids
        assert "CVE-2020-28500" in vuln_ids


@pytest.mark.integration
class TestMultiManifestPipeline:
    """Integration tests for pipeline handling multiple manifest formats.

    Validates: Requirement 17.1
    """

    def test_python_requirements_through_pipeline(self):
        """Test pipeline with Python requirements.txt manifest."""
        content = """
requests==2.28.0
flask>=2.0.0
sqlalchemy~=1.4.0
click
"""
        parse_result = parse_manifest("requirements.txt", content)
        assert len(parse_result.parse_errors) == 0
        assert len(parse_result.dependencies) == 4

        # Generate SBOM from parsed deps
        sbom = generate_sbom(
            parse_result.dependencies, "acme/python-app", "def789"
        )
        assert len(sbom.components) == 4

        # Verify purls use pypi type
        for comp in sbom.components:
            assert "pkg:pypi/" in comp.purl

    def test_go_mod_through_pipeline(self):
        """Test pipeline with Go go.mod manifest."""
        content = """module github.com/acme/go-app

go 1.21

require (
    github.com/gin-gonic/gin v1.9.1
    github.com/lib/pq v1.10.9
    golang.org/x/crypto v0.14.0
)
"""
        parse_result = parse_manifest("go.mod", content)
        assert len(parse_result.parse_errors) == 0
        assert len(parse_result.dependencies) == 3

        sbom = generate_sbom(
            parse_result.dependencies, "acme/go-app", "ghi012"
        )
        assert len(sbom.components) == 3

        # Verify purls use golang type
        for comp in sbom.components:
            assert "pkg:golang/" in comp.purl

    def test_cargo_toml_through_pipeline(self):
        """Test pipeline with Rust Cargo.toml manifest."""
        content = """
[package]
name = "rust-app"
version = "0.1.0"

[dependencies]
serde = "1.0"
tokio = { version = "1.32", features = ["full"] }
reqwest = { version = "0.11", features = ["json"] }
"""
        parse_result = parse_manifest("Cargo.toml", content)
        assert len(parse_result.parse_errors) == 0
        assert len(parse_result.dependencies) == 3

        sbom = generate_sbom(
            parse_result.dependencies, "acme/rust-app", "jkl345"
        )
        assert len(sbom.components) == 3

        for comp in sbom.components:
            assert "pkg:cargo/" in comp.purl
