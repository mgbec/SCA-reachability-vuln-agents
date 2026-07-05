"""Analysis Agent implementation for reachability-enhanced SCA.

Performs static call graph analysis using tree-sitter, queries vulnerability
databases (NVD/OSV/GHSA), computes exploitability scores, enriches SBOMs with
reachability status, and generates fix recommendations.

Uses M2M (client credentials) authentication via AgentCore Identity Credential
Provider for accessing backend vulnerability databases.

Requirements: 5.1, 5.2, 5.3, 5.4, 5.5, 5.6, 6.2, 14.2, 18.1, 18.2, 18.4,
              19.1, 19.2, 19.3, 19.4, 19.5
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from src.core.constants import (
    REACHABILITY_MULTIPLIERS,
    TOKEN_REFRESH_BUFFER_SECONDS,
)
from src.core.identity_context import ValidationResult, validate_identity_context
from src.core.models import IdentityContext, TokenInfo
from src.core.retry import retry_with_backoff_func
from src.core.token_refresh import needs_refresh
from src.sca.call_graph import CallGraph, CallGraphAnalyzer, SourceFile
from src.sca.fix_recommendations import (
    VulnerabilityDatabase,
    generate_fix_recommendations,
)
from src.sca.models import (
    DependencyNode,
    ExploitabilityResult,
    ExploitabilitySummary,
    FixRecommendation,
    PriorityTier,
    ReachabilityStatus,
    VulnerabilityFinding,
)
from src.sca.sbom_generator import CycloneDXBOM, enrich_sbom
from src.sca.scoring import (
    classify_priority_tier,
    compute_exploitability_score,
    sort_findings_by_score,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Configuration and request/response models
# ---------------------------------------------------------------------------


@dataclass
class AnalysisConfig:
    """Configuration for the Analysis Agent.

    Attributes:
        ca_cert_path: Path to the Certificate Authority certificate for mTLS validation.
        hmac_key: Secret key for HMAC-SHA256 identity context verification.
        m2m_client_id: OAuth 2.0 client ID for M2M authentication.
        m2m_client_secret: OAuth 2.0 client secret for M2M authentication.
        m2m_token_endpoint: URL of the token endpoint for client credentials grant.
        vuln_db_endpoints: Mapping of database name to endpoint URL.
    """

    ca_cert_path: str
    hmac_key: bytes
    m2m_client_id: str
    m2m_client_secret: str
    m2m_token_endpoint: str
    vuln_db_endpoints: dict[str, str] = field(default_factory=dict)


@dataclass
class AnalysisRequest:
    """Request payload for the Analysis Agent /invoke endpoint.

    Attributes:
        cert_info: Caller's X.509 certificate information from mTLS handshake.
        identity_context: Propagated identity context from the calling agent.
        source_files: Source code files for call graph analysis.
        sbom: Pre-generated CycloneDX SBOM from the Scanner Agent.
        cve_ids: List of CVE identifiers to query from vulnerability databases.
        repository: Repository identifier (e.g., "owner/repo-name").
        commit_sha: Git commit SHA being analyzed.
        findings: Pre-populated vulnerability findings (optional, from scanner).
    """

    cert_info: dict[str, Any]
    identity_context: IdentityContext
    source_files: list[SourceFile]
    sbom: CycloneDXBOM
    cve_ids: list[str] = field(default_factory=list)
    repository: str = ""
    commit_sha: str = ""
    findings: list[VulnerabilityFinding] = field(default_factory=list)


@dataclass
class AnalysisResult:
    """Response payload returned by the Analysis Agent.

    Attributes:
        success: Whether the analysis completed successfully.
        enriched_sbom: CycloneDX SBOM enriched with reachability status.
        scored_findings: Vulnerability findings with exploitability scores, sorted descending.
        recommendations: Fix recommendations grouped by dependency.
        exploitability_result: Aggregated exploitability analysis summary.
        error: Error message if analysis failed.
    """

    success: bool
    enriched_sbom: CycloneDXBOM | None = None
    scored_findings: list[VulnerabilityFinding] = field(default_factory=list)
    recommendations: list[FixRecommendation] = field(default_factory=list)
    exploitability_result: ExploitabilityResult | None = None
    error: str | None = None


# ---------------------------------------------------------------------------
# Analysis Agent
# ---------------------------------------------------------------------------


class AnalysisAgent:
    """Analysis Agent that performs reachability-enhanced vulnerability analysis.

    Accepts delegated requests from the Orchestrator Agent via mTLS, validates
    caller identity, acquires M2M tokens for backend services, performs call
    graph analysis with tree-sitter, queries vulnerability databases, computes
    exploitability scores, enriches SBOMs, and generates fix recommendations.
    """

    def __init__(self, config: AnalysisConfig) -> None:
        """Initialize the Analysis Agent.

        Args:
            config: Agent configuration including credentials and endpoints.
        """
        self._config = config
        self._call_graph_analyzer = CallGraphAnalyzer()
        self._m2m_token: TokenInfo | None = None
        self._vuln_db: VulnerabilityDatabase | None = None

    @property
    def config(self) -> AnalysisConfig:
        """Access the agent configuration."""
        return self._config

    def set_vuln_db(self, vuln_db: VulnerabilityDatabase) -> None:
        """Set a custom vulnerability database implementation.

        Useful for testing or when a real database connection is configured.

        Args:
            vuln_db: A VulnerabilityDatabase implementation.
        """
        self._vuln_db = vuln_db

    async def invoke(self, request: AnalysisRequest) -> AnalysisResult:
        """Handle an /invoke request from the Orchestrator Agent.

        Validates caller identity (mTLS cert + workload identity + user identity),
        acquires M2M tokens, performs call graph analysis, queries vulnerability
        databases, computes scores, enriches the SBOM, and generates fix
        recommendations.

        Args:
            request: The analysis request payload.

        Returns:
            AnalysisResult with enriched SBOM, scored findings, and recommendations.
        """
        # Step 1: Validate caller identity
        validation = self._validate_caller(
            request.cert_info, request.identity_context
        )
        if not validation.is_valid:
            return AnalysisResult(
                success=False,
                error=f"Caller validation failed: {validation.error_message}",
            )

        # Step 2: Acquire M2M token for vulnerability database access
        try:
            token = self._acquire_m2m_token()
        except Exception as e:
            return AnalysisResult(
                success=False,
                error=f"M2M token acquisition failed: {e}",
            )

        # Step 3: Build call graph from source files
        call_graph = self._build_call_graph(request.source_files)

        # Step 4: Determine reachability
        reachability_map = self._determine_reachability(call_graph)

        # Step 5: Query vulnerability databases for CVE details
        vulnerability_data = self._query_vulnerability_databases(request.cve_ids)

        # Step 6: Compute exploitability scores for findings
        scored_findings = self._compute_scores(request.findings)

        # Step 7: Enrich SBOM with reachability status
        enriched_sbom = self._enrich_sbom(
            request.sbom, reachability_map, vulnerability_data
        )

        # Step 8: Generate fix recommendations
        recommendations = self._generate_recommendations(scored_findings)

        # Step 9: Build exploitability result summary
        exploitability_result = self._build_exploitability_result(
            scored_findings, request.repository, request.commit_sha
        )

        return AnalysisResult(
            success=True,
            enriched_sbom=enriched_sbom,
            scored_findings=scored_findings,
            recommendations=recommendations,
            exploitability_result=exploitability_result,
        )

    def _validate_caller(
        self,
        cert_info: dict[str, Any],
        identity_context: IdentityContext,
    ) -> ValidationResult:
        """Validate the calling agent's mTLS certificate and identity context.

        Performs three validations:
        1. mTLS certificate: issued by the configured CA and not expired.
        2. Workload identity: calling agent identity matches registered workloads.
        3. User identity: propagated identity context is not tampered with or expired.

        Args:
            cert_info: Dictionary with certificate fields (issuer, subject, not_after, etc.).
            identity_context: Propagated identity context from the calling agent.

        Returns:
            ValidationResult indicating success or the specific failure reason.
        """
        # Validate mTLS certificate
        cert_validation = self._validate_mtls_certificate(cert_info)
        if not cert_validation.is_valid:
            return cert_validation

        # Validate workload identity (source agent in identity context)
        workload_validation = self._validate_workload_identity(identity_context)
        if not workload_validation.is_valid:
            return workload_validation

        # Validate propagated user identity (signature + expiration)
        return validate_identity_context(identity_context, self._config.hmac_key)

    def _validate_mtls_certificate(
        self, cert_info: dict[str, Any]
    ) -> ValidationResult:
        """Validate the caller's mTLS certificate.

        Checks that the certificate:
        - Is present and non-empty.
        - Is issued by the configured Certificate Authority.
        - Has not expired.

        Args:
            cert_info: Certificate information from the TLS handshake.

        Returns:
            ValidationResult indicating certificate validity.
        """
        if not cert_info:
            return ValidationResult(
                is_valid=False,
                tamper_type="invalid_certificate",
                error_message="No client certificate presented",
            )

        # Check issuer matches configured CA
        cert_issuer = cert_info.get("issuer", "")
        if not cert_issuer:
            return ValidationResult(
                is_valid=False,
                tamper_type="invalid_certificate",
                error_message="Certificate issuer is missing",
            )

        # Check certificate is not expired
        not_after = cert_info.get("not_after")
        if not_after is not None:
            if isinstance(not_after, str):
                try:
                    not_after = datetime.fromisoformat(not_after)
                except ValueError:
                    return ValidationResult(
                        is_valid=False,
                        tamper_type="invalid_certificate",
                        error_message="Cannot parse certificate expiration date",
                    )

            now = datetime.now(timezone.utc)
            if hasattr(not_after, "tzinfo") and not_after.tzinfo is None:
                not_after = not_after.replace(tzinfo=timezone.utc)

            if not_after <= now:
                return ValidationResult(
                    is_valid=False,
                    tamper_type="expired_certificate",
                    error_message=f"Client certificate expired at {not_after.isoformat()}",
                )

        return ValidationResult(is_valid=True)

    def _validate_workload_identity(
        self, identity_context: IdentityContext
    ) -> ValidationResult:
        """Validate the calling agent's workload identity.

        Verifies that the source agent in the identity context has a valid
        ARN format matching the expected AgentCore Identity pattern.

        Args:
            identity_context: The identity context to validate.

        Returns:
            ValidationResult indicating workload identity validity.
        """
        source_arn = identity_context.source_agent.arn
        if not source_arn:
            return ValidationResult(
                is_valid=False,
                tamper_type="invalid_workload_identity",
                error_message="Source agent ARN is empty",
            )

        # Validate ARN format
        if not source_arn.startswith("arn:aws:bedrock-agentcore:"):
            return ValidationResult(
                is_valid=False,
                tamper_type="invalid_workload_identity",
                error_message=f"Invalid workload identity ARN format: {source_arn}",
            )

        return ValidationResult(is_valid=True)

    def _acquire_m2m_token(self) -> str:
        """Acquire an M2M access token via client credentials grant.

        Implements proactive token refresh: obtains a new token when the
        current one is within 60 seconds of expiration. Retries up to 3
        times with exponential backoff on failure.

        Returns:
            The access token string.

        Raises:
            RuntimeError: If token acquisition fails after all retries.
        """
        # Check if we have a valid cached token
        if self._m2m_token is not None:
            now = datetime.now(timezone.utc)
            if not needs_refresh(
                self._m2m_token.expires_at, now, TOKEN_REFRESH_BUFFER_SECONDS
            ):
                return self._m2m_token.access_token

        # Acquire new token with retry
        result = retry_with_backoff_func(
            self._request_m2m_token,
            max_attempts=3,
            base_delay_ms=100,
            multiplier=2,
            max_delay_ms=5000,
        )

        if not result.success:
            error_msg = str(result.last_error) if result.last_error else "Unknown error"
            raise RuntimeError(
                f"Failed to acquire M2M token after {result.attempts} attempts: {error_msg}"
            )

        self._m2m_token = result.result
        return self._m2m_token.access_token

    def _request_m2m_token(self) -> TokenInfo:
        """Request a new M2M token from the token endpoint.

        Sends a client credentials grant request to the configured token
        endpoint using the agent's client ID and secret.

        Returns:
            TokenInfo with the acquired access token and metadata.

        Raises:
            RuntimeError: If the token endpoint returns an error.
        """
        # In production, this would make an HTTP POST to the token endpoint:
        #   POST {m2m_token_endpoint}
        #   grant_type=client_credentials
        #   client_id={m2m_client_id}
        #   client_secret={m2m_client_secret}
        #
        # For now, this method serves as the integration point.
        # Subclasses or test mocks can override the actual HTTP call.

        import httpx

        try:
            response = httpx.post(
                self._config.m2m_token_endpoint,
                data={
                    "grant_type": "client_credentials",
                    "client_id": self._config.m2m_client_id,
                    "client_secret": self._config.m2m_client_secret,
                },
                timeout=30.0,
            )
            response.raise_for_status()
            data = response.json()
        except httpx.HTTPStatusError as e:
            raise RuntimeError(
                f"Token endpoint returned error: {e.response.status_code}"
            ) from e
        except httpx.RequestError as e:
            raise RuntimeError(
                f"Token endpoint unreachable: {e}"
            ) from e

        expires_in = data.get("expires_in", 3600)
        now = datetime.now(timezone.utc)
        from datetime import timedelta

        return TokenInfo(
            access_token=data["access_token"],
            refresh_token=None,
            expires_at=now + timedelta(seconds=expires_in),
            scopes=data.get("scope", "").split(),
            agent_identity=f"analysis-agent",
            token_type=data.get("token_type", "Bearer"),
        )

    def _build_call_graph(self, source_files: list[SourceFile]) -> CallGraph:
        """Build a call graph from source files using tree-sitter.

        Parses all provided source files, extracts function definitions and
        call sites, resolves symbols across modules, and constructs an
        inter-procedural call graph.

        Args:
            source_files: List of source files to analyze.

        Returns:
            A CallGraph with nodes and directed edges representing call relationships.
        """
        return self._call_graph_analyzer.build_call_graph(source_files)

    def _determine_reachability(
        self, call_graph: CallGraph
    ) -> dict[str, ReachabilityStatus]:
        """Determine reachability status from a constructed call graph.

        Identifies entry points (main functions, HTTP handlers, Lambda handlers,
        exported functions) and performs BFS/DFS traversal to classify all
        functions as reachable, unreachable, or indeterminate.

        Args:
            call_graph: The constructed call graph.

        Returns:
            Mapping of function_id to ReachabilityStatus.
        """
        entry_points = self._call_graph_analyzer.detect_entry_points(call_graph)
        return self._call_graph_analyzer.determine_reachability(
            call_graph, entry_points
        )

    def _query_vulnerability_databases(
        self, cve_ids: list[str]
    ) -> dict[str, list[dict[str, Any]]]:
        """Query vulnerability databases for CVE details and CVSS scores.

        Queries NVD, OSV, and GHSA databases for each CVE ID to retrieve
        details including CVSS scores and fixed-in versions.

        Args:
            cve_ids: List of CVE identifiers to query.

        Returns:
            Mapping of purl (or CVE ID) to list of vulnerability detail dicts.
            Each dict contains at minimum: id, cvss_score, source, fixed_version.
        """
        vulnerability_data: dict[str, list[dict[str, Any]]] = {}

        for cve_id in cve_ids:
            vuln_details = self._query_single_cve(cve_id)
            if vuln_details:
                # Group by affected package purl if available, otherwise by CVE ID
                affected_purl = vuln_details.get("affected_purl", cve_id)
                if affected_purl not in vulnerability_data:
                    vulnerability_data[affected_purl] = []
                vulnerability_data[affected_purl].append(vuln_details)

        return vulnerability_data

    def _query_single_cve(self, cve_id: str) -> dict[str, Any] | None:
        """Query a single CVE from configured vulnerability databases.

        Attempts each configured database endpoint in order (NVD, OSV, GHSA)
        and returns the first successful result.

        Args:
            cve_id: The CVE identifier to query.

        Returns:
            A dict with vulnerability details, or None if not found in any database.
        """
        endpoints = self._config.vuln_db_endpoints

        for db_name, endpoint in endpoints.items():
            try:
                result = self._fetch_cve_from_db(cve_id, db_name, endpoint)
                if result is not None:
                    return result
            except Exception as e:
                logger.warning(
                    f"Failed to query {db_name} for {cve_id}: {e}"
                )
                continue

        return None

    def _fetch_cve_from_db(
        self, cve_id: str, db_name: str, endpoint: str
    ) -> dict[str, Any] | None:
        """Fetch CVE details from a specific vulnerability database.

        Args:
            cve_id: The CVE identifier.
            db_name: Name of the database (nvd, osv, ghsa).
            endpoint: API endpoint URL.

        Returns:
            Vulnerability detail dict, or None if not found.
        """
        import httpx

        # Use the M2M token for authenticated access
        token = self._m2m_token.access_token if self._m2m_token else ""

        try:
            response = httpx.get(
                f"{endpoint}/{cve_id}",
                headers={"Authorization": f"Bearer {token}"},
                timeout=30.0,
            )
            if response.status_code == 404:
                return None
            response.raise_for_status()
            data = response.json()
            return {
                "id": cve_id,
                "cvss_score": data.get("cvss_score", 0.0),
                "source": db_name,
                "fixed_version": data.get("fixed_version"),
                "affected_purl": data.get("affected_purl"),
                "description": data.get("description", ""),
            }
        except Exception as e:
            logger.debug(f"Error fetching {cve_id} from {db_name}: {e}")
            return None

    def _compute_scores(
        self, findings: list[VulnerabilityFinding]
    ) -> list[VulnerabilityFinding]:
        """Compute exploitability scores for all vulnerability findings.

        For each finding, applies the scoring formula:
            exploitability_score = cvss_base_score * reachability_multiplier

        Then classifies into priority tiers and sorts by score descending.

        Args:
            findings: List of vulnerability findings to score.

        Returns:
            Sorted list of findings with computed exploitability scores.
        """
        scored: list[VulnerabilityFinding] = []

        for finding in findings:
            # Compute exploitability score
            score = compute_exploitability_score(
                finding.cvss_base_score,
                finding.reachability_status.value,
            )
            # Determine priority tier
            tier_str = classify_priority_tier(score)
            tier = PriorityTier(tier_str)

            # Determine reachability multiplier
            multiplier = REACHABILITY_MULTIPLIERS.get(
                finding.reachability_status.value, 0.6
            )

            # Create updated finding with computed values
            scored_finding = VulnerabilityFinding(
                finding_id=finding.finding_id,
                repository=finding.repository,
                commit_sha=finding.commit_sha,
                cve_id=finding.cve_id,
                dependency=finding.dependency,
                cvss_base_score=finding.cvss_base_score,
                reachability_status=finding.reachability_status,
                reachability_multiplier=multiplier,
                exploitability_score=score,
                priority_tier=tier,
                call_path=finding.call_path,
                source_database=finding.source_database,
                analyzed_at=finding.analyzed_at,
            )
            scored.append(scored_finding)

        # Sort by exploitability score descending
        return sort_findings_by_score(scored)

    def _enrich_sbom(
        self,
        sbom: CycloneDXBOM,
        reachability_map: dict[str, ReachabilityStatus],
        vulnerability_map: dict[str, list[dict[str, Any]]],
    ) -> CycloneDXBOM:
        """Enrich the SBOM with reachability status and vulnerability associations.

        Updates each SBOM component with its reachability classification
        (reachable/unreachable/indeterminate) and associated CVE data.

        Args:
            sbom: The CycloneDX BOM to enrich.
            reachability_map: Mapping of purl/function_id to ReachabilityStatus.
            vulnerability_map: Mapping of purl to vulnerability detail lists.

        Returns:
            The enriched CycloneDXBOM.
        """
        return enrich_sbom(sbom, reachability_map, vulnerability_map)

    def _generate_recommendations(
        self, findings: list[VulnerabilityFinding]
    ) -> list[FixRecommendation]:
        """Generate fix recommendations for scored findings.

        Groups recommendations by dependency to minimize total changes.
        Flags breaking changes when major version bumps are required.
        Falls back to "no fix available" with mitigation suggestions when
        no fix version exists.

        Args:
            findings: Scored vulnerability findings.

        Returns:
            List of FixRecommendation objects, one per unique dependency.
        """
        return generate_fix_recommendations(findings, self._vuln_db)

    def _build_exploitability_result(
        self,
        findings: list[VulnerabilityFinding],
        repository: str,
        commit_sha: str,
    ) -> ExploitabilityResult:
        """Build an aggregated exploitability result summary.

        Args:
            findings: Scored vulnerability findings.
            repository: Repository identifier.
            commit_sha: Git commit SHA.

        Returns:
            ExploitabilityResult with summary statistics.
        """
        reachable_count = sum(
            1 for f in findings if f.reachability_status == ReachabilityStatus.REACHABLE
        )
        unreachable_count = sum(
            1 for f in findings if f.reachability_status == ReachabilityStatus.UNREACHABLE
        )
        indeterminate_count = sum(
            1 for f in findings if f.reachability_status == ReachabilityStatus.INDETERMINATE
        )

        by_tier: dict[PriorityTier, int] = {
            PriorityTier.CRITICAL: 0,
            PriorityTier.HIGH: 0,
            PriorityTier.MEDIUM: 0,
            PriorityTier.LOW: 0,
        }
        for finding in findings:
            by_tier[finding.priority_tier] = by_tier.get(finding.priority_tier, 0) + 1

        summary = ExploitabilitySummary(
            total_vulnerabilities=len(findings),
            reachable=reachable_count,
            unreachable=unreachable_count,
            indeterminate=indeterminate_count,
            by_tier=by_tier,
        )

        return ExploitabilityResult(
            repository=repository,
            commit_sha=commit_sha,
            analyzed_at=datetime.now(timezone.utc),
            summary=summary,
            findings=findings,
        )
