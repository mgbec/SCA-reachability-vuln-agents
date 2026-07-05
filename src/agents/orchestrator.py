"""Orchestrator Agent implementation.

Receives authenticated user requests via JWT bearer tokens, validates them,
constructs identity context envelopes, and delegates work to Scanner Agent
and Analysis Agent over mTLS. Coordinates the full vulnerability analysis
workflow: scan → analyze → score → recommend.

Deployed as an AWS AgentCore Runtime handler. HMAC signing keys and other
secrets are retrieved from AWS Secrets Manager at startup with retry logic.

Requirements: 3.1, 3.2, 6.1, 11.2, 11.3, 14.1
"""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

import boto3
import httpx

from src.core.constants import IDENTITY_CONTEXT_VERSION
from src.core.correlation import (
    extract_or_generate_correlation_id,
    propagate_correlation_id,
)
from src.core.identity_context import build_identity_context
from src.core.jwt_validation import ValidationResult as JWTValidationResult
from src.core.jwt_validation import validate_jwt
from src.core.metrics import AuthMetrics
from src.core.models import IdentityContext, WorkloadIdentity
from src.core.retry import retry_with_backoff_func
from src.core.telemetry import TelemetryProvider

logger = logging.getLogger(__name__)


# --- Configuration ---


@dataclass
class OrchestratorConfig:
    """Configuration for the Orchestrator Agent.

    Attributes:
        scanner_endpoint: Base URL of the Scanner Agent (e.g., "https://scanner:8443").
        analysis_endpoint: Base URL of the Analysis Agent (e.g., "https://analysis:8443").
        cognito_issuer: Expected JWT issuer URL (Cognito user pool endpoint).
        cognito_audience: Expected JWT audience (Cognito app client ID).
        signing_key: Key for JWT signature verification (public key or HMAC secret).
        hmac_key: HMAC key bytes for signing identity context envelopes.
        client_cert_path: Path to the orchestrator's X.509 client certificate (PEM).
        client_key_path: Path to the orchestrator's private key (PEM).
        ca_cert_path: Path to the CA certificate for verifying server certs (PEM).
        agent_name: Name of this agent for identity purposes.
        agent_arn: Full ARN of the orchestrator workload identity.
    """

    scanner_endpoint: str
    analysis_endpoint: str
    cognito_issuer: str
    cognito_audience: str
    signing_key: Any
    hmac_key: bytes
    client_cert_path: str
    client_key_path: str
    ca_cert_path: str
    agent_name: str = "orchestrator-agent"
    agent_arn: str = ""


# --- Request/Response Models ---


@dataclass
class InvokeRequest:
    """Inbound request to the Orchestrator Agent /invoke endpoint.

    Attributes:
        authorization: The full Authorization header value (e.g., "Bearer <token>").
        headers: All request headers (for correlation ID extraction).
        body: Request payload containing the action and parameters.
    """

    authorization: str
    headers: dict = field(default_factory=dict)
    body: dict = field(default_factory=dict)


@dataclass
class InvokeResponse:
    """Response from the Orchestrator Agent.

    Attributes:
        status_code: HTTP status code (200, 401, 500, etc.).
        body: Response payload.
        headers: Response headers (includes correlation ID).
        error: Error message if request failed.
    """

    status_code: int
    body: dict = field(default_factory=dict)
    headers: dict = field(default_factory=dict)
    error: Optional[str] = None


@dataclass
class ScanResult:
    """Result from the Scanner Agent delegation.

    Attributes:
        success: Whether the scan completed successfully.
        sbom: Generated CycloneDX SBOM data.
        scan_results: Raw vulnerability scan results.
        source_artifacts: Source code artifacts for analysis.
        error: Error description if scan failed.
    """

    success: bool
    sbom: dict = field(default_factory=dict)
    scan_results: dict = field(default_factory=dict)
    source_artifacts: dict = field(default_factory=dict)
    error: Optional[str] = None


@dataclass
class AnalysisResult:
    """Result from the Analysis Agent delegation.

    Attributes:
        success: Whether the analysis completed successfully.
        enriched_sbom: SBOM enriched with reachability status.
        scored_findings: Vulnerability findings with exploitability scores.
        recommendations: Fix recommendations grouped by dependency.
        error: Error description if analysis failed.
    """

    success: bool
    enriched_sbom: dict = field(default_factory=dict)
    scored_findings: list = field(default_factory=list)
    recommendations: list = field(default_factory=list)
    error: Optional[str] = None


@dataclass
class PipelineResult:
    """Result from the full vulnerability analysis pipeline.

    Attributes:
        success: Whether the full pipeline completed successfully.
        scan_result: Intermediate scan result.
        analysis_result: Final analysis result with scores and recommendations.
        correlation_id: Correlation ID used throughout the pipeline.
        error: Error description if pipeline failed at any stage.
        failed_stage: Name of the stage that failed, if any.
    """

    success: bool
    scan_result: Optional[ScanResult] = None
    analysis_result: Optional[AnalysisResult] = None
    correlation_id: str = ""
    error: Optional[str] = None
    failed_stage: Optional[str] = None


# --- Orchestrator Agent ---


class OrchestratorAgent:
    """Orchestrator Agent that coordinates vulnerability analysis across sub-agents.

    Validates inbound JWT tokens, constructs signed identity context envelopes,
    and delegates work to Scanner Agent and Analysis Agent over mTLS connections.
    Propagates correlation IDs to all downstream calls for distributed tracing.

    Args:
        config: OrchestratorConfig with endpoints, certificates, and keys.
    """

    def __init__(self, config: OrchestratorConfig) -> None:
        self._config = config
        self._workload_identity = WorkloadIdentity(
            arn=config.agent_arn,
            name=config.agent_name,
        )

        # Initialize telemetry and metrics
        self._telemetry = TelemetryProvider(service_name=config.agent_name)
        self._metrics = AuthMetrics(agent_name=config.agent_name)

    @property
    def config(self) -> OrchestratorConfig:
        """Return the agent configuration."""
        return self._config

    @property
    def workload_identity(self) -> WorkloadIdentity:
        """Return the agent's workload identity."""
        return self._workload_identity

    async def invoke(self, request: InvokeRequest) -> InvokeResponse:
        """Handle an inbound /invoke request.

        Validates the JWT bearer token, extracts user identity, and routes
        the request to the appropriate workflow (scan, analyze, or full pipeline).

        Args:
            request: The inbound invoke request with authorization and payload.

        Returns:
            InvokeResponse with appropriate status code and body.
        """
        # Extract or generate correlation ID
        correlation_id = extract_or_generate_correlation_id(request.headers)

        response_headers: dict = {}
        propagate_correlation_id(response_headers, correlation_id)

        # Validate inbound JWT
        jwt_result = self._validate_inbound_jwt(request.authorization)
        if not jwt_result.is_valid:
            self._metrics.record_auth_failure()
            return InvokeResponse(
                status_code=401,
                body={"error": jwt_result.error_reason},
                headers=response_headers,
                error=jwt_result.error_reason,
            )

        self._metrics.record_auth_success()

        # Build identity context from validated claims
        user_claims = jwt_result.claims
        identity_context = self._build_identity_context(user_claims, correlation_id)

        # Route based on request action
        action = request.body.get("action", "full_pipeline")

        try:
            if action == "scan":
                scan_result = await self._delegate_to_scanner(
                    identity_context, request.body
                )
                return InvokeResponse(
                    status_code=200 if scan_result.success else 502,
                    body={
                        "action": "scan",
                        "result": {
                            "sbom": scan_result.sbom,
                            "scan_results": scan_result.scan_results,
                        },
                    },
                    headers=response_headers,
                    error=scan_result.error,
                )

            elif action == "analyze":
                analysis_result = await self._delegate_to_analysis(
                    identity_context, request.body
                )
                return InvokeResponse(
                    status_code=200 if analysis_result.success else 502,
                    body={
                        "action": "analyze",
                        "result": {
                            "enriched_sbom": analysis_result.enriched_sbom,
                            "scored_findings": analysis_result.scored_findings,
                            "recommendations": analysis_result.recommendations,
                        },
                    },
                    headers=response_headers,
                    error=analysis_result.error,
                )

            else:
                # Default: full pipeline (scan → analyze → score → recommend)
                pipeline_result = await self._run_full_pipeline(
                    identity_context, request.body, correlation_id
                )
                return InvokeResponse(
                    status_code=200 if pipeline_result.success else 502,
                    body={
                        "action": "full_pipeline",
                        "correlation_id": correlation_id,
                        "result": {
                            "analysis": {
                                "enriched_sbom": (
                                    pipeline_result.analysis_result.enriched_sbom
                                    if pipeline_result.analysis_result
                                    else {}
                                ),
                                "scored_findings": (
                                    pipeline_result.analysis_result.scored_findings
                                    if pipeline_result.analysis_result
                                    else []
                                ),
                                "recommendations": (
                                    pipeline_result.analysis_result.recommendations
                                    if pipeline_result.analysis_result
                                    else []
                                ),
                            },
                        },
                    },
                    headers=response_headers,
                    error=pipeline_result.error,
                )

        except Exception as exc:
            return InvokeResponse(
                status_code=500,
                body={"error": "internal_error"},
                headers=response_headers,
                error=str(exc),
            )

    def _validate_inbound_jwt(self, authorization: str) -> JWTValidationResult:
        """Validate the inbound JWT bearer token.

        Extracts the token from the Authorization header, verifies issuer,
        signature, expiration, audience, and client claims.

        Args:
            authorization: The full Authorization header value.

        Returns:
            JWTValidationResult with decoded claims on success, error reason on failure.
        """
        start_time = time.time()

        with self._telemetry.create_auth_span(
            step_type="token_validation",
            agent_identity=self._config.agent_arn,
        ) as span:
            # Extract bearer token from Authorization header
            if not authorization:
                self._telemetry.record_failure(span, "missing_token")
                duration_ms = (time.time() - start_time) * 1000
                self._metrics.record_jwt_validation_duration(duration_ms)
                return JWTValidationResult(
                    is_valid=False,
                    error_reason="missing_token",
                )

            parts = authorization.split(" ", 1)
            if len(parts) != 2 or parts[0].lower() != "bearer":
                self._telemetry.record_failure(span, "missing_token")
                duration_ms = (time.time() - start_time) * 1000
                self._metrics.record_jwt_validation_duration(duration_ms)
                return JWTValidationResult(
                    is_valid=False,
                    error_reason="missing_token",
                )

            token = parts[1]

            # Validate the JWT
            result = validate_jwt(
                token=token,
                issuer=self._config.cognito_issuer,
                audience=self._config.cognito_audience,
                signing_key=self._config.signing_key,
            )

            duration_ms = (time.time() - start_time) * 1000
            self._metrics.record_jwt_validation_duration(duration_ms)

            if result.is_valid:
                self._telemetry.record_success(span)
            else:
                self._telemetry.record_failure(span, result.error_reason or "unknown")

            return result

    def _build_identity_context(
        self, user_claims: dict, correlation_id: str
    ) -> IdentityContext:
        """Construct a signed identity context envelope from validated JWT claims.

        Extracts user identity fields from the JWT payload and creates a
        signed IdentityContext for propagation to downstream agents.

        Args:
            user_claims: Decoded JWT claims dictionary.
            correlation_id: The correlation ID for this request.

        Returns:
            A signed IdentityContext envelope.
        """
        # Map standard JWT claims to identity context fields
        context_claims = {
            "subject": user_claims.get("sub", ""),
            "issuer": user_claims.get("iss", ""),
            "audience": user_claims.get("aud", ""),
            "scopes": user_claims.get("scope", "").split(" ")
            if isinstance(user_claims.get("scope"), str)
            else user_claims.get("scope", []),
            "issued_at": datetime.fromtimestamp(
                user_claims.get("iat", 0), tz=timezone.utc
            ),
            "expires_at": datetime.fromtimestamp(
                user_claims.get("exp", 0), tz=timezone.utc
            ),
            "token_reference": user_claims.get("jti", ""),
        }

        identity_context = build_identity_context(
            user_claims=context_claims,
            source_agent=self._workload_identity,
            hmac_key=self._config.hmac_key,
        )

        # Override the auto-generated correlation ID with the request's correlation ID
        identity_context.correlation_id = correlation_id

        return identity_context

    def _create_mtls_client(self) -> httpx.AsyncClient:
        """Create an httpx AsyncClient configured with mTLS client certificate.

        Presents the orchestrator's X.509 client certificate (CN: orchestrator-agent)
        during the TLS handshake and verifies server certificates against the CA.

        Returns:
            An httpx.AsyncClient configured for mTLS.
        """
        return httpx.AsyncClient(
            cert=(self._config.client_cert_path, self._config.client_key_path),
            verify=self._config.ca_cert_path,
            timeout=httpx.Timeout(30.0),
        )

    def _serialize_identity_context(self, context: IdentityContext) -> dict:
        """Serialize the identity context to a dictionary for transmission.

        Args:
            context: The IdentityContext to serialize.

        Returns:
            Dictionary representation suitable for JSON serialization.
        """
        return {
            "version": context.version,
            "correlation_id": context.correlation_id,
            "source_agent": {
                "arn": context.source_agent.arn,
                "name": context.source_agent.name,
            },
            "user_identity": {
                "subject": context.user_identity.subject,
                "issuer": context.user_identity.issuer,
                "audience": context.user_identity.audience,
                "scopes": context.user_identity.scopes,
                "issued_at": context.user_identity.issued_at.isoformat(),
                "expires_at": context.user_identity.expires_at.isoformat(),
                "token_reference": context.user_identity.token_reference,
            },
            "delegation_chain": [
                {
                    "agent_arn": entry.agent_arn,
                    "delegated_at": entry.delegated_at.isoformat(),
                }
                for entry in context.delegation_chain
            ],
            "signature": context.signature,
        }

    async def _delegate_to_scanner(
        self,
        identity_context: IdentityContext,
        scan_request: dict,
    ) -> ScanResult:
        """Delegate a scan task to the Scanner Agent over mTLS.

        Sends the identity context and scan parameters to the Scanner Agent,
        presenting the orchestrator's X.509 client certificate during the
        TLS handshake.

        Args:
            identity_context: Signed identity context for user propagation.
            scan_request: Request payload for the scanner.

        Returns:
            ScanResult with scan data or error information.
        """
        with self._telemetry.create_auth_span(
            step_type="resource_access",
            agent_identity=self._config.agent_arn,
        ) as span:
            span.set_attribute("auth.target_resource", "scanner-agent")

            try:
                async with self._create_mtls_client() as client:
                    # Build request headers with correlation ID
                    headers: dict = {"Content-Type": "application/json"}
                    propagate_correlation_id(headers, identity_context.correlation_id)

                    # Build request body with identity context
                    payload = {
                        "identity_context": self._serialize_identity_context(
                            identity_context
                        ),
                        "request": scan_request,
                    }

                    response = await client.post(
                        f"{self._config.scanner_endpoint}/invoke",
                        json=payload,
                        headers=headers,
                    )

                    if response.status_code == 200:
                        data = response.json()
                        self._telemetry.record_success(span)
                        return ScanResult(
                            success=True,
                            sbom=data.get("sbom", {}),
                            scan_results=data.get("scan_results", {}),
                            source_artifacts=data.get("source_artifacts", {}),
                        )
                    else:
                        error_msg = f"Scanner returned status {response.status_code}"
                        self._telemetry.record_failure(span, error_msg)
                        return ScanResult(success=False, error=error_msg)

            except httpx.ConnectError as exc:
                error_msg = f"Failed to connect to Scanner Agent: {exc}"
                self._telemetry.record_failure(span, error_msg)
                return ScanResult(success=False, error=error_msg)
            except Exception as exc:
                error_msg = f"Scanner delegation failed: {exc}"
                self._telemetry.record_failure(span, error_msg)
                return ScanResult(success=False, error=error_msg)

    async def _delegate_to_analysis(
        self,
        identity_context: IdentityContext,
        analysis_request: dict,
    ) -> AnalysisResult:
        """Delegate an analysis task to the Analysis Agent over mTLS.

        Sends the identity context, scan results, and source artifacts to the
        Analysis Agent for call graph analysis, scoring, and recommendation
        generation.

        Args:
            identity_context: Signed identity context for user propagation.
            analysis_request: Request payload for the analysis agent.

        Returns:
            AnalysisResult with enriched SBOM, scored findings, and recommendations.
        """
        with self._telemetry.create_auth_span(
            step_type="resource_access",
            agent_identity=self._config.agent_arn,
        ) as span:
            span.set_attribute("auth.target_resource", "analysis-agent")

            try:
                async with self._create_mtls_client() as client:
                    # Build request headers with correlation ID
                    headers: dict = {"Content-Type": "application/json"}
                    propagate_correlation_id(headers, identity_context.correlation_id)

                    # Build request body with identity context
                    payload = {
                        "identity_context": self._serialize_identity_context(
                            identity_context
                        ),
                        "request": analysis_request,
                    }

                    response = await client.post(
                        f"{self._config.analysis_endpoint}/invoke",
                        json=payload,
                        headers=headers,
                    )

                    if response.status_code == 200:
                        data = response.json()
                        self._telemetry.record_success(span)
                        return AnalysisResult(
                            success=True,
                            enriched_sbom=data.get("enriched_sbom", {}),
                            scored_findings=data.get("scored_findings", []),
                            recommendations=data.get("recommendations", []),
                        )
                    else:
                        error_msg = (
                            f"Analysis Agent returned status {response.status_code}"
                        )
                        self._telemetry.record_failure(span, error_msg)
                        return AnalysisResult(success=False, error=error_msg)

            except httpx.ConnectError as exc:
                error_msg = f"Failed to connect to Analysis Agent: {exc}"
                self._telemetry.record_failure(span, error_msg)
                return AnalysisResult(success=False, error=error_msg)
            except Exception as exc:
                error_msg = f"Analysis delegation failed: {exc}"
                self._telemetry.record_failure(span, error_msg)
                return AnalysisResult(success=False, error=error_msg)

    async def _run_full_pipeline(
        self,
        identity_context: IdentityContext,
        request: dict,
        correlation_id: str,
    ) -> PipelineResult:
        """Execute the full vulnerability analysis pipeline.

        Coordinates the complete workflow:
        1. Scan: Delegate to Scanner Agent for GitHub data and SBOM generation
        2. Analyze: Delegate to Analysis Agent for call graph analysis and scoring
        3. Return: Combine results into final pipeline output

        Args:
            identity_context: Signed identity context for user propagation.
            request: Original request payload with repo info.
            correlation_id: Correlation ID for tracing.

        Returns:
            PipelineResult with the complete analysis output.
        """
        # Stage 1: Scan
        scan_request = {
            "action": "scan",
            "repository": request.get("repository", ""),
            "branch": request.get("branch", "main"),
        }

        scan_result = await self._delegate_to_scanner(identity_context, scan_request)
        if not scan_result.success:
            return PipelineResult(
                success=False,
                scan_result=scan_result,
                correlation_id=correlation_id,
                error=scan_result.error,
                failed_stage="scan",
            )

        # Stage 2: Analyze (includes scoring and recommendations)
        analysis_request = {
            "action": "analyze",
            "sbom": scan_result.sbom,
            "scan_results": scan_result.scan_results,
            "source_artifacts": scan_result.source_artifacts,
            "repository": request.get("repository", ""),
        }

        analysis_result = await self._delegate_to_analysis(
            identity_context, analysis_request
        )
        if not analysis_result.success:
            return PipelineResult(
                success=False,
                scan_result=scan_result,
                analysis_result=analysis_result,
                correlation_id=correlation_id,
                error=analysis_result.error,
                failed_stage="analyze",
            )

        # Pipeline completed successfully
        return PipelineResult(
            success=True,
            scan_result=scan_result,
            analysis_result=analysis_result,
            correlation_id=correlation_id,
        )


# --- Secrets Manager Integration (Requirement 16.2) ---


def retrieve_secret(secret_id: str, region: Optional[str] = None) -> str:
    """Retrieve a secret value from AWS Secrets Manager with retry.

    Uses the retry_with_backoff_func to handle transient failures
    when the Secrets Manager service is temporarily unreachable.

    Args:
        secret_id: The ARN or name of the secret to retrieve.
        region: AWS region override. Defaults to AWS_REGION env var.

    Returns:
        The secret string value.

    Raises:
        RuntimeError: If all retry attempts are exhausted.
    """
    region_name = region or os.environ.get("AWS_REGION", "us-east-1")

    def _fetch() -> str:
        client = boto3.client("secretsmanager", region_name=region_name)
        response = client.get_secret_value(SecretId=secret_id)
        return response["SecretString"]

    result = retry_with_backoff_func(
        _fetch,
        max_attempts=3,
        base_delay_ms=100,
        multiplier=2,
        max_delay_ms=5000,
    )

    if not result.success:
        raise RuntimeError(
            f"Failed to retrieve secret '{secret_id}' after {result.attempts} attempts: "
            f"{result.last_error}"
        )

    return result.result


def retrieve_hmac_key(secret_id: str, region: Optional[str] = None) -> bytes:
    """Retrieve the HMAC signing key from Secrets Manager as bytes.

    The secret is expected to be stored as a base64-encoded string or plain
    UTF-8 string. Returns the raw bytes for HMAC-SHA256 signing.

    Args:
        secret_id: The ARN or name of the HMAC key secret.
        region: AWS region override.

    Returns:
        HMAC key as bytes.
    """
    secret_value = retrieve_secret(secret_id, region)
    return secret_value.encode("utf-8")


# --- Factory: Create OrchestratorAgent from environment/Secrets Manager ---


def create_orchestrator_from_environment() -> OrchestratorAgent:
    """Create an OrchestratorAgent configured from environment variables and Secrets Manager.

    Environment variables:
        SCANNER_ENDPOINT: Base URL of the Scanner Agent
        ANALYSIS_ENDPOINT: Base URL of the Analysis Agent
        COGNITO_ISSUER: Expected JWT issuer URL (Cognito user pool endpoint)
        COGNITO_AUDIENCE: Expected JWT audience (Cognito app client ID)
        JWT_SIGNING_KEY_SECRET_ID: Secrets Manager ID for JWT signing key
        HMAC_KEY_SECRET_ID: Secrets Manager ID for HMAC signing key
        CLIENT_CERT_PATH: Path to the orchestrator X.509 client cert (PEM)
        CLIENT_KEY_PATH: Path to the orchestrator private key (PEM)
        CA_CERT_PATH: Path to the CA certificate (PEM)
        AGENT_NAME: Agent name (default: orchestrator-agent)
        AGENT_ARN: Full ARN of the orchestrator workload identity
        AWS_REGION: AWS region for Secrets Manager calls

    Returns:
        A fully configured OrchestratorAgent ready to handle requests.

    Raises:
        RuntimeError: If required secrets cannot be retrieved.
    """
    region = os.environ.get("AWS_REGION", "us-east-1")

    # Retrieve secrets from Secrets Manager
    hmac_key_secret_id = os.environ.get(
        "HMAC_KEY_SECRET_ID", "identity-context-hmac-key"
    )
    hmac_key = retrieve_hmac_key(hmac_key_secret_id, region)

    jwt_signing_key_secret_id = os.environ.get("JWT_SIGNING_KEY_SECRET_ID", "")
    signing_key: Any = os.environ.get("JWT_SIGNING_KEY", "")
    if jwt_signing_key_secret_id:
        signing_key = retrieve_secret(jwt_signing_key_secret_id, region)

    config = OrchestratorConfig(
        scanner_endpoint=os.environ.get("SCANNER_ENDPOINT", "https://scanner:8443"),
        analysis_endpoint=os.environ.get("ANALYSIS_ENDPOINT", "https://analysis:8443"),
        cognito_issuer=os.environ.get("COGNITO_ISSUER", ""),
        cognito_audience=os.environ.get("COGNITO_AUDIENCE", ""),
        signing_key=signing_key,
        hmac_key=hmac_key,
        client_cert_path=os.environ.get("CLIENT_CERT_PATH", "/opt/certs/orchestrator.pem"),
        client_key_path=os.environ.get("CLIENT_KEY_PATH", "/opt/certs/orchestrator-key.pem"),
        ca_cert_path=os.environ.get("CA_CERT_PATH", "/opt/certs/ca.pem"),
        agent_name=os.environ.get("AGENT_NAME", "orchestrator-agent"),
        agent_arn=os.environ.get("AGENT_ARN", ""),
    )

    logger.info(
        "OrchestratorAgent initialized",
        extra={
            "agent_name": config.agent_name,
            "scanner_endpoint": config.scanner_endpoint,
            "analysis_endpoint": config.analysis_endpoint,
        },
    )

    return OrchestratorAgent(config)


# --- AWS AgentCore Runtime Handler Entry Point ---

# Module-level agent instance (created on cold start)
_agent_instance: Optional[OrchestratorAgent] = None


def _get_agent() -> OrchestratorAgent:
    """Get or create the singleton OrchestratorAgent instance.

    On first invocation (cold start), initializes the agent from environment
    variables and Secrets Manager. Subsequent invocations reuse the instance.
    """
    global _agent_instance
    if _agent_instance is None:
        _agent_instance = create_orchestrator_from_environment()
    return _agent_instance


async def agentcore_handler(event: dict, context: Any = None) -> dict:
    """AWS AgentCore Runtime / Lambda handler entry point.

    Translates the AgentCore Runtime invocation event into an InvokeRequest,
    delegates to the OrchestratorAgent, and returns the response in the
    expected format.

    Args:
        event: The AgentCore Runtime invocation event containing:
            - headers: HTTP headers dict (includes Authorization)
            - body: Request payload dict
        context: Lambda/AgentCore runtime context (unused).

    Returns:
        Response dict with statusCode, headers, and body matching
        AgentCore Runtime response format.
    """
    import asyncio

    agent = _get_agent()

    # Extract fields from the AgentCore event
    headers = event.get("headers", {})
    body = event.get("body", {})

    # Parse body if it's a JSON string
    if isinstance(body, str):
        try:
            body = json.loads(body)
        except (json.JSONDecodeError, TypeError):
            body = {}

    # Extract Authorization header (case-insensitive lookup)
    authorization = ""
    for key, value in headers.items():
        if key.lower() == "authorization":
            authorization = value
            break

    request = InvokeRequest(
        authorization=authorization,
        headers=headers,
        body=body,
    )

    response = await agent.invoke(request)

    return {
        "statusCode": response.status_code,
        "headers": response.headers,
        "body": json.dumps(response.body),
    }


def handler(event: dict, context: Any = None) -> dict:
    """Synchronous Lambda handler wrapper around the async agentcore_handler.

    AWS Lambda invokes this synchronous function. It creates or reuses an
    asyncio event loop to run the async handler.

    Args:
        event: The Lambda/AgentCore invocation event.
        context: Lambda runtime context.

    Returns:
        Response dict for the AgentCore Runtime.
    """
    import asyncio

    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(agentcore_handler(event, context))
    finally:
        loop.close()
