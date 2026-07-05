"""AWS AgentCore Runtime handler for the Analysis Agent.

Provides the Lambda-compatible entry point for deploying the Analysis Agent
to AWS AgentCore Runtime. Handles request deserialization, agent instantiation
with Secrets Manager credentials, and response serialization.

At cold start, retrieves M2M client credentials and HMAC signing key from
AWS Secrets Manager. The agent instance is cached across invocations for
warm starts (connection reuse, token caching).

Requirements: 5.1, 5.2, 5.3, 5.4, 5.5, 5.6, 6.2, 14.2, 16.1, 16.2, 18.1,
              18.2, 18.4, 19.1, 19.2, 19.3, 19.4, 19.5
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from datetime import datetime, timezone
from typing import Any

import boto3
from botocore.exceptions import ClientError

from src.agents.analysis import (
    AnalysisAgent,
    AnalysisConfig,
    AnalysisRequest,
    AnalysisResult,
)
from src.core.models import (
    DelegationEntry,
    IdentityContext,
    UserIdentity,
    WorkloadIdentity,
)
from src.core.retry import retry_with_backoff_func
from src.sca.call_graph import SourceFile
from src.sca.models import (
    DependencyNode,
    DependencyRelationship,
    ReachabilityStatus,
    VulnerabilityFinding,
    PriorityTier,
)
from src.sca.sbom_generator import CycloneDXBOM

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# ---------------------------------------------------------------------------
# AWS Configuration (from environment variables)
# ---------------------------------------------------------------------------

AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")
SECRETS_PREFIX = os.environ.get("SECRETS_PREFIX", "agentcore-sca")
M2M_SECRET_NAME = os.environ.get(
    "M2M_SECRET_NAME", f"{SECRETS_PREFIX}/analysis-agent/m2m-credentials"
)
HMAC_SECRET_NAME = os.environ.get(
    "HMAC_SECRET_NAME", f"{SECRETS_PREFIX}/identity-context/hmac-key"
)
CA_CERT_PATH = os.environ.get("CA_CERT_PATH", "/opt/certs/ca.pem")
M2M_TOKEN_ENDPOINT = os.environ.get(
    "M2M_TOKEN_ENDPOINT", "https://auth.agentcore.amazonaws.com/oauth2/token"
)

# Vulnerability database endpoints
NVD_ENDPOINT = os.environ.get("NVD_ENDPOINT", "https://services.nvd.nist.gov/rest/json/cves/2.0")
OSV_ENDPOINT = os.environ.get("OSV_ENDPOINT", "https://api.osv.dev/v1/vulns")
GHSA_ENDPOINT = os.environ.get("GHSA_ENDPOINT", "https://api.github.com/advisories")

# ---------------------------------------------------------------------------
# Secrets Manager Integration
# ---------------------------------------------------------------------------

# Module-level cache for the agent instance (persists across warm invocations)
_agent_instance: AnalysisAgent | None = None
_secrets_client: Any = None


def _get_secrets_client() -> Any:
    """Get or create a boto3 Secrets Manager client.

    Returns:
        A boto3 Secrets Manager client configured for the deployment region.
    """
    global _secrets_client
    if _secrets_client is None:
        _secrets_client = boto3.client(
            "secretsmanager",
            region_name=AWS_REGION,
        )
    return _secrets_client


def _retrieve_secret(secret_name: str) -> dict[str, Any]:
    """Retrieve a secret from AWS Secrets Manager with retry.

    Uses exponential backoff (up to 3 attempts) to handle transient failures
    when accessing Secrets Manager.

    Args:
        secret_name: The name or ARN of the secret to retrieve.

    Returns:
        Parsed JSON dictionary of the secret value.

    Raises:
        RuntimeError: If the secret cannot be retrieved after all retries.
    """
    def _fetch() -> dict[str, Any]:
        client = _get_secrets_client()
        response = client.get_secret_value(SecretId=secret_name)
        secret_string = response.get("SecretString")
        if secret_string is None:
            raise RuntimeError(f"Secret {secret_name} has no SecretString")
        return json.loads(secret_string)

    result = retry_with_backoff_func(
        _fetch,
        max_attempts=3,
        base_delay_ms=100,
        multiplier=2,
        max_delay_ms=5000,
    )

    if not result.success:
        error_msg = str(result.last_error) if result.last_error else "Unknown error"
        raise RuntimeError(
            f"Failed to retrieve secret '{secret_name}' after {result.attempts} "
            f"attempts: {error_msg}"
        )

    return result.result


def _load_config_from_secrets() -> AnalysisConfig:
    """Load Analysis Agent configuration from AWS Secrets Manager.

    Retrieves M2M client credentials and HMAC signing key from Secrets Manager
    and constructs an AnalysisConfig.

    Returns:
        AnalysisConfig populated with credentials from Secrets Manager.

    Raises:
        RuntimeError: If secrets cannot be retrieved.
    """
    # Retrieve M2M credentials (client_id + client_secret)
    m2m_secret = _retrieve_secret(M2M_SECRET_NAME)
    client_id = m2m_secret.get("client_id", "")
    client_secret = m2m_secret.get("client_secret", "")

    if not client_id or not client_secret:
        raise RuntimeError(
            f"M2M secret '{M2M_SECRET_NAME}' missing client_id or client_secret"
        )

    # Retrieve HMAC signing key
    hmac_secret = _retrieve_secret(HMAC_SECRET_NAME)
    hmac_key_str = hmac_secret.get("hmac_key", "")
    if not hmac_key_str:
        raise RuntimeError(
            f"HMAC secret '{HMAC_SECRET_NAME}' missing hmac_key field"
        )
    hmac_key = hmac_key_str.encode("utf-8")

    return AnalysisConfig(
        ca_cert_path=CA_CERT_PATH,
        hmac_key=hmac_key,
        m2m_client_id=client_id,
        m2m_client_secret=client_secret,
        m2m_token_endpoint=M2M_TOKEN_ENDPOINT,
        vuln_db_endpoints={
            "nvd": NVD_ENDPOINT,
            "osv": OSV_ENDPOINT,
            "ghsa": GHSA_ENDPOINT,
        },
    )


def _get_agent() -> AnalysisAgent:
    """Get or create the AnalysisAgent instance.

    On first invocation (cold start), loads configuration from Secrets Manager
    and creates the agent. On subsequent invocations (warm start), returns the
    cached instance.

    Returns:
        An initialized AnalysisAgent ready to handle requests.
    """
    global _agent_instance
    if _agent_instance is None:
        logger.info("Cold start: loading configuration from Secrets Manager")
        config = _load_config_from_secrets()
        _agent_instance = AnalysisAgent(config)
        logger.info("Analysis Agent initialized successfully")
    return _agent_instance


# ---------------------------------------------------------------------------
# Request/Response Serialization
# ---------------------------------------------------------------------------


def _deserialize_request(event: dict[str, Any]) -> AnalysisRequest:
    """Deserialize a Lambda/AgentCore event into an AnalysisRequest.

    Handles the AgentCore Runtime invoke event format, extracting certificate
    info from the request context, identity context from the payload, and
    analysis parameters.

    Args:
        event: The Lambda/AgentCore invoke event dictionary.

    Returns:
        An AnalysisRequest populated from the event.
    """
    # AgentCore Runtime provides mTLS cert info in requestContext
    request_context = event.get("requestContext", {})
    cert_info = request_context.get("identity", {}).get("clientCert", {})

    # If no cert info in requestContext, check direct body
    if not cert_info:
        cert_info = event.get("cert_info", {})

    # Parse the body (may be JSON string or already a dict)
    body = event.get("body", {})
    if isinstance(body, str):
        body = json.loads(body)

    # Deserialize identity context
    ic_data = body.get("identity_context", {})
    identity_context = _deserialize_identity_context(ic_data)

    # Deserialize source files
    source_files_data = body.get("source_files", [])
    source_files = [
        SourceFile(
            path=sf.get("path", ""),
            content=sf.get("content", ""),
            language=sf.get("language", ""),
        )
        for sf in source_files_data
    ]

    # Deserialize SBOM
    sbom_data = body.get("sbom", {})
    sbom = _deserialize_sbom(sbom_data)

    # Deserialize existing findings (if any)
    findings_data = body.get("findings", [])
    findings = [_deserialize_finding(f) for f in findings_data]

    return AnalysisRequest(
        cert_info=cert_info,
        identity_context=identity_context,
        source_files=source_files,
        sbom=sbom,
        cve_ids=body.get("cve_ids", []),
        repository=body.get("repository", ""),
        commit_sha=body.get("commit_sha", ""),
        findings=findings,
    )


def _deserialize_identity_context(data: dict[str, Any]) -> IdentityContext:
    """Deserialize an identity context from a dictionary.

    Args:
        data: Dictionary representation of an IdentityContext.

    Returns:
        An IdentityContext instance.
    """
    source_agent_data = data.get("source_agent", {})
    source_agent = WorkloadIdentity(
        arn=source_agent_data.get("arn", ""),
        name=source_agent_data.get("name", ""),
    )

    user_data = data.get("user_identity", {})
    user_identity = UserIdentity(
        subject=user_data.get("subject", ""),
        issuer=user_data.get("issuer", ""),
        audience=user_data.get("audience", ""),
        scopes=user_data.get("scopes", []),
        issued_at=_parse_datetime(user_data.get("issued_at", "")),
        expires_at=_parse_datetime(user_data.get("expires_at", "")),
        token_reference=user_data.get("token_reference", ""),
    )

    delegation_chain = [
        DelegationEntry(
            agent_arn=entry.get("agent_arn", ""),
            delegated_at=_parse_datetime(entry.get("delegated_at", "")),
        )
        for entry in data.get("delegation_chain", [])
    ]

    return IdentityContext(
        version=data.get("version", "1.0"),
        correlation_id=data.get("correlation_id", ""),
        source_agent=source_agent,
        user_identity=user_identity,
        delegation_chain=delegation_chain,
        signature=data.get("signature", ""),
    )


def _deserialize_sbom(data: dict[str, Any]) -> CycloneDXBOM:
    """Deserialize an SBOM from a dictionary.

    Args:
        data: Dictionary representation of a CycloneDXBOM.

    Returns:
        A CycloneDXBOM instance.
    """
    # CycloneDXBOM constructor expects components list
    return CycloneDXBOM(components=data.get("components", []))


def _deserialize_finding(data: dict[str, Any]) -> VulnerabilityFinding:
    """Deserialize a vulnerability finding from a dictionary.

    Args:
        data: Dictionary representation of a VulnerabilityFinding.

    Returns:
        A VulnerabilityFinding instance.
    """
    dep_data = data.get("dependency", {})
    dependency = DependencyNode(
        name=dep_data.get("name", ""),
        version=dep_data.get("version", ""),
        purl=dep_data.get("purl", ""),
        relationship=DependencyRelationship(
            dep_data.get("relationship", "direct")
        ),
    )

    reachability_str = data.get("reachability_status", "indeterminate")
    reachability_status = ReachabilityStatus(reachability_str)

    priority_str = data.get("priority_tier", "low")
    priority_tier = PriorityTier(priority_str)

    return VulnerabilityFinding(
        finding_id=data.get("finding_id", ""),
        repository=data.get("repository", ""),
        commit_sha=data.get("commit_sha", ""),
        cve_id=data.get("cve_id", ""),
        dependency=dependency,
        cvss_base_score=float(data.get("cvss_base_score", 0.0)),
        reachability_status=reachability_status,
        reachability_multiplier=float(data.get("reachability_multiplier", 0.6)),
        exploitability_score=float(data.get("exploitability_score", 0.0)),
        priority_tier=priority_tier,
        call_path=data.get("call_path", []),
        source_database=data.get("source_database", ""),
        analyzed_at=data.get("analyzed_at"),
    )


def _serialize_result(result: AnalysisResult) -> dict[str, Any]:
    """Serialize an AnalysisResult to a JSON-compatible dictionary.

    Args:
        result: The AnalysisResult to serialize.

    Returns:
        Dictionary suitable for JSON serialization as the Lambda response body.
    """
    response: dict[str, Any] = {
        "success": result.success,
    }

    if result.error:
        response["error"] = result.error

    if result.enriched_sbom is not None:
        response["enriched_sbom"] = {
            "components": [
                _serialize_component(c) for c in result.enriched_sbom.components
            ]
        }

    if result.scored_findings:
        response["scored_findings"] = [
            _serialize_finding(f) for f in result.scored_findings
        ]

    if result.recommendations:
        response["recommendations"] = [
            _serialize_recommendation(r) for r in result.recommendations
        ]

    if result.exploitability_result is not None:
        er = result.exploitability_result
        response["exploitability_result"] = {
            "repository": er.repository,
            "commit_sha": er.commit_sha,
            "analyzed_at": er.analyzed_at.isoformat() if er.analyzed_at else None,
            "summary": {
                "total_vulnerabilities": er.summary.total_vulnerabilities,
                "reachable": er.summary.reachable,
                "unreachable": er.summary.unreachable,
                "indeterminate": er.summary.indeterminate,
                "by_tier": {
                    tier.value: count
                    for tier, count in er.summary.by_tier.items()
                },
            },
        }

    return response


def _serialize_component(component: Any) -> dict[str, Any]:
    """Serialize an SBOM component to a dictionary."""
    if isinstance(component, dict):
        return component
    # Handle SBOMComponent dataclass or similar
    return {
        "name": getattr(component, "name", ""),
        "version": getattr(component, "version", ""),
        "purl": getattr(component, "purl", ""),
        "scope": getattr(component, "scope", "required"),
        "properties": getattr(component, "properties", []),
    }


def _serialize_finding(finding: VulnerabilityFinding) -> dict[str, Any]:
    """Serialize a VulnerabilityFinding to a dictionary."""
    return {
        "finding_id": finding.finding_id,
        "repository": finding.repository,
        "commit_sha": finding.commit_sha,
        "cve_id": finding.cve_id,
        "dependency": {
            "name": finding.dependency.name,
            "version": finding.dependency.version,
            "purl": finding.dependency.purl,
            "relationship": finding.dependency.relationship.value,
        },
        "cvss_base_score": finding.cvss_base_score,
        "reachability_status": finding.reachability_status.value,
        "reachability_multiplier": finding.reachability_multiplier,
        "exploitability_score": finding.exploitability_score,
        "priority_tier": finding.priority_tier.value,
        "call_path": finding.call_path,
        "source_database": finding.source_database,
        "analyzed_at": finding.analyzed_at,
    }


def _serialize_recommendation(rec: Any) -> dict[str, Any]:
    """Serialize a FixRecommendation to a dictionary."""
    dep = getattr(rec, "dependency", None)
    dep_dict = {}
    if dep is not None:
        dep_dict = {
            "name": getattr(dep, "name", ""),
            "current_version": getattr(dep, "version", ""),
            "purl": getattr(dep, "purl", ""),
        }

    return {
        "dependency": dep_dict,
        "recommended_version": getattr(rec, "recommended_version", None),
        "is_breaking_change": getattr(rec, "is_breaking_change", False),
        "current_major": getattr(rec, "current_major", None),
        "target_major": getattr(rec, "target_major", None),
        "resolved_cves": getattr(rec, "resolved_cves", []),
        "fix_available": getattr(rec, "fix_available", False),
        "mitigation_note": getattr(rec, "mitigation_note", None),
    }


def _parse_datetime(value: str | datetime) -> datetime:
    """Parse a datetime from an ISO 8601 string or return as-is if already datetime.

    Args:
        value: ISO 8601 string or datetime object.

    Returns:
        A timezone-aware datetime (defaults to UTC if no tzinfo).
    """
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value
    if not value:
        return datetime.now(timezone.utc)
    try:
        dt = datetime.fromisoformat(value)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, TypeError):
        return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Lambda / AgentCore Runtime Handler
# ---------------------------------------------------------------------------


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """AWS Lambda / AgentCore Runtime invoke handler for the Analysis Agent.

    This is the entry point invoked by AWS AgentCore Runtime or Lambda.
    It initializes the agent (with Secrets Manager credentials on cold start),
    deserializes the request, invokes the analysis pipeline, and returns
    a serialized response.

    Args:
        event: The Lambda event dictionary. For AgentCore Runtime invocations,
               this contains requestContext (with mTLS cert info) and body
               (with identity context + analysis parameters).
        context: The Lambda context object (provides request ID, function name, etc.).

    Returns:
        A dictionary with statusCode, headers, and body suitable for API Gateway
        or AgentCore Runtime response format.
    """
    request_id = getattr(context, "aws_request_id", "unknown") if context else "unknown"
    logger.info(f"Handling invoke request: {request_id}")

    try:
        # Get or initialize the agent (cold start loads from Secrets Manager)
        agent = _get_agent()

        # Deserialize the incoming request
        request = _deserialize_request(event)

        # Run the async invoke
        loop = asyncio.new_event_loop()
        try:
            result = loop.run_until_complete(agent.invoke(request))
        finally:
            loop.close()

        # Serialize the response
        response_body = _serialize_result(result)
        status_code = 200 if result.success else 403 if "validation failed" in (result.error or "").lower() else 500

        return {
            "statusCode": status_code,
            "headers": {
                "Content-Type": "application/json",
                "X-Request-Id": request_id,
            },
            "body": json.dumps(response_body),
        }

    except Exception as e:
        logger.exception(f"Handler error: {e}")
        return {
            "statusCode": 500,
            "headers": {
                "Content-Type": "application/json",
                "X-Request-Id": request_id,
            },
            "body": json.dumps({
                "success": False,
                "error": f"Internal server error: {type(e).__name__}",
            }),
        }


# Alias for AgentCore Runtime conventions
lambda_handler = handler
