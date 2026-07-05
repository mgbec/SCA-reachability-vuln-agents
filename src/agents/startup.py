"""Agent startup and wiring module for the Reachability-Enhanced SCA platform.

Provides a unified startup mechanism that initializes all three agents
(Orchestrator, Scanner, Analysis) with credentials retrieved from AWS Secrets
Manager. Ensures mTLS certificates, HMAC signing keys, and OAuth secrets are
loaded at initialization time, and wires the full vulnerability analysis
pipeline: CLI -> Orchestrator -> Scanner (GitHub) -> Orchestrator -> Analysis
(tree-sitter + vuln DBs) -> Orchestrator -> CLI.

This module acts as the composition root that connects all pieces together
without hardcoding any secrets. All sensitive material is retrieved from
Secrets Manager with retry logic at agent startup.

Requirements: 6.1, 6.2, 6.3, 14.1, 14.2, 16.2
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from typing import Any, Optional

import boto3

from src.core.retry import retry_with_backoff_func

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Secrets Manager Client (shared across agents)
# ---------------------------------------------------------------------------


class StartupSecretsClient:
    """Centralized Secrets Manager client for agent startup wiring.

    Retrieves HMAC keys, OAuth secrets, and certificate private keys from
    AWS Secrets Manager with retry logic. Used during agent initialization
    to avoid hardcoding sensitive credentials.

    Requirements: 16.1, 16.2, 16.5
    """

    def __init__(self, region_name: str = "us-east-1") -> None:
        self._region_name = region_name
        self._client: Any = None

    def _get_client(self) -> Any:
        """Get or create the boto3 Secrets Manager client."""
        if self._client is None:
            self._client = boto3.client(
                "secretsmanager", region_name=self._region_name
            )
        return self._client

    def retrieve_secret(self, secret_id: str) -> dict[str, Any]:
        """Retrieve a secret from AWS Secrets Manager with exponential backoff.

        Args:
            secret_id: ARN or name of the secret to retrieve.

        Returns:
            Parsed JSON dictionary of the secret value.

        Raises:
            RuntimeError: If all retry attempts are exhausted.
        """

        def _fetch() -> dict[str, Any]:
            client = self._get_client()
            response = client.get_secret_value(SecretId=secret_id)
            secret_string = response.get("SecretString")
            if secret_string is None:
                raise RuntimeError(f"Secret '{secret_id}' has no SecretString")
            return json.loads(secret_string)

        result = retry_with_backoff_func(
            _fetch,
            max_attempts=3,
            base_delay_ms=100,
            multiplier=2,
            max_delay_ms=5000,
        )

        if not result.success:
            error_msg = str(result.last_error) if result.last_error else "Unknown"
            raise RuntimeError(
                f"Failed to retrieve secret '{secret_id}' after "
                f"{result.attempts} attempts: {error_msg}"
            )

        return result.result

    def retrieve_hmac_key(self, secret_id: str) -> bytes:
        """Retrieve the HMAC signing key as raw bytes.

        Expects the secret JSON to contain an 'hmac_key' field with the key
        value encoded as a UTF-8 string.

        Args:
            secret_id: ARN or name of the HMAC key secret.

        Returns:
            HMAC key bytes for HMAC-SHA256 signing.

        Raises:
            RuntimeError: If secret retrieval fails.
            ValueError: If the 'hmac_key' field is missing.
        """
        secret = self.retrieve_secret(secret_id)
        hmac_key_str = secret.get("hmac_key", "")
        if not hmac_key_str:
            raise ValueError(
                f"HMAC secret '{secret_id}' missing required 'hmac_key' field"
            )
        return hmac_key_str.encode("utf-8")

    def retrieve_oauth_credentials(self, secret_id: str) -> dict[str, str]:
        """Retrieve OAuth client credentials from Secrets Manager.

        Expects the secret JSON to contain: client_id, client_secret,
        and optionally callback_url.

        Args:
            secret_id: ARN or name of the OAuth credentials secret.

        Returns:
            Dictionary with client_id, client_secret, and callback_url.

        Raises:
            RuntimeError: If secret retrieval fails.
            ValueError: If required fields are missing.
        """
        secret = self.retrieve_secret(secret_id)
        required = ["client_id", "client_secret"]
        missing = [k for k in required if not secret.get(k)]
        if missing:
            raise ValueError(
                f"OAuth secret '{secret_id}' missing required fields: {missing}"
            )
        return {
            "client_id": secret["client_id"],
            "client_secret": secret["client_secret"],
            "callback_url": secret.get("callback_url", ""),
        }

    def retrieve_cert_private_key(self, secret_id: str) -> str:
        """Retrieve a certificate private key (PEM) from Secrets Manager.

        Expects the secret JSON to contain a 'private_key' field with the
        PEM-encoded private key.

        Args:
            secret_id: ARN or name of the certificate key secret.

        Returns:
            PEM-encoded private key string.

        Raises:
            RuntimeError: If secret retrieval fails.
            ValueError: If the 'private_key' field is missing.
        """
        secret = self.retrieve_secret(secret_id)
        private_key = secret.get("private_key", "")
        if not private_key:
            raise ValueError(
                f"Certificate secret '{secret_id}' missing 'private_key' field"
            )
        return private_key


# ---------------------------------------------------------------------------
# Platform Configuration
# ---------------------------------------------------------------------------


@dataclass
class PlatformConfig:
    """Complete platform configuration for all three agents.

    Consolidates all environment variables and Secrets Manager references
    needed to initialize the multi-agent vulnerability analysis pipeline.

    Attributes:
        region: AWS region for service access.
        hmac_secret_id: Secrets Manager ID for the shared HMAC signing key.
        orchestrator_cert_path: Path to orchestrator X.509 client cert (PEM).
        orchestrator_key_path: Path to orchestrator private key (PEM).
        ca_cert_path: Path to the internal CA certificate (PEM).
        scanner_endpoint: Base URL of the Scanner Agent.
        analysis_endpoint: Base URL of the Analysis Agent.
        cognito_issuer: Expected JWT issuer URL.
        cognito_audience: Expected JWT audience (client ID).
        jwt_signing_key_secret_id: Secrets Manager ID for JWT signing key.
        scanner_oauth_secret_id: Secrets Manager ID for Scanner OAuth creds.
        analysis_m2m_secret_id: Secrets Manager ID for Analysis M2M creds.
        m2m_token_endpoint: Token endpoint for M2M client credentials.
        orchestrator_agent_name: Orchestrator agent name.
        orchestrator_agent_arn: Orchestrator workload identity ARN.
        scanner_ca_cert_path: Path to CA cert for Scanner mTLS validation.
        analysis_ca_cert_path: Path to CA cert for Analysis mTLS validation.
        vuln_db_endpoints: Vulnerability database endpoint URLs.
    """

    region: str = "us-east-1"
    hmac_secret_id: str = "agentcore-sca/identity-context/hmac-key"
    orchestrator_cert_path: str = "/opt/certs/orchestrator.pem"
    orchestrator_key_path: str = "/opt/certs/orchestrator-key.pem"
    ca_cert_path: str = "/opt/certs/ca.pem"
    scanner_endpoint: str = "https://scanner:8443"
    analysis_endpoint: str = "https://analysis:8443"
    cognito_issuer: str = ""
    cognito_audience: str = ""
    jwt_signing_key_secret_id: str = ""
    scanner_oauth_secret_id: str = "agentcore-sca/scanner/github-oauth"
    analysis_m2m_secret_id: str = "agentcore-sca/analysis/m2m-credentials"
    m2m_token_endpoint: str = "https://auth.agentcore.amazonaws.com/oauth2/token"
    orchestrator_agent_name: str = "orchestrator-agent"
    orchestrator_agent_arn: str = ""
    scanner_ca_cert_path: str = "/opt/certs/ca.pem"
    analysis_ca_cert_path: str = "/opt/certs/ca.pem"
    vuln_db_endpoints: dict[str, str] = field(default_factory=lambda: {
        "nvd": "https://services.nvd.nist.gov/rest/json/cves/2.0",
        "osv": "https://api.osv.dev/v1/vulns",
        "ghsa": "https://api.github.com/advisories",
    })


def load_platform_config_from_env() -> PlatformConfig:
    """Load PlatformConfig from environment variables.

    Environment variables (all optional with defaults):
        AWS_REGION: AWS region (default: us-east-1)
        HMAC_SECRET_ID: Secrets Manager ID for HMAC key
        ORCHESTRATOR_CERT_PATH: Path to orchestrator client cert
        ORCHESTRATOR_KEY_PATH: Path to orchestrator private key
        CA_CERT_PATH: Path to CA certificate
        SCANNER_ENDPOINT: Scanner Agent base URL
        ANALYSIS_ENDPOINT: Analysis Agent base URL
        COGNITO_ISSUER: JWT issuer URL
        COGNITO_AUDIENCE: JWT audience / client ID
        JWT_SIGNING_KEY_SECRET_ID: Secrets Manager ID for JWT signing key
        SCANNER_OAUTH_SECRET_ID: Secrets Manager ID for Scanner OAuth
        ANALYSIS_M2M_SECRET_ID: Secrets Manager ID for Analysis M2M
        M2M_TOKEN_ENDPOINT: Token endpoint for M2M flow
        ORCHESTRATOR_AGENT_NAME: Orchestrator agent name
        ORCHESTRATOR_AGENT_ARN: Orchestrator workload identity ARN
        SCANNER_CA_CERT_PATH: CA cert path for Scanner
        ANALYSIS_CA_CERT_PATH: CA cert path for Analysis
        NVD_ENDPOINT: NVD API endpoint
        OSV_ENDPOINT: OSV API endpoint
        GHSA_ENDPOINT: GHSA API endpoint

    Returns:
        A PlatformConfig populated from environment variables.
    """
    vuln_endpoints = {
        "nvd": os.environ.get(
            "NVD_ENDPOINT",
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
        ),
        "osv": os.environ.get("OSV_ENDPOINT", "https://api.osv.dev/v1/vulns"),
        "ghsa": os.environ.get(
            "GHSA_ENDPOINT", "https://api.github.com/advisories"
        ),
    }

    return PlatformConfig(
        region=os.environ.get("AWS_REGION", "us-east-1"),
        hmac_secret_id=os.environ.get(
            "HMAC_SECRET_ID", "agentcore-sca/identity-context/hmac-key"
        ),
        orchestrator_cert_path=os.environ.get(
            "ORCHESTRATOR_CERT_PATH", "/opt/certs/orchestrator.pem"
        ),
        orchestrator_key_path=os.environ.get(
            "ORCHESTRATOR_KEY_PATH", "/opt/certs/orchestrator-key.pem"
        ),
        ca_cert_path=os.environ.get("CA_CERT_PATH", "/opt/certs/ca.pem"),
        scanner_endpoint=os.environ.get(
            "SCANNER_ENDPOINT", "https://scanner:8443"
        ),
        analysis_endpoint=os.environ.get(
            "ANALYSIS_ENDPOINT", "https://analysis:8443"
        ),
        cognito_issuer=os.environ.get("COGNITO_ISSUER", ""),
        cognito_audience=os.environ.get("COGNITO_AUDIENCE", ""),
        jwt_signing_key_secret_id=os.environ.get(
            "JWT_SIGNING_KEY_SECRET_ID", ""
        ),
        scanner_oauth_secret_id=os.environ.get(
            "SCANNER_OAUTH_SECRET_ID", "agentcore-sca/scanner/github-oauth"
        ),
        analysis_m2m_secret_id=os.environ.get(
            "ANALYSIS_M2M_SECRET_ID", "agentcore-sca/analysis/m2m-credentials"
        ),
        m2m_token_endpoint=os.environ.get(
            "M2M_TOKEN_ENDPOINT",
            "https://auth.agentcore.amazonaws.com/oauth2/token",
        ),
        orchestrator_agent_name=os.environ.get(
            "ORCHESTRATOR_AGENT_NAME", "orchestrator-agent"
        ),
        orchestrator_agent_arn=os.environ.get("ORCHESTRATOR_AGENT_ARN", ""),
        scanner_ca_cert_path=os.environ.get(
            "SCANNER_CA_CERT_PATH", "/opt/certs/ca.pem"
        ),
        analysis_ca_cert_path=os.environ.get(
            "ANALYSIS_CA_CERT_PATH", "/opt/certs/ca.pem"
        ),
        vuln_db_endpoints=vuln_endpoints,
    )


# ---------------------------------------------------------------------------
# Agent Initialization Results
# ---------------------------------------------------------------------------


@dataclass
class AgentStartupResult:
    """Result of agent initialization.

    Attributes:
        success: Whether all agents initialized successfully.
        orchestrator: Initialized OrchestratorAgent (None on failure).
        scanner: Initialized ScannerAgent (None on failure).
        analysis: Initialized AnalysisAgent (None on failure).
        errors: List of initialization error messages.
    """

    success: bool
    orchestrator: Any = None
    scanner: Any = None
    analysis: Any = None
    errors: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Agent Startup Wiring
# ---------------------------------------------------------------------------


def initialize_orchestrator(
    platform_config: PlatformConfig,
    secrets_client: StartupSecretsClient,
) -> "OrchestratorAgent":
    """Initialize the Orchestrator Agent with secrets from Secrets Manager.

    Retrieves the HMAC signing key and optional JWT signing key from Secrets
    Manager, configures mTLS certificates, and creates a fully wired
    OrchestratorAgent ready to delegate to Scanner and Analysis agents.

    The Orchestrator is configured with:
    - mTLS client certificate (CN: orchestrator-agent) for outbound calls
    - CA certificate for verifying Scanner and Analysis server certificates
    - HMAC key for signing identity context envelopes
    - Scanner and Analysis endpoints for delegation

    Args:
        platform_config: Platform-wide configuration.
        secrets_client: Initialized Secrets Manager client.

    Returns:
        A fully configured OrchestratorAgent.

    Raises:
        RuntimeError: If required secrets cannot be retrieved.
    """
    from src.agents.orchestrator import OrchestratorAgent, OrchestratorConfig

    logger.info("Initializing Orchestrator Agent...")

    # Retrieve HMAC key from Secrets Manager
    hmac_key = secrets_client.retrieve_hmac_key(platform_config.hmac_secret_id)

    # Retrieve JWT signing key (optional - may use env var fallback)
    signing_key: Any = ""
    if platform_config.jwt_signing_key_secret_id:
        jwt_secret = secrets_client.retrieve_secret(
            platform_config.jwt_signing_key_secret_id
        )
        signing_key = jwt_secret.get("signing_key", "")

    config = OrchestratorConfig(
        scanner_endpoint=platform_config.scanner_endpoint,
        analysis_endpoint=platform_config.analysis_endpoint,
        cognito_issuer=platform_config.cognito_issuer,
        cognito_audience=platform_config.cognito_audience,
        signing_key=signing_key,
        hmac_key=hmac_key,
        client_cert_path=platform_config.orchestrator_cert_path,
        client_key_path=platform_config.orchestrator_key_path,
        ca_cert_path=platform_config.ca_cert_path,
        agent_name=platform_config.orchestrator_agent_name,
        agent_arn=platform_config.orchestrator_agent_arn,
    )

    agent = OrchestratorAgent(config)
    logger.info(
        "Orchestrator Agent initialized",
        extra={
            "scanner_endpoint": platform_config.scanner_endpoint,
            "analysis_endpoint": platform_config.analysis_endpoint,
            "mtls_cert": platform_config.orchestrator_cert_path,
        },
    )
    return agent


def initialize_scanner(
    platform_config: PlatformConfig,
    secrets_client: StartupSecretsClient,
) -> "ScannerAgent":
    """Initialize the Scanner Agent with secrets from Secrets Manager.

    Retrieves GitHub OAuth client credentials and HMAC signing key from
    Secrets Manager. The Scanner Agent is configured to:
    - Validate caller mTLS certificates against the internal CA
    - Verify identity context HMAC signatures
    - Use GitHub OAuth (USER_FEDERATION) with scopes: security_events, repo

    Args:
        platform_config: Platform-wide configuration.
        secrets_client: Initialized Secrets Manager client.

    Returns:
        A fully configured ScannerAgent.

    Raises:
        RuntimeError: If required secrets cannot be retrieved.
    """
    from src.core.metrics import AuthMetrics
    from src.core.telemetry import TelemetryProvider
    from src.agents.scanner import ScannerAgent, ScannerConfig

    logger.info("Initializing Scanner Agent...")

    # Retrieve HMAC key from Secrets Manager
    hmac_key = secrets_client.retrieve_hmac_key(platform_config.hmac_secret_id)

    # Retrieve GitHub OAuth credentials from Secrets Manager
    oauth_creds = secrets_client.retrieve_oauth_credentials(
        platform_config.scanner_oauth_secret_id
    )

    config = ScannerConfig(
        ca_cert_path=platform_config.scanner_ca_cert_path,
        hmac_key=hmac_key,
        github_oauth_client_id=oauth_creds["client_id"],
        github_oauth_client_secret=oauth_creds["client_secret"],
        github_oauth_callback_url=oauth_creds["callback_url"],
        identity_directory_endpoint="",
        telemetry_provider=TelemetryProvider(service_name="scanner-agent"),
        metrics=AuthMetrics(agent_name="scanner-agent"),
    )

    agent = ScannerAgent(config)
    logger.info(
        "Scanner Agent initialized",
        extra={
            "ca_cert": platform_config.scanner_ca_cert_path,
            "oauth_client_id": oauth_creds["client_id"],
        },
    )
    return agent


def initialize_analysis(
    platform_config: PlatformConfig,
    secrets_client: StartupSecretsClient,
) -> "AnalysisAgent":
    """Initialize the Analysis Agent with secrets from Secrets Manager.

    Retrieves M2M client credentials and HMAC signing key from Secrets
    Manager. The Analysis Agent is configured to:
    - Validate caller mTLS certificates against the internal CA
    - Verify identity context HMAC signatures and workload identity
    - Use M2M client credentials for vulnerability database access
    - Perform tree-sitter call graph analysis
    - Compute exploitability scores and generate fix recommendations

    Args:
        platform_config: Platform-wide configuration.
        secrets_client: Initialized Secrets Manager client.

    Returns:
        A fully configured AnalysisAgent.

    Raises:
        RuntimeError: If required secrets cannot be retrieved.
    """
    from src.agents.analysis import AnalysisAgent, AnalysisConfig

    logger.info("Initializing Analysis Agent...")

    # Retrieve HMAC key from Secrets Manager
    hmac_key = secrets_client.retrieve_hmac_key(platform_config.hmac_secret_id)

    # Retrieve M2M credentials from Secrets Manager
    m2m_creds = secrets_client.retrieve_oauth_credentials(
        platform_config.analysis_m2m_secret_id
    )

    config = AnalysisConfig(
        ca_cert_path=platform_config.analysis_ca_cert_path,
        hmac_key=hmac_key,
        m2m_client_id=m2m_creds["client_id"],
        m2m_client_secret=m2m_creds["client_secret"],
        m2m_token_endpoint=platform_config.m2m_token_endpoint,
        vuln_db_endpoints=platform_config.vuln_db_endpoints,
    )

    agent = AnalysisAgent(config)
    logger.info(
        "Analysis Agent initialized",
        extra={
            "ca_cert": platform_config.analysis_ca_cert_path,
            "m2m_client_id": m2m_creds["client_id"],
            "token_endpoint": platform_config.m2m_token_endpoint,
        },
    )
    return agent


# ---------------------------------------------------------------------------
# Full Platform Startup
# ---------------------------------------------------------------------------


def initialize_platform(
    config: Optional[PlatformConfig] = None,
) -> AgentStartupResult:
    """Initialize all agents for the vulnerability analysis pipeline.

    Performs the complete startup sequence:
    1. Load platform configuration (from env vars if not provided)
    2. Create Secrets Manager client
    3. Retrieve HMAC keys, OAuth secrets, and cert private keys
    4. Initialize Orchestrator Agent (with mTLS client cert for delegation)
    5. Initialize Scanner Agent (with GitHub OAuth credentials)
    6. Initialize Analysis Agent (with M2M credentials)

    The initialized Orchestrator is pre-configured to delegate to Scanner and
    Analysis agents over mTLS with identity context envelopes, forming the
    complete pipeline:
        CLI -> Orchestrator -> Scanner (GitHub) -> Orchestrator
            -> Analysis (tree-sitter + vuln DBs) -> Orchestrator -> CLI

    Args:
        config: Optional PlatformConfig. If None, loads from env vars.

    Returns:
        AgentStartupResult with initialized agents or error details.
    """
    if config is None:
        config = load_platform_config_from_env()

    secrets_client = StartupSecretsClient(region_name=config.region)
    errors: list[str] = []

    # Initialize Orchestrator Agent
    orchestrator = None
    try:
        orchestrator = initialize_orchestrator(config, secrets_client)
    except Exception as e:
        error_msg = f"Orchestrator initialization failed: {e}"
        logger.error(error_msg)
        errors.append(error_msg)

    # Initialize Scanner Agent
    scanner = None
    try:
        scanner = initialize_scanner(config, secrets_client)
    except Exception as e:
        error_msg = f"Scanner initialization failed: {e}"
        logger.error(error_msg)
        errors.append(error_msg)

    # Initialize Analysis Agent
    analysis = None
    try:
        analysis = initialize_analysis(config, secrets_client)
    except Exception as e:
        error_msg = f"Analysis initialization failed: {e}"
        logger.error(error_msg)
        errors.append(error_msg)

    success = len(errors) == 0
    if success:
        logger.info(
            "Platform startup complete: all agents initialized successfully"
        )
    else:
        logger.warning(
            f"Platform startup completed with {len(errors)} error(s)",
            extra={"errors": errors},
        )

    return AgentStartupResult(
        success=success,
        orchestrator=orchestrator,
        scanner=scanner,
        analysis=analysis,
        errors=errors,
    )


# ---------------------------------------------------------------------------
# Pipeline Execution Helper
# ---------------------------------------------------------------------------


async def run_vulnerability_analysis_pipeline(
    orchestrator: "OrchestratorAgent",
    authorization: str,
    repository: str,
    branch: str = "main",
    headers: Optional[dict] = None,
) -> dict:
    """Execute the full vulnerability analysis pipeline through the Orchestrator.

    This is the top-level entry point for running the complete pipeline:
        CLI -> Orchestrator -> Scanner (GitHub) -> Orchestrator
            -> Analysis (tree-sitter + vuln DBs) -> Orchestrator -> CLI

    The Orchestrator handles:
    1. JWT validation of the inbound user token
    2. Identity context construction with HMAC signature
    3. Delegation to Scanner Agent over mTLS (fetches GitHub data)
    4. Delegation to Analysis Agent over mTLS (call graph + scoring)
    5. Aggregation of results for the CLI

    Args:
        orchestrator: An initialized OrchestratorAgent.
        authorization: Authorization header (e.g., "Bearer <jwt>").
        repository: GitHub repository in "owner/repo" format.
        branch: Git branch to analyze (default: "main").
        headers: Optional HTTP headers (for correlation ID propagation).

    Returns:
        Dictionary with pipeline results including enriched SBOM,
        scored findings, and fix recommendations.
    """
    from src.agents.orchestrator import InvokeRequest

    request = InvokeRequest(
        authorization=authorization,
        headers=headers or {},
        body={
            "action": "full_pipeline",
            "repository": repository,
            "branch": branch,
        },
    )

    response = await orchestrator.invoke(request)

    return {
        "status_code": response.status_code,
        "body": response.body,
        "headers": response.headers,
        "error": response.error,
    }


# ---------------------------------------------------------------------------
# Convenience: Single-command platform startup from environment
# ---------------------------------------------------------------------------


def create_platform_from_environment() -> AgentStartupResult:
    """Create the full agent platform from environment variables.

    A convenience function that combines load_platform_config_from_env()
    and initialize_platform() into a single call. Suitable for use in
    production deployment scripts or as the composition root.

    Returns:
        AgentStartupResult with all agents ready for pipeline execution.
    """
    config = load_platform_config_from_env()
    return initialize_platform(config)
