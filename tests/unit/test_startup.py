"""Unit tests for agent startup and wiring module.

Tests the initialization of all three agents (Orchestrator, Scanner, Analysis)
from Secrets Manager credentials, mTLS configuration, and identity propagation
wiring.

Requirements: 6.1, 6.2, 6.3, 14.1, 14.2, 16.2
"""

from __future__ import annotations

import json
import os
from unittest.mock import MagicMock, patch

import pytest

from src.agents.startup import (
    AgentStartupResult,
    PlatformConfig,
    StartupSecretsClient,
    initialize_analysis,
    initialize_orchestrator,
    initialize_platform,
    initialize_scanner,
    load_platform_config_from_env,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_secrets_client():
    """Create a mock StartupSecretsClient with pre-configured returns."""
    client = MagicMock(spec=StartupSecretsClient)
    client.retrieve_hmac_key.return_value = b"test-hmac-key-32-bytes-long!!"
    client.retrieve_oauth_credentials.return_value = {
        "client_id": "test-client-id",
        "client_secret": "test-client-secret",
        "callback_url": "https://scanner.example.com/oauth/callback",
    }
    client.retrieve_secret.return_value = {"signing_key": "test-jwt-key"}
    client.retrieve_cert_private_key.return_value = "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----"
    return client


@pytest.fixture
def platform_config():
    """Create a test PlatformConfig."""
    return PlatformConfig(
        region="us-east-1",
        hmac_secret_id="test/hmac-key",
        orchestrator_cert_path="/tmp/test-orch.pem",
        orchestrator_key_path="/tmp/test-orch-key.pem",
        ca_cert_path="/tmp/test-ca.pem",
        scanner_endpoint="https://scanner.test:8443",
        analysis_endpoint="https://analysis.test:8443",
        cognito_issuer="https://cognito-idp.us-east-1.amazonaws.com/us-east-1_test",
        cognito_audience="test-client-id",
        jwt_signing_key_secret_id="test/jwt-signing-key",
        scanner_oauth_secret_id="test/scanner-oauth",
        analysis_m2m_secret_id="test/analysis-m2m",
        m2m_token_endpoint="https://auth.test/oauth2/token",
        orchestrator_agent_name="orchestrator-agent",
        orchestrator_agent_arn="arn:aws:bedrock-agentcore:us-east-1:123456789012:workload-identity/directory/default/workload-identity/orchestrator-agent",
        scanner_ca_cert_path="/tmp/test-ca.pem",
        analysis_ca_cert_path="/tmp/test-ca.pem",
    )


# ---------------------------------------------------------------------------
# StartupSecretsClient Tests
# ---------------------------------------------------------------------------


class TestStartupSecretsClient:
    """Tests for the StartupSecretsClient class."""

    @patch("src.agents.startup.boto3")
    def test_retrieve_secret_success(self, mock_boto3):
        """Test successful secret retrieval from Secrets Manager."""
        mock_client = MagicMock()
        mock_boto3.client.return_value = mock_client
        mock_client.get_secret_value.return_value = {
            "SecretString": json.dumps({"hmac_key": "my-secret-key"})
        }

        client = StartupSecretsClient(region_name="us-east-1")
        result = client.retrieve_secret("test-secret-id")

        assert result == {"hmac_key": "my-secret-key"}
        mock_client.get_secret_value.assert_called_once_with(
            SecretId="test-secret-id"
        )

    @patch("src.agents.startup.boto3")
    def test_retrieve_secret_retry_on_failure(self, mock_boto3):
        """Test that secret retrieval retries on transient failure."""
        mock_client = MagicMock()
        mock_boto3.client.return_value = mock_client
        # First call fails, second succeeds
        mock_client.get_secret_value.side_effect = [
            Exception("Transient error"),
            {"SecretString": json.dumps({"key": "value"})},
        ]

        client = StartupSecretsClient(region_name="us-east-1")
        result = client.retrieve_secret("test-secret")

        assert result == {"key": "value"}
        assert mock_client.get_secret_value.call_count == 2

    @patch("src.agents.startup.boto3")
    def test_retrieve_secret_all_retries_exhausted(self, mock_boto3):
        """Test RuntimeError when all retry attempts are exhausted."""
        mock_client = MagicMock()
        mock_boto3.client.return_value = mock_client
        mock_client.get_secret_value.side_effect = Exception("Persistent failure")

        client = StartupSecretsClient(region_name="us-east-1")

        with pytest.raises(RuntimeError, match="Failed to retrieve secret"):
            client.retrieve_secret("test-secret")

    @patch("src.agents.startup.boto3")
    def test_retrieve_hmac_key(self, mock_boto3):
        """Test HMAC key retrieval returns bytes."""
        mock_client = MagicMock()
        mock_boto3.client.return_value = mock_client
        mock_client.get_secret_value.return_value = {
            "SecretString": json.dumps({"hmac_key": "super-secret-key"})
        }

        client = StartupSecretsClient(region_name="us-east-1")
        result = client.retrieve_hmac_key("hmac-secret-id")

        assert result == b"super-secret-key"
        assert isinstance(result, bytes)

    @patch("src.agents.startup.boto3")
    def test_retrieve_hmac_key_missing_field(self, mock_boto3):
        """Test ValueError when hmac_key field is missing."""
        mock_client = MagicMock()
        mock_boto3.client.return_value = mock_client
        mock_client.get_secret_value.return_value = {
            "SecretString": json.dumps({"other_field": "value"})
        }

        client = StartupSecretsClient(region_name="us-east-1")

        with pytest.raises(ValueError, match="missing required 'hmac_key' field"):
            client.retrieve_hmac_key("hmac-secret-id")

    @patch("src.agents.startup.boto3")
    def test_retrieve_oauth_credentials(self, mock_boto3):
        """Test OAuth credentials retrieval with all required fields."""
        mock_client = MagicMock()
        mock_boto3.client.return_value = mock_client
        mock_client.get_secret_value.return_value = {
            "SecretString": json.dumps({
                "client_id": "gh-client-id",
                "client_secret": "gh-client-secret",
                "callback_url": "https://scanner/callback",
            })
        }

        client = StartupSecretsClient(region_name="us-east-1")
        result = client.retrieve_oauth_credentials("oauth-secret-id")

        assert result["client_id"] == "gh-client-id"
        assert result["client_secret"] == "gh-client-secret"
        assert result["callback_url"] == "https://scanner/callback"

    @patch("src.agents.startup.boto3")
    def test_retrieve_oauth_credentials_missing_fields(self, mock_boto3):
        """Test ValueError when OAuth secret is missing required fields."""
        mock_client = MagicMock()
        mock_boto3.client.return_value = mock_client
        mock_client.get_secret_value.return_value = {
            "SecretString": json.dumps({"client_id": "only-id"})
        }

        client = StartupSecretsClient(region_name="us-east-1")

        with pytest.raises(ValueError, match="missing required fields"):
            client.retrieve_oauth_credentials("oauth-secret-id")

    @patch("src.agents.startup.boto3")
    def test_retrieve_cert_private_key(self, mock_boto3):
        """Test PEM private key retrieval."""
        pem_key = "-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----"
        mock_client = MagicMock()
        mock_boto3.client.return_value = mock_client
        mock_client.get_secret_value.return_value = {
            "SecretString": json.dumps({"private_key": pem_key})
        }

        client = StartupSecretsClient(region_name="us-east-1")
        result = client.retrieve_cert_private_key("cert-secret-id")

        assert result == pem_key


# ---------------------------------------------------------------------------
# Agent Initialization Tests
# ---------------------------------------------------------------------------


class TestInitializeOrchestrator:
    """Tests for Orchestrator Agent initialization."""

    def test_orchestrator_initialized_with_mtls_config(
        self, platform_config, mock_secrets_client
    ):
        """Test that Orchestrator is configured with mTLS certs and endpoints."""
        agent = initialize_orchestrator(platform_config, mock_secrets_client)

        assert agent.config.scanner_endpoint == "https://scanner.test:8443"
        assert agent.config.analysis_endpoint == "https://analysis.test:8443"
        assert agent.config.client_cert_path == "/tmp/test-orch.pem"
        assert agent.config.client_key_path == "/tmp/test-orch-key.pem"
        assert agent.config.ca_cert_path == "/tmp/test-ca.pem"

    def test_orchestrator_hmac_key_from_secrets(
        self, platform_config, mock_secrets_client
    ):
        """Test that HMAC key is retrieved from Secrets Manager."""
        agent = initialize_orchestrator(platform_config, mock_secrets_client)

        mock_secrets_client.retrieve_hmac_key.assert_called_once_with(
            "test/hmac-key"
        )
        assert agent.config.hmac_key == b"test-hmac-key-32-bytes-long!!"

    def test_orchestrator_jwt_signing_key_from_secrets(
        self, platform_config, mock_secrets_client
    ):
        """Test that JWT signing key is retrieved from Secrets Manager."""
        agent = initialize_orchestrator(platform_config, mock_secrets_client)

        mock_secrets_client.retrieve_secret.assert_called_once_with(
            "test/jwt-signing-key"
        )
        assert agent.config.signing_key == "test-jwt-key"

    def test_orchestrator_agent_identity(
        self, platform_config, mock_secrets_client
    ):
        """Test that workload identity is properly set."""
        agent = initialize_orchestrator(platform_config, mock_secrets_client)

        assert agent.workload_identity.name == "orchestrator-agent"
        assert "orchestrator-agent" in agent.workload_identity.arn


class TestInitializeScanner:
    """Tests for Scanner Agent initialization."""

    def test_scanner_initialized_with_oauth_credentials(
        self, platform_config, mock_secrets_client
    ):
        """Test that Scanner is configured with GitHub OAuth credentials."""
        agent = initialize_scanner(platform_config, mock_secrets_client)

        mock_secrets_client.retrieve_oauth_credentials.assert_called_once_with(
            "test/scanner-oauth"
        )

    def test_scanner_hmac_key_from_secrets(
        self, platform_config, mock_secrets_client
    ):
        """Test that Scanner gets HMAC key for identity context validation."""
        initialize_scanner(platform_config, mock_secrets_client)

        mock_secrets_client.retrieve_hmac_key.assert_called_once_with(
            "test/hmac-key"
        )

    def test_scanner_ca_cert_configured(
        self, platform_config, mock_secrets_client
    ):
        """Test that Scanner has CA cert path for mTLS validation."""
        agent = initialize_scanner(platform_config, mock_secrets_client)

        assert agent._config.ca_cert_path == "/tmp/test-ca.pem"


class TestInitializeAnalysis:
    """Tests for Analysis Agent initialization."""

    def test_analysis_initialized_with_m2m_credentials(
        self, platform_config, mock_secrets_client
    ):
        """Test that Analysis is configured with M2M credentials."""
        agent = initialize_analysis(platform_config, mock_secrets_client)

        # M2M credentials should be retrieved from the m2m secret
        mock_secrets_client.retrieve_oauth_credentials.assert_called_once_with(
            "test/analysis-m2m"
        )

    def test_analysis_hmac_key_from_secrets(
        self, platform_config, mock_secrets_client
    ):
        """Test that Analysis gets HMAC key for identity context validation."""
        initialize_analysis(platform_config, mock_secrets_client)

        mock_secrets_client.retrieve_hmac_key.assert_called_once_with(
            "test/hmac-key"
        )

    def test_analysis_vuln_db_endpoints_configured(
        self, platform_config, mock_secrets_client
    ):
        """Test that vulnerability DB endpoints are passed to Analysis."""
        agent = initialize_analysis(platform_config, mock_secrets_client)

        assert agent._config.vuln_db_endpoints is not None


# ---------------------------------------------------------------------------
# Platform Initialization Tests
# ---------------------------------------------------------------------------


class TestInitializePlatform:
    """Tests for full platform initialization."""

    @patch("src.agents.startup.StartupSecretsClient")
    def test_successful_platform_initialization(
        self, MockSecretsClient, platform_config
    ):
        """Test that all agents are initialized when secrets are available."""
        mock_client = MockSecretsClient.return_value
        mock_client.retrieve_hmac_key.return_value = b"hmac-key-bytes"
        mock_client.retrieve_oauth_credentials.return_value = {
            "client_id": "test-id",
            "client_secret": "test-secret",
            "callback_url": "https://callback.test",
        }
        mock_client.retrieve_secret.return_value = {"signing_key": "jwt-key"}

        result = initialize_platform(platform_config)

        assert result.success is True
        assert result.orchestrator is not None
        assert result.scanner is not None
        assert result.analysis is not None
        assert result.errors == []

    @patch("src.agents.startup.StartupSecretsClient")
    def test_partial_failure_still_initializes_other_agents(
        self, MockSecretsClient, platform_config
    ):
        """Test that failure of one agent doesn't prevent others."""
        mock_client = MockSecretsClient.return_value
        mock_client.retrieve_hmac_key.side_effect = [
            RuntimeError("HMAC retrieval failed"),  # Orchestrator fails
            b"hmac-key-bytes",  # Scanner succeeds
            b"hmac-key-bytes",  # Analysis succeeds
        ]
        mock_client.retrieve_oauth_credentials.return_value = {
            "client_id": "test-id",
            "client_secret": "test-secret",
            "callback_url": "https://callback.test",
        }

        result = initialize_platform(platform_config)

        assert result.success is False
        assert result.orchestrator is None
        assert result.scanner is not None
        assert result.analysis is not None
        assert len(result.errors) == 1
        assert "Orchestrator" in result.errors[0]

    @patch("src.agents.startup.StartupSecretsClient")
    def test_all_agents_fail(self, MockSecretsClient, platform_config):
        """Test result when all agent initializations fail."""
        mock_client = MockSecretsClient.return_value
        mock_client.retrieve_hmac_key.side_effect = RuntimeError("No access")
        mock_client.retrieve_oauth_credentials.side_effect = RuntimeError(
            "No access"
        )
        mock_client.retrieve_secret.side_effect = RuntimeError("No access")

        result = initialize_platform(platform_config)

        assert result.success is False
        assert result.orchestrator is None
        assert result.scanner is None
        assert result.analysis is None
        assert len(result.errors) == 3


# ---------------------------------------------------------------------------
# Configuration Loading Tests
# ---------------------------------------------------------------------------


class TestLoadPlatformConfigFromEnv:
    """Tests for loading PlatformConfig from environment variables."""

    def test_default_values(self):
        """Test that defaults are used when no env vars are set."""
        with patch.dict(os.environ, {}, clear=True):
            config = load_platform_config_from_env()

        assert config.region == "us-east-1"
        assert config.scanner_endpoint == "https://scanner:8443"
        assert config.analysis_endpoint == "https://analysis:8443"
        assert config.ca_cert_path == "/opt/certs/ca.pem"

    def test_env_vars_override_defaults(self):
        """Test that environment variables override default values."""
        env = {
            "AWS_REGION": "eu-west-1",
            "SCANNER_ENDPOINT": "https://my-scanner:9443",
            "ANALYSIS_ENDPOINT": "https://my-analysis:9443",
            "CA_CERT_PATH": "/custom/ca.pem",
            "COGNITO_ISSUER": "https://cognito.example.com",
            "COGNITO_AUDIENCE": "my-client-id",
            "ORCHESTRATOR_AGENT_ARN": "arn:aws:bedrock-agentcore:eu-west-1:111:workload-identity/directory/default/workload-identity/orchestrator-agent",
        }

        with patch.dict(os.environ, env, clear=False):
            config = load_platform_config_from_env()

        assert config.region == "eu-west-1"
        assert config.scanner_endpoint == "https://my-scanner:9443"
        assert config.analysis_endpoint == "https://my-analysis:9443"
        assert config.ca_cert_path == "/custom/ca.pem"
        assert config.cognito_issuer == "https://cognito.example.com"
        assert config.cognito_audience == "my-client-id"
        assert "eu-west-1" in config.orchestrator_agent_arn
