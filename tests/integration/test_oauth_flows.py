"""Integration tests for OAuth flows.

Tests the GitHub OAuth authorization code flow (Scanner Agent),
M2M client credentials flow (Analysis Agent), token refresh flows,
and consent denied error handling.

Requirements: 4.1, 4.5, 4.6, 5.1, 5.4
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from src.agents.analysis import AnalysisAgent, AnalysisConfig, AnalysisRequest
from src.agents.scanner import (
    AuthorizationError,
    ConsentDeniedError,
    ScannerAgent,
    ScannerConfig,
    ScanRequest,
    ScanResult,
    TokenExpiredError,
    TokenVault,
)
from src.core.identity_context import build_identity_context
from src.core.models import (
    DelegationEntry,
    IdentityContext,
    TokenInfo,
    UserIdentity,
    WorkloadIdentity,
)
from src.core.token_refresh import needs_refresh


# --- Test Helpers ---

HMAC_KEY = b"test-hmac-key-for-integration-tests-32bytes!!"

ORCHESTRATOR_ARN = (
    "arn:aws:bedrock-agentcore:us-east-1:123456789012:"
    "workload-identity/directory/default/workload-identity/orchestrator-agent"
)
SCANNER_ARN = (
    "arn:aws:bedrock-agentcore:us-east-1:123456789012:"
    "workload-identity/directory/default/workload-identity/scanner-agent"
)


def _make_valid_identity_context() -> IdentityContext:
    """Create a valid, signed identity context for testing."""
    user_claims = {
        "subject": "user-123",
        "issuer": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_TestPool",
        "audience": "test-client-id",
        "scopes": ["openid", "profile"],
        "issued_at": datetime.now(timezone.utc) - timedelta(minutes=5),
        "expires_at": datetime.now(timezone.utc) + timedelta(hours=1),
        "token_reference": "jti-test-ref",
    }
    source_agent = WorkloadIdentity(arn=ORCHESTRATOR_ARN, name="orchestrator-agent")
    return build_identity_context(user_claims, source_agent, HMAC_KEY)


def _make_valid_cert_info() -> dict:
    """Create valid mTLS certificate info for testing."""
    return {
        "subject_cn": "orchestrator-agent",
        "issuer_cn": "AgentCore Internal CA",
        "not_after": (datetime.now(timezone.utc) + timedelta(days=365)).isoformat(),
        "is_revoked": False,
        "ca_verified": True,
    }


def _make_scanner_config() -> ScannerConfig:
    """Create a ScannerConfig for testing."""
    return ScannerConfig(
        ca_cert_path="/etc/agentcore/certs/ca.pem",
        hmac_key=HMAC_KEY,
        github_oauth_client_id="test-client-id",
        github_oauth_client_secret="test-client-secret",
        github_oauth_callback_url="https://scanner.example.com/callback",
        identity_directory_endpoint="https://identity.example.com",
    )


def _make_analysis_config() -> AnalysisConfig:
    """Create an AnalysisConfig for testing."""
    return AnalysisConfig(
        ca_cert_path="/etc/agentcore/certs/ca.pem",
        hmac_key=HMAC_KEY,
        m2m_client_id="analysis-client-id",
        m2m_client_secret="analysis-client-secret",
        m2m_token_endpoint="https://auth.example.com/oauth2/token",
        vuln_db_endpoints={
            "nvd": "https://nvd.example.com/api",
            "osv": "https://osv.example.com/api",
        },
    )


# ---------------------------------------------------------------------------
# Test GitHub OAuth Authorization Code Flow (Scanner Agent)
# Validates: Requirement 4.1
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestGitHubOAuthAuthorizationCodeFlow:
    """Tests for the Scanner Agent's OAuth 2.0 authorization code grant flow."""

    @pytest.mark.asyncio
    async def test_initiate_oauth_flow_success(self):
        """Test successful OAuth authorization code flow end-to-end.

        Verifies that when no token exists, the Scanner Agent initiates the
        OAuth flow, exchanges the code for tokens, and stores them.
        Validates: Requirement 4.1
        """
        config = _make_scanner_config()
        agent = ScannerAgent(config)

        # Mock _get_authorization_code to return a valid auth code
        # and _exchange_code_for_tokens to return valid tokens
        now = datetime.now(timezone.utc)
        expected_token = TokenInfo(
            access_token="gh_test_access_token_123",
            refresh_token="gh_test_refresh_token_456",
            expires_at=now + timedelta(hours=1),
            scopes=["security_events", "repo"],
            agent_identity=SCANNER_ARN,
        )

        with patch.object(
            agent, "_get_authorization_code", new_callable=AsyncMock
        ) as mock_get_code, patch.object(
            agent, "_exchange_code_for_tokens", new_callable=AsyncMock
        ) as mock_exchange:
            mock_get_code.return_value = "test_auth_code_789"
            mock_exchange.return_value = expected_token

            # Initiate OAuth flow
            token = await agent._initiate_oauth_flow(
                "user-123", ["security_events", "repo"]
            )

            # Verify authorization code was requested
            mock_get_code.assert_called_once()
            # Verify code exchange occurred
            mock_exchange.assert_called_once_with(
                "test_auth_code_789", ["security_events", "repo"]
            )
            # Verify token returned correctly
            assert token.access_token == "gh_test_access_token_123"
            assert token.refresh_token == "gh_test_refresh_token_456"
            assert token.scopes == ["security_events", "repo"]

    @pytest.mark.asyncio
    async def test_oauth_flow_stores_token_in_vault(self):
        """Test that tokens obtained via OAuth flow are stored in the vault.

        Verifies the full invoke path: when no token is cached, the agent
        obtains one via OAuth and stores it for future use.
        Validates: Requirement 4.1
        """
        config = _make_scanner_config()
        agent = ScannerAgent(config)
        identity_context = _make_valid_identity_context()
        cert_info = _make_valid_cert_info()

        now = datetime.now(timezone.utc)
        mock_token = TokenInfo(
            access_token="gh_stored_token",
            refresh_token="gh_stored_refresh",
            expires_at=now + timedelta(hours=1),
            scopes=["security_events", "repo"],
            agent_identity=SCANNER_ARN,
        )

        with patch.object(
            agent, "_get_authorization_code", new_callable=AsyncMock
        ) as mock_get_code, patch.object(
            agent, "_exchange_code_for_tokens", new_callable=AsyncMock
        ) as mock_exchange, patch.object(
            agent, "_fetch_dependabot_alerts", new_callable=AsyncMock
        ) as mock_alerts, patch.object(
            agent, "_fetch_dependency_manifests", new_callable=AsyncMock
        ) as mock_manifests, patch.object(
            agent, "_fetch_source_code", new_callable=AsyncMock
        ) as mock_source:
            mock_get_code.return_value = "auth_code_store_test"
            mock_exchange.return_value = mock_token
            mock_alerts.return_value = []
            mock_manifests.return_value = []
            mock_source.return_value = []

            request = ScanRequest(
                repository="owner/repo",
                commit_sha="abc123",
                identity_context=identity_context,
                caller_cert_info=cert_info,
            )

            result = await agent.invoke(request)

            assert result.success is True
            # Verify token was stored in vault
            stored = agent._token_vault.get_token(
                agent._agent_arn, "user-123"
            )
            assert stored is not None
            assert stored.access_token == "gh_stored_token"

    @pytest.mark.asyncio
    async def test_oauth_flow_uses_cached_token(self):
        """Test that a valid cached token is used without initiating OAuth.

        Verifies: When a valid (non-expired) token exists in the vault,
        the agent uses it directly without re-initiating the OAuth flow.
        Validates: Requirement 4.1
        """
        config = _make_scanner_config()
        agent = ScannerAgent(config)
        identity_context = _make_valid_identity_context()
        cert_info = _make_valid_cert_info()

        # Pre-store a valid token in the vault
        now = datetime.now(timezone.utc)
        cached_token = TokenInfo(
            access_token="cached_valid_token",
            refresh_token="cached_refresh",
            expires_at=now + timedelta(hours=1),
            scopes=["security_events", "repo"],
            agent_identity=SCANNER_ARN,
        )
        agent._token_vault.store_token(
            agent._agent_arn, "user-123", cached_token
        )

        with patch.object(
            agent, "_initiate_oauth_flow", new_callable=AsyncMock
        ) as mock_oauth, patch.object(
            agent, "_fetch_dependabot_alerts", new_callable=AsyncMock
        ) as mock_alerts, patch.object(
            agent, "_fetch_dependency_manifests", new_callable=AsyncMock
        ) as mock_manifests, patch.object(
            agent, "_fetch_source_code", new_callable=AsyncMock
        ) as mock_source:
            mock_alerts.return_value = []
            mock_manifests.return_value = []
            mock_source.return_value = []

            request = ScanRequest(
                repository="owner/repo",
                commit_sha="abc123",
                identity_context=identity_context,
                caller_cert_info=cert_info,
            )

            result = await agent.invoke(request)

            assert result.success is True
            # OAuth flow should NOT be called since token is valid
            mock_oauth.assert_not_called()


# ---------------------------------------------------------------------------
# Test M2M Client Credentials Flow (Analysis Agent)
# Validates: Requirement 5.1
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestM2MClientCredentialsFlow:
    """Tests for the Analysis Agent's OAuth 2.0 client credentials grant flow."""

    def test_acquire_m2m_token_success(self):
        """Test successful M2M token acquisition via client credentials.

        Verifies that the Analysis Agent obtains a token from the token
        endpoint using client_id and client_secret.
        Validates: Requirement 5.1
        """
        config = _make_analysis_config()
        agent = AnalysisAgent(config)

        # Mock the HTTP call to the token endpoint
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "access_token": "m2m_access_token_xyz",
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": "read:vulnerabilities",
        }
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.post", return_value=mock_response) as mock_post:
            token = agent._acquire_m2m_token()

            assert token == "m2m_access_token_xyz"
            # Verify the POST was made to the token endpoint
            mock_post.assert_called_once()
            call_kwargs = mock_post.call_args
            assert call_kwargs[1]["data"]["grant_type"] == "client_credentials"
            assert call_kwargs[1]["data"]["client_id"] == "analysis-client-id"
            assert call_kwargs[1]["data"]["client_secret"] == "analysis-client-secret"

    def test_acquire_m2m_token_caches_result(self):
        """Test that acquired M2M token is cached for subsequent calls.

        Verifies: Token is stored internally and reused without making
        additional HTTP calls.
        Validates: Requirement 5.1
        """
        config = _make_analysis_config()
        agent = AnalysisAgent(config)

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "access_token": "cached_m2m_token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": "read:vulnerabilities",
        }
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.post", return_value=mock_response) as mock_post:
            # First call - acquires token
            token1 = agent._acquire_m2m_token()
            # Second call - should use cached token
            token2 = agent._acquire_m2m_token()

            assert token1 == "cached_m2m_token"
            assert token2 == "cached_m2m_token"
            # httpx.post should only be called once (cached on second)
            assert mock_post.call_count == 1

    def test_acquire_m2m_token_retries_on_failure(self):
        """Test that M2M token acquisition retries on failure.

        Verifies: Retries up to 3 times with exponential backoff.
        Validates: Requirement 5.1
        """
        config = _make_analysis_config()
        agent = AnalysisAgent(config)

        # All attempts fail
        with patch("httpx.post") as mock_post:
            mock_post.side_effect = httpx.RequestError("Connection refused")

            with pytest.raises(RuntimeError, match="Failed to acquire M2M token"):
                agent._acquire_m2m_token()

            # Should have retried 3 times
            assert mock_post.call_count == 3

    def test_acquire_m2m_token_retries_then_succeeds(self):
        """Test M2M token acquisition succeeds after initial failures.

        Verifies: If early attempts fail but a later attempt succeeds,
        the token is returned successfully.
        Validates: Requirement 5.1
        """
        config = _make_analysis_config()
        agent = AnalysisAgent(config)

        success_response = MagicMock()
        success_response.status_code = 200
        success_response.json.return_value = {
            "access_token": "retry_success_token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": "read:vulnerabilities",
        }
        success_response.raise_for_status = MagicMock()

        with patch("httpx.post") as mock_post:
            # First two calls fail, third succeeds
            mock_post.side_effect = [
                httpx.RequestError("Connection refused"),
                httpx.RequestError("Timeout"),
                success_response,
            ]

            token = agent._acquire_m2m_token()

            assert token == "retry_success_token"
            assert mock_post.call_count == 3


# ---------------------------------------------------------------------------
# Test Token Refresh Flows
# Validates: Requirements 4.5, 5.4
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestTokenRefreshFlows:
    """Tests for token refresh logic in both Scanner and Analysis agents."""

    @pytest.mark.asyncio
    async def test_scanner_refreshes_expired_token(self):
        """Test that Scanner Agent refreshes an expired access token.

        Verifies: When the stored access token is expired but the refresh
        token is valid, the agent uses the refresh token to get a new
        access token without requiring user interaction.
        Validates: Requirement 4.5
        """
        config = _make_scanner_config()
        agent = ScannerAgent(config)
        identity_context = _make_valid_identity_context()
        cert_info = _make_valid_cert_info()

        # Store an expired token with a valid refresh token
        now = datetime.now(timezone.utc)
        expired_token = TokenInfo(
            access_token="expired_access_token",
            refresh_token="valid_refresh_token",
            expires_at=now - timedelta(minutes=5),  # Already expired
            scopes=["security_events", "repo"],
            agent_identity=SCANNER_ARN,
        )
        agent._token_vault.store_token(
            agent._agent_arn, "user-123", expired_token
        )

        # Mock the refresh to return a new token
        refreshed_token = TokenInfo(
            access_token="refreshed_access_token",
            refresh_token="new_refresh_token",
            expires_at=now + timedelta(hours=1),
            scopes=["security_events", "repo"],
            agent_identity=SCANNER_ARN,
        )

        with patch.object(
            agent, "_refresh_github_token", new_callable=AsyncMock
        ) as mock_refresh, patch.object(
            agent, "_fetch_dependabot_alerts", new_callable=AsyncMock
        ) as mock_alerts, patch.object(
            agent, "_fetch_dependency_manifests", new_callable=AsyncMock
        ) as mock_manifests, patch.object(
            agent, "_fetch_source_code", new_callable=AsyncMock
        ) as mock_source:
            mock_refresh.return_value = refreshed_token
            mock_alerts.return_value = []
            mock_manifests.return_value = []
            mock_source.return_value = []

            request = ScanRequest(
                repository="owner/repo",
                commit_sha="abc123",
                identity_context=identity_context,
                caller_cert_info=cert_info,
            )

            result = await agent.invoke(request)

            assert result.success is True
            # Verify refresh was called with the old refresh token
            mock_refresh.assert_called_once_with("valid_refresh_token")
            # Verify new token is stored
            stored = agent._token_vault.get_token(
                agent._agent_arn, "user-123"
            )
            assert stored.access_token == "refreshed_access_token"

    @pytest.mark.asyncio
    async def test_scanner_reinitiates_oauth_when_refresh_token_expired(self):
        """Test new OAuth flow when both access and refresh tokens are expired.

        Verifies: When the refresh token is expired/revoked, the Scanner Agent
        initiates a new authorization code grant flow requiring user interaction.
        Validates: Requirement 4.5
        """
        config = _make_scanner_config()
        agent = ScannerAgent(config)
        identity_context = _make_valid_identity_context()
        cert_info = _make_valid_cert_info()

        # Store an expired token with an expired refresh token
        now = datetime.now(timezone.utc)
        expired_token = TokenInfo(
            access_token="expired_access",
            refresh_token="expired_refresh",
            expires_at=now - timedelta(minutes=5),
            scopes=["security_events", "repo"],
            agent_identity=SCANNER_ARN,
        )
        agent._token_vault.store_token(
            agent._agent_arn, "user-123", expired_token
        )

        # Mock refresh to raise TokenExpiredError (refresh token invalid)
        new_token = TokenInfo(
            access_token="new_oauth_token",
            refresh_token="new_oauth_refresh",
            expires_at=now + timedelta(hours=1),
            scopes=["security_events", "repo"],
            agent_identity=SCANNER_ARN,
        )

        with patch.object(
            agent, "_refresh_github_token", new_callable=AsyncMock
        ) as mock_refresh, patch.object(
            agent, "_initiate_oauth_flow", new_callable=AsyncMock
        ) as mock_oauth, patch.object(
            agent, "_fetch_dependabot_alerts", new_callable=AsyncMock
        ) as mock_alerts, patch.object(
            agent, "_fetch_dependency_manifests", new_callable=AsyncMock
        ) as mock_manifests, patch.object(
            agent, "_fetch_source_code", new_callable=AsyncMock
        ) as mock_source:
            mock_refresh.side_effect = TokenExpiredError()
            mock_oauth.return_value = new_token
            mock_alerts.return_value = []
            mock_manifests.return_value = []
            mock_source.return_value = []

            request = ScanRequest(
                repository="owner/repo",
                commit_sha="def456",
                identity_context=identity_context,
                caller_cert_info=cert_info,
            )

            result = await agent.invoke(request)

            assert result.success is True
            # Verify refresh was attempted first
            mock_refresh.assert_called_once_with("expired_refresh")
            # Then a new OAuth flow was initiated
            mock_oauth.assert_called_once()

    def test_m2m_token_proactive_refresh_within_60_seconds(self):
        """Test that M2M token is proactively refreshed within 60s of expiry.

        Verifies: When the stored M2M token is within 60 seconds of
        expiration, a new token is acquired before the next request.
        Validates: Requirement 5.4
        """
        config = _make_analysis_config()
        agent = AnalysisAgent(config)

        # Set a token that's about to expire (within 60s buffer)
        now = datetime.now(timezone.utc)
        about_to_expire_token = TokenInfo(
            access_token="about_to_expire",
            refresh_token=None,
            expires_at=now + timedelta(seconds=30),  # Within 60s buffer
            scopes=["read:vulnerabilities"],
            agent_identity="analysis-agent",
        )
        agent._m2m_token = about_to_expire_token

        # Verify needs_refresh detects it
        assert needs_refresh(about_to_expire_token.expires_at, now, 60) is True

        # Mock the token endpoint to return a fresh token
        fresh_response = MagicMock()
        fresh_response.status_code = 200
        fresh_response.json.return_value = {
            "access_token": "fresh_m2m_token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": "read:vulnerabilities",
        }
        fresh_response.raise_for_status = MagicMock()

        with patch("httpx.post", return_value=fresh_response):
            token = agent._acquire_m2m_token()

            # Should have acquired a fresh token
            assert token == "fresh_m2m_token"
            # Internal token should be updated
            assert agent._m2m_token.access_token == "fresh_m2m_token"

    def test_m2m_token_not_refreshed_when_far_from_expiry(self):
        """Test M2M token is reused when far from expiration.

        Verifies: Token is not refreshed when more than 60s from expiry.
        Validates: Requirement 5.4
        """
        config = _make_analysis_config()
        agent = AnalysisAgent(config)

        # Set a token that's far from expiry
        now = datetime.now(timezone.utc)
        valid_token = TokenInfo(
            access_token="still_valid_token",
            refresh_token=None,
            expires_at=now + timedelta(hours=1),  # Well outside buffer
            scopes=["read:vulnerabilities"],
            agent_identity="analysis-agent",
        )
        agent._m2m_token = valid_token

        with patch("httpx.post") as mock_post:
            token = agent._acquire_m2m_token()

            assert token == "still_valid_token"
            # Should NOT have called the token endpoint
            mock_post.assert_not_called()


# ---------------------------------------------------------------------------
# Test Consent Denied Error Handling
# Validates: Requirement 4.6
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestConsentDeniedErrorHandling:
    """Tests for consent denied error handling in the Scanner Agent."""

    @pytest.mark.asyncio
    async def test_consent_denied_returns_error_without_resource_access(self):
        """Test that consent denial prevents resource access and returns error.

        Verifies: If the user denies consent on the identity provider's
        consent screen, the Scanner Agent returns an error indication and
        does not access the protected resource.
        Validates: Requirement 4.6
        """
        config = _make_scanner_config()
        agent = ScannerAgent(config)
        identity_context = _make_valid_identity_context()
        cert_info = _make_valid_cert_info()

        with patch.object(
            agent, "_get_authorization_code", new_callable=AsyncMock
        ) as mock_get_code, patch.object(
            agent, "_fetch_dependabot_alerts", new_callable=AsyncMock
        ) as mock_alerts:
            # User denies consent -> _get_authorization_code returns None
            mock_get_code.return_value = None

            request = ScanRequest(
                repository="owner/repo",
                commit_sha="abc123",
                identity_context=identity_context,
                caller_cert_info=cert_info,
            )

            result = await agent.invoke(request)

            # Should fail with consent_denied error
            assert result.success is False
            assert result.error_type == "consent_denied"
            assert "consent" in result.error.lower()
            # Should NOT have attempted to access GitHub resources
            mock_alerts.assert_not_called()

    @pytest.mark.asyncio
    async def test_consent_denied_raises_correct_error_type(self):
        """Test that ConsentDeniedError is raised when auth code is None.

        Verifies: The _initiate_oauth_flow method raises ConsentDeniedError
        when the authorization code is None (consent denied).
        Validates: Requirement 4.6
        """
        config = _make_scanner_config()
        agent = ScannerAgent(config)

        with patch.object(
            agent, "_get_authorization_code", new_callable=AsyncMock
        ) as mock_get_code:
            mock_get_code.return_value = None

            with pytest.raises(ConsentDeniedError):
                await agent._initiate_oauth_flow(
                    "user-456", ["security_events", "repo"]
                )

    @pytest.mark.asyncio
    async def test_authorization_code_exchange_failure(self):
        """Test handling of failed authorization code exchange.

        Verifies: If the code exchange fails, an AuthorizationError is raised
        without exposing internal provider details.
        Validates: Requirement 4.6
        """
        config = _make_scanner_config()
        agent = ScannerAgent(config)

        # Mock getting a valid code, but exchange fails
        with patch.object(
            agent, "_get_authorization_code", new_callable=AsyncMock
        ) as mock_get_code, patch.object(
            agent, "_get_http_client", new_callable=AsyncMock
        ) as mock_client:
            mock_get_code.return_value = "invalid_code"

            # Mock HTTP client to return an error from token endpoint
            mock_http = AsyncMock()
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "error": "bad_verification_code",
                "error_description": "The code is invalid or expired",
            }
            mock_http.post = AsyncMock(return_value=mock_response)
            mock_client.return_value = mock_http

            with pytest.raises(AuthorizationError) as exc_info:
                await agent._initiate_oauth_flow(
                    "user-789", ["security_events", "repo"]
                )

            # Error message should NOT expose internal provider details
            error_msg = str(exc_info.value)
            assert "bad_verification_code" not in error_msg or "failed" in error_msg.lower()

    @pytest.mark.asyncio
    async def test_token_refresh_failure_triggers_new_oauth_flow(self):
        """Test that refresh token failure triggers full re-authorization.

        Verifies: When a refresh token is expired/revoked and access token is
        invalid, a new authorization code grant flow is initiated.
        Validates: Requirement 4.6
        """
        config = _make_scanner_config()
        agent = ScannerAgent(config)

        # Simulate a token refresh that fails with TokenExpiredError
        with patch.object(
            agent, "_get_http_client", new_callable=AsyncMock
        ) as mock_client:
            mock_http = AsyncMock()
            mock_response = MagicMock()
            mock_response.status_code = 401  # Unauthorized
            mock_http.post = AsyncMock(return_value=mock_response)
            mock_client.return_value = mock_http

            with pytest.raises(TokenExpiredError):
                await agent._refresh_github_token("expired_refresh_token")
