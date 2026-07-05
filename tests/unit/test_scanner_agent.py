"""Unit tests for the Scanner Agent.

Tests the ScannerAgent class covering:
- mTLS certificate validation (Requirement 14.2, 14.3)
- Identity context validation (Requirement 6.2)
- OAuth decorator token management (Requirement 4.1, 4.5, 4.7)
- GitHub API interactions (Requirement 4.3, 4.4)
- Dependency tree building (Requirement 17.1)
- SBOM generation
- Consent denied error handling (Requirement 4.6)
- Expired refresh token handling (Requirement 4.7)
- Helper methods (_detect_language, _determine_source_paths, _get_http_client)
"""

from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.agents.scanner import (
    AuthorizationError,
    ConsentDeniedError,
    IdentityValidationError,
    MTLSValidationError,
    ScannerAgent,
    ScannerConfig,
    ScanRequest,
    ScanResult,
    TokenExpiredError,
    TokenVault,
    requires_access_token,
    GITHUB_OAUTH_SCOPES,
)
from src.core.models import (
    DelegationEntry,
    IdentityContext,
    TokenInfo,
    UserIdentity,
    WorkloadIdentity,
)


# Test constants
HMAC_KEY = b"test-hmac-key-for-identity-signing"
CA_CERT_PATH = "/tmp/certs/ca.pem"
SCANNER_ARN = (
    "arn:aws:bedrock-agentcore:us-east-1:123456789012:"
    "workload-identity/directory/default/workload-identity/scanner-agent"
)
ORCHESTRATOR_ARN = (
    "arn:aws:bedrock-agentcore:us-east-1:123456789012:"
    "workload-identity/directory/default/workload-identity/orchestrator-agent"
)


def _make_config() -> ScannerConfig:
    """Create a test ScannerConfig."""
    return ScannerConfig(
        ca_cert_path=CA_CERT_PATH,
        hmac_key=HMAC_KEY,
        github_oauth_client_id="test-client-id",
        github_oauth_client_secret="test-client-secret",
        github_oauth_callback_url="https://scanner.example.com/callback",
        identity_directory_endpoint="https://identity.example.com",
    )


def _make_identity_context(
    expired: bool = False,
    tampered: bool = False,
) -> IdentityContext:
    """Create a test IdentityContext."""
    from src.core.identity_context import build_identity_context

    now = datetime.now(timezone.utc)
    if expired:
        issued_at = now - timedelta(hours=2)
        expires_at = now - timedelta(hours=1)
    else:
        issued_at = now - timedelta(minutes=5)
        expires_at = now + timedelta(hours=1)

    user_claims = {
        "subject": "user-sub-123",
        "issuer": "https://cognito-idp.us-east-1.amazonaws.com/pool-123",
        "audience": "test-client-id",
        "scopes": ["openid", "profile"],
        "issued_at": issued_at,
        "expires_at": expires_at,
        "token_reference": "jti-abc-123",
    }

    source_agent = WorkloadIdentity(
        arn=ORCHESTRATOR_ARN,
        name="orchestrator-agent",
    )

    context = build_identity_context(user_claims, source_agent, HMAC_KEY)

    if tampered:
        # Tamper with the subject to invalidate the signature
        from dataclasses import replace

        tampered_user = UserIdentity(
            subject="tampered-subject",
            issuer=context.user_identity.issuer,
            audience=context.user_identity.audience,
            scopes=context.user_identity.scopes,
            issued_at=context.user_identity.issued_at,
            expires_at=context.user_identity.expires_at,
            token_reference=context.user_identity.token_reference,
        )
        context.user_identity = tampered_user

    return context


def _make_valid_cert_info() -> dict:
    """Create valid mTLS certificate info."""
    return {
        "subject_cn": "orchestrator-agent",
        "issuer_cn": "Internal-CA",
        "not_after": (datetime.now(timezone.utc) + timedelta(days=365)).isoformat(),
        "is_revoked": False,
        "ca_verified": True,
    }


def _make_scan_request(
    expired_identity: bool = False,
    tampered_identity: bool = False,
    valid_cert: bool = True,
) -> ScanRequest:
    """Create a test ScanRequest."""
    cert_info = _make_valid_cert_info() if valid_cert else {}
    return ScanRequest(
        repository="owner/test-repo",
        commit_sha="abc123def456",
        identity_context=_make_identity_context(
            expired=expired_identity,
            tampered=tampered_identity,
        ),
        caller_cert_info=cert_info,
        headers={"X-Correlation-ID": "550e8400-e29b-41d4-a716-446655440000"},
    )


class TestScannerInit:
    """Tests for ScannerAgent initialization."""

    def test_creates_agent_with_config(self):
        config = _make_config()
        agent = ScannerAgent(config)
        assert agent._config is config
        assert agent._agent_arn == SCANNER_ARN

    def test_initializes_empty_token_vault(self):
        config = _make_config()
        agent = ScannerAgent(config)
        assert isinstance(agent._token_vault, TokenVault)


class TestMTLSValidation:
    """Tests for mTLS certificate validation (Requirements 14.2, 14.3)."""

    def test_valid_certificate_accepted(self):
        config = _make_config()
        agent = ScannerAgent(config)
        cert_info = _make_valid_cert_info()
        assert agent._validate_caller_mtls(cert_info) is True

    def test_empty_cert_info_rejected(self):
        config = _make_config()
        agent = ScannerAgent(config)
        assert agent._validate_caller_mtls({}) is False

    def test_no_subject_cn_rejected(self):
        config = _make_config()
        agent = ScannerAgent(config)
        cert_info = _make_valid_cert_info()
        cert_info["subject_cn"] = ""
        assert agent._validate_caller_mtls(cert_info) is False

    def test_ca_not_verified_rejected(self):
        config = _make_config()
        agent = ScannerAgent(config)
        cert_info = _make_valid_cert_info()
        cert_info["ca_verified"] = False
        assert agent._validate_caller_mtls(cert_info) is False

    def test_expired_cert_rejected(self):
        config = _make_config()
        agent = ScannerAgent(config)
        cert_info = _make_valid_cert_info()
        cert_info["not_after"] = (
            datetime.now(timezone.utc) - timedelta(days=1)
        ).isoformat()
        assert agent._validate_caller_mtls(cert_info) is False

    def test_revoked_cert_rejected(self):
        config = _make_config()
        agent = ScannerAgent(config)
        cert_info = _make_valid_cert_info()
        cert_info["is_revoked"] = True
        assert agent._validate_caller_mtls(cert_info) is False


class TestIdentityContextValidation:
    """Tests for identity context validation (Requirement 6.2)."""

    def test_valid_identity_context_accepted(self):
        config = _make_config()
        agent = ScannerAgent(config)
        context = _make_identity_context()
        result = agent._validate_identity_context(context)
        assert result.is_valid is True

    def test_expired_identity_context_rejected(self):
        config = _make_config()
        agent = ScannerAgent(config)
        context = _make_identity_context(expired=True)
        result = agent._validate_identity_context(context)
        assert result.is_valid is False
        assert result.tamper_type == "expired_identity"

    def test_tampered_identity_context_rejected(self):
        config = _make_config()
        agent = ScannerAgent(config)
        context = _make_identity_context(tampered=True)
        result = agent._validate_identity_context(context)
        assert result.is_valid is False
        assert result.tamper_type == "signature_mismatch"


class TestTokenVault:
    """Tests for TokenVault (Requirement 4.4)."""

    def test_store_and_retrieve_token(self):
        vault = TokenVault()
        token = TokenInfo(
            access_token="gho_test_token",
            refresh_token="ghr_test_refresh",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            scopes=["security_events", "repo"],
            agent_identity=SCANNER_ARN,
        )
        vault.store_token(SCANNER_ARN, "user-sub-123", token)
        retrieved = vault.get_token(SCANNER_ARN, "user-sub-123")
        assert retrieved is not None
        assert retrieved.access_token == "gho_test_token"

    def test_returns_none_for_missing_token(self):
        vault = TokenVault()
        assert vault.get_token(SCANNER_ARN, "unknown-user") is None

    def test_remove_token(self):
        vault = TokenVault()
        token = TokenInfo(
            access_token="gho_test_token",
            refresh_token="ghr_test_refresh",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            scopes=["security_events", "repo"],
            agent_identity=SCANNER_ARN,
        )
        vault.store_token(SCANNER_ARN, "user-sub-123", token)
        vault.remove_token(SCANNER_ARN, "user-sub-123")
        assert vault.get_token(SCANNER_ARN, "user-sub-123") is None


class TestInvokeEndpoint:
    """Tests for the invoke endpoint (Requirements 4.1, 6.2, 14.2)."""

    @pytest.mark.asyncio
    async def test_rejects_invalid_mtls_cert(self):
        config = _make_config()
        agent = ScannerAgent(config)
        request = _make_scan_request(valid_cert=False)

        result = await agent.invoke(request)
        assert result.success is False
        assert result.error_type == "mtls_validation_failed"

    @pytest.mark.asyncio
    async def test_rejects_expired_identity(self):
        config = _make_config()
        agent = ScannerAgent(config)
        request = _make_scan_request(expired_identity=True)

        result = await agent.invoke(request)
        assert result.success is False
        assert result.error_type == "identity_expired_identity"

    @pytest.mark.asyncio
    async def test_rejects_tampered_identity(self):
        config = _make_config()
        agent = ScannerAgent(config)
        request = _make_scan_request(tampered_identity=True)

        result = await agent.invoke(request)
        assert result.success is False
        assert result.error_type == "identity_signature_mismatch"

    @pytest.mark.asyncio
    async def test_consent_denied_returns_error(self):
        """Consent denied → do not access resource, return error (Req 4.6)."""
        config = _make_config()
        agent = ScannerAgent(config)
        request = _make_scan_request()

        # The default _get_authorization_code returns None → ConsentDeniedError
        result = await agent.invoke(request)
        assert result.success is False
        assert result.error_type == "consent_denied"
        assert "consent" in result.error.lower()


class TestDetectLanguage:
    """Tests for _detect_language helper method."""

    def test_javascript_extensions(self):
        config = _make_config()
        agent = ScannerAgent(config)
        assert agent._detect_language("src/index.js") == "javascript"
        assert agent._detect_language("lib/utils.mjs") == "javascript"
        assert agent._detect_language("app.cjs") == "javascript"
        assert agent._detect_language("Component.jsx") == "javascript"

    def test_typescript_extensions(self):
        config = _make_config()
        agent = ScannerAgent(config)
        assert agent._detect_language("src/main.ts") == "typescript"
        assert agent._detect_language("Component.tsx") == "typescript"

    def test_python_extension(self):
        config = _make_config()
        agent = ScannerAgent(config)
        assert agent._detect_language("app/main.py") == "python"

    def test_java_extension(self):
        config = _make_config()
        agent = ScannerAgent(config)
        assert agent._detect_language("src/Main.java") == "java"

    def test_go_extension(self):
        config = _make_config()
        agent = ScannerAgent(config)
        assert agent._detect_language("cmd/main.go") == "go"

    def test_rust_extension(self):
        config = _make_config()
        agent = ScannerAgent(config)
        assert agent._detect_language("src/lib.rs") == "rust"

    def test_unknown_extension(self):
        config = _make_config()
        agent = ScannerAgent(config)
        assert agent._detect_language("README.md") == "unknown"
        assert agent._detect_language("data.csv") == "unknown"


class TestDetermineSourcePaths:
    """Tests for _determine_source_paths helper method."""

    def test_infers_source_dirs_from_manifests(self):
        config = _make_config()
        agent = ScannerAgent(config)
        manifests = [{"path": "package.json", "filename": "package.json"}]
        paths = agent._determine_source_paths(manifests)
        assert "src" in paths
        assert "lib" in paths
        assert "app" in paths

    def test_includes_nested_manifest_dirs(self):
        config = _make_config()
        agent = ScannerAgent(config)
        manifests = [
            {"path": "frontend/package.json", "filename": "package.json"}
        ]
        paths = agent._determine_source_paths(manifests)
        assert "frontend/src" in paths
        assert "frontend/lib" in paths
        assert "frontend/app" in paths
        assert "frontend" in paths

    def test_empty_manifests_returns_defaults(self):
        config = _make_config()
        agent = ScannerAgent(config)
        paths = agent._determine_source_paths([])
        assert "src" in paths
        assert "lib" in paths
        assert "app" in paths

    def test_deduplicates_paths(self):
        config = _make_config()
        agent = ScannerAgent(config)
        manifests = [
            {"path": "package.json", "filename": "package.json"},
            {"path": "requirements.txt", "filename": "requirements.txt"},
        ]
        paths = agent._determine_source_paths(manifests)
        # Should not have duplicates
        assert len(paths) == len(set(paths))


class TestGetHttpClient:
    """Tests for _get_http_client helper method."""

    @pytest.mark.asyncio
    async def test_returns_http_client(self):
        config = _make_config()
        agent = ScannerAgent(config)
        client = await agent._get_http_client()
        assert client is not None

    @pytest.mark.asyncio
    async def test_reuses_client_on_subsequent_calls(self):
        config = _make_config()
        agent = ScannerAgent(config)
        client1 = await agent._get_http_client()
        client2 = await agent._get_http_client()
        assert client1 is client2


class TestBuildDependencyTree:
    """Tests for dependency tree building (Requirement 17.1)."""

    def test_builds_tree_from_manifests(self):
        config = _make_config()
        agent = ScannerAgent(config)
        manifests = [
            {
                "filename": "requirements.txt",
                "path": "requirements.txt",
                "content": "requests==2.28.0\nflask==2.3.0\n",
            }
        ]
        tree = agent._build_dependency_tree(manifests)
        assert len(tree) > 0
        # Check that at least requests is in the tree
        names = [dep.name for dep in tree]
        assert "requests" in names

    def test_skips_empty_manifests(self):
        config = _make_config()
        agent = ScannerAgent(config)
        manifests = [
            {"filename": "", "path": "", "content": ""},
            {"filename": "requirements.txt", "path": "requirements.txt", "content": ""},
        ]
        tree = agent._build_dependency_tree(manifests)
        assert tree == []

    def test_deduplicates_dependencies(self):
        config = _make_config()
        agent = ScannerAgent(config)
        manifests = [
            {
                "filename": "requirements.txt",
                "path": "requirements.txt",
                "content": "requests==2.28.0\n",
            },
            {
                "filename": "requirements.txt",
                "path": "subdir/requirements.txt",
                "content": "requests==2.28.0\nflask==2.3.0\n",
            },
        ]
        tree = agent._build_dependency_tree(manifests)
        purls = [dep.purl for dep in tree]
        assert len(purls) == len(set(purls))


class TestRefreshGitHubToken:
    """Tests for token refresh (Requirements 4.5, 4.7)."""

    @pytest.mark.asyncio
    async def test_expired_refresh_token_raises(self):
        """Expired refresh token → TokenExpiredError (Req 4.7)."""
        config = _make_config()
        agent = ScannerAgent(config)

        # Mock the http client to return an error
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_response)
        agent._http_client = mock_client

        with pytest.raises(TokenExpiredError):
            await agent._refresh_github_token("expired-refresh-token")

    @pytest.mark.asyncio
    async def test_successful_refresh_returns_new_token(self):
        """Successful refresh returns new TokenInfo (Req 4.5)."""
        config = _make_config()
        agent = ScannerAgent(config)

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "access_token": "gho_new_access_token",
            "refresh_token": "ghr_new_refresh_token",
            "expires_in": 3600,
            "scope": "security_events,repo",
        }
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_response)
        agent._http_client = mock_client

        token = await agent._refresh_github_token("ghr_old_refresh_token")
        assert token.access_token == "gho_new_access_token"
        assert token.refresh_token == "ghr_new_refresh_token"
        assert "security_events" in token.scopes


class TestExchangeCodeForTokens:
    """Tests for authorization code exchange (Requirements 4.3, 4.8)."""

    @pytest.mark.asyncio
    async def test_successful_exchange(self):
        config = _make_config()
        agent = ScannerAgent(config)

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "access_token": "gho_exchanged_token",
            "refresh_token": "ghr_exchanged_refresh",
            "expires_in": 3600,
            "scope": "security_events,repo",
        }
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_response)
        agent._http_client = mock_client

        token = await agent._exchange_code_for_tokens(
            "auth-code-123", ["security_events", "repo"]
        )
        assert token.access_token == "gho_exchanged_token"
        assert token.refresh_token == "ghr_exchanged_refresh"

    @pytest.mark.asyncio
    async def test_failed_exchange_raises_authorization_error(self):
        """Auth code exchange failure (Req 4.8)."""
        config = _make_config()
        agent = ScannerAgent(config)

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "error": "bad_verification_code",
            "error_description": "The code passed is incorrect or expired.",
        }
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_response)
        agent._http_client = mock_client

        with pytest.raises(AuthorizationError):
            await agent._exchange_code_for_tokens(
                "invalid-code", ["security_events", "repo"]
            )

    @pytest.mark.asyncio
    async def test_non_200_response_raises_authorization_error(self):
        config = _make_config()
        agent = ScannerAgent(config)

        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_response)
        agent._http_client = mock_client

        with pytest.raises(AuthorizationError):
            await agent._exchange_code_for_tokens(
                "some-code", ["security_events", "repo"]
            )


class TestBuildAuthorizationUrl:
    """Tests for OAuth authorization URL construction."""

    def test_includes_required_params(self):
        config = _make_config()
        agent = ScannerAgent(config)
        url = agent._build_authorization_url(["security_events", "repo"])
        assert "client_id=test-client-id" in url
        assert "security_events" in url
        assert "repo" in url
        assert "response_type=code" in url
        assert "state=" in url
        assert "redirect_uri=" in url


class TestOAuthScopes:
    """Tests for OAuth scope configuration."""

    def test_default_scopes_are_security_events_and_repo(self):
        assert "security_events" in GITHUB_OAUTH_SCOPES
        assert "repo" in GITHUB_OAUTH_SCOPES
        assert len(GITHUB_OAUTH_SCOPES) == 2
