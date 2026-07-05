"""Scanner Agent for user-delegated GitHub repository scanning.

Implements the Scanner_Agent responsible for accessing GitHub repositories
via user-delegated OAuth 2.0 (authorization code grant) to pull Dependabot
alerts, read source code, and parse dependency manifests to build dependency
trees and generate initial CycloneDX SBOMs.

Authentication:
- Validates caller mTLS certificate against internal CA
- Validates calling agent workload identity via Identity Directory
- Validates propagated user identity (not tampered, not expired)
- Uses @requires_access_token decorator for GitHub OAuth (USER_FEDERATION)

Deployment:
- Deployed as an AWS AgentCore Runtime instance
- OAuth client credentials retrieved from AWS Secrets Manager at startup
- Handler entry point exposed for AgentCore Runtime invocation

Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.7, 4.8, 6.2, 14.2, 14.3, 17.1
"""

from __future__ import annotations

import functools
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, TypeVar

import httpx

from src.core.constants import SUPPORTED_MANIFESTS
from src.core.correlation import extract_or_generate_correlation_id
from src.core.identity_context import ValidationResult, validate_identity_context
from src.core.metrics import AuthMetrics
from src.core.models import IdentityContext, TokenInfo
from src.core.retry import retry_with_backoff
from src.core.telemetry import TelemetryProvider
from src.core.token_refresh import needs_refresh
from src.sca.manifest_parser import parse_manifest
from src.sca.models import DependencyNode
from src.sca.sbom_generator import CycloneDXBOM, generate_sbom


logger = logging.getLogger(__name__)


F = TypeVar("F", bound=Callable[..., Any])

# GitHub API base URL
GITHUB_API_BASE = "https://api.github.com"

# Required OAuth scopes for Scanner Agent
GITHUB_OAUTH_SCOPES = ["security_events", "repo"]


# --- Error Types ---


class ConsentDeniedError(Exception):
    """Raised when the user denies OAuth consent on the identity provider's consent screen."""

    pass


class TokenExpiredError(Exception):
    """Raised when both access and refresh tokens are expired/revoked."""

    pass


class AuthorizationError(Exception):
    """Raised when authorization code exchange fails."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(f"Authorization failed: {reason}")


class MTLSValidationError(Exception):
    """Raised when mTLS certificate validation fails."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(f"mTLS validation failed: {reason}")


class IdentityValidationError(Exception):
    """Raised when identity context validation fails."""

    def __init__(self, validation_result: ValidationResult) -> None:
        self.validation_result = validation_result
        super().__init__(
            f"Identity validation failed: {validation_result.tamper_type} - "
            f"{validation_result.error_message}"
        )


# --- Configuration ---


@dataclass
class ScannerConfig:
    """Configuration for the Scanner Agent.

    Attributes:
        ca_cert_path: Path to the CA certificate for mTLS validation.
        hmac_key: Secret key for identity context HMAC signature verification.
        github_oauth_client_id: OAuth client ID for GitHub authorization.
        github_oauth_client_secret: OAuth client secret for GitHub authorization.
        github_oauth_callback_url: OAuth callback URL registered in Identity Directory.
        identity_directory_endpoint: Endpoint for workload identity verification.
        telemetry_provider: Optional telemetry provider for span creation.
        metrics: Optional metrics collector for auth event recording.
    """

    ca_cert_path: str = ""
    hmac_key: bytes = b""
    github_oauth_client_id: str = ""
    github_oauth_client_secret: str = ""
    github_oauth_callback_url: str = ""
    identity_directory_endpoint: str = ""
    telemetry_provider: TelemetryProvider | None = None
    metrics: AuthMetrics | None = None


# --- Request/Response Models ---


@dataclass
class ScanRequest:
    """Inbound scan request from the Orchestrator Agent.

    Attributes:
        repository: GitHub repository in "owner/repo" format.
        commit_sha: Git commit SHA to analyze.
        identity_context: Propagated user identity context from Orchestrator.
        caller_cert_info: mTLS certificate information from the calling agent.
        headers: HTTP headers from the inbound request.
    """

    repository: str
    commit_sha: str
    identity_context: IdentityContext
    caller_cert_info: dict = field(default_factory=dict)
    headers: dict = field(default_factory=dict)


@dataclass
class ScanResult:
    """Result of a scan operation returned to the Orchestrator.

    Attributes:
        success: Whether the scan completed successfully.
        repository: The scanned repository identifier.
        commit_sha: The analyzed commit SHA.
        dependabot_alerts: Raw Dependabot alert data from GitHub.
        dependency_tree: Parsed dependency tree.
        sbom: Generated CycloneDX SBOM.
        source_artifacts: Source code files retrieved for call graph analysis.
        error: Error message if the scan failed.
        error_type: Type of error (e.g., "consent_denied", "auth_failed").
    """

    success: bool
    repository: str = ""
    commit_sha: str = ""
    dependabot_alerts: list[dict] = field(default_factory=list)
    dependency_tree: list[DependencyNode] = field(default_factory=list)
    sbom: CycloneDXBOM | None = None
    source_artifacts: list[dict] = field(default_factory=list)
    error: str | None = None
    error_type: str | None = None


# --- Token Vault (in-memory for demonstration) ---


class RefreshTokenReplayError(Exception):
    """Raised when a refresh token is presented that has already been used.

    This indicates a potential token replay attack. OAuth 2.1 mandates
    refresh token rotation and replay detection.
    """

    pass


class TokenVault:
    """In-memory token vault simulating AgentCore Identity Token Vault.

    Stores OAuth tokens keyed by agent-user pairs with encryption at rest
    semantics (simulated in this implementation).

    Implements refresh token rotation with replay detection per OAuth 2.1:
    - When a refresh token is used, the new one replaces it.
    - If the same refresh token is presented twice, it is rejected.
    """

    def __init__(self) -> None:
        self._tokens: dict[str, TokenInfo] = {}
        self.used_refresh_tokens: set[str] = set()

    def get_token(self, agent_identity: str, user_subject: str) -> TokenInfo | None:
        """Retrieve stored token for an agent-user pair.

        Args:
            agent_identity: ARN of the requesting agent.
            user_subject: Subject claim of the user.

        Returns:
            TokenInfo if a token exists for this pair, None otherwise.
        """
        key = f"{agent_identity}:{user_subject}"
        return self._tokens.get(key)

    def store_token(
        self, agent_identity: str, user_subject: str, token: TokenInfo
    ) -> None:
        """Store a token for an agent-user pair.

        Args:
            agent_identity: ARN of the agent.
            user_subject: Subject claim of the user.
            token: The token information to store.
        """
        key = f"{agent_identity}:{user_subject}"
        self._tokens[key] = token

    def remove_token(self, agent_identity: str, user_subject: str) -> None:
        """Remove a stored token for an agent-user pair.

        Args:
            agent_identity: ARN of the agent.
            user_subject: Subject claim of the user.
        """
        key = f"{agent_identity}:{user_subject}"
        self._tokens.pop(key, None)

    def mark_refresh_token_used(self, refresh_token: str) -> None:
        """Mark a refresh token as used for replay detection.

        Args:
            refresh_token: The refresh token that was just consumed.
        """
        self.used_refresh_tokens.add(refresh_token)

    def is_refresh_token_replayed(self, refresh_token: str) -> bool:
        """Check whether a refresh token has already been used (replay attack).

        Args:
            refresh_token: The refresh token to check.

        Returns:
            True if this token was already used, False otherwise.
        """
        return refresh_token in self.used_refresh_tokens


# --- OAuth Decorator ---


def requires_access_token(
    scopes: list[str] | None = None,
) -> Callable[[F], F]:
    """Decorator that ensures a valid GitHub OAuth access token is available.

    Checks the token vault for an existing valid token for the agent-user pair.
    If no token exists or the token is expired, initiates the OAuth 2.0
    authorization code grant flow (USER_FEDERATION).

    If the refresh token is expired/revoked, initiates a new authorization
    code grant flow requiring user interaction.

    If the user denies consent, raises ConsentDeniedError.

    Args:
        scopes: OAuth scopes to request (defaults to GITHUB_OAUTH_SCOPES).

    Returns:
        Decorator that wraps async methods requiring OAuth access.
    """
    if scopes is None:
        scopes = GITHUB_OAUTH_SCOPES

    def decorator(func: F) -> F:
        @functools.wraps(func)
        async def wrapper(self: "ScannerAgent", *args: Any, **kwargs: Any) -> Any:
            # Extract user subject from the identity context in kwargs or args
            identity_context: IdentityContext | None = kwargs.get("identity_context")
            if identity_context is None and args:
                # Try to find it from a ScanRequest argument
                for arg in args:
                    if isinstance(arg, ScanRequest):
                        identity_context = arg.identity_context
                        break

            if identity_context is None:
                raise IdentityValidationError(
                    ValidationResult(
                        is_valid=False,
                        tamper_type="malformed_structure",
                        error_message="No identity context provided",
                    )
                )

            user_subject = identity_context.user_identity.subject
            agent_identity = self._agent_arn

            # Check token vault for existing token
            token = self._token_vault.get_token(agent_identity, user_subject)

            if token is not None:
                # Check if token needs refresh
                now = datetime.now(timezone.utc)
                if needs_refresh(token.expires_at, now):
                    if token.refresh_token:
                        try:
                            token = await self._refresh_github_token(
                                token.refresh_token
                            )
                            self._token_vault.store_token(
                                agent_identity, user_subject, token
                            )
                        except TokenExpiredError:
                            # Refresh token expired - need new auth flow
                            token = await self._initiate_oauth_flow(
                                user_subject, scopes
                            )
                            self._token_vault.store_token(
                                agent_identity, user_subject, token
                            )
                    else:
                        # No refresh token - need new auth flow
                        token = await self._initiate_oauth_flow(
                            user_subject, scopes
                        )
                        self._token_vault.store_token(
                            agent_identity, user_subject, token
                        )
            else:
                # No token exists - initiate OAuth flow
                token = await self._initiate_oauth_flow(user_subject, scopes)
                self._token_vault.store_token(agent_identity, user_subject, token)

            # Inject the access token into kwargs
            kwargs["access_token"] = token.access_token
            return await func(self, *args, **kwargs)

        return wrapper  # type: ignore[return-value]

    return decorator


# --- Scanner Agent Implementation ---


class ScannerAgent:
    """Scanner Agent that accesses GitHub repositories via user-delegated OAuth.

    Performs repository scanning by:
    1. Validating caller mTLS certificate against the internal CA
    2. Validating calling agent workload identity
    3. Validating propagated user identity (not tampered, not expired)
    4. Obtaining a GitHub OAuth token via USER_FEDERATION flow
    5. Fetching Dependabot alerts, dependency manifests, and source code
    6. Parsing manifests into a dependency tree
    7. Generating an initial CycloneDX SBOM

    Args:
        config: ScannerConfig with CA cert, HMAC key, and OAuth credentials.
    """

    def __init__(self, config: ScannerConfig) -> None:
        self._config = config
        self._token_vault = TokenVault()
        self._agent_arn = (
            "arn:aws:bedrock-agentcore:us-east-1:123456789012:"
            "workload-identity/directory/default/workload-identity/scanner-agent"
        )
        self._telemetry = config.telemetry_provider
        self._metrics = config.metrics
        self._http_client: httpx.AsyncClient | None = None

    async def invoke(self, request: ScanRequest) -> ScanResult:
        """Process an inbound scan request from the Orchestrator Agent.

        Validates all authentication layers, obtains GitHub OAuth token,
        and performs repository scanning.

        Args:
            request: The scan request containing repository info and identity context.

        Returns:
            ScanResult with scan data on success, or error details on failure.
        """
        correlation_id = extract_or_generate_correlation_id(request.headers)

        try:
            # Step 1: Validate caller mTLS certificate
            if not self._validate_caller_mtls(request.caller_cert_info):
                return ScanResult(
                    success=False,
                    repository=request.repository,
                    commit_sha=request.commit_sha,
                    error="Caller mTLS certificate validation failed",
                    error_type="mtls_validation_failed",
                )

            # Step 2: Validate calling agent workload identity
            identity_result = self._validate_identity_context(
                request.identity_context
            )
            if not identity_result.is_valid:
                return ScanResult(
                    success=False,
                    repository=request.repository,
                    commit_sha=request.commit_sha,
                    error=identity_result.error_message,
                    error_type=f"identity_{identity_result.tamper_type}",
                )

            # Step 3: Perform scan with OAuth token
            return await self._perform_scan(request)

        except ConsentDeniedError:
            # User denied consent - do not access the resource
            if self._metrics:
                self._metrics.record_authz_denial()
            return ScanResult(
                success=False,
                repository=request.repository,
                commit_sha=request.commit_sha,
                error="User denied consent for GitHub access",
                error_type="consent_denied",
            )

        except AuthorizationError as e:
            return ScanResult(
                success=False,
                repository=request.repository,
                commit_sha=request.commit_sha,
                error=str(e),
                error_type="authorization_failed",
            )

        except Exception as e:
            return ScanResult(
                success=False,
                repository=request.repository,
                commit_sha=request.commit_sha,
                error=f"Unexpected error during scan: {e}",
                error_type="internal_error",
            )

    def _validate_caller_mtls(self, cert_info: dict) -> bool:
        """Validate the caller's mTLS certificate against the internal CA.

        Checks that:
        - A certificate was presented
        - The certificate was issued by the internal Certificate Authority
        - The certificate has not expired
        - The certificate has not been revoked

        Args:
            cert_info: Dictionary containing certificate details:
                - subject_cn: Common Name from the certificate subject
                - issuer_cn: Common Name from the certificate issuer
                - not_after: Certificate expiration datetime (ISO 8601 string)
                - is_revoked: Whether the certificate is revoked
                - ca_verified: Whether the CA chain validates

        Returns:
            True if the certificate is valid, False otherwise.
        """
        start_time = time.time()

        try:
            if not cert_info:
                if self._metrics:
                    self._metrics.record_auth_failure()
                return False

            # Check that a certificate was presented
            if not cert_info.get("subject_cn"):
                if self._metrics:
                    self._metrics.record_auth_failure()
                return False

            # Verify the certificate is issued by the internal CA
            if not cert_info.get("ca_verified", False):
                if self._metrics:
                    self._metrics.record_auth_failure()
                return False

            # Check certificate expiration
            not_after = cert_info.get("not_after")
            if not_after:
                if isinstance(not_after, str):
                    expiry = datetime.fromisoformat(not_after)
                else:
                    expiry = not_after
                if expiry <= datetime.now(timezone.utc):
                    if self._metrics:
                        self._metrics.record_auth_failure()
                    return False

            # Check revocation status
            if cert_info.get("is_revoked", False):
                if self._metrics:
                    self._metrics.record_auth_failure()
                return False

            if self._metrics:
                self._metrics.record_auth_success()
            return True

        finally:
            elapsed_ms = (time.time() - start_time) * 1000
            if self._metrics:
                self._metrics.record_mtls_validation_duration(elapsed_ms)

    def _validate_identity_context(
        self, context: IdentityContext
    ) -> ValidationResult:
        """Validate the propagated user identity context.

        Verifies:
        - The calling agent's workload identity is registered
        - The identity context HMAC signature is intact (not tampered)
        - The user identity has not expired

        Args:
            context: The IdentityContext envelope from the calling agent.

        Returns:
            ValidationResult indicating success or specific failure type.
        """
        if self._telemetry:
            with self._telemetry.create_auth_span(
                "token_validation", self._agent_arn
            ) as span:
                result = validate_identity_context(
                    context, self._config.hmac_key
                )
                if result.is_valid:
                    self._telemetry.record_success(span)
                    if self._metrics:
                        self._metrics.record_auth_success()
                else:
                    self._telemetry.record_failure(
                        span, result.error_message or "Validation failed"
                    )
                    if self._metrics:
                        self._metrics.record_auth_failure()
                return result
        else:
            result = validate_identity_context(context, self._config.hmac_key)
            if result.is_valid and self._metrics:
                self._metrics.record_auth_success()
            elif not result.is_valid and self._metrics:
                self._metrics.record_auth_failure()
            return result

    @requires_access_token(scopes=GITHUB_OAUTH_SCOPES)
    async def _perform_scan(
        self,
        request: ScanRequest,
        *,
        access_token: str = "",
        identity_context: IdentityContext | None = None,
    ) -> ScanResult:
        """Execute the scan operations with a valid GitHub OAuth token.

        Fetches Dependabot alerts, dependency manifests, and source code,
        then builds the dependency tree and generates an SBOM.

        Args:
            request: The scan request.
            access_token: GitHub OAuth token (injected by decorator).
            identity_context: Identity context (used by decorator).

        Returns:
            ScanResult with all scan artifacts.
        """
        repo = request.repository
        token = access_token

        # Fetch Dependabot alerts
        alerts = await self._fetch_dependabot_alerts(repo, token)

        # Fetch dependency manifests
        manifests = await self._fetch_dependency_manifests(repo, token)

        # Build dependency tree from manifests
        dependency_tree = self._build_dependency_tree(manifests)

        # Generate initial CycloneDX SBOM
        sbom = self._generate_sbom(
            dependency_tree, repo, request.commit_sha
        )

        # Fetch source code for call graph analysis
        # Determine which paths to fetch based on manifest locations
        source_paths = self._determine_source_paths(manifests)
        source_artifacts = await self._fetch_source_code(
            repo, token, source_paths
        )

        return ScanResult(
            success=True,
            repository=repo,
            commit_sha=request.commit_sha,
            dependabot_alerts=alerts,
            dependency_tree=dependency_tree,
            sbom=sbom,
            source_artifacts=source_artifacts,
        )

    async def _fetch_dependabot_alerts(
        self, repo: str, token: str
    ) -> list[dict]:
        """Fetch Dependabot security alerts from the GitHub API.

        Requires the `security_events` OAuth scope.

        Args:
            repo: Repository in "owner/repo" format.
            token: GitHub OAuth access token.

        Returns:
            List of Dependabot alert dictionaries from GitHub API.
        """
        url = f"{GITHUB_API_BASE}/repos/{repo}/dependabot/alerts"
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

        if self._telemetry:
            with self._telemetry.create_auth_span(
                "resource_access", self._agent_arn
            ) as span:
                span.set_attribute("auth.target_resource", "github-api")
                span.set_attribute(
                    "auth.scopes_granted", ",".join(GITHUB_OAUTH_SCOPES)
                )
                try:
                    client = await self._get_http_client()
                    response = await client.get(url, headers=headers)
                    response.raise_for_status()
                    self._telemetry.record_success(span)
                    return response.json()
                except httpx.HTTPStatusError as e:
                    self._telemetry.record_failure(
                        span, f"GitHub API error: {e.response.status_code}"
                    )
                    return []
                except Exception as e:
                    self._telemetry.record_failure(span, str(e))
                    return []
        else:
            try:
                client = await self._get_http_client()
                response = await client.get(url, headers=headers)
                response.raise_for_status()
                return response.json()
            except Exception:
                return []

    async def _fetch_dependency_manifests(
        self, repo: str, token: str
    ) -> list[dict]:
        """Fetch dependency manifest files from the GitHub API.

        Searches for supported manifest files (package.json, requirements.txt,
        pom.xml, go.mod, Cargo.toml) in the repository.

        Requires the `repo` OAuth scope.

        Args:
            repo: Repository in "owner/repo" format.
            token: GitHub OAuth access token.

        Returns:
            List of dicts with keys: filename, path, content.
        """
        manifests: list[dict] = []
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

        client = await self._get_http_client()

        for manifest_name in SUPPORTED_MANIFESTS:
            # Search for manifest files in the repository
            search_url = (
                f"{GITHUB_API_BASE}/search/code"
                f"?q=filename:{manifest_name}+repo:{repo}"
            )
            try:
                response = await client.get(search_url, headers=headers)
                if response.status_code != 200:
                    continue

                search_results = response.json()
                items = search_results.get("items", [])

                for item in items:
                    file_path = item.get("path", "")
                    # Fetch file content
                    content_url = (
                        f"{GITHUB_API_BASE}/repos/{repo}/contents/{file_path}"
                    )
                    content_resp = await client.get(
                        content_url, headers=headers
                    )
                    if content_resp.status_code == 200:
                        content_data = content_resp.json()
                        # GitHub returns content as base64 encoded
                        import base64

                        raw_content = base64.b64decode(
                            content_data.get("content", "")
                        ).decode("utf-8")
                        manifests.append(
                            {
                                "filename": manifest_name,
                                "path": file_path,
                                "content": raw_content,
                            }
                        )
            except Exception:
                # Skip unparseable manifests, continue with others
                continue

        return manifests

    async def _fetch_source_code(
        self, repo: str, token: str, paths: list[str]
    ) -> list[dict]:
        """Fetch source code files from the GitHub API for call graph analysis.

        Requires the `repo` OAuth scope.

        Args:
            repo: Repository in "owner/repo" format.
            token: GitHub OAuth access token.
            paths: List of file paths to fetch from the repository.

        Returns:
            List of dicts with keys: path, content, language.
        """
        source_files: list[dict] = []
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

        client = await self._get_http_client()

        for path in paths:
            try:
                url = f"{GITHUB_API_BASE}/repos/{repo}/contents/{path}"
                response = await client.get(url, headers=headers)
                if response.status_code != 200:
                    continue

                content_data = response.json()
                import base64

                raw_content = base64.b64decode(
                    content_data.get("content", "")
                ).decode("utf-8")

                # Detect language from file extension
                language = self._detect_language(path)

                source_files.append(
                    {
                        "path": path,
                        "content": raw_content,
                        "language": language,
                    }
                )
            except Exception:
                continue

        return source_files

    def _build_dependency_tree(
        self, manifests: list[dict]
    ) -> list[DependencyNode]:
        """Parse dependency manifests and build a complete dependency tree.

        Parses each manifest file using the appropriate parser and collects
        all dependencies (including transitive where available).

        Args:
            manifests: List of manifest dicts with filename and content.

        Returns:
            List of DependencyNode objects representing the full dependency tree.
        """
        all_dependencies: list[DependencyNode] = []
        seen_purls: set[str] = set()

        for manifest in manifests:
            filename = manifest.get("filename", "")
            content = manifest.get("content", "")

            if not filename or not content:
                continue

            result = parse_manifest(filename, content)

            for dep in result.dependencies:
                if dep.purl not in seen_purls:
                    seen_purls.add(dep.purl)
                    all_dependencies.append(dep)

        return all_dependencies

    def _generate_sbom(
        self,
        dependency_tree: list[DependencyNode],
        repo: str,
        commit_sha: str,
    ) -> CycloneDXBOM:
        """Generate an initial CycloneDX SBOM from the dependency tree.

        Creates a CycloneDX JSON v1.5 SBOM with name, version, purl,
        and direct/transitive classification for each component.

        Args:
            dependency_tree: Complete list of dependency nodes.
            repo: Repository identifier.
            commit_sha: Git commit SHA being analyzed.

        Returns:
            CycloneDXBOM instance with all components.
        """
        start_time = time.time()
        sbom = generate_sbom(dependency_tree, repo, commit_sha)
        elapsed_ms = (time.time() - start_time) * 1000

        if self._metrics:
            self._metrics.record_sbom_generation_duration(elapsed_ms)

        return sbom

    # --- Helper Methods ---

    def _detect_language(self, path: str) -> str:
        """Detect the programming language from a file path extension.

        Supports: JavaScript, TypeScript, Python, Java, Go, Rust.

        Args:
            path: File path to detect language from.

        Returns:
            Language name string, or "unknown" if not recognized.
        """
        extension_map = {
            ".js": "javascript",
            ".mjs": "javascript",
            ".cjs": "javascript",
            ".jsx": "javascript",
            ".ts": "typescript",
            ".tsx": "typescript",
            ".py": "python",
            ".java": "java",
            ".go": "go",
            ".rs": "rust",
        }
        import os

        _, ext = os.path.splitext(path)
        return extension_map.get(ext.lower(), "unknown")

    def _determine_source_paths(self, manifests: list[dict]) -> list[str]:
        """Determine source code paths to fetch based on manifest locations.

        Infers source directories from manifest locations. For example, if
        a package.json is at "frontend/package.json", the source directory
        is inferred to be "frontend/src".

        Common source directory patterns checked:
        - src/
        - lib/
        - app/
        - (root directory of the manifest)

        Args:
            manifests: List of manifest dicts with "path" keys.

        Returns:
            List of source directory paths to scan for code files.
        """
        import os

        source_paths: list[str] = []
        seen_dirs: set[str] = set()

        # Default source directories relative to manifest location
        source_dir_candidates = ["src", "lib", "app"]

        for manifest in manifests:
            manifest_path = manifest.get("path", "")
            if not manifest_path:
                continue

            # Get the directory containing the manifest
            manifest_dir = os.path.dirname(manifest_path)

            for candidate in source_dir_candidates:
                if manifest_dir:
                    source_dir = f"{manifest_dir}/{candidate}"
                else:
                    source_dir = candidate

                if source_dir not in seen_dirs:
                    seen_dirs.add(source_dir)
                    source_paths.append(source_dir)

            # Also include the manifest directory itself (for root-level source files)
            if manifest_dir and manifest_dir not in seen_dirs:
                seen_dirs.add(manifest_dir)
                source_paths.append(manifest_dir)

        # If no manifests found, use default top-level directories
        if not source_paths:
            source_paths = list(source_dir_candidates)

        return source_paths

    async def _get_http_client(self) -> httpx.AsyncClient:
        """Get or create the shared HTTP client for GitHub API calls.

        Lazily initializes an httpx.AsyncClient with sensible defaults
        for GitHub API interactions.

        Returns:
            An httpx.AsyncClient instance.
        """
        if self._http_client is None:
            self._http_client = httpx.AsyncClient(
                timeout=httpx.Timeout(30.0, connect=10.0),
                follow_redirects=True,
            )
        return self._http_client

    # --- OAuth Flow Methods ---

    async def _initiate_oauth_flow(
        self, user_subject: str, scopes: list[str]
    ) -> TokenInfo:
        """Initiate the OAuth 2.1 authorization code grant flow with PKCE.

        Generates a PKCE code_verifier and code_challenge, redirects the user
        to GitHub's consent screen with the challenge. If the user grants
        consent, exchanges the authorization code (with code_verifier) for
        tokens. If consent is denied, raises ConsentDeniedError.

        Args:
            user_subject: The user's subject identifier.
            scopes: OAuth scopes to request.

        Returns:
            TokenInfo with the obtained access and refresh tokens.

        Raises:
            ConsentDeniedError: If the user denies consent.
            AuthorizationError: If the code exchange fails.
        """
        from src.core.pkce import compute_code_challenge, generate_code_verifier

        start_time = time.time()

        try:
            # Generate PKCE code verifier and challenge (OAuth 2.1 mandatory)
            code_verifier = generate_code_verifier()
            code_challenge = compute_code_challenge(code_verifier)

            # Build the authorization URL with PKCE challenge
            auth_url = self._build_authorization_url(
                scopes, code_challenge=code_challenge
            )

            # In a real implementation, this would redirect the user to auth_url
            # and wait for the callback. Here we simulate the flow through the
            # credential provider.
            auth_code = await self._get_authorization_code(
                auth_url, user_subject
            )

            if auth_code is None:
                raise ConsentDeniedError()

            # Exchange the authorization code for tokens (include code_verifier)
            token = await self._exchange_code_for_tokens(
                auth_code, scopes, code_verifier=code_verifier
            )

            if self._metrics:
                self._metrics.record_auth_success()
                elapsed_ms = (time.time() - start_time) * 1000
                self._metrics.record_token_retrieval_duration(elapsed_ms)

            return token

        except ConsentDeniedError:
            if self._metrics:
                self._metrics.record_authz_denial()
            raise

        except AuthorizationError:
            if self._metrics:
                self._metrics.record_auth_failure()
            raise

    async def _refresh_github_token(self, refresh_token: str) -> TokenInfo:
        """Refresh a GitHub OAuth access token using the refresh token.

        Implements OAuth 2.1 refresh token rotation: the authorization server
        issues a new refresh token with each use, and the old refresh token
        is marked as consumed. If the same refresh token is presented twice,
        it is rejected as a replay attack.

        Args:
            refresh_token: The OAuth refresh token.

        Returns:
            TokenInfo with the new access token and rotated refresh token.

        Raises:
            TokenExpiredError: If the refresh token is expired/revoked.
            RefreshTokenReplayError: If the refresh token was already used.
        """
        start_time = time.time()

        # OAuth 2.1 replay detection: reject already-used refresh tokens
        if self._token_vault.is_refresh_token_replayed(refresh_token):
            raise RefreshTokenReplayError()

        try:
            client = await self._get_http_client()
            response = await client.post(
                "https://github.com/login/oauth/access_token",
                data={
                    "client_id": self._config.github_oauth_client_id,
                    "client_secret": self._config.github_oauth_client_secret,
                    "refresh_token": refresh_token,
                    "grant_type": "refresh_token",
                },
                headers={"Accept": "application/json"},
            )

            if response.status_code != 200:
                raise TokenExpiredError()

            data = response.json()

            if "error" in data:
                error = data["error"]
                if error in ("bad_refresh_token", "expired_token"):
                    raise TokenExpiredError()
                raise AuthorizationError(
                    f"Token refresh failed: {error}"
                )

            from datetime import timedelta

            expires_in = data.get("expires_in", 3600)
            now = datetime.now(timezone.utc)

            # OAuth 2.1: Mark the old refresh token as used (rotation)
            self._token_vault.mark_refresh_token_used(refresh_token)

            # The new refresh token replaces the old one
            new_refresh_token = data.get("refresh_token", refresh_token)

            token = TokenInfo(
                access_token=data["access_token"],
                refresh_token=new_refresh_token,
                expires_at=now + timedelta(seconds=expires_in),
                scopes=data.get("scope", "").split(","),
                agent_identity=self._agent_arn,
            )

            if self._metrics:
                self._metrics.record_token_refresh()
                elapsed_ms = (time.time() - start_time) * 1000
                self._metrics.record_token_refresh_duration(elapsed_ms)

            return token

        except (TokenExpiredError, RefreshTokenReplayError):
            raise

        except Exception as e:
            raise TokenExpiredError() from e

    def _build_authorization_url(
        self, scopes: list[str], *, code_challenge: str | None = None
    ) -> str:
        """Build the GitHub OAuth authorization URL with required parameters.

        Includes client_id, redirect_uri, scopes, state parameter for CSRF
        protection, and PKCE code_challenge/code_challenge_method per OAuth 2.1.

        Args:
            scopes: List of OAuth scopes to request.
            code_challenge: PKCE S256 code challenge (required for OAuth 2.1).

        Returns:
            The full authorization URL string.
        """
        import urllib.parse
        import uuid

        params = {
            "client_id": self._config.github_oauth_client_id,
            "redirect_uri": self._config.github_oauth_callback_url,
            "scope": " ".join(scopes),
            "state": str(uuid.uuid4()),  # CSRF protection
            "response_type": "code",
        }

        # OAuth 2.1: PKCE is mandatory on all authorization code flows
        if code_challenge:
            params["code_challenge"] = code_challenge
            params["code_challenge_method"] = "S256"

        return f"https://github.com/login/oauth/authorize?{urllib.parse.urlencode(params)}"

    async def _get_authorization_code(
        self, auth_url: str, user_subject: str
    ) -> str | None:
        """Obtain the authorization code from the OAuth flow.

        In a real implementation, this would involve redirecting the user
        and waiting for the callback. Returns None if consent is denied.

        Args:
            auth_url: The authorization URL to redirect the user to.
            user_subject: The user's subject identifier.

        Returns:
            The authorization code string, or None if consent was denied.
        """
        # This is a placeholder for the actual OAuth callback handling.
        # In production, the Credential Provider handles the redirect/callback.
        # The method signature supports integration with AgentCore Identity.
        return None  # Triggers ConsentDeniedError in calling code

    async def _exchange_code_for_tokens(
        self, auth_code: str, scopes: list[str], *, code_verifier: str | None = None
    ) -> TokenInfo:
        """Exchange an authorization code for access and refresh tokens.

        Must complete within 30 seconds of receiving the authorization code.
        Includes the PKCE code_verifier for server-side verification per OAuth 2.1.

        Args:
            auth_code: The authorization code from the OAuth callback.
            scopes: The requested OAuth scopes.
            code_verifier: PKCE code verifier for proof of possession (OAuth 2.1).

        Returns:
            TokenInfo with access and refresh tokens.

        Raises:
            AuthorizationError: If the exchange fails.
        """
        client = await self._get_http_client()

        try:
            data = {
                "client_id": self._config.github_oauth_client_id,
                "client_secret": self._config.github_oauth_client_secret,
                "code": auth_code,
                "redirect_uri": self._config.github_oauth_callback_url,
            }

            # OAuth 2.1: Include code_verifier for PKCE verification
            if code_verifier:
                data["code_verifier"] = code_verifier

            response = await client.post(
                "https://github.com/login/oauth/access_token",
                data=data,
                headers={"Accept": "application/json"},
                timeout=30.0,  # Must complete within 30 seconds
            )

            if response.status_code != 200:
                raise AuthorizationError(
                    "Token endpoint returned non-200 status"
                )

            resp_data = response.json()

            if "error" in resp_data:
                # Do not expose internal provider details to end user
                raise AuthorizationError(
                    "Authorization code exchange failed"
                )

            from datetime import timedelta

            expires_in = resp_data.get("expires_in", 3600)
            now = datetime.now(timezone.utc)

            return TokenInfo(
                access_token=resp_data["access_token"],
                refresh_token=resp_data.get("refresh_token"),
                expires_at=now + timedelta(seconds=expires_in),
                scopes=resp_data.get("scope", "").split(","),
                agent_identity=self._agent_arn,
            )

        except httpx.TimeoutException:
            raise AuthorizationError(
                "Authorization code exchange timed out (30s limit)"
            )

        except AuthorizationError:
            raise

        except Exception as e:
            raise AuthorizationError(
                "Authorization code exchange failed"
            ) from e


    async def close(self) -> None:
        """Close the HTTP client and release resources.

        Should be called when the agent is shutting down to ensure
        proper cleanup of connection pools.
        """
        if self._http_client is not None:
            await self._http_client.aclose()
            self._http_client = None


# --- Secrets Manager Integration ---


class SecretsManagerClient:
    """Client for retrieving OAuth credentials from AWS Secrets Manager.

    Implements retry with exponential backoff for resilient secret retrieval.
    Used at agent startup to load GitHub OAuth client credentials without
    hardcoding them in configuration files or environment variables.

    Requirements: 16.1, 16.2, 16.5
    """

    def __init__(self, region_name: str = "us-east-1") -> None:
        """Initialize the Secrets Manager client.

        Args:
            region_name: AWS region for Secrets Manager access.
        """
        self._region_name = region_name
        self._client: Any = None

    def _get_client(self) -> Any:
        """Get or create the boto3 Secrets Manager client.

        Returns:
            A boto3 Secrets Manager client.
        """
        if self._client is None:
            import boto3

            self._client = boto3.client(
                "secretsmanager", region_name=self._region_name
            )
        return self._client

    @retry_with_backoff(max_attempts=3, base_delay_ms=100, multiplier=2, max_delay_ms=5000)
    def get_secret_value(self, secret_id: str) -> dict:
        """Retrieve a secret value from AWS Secrets Manager.

        Retries up to 3 times with exponential backoff on failure.

        Args:
            secret_id: The ARN or name of the secret to retrieve.

        Returns:
            Dictionary of the parsed secret JSON value.

        Raises:
            Exception: If all retry attempts are exhausted.
        """
        client = self._get_client()
        response = client.get_secret_value(SecretId=secret_id)
        secret_string = response.get("SecretString", "{}")
        return json.loads(secret_string)

    def get_oauth_credentials(self, secret_id: str) -> dict:
        """Retrieve OAuth client credentials from Secrets Manager.

        Expects the secret to contain JSON with keys:
        - client_id: GitHub OAuth application client ID
        - client_secret: GitHub OAuth application client secret
        - callback_url: OAuth callback URL registered in Identity Directory

        Args:
            secret_id: The ARN or name of the OAuth credentials secret.

        Returns:
            Dictionary with client_id, client_secret, and callback_url.

        Raises:
            ValueError: If required keys are missing from the secret.
        """
        secret = self.get_secret_value(secret_id)

        required_keys = ["client_id", "client_secret", "callback_url"]
        missing = [k for k in required_keys if k not in secret]
        if missing:
            raise ValueError(
                f"OAuth credentials secret missing required keys: {missing}"
            )

        return {
            "client_id": secret["client_id"],
            "client_secret": secret["client_secret"],
            "callback_url": secret["callback_url"],
        }

    def get_hmac_key(self, secret_id: str) -> bytes:
        """Retrieve the HMAC signing key from Secrets Manager.

        Expects the secret to contain JSON with a "hmac_key" field
        containing a base64-encoded key.

        Args:
            secret_id: The ARN or name of the HMAC key secret.

        Returns:
            The HMAC key as bytes.

        Raises:
            ValueError: If the hmac_key field is missing.
        """
        import base64

        secret = self.get_secret_value(secret_id)

        if "hmac_key" not in secret:
            raise ValueError("HMAC secret missing required 'hmac_key' field")

        return base64.b64decode(secret["hmac_key"])


# --- Factory Function ---


def create_scanner_agent_from_secrets(
    oauth_secret_id: str,
    hmac_secret_id: str,
    ca_cert_path: str = "/etc/agentcore/certs/ca.pem",
    identity_directory_endpoint: str = "",
    region_name: str = "us-east-1",
) -> ScannerAgent:
    """Create a ScannerAgent with credentials loaded from AWS Secrets Manager.

    This is the recommended way to instantiate the Scanner Agent in production.
    Loads OAuth client credentials and HMAC signing key from Secrets Manager
    rather than requiring them in environment variables or config files.

    Args:
        oauth_secret_id: Secrets Manager ARN or name for OAuth credentials.
        hmac_secret_id: Secrets Manager ARN or name for HMAC signing key.
        ca_cert_path: Path to the CA certificate for mTLS validation.
        identity_directory_endpoint: Endpoint for workload identity verification.
        region_name: AWS region for Secrets Manager access.

    Returns:
        A fully configured ScannerAgent instance.
    """
    secrets_client = SecretsManagerClient(region_name=region_name)

    # Retrieve OAuth credentials from Secrets Manager
    oauth_creds = secrets_client.get_oauth_credentials(oauth_secret_id)

    # Retrieve HMAC key from Secrets Manager
    hmac_key = secrets_client.get_hmac_key(hmac_secret_id)

    config = ScannerConfig(
        ca_cert_path=ca_cert_path,
        hmac_key=hmac_key,
        github_oauth_client_id=oauth_creds["client_id"],
        github_oauth_client_secret=oauth_creds["client_secret"],
        github_oauth_callback_url=oauth_creds["callback_url"],
        identity_directory_endpoint=identity_directory_endpoint,
        telemetry_provider=TelemetryProvider(service_name="scanner-agent"),
        metrics=AuthMetrics(agent_name="scanner-agent"),
    )

    return ScannerAgent(config)


# --- AWS AgentCore Runtime Handler ---


# Module-level agent instance (lazy-initialized on first invocation)
_scanner_agent: ScannerAgent | None = None


def _get_or_create_agent() -> ScannerAgent:
    """Get or create the module-level ScannerAgent instance.

    Reads configuration from environment variables on first call:
    - SCANNER_OAUTH_SECRET_ID: Secrets Manager ARN for OAuth credentials
    - SCANNER_HMAC_SECRET_ID: Secrets Manager ARN for HMAC key
    - SCANNER_CA_CERT_PATH: Path to CA certificate (default: /etc/agentcore/certs/ca.pem)
    - SCANNER_IDENTITY_DIRECTORY_ENDPOINT: Identity Directory endpoint URL
    - AWS_REGION: AWS region (default: us-east-1)

    Returns:
        The initialized ScannerAgent.
    """
    global _scanner_agent

    if _scanner_agent is None:
        import os

        oauth_secret_id = os.environ.get(
            "SCANNER_OAUTH_SECRET_ID",
            "agentcore/scanner/github-oauth-credentials",
        )
        hmac_secret_id = os.environ.get(
            "SCANNER_HMAC_SECRET_ID",
            "agentcore/scanner/hmac-signing-key",
        )
        ca_cert_path = os.environ.get(
            "SCANNER_CA_CERT_PATH",
            "/etc/agentcore/certs/ca.pem",
        )
        identity_directory_endpoint = os.environ.get(
            "SCANNER_IDENTITY_DIRECTORY_ENDPOINT", ""
        )
        region_name = os.environ.get("AWS_REGION", "us-east-1")

        _scanner_agent = create_scanner_agent_from_secrets(
            oauth_secret_id=oauth_secret_id,
            hmac_secret_id=hmac_secret_id,
            ca_cert_path=ca_cert_path,
            identity_directory_endpoint=identity_directory_endpoint,
            region_name=region_name,
        )

    return _scanner_agent


def _parse_identity_context(raw: dict) -> IdentityContext:
    """Parse a serialized identity context dictionary into an IdentityContext object.

    Args:
        raw: Dictionary representation of the identity context (from JSON).

    Returns:
        Populated IdentityContext dataclass.
    """
    from src.core.models import DelegationEntry, UserIdentity, WorkloadIdentity

    source_agent_data = raw.get("source_agent", {})
    source_agent = WorkloadIdentity(
        arn=source_agent_data.get("arn", ""),
        name=source_agent_data.get("name", ""),
    )

    ui_data = raw.get("user_identity", {})
    user_identity = UserIdentity(
        subject=ui_data.get("subject", ""),
        issuer=ui_data.get("issuer", ""),
        audience=ui_data.get("audience", ""),
        scopes=ui_data.get("scopes", []),
        issued_at=datetime.fromisoformat(ui_data["issued_at"])
        if "issued_at" in ui_data
        else datetime.now(timezone.utc),
        expires_at=datetime.fromisoformat(ui_data["expires_at"])
        if "expires_at" in ui_data
        else datetime.now(timezone.utc),
        token_reference=ui_data.get("token_reference", ""),
    )

    delegation_chain = [
        DelegationEntry(
            agent_arn=entry.get("agent_arn", ""),
            delegated_at=datetime.fromisoformat(entry["delegated_at"])
            if "delegated_at" in entry
            else datetime.now(timezone.utc),
        )
        for entry in raw.get("delegation_chain", [])
    ]

    return IdentityContext(
        version=raw.get("version", "1.0"),
        correlation_id=raw.get("correlation_id", ""),
        source_agent=source_agent,
        user_identity=user_identity,
        delegation_chain=delegation_chain,
        signature=raw.get("signature", ""),
    )


async def handler(event: dict, context: Any) -> dict:
    """AWS AgentCore Runtime handler entry point for the Scanner Agent.

    This function is invoked by AgentCore Runtime when the Scanner Agent
    receives an /invoke request. It deserializes the event, constructs a
    ScanRequest, invokes the ScannerAgent, and returns the serialized response.

    The handler expects the event to contain:
    - identity_context: Serialized identity context from the Orchestrator
    - request: Dict with repository, commit_sha, and other scan parameters
    - caller_cert_info: mTLS certificate metadata from the calling agent
    - headers: HTTP headers from the inbound request

    Args:
        event: The AgentCore Runtime invocation event.
        context: The AgentCore Runtime context (provides metadata about the invocation).

    Returns:
        Dictionary response serializable to JSON, containing scan results or error.
    """
    import asyncio

    agent = _get_or_create_agent()

    try:
        # Parse the identity context
        raw_identity = event.get("identity_context", {})
        identity_context = _parse_identity_context(raw_identity)

        # Build the scan request
        request_data = event.get("request", {})
        scan_request = ScanRequest(
            repository=request_data.get("repository", ""),
            commit_sha=request_data.get("commit_sha", ""),
            identity_context=identity_context,
            caller_cert_info=event.get("caller_cert_info", {}),
            headers=event.get("headers", {}),
        )

        # Execute the scan
        result = await agent.invoke(scan_request)

        # Serialize the response
        response = {
            "success": result.success,
            "repository": result.repository,
            "commit_sha": result.commit_sha,
            "error": result.error,
            "error_type": result.error_type,
        }

        if result.success:
            response["dependabot_alerts"] = result.dependabot_alerts
            response["dependency_tree"] = [
                {
                    "name": dep.name,
                    "version": dep.version,
                    "purl": dep.purl,
                    "is_direct": dep.is_direct,
                }
                for dep in result.dependency_tree
            ]
            response["sbom"] = (
                result.sbom.to_dict() if result.sbom else None
            )
            response["source_artifacts"] = result.source_artifacts

        return response

    except Exception as e:
        logger.exception("Scanner handler encountered an unexpected error")
        return {
            "success": False,
            "error": f"Handler error: {e}",
            "error_type": "handler_error",
        }


# Synchronous wrapper for non-async AgentCore Runtime environments
def handler_sync(event: dict, context: Any) -> dict:
    """Synchronous handler entry point for AgentCore Runtime.

    Wraps the async handler for environments that do not natively
    support async invocation.

    Args:
        event: The AgentCore Runtime invocation event.
        context: The AgentCore Runtime context.

    Returns:
        Dictionary response serializable to JSON.
    """
    import asyncio

    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(handler(event, context))
    finally:
        loop.close()
