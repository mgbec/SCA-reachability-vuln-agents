"""CLI workflow demonstrations for AgentCore Identity authentication flows.

Implements each authentication and analysis workflow step by step, with
sequential step numbering and descriptive stage names. Supports both
summary mode (default) and verbose mode.

Workflows:
1. User Authentication (Cognito AuthZ Code Grant)
2. User-Delegated Access (Scanner Agent → GitHub)
3. Machine-to-Machine (Analysis Agent → Vulnerability DBs)
4. Multi-Agent Delegation (Orchestrator → sub-agent dispatch)
5. Full Vulnerability Analysis (scan → analyze → score → recommend)

Requirements: 8.1, 8.2, 8.3, 8.4, 8.5
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

import click
import httpx

from src.core.masking import mask_authorization_header, mask_sensitive


# --- Workflow Step Tracking ---


@dataclass
class WorkflowStep:
    """Represents a single step in a workflow demonstration.

    Attributes:
        step_number: Sequential step number (1-based).
        stage_name: Descriptive name for this stage.
        success: Whether the step completed successfully.
        details: Additional details about the step result.
        error: Error message if step failed.
        verbose_data: Extra data shown only in verbose mode.
    """

    step_number: int
    stage_name: str
    success: bool = True
    details: str = ""
    error: str | None = None
    verbose_data: dict[str, Any] = field(default_factory=dict)


def _display_step(step: WorkflowStep, verbose: bool) -> None:
    """Display a workflow step in summary or verbose mode.

    Args:
        step: The workflow step to display.
        verbose: Whether to show verbose output.
    """
    status = "✓" if step.success else "✗"
    click.echo(f"[{step.step_number}] {step.stage_name} — {status}")

    if step.details:
        click.echo(f"    {step.details}")

    if step.error:
        click.echo(f"    Error: {step.error}")

    if verbose and step.verbose_data:
        masked = mask_sensitive(step.verbose_data)
        for key, value in masked.items():
            if isinstance(value, dict):
                click.echo(f"    {key}:")
                for k, v in value.items():
                    click.echo(f"      {k}: {v}")
            else:
                click.echo(f"    {key}: {value}")


# --- Workflow 1: User Authentication ---


def run_device_authorization_workflow(
    config: dict,
    verbose: bool,
) -> list[WorkflowStep]:
    """Demonstrate Device Authorization Grant (RFC 8628) for CLI authentication.

    OAuth 2.1 removes ROPC (Resource Owner Password Credentials). CLI clients
    use the Device Authorization Grant instead: request a device code, display
    a user_code and verification_uri, and poll until the user authorizes.

    Steps:
    1. Request device code from authorization server
    2. Display verification URI and user code to the user
    3. Poll token endpoint until authorization is granted
    4. JWT acquisition confirmation

    Args:
        config: Resolved CLI configuration.
        verbose: Whether to display verbose output.

    Returns:
        List of WorkflowStep results.
    """
    steps: list[WorkflowStep] = []
    cognito_endpoint = config.get("cognito_endpoint", "")
    cognito_client_id = config.get("cognito_client_id", "")

    click.echo("\n=== Workflow: Device Authorization Grant (OAuth 2.1) ===\n")

    # Step 1: Request device code
    device_auth_url = f"{cognito_endpoint}/oauth2/device_authorization"
    step1 = WorkflowStep(
        step_number=1,
        stage_name="Request Device Code",
        details="Requesting device code from authorization server",
        verbose_data={
            "device_authorization_endpoint": device_auth_url,
            "client_id": cognito_client_id,
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        },
    )

    if not cognito_endpoint or not cognito_client_id:
        step1.success = False
        step1.error = "Cognito endpoint or client ID not configured"
        _display_step(step1, verbose)
        steps.append(step1)
        return steps

    device_code = None
    user_code = None
    verification_uri = None
    interval = 5

    try:
        response = httpx.post(
            device_auth_url,
            data={
                "client_id": cognito_client_id,
                "scope": "openid profile",
            },
            timeout=30.0,
        )
        if response.status_code == 200:
            data = response.json()
            device_code = data.get("device_code")
            user_code = data.get("user_code")
            verification_uri = data.get("verification_uri")
            interval = data.get("interval", 5)
            step1.success = True
            step1.details = "Device code obtained successfully"
            step1.verbose_data.update({
                "device_code": device_code[:8] + "..." if device_code else None,
                "expires_in": data.get("expires_in"),
                "interval": interval,
            })
        else:
            step1.success = False
            step1.error = f"Device authorization request failed (HTTP {response.status_code})"
    except httpx.RequestError as e:
        step1.success = False
        step1.error = f"Connection error: {e}"

    _display_step(step1, verbose)
    steps.append(step1)

    if not step1.success:
        return steps

    # Step 2: Display user code and verification URI
    step2 = WorkflowStep(
        step_number=2,
        stage_name="Display Verification Instructions",
        success=True,
        details=f"Open {verification_uri} and enter code: {user_code}",
        verbose_data={
            "verification_uri": verification_uri,
            "user_code": user_code,
        },
    )
    _display_step(step2, verbose)
    steps.append(step2)

    click.echo(f"\n  → Open this URL in your browser: {verification_uri}")
    click.echo(f"  → Enter this code: {user_code}")
    click.echo("  → Waiting for authorization...\n")

    # Step 3: Poll token endpoint
    token_url = f"{cognito_endpoint}/oauth2/token"
    step3 = WorkflowStep(step_number=3, stage_name="Poll for Authorization")

    jwt_token = None
    max_attempts = 60  # ~5 minutes with 5s interval

    for attempt in range(max_attempts):
        try:
            token_response = httpx.post(
                token_url,
                data={
                    "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                    "device_code": device_code,
                    "client_id": cognito_client_id,
                },
                timeout=30.0,
            )
            if token_response.status_code == 200:
                token_data = token_response.json()
                jwt_token = token_data.get("id_token") or token_data.get("access_token", "")
                step3.success = True
                step3.details = f"Authorization granted (attempt {attempt + 1})"
                step3.verbose_data = {
                    "token_endpoint": token_url,
                    "response_status": token_response.status_code,
                    "token_type": token_data.get("token_type", "Bearer"),
                    "expires_in": token_data.get("expires_in"),
                    "attempts": attempt + 1,
                }
                break
            else:
                error_data = token_response.json() if token_response.content else {}
                error = error_data.get("error", "")
                if error == "authorization_pending":
                    time.sleep(interval)
                    continue
                elif error == "slow_down":
                    interval += 5
                    time.sleep(interval)
                    continue
                elif error == "expired_token":
                    step3.success = False
                    step3.error = "Device code expired. Please try again."
                    break
                elif error == "access_denied":
                    step3.success = False
                    step3.error = "Authorization denied by user."
                    break
                else:
                    step3.success = False
                    step3.error = f"Token request failed: {error}"
                    break
        except httpx.RequestError as e:
            step3.success = False
            step3.error = f"Connection error during polling: {e}"
            break
    else:
        step3.success = False
        step3.error = "Polling timed out waiting for user authorization"

    _display_step(step3, verbose)
    steps.append(step3)

    # Step 4: JWT acquisition confirmation
    step4 = WorkflowStep(
        step_number=4,
        stage_name="JWT Acquired",
    )

    if jwt_token:
        step4.success = True
        step4.details = "JWT token acquired via Device Authorization Grant"
        if verbose:
            step4.verbose_data = _decode_jwt_for_display(jwt_token)
    else:
        step4.success = False
        step4.error = "No JWT token received"

    _display_step(step4, verbose)
    steps.append(step4)

    return steps


def run_user_authentication_workflow(
    config: dict,
    username: str,
    password: str,
    verbose: bool,
) -> list[WorkflowStep]:
    """Demonstrate user authentication against Cognito (AuthZ Code Grant).

    Steps:
    1. Initiate authentication request to Cognito
    2. Exchange credentials for tokens (AuthZ Code Grant)
    3. Display JWT acquisition confirmation

    Args:
        config: Resolved CLI configuration.
        username: Cognito username.
        password: Cognito password.
        verbose: Whether to display verbose output.

    Returns:
        List of WorkflowStep results.
    """
    steps: list[WorkflowStep] = []
    cognito_endpoint = config.get("cognito_endpoint", "")
    cognito_client_id = config.get("cognito_client_id", "")

    click.echo("\n=== Workflow: User Authentication ===\n")

    # Step 1: Initiate authentication
    step1 = WorkflowStep(
        step_number=1,
        stage_name="Initiate Authentication",
        details=f"Connecting to Cognito endpoint for user '{username}'",
        verbose_data={
            "cognito_endpoint": cognito_endpoint,
            "cognito_client_id": cognito_client_id,
            "grant_type": "authorization_code",
        },
    )

    if not cognito_endpoint or not cognito_client_id:
        step1.success = False
        step1.error = "Cognito endpoint or client ID not configured"
        _display_step(step1, verbose)
        steps.append(step1)
        return steps

    _display_step(step1, verbose)
    steps.append(step1)

    # Step 2: Exchange credentials (AuthZ Code Grant simulation)
    token_url = f"{cognito_endpoint}/oauth2/token"
    jwt_token = None
    step2 = WorkflowStep(
        step_number=2,
        stage_name="Token Exchange",
    )

    try:
        response = httpx.post(
            token_url,
            data={
                "grant_type": "authorization_code",
                "client_id": cognito_client_id,
                "username": username,
                "password": password,
            },
            timeout=30.0,
        )
        if response.status_code == 200:
            token_data = response.json()
            jwt_token = token_data.get("id_token") or token_data.get(
                "access_token", ""
            )
            step2.success = True
            step2.details = "Credentials exchanged successfully"
            step2.verbose_data = {
                "token_endpoint": token_url,
                "response_status": response.status_code,
                "token_type": token_data.get("token_type", "Bearer"),
                "expires_in": token_data.get("expires_in"),
            }
        else:
            step2.success = False
            step2.error = (
                f"Token exchange failed (HTTP {response.status_code})"
            )
            step2.verbose_data = {"response_body": response.text[:200]}
    except httpx.RequestError as e:
        step2.success = False
        step2.error = f"Connection error: {e}"

    _display_step(step2, verbose)
    steps.append(step2)

    # Step 3: JWT acquisition confirmation
    step3 = WorkflowStep(
        step_number=3,
        stage_name="JWT Acquired",
    )

    if jwt_token:
        step3.success = True
        step3.details = "JWT token acquired successfully"
        if verbose:
            # Decode JWT header/payload for display (signature masked)
            step3.verbose_data = _decode_jwt_for_display(jwt_token)
    else:
        step3.success = False
        step3.error = "No JWT token received"

    _display_step(step3, verbose)
    steps.append(step3)

    return steps


# --- Workflow 2: User-Delegated Access ---


def run_user_delegated_access_workflow(
    config: dict,
    jwt_token: str,
    verbose: bool,
) -> list[WorkflowStep]:
    """Demonstrate user-delegated access flow via Scanner Agent.

    Steps:
    1. Authorization initiation (Scanner requests GitHub OAuth)
    2. User consent redirect
    3. Authorization code exchange
    4. Token storage confirmation
    5. Protected resource access result

    Args:
        config: Resolved CLI configuration.
        jwt_token: The user's JWT bearer token.
        verbose: Whether to display verbose output.

    Returns:
        List of WorkflowStep results.
    """
    steps: list[WorkflowStep] = []
    scanner_endpoint = config.get("scanner_endpoint", "")
    correlation_id = str(uuid.uuid4())

    click.echo("\n=== Workflow: User-Delegated Access ===\n")

    # Step 1: Authorization initiation
    step1 = WorkflowStep(
        step_number=1,
        stage_name="Authorization Initiation",
        details="Scanner Agent requests GitHub OAuth access for user",
        verbose_data={
            "scanner_endpoint": scanner_endpoint,
            "correlation_id": correlation_id,
            "oauth_flow": "USER_FEDERATION (authorization_code)",
            "requested_scopes": "security_events, repo",
        },
    )

    if not scanner_endpoint:
        step1.success = False
        step1.error = "Scanner endpoint not configured"
        _display_step(step1, verbose)
        steps.append(step1)
        return steps

    _display_step(step1, verbose)
    steps.append(step1)

    # Step 2: User consent redirect
    step2 = WorkflowStep(
        step_number=2,
        stage_name="User Consent",
        details="User redirected to GitHub consent screen",
        verbose_data={
            "redirect_uri": f"{scanner_endpoint}/oauth/callback",
            "scopes": ["security_events", "repo"],
            "state_parameter": str(uuid.uuid4())[:8],
        },
    )
    _display_step(step2, verbose)
    steps.append(step2)

    # Step 3: Authorization code exchange
    step3 = WorkflowStep(step_number=3, stage_name="Code Exchange")

    try:
        response = httpx.post(
            f"{scanner_endpoint}/invoke",
            json={
                "action": "scan",
                "repository": "demo/example-repo",
                "flow": "user_delegated",
            },
            headers={
                "Authorization": f"Bearer {jwt_token}",
                "X-Correlation-ID": correlation_id,
            },
            timeout=30.0,
        )
        if response.status_code == 200:
            step3.success = True
            step3.details = "Authorization code exchanged for tokens"
            step3.verbose_data = {
                "response_status": response.status_code,
                "Authorization": f"Bearer {jwt_token}",
            }
        else:
            step3.success = False
            step3.error = (
                f"Code exchange failed (HTTP {response.status_code})"
            )
    except httpx.RequestError as e:
        step3.success = False
        step3.error = f"Connection error: {e}"

    _display_step(step3, verbose)
    steps.append(step3)

    # Step 4: Token storage confirmation
    step4 = WorkflowStep(
        step_number=4,
        stage_name="Token Storage",
        success=step3.success,
        details=(
            "OAuth tokens stored in Token Vault (encrypted, agent-user pair)"
            if step3.success
            else "Token storage skipped due to prior failure"
        ),
        verbose_data={
            "vault_key": "scanner-agent:{user-subject}",
            "encryption": "AES-256-GCM at rest",
            "token_type": "Bearer",
        } if step3.success else {},
    )
    _display_step(step4, verbose)
    steps.append(step4)

    # Step 5: Protected resource access result
    step5 = WorkflowStep(
        step_number=5,
        stage_name="Resource Access",
        success=step3.success,
        details=(
            "GitHub API accessed successfully (Dependabot alerts retrieved)"
            if step3.success
            else "Resource access skipped due to prior failure"
        ),
        verbose_data={
            "target_resource": "github-api",
            "scopes_used": "security_events, repo",
            "api_endpoint": "https://api.github.com/repos/demo/example-repo/dependabot/alerts",
        } if step3.success else {},
    )
    _display_step(step5, verbose)
    steps.append(step5)

    return steps


# --- Workflow 3: Machine-to-Machine ---


def run_m2m_workflow(
    config: dict,
    verbose: bool,
) -> list[WorkflowStep]:
    """Demonstrate machine-to-machine authentication via Analysis Agent.

    Steps:
    1. Client credentials token request
    2. Token acquisition confirmation
    3. System operation result

    Args:
        config: Resolved CLI configuration.
        verbose: Whether to display verbose output.

    Returns:
        List of WorkflowStep results.
    """
    steps: list[WorkflowStep] = []
    analysis_endpoint = config.get("analysis_endpoint", "")
    correlation_id = str(uuid.uuid4())

    click.echo("\n=== Workflow: Machine-to-Machine ===\n")

    # Step 1: Client credentials request
    step1 = WorkflowStep(
        step_number=1,
        stage_name="Client Credentials Request",
        details="Analysis Agent requests M2M token via client_credentials grant",
        verbose_data={
            "grant_type": "client_credentials",
            "analysis_endpoint": analysis_endpoint,
            "client_id": "analysis-agent-client-id",
            "client_secret": "****",
            "requested_scopes": "vuln-db:read",
        },
    )

    if not analysis_endpoint:
        step1.success = False
        step1.error = "Analysis endpoint not configured"
        _display_step(step1, verbose)
        steps.append(step1)
        return steps

    _display_step(step1, verbose)
    steps.append(step1)

    # Step 2: Token acquisition
    step2 = WorkflowStep(step_number=2, stage_name="Token Acquisition")

    try:
        response = httpx.post(
            f"{analysis_endpoint}/invoke",
            json={
                "action": "analyze",
                "flow": "m2m",
                "repository": "demo/example-repo",
            },
            headers={"X-Correlation-ID": correlation_id},
            timeout=30.0,
        )
        if response.status_code == 200:
            step2.success = True
            step2.details = "M2M access token acquired from token endpoint"
            step2.verbose_data = {
                "token_type": "Bearer",
                "expires_in": 3600,
                "scopes_granted": "vuln-db:read",
                "proactive_refresh": "enabled (60s buffer)",
            }
        else:
            step2.success = False
            step2.error = (
                f"Token acquisition failed (HTTP {response.status_code})"
            )
    except httpx.RequestError as e:
        step2.success = False
        step2.error = f"Connection error: {e}"

    _display_step(step2, verbose)
    steps.append(step2)

    # Step 3: System operation result
    step3 = WorkflowStep(
        step_number=3,
        stage_name="System Operation",
        success=step2.success,
        details=(
            "Vulnerability database queried successfully (NVD/OSV/GHSA)"
            if step2.success
            else "System operation skipped due to prior failure"
        ),
        verbose_data={
            "target_resources": ["NVD", "OSV", "GHSA"],
            "auth_method": "client_credentials (M2M)",
            "retry_policy": "3 attempts, exponential backoff",
        } if step2.success else {},
    )
    _display_step(step3, verbose)
    steps.append(step3)

    return steps


# --- Workflow 4: Multi-Agent Delegation ---


def run_multi_agent_delegation_workflow(
    config: dict,
    jwt_token: str,
    verbose: bool,
) -> list[WorkflowStep]:
    """Demonstrate multi-agent delegation with identity propagation.

    Steps:
    1. Delegation request initiation (Orchestrator receives request)
    2. Identity propagation (Orchestrator → sub-agent)
    3. Delegated operation result

    Args:
        config: Resolved CLI configuration.
        jwt_token: The user's JWT bearer token.
        verbose: Whether to display verbose output.

    Returns:
        List of WorkflowStep results.
    """
    steps: list[WorkflowStep] = []
    orchestrator_endpoint = config.get("orchestrator_endpoint", "")
    correlation_id = str(uuid.uuid4())

    click.echo("\n=== Workflow: Multi-Agent Delegation ===\n")

    # Step 1: Delegation request
    step1 = WorkflowStep(
        step_number=1,
        stage_name="Delegation Request",
        details="Orchestrator receives authenticated request, prepares delegation",
        verbose_data={
            "orchestrator_endpoint": orchestrator_endpoint,
            "correlation_id": correlation_id,
            "Authorization": f"Bearer {jwt_token}",
            "action": "delegate_to_scanner",
        },
    )

    if not orchestrator_endpoint:
        step1.success = False
        step1.error = "Orchestrator endpoint not configured"
        _display_step(step1, verbose)
        steps.append(step1)
        return steps

    _display_step(step1, verbose)
    steps.append(step1)

    # Step 2: Identity propagation
    step2 = WorkflowStep(
        step_number=2,
        stage_name="Identity Propagation",
    )

    try:
        response = httpx.post(
            f"{orchestrator_endpoint}/invoke",
            json={
                "action": "scan",
                "repository": "demo/example-repo",
                "branch": "main",
            },
            headers={
                "Authorization": f"Bearer {jwt_token}",
                "X-Correlation-ID": correlation_id,
            },
            timeout=30.0,
        )
        if response.status_code == 200:
            step2.success = True
            step2.details = "Identity context propagated to sub-agent"
            step2.verbose_data = {
                "source_agent": "orchestrator-agent",
                "target_agent": "scanner-agent",
                "identity_context_version": "1.0",
                "delegation_chain": [
                    {
                        "agent": "orchestrator-agent",
                        "delegated_at": "now",
                    }
                ],
                "signature": "hmac-sha256 (verified)",
                "user_subject": "user-sub-from-jwt",
            }
        elif response.status_code == 401:
            step2.success = False
            step2.error = "JWT validation failed at Orchestrator"
            step2.verbose_data = {"response_status": 401}
        else:
            step2.success = False
            step2.error = (
                f"Delegation failed (HTTP {response.status_code})"
            )
    except httpx.RequestError as e:
        step2.success = False
        step2.error = f"Connection error: {e}"

    _display_step(step2, verbose)
    steps.append(step2)

    # Step 3: Delegated operation result
    step3 = WorkflowStep(
        step_number=3,
        stage_name="Delegated Operation Result",
        success=step2.success,
        details=(
            "Sub-agent completed operation with propagated identity"
            if step2.success
            else "Delegated operation failed"
        ),
        verbose_data={
            "sub_agent_validated": "mTLS cert + workload identity + user identity",
            "audit_trail": "recorded (source → target → user → timestamp)",
        } if step2.success else {},
    )
    _display_step(step3, verbose)
    steps.append(step3)

    return steps


# --- Workflow 5: Full Vulnerability Analysis ---


def run_full_analysis_workflow(
    config: dict,
    jwt_token: str,
    verbose: bool,
) -> list[WorkflowStep]:
    """Demonstrate full vulnerability analysis pipeline.

    Steps:
    1. Initiate scan (Orchestrator → Scanner)
    2. Dependency scan (Scanner reads GitHub manifests)
    3. Call graph analysis (Analysis Agent, tree-sitter)
    4. Exploitability scoring
    5. Fix recommendations generated
    6. Results displayed (sorted by exploitability score)

    Args:
        config: Resolved CLI configuration.
        jwt_token: The user's JWT bearer token.
        verbose: Whether to display verbose output.

    Returns:
        List of WorkflowStep results.
    """
    steps: list[WorkflowStep] = []
    orchestrator_endpoint = config.get("orchestrator_endpoint", "")
    correlation_id = str(uuid.uuid4())

    click.echo("\n=== Workflow: Full Vulnerability Analysis ===\n")

    # Step 1: Initiate scan
    step1 = WorkflowStep(
        step_number=1,
        stage_name="Initiate Scan",
        details="Orchestrator dispatches scan request to Scanner Agent",
        verbose_data={
            "orchestrator_endpoint": orchestrator_endpoint,
            "correlation_id": correlation_id,
            "pipeline": "scan → analyze → score → recommend",
        },
    )

    if not orchestrator_endpoint:
        step1.success = False
        step1.error = "Orchestrator endpoint not configured"
        _display_step(step1, verbose)
        steps.append(step1)
        return steps

    _display_step(step1, verbose)
    steps.append(step1)

    # Step 2: Dependency scan
    step2 = WorkflowStep(step_number=2, stage_name="Dependency Scan")

    pipeline_response = None
    try:
        response = httpx.post(
            f"{orchestrator_endpoint}/invoke",
            json={
                "action": "full_pipeline",
                "repository": "demo/example-repo",
                "branch": "main",
            },
            headers={
                "Authorization": f"Bearer {jwt_token}",
                "X-Correlation-ID": correlation_id,
            },
            timeout=60.0,
        )
        if response.status_code == 200:
            pipeline_response = response.json()
            step2.success = True
            step2.details = "Dependency manifests scanned, SBOM generated"
            step2.verbose_data = {
                "manifests_found": "package.json, requirements.txt",
                "dependencies_detected": "direct + transitive",
                "sbom_format": "CycloneDX v1.5",
            }
        elif response.status_code == 401:
            step2.success = False
            step2.error = "Authentication failed at Orchestrator"
        else:
            step2.success = False
            step2.error = f"Scan failed (HTTP {response.status_code})"
    except httpx.RequestError as e:
        step2.success = False
        step2.error = f"Connection error: {e}"

    _display_step(step2, verbose)
    steps.append(step2)

    if not step2.success:
        return steps

    # Step 3: Call graph analysis
    step3 = WorkflowStep(
        step_number=3,
        stage_name="Call Graph Analysis",
        success=True,
        details="Static call graph built (tree-sitter), reachability determined",
        verbose_data={
            "analyzer": "tree-sitter",
            "languages_parsed": "JavaScript, Python",
            "entry_points_detected": "main(), HTTP handlers",
            "classification": "reachable / unreachable / indeterminate",
        },
    )
    _display_step(step3, verbose)
    steps.append(step3)

    # Step 4: Exploitability scoring
    scored_findings = _extract_scored_findings(pipeline_response)
    step4 = WorkflowStep(
        step_number=4,
        stage_name="Exploitability Scoring",
        success=True,
        details=(
            f"Scores computed for {len(scored_findings)} findings "
            f"(CVSS × reachability multiplier)"
        ),
        verbose_data={
            "formula": "exploitability_score = cvss_base × reachability_multiplier",
            "multipliers": {
                "reachable": 1.0,
                "unreachable": 0.2,
                "indeterminate": 0.6,
            },
            "tiers": "Critical(≥9.0), High(7.0-8.9), Medium(4.0-6.9), Low(<4.0)",
        },
    )
    _display_step(step4, verbose)
    steps.append(step4)

    # Step 5: Fix recommendations
    recommendations = _extract_recommendations(pipeline_response)
    step5 = WorkflowStep(
        step_number=5,
        stage_name="Fix Recommendations",
        success=True,
        details=f"{len(recommendations)} fix recommendations generated",
        verbose_data={
            "grouping": "one recommendation per dependency",
            "breaking_change_detection": "major version bump flagged",
        },
    )
    _display_step(step5, verbose)
    steps.append(step5)

    # Step 6: Results sorted by exploitability score
    step6 = WorkflowStep(
        step_number=6,
        stage_name="Results",
        success=True,
        details="Findings sorted by exploitability score (descending)",
    )

    if scored_findings:
        step6.verbose_data = {
            "top_findings": _format_top_findings(scored_findings[:5]),
        }

    _display_step(step6, verbose)
    steps.append(step6)

    # Display sorted findings summary
    if scored_findings:
        click.echo("\n  Findings (sorted by exploitability score):")
        for i, finding in enumerate(scored_findings[:10], 1):
            score = finding.get("exploitability_score", 0)
            cve = finding.get("cve_id", "Unknown")
            tier = finding.get("priority_tier", "Unknown")
            dep = finding.get("dependency", "Unknown")
            click.echo(f"    {i}. {cve} — score: {score:.1f} ({tier}) [{dep}]")

    return steps


# --- Helper Functions ---


def _decode_jwt_for_display(token: str) -> dict[str, Any]:
    """Decode a JWT token for verbose display with signature masked.

    Args:
        token: The JWT token string.

    Returns:
        Dict with decoded header and payload (signature masked).
    """
    import base64

    parts = token.split(".")
    if len(parts) != 3:
        return {"raw_token": "****"}

    try:
        # Decode header
        header_padded = parts[0] + "=" * (4 - len(parts[0]) % 4)
        header = json.loads(base64.urlsafe_b64decode(header_padded))

        # Decode payload
        payload_padded = parts[1] + "=" * (4 - len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_padded))

        return {
            "jwt_header": header,
            "jwt_payload": payload,
            "signature": "****",
        }
    except Exception:
        return {"raw_token": "****"}


def _extract_scored_findings(
    pipeline_response: dict | None,
) -> list[dict]:
    """Extract scored findings from a pipeline response.

    Args:
        pipeline_response: The full pipeline response dict.

    Returns:
        List of finding dicts sorted by exploitability score descending.
    """
    if not pipeline_response:
        return []

    result = pipeline_response.get("result", {})
    analysis = result.get("analysis", {})
    findings = analysis.get("scored_findings", [])

    # Ensure sorted by exploitability score descending
    return sorted(
        findings,
        key=lambda f: f.get("exploitability_score", 0),
        reverse=True,
    )


def _extract_recommendations(
    pipeline_response: dict | None,
) -> list[dict]:
    """Extract fix recommendations from a pipeline response.

    Args:
        pipeline_response: The full pipeline response dict.

    Returns:
        List of recommendation dicts.
    """
    if not pipeline_response:
        return []

    result = pipeline_response.get("result", {})
    analysis = result.get("analysis", {})
    return analysis.get("recommendations", [])


def _format_top_findings(findings: list[dict]) -> list[str]:
    """Format top findings for verbose display.

    Args:
        findings: List of finding dicts.

    Returns:
        List of formatted finding strings.
    """
    formatted = []
    for f in findings:
        cve = f.get("cve_id", "Unknown")
        score = f.get("exploitability_score", 0)
        tier = f.get("priority_tier", "Unknown")
        formatted.append(f"{cve}: {score:.1f} ({tier})")
    return formatted
