"""Demo CLI for the Reachability-Enhanced SCA Security Platform.

Click-based CLI application that demonstrates each authentication and
analysis workflow step by step. Supports summary mode (default) and
verbose mode (--verbose / -v).

Configuration is resolved with CLI arguments taking precedence over
environment variables for agent endpoints, Cognito endpoint, and client ID.

Requirements: 8.5, 8.7, 13.5
"""

from __future__ import annotations

import os

import click

from src.core.config import resolve_config

# Configuration keys resolved from CLI args and environment variables
CONFIG_KEYS = [
    "orchestrator_endpoint",
    "scanner_endpoint",
    "analysis_endpoint",
    "cognito_endpoint",
    "cognito_client_id",
]

# Mapping of CLI option names to environment variable names
ENV_VAR_MAP = {
    "orchestrator_endpoint": "AGENTCORE_ORCHESTRATOR_ENDPOINT",
    "scanner_endpoint": "AGENTCORE_SCANNER_ENDPOINT",
    "analysis_endpoint": "AGENTCORE_ANALYSIS_ENDPOINT",
    "cognito_endpoint": "AGENTCORE_COGNITO_ENDPOINT",
    "cognito_client_id": "AGENTCORE_COGNITO_CLIENT_ID",
}


def _gather_env_vars() -> dict:
    """Gather configuration values from environment variables.

    Returns:
        Dictionary mapping config keys to their environment variable values,
        with None values excluded.
    """
    env_vars = {}
    for key, env_name in ENV_VAR_MAP.items():
        value = os.environ.get(env_name)
        if value is not None:
            env_vars[key] = value
    return env_vars


@click.group()
@click.option("--verbose", "-v", is_flag=True, default=False, help="Enable verbose output mode.")
@click.option(
    "--orchestrator-endpoint",
    default=None,
    help="Orchestrator Agent endpoint URL.",
)
@click.option(
    "--scanner-endpoint",
    default=None,
    help="Scanner Agent endpoint URL.",
)
@click.option(
    "--analysis-endpoint",
    default=None,
    help="Analysis Agent endpoint URL.",
)
@click.option(
    "--cognito-endpoint",
    default=None,
    help="Cognito user pool endpoint URL.",
)
@click.option(
    "--cognito-client-id",
    default=None,
    help="Cognito user pool client ID.",
)
@click.pass_context
def cli(
    ctx: click.Context,
    verbose: bool,
    orchestrator_endpoint: str | None,
    scanner_endpoint: str | None,
    analysis_endpoint: str | None,
    cognito_endpoint: str | None,
    cognito_client_id: str | None,
) -> None:
    """Reachability-Enhanced SCA Demo CLI.

    Demonstrates authentication workflows and vulnerability analysis
    using Amazon Bedrock AgentCore Identity.
    """
    ctx.ensure_object(dict)

    # Store verbose flag in context
    ctx.obj["verbose"] = verbose

    # Build CLI args dict from provided options
    cli_args = {
        "orchestrator_endpoint": orchestrator_endpoint,
        "scanner_endpoint": scanner_endpoint,
        "analysis_endpoint": analysis_endpoint,
        "cognito_endpoint": cognito_endpoint,
        "cognito_client_id": cognito_client_id,
    }

    # Gather environment variables
    env_vars = _gather_env_vars()

    # Resolve configuration: CLI args > env vars
    config = resolve_config(cli_args, env_vars, CONFIG_KEYS)

    # Store resolved config in context for subcommands
    ctx.obj["config"] = config


@cli.command()
@click.option("--legacy", is_flag=True, default=False,
              help="[DEPRECATED] Use legacy username/password authentication (ROPC).")
@click.option("--username", default=None, help="[DEPRECATED] Cognito username (legacy mode only).")
@click.option(
    "--password",
    default=None,
    hide_input=True,
    help="[DEPRECATED] Cognito password (legacy mode only).",
)
@click.pass_context
def authenticate(ctx: click.Context, legacy: bool, username: str | None, password: str | None) -> None:
    """Authenticate using Device Authorization Grant (OAuth 2.1).

    By default, uses the Device Authorization Grant (RFC 8628): requests a
    device code, displays a verification URI and user code, and polls
    until the user authorizes in their browser. No passwords are transmitted.

    The --legacy flag preserves backward-compatible username/password auth
    with a deprecation warning (ROPC removed in OAuth 2.1).
    """
    from src.cli.workflows import run_device_authorization_workflow, run_user_authentication_workflow

    verbose = ctx.obj["verbose"]
    config = ctx.obj["config"]

    cognito_endpoint = config.get("cognito_endpoint")
    cognito_client_id = config.get("cognito_client_id")

    if not cognito_endpoint:
        click.echo("Error: Cognito endpoint not configured. "
                   "Set --cognito-endpoint or AGENTCORE_COGNITO_ENDPOINT.", err=True)
        ctx.exit(1)
        return

    if not cognito_client_id:
        click.echo("Error: Cognito client ID not configured. "
                   "Set --cognito-client-id or AGENTCORE_COGNITO_CLIENT_ID.", err=True)
        ctx.exit(1)
        return

    if legacy or (username and password):
        # Legacy ROPC mode with deprecation warning
        click.echo(
            "WARNING: --username/--password authentication is deprecated. "
            "OAuth 2.1 removes the Resource Owner Password Credentials grant. "
            "Use the default Device Authorization Grant instead.",
            err=True,
        )
        if not username:
            username = click.prompt("Username")
        if not password:
            password = click.prompt("Password", hide_input=True)
        ctx.obj["username"] = username
        ctx.obj["password"] = password
        run_user_authentication_workflow(config, username, password, verbose)
    else:
        # OAuth 2.1 Device Authorization Grant (default)
        run_device_authorization_workflow(config, verbose)


@cli.command()
@click.option("--username", prompt="Username", help="Cognito username for authentication.")
@click.option(
    "--password",
    prompt="Password",
    hide_input=True,
    help="Cognito password for authentication.",
)
@click.pass_context
def run_demo(ctx: click.Context, username: str, password: str) -> None:
    """Run the full demonstration workflow (all five auth workflows)."""
    from src.cli.workflows import (
        run_full_analysis_workflow,
        run_m2m_workflow,
        run_multi_agent_delegation_workflow,
        run_user_authentication_workflow,
        run_user_delegated_access_workflow,
    )

    verbose = ctx.obj["verbose"]
    config = ctx.obj["config"]

    # Store credentials
    ctx.obj["username"] = username
    ctx.obj["password"] = password

    if verbose:
        click.echo("=== Demo CLI - Verbose Mode ===")
        click.echo(f"Configuration: {config}")
    else:
        click.echo("=== Reachability-Enhanced SCA Demo ===")

    # Workflow 1: User Authentication
    auth_steps = run_user_authentication_workflow(config, username, password, verbose)

    # Use a placeholder token for subsequent workflows if auth succeeded
    jwt_token = _get_demo_jwt_token(auth_steps)

    # Workflow 2: User-Delegated Access
    run_user_delegated_access_workflow(config, jwt_token, verbose)

    # Workflow 3: Machine-to-Machine
    run_m2m_workflow(config, verbose)

    # Workflow 4: Multi-Agent Delegation
    run_multi_agent_delegation_workflow(config, jwt_token, verbose)

    # Workflow 5: Full Vulnerability Analysis
    run_full_analysis_workflow(config, jwt_token, verbose)

    click.echo("\n=== Demo Complete ===")


@cli.command(name="user-delegated")
@click.option("--token", required=True, help="JWT bearer token for authentication.")
@click.pass_context
def user_delegated(ctx: click.Context, token: str) -> None:
    """Demonstrate user-delegated access workflow (Scanner Agent → GitHub)."""
    from src.cli.workflows import run_user_delegated_access_workflow

    verbose = ctx.obj["verbose"]
    config = ctx.obj["config"]
    run_user_delegated_access_workflow(config, token, verbose)


@cli.command(name="m2m")
@click.pass_context
def m2m(ctx: click.Context) -> None:
    """Demonstrate machine-to-machine workflow (Analysis Agent → Vuln DBs)."""
    from src.cli.workflows import run_m2m_workflow

    verbose = ctx.obj["verbose"]
    config = ctx.obj["config"]
    run_m2m_workflow(config, verbose)


@cli.command(name="delegation")
@click.option("--token", required=True, help="JWT bearer token for authentication.")
@click.pass_context
def delegation(ctx: click.Context, token: str) -> None:
    """Demonstrate multi-agent delegation workflow."""
    from src.cli.workflows import run_multi_agent_delegation_workflow

    verbose = ctx.obj["verbose"]
    config = ctx.obj["config"]
    run_multi_agent_delegation_workflow(config, token, verbose)


@cli.command(name="full-analysis")
@click.option("--token", required=True, help="JWT bearer token for authentication.")
@click.pass_context
def full_analysis(ctx: click.Context, token: str) -> None:
    """Demonstrate full vulnerability analysis pipeline."""
    from src.cli.workflows import run_full_analysis_workflow

    verbose = ctx.obj["verbose"]
    config = ctx.obj["config"]
    run_full_analysis_workflow(config, token, verbose)


def _get_demo_jwt_token(auth_steps: list) -> str:
    """Extract or generate a demo JWT token from authentication steps.

    If authentication succeeded, uses a placeholder token for demonstration.
    In production, the actual JWT from the Cognito exchange would be used.

    Args:
        auth_steps: The steps from the authentication workflow.

    Returns:
        A JWT token string (placeholder for demo purposes).
    """
    # In a real scenario, we'd extract the token from the auth response.
    # For demo, use a placeholder that demonstrates the flow structure.
    all_success = all(step.success for step in auth_steps)
    if all_success:
        return "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJkZW1vLXVzZXIiLCJpc3MiOiJjb2duaXRvIn0.demo-signature"
    return "invalid-token"


if __name__ == "__main__":
    cli()
