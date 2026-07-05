"""Unit tests for the Demo CLI framework and configuration handling.

Tests the Click-based CLI application covering:
- Verbose mode activation via --verbose / -v flag (Requirement 13.5)
- Default summary mode behavior (Requirement 8.5)
- Configuration resolution: CLI args > env vars (Requirement 8.7)
- Username/password acceptance for Cognito authentication (Requirement 8.5)
"""

import os

import pytest
from click.testing import CliRunner

from src.cli.main import (
    CONFIG_KEYS,
    ENV_VAR_MAP,
    _gather_env_vars,
    cli,
)


@pytest.fixture
def runner():
    """Provide a Click test runner."""
    return CliRunner()


class TestVerboseFlag:
    """Tests for Requirement 13.5: --verbose / -v flag activates verbose mode."""

    def test_verbose_long_flag_sets_verbose_true(self, runner):
        result = runner.invoke(cli, ["--verbose", "run-demo", "--username", "user", "--password", "pass"])
        assert result.exit_code == 0
        assert "Verbose Mode" in result.output

    def test_verbose_short_flag_sets_verbose_true(self, runner):
        result = runner.invoke(cli, ["-v", "run-demo", "--username", "user", "--password", "pass"])
        assert result.exit_code == 0
        assert "Verbose Mode" in result.output

    def test_default_is_summary_mode(self, runner):
        result = runner.invoke(cli, ["run-demo", "--username", "user", "--password", "pass"])
        assert result.exit_code == 0
        assert "Verbose Mode" not in result.output
        assert "Reachability-Enhanced SCA Demo" in result.output


class TestConfigurationResolution:
    """Tests for Requirement 8.7: CLI args > env vars precedence."""

    def test_cli_args_take_precedence_over_env_vars(self, runner):
        env = {"AGENTCORE_ORCHESTRATOR_ENDPOINT": "http://env-endpoint.example.com"}
        result = runner.invoke(
            cli,
            [
                "--orchestrator-endpoint", "http://cli-endpoint.example.com",
                "-v",
                "run-demo",
                "--username", "user",
                "--password", "pass",
            ],
            env=env,
        )
        assert result.exit_code == 0
        assert "http://cli-endpoint.example.com" in result.output

    def test_env_vars_used_when_no_cli_args(self, runner):
        env = {"AGENTCORE_COGNITO_ENDPOINT": "http://cognito-from-env.example.com"}
        result = runner.invoke(
            cli,
            ["-v", "run-demo", "--username", "user", "--password", "pass"],
            env=env,
        )
        assert result.exit_code == 0
        assert "cognito_endpoint" in result.output or "cognito-from-env" in result.output

    def test_all_config_keys_resolvable_from_cli(self, runner):
        result = runner.invoke(
            cli,
            [
                "--orchestrator-endpoint", "http://orc.example.com",
                "--scanner-endpoint", "http://scan.example.com",
                "--analysis-endpoint", "http://analysis.example.com",
                "--cognito-endpoint", "http://cognito.example.com",
                "--cognito-client-id", "test-client-id",
                "-v",
                "run-demo",
                "--username", "user",
                "--password", "pass",
            ],
        )
        assert result.exit_code == 0
        assert "http://orc.example.com" in result.output

    def test_missing_config_results_in_absent_keys(self, runner):
        # No CLI args and no env vars → config should be empty
        result = runner.invoke(
            cli,
            ["-v", "run-demo", "--username", "user", "--password", "pass"],
            env={},
        )
        assert result.exit_code == 0
        # Config should be displayed as empty or minimal dict
        assert "Configuration:" in result.output


class TestGatherEnvVars:
    """Tests for the _gather_env_vars helper function."""

    def test_gathers_set_env_vars(self, monkeypatch):
        monkeypatch.setenv("AGENTCORE_ORCHESTRATOR_ENDPOINT", "http://orc.example.com")
        monkeypatch.setenv("AGENTCORE_COGNITO_CLIENT_ID", "my-client-id")

        result = _gather_env_vars()

        assert result["orchestrator_endpoint"] == "http://orc.example.com"
        assert result["cognito_client_id"] == "my-client-id"

    def test_skips_unset_env_vars(self, monkeypatch):
        # Only set one var, others unset
        monkeypatch.setenv("AGENTCORE_SCANNER_ENDPOINT", "http://scan.example.com")
        monkeypatch.delenv("AGENTCORE_ORCHESTRATOR_ENDPOINT", raising=False)
        monkeypatch.delenv("AGENTCORE_ANALYSIS_ENDPOINT", raising=False)
        monkeypatch.delenv("AGENTCORE_COGNITO_ENDPOINT", raising=False)
        monkeypatch.delenv("AGENTCORE_COGNITO_CLIENT_ID", raising=False)

        result = _gather_env_vars()

        assert result == {"scanner_endpoint": "http://scan.example.com"}

    def test_returns_empty_when_no_env_vars_set(self, monkeypatch):
        for env_name in ENV_VAR_MAP.values():
            monkeypatch.delenv(env_name, raising=False)

        result = _gather_env_vars()

        assert result == {}


class TestAuthenticateCommand:
    """Tests for OAuth 2.1 Device Authorization Grant and legacy mode."""

    def test_authenticate_uses_device_flow_by_default(self, runner):
        """Default authenticate uses Device Authorization Grant (no password prompts)."""
        env = {
            "AGENTCORE_COGNITO_ENDPOINT": "http://cognito.example.com",
            "AGENTCORE_COGNITO_CLIENT_ID": "test-client-id",
        }
        result = runner.invoke(
            cli,
            ["authenticate"],
            env=env,
        )
        assert result.exit_code == 0
        assert "Device Authorization Grant" in result.output

    def test_authenticate_device_flow_displays_verification_steps(self, runner):
        """Device flow displays verification URI instructions."""
        env = {
            "AGENTCORE_COGNITO_ENDPOINT": "http://cognito.example.com",
            "AGENTCORE_COGNITO_CLIENT_ID": "test-client-id",
        }
        result = runner.invoke(
            cli,
            ["authenticate"],
            env=env,
        )
        assert result.exit_code == 0
        # Should show workflow step numbering
        assert "[1]" in result.output
        assert "Device Code" in result.output or "device" in result.output.lower()

    def test_authenticate_legacy_flag_shows_deprecation_warning(self, runner):
        """--legacy flag triggers deprecation warning about ROPC removal."""
        env = {
            "AGENTCORE_COGNITO_ENDPOINT": "http://cognito.example.com",
            "AGENTCORE_COGNITO_CLIENT_ID": "test-client-id",
        }
        result = runner.invoke(
            cli,
            ["authenticate", "--legacy", "--username", "myuser", "--password", "mypass"],
            env=env,
        )
        assert result.exit_code == 0
        assert "deprecated" in result.output.lower() or "DEPRECATED" in result.output

    def test_authenticate_username_password_triggers_legacy_with_warning(self, runner):
        """Providing --username/--password uses legacy mode with warning."""
        env = {
            "AGENTCORE_COGNITO_ENDPOINT": "http://cognito.example.com",
            "AGENTCORE_COGNITO_CLIENT_ID": "test-client-id",
        }
        result = runner.invoke(
            cli,
            ["authenticate", "--username", "myuser", "--password", "mypass"],
            env=env,
        )
        assert result.exit_code == 0
        assert "deprecated" in result.output.lower() or "DEPRECATED" in result.output

    def test_authenticate_legacy_verbose_shows_endpoint_details(self, runner):
        """Legacy mode in verbose still shows Cognito endpoint details."""
        env = {
            "AGENTCORE_COGNITO_ENDPOINT": "http://cognito.example.com",
            "AGENTCORE_COGNITO_CLIENT_ID": "test-client-id",
        }
        result = runner.invoke(
            cli,
            ["-v", "authenticate", "--legacy", "--username", "myuser", "--password", "mypass"],
            env=env,
        )
        assert result.exit_code == 0
        assert "http://cognito.example.com" in result.output
        assert "test-client-id" in result.output

    def test_authenticate_errors_without_cognito_endpoint(self, runner):
        result = runner.invoke(
            cli,
            ["authenticate"],
            env={},
        )
        # Should report an error about missing cognito endpoint
        assert "Cognito endpoint not configured" in result.output

    def test_authenticate_errors_without_cognito_client_id(self, runner):
        env = {"AGENTCORE_COGNITO_ENDPOINT": "http://cognito.example.com"}
        result = runner.invoke(
            cli,
            ["authenticate"],
            env=env,
        )
        assert "Cognito client ID not configured" in result.output


class TestCliEntryPoint:
    """Tests for the CLI entry point and project script configuration."""

    def test_cli_help_displays(self, runner):
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "Reachability-Enhanced SCA Demo CLI" in result.output

    def test_authenticate_help_displays(self, runner):
        result = runner.invoke(cli, ["authenticate", "--help"])
        assert result.exit_code == 0
        assert "--legacy" in result.output
        assert "--username" in result.output
        assert "--password" in result.output

    def test_run_demo_help_displays(self, runner):
        result = runner.invoke(cli, ["run-demo", "--help"])
        assert result.exit_code == 0
        assert "--username" in result.output
        assert "--password" in result.output
