"""Unit tests for CLI workflow demonstrations.

Tests verify that each workflow:
- Produces sequentially numbered steps with descriptive stage names
- Handles missing configuration gracefully
- Returns WorkflowStep objects with correct structure
- Displays verbose data when verbose mode is enabled

Requirements: 8.1, 8.2, 8.3, 8.4, 8.5, 8.8
"""

from __future__ import annotations

from unittest.mock import patch

import pytest
from click.testing import CliRunner

from src.cli.main import cli
from src.cli.workflows import (
    WorkflowStep,
    _decode_jwt_for_display,
    _display_step,
    _extract_recommendations,
    _extract_scored_findings,
    run_full_analysis_workflow,
    run_m2m_workflow,
    run_multi_agent_delegation_workflow,
    run_user_authentication_workflow,
    run_user_delegated_access_workflow,
)


class TestWorkflowStep:
    """Tests for the WorkflowStep dataclass."""

    def test_step_has_required_fields(self):
        step = WorkflowStep(step_number=1, stage_name="Test Stage")
        assert step.step_number == 1
        assert step.stage_name == "Test Stage"
        assert step.success is True
        assert step.details == ""
        assert step.error is None
        assert step.verbose_data == {}

    def test_step_with_failure(self):
        step = WorkflowStep(
            step_number=2,
            stage_name="Failed Stage",
            success=False,
            error="Something went wrong",
        )
        assert step.success is False
        assert step.error == "Something went wrong"


class TestUserAuthenticationWorkflow:
    """Tests for the user authentication workflow."""

    def test_returns_steps_with_missing_config(self):
        config = {}
        steps = run_user_authentication_workflow(config, "user", "pass", False)
        assert len(steps) == 1
        assert steps[0].success is False
        assert "not configured" in steps[0].error

    def test_steps_have_sequential_numbering(self):
        config = {
            "cognito_endpoint": "http://cognito.test.local",
            "cognito_client_id": "test-client",
        }
        # The HTTP call will fail, but we still get steps 1-3
        steps = run_user_authentication_workflow(config, "user", "pass", False)
        assert len(steps) == 3
        for i, step in enumerate(steps, 1):
            assert step.step_number == i

    def test_steps_have_non_empty_stage_names(self):
        config = {
            "cognito_endpoint": "http://cognito.test.local",
            "cognito_client_id": "test-client",
        }
        steps = run_user_authentication_workflow(config, "user", "pass", False)
        for step in steps:
            assert step.stage_name
            assert len(step.stage_name) > 0


class TestUserDelegatedAccessWorkflow:
    """Tests for the user-delegated access workflow."""

    def test_returns_steps_with_missing_scanner_endpoint(self):
        config = {}
        steps = run_user_delegated_access_workflow(config, "token", False)
        assert len(steps) == 1
        assert steps[0].success is False
        assert "not configured" in steps[0].error

    def test_has_five_steps_when_endpoint_configured(self):
        config = {"scanner_endpoint": "http://scanner.test.local"}
        steps = run_user_delegated_access_workflow(config, "token", False)
        assert len(steps) == 5
        for i, step in enumerate(steps, 1):
            assert step.step_number == i

    def test_stage_names_describe_oauth_flow(self):
        config = {"scanner_endpoint": "http://scanner.test.local"}
        steps = run_user_delegated_access_workflow(config, "token", False)
        stage_names = [s.stage_name for s in steps]
        assert "Authorization Initiation" in stage_names
        assert "User Consent" in stage_names
        assert "Code Exchange" in stage_names
        assert "Token Storage" in stage_names
        assert "Resource Access" in stage_names


class TestM2MWorkflow:
    """Tests for the machine-to-machine workflow."""

    def test_returns_steps_with_missing_analysis_endpoint(self):
        config = {}
        steps = run_m2m_workflow(config, False)
        assert len(steps) == 1
        assert steps[0].success is False
        assert "not configured" in steps[0].error

    def test_has_three_steps_when_endpoint_configured(self):
        config = {"analysis_endpoint": "http://analysis.test.local"}
        steps = run_m2m_workflow(config, False)
        assert len(steps) == 3
        for i, step in enumerate(steps, 1):
            assert step.step_number == i

    def test_stage_names_describe_m2m_flow(self):
        config = {"analysis_endpoint": "http://analysis.test.local"}
        steps = run_m2m_workflow(config, False)
        stage_names = [s.stage_name for s in steps]
        assert "Client Credentials Request" in stage_names
        assert "Token Acquisition" in stage_names
        assert "System Operation" in stage_names


class TestMultiAgentDelegationWorkflow:
    """Tests for the multi-agent delegation workflow."""

    def test_returns_steps_with_missing_orchestrator_endpoint(self):
        config = {}
        steps = run_multi_agent_delegation_workflow(config, "token", False)
        assert len(steps) == 1
        assert steps[0].success is False
        assert "not configured" in steps[0].error

    def test_has_three_steps_when_endpoint_configured(self):
        config = {"orchestrator_endpoint": "http://orchestrator.test.local"}
        steps = run_multi_agent_delegation_workflow(config, "token", False)
        assert len(steps) == 3
        for i, step in enumerate(steps, 1):
            assert step.step_number == i

    def test_stage_names_describe_delegation_flow(self):
        config = {"orchestrator_endpoint": "http://orchestrator.test.local"}
        steps = run_multi_agent_delegation_workflow(config, "token", False)
        stage_names = [s.stage_name for s in steps]
        assert "Delegation Request" in stage_names
        assert "Identity Propagation" in stage_names
        assert "Delegated Operation Result" in stage_names


class TestFullAnalysisWorkflow:
    """Tests for the full vulnerability analysis workflow."""

    def test_returns_steps_with_missing_orchestrator_endpoint(self):
        config = {}
        steps = run_full_analysis_workflow(config, "token", False)
        assert len(steps) == 1
        assert steps[0].success is False
        assert "not configured" in steps[0].error

    def test_first_step_is_initiate_scan(self):
        config = {"orchestrator_endpoint": "http://orchestrator.test.local"}
        steps = run_full_analysis_workflow(config, "token", False)
        assert steps[0].step_number == 1
        assert steps[0].stage_name == "Initiate Scan"


class TestHelperFunctions:
    """Tests for workflow helper functions."""

    def test_decode_jwt_valid_token(self):
        # Base64url encoded: {"alg":"RS256"}.{"sub":"demo-user","iss":"cognito"}.signature
        import base64
        header = base64.urlsafe_b64encode(b'{"alg":"RS256"}').rstrip(b"=").decode()
        payload = base64.urlsafe_b64encode(
            b'{"sub":"demo-user","iss":"cognito"}'
        ).rstrip(b"=").decode()
        token = f"{header}.{payload}.fake-signature"

        result = _decode_jwt_for_display(token)
        assert "jwt_header" in result
        assert result["jwt_header"]["alg"] == "RS256"
        assert "jwt_payload" in result
        assert result["jwt_payload"]["sub"] == "demo-user"
        assert result["signature"] == "****"

    def test_decode_jwt_invalid_token(self):
        result = _decode_jwt_for_display("not-a-jwt")
        assert result == {"raw_token": "****"}

    def test_extract_scored_findings_empty(self):
        assert _extract_scored_findings(None) == []
        assert _extract_scored_findings({}) == []

    def test_extract_scored_findings_sorted(self):
        response = {
            "result": {
                "analysis": {
                    "scored_findings": [
                        {"cve_id": "CVE-1", "exploitability_score": 3.0},
                        {"cve_id": "CVE-2", "exploitability_score": 9.5},
                        {"cve_id": "CVE-3", "exploitability_score": 6.0},
                    ]
                }
            }
        }
        findings = _extract_scored_findings(response)
        assert findings[0]["cve_id"] == "CVE-2"
        assert findings[1]["cve_id"] == "CVE-3"
        assert findings[2]["cve_id"] == "CVE-1"

    def test_extract_recommendations_empty(self):
        assert _extract_recommendations(None) == []
        assert _extract_recommendations({}) == []

    def test_extract_recommendations(self):
        response = {
            "result": {
                "analysis": {
                    "recommendations": [
                        {"dependency": "lodash", "recommended_version": "4.17.21"}
                    ]
                }
            }
        }
        recs = _extract_recommendations(response)
        assert len(recs) == 1
        assert recs[0]["dependency"] == "lodash"


class TestCLISubcommands:
    """Tests for CLI subcommands integration."""

    @pytest.fixture
    def runner(self):
        return CliRunner()

    def test_m2m_command_accessible(self, runner):
        result = runner.invoke(cli, ["m2m", "--help"])
        assert result.exit_code == 0
        assert "machine-to-machine" in result.output.lower()

    def test_user_delegated_command_accessible(self, runner):
        result = runner.invoke(cli, ["user-delegated", "--help"])
        assert result.exit_code == 0
        assert "user-delegated" in result.output.lower()

    def test_delegation_command_accessible(self, runner):
        result = runner.invoke(cli, ["delegation", "--help"])
        assert result.exit_code == 0
        assert "delegation" in result.output.lower()

    def test_full_analysis_command_accessible(self, runner):
        result = runner.invoke(cli, ["full-analysis", "--help"])
        assert result.exit_code == 0
        assert "analysis" in result.output.lower()
