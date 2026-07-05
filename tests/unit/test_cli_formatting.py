"""Unit tests for CLI output formatting module.

Tests both summary and verbose output modes, including:
- Summary mode: one line per step with step number, stage name, success/failure (Requirement 8.8)
- Verbose mode: decoded JWT (signature masked), HTTP headers (auth masked),
  OAuth exchanges (secrets masked), identity propagation headers (Requirements 13.1-13.4)
- Trace ID display for X-Ray lookup (Requirement 11.7)
- Error response body and headers in verbose mode on failure (Requirement 13.6)
- Sequential step labeling (Requirement 8.6)
"""

from __future__ import annotations

import base64
import json

import pytest

from src.cli.formatting import (
    FAILURE_INDICATOR,
    SUCCESS_INDICATOR,
    StepResult,
    _base64url_decode,
    _decode_jwt_for_display,
    _mask_headers,
    format_step,
    format_summary_line,
    format_verbose_output,
)
from src.core.masking import MASK_PLACEHOLDER


def _make_jwt(header: dict | None = None, payload: dict | None = None) -> str:
    """Helper to create a test JWT token."""
    if header is None:
        header = {"alg": "RS256", "typ": "JWT"}
    if payload is None:
        payload = {"sub": "user-123", "iss": "https://cognito.example.com", "aud": "client-id"}

    def b64url_encode(data: dict) -> str:
        json_bytes = json.dumps(data).encode("utf-8")
        return base64.urlsafe_b64encode(json_bytes).rstrip(b"=").decode("utf-8")

    header_b64 = b64url_encode(header)
    payload_b64 = b64url_encode(payload)
    signature_b64 = base64.urlsafe_b64encode(b"fakesignature").rstrip(b"=").decode("utf-8")
    return f"{header_b64}.{payload_b64}.{signature_b64}"


class TestSummaryMode:
    """Tests for summary mode formatting (Requirement 8.8)."""

    def test_success_step_format(self):
        step = StepResult(step_number=1, stage_name="Authenticate", success=True)
        line = format_summary_line(step)
        assert "[1]" in line
        assert "Authenticate" in line
        assert SUCCESS_INDICATOR in line
        assert "success" in line

    def test_failure_step_format(self):
        step = StepResult(
            step_number=2,
            stage_name="Token Exchange",
            success=False,
            error_reason="expired_token",
        )
        line = format_summary_line(step)
        assert "[2]" in line
        assert "Token Exchange" in line
        assert FAILURE_INDICATOR in line
        assert "failure" in line
        assert "expired_token" in line

    def test_failure_without_reason(self):
        step = StepResult(step_number=3, stage_name="Resource Access", success=False)
        line = format_summary_line(step)
        assert "[3]" in line
        assert FAILURE_INDICATOR in line
        assert "failure" in line
        # No trailing colon when no reason
        assert "failure:" not in line

    def test_trace_id_included_in_summary(self):
        step = StepResult(
            step_number=1,
            stage_name="Authenticate",
            success=True,
            trace_id="1-5f4c7c14-abc123def456",
        )
        line = format_summary_line(step)
        assert "1-5f4c7c14-abc123def456" in line
        assert "trace:" in line

    def test_no_trace_id_when_not_provided(self):
        step = StepResult(step_number=1, stage_name="Authenticate", success=True)
        line = format_summary_line(step)
        assert "trace:" not in line

    def test_sequential_step_numbering(self):
        steps = [
            StepResult(step_number=i, stage_name=f"Step {i}", success=True)
            for i in range(1, 6)
        ]
        for i, step in enumerate(steps, start=1):
            line = format_summary_line(step)
            assert f"[{i}]" in line

    def test_em_dash_separator(self):
        step = StepResult(step_number=1, stage_name="Test", success=True)
        line = format_summary_line(step)
        assert "\u2014" in line  # em-dash


class TestVerboseModeJWT:
    """Tests for verbose mode JWT display (Requirement 13.1)."""

    def test_decoded_jwt_shown_in_verbose(self):
        token = _make_jwt()
        step = StepResult(
            step_number=1,
            stage_name="JWT Validation",
            success=True,
            jwt_token=token,
        )
        output = format_verbose_output(step)
        assert "JWT Token (decoded):" in output
        assert "Header:" in output
        assert "Payload:" in output
        assert "RS256" in output
        assert "user-123" in output

    def test_jwt_signature_masked(self):
        token = _make_jwt()
        step = StepResult(
            step_number=1,
            stage_name="JWT Validation",
            success=True,
            jwt_token=token,
        )
        output = format_verbose_output(step)
        assert f"Signature: {MASK_PLACEHOLDER}" in output
        # The actual signature bytes should not appear
        assert "fakesignature" not in output

    def test_invalid_jwt_format_handled(self):
        step = StepResult(
            step_number=1,
            stage_name="JWT Validation",
            success=True,
            jwt_token="not-a-jwt",
        )
        output = format_verbose_output(step)
        assert "invalid JWT format" in output
        assert MASK_PLACEHOLDER in output


class TestVerboseModeHeaders:
    """Tests for verbose mode HTTP header display (Requirement 13.2)."""

    def test_request_headers_displayed(self):
        step = StepResult(
            step_number=1,
            stage_name="Agent Invocation",
            success=True,
            request_headers={
                "Content-Type": "application/json",
                "X-Request-Id": "abc-123",
            },
        )
        output = format_verbose_output(step)
        assert "Request Headers:" in output
        assert "Content-Type: application/json" in output
        assert "X-Request-Id: abc-123" in output

    def test_authorization_header_masked_in_request(self):
        step = StepResult(
            step_number=1,
            stage_name="Agent Invocation",
            success=True,
            request_headers={
                "Authorization": "Bearer eyJhbGciOiJSUzI1NiJ9.payload.sig",
                "Content-Type": "application/json",
            },
        )
        output = format_verbose_output(step)
        assert "Request Headers:" in output
        assert f"Authorization: Bearer {MASK_PLACEHOLDER}" in output
        # The actual token should not appear
        assert "eyJhbGciOiJSUzI1NiJ9" not in output

    def test_response_headers_displayed(self):
        step = StepResult(
            step_number=1,
            stage_name="Agent Invocation",
            success=True,
            response_headers={
                "X-Amzn-RequestId": "req-456",
                "Content-Type": "application/json",
            },
        )
        output = format_verbose_output(step)
        assert "Response Headers:" in output
        assert "X-Amzn-RequestId: req-456" in output


class TestVerboseModeOAuth:
    """Tests for verbose mode OAuth exchange display (Requirement 13.3)."""

    def test_oauth_exchange_displayed(self):
        step = StepResult(
            step_number=2,
            stage_name="Token Exchange",
            success=True,
            oauth_exchange={
                "grant_type": "authorization_code",
                "scope": "security_events repo",
                "token_endpoint": "https://github.com/login/oauth/access_token",
            },
        )
        output = format_verbose_output(step)
        assert "OAuth Exchange:" in output
        assert "authorization_code" in output
        assert "security_events repo" in output

    def test_oauth_client_secret_masked(self):
        step = StepResult(
            step_number=2,
            stage_name="Token Exchange",
            success=True,
            oauth_exchange={
                "grant_type": "client_credentials",
                "client_secret": "super-secret-value-123",
                "client_id": "my-client-id",
            },
        )
        output = format_verbose_output(step)
        assert "super-secret-value-123" not in output
        assert MASK_PLACEHOLDER in output
        assert "my-client-id" in output

    def test_oauth_refresh_token_masked(self):
        step = StepResult(
            step_number=3,
            stage_name="Token Refresh",
            success=True,
            oauth_exchange={
                "grant_type": "refresh_token",
                "refresh_token": "rt-secret-token-value",
                "scope": "repo",
            },
        )
        output = format_verbose_output(step)
        assert "rt-secret-token-value" not in output
        assert MASK_PLACEHOLDER in output
        assert "repo" in output


class TestVerboseModeIdentityPropagation:
    """Tests for verbose mode identity propagation display (Requirement 13.4)."""

    def test_identity_headers_displayed(self):
        step = StepResult(
            step_number=4,
            stage_name="Identity Propagation",
            success=True,
            identity_headers={
                "X-Source-Agent": "orchestrator-agent",
                "X-User-Subject": "user-sub-123",
                "X-Correlation-ID": "550e8400-e29b-41d4-a716-446655440000",
                "X-Delegation-Chain": "orchestrator-agent -> scanner-agent",
            },
        )
        output = format_verbose_output(step)
        assert "Identity Propagation Headers:" in output
        assert "X-Source-Agent: orchestrator-agent" in output
        assert "X-User-Subject: user-sub-123" in output
        assert "X-Correlation-ID: 550e8400-e29b-41d4-a716-446655440000" in output
        assert "X-Delegation-Chain: orchestrator-agent -> scanner-agent" in output


class TestVerboseModeTraceID:
    """Tests for trace ID display (Requirement 11.7)."""

    def test_trace_id_displayed_in_verbose(self):
        step = StepResult(
            step_number=1,
            stage_name="Authenticate",
            success=True,
            trace_id="1-5f4c7c14-e0ef3b5f67890abc",
        )
        output = format_verbose_output(step)
        assert "Trace ID: 1-5f4c7c14-e0ef3b5f67890abc" in output

    def test_no_trace_id_when_absent(self):
        step = StepResult(
            step_number=1,
            stage_name="Authenticate",
            success=True,
        )
        output = format_verbose_output(step)
        assert "Trace ID:" not in output


class TestVerboseModeFailure:
    """Tests for verbose mode error display on failure (Requirement 13.6)."""

    def test_failure_shows_error_response_body(self):
        step = StepResult(
            step_number=3,
            stage_name="Resource Access",
            success=False,
            error_reason="unauthorized",
            response_status=401,
            response_body='{"message": "Token expired", "error": "Unauthorized"}',
            response_headers={
                "Content-Type": "application/json",
                "X-Amzn-RequestId": "req-789",
            },
        )
        output = format_verbose_output(step)
        assert FAILURE_INDICATOR in output
        assert "unauthorized" in output
        assert "401" in output
        assert "Token expired" in output
        assert "Error Response Body:" in output
        assert "Error Response Headers:" in output

    def test_failure_masks_auth_in_error_headers(self):
        step = StepResult(
            step_number=3,
            stage_name="Resource Access",
            success=False,
            error_reason="forbidden",
            response_status=403,
            response_body="Forbidden",
            response_headers={
                "Authorization": "Bearer secret-token",
                "Content-Type": "text/plain",
            },
        )
        output = format_verbose_output(step)
        assert "secret-token" not in output
        assert f"Bearer {MASK_PLACEHOLDER}" in output


class TestFormatStep:
    """Tests for the format_step dispatcher."""

    def test_format_step_verbose_true(self):
        step = StepResult(step_number=1, stage_name="Test", success=True)
        output = format_step(step, verbose=True)
        # Verbose mode produces multi-line output with section header
        assert "=" * 60 in output
        assert "[1] Test" in output

    def test_format_step_verbose_false(self):
        step = StepResult(step_number=1, stage_name="Test", success=True)
        output = format_step(step, verbose=False)
        # Summary mode is a single line
        assert output.count("\n") == 0
        assert "[1]" in output
        assert "Test" in output


class TestStepLabeling:
    """Tests for sequential step labeling (Requirement 8.6, 8.8)."""

    def test_step_has_number_and_name(self):
        step = StepResult(step_number=5, stage_name="Consent Redirect", success=True)
        line = format_summary_line(step)
        assert "[5]" in line
        assert "Consent Redirect" in line

    def test_verbose_step_header_has_number_and_name(self):
        step = StepResult(step_number=7, stage_name="Token Storage", success=True)
        output = format_verbose_output(step)
        assert "[7] Token Storage" in output


class TestHelpers:
    """Tests for internal helper functions."""

    def test_base64url_decode_with_padding(self):
        # "hello" base64url encoded (without padding)
        encoded = base64.urlsafe_b64encode(b"hello").rstrip(b"=").decode("utf-8")
        assert _base64url_decode(encoded) == "hello"

    def test_mask_headers_preserves_non_sensitive(self):
        headers = {"Content-Type": "application/json", "Accept": "text/html"}
        masked = _mask_headers(headers)
        assert masked["Content-Type"] == "application/json"
        assert masked["Accept"] == "text/html"

    def test_mask_headers_masks_authorization(self):
        headers = {"Authorization": "Bearer my-secret-token"}
        masked = _mask_headers(headers)
        assert masked["Authorization"] == f"Bearer {MASK_PLACEHOLDER}"
        assert "my-secret-token" not in masked["Authorization"]

    def test_mask_headers_masks_api_key(self):
        headers = {"X-Api-Key": "secret-api-key-123"}
        masked = _mask_headers(headers)
        assert masked["X-Api-Key"] == MASK_PLACEHOLDER

    def test_mask_headers_case_insensitive(self):
        headers = {"AUTHORIZATION": "Bearer token123"}
        masked = _mask_headers(headers)
        assert masked["AUTHORIZATION"] == f"Bearer {MASK_PLACEHOLDER}"

    def test_decode_jwt_three_parts(self):
        token = _make_jwt(
            header={"alg": "RS256", "kid": "key-1"},
            payload={"sub": "test-user", "exp": 9999999999},
        )
        lines = _decode_jwt_for_display(token)
        combined = "\n".join(lines)
        assert "RS256" in combined
        assert "key-1" in combined
        assert "test-user" in combined
        assert f"Signature: {MASK_PLACEHOLDER}" in combined

    def test_decode_jwt_invalid_format(self):
        lines = _decode_jwt_for_display("not.a.valid.jwt.format")
        combined = "\n".join(lines)
        assert "invalid JWT format" in combined
