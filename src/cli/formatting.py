"""CLI output formatting utilities for summary and verbose modes.

Provides functions to format workflow step output in two modes:
- Summary mode: one line per step with step number, stage name, success/failure indicator
- Verbose mode: decoded JWT (signature masked), HTTP request/response headers (auth
  values masked), OAuth protocol exchanges (secrets masked), identity propagation headers

Each request displays its trace ID for X-Ray console lookup.
On failure in verbose mode, error response body and headers are displayed.

Requirements: 8.6, 8.8, 11.7, 13.1, 13.2, 13.3, 13.4, 13.6
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from typing import Any

import click

from src.core.masking import (
    MASK_PLACEHOLDER,
    mask_authorization_header,
    mask_jwt_signature,
    mask_sensitive,
)

# Success and failure indicators for summary mode
SUCCESS_INDICATOR = "\u2713"
FAILURE_INDICATOR = "\u2717"

# Default sensitive fields for HTTP header masking
SENSITIVE_HEADER_FIELDS = [
    "authorization",
    "x-api-key",
    "cookie",
    "set-cookie",
]

# Sensitive fields in OAuth exchanges
OAUTH_SENSITIVE_FIELDS = [
    "client_secret",
    "refresh_token",
    "code",
]


@dataclass
class StepResult:
    """Result of a single workflow step.

    Attributes:
        step_number: Sequential step number (1-based).
        stage_name: Descriptive name of the stage.
        success: Whether the step succeeded.
        trace_id: The X-Ray trace ID for this request.
        error_reason: Short reason string on failure.
        jwt_token: Raw JWT token to decode and display in verbose mode.
        request_headers: HTTP request headers for verbose display.
        response_headers: HTTP response headers for verbose display.
        response_body: Response body (displayed on failure in verbose mode).
        response_status: HTTP response status code.
        oauth_exchange: OAuth protocol exchange details for verbose display.
        identity_headers: Identity propagation headers for verbose display.
    """

    step_number: int
    stage_name: str
    success: bool
    trace_id: str | None = None
    error_reason: str | None = None
    jwt_token: str | None = None
    request_headers: dict[str, str] | None = None
    response_headers: dict[str, str] | None = None
    response_body: str | None = None
    response_status: int | None = None
    oauth_exchange: dict[str, Any] | None = None
    identity_headers: dict[str, str] | None = None


def format_summary_line(step: StepResult) -> str:
    """Format a single step as a summary-mode line.

    Format: [N] Stage Name — ✓ success
            [N] Stage Name — ✗ failure: reason

    Args:
        step: The step result to format.

    Returns:
        A single-line string in summary format.
    """
    if step.success:
        indicator = f"{SUCCESS_INDICATOR} success"
    else:
        reason_suffix = f": {step.error_reason}" if step.error_reason else ""
        indicator = f"{FAILURE_INDICATOR} failure{reason_suffix}"

    line = f"[{step.step_number}] {step.stage_name} \u2014 {indicator}"

    if step.trace_id:
        line += f"  (trace: {step.trace_id})"

    return line


def format_verbose_output(step: StepResult) -> str:
    """Format a single step as verbose-mode output.

    Includes decoded JWT (signature masked), HTTP headers (auth values masked),
    OAuth exchange details (secrets masked), identity propagation headers,
    and trace ID for X-Ray lookup. On failure, shows error response body and headers.

    Args:
        step: The step result to format.

    Returns:
        A multi-line string with verbose output for this step.
    """
    lines: list[str] = []

    # Step header with number and stage name
    lines.append(f"{'=' * 60}")
    lines.append(f"[{step.step_number}] {step.stage_name}")
    lines.append(f"{'=' * 60}")

    # Trace ID for X-Ray console lookup
    if step.trace_id:
        lines.append(f"  Trace ID: {step.trace_id}")
        lines.append("")

    # Decoded JWT (signature masked)
    if step.jwt_token:
        lines.append("  JWT Token (decoded):")
        decoded = _decode_jwt_for_display(step.jwt_token)
        for line in decoded:
            lines.append(f"    {line}")
        lines.append("")

    # HTTP request headers (auth values masked)
    if step.request_headers:
        lines.append("  Request Headers:")
        masked_headers = _mask_headers(step.request_headers)
        for key, value in masked_headers.items():
            lines.append(f"    {key}: {value}")
        lines.append("")

    # HTTP response headers (auth values masked)
    if step.response_headers:
        lines.append("  Response Headers:")
        masked_headers = _mask_headers(step.response_headers)
        for key, value in masked_headers.items():
            lines.append(f"    {key}: {value}")
        lines.append("")

    # OAuth protocol exchange (secrets masked)
    if step.oauth_exchange:
        lines.append("  OAuth Exchange:")
        masked_exchange = mask_sensitive(step.oauth_exchange, OAUTH_SENSITIVE_FIELDS)
        formatted = json.dumps(masked_exchange, indent=4)
        for line in formatted.splitlines():
            lines.append(f"    {line}")
        lines.append("")

    # Identity propagation headers
    if step.identity_headers:
        lines.append("  Identity Propagation Headers:")
        for key, value in step.identity_headers.items():
            lines.append(f"    {key}: {value}")
        lines.append("")

    # Success/failure status
    if step.success:
        lines.append(f"  Status: {SUCCESS_INDICATOR} success")
    else:
        lines.append(f"  Status: {FAILURE_INDICATOR} failure")
        if step.error_reason:
            lines.append(f"  Error: {step.error_reason}")

        # On failure, show error response body and headers
        if step.response_status:
            lines.append(f"  HTTP Status: {step.response_status}")
        if step.response_body:
            lines.append("  Error Response Body:")
            lines.append(f"    {step.response_body}")
        if step.response_headers:
            lines.append("  Error Response Headers:")
            masked_headers = _mask_headers(step.response_headers)
            for key, value in masked_headers.items():
                lines.append(f"    {key}: {value}")

    lines.append("")
    return "\n".join(lines)


def format_step(step: StepResult, verbose: bool) -> str:
    """Format a step result according to the output mode.

    Args:
        step: The step result to format.
        verbose: If True, use verbose output mode; otherwise use summary mode.

    Returns:
        Formatted string for the step.
    """
    if verbose:
        return format_verbose_output(step)
    return format_summary_line(step)


def print_step(step: StepResult, verbose: bool) -> None:
    """Format and print a step result to stdout using click.echo.

    Args:
        step: The step result to format and display.
        verbose: If True, use verbose output mode; otherwise use summary mode.
    """
    output = format_step(step, verbose)
    click.echo(output)


def _decode_jwt_for_display(token: str) -> list[str]:
    """Decode a JWT token for display with the signature masked.

    Decodes the header and payload segments of the JWT using base64url
    decoding and formats them as JSON. The signature is replaced with
    the mask placeholder.

    Args:
        token: A JWT string (three dot-separated base64url segments).

    Returns:
        A list of formatted lines showing header, payload, and masked signature.
    """
    parts = token.split(".")
    lines: list[str] = []

    if len(parts) != 3:
        lines.append(f"(invalid JWT format: {MASK_PLACEHOLDER})")
        return lines

    # Decode header
    try:
        header_json = _base64url_decode(parts[0])
        header_data = json.loads(header_json)
        lines.append("Header:")
        header_formatted = json.dumps(header_data, indent=2)
        for line in header_formatted.splitlines():
            lines.append(f"  {line}")
    except (ValueError, json.JSONDecodeError):
        lines.append(f"Header: (decode error)")

    # Decode payload
    try:
        payload_json = _base64url_decode(parts[1])
        payload_data = json.loads(payload_json)
        lines.append("Payload:")
        payload_formatted = json.dumps(payload_data, indent=2)
        for line in payload_formatted.splitlines():
            lines.append(f"  {line}")
    except (ValueError, json.JSONDecodeError):
        lines.append(f"Payload: (decode error)")

    # Signature masked
    lines.append(f"Signature: {MASK_PLACEHOLDER}")

    return lines


def _base64url_decode(data: str) -> str:
    """Decode a base64url-encoded string (with optional padding).

    Args:
        data: A base64url-encoded string.

    Returns:
        The decoded UTF-8 string.
    """
    # Add padding if needed
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data).decode("utf-8")


def _mask_headers(headers: dict[str, str]) -> dict[str, str]:
    """Mask sensitive values in HTTP headers.

    Masks Authorization header values (preserving scheme prefix),
    and fully masks other sensitive headers (x-api-key, cookie, set-cookie).

    Args:
        headers: Dictionary of HTTP headers.

    Returns:
        A new dictionary with sensitive header values masked.
    """
    masked: dict[str, str] = {}
    for key, value in headers.items():
        if key.lower() == "authorization":
            masked[key] = mask_authorization_header(value)
        elif key.lower() in SENSITIVE_HEADER_FIELDS:
            masked[key] = MASK_PLACEHOLDER
        else:
            masked[key] = value
    return masked
