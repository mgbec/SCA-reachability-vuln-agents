"""Correlation ID propagation utility.

Provides functions for extracting or generating correlation IDs from
inbound request headers and propagating them to outbound requests.
This enables distributed tracing across agent boundaries by maintaining
a consistent identifier throughout the request lifecycle.

The correlation ID header name is "X-Correlation-ID" and lookups are
performed case-insensitively to handle variations from different HTTP
libraries and proxies.

Requirements: 11.1, 11.2, 11.3
"""

from __future__ import annotations

import uuid

CORRELATION_ID_HEADER = "X-Correlation-ID"


def _is_valid_uuid_v4(value: str) -> bool:
    """Check if a string is a valid UUID v4.

    Args:
        value: The string to validate.

    Returns:
        True if the string is a valid UUID v4, False otherwise.
    """
    try:
        parsed = uuid.UUID(value, version=4)
        # Ensure the string round-trips correctly and is actually version 4
        return str(parsed) == value.lower().strip() and parsed.version == 4
    except (ValueError, AttributeError):
        return False


def _find_correlation_id_header(headers: dict) -> str | None:
    """Perform a case-insensitive lookup for the correlation ID header.

    Args:
        headers: Dictionary of request headers.

    Returns:
        The correlation ID value if found with a case-insensitive match
        on the header name, or None if not present.
    """
    for key, value in headers.items():
        if key.lower() == CORRELATION_ID_HEADER.lower():
            return value
    return None


def extract_or_generate_correlation_id(headers: dict) -> str:
    """Extract a valid correlation ID from headers or generate a new one.

    Performs a case-insensitive lookup for the "X-Correlation-ID" header.
    If found and the value is a valid UUID v4, returns it. Otherwise,
    generates and returns a new UUID v4.

    Args:
        headers: Dictionary of inbound request headers.

    Returns:
        A valid UUID v4 string — either extracted from headers or
        newly generated.
    """
    existing = _find_correlation_id_header(headers)
    if existing is not None and _is_valid_uuid_v4(existing):
        return existing
    return str(uuid.uuid4())


def propagate_correlation_id(outbound_headers: dict, correlation_id: str) -> dict:
    """Add or overwrite the correlation ID in outbound request headers.

    Sets the "X-Correlation-ID" header in the provided headers dictionary,
    overwriting any existing value. Returns the modified dictionary.

    Args:
        outbound_headers: Dictionary of outbound request headers to modify.
        correlation_id: The correlation ID string to propagate.

    Returns:
        The outbound_headers dictionary with the X-Correlation-ID header set.
    """
    outbound_headers[CORRELATION_ID_HEADER] = correlation_id
    return outbound_headers
