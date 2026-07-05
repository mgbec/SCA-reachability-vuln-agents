"""Sensitive data masking utilities for verbose output mode.

Provides functions to mask sensitive fields in dicts before display,
ensuring JWT signatures, Authorization header values, client secrets,
and refresh tokens are not exposed in logs or CLI output.

Requirements: 13.1, 13.2, 13.3
"""

from __future__ import annotations

import copy
from typing import Any

# Default fields considered sensitive and subject to masking.
DEFAULT_SENSITIVE_FIELDS: list[str] = [
    "client_secret",
    "refresh_token",
    "signature",
    "authorization",
    "Authorization",
]

MASK_PLACEHOLDER: str = "****"


def mask_jwt_signature(jwt_value: str) -> str:
    """Mask the signature segment of a JWT token.

    A JWT has three dot-separated segments: header.payload.signature.
    This function preserves the header and payload but replaces the
    signature with the mask placeholder.

    Args:
        jwt_value: A string that may be a JWT (three dot-separated parts).

    Returns:
        The JWT with its signature masked if it has three segments,
        otherwise the original string masked entirely.
    """
    parts = jwt_value.split(".")
    if len(parts) == 3:
        return f"{parts[0]}.{parts[1]}.{MASK_PLACEHOLDER}"
    return MASK_PLACEHOLDER


def mask_authorization_header(header_value: str) -> str:
    """Mask the token value in an Authorization header, preserving the scheme prefix.

    For example, "Bearer eyJhbG..." becomes "Bearer ****".

    Args:
        header_value: The full Authorization header value (e.g., "Bearer <token>").

    Returns:
        The header with the token portion masked. If no scheme prefix is
        detected (no space separator), the entire value is masked.
    """
    parts = header_value.split(" ", 1)
    if len(parts) == 2:
        return f"{parts[0]} {MASK_PLACEHOLDER}"
    return MASK_PLACEHOLDER


def _mask_value(field_name: str, value: Any) -> Any:
    """Apply the appropriate masking strategy based on field name and value type.

    Args:
        field_name: The dictionary key name (used to select masking strategy).
        value: The value to mask.

    Returns:
        The masked value.
    """
    if not isinstance(value, str):
        return MASK_PLACEHOLDER

    lower_name = field_name.lower()

    if lower_name == "signature":
        # Could be a standalone JWT signature or a full JWT
        return mask_jwt_signature(value) if "." in value else MASK_PLACEHOLDER

    if lower_name in ("authorization",):
        return mask_authorization_header(value)

    # For client_secret, refresh_token, and other sensitive fields: full mask.
    return MASK_PLACEHOLDER


def mask_sensitive(
    data: dict[str, Any],
    sensitive_fields: list[str] | None = None,
) -> dict[str, Any]:
    """Deep-copy the input dict and mask all sensitive field values.

    Recursively traverses nested dicts, masking any field whose name
    (case-insensitive match) appears in the sensitive_fields list.

    Args:
        data: The input dictionary (not modified).
        sensitive_fields: List of field names to mask. Defaults to
            DEFAULT_SENSITIVE_FIELDS if not provided.

    Returns:
        A new dictionary with sensitive values masked and all other
        values preserved unchanged.
    """
    if sensitive_fields is None:
        sensitive_fields = DEFAULT_SENSITIVE_FIELDS

    # Build a lowercase set for case-insensitive matching.
    sensitive_set = {f.lower() for f in sensitive_fields}

    result = copy.deepcopy(data)
    _mask_dict_recursive(result, sensitive_set)
    return result


def _mask_dict_recursive(d: dict[str, Any], sensitive_set: set[str]) -> None:
    """Recursively mask sensitive fields in-place within a dict.

    Args:
        d: The dictionary to process (modified in-place).
        sensitive_set: Set of lowercase field names considered sensitive.
    """
    for key in list(d.keys()):
        value = d[key]
        if isinstance(value, dict):
            _mask_dict_recursive(value, sensitive_set)
        elif key.lower() in sensitive_set:
            d[key] = _mask_value(key, value)
