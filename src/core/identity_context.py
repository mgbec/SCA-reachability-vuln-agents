"""Identity context construction and validation for agent-to-agent delegation.

Implements HMAC-SHA256 signed identity context envelopes that propagate user
identity across agent boundaries. Provides tamper detection via signature
verification, expiration checking, and structural validation.

Requirements: 6.1, 6.2, 6.4, 6.5
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from src.core.constants import IDENTITY_CONTEXT_VERSION
from src.core.models import (
    DelegationEntry,
    IdentityContext,
    UserIdentity,
    WorkloadIdentity,
)


@dataclass
class ValidationResult:
    """Result of identity context validation.

    Attributes:
        is_valid: Whether the identity context passed all validation checks.
        tamper_type: Type of tampering detected, if any.
            One of: "signature_mismatch", "expired_identity", "malformed_structure"
        error_message: Human-readable description of the validation failure.
    """

    is_valid: bool
    tamper_type: Optional[str] = None
    error_message: Optional[str] = None


def _serialize_context_fields(context: IdentityContext) -> str:
    """Serialize identity context fields into a canonical string for HMAC signing.

    The signature covers:
    - version
    - correlation_id
    - source_agent.arn
    - user_identity fields: subject, issuer, audience, scopes, issued_at, expires_at
    - delegation_chain entries: agent_arn + delegated_at for each entry

    Fields are joined with '|' separators for unambiguous parsing.
    """
    parts: list[str] = [
        context.version,
        context.correlation_id,
        context.source_agent.arn,
        context.user_identity.subject,
        context.user_identity.issuer,
        context.user_identity.audience,
        ",".join(sorted(context.user_identity.scopes)),
        context.user_identity.issued_at.isoformat(),
        context.user_identity.expires_at.isoformat(),
    ]

    for entry in context.delegation_chain:
        parts.append(entry.agent_arn)
        parts.append(entry.delegated_at.isoformat())

    return "|".join(parts)


def _compute_hmac_signature(data: str, hmac_key: bytes) -> str:
    """Compute HMAC-SHA256 signature and return as base64-encoded string."""
    signature = hmac.new(hmac_key, data.encode("utf-8"), hashlib.sha256).digest()
    return base64.b64encode(signature).decode("utf-8")


def build_identity_context(
    user_claims: dict,
    source_agent: WorkloadIdentity,
    hmac_key: bytes,
) -> IdentityContext:
    """Build a signed identity context for agent-to-agent delegation.

    Constructs an IdentityContext envelope containing the user identity claims,
    source agent identity, a generated correlation ID, and an HMAC-SHA256
    signature over all context fields.

    Args:
        user_claims: Dictionary containing user identity fields:
            - subject: User subject claim from JWT
            - issuer: Token issuer URL
            - audience: Intended audience
            - scopes: List of granted OAuth scopes
            - issued_at: Token issuance timestamp (datetime)
            - expires_at: Token expiration timestamp (datetime)
        source_agent: WorkloadIdentity of the agent constructing this context.
        hmac_key: Secret key for HMAC-SHA256 signature computation.

    Returns:
        A fully populated and signed IdentityContext.
    """
    user_identity = UserIdentity(
        subject=user_claims["subject"],
        issuer=user_claims["issuer"],
        audience=user_claims["audience"],
        scopes=user_claims["scopes"],
        issued_at=user_claims["issued_at"],
        expires_at=user_claims["expires_at"],
        token_reference=user_claims.get("token_reference", ""),
    )

    delegation_entry = DelegationEntry(
        agent_arn=source_agent.arn,
        delegated_at=datetime.now(timezone.utc),
    )

    context = IdentityContext(
        version=IDENTITY_CONTEXT_VERSION,
        correlation_id=str(uuid.uuid4()),
        source_agent=source_agent,
        user_identity=user_identity,
        delegation_chain=[delegation_entry],
        signature="",
    )

    # Compute HMAC-SHA256 signature over serialized fields
    serialized = _serialize_context_fields(context)
    context.signature = _compute_hmac_signature(serialized, hmac_key)

    return context


def validate_identity_context(
    context: IdentityContext,
    hmac_key: bytes,
) -> ValidationResult:
    """Validate an identity context envelope for tamper detection.

    Performs three validation checks in order:
    1. Structure completeness — all required fields present and non-empty
    2. Expiration — user identity has not expired
    3. Signature — HMAC-SHA256 matches recomputed signature

    Args:
        context: The IdentityContext to validate.
        hmac_key: Secret key for HMAC-SHA256 signature verification.

    Returns:
        ValidationResult indicating success or the specific tamper type detected.
    """
    # 1. Verify structure completeness
    structure_error = _check_structure(context)
    if structure_error:
        return ValidationResult(
            is_valid=False,
            tamper_type="malformed_structure",
            error_message=structure_error,
        )

    # 2. Check expiration
    now = datetime.now(timezone.utc)
    if context.user_identity.expires_at <= now:
        return ValidationResult(
            is_valid=False,
            tamper_type="expired_identity",
            error_message=(
                f"User identity expired at {context.user_identity.expires_at.isoformat()}"
            ),
        )

    # 3. Verify HMAC-SHA256 signature
    serialized = _serialize_context_fields(context)
    expected_signature = _compute_hmac_signature(serialized, hmac_key)

    if not hmac.compare_digest(context.signature, expected_signature):
        return ValidationResult(
            is_valid=False,
            tamper_type="signature_mismatch",
            error_message="Identity context signature does not match computed HMAC-SHA256",
        )

    return ValidationResult(is_valid=True)


def _check_structure(context: IdentityContext) -> Optional[str]:
    """Check that the identity context has all required fields populated.

    Returns an error message string if validation fails, or None if structure is valid.
    """
    if not context.version:
        return "Missing version field"

    if not context.correlation_id:
        return "Missing correlation_id field"

    if not context.source_agent or not context.source_agent.arn:
        return "Missing or empty source_agent ARN"

    if not context.user_identity:
        return "Missing user_identity"

    ui = context.user_identity
    if not ui.subject:
        return "Missing user_identity.subject"
    if not ui.issuer:
        return "Missing user_identity.issuer"
    if not ui.audience:
        return "Missing user_identity.audience"
    if not ui.scopes:
        return "Missing user_identity.scopes"
    if not ui.issued_at:
        return "Missing user_identity.issued_at"
    if not ui.expires_at:
        return "Missing user_identity.expires_at"

    if not context.signature:
        return "Missing signature field"

    return None
