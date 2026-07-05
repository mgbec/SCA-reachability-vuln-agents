"""Scope intersection logic for OAuth 2.0 authorization scope enforcement.

Implements the scope resolution algorithm that determines which scopes to grant
when an agent requests a token. The granted scopes are the intersection of
requested scopes and the configured maximum scopes for the agent's credential
provider.

Requirements:
    7.1 - Credential provider specifies maximum allowed OAuth scopes per agent.
    7.2 - Token issued with scopes limited to intersection of requested and maximum.
    7.4 - Empty intersection results in rejection with error.
    7.5 - Empty request grants full set of configured maximum scopes.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class GrantResult:
    """Result of scope resolution between requested and maximum allowed scopes.

    Attributes:
        granted_scopes: The set of scopes granted to the agent. Empty if rejected.
        is_granted: True if scopes were successfully granted, False if rejected.
        error_message: Describes the reason for rejection, or None if granted.
    """

    granted_scopes: set[str]
    is_granted: bool
    error_message: Optional[str]


def resolve_scopes(requested: set[str], maximum: set[str]) -> GrantResult:
    """Resolve the granted scopes from requested and maximum allowed scopes.

    Implements the scope enforcement rules:
    - If requested is empty, grant the full set of maximum scopes (Requirement 7.5).
    - Otherwise, grant the intersection of requested and maximum scopes (Requirement 7.2).
    - If the intersection is empty, reject with an error (Requirement 7.4).

    Args:
        requested: The set of scopes the agent is requesting. May be empty.
        maximum: The configured maximum allowed scopes for the agent's credential
                 provider (Requirement 7.1).

    Returns:
        A GrantResult indicating whether scopes were granted and which ones.
    """
    if not requested:
        # Requirement 7.5: no scopes specified → grant full maximum
        return GrantResult(
            granted_scopes=set(maximum),
            is_granted=True,
            error_message=None,
        )

    intersection = requested & maximum

    if not intersection:
        # Requirement 7.4: empty intersection → reject
        return GrantResult(
            granted_scopes=set(),
            is_granted=False,
            error_message="No valid scopes could be granted: "
            "requested scopes have no overlap with maximum allowed scopes",
        )

    # Requirement 7.2: grant the intersection
    return GrantResult(
        granted_scopes=intersection,
        is_granted=True,
        error_message=None,
    )
