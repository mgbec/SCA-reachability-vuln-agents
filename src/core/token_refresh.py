"""Token refresh decision logic.

Determines whether an OAuth token needs to be refreshed based on its
expiration time and a configurable buffer window. Used by both the
Scanner Agent (user-delegated tokens) and Analysis Agent (M2M tokens)
to proactively refresh credentials before they expire.

Requirements: 5.4, 4.5
"""

from __future__ import annotations

from datetime import datetime, timedelta

from src.core.constants import TOKEN_REFRESH_BUFFER_SECONDS


def needs_refresh(
    token_expiration: datetime,
    current_time: datetime,
    buffer_seconds: int = TOKEN_REFRESH_BUFFER_SECONDS,
) -> bool:
    """Determine whether a token needs to be refreshed.

    Returns True if the token is already expired or is within
    `buffer_seconds` of expiration, indicating that a new token
    should be obtained before the next resource request.

    Args:
        token_expiration: The UTC datetime when the token expires.
        current_time: The current UTC datetime.
        buffer_seconds: Number of seconds before expiration to trigger
            refresh. Defaults to TOKEN_REFRESH_BUFFER_SECONDS (60).

    Returns:
        True if the token should be refreshed, False otherwise.
    """
    refresh_threshold = current_time + timedelta(seconds=buffer_seconds)
    return token_expiration <= refresh_threshold
