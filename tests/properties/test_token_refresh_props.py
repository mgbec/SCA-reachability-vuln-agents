"""Property-based tests for token refresh decision logic.

**Validates: Requirements 5.4, 4.5**

Property 4: Token Refresh Decision Boundary
Tests that refresh is needed iff token expired or within buffer seconds of expiration.
"""

from datetime import timedelta

import pytest
from hypothesis import given
from hypothesis import strategies as st

from src.core.token_refresh import needs_refresh
from tests.properties import timestamps, token_expiration_scenarios


@pytest.mark.property
@given(data=token_expiration_scenarios(buffer_seconds=60))
def test_token_refresh_decision_matches_expected(data):
    """Token refresh decision matches expected outcome for all expiration scenarios.

    **Validates: Requirements 5.4, 4.5**

    Uses the token_expiration_scenarios strategy which generates triples of
    (current_time, token_expiration, expected_needs_refresh) covering expired,
    within-buffer, and safe cases.
    """
    current_time, token_expiration, expected = data
    result = needs_refresh(token_expiration, current_time, buffer_seconds=60)
    assert result == expected


@pytest.mark.property
@given(
    current_time=timestamps(),
    seconds_past=st.integers(min_value=1, max_value=86400),
)
def test_expired_token_always_needs_refresh(current_time, seconds_past):
    """If token_expiration <= current_time, needs_refresh returns True (expired).

    **Validates: Requirements 5.4, 4.5**
    """
    token_expiration = current_time - timedelta(seconds=seconds_past)
    assert needs_refresh(token_expiration, current_time, buffer_seconds=60) is True


@pytest.mark.property
@given(
    current_time=timestamps(),
    seconds_within_buffer=st.integers(min_value=0, max_value=59),
)
def test_within_buffer_needs_refresh(current_time, seconds_within_buffer):
    """If token_expiration <= current_time + buffer, needs_refresh returns True.

    **Validates: Requirements 5.4, 4.5**

    Token expires within the 60-second buffer window, so proactive refresh
    is required before the next resource request.
    """
    token_expiration = current_time + timedelta(seconds=seconds_within_buffer)
    assert needs_refresh(token_expiration, current_time, buffer_seconds=60) is True


@pytest.mark.property
@given(
    current_time=timestamps(),
    seconds_beyond_buffer=st.integers(min_value=61, max_value=86400),
)
def test_beyond_buffer_does_not_need_refresh(current_time, seconds_beyond_buffer):
    """If token_expiration > current_time + buffer, needs_refresh returns False.

    **Validates: Requirements 5.4, 4.5**

    Token has more than 60 seconds remaining, so no refresh is needed.
    """
    token_expiration = current_time + timedelta(seconds=seconds_beyond_buffer)
    assert needs_refresh(token_expiration, current_time, buffer_seconds=60) is False


@pytest.mark.property
@given(
    current_time=timestamps(),
    buffer=st.integers(min_value=1, max_value=300),
)
def test_exact_boundary_needs_refresh(current_time, buffer):
    """Token expiring exactly at current_time + buffer needs refresh.

    **Validates: Requirements 5.4, 4.5**

    The boundary condition: when token_expiration == current_time + timedelta(seconds=buffer),
    the token is at the edge of the buffer window and needs_refresh should return True
    (token_expiration <= refresh_threshold).
    """
    token_expiration = current_time + timedelta(seconds=buffer)
    assert needs_refresh(token_expiration, current_time, buffer_seconds=buffer) is True


@pytest.mark.property
@given(
    current_time=timestamps(),
    buffer=st.integers(min_value=1, max_value=300),
)
def test_one_second_past_boundary_safe(current_time, buffer):
    """Token expiring one second past the buffer boundary does not need refresh.

    **Validates: Requirements 5.4, 4.5**

    When token_expiration = current_time + buffer + 1 second, the token is just
    outside the refresh window and should be considered safe.
    """
    token_expiration = current_time + timedelta(seconds=buffer + 1)
    assert needs_refresh(token_expiration, current_time, buffer_seconds=buffer) is False
