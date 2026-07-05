"""Property-based tests for retry with exponential backoff.

**Validates: Requirements 5.6, 10.8, 16.5**

Property 5: Retry with Exponential Backoff
- For N failures, exactly min(N, max_attempts-1) retries occur with correct exponential delays.
- Total delay equals the sum of compute_delay_ms for each retry attempt.
- Each individual delay is min(base_delay * multiplier^attempt, max_delay).
"""

from unittest.mock import patch

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from src.core.retry import compute_delay_ms, retry_with_backoff_func


# --- Strategies ---

# Number of failures before success (0 means immediate success, up to 10 failures)
num_failures_st = st.integers(min_value=0, max_value=10)

# Base delay in milliseconds
base_delay_ms_st = st.integers(min_value=10, max_value=1000)

# Multiplier for exponential backoff
multiplier_st = st.integers(min_value=1, max_value=5)

# Maximum delay cap in milliseconds
max_delay_ms_st = st.integers(min_value=500, max_value=10000)


def make_failing_func(num_failures: int):
    """Create a function that fails num_failures times then succeeds.

    Returns a tuple of (func, call_count_list) where call_count_list[0]
    tracks how many times the function has been called.
    """
    call_count = [0]

    def func():
        call_count[0] += 1
        if call_count[0] <= num_failures:
            raise RuntimeError(f"Failure #{call_count[0]}")
        return "success"

    return func, call_count


@pytest.mark.property
@given(
    num_failures=num_failures_st,
    base_delay_ms=base_delay_ms_st,
    multiplier=multiplier_st,
    max_delay_ms=max_delay_ms_st,
)
def test_retry_attempts_and_success(num_failures, base_delay_ms, multiplier, max_delay_ms):
    """For a function that fails N times then succeeds:
    - attempts == min(N+1, max_attempts)
    - success == (N < max_attempts)

    **Validates: Requirements 5.6, 10.8, 16.5**
    """
    max_attempts = 3  # Fixed at 3 per requirements (retry up to 3 times)

    func, call_count = make_failing_func(num_failures)

    with patch("src.core.retry.time.sleep"):
        result = retry_with_backoff_func(
            func,
            max_attempts=max_attempts,
            base_delay_ms=base_delay_ms,
            multiplier=multiplier,
            max_delay_ms=max_delay_ms,
        )

    expected_attempts = min(num_failures + 1, max_attempts)
    expected_success = num_failures < max_attempts

    assert result.attempts == expected_attempts, (
        f"Expected {expected_attempts} attempts for {num_failures} failures "
        f"with max_attempts={max_attempts}, got {result.attempts}"
    )
    assert result.success == expected_success, (
        f"Expected success={expected_success} for {num_failures} failures "
        f"with max_attempts={max_attempts}, got {result.success}"
    )

    if expected_success:
        assert result.result == "success"
        assert result.last_error is None
    else:
        assert result.result is None
        assert result.last_error is not None


@pytest.mark.property
@given(
    num_failures=num_failures_st,
    base_delay_ms=base_delay_ms_st,
    multiplier=multiplier_st,
    max_delay_ms=max_delay_ms_st,
)
def test_retry_total_delay_equals_sum_of_individual_delays(
    num_failures, base_delay_ms, multiplier, max_delay_ms
):
    """Total delay equals sum of compute_delay_ms for each retry attempt.

    **Validates: Requirements 5.6, 10.8, 16.5**
    """
    max_attempts = 3

    func, _ = make_failing_func(num_failures)

    with patch("src.core.retry.time.sleep"):
        result = retry_with_backoff_func(
            func,
            max_attempts=max_attempts,
            base_delay_ms=base_delay_ms,
            multiplier=multiplier,
            max_delay_ms=max_delay_ms,
        )

    # Calculate expected total delay: sum of delays for each retry (not the initial attempt)
    # Retries happen after failures, before the next attempt.
    # Number of retries = attempts - 1 if success, or max_attempts - 1 if all failed
    num_retries = result.attempts - 1 if result.success else max_attempts - 1

    expected_total_delay = sum(
        compute_delay_ms(attempt, base_delay_ms, multiplier, max_delay_ms)
        for attempt in range(num_retries)
    )

    assert result.total_delay_ms == expected_total_delay, (
        f"Expected total_delay_ms={expected_total_delay} for {num_retries} retries, "
        f"got {result.total_delay_ms}"
    )


@pytest.mark.property
@given(
    attempt=st.integers(min_value=0, max_value=10),
    base_delay_ms=base_delay_ms_st,
    multiplier=multiplier_st,
    max_delay_ms=max_delay_ms_st,
)
def test_individual_delay_formula(attempt, base_delay_ms, multiplier, max_delay_ms):
    """Each individual delay is min(base_delay * multiplier^attempt, max_delay).

    **Validates: Requirements 5.6, 10.8, 16.5**
    """
    delay = compute_delay_ms(attempt, base_delay_ms, multiplier, max_delay_ms)

    raw_delay = base_delay_ms * (multiplier ** attempt)
    expected_delay = min(raw_delay, max_delay_ms)

    assert delay == expected_delay, (
        f"Expected delay={expected_delay} for attempt={attempt}, "
        f"base={base_delay_ms}, multiplier={multiplier}, max={max_delay_ms}, "
        f"got {delay}"
    )

    # Verify the delay is always capped by max_delay_ms
    assert delay <= max_delay_ms, (
        f"Delay {delay} exceeds max_delay_ms {max_delay_ms}"
    )

    # Verify the delay is always non-negative
    assert delay >= 0
