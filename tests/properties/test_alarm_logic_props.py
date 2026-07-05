"""Property-based tests for failure rate threshold validation and alarm logic.

**Validates: Requirements 12.4, 12.6**

Property 10: Failure Rate Threshold Validation and Alarm
Tests that thresholds in [1,100] accepted, outside rejected; alarm triggers iff
calculated rate exceeds threshold.
"""

import pytest
from hypothesis import given, assume
from hypothesis import strategies as st

from src.core.alarm_logic import check_failure_rate


# --- Strategies ---

valid_thresholds = st.floats(min_value=1.0, max_value=100.0, allow_nan=False, allow_infinity=False)

invalid_thresholds_low = st.floats(
    max_value=0.99, allow_nan=False, allow_infinity=False, allow_subnormal=False
).filter(lambda x: x < 1.0)

invalid_thresholds_high = st.floats(
    min_value=100.01, max_value=1e6, allow_nan=False, allow_infinity=False
)

successes_strategy = st.integers(min_value=0, max_value=1000)
failures_strategy = st.integers(min_value=0, max_value=1000)


@pytest.mark.property
@given(
    threshold=valid_thresholds,
    successes=successes_strategy,
    failures=failures_strategy,
)
def test_valid_threshold_accepted_no_error(threshold, successes, failures):
    """For any threshold in [1, 100], error_message is None.

    **Validates: Requirements 12.4, 12.6**

    Valid thresholds should always be accepted without error, regardless of
    the success/failure counts provided.
    """
    result = check_failure_rate(successes, failures, threshold)
    assert result.error_message is None


@pytest.mark.property
@given(threshold=invalid_thresholds_low)
def test_threshold_below_range_rejected(threshold):
    """For any threshold < 1, error_message is not None and alarm_triggered is False.

    **Validates: Requirements 12.6**

    Thresholds below the valid range [1, 100] are rejected with an error message
    indicating the valid range. The alarm must not trigger for invalid thresholds.
    """
    result = check_failure_rate(100, 50, threshold)
    assert result.error_message is not None
    assert result.alarm_triggered is False


@pytest.mark.property
@given(threshold=invalid_thresholds_high)
def test_threshold_above_range_rejected(threshold):
    """For any threshold > 100, error_message is not None and alarm_triggered is False.

    **Validates: Requirements 12.6**

    Thresholds above the valid range [1, 100] are rejected with an error message
    indicating the valid range. The alarm must not trigger for invalid thresholds.
    """
    result = check_failure_rate(100, 50, threshold)
    assert result.error_message is not None
    assert result.alarm_triggered is False


@pytest.mark.property
@given(
    successes=successes_strategy,
    failures=st.integers(min_value=0, max_value=1000),
    threshold=valid_thresholds,
)
def test_alarm_triggers_iff_rate_exceeds_threshold(successes, failures, threshold):
    """For valid threshold and non-zero total: alarm_triggered == ((failures / total) * 100 > threshold).

    **Validates: Requirements 12.4, 12.6**

    The alarm should trigger if and only if the calculated failure rate
    (as a percentage) strictly exceeds the configured threshold.
    """
    total = successes + failures
    assume(total > 0)

    result = check_failure_rate(successes, failures, threshold)

    expected_rate = (failures / total) * 100
    expected_alarm = expected_rate > threshold

    assert result.alarm_triggered == expected_alarm
    assert result.error_message is None


@pytest.mark.property
@given(threshold=valid_thresholds)
def test_zero_total_does_not_trigger_alarm(threshold):
    """When both successes and failures are zero, alarm is not triggered.

    **Validates: Requirements 12.4, 12.6**

    With no authentication attempts, the failure rate is undefined (0/0),
    so the system should not trigger an alarm.
    """
    result = check_failure_rate(0, 0, threshold)
    assert result.alarm_triggered is False
    assert result.failure_rate == 0.0
    assert result.error_message is None
