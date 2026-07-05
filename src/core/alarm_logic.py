"""Failure rate threshold validation and alarm logic.

Implements authentication failure rate monitoring with configurable thresholds.
Triggers alarms when the failure rate exceeds the configured threshold,
supporting the CloudWatch alarm integration defined in Requirements 12.4 and 12.6.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from src.core.constants import (
    MAX_FAILURE_RATE_THRESHOLD_PERCENT,
    MIN_FAILURE_RATE_THRESHOLD_PERCENT,
)


@dataclass(frozen=True)
class AlarmResult:
    """Result of a failure rate threshold check.

    Attributes:
        alarm_triggered: Whether the failure rate exceeds the threshold.
        failure_rate: The calculated failure rate as a percentage (0-100).
        threshold: The threshold that was checked against.
        error_message: Error message if the threshold is invalid, None otherwise.
    """

    alarm_triggered: bool
    failure_rate: float
    threshold: float
    error_message: Optional[str] = None


def check_failure_rate(
    successes: int, failures: int, threshold: float
) -> AlarmResult:
    """Check whether the authentication failure rate exceeds the configured threshold.

    Calculates the failure rate as a percentage of total authentication attempts
    and determines whether it exceeds the given threshold, triggering an alarm.

    Args:
        successes: Number of successful authentication attempts.
        failures: Number of failed authentication attempts.
        threshold: The failure rate threshold percentage (must be in [1, 100]).

    Returns:
        AlarmResult with alarm status, calculated failure rate, threshold used,
        and an error message if the threshold is outside the valid range.

    Requirements:
        - 12.4: Trigger alarm when failure rate exceeds configurable threshold.
        - 12.6: Accept threshold values between 1% and 100%, reject values outside.
    """
    # Validate threshold range
    if threshold < MIN_FAILURE_RATE_THRESHOLD_PERCENT or threshold > MAX_FAILURE_RATE_THRESHOLD_PERCENT:
        return AlarmResult(
            alarm_triggered=False,
            failure_rate=0.0,
            threshold=threshold,
            error_message="Threshold must be between 1 and 100",
        )

    # Calculate failure rate
    total = successes + failures
    if total == 0:
        return AlarmResult(
            alarm_triggered=False,
            failure_rate=0.0,
            threshold=threshold,
        )

    failure_rate = (failures / total) * 100

    # Determine if alarm should trigger
    alarm_triggered = failure_rate > threshold

    return AlarmResult(
        alarm_triggered=alarm_triggered,
        failure_rate=failure_rate,
        threshold=threshold,
    )
