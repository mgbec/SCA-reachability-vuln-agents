"""Retry with exponential backoff for resilient operation execution.

Provides both a decorator and a callable function for retrying operations
that may transiently fail (e.g., token acquisition, log writes, Secrets Manager access).

Delay formula: min(base_delay_ms * (multiplier ^ attempt), max_delay_ms)

Requirements: 5.6, 10.8, 16.5
"""

from __future__ import annotations

import functools
import time
from dataclasses import dataclass
from typing import Any, Callable, Optional, TypeVar

from src.core.constants import DEFAULT_RETRY_CONFIG, RetryConfig

F = TypeVar("F", bound=Callable[..., Any])


@dataclass
class RetryResult:
    """Result of a retried operation.

    Attributes:
        success: Whether the operation eventually succeeded.
        result: The return value of the function if successful, else None.
        attempts: Total number of attempts made (1 = no retries needed).
        total_delay_ms: Cumulative delay in milliseconds spent waiting between retries.
        last_error: The last exception raised if all attempts failed, else None.
    """

    success: bool
    result: Any
    attempts: int
    total_delay_ms: int
    last_error: Optional[Exception]


def compute_delay_ms(
    attempt: int,
    base_delay_ms: int,
    multiplier: int,
    max_delay_ms: int,
) -> int:
    """Calculate the delay for a given retry attempt.

    Args:
        attempt: Zero-based attempt index (0 = first retry).
        base_delay_ms: Base delay in milliseconds.
        multiplier: Exponential multiplier.
        max_delay_ms: Maximum allowed delay cap.

    Returns:
        Delay in milliseconds for this attempt.
    """
    delay = base_delay_ms * (multiplier ** attempt)
    return min(delay, max_delay_ms)


def retry_with_backoff_func(
    func: Callable[..., Any],
    *args: Any,
    max_attempts: int = DEFAULT_RETRY_CONFIG.max_attempts,
    base_delay_ms: int = DEFAULT_RETRY_CONFIG.base_delay_ms,
    multiplier: int = DEFAULT_RETRY_CONFIG.multiplier,
    max_delay_ms: int = DEFAULT_RETRY_CONFIG.max_delay_ms,
    **kwargs: Any,
) -> RetryResult:
    """Execute a function with retry and exponential backoff (programmatic API).

    Calls *func* up to *max_attempts* times. On each failure, waits for an
    exponentially increasing delay before the next attempt.

    Args:
        func: The callable to execute.
        *args: Positional arguments forwarded to *func*.
        max_attempts: Maximum number of attempts (including the initial call).
        base_delay_ms: Initial delay in milliseconds before the first retry.
        multiplier: Multiplier applied to the delay after each failed attempt.
        max_delay_ms: Maximum delay cap in milliseconds.
        **kwargs: Keyword arguments forwarded to *func*.

    Returns:
        A RetryResult capturing success/failure state, result, attempt count,
        total delay, and last error.
    """
    last_error: Optional[Exception] = None
    total_delay_ms: int = 0

    for attempt in range(max_attempts):
        try:
            result = func(*args, **kwargs)
            return RetryResult(
                success=True,
                result=result,
                attempts=attempt + 1,
                total_delay_ms=total_delay_ms,
                last_error=None,
            )
        except Exception as exc:  # noqa: BLE001
            last_error = exc
            # Sleep before next attempt (not after the last failure)
            if attempt < max_attempts - 1:
                delay = compute_delay_ms(attempt, base_delay_ms, multiplier, max_delay_ms)
                total_delay_ms += delay
                time.sleep(delay / 1000.0)

    # All retries exhausted — report failure
    return RetryResult(
        success=False,
        result=None,
        attempts=max_attempts,
        total_delay_ms=total_delay_ms,
        last_error=last_error,
    )


def retry_with_backoff(
    max_attempts: int = DEFAULT_RETRY_CONFIG.max_attempts,
    base_delay_ms: int = DEFAULT_RETRY_CONFIG.base_delay_ms,
    multiplier: int = DEFAULT_RETRY_CONFIG.multiplier,
    max_delay_ms: int = DEFAULT_RETRY_CONFIG.max_delay_ms,
) -> Callable[[F], F]:
    """Decorator for retrying a function with exponential backoff.

    On success the decorated function returns normally. On exhaustion of all
    retries the last exception is re-raised.

    Usage::

        @retry_with_backoff(max_attempts=5, base_delay_ms=200)
        def fetch_secret():
            ...

    Args:
        max_attempts: Maximum number of attempts (including the initial call).
        base_delay_ms: Initial delay in milliseconds before the first retry.
        multiplier: Multiplier applied to the delay after each failed attempt.
        max_delay_ms: Maximum delay cap in milliseconds.

    Returns:
        A decorator that wraps the target function with retry logic.
    """

    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            retry_result = retry_with_backoff_func(
                func,
                *args,
                max_attempts=max_attempts,
                base_delay_ms=base_delay_ms,
                multiplier=multiplier,
                max_delay_ms=max_delay_ms,
                **kwargs,
            )
            if retry_result.success:
                return retry_result.result
            # All retries exhausted — raise the last exception
            raise retry_result.last_error  # type: ignore[misc]

        return wrapper  # type: ignore[return-value]

    return decorator
