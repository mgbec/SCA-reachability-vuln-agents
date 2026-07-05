"""Unit tests for retry with exponential backoff.

Tests the retry_with_backoff decorator, retry_with_backoff_func function,
and compute_delay_ms utility covering:
- Successful execution on first attempt (no retries needed)
- Retry and eventual success
- All retries exhausted → failure reported
- Exponential delay computation with max cap
- Decorator interface re-raises last exception on exhaustion

Requirements: 5.6, 10.8, 16.5
"""

from unittest.mock import patch

import pytest

from src.core.retry import (
    RetryResult,
    compute_delay_ms,
    retry_with_backoff,
    retry_with_backoff_func,
)


class TestComputeDelayMs:
    """Tests for delay calculation: min(base_delay * (multiplier ^ attempt), max_delay)."""

    def test_first_retry_uses_base_delay(self):
        delay = compute_delay_ms(attempt=0, base_delay_ms=100, multiplier=2, max_delay_ms=5000)
        assert delay == 100  # 100 * 2^0 = 100

    def test_second_retry_doubles_delay(self):
        delay = compute_delay_ms(attempt=1, base_delay_ms=100, multiplier=2, max_delay_ms=5000)
        assert delay == 200  # 100 * 2^1 = 200

    def test_third_retry_quadruples_base(self):
        delay = compute_delay_ms(attempt=2, base_delay_ms=100, multiplier=2, max_delay_ms=5000)
        assert delay == 400  # 100 * 2^2 = 400

    def test_delay_capped_at_max(self):
        delay = compute_delay_ms(attempt=10, base_delay_ms=100, multiplier=2, max_delay_ms=5000)
        assert delay == 5000  # 100 * 2^10 = 102400, capped at 5000

    def test_custom_multiplier(self):
        delay = compute_delay_ms(attempt=2, base_delay_ms=50, multiplier=3, max_delay_ms=10000)
        assert delay == 450  # 50 * 3^2 = 450


class TestRetryWithBackoffFunc:
    """Tests for the programmatic retry_with_backoff_func interface."""

    def test_success_on_first_attempt(self):
        def always_works():
            return 42

        result = retry_with_backoff_func(always_works)

        assert result.success is True
        assert result.result == 42
        assert result.attempts == 1
        assert result.total_delay_ms == 0
        assert result.last_error is None

    def test_success_after_retries(self):
        call_count = 0

        def succeeds_on_third():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise RuntimeError(f"Failure #{call_count}")
            return "success"

        with patch("src.core.retry.time.sleep"):
            result = retry_with_backoff_func(succeeds_on_third)

        assert result.success is True
        assert result.result == "success"
        assert result.attempts == 3
        assert result.last_error is None

    def test_all_retries_exhausted(self):
        def always_fails():
            raise ValueError("persistent failure")

        with patch("src.core.retry.time.sleep"):
            result = retry_with_backoff_func(always_fails, max_attempts=3)

        assert result.success is False
        assert result.result is None
        assert result.attempts == 3
        assert isinstance(result.last_error, ValueError)
        assert "persistent failure" in str(result.last_error)

    def test_total_delay_accumulated_correctly(self):
        def always_fails():
            raise RuntimeError("fail")

        with patch("src.core.retry.time.sleep"):
            result = retry_with_backoff_func(
                always_fails,
                max_attempts=3,
                base_delay_ms=100,
                multiplier=2,
                max_delay_ms=5000,
            )

        # attempt 0 fails → delay 100ms, attempt 1 fails → delay 200ms, attempt 2 fails → done
        assert result.total_delay_ms == 300  # 100 + 200
        assert result.attempts == 3

    def test_delay_capped_in_accumulated_total(self):
        def always_fails():
            raise RuntimeError("fail")

        with patch("src.core.retry.time.sleep"):
            result = retry_with_backoff_func(
                always_fails,
                max_attempts=4,
                base_delay_ms=1000,
                multiplier=3,
                max_delay_ms=5000,
            )

        # attempt 0 → delay 1000, attempt 1 → delay 3000, attempt 2 → delay min(9000, 5000)=5000
        assert result.total_delay_ms == 9000  # 1000 + 3000 + 5000
        assert result.attempts == 4

    def test_arguments_forwarded_to_function(self):
        def add(a, b, offset=0):
            return a + b + offset

        result = retry_with_backoff_func(add, 2, 3, offset=10)

        assert result.success is True
        assert result.result == 15

    @patch("src.core.retry.time.sleep")
    def test_sleep_called_with_correct_seconds(self, mock_sleep):
        call_count = 0

        def fails_twice():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise RuntimeError("fail")
            return "ok"

        retry_with_backoff_func(
            fails_twice,
            max_attempts=3,
            base_delay_ms=100,
            multiplier=2,
            max_delay_ms=5000,
        )

        # Should sleep 100ms then 200ms (in seconds)
        assert mock_sleep.call_count == 2
        mock_sleep.assert_any_call(0.1)   # 100ms
        mock_sleep.assert_any_call(0.2)   # 200ms


class TestRetryWithBackoffDecorator:
    """Tests for the @retry_with_backoff decorator interface."""

    def test_decorated_function_returns_normally_on_success(self):
        @retry_with_backoff()
        def get_value():
            return "hello"

        assert get_value() == "hello"

    def test_decorated_function_retries_and_succeeds(self):
        call_count = 0

        @retry_with_backoff(max_attempts=3, base_delay_ms=10)
        def flaky():
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise RuntimeError("transient")
            return "recovered"

        with patch("src.core.retry.time.sleep"):
            result = flaky()

        assert result == "recovered"
        assert call_count == 2

    def test_decorated_function_raises_on_exhaustion(self):
        @retry_with_backoff(max_attempts=2, base_delay_ms=10)
        def always_fails():
            raise IOError("connection refused")

        with patch("src.core.retry.time.sleep"):
            with pytest.raises(IOError, match="connection refused"):
                always_fails()

    def test_decorator_preserves_function_name(self):
        @retry_with_backoff()
        def my_special_function():
            pass

        assert my_special_function.__name__ == "my_special_function"


class TestRetryResult:
    """Tests for the RetryResult dataclass."""

    def test_success_result(self):
        result = RetryResult(
            success=True,
            result="data",
            attempts=1,
            total_delay_ms=0,
            last_error=None,
        )
        assert result.success is True
        assert result.result == "data"
        assert result.attempts == 1
        assert result.total_delay_ms == 0
        assert result.last_error is None

    def test_failure_result(self):
        error = RuntimeError("failed")
        result = RetryResult(
            success=False,
            result=None,
            attempts=3,
            total_delay_ms=300,
            last_error=error,
        )
        assert result.success is False
        assert result.result is None
        assert result.attempts == 3
        assert result.total_delay_ms == 300
        assert result.last_error is error
