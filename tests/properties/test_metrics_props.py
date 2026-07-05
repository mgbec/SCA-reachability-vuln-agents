"""Property-based tests for metric counter accuracy.

Tests that metric counters per agent exactly equal the count of corresponding
events in the input sequence.

**Validates: Requirements 12.1**
"""

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import InMemoryMetricReader

from src.core.metrics import AuthMetrics
from tests.properties import agent_names


def _get_counter_value(reader: InMemoryMetricReader, metric_name: str, agent_name: str) -> int:
    """Extract the cumulative counter value for a given metric and agent from the reader.

    OpenTelemetry SDK lowercases metric names internally, so comparison is
    performed case-insensitively.

    Returns 0 if the metric is not found.
    """
    metrics_data = reader.get_metrics_data()
    target_name = metric_name.lower()
    for resource_metrics in metrics_data.resource_metrics:
        for scope_metrics in resource_metrics.scope_metrics:
            for metric in scope_metrics.metrics:
                if metric.name == target_name:
                    for data_point in metric.data.data_points:
                        attrs = dict(data_point.attributes) if data_point.attributes else {}
                        if attrs.get("AgentName") == agent_name:
                            return data_point.value
    return 0


@pytest.mark.property
class TestMetricCounterAccuracy:
    """Property 13: Metric Counter Accuracy.

    Tests that metric counters per agent exactly equal the count of
    corresponding events in input sequence.

    **Validates: Requirements 12.1**
    """

    @given(count=st.integers(min_value=1, max_value=100), agent_name=agent_names)
    def test_auth_success_counter_matches_call_count(self, count: int, agent_name: str):
        """For any sequence of N auth_success calls, the AuthSuccess counter == N.

        **Validates: Requirements 12.1**
        """
        reader = InMemoryMetricReader()
        provider = MeterProvider(metric_readers=[reader])
        metrics = AuthMetrics(agent_name=agent_name, meter_provider=provider)

        for _ in range(count):
            metrics.record_auth_success()

        value = _get_counter_value(reader, "AuthSuccess", agent_name)
        assert value == count, (
            f"Expected AuthSuccess counter == {count} for agent '{agent_name}', got {value}"
        )

        provider.shutdown()

    @given(count=st.integers(min_value=1, max_value=100), agent_name=agent_names)
    def test_auth_failure_counter_matches_call_count(self, count: int, agent_name: str):
        """For any sequence of M auth_failure calls, the AuthFailure counter == M.

        **Validates: Requirements 12.1**
        """
        reader = InMemoryMetricReader()
        provider = MeterProvider(metric_readers=[reader])
        metrics = AuthMetrics(agent_name=agent_name, meter_provider=provider)

        for _ in range(count):
            metrics.record_auth_failure()

        value = _get_counter_value(reader, "AuthFailure", agent_name)
        assert value == count, (
            f"Expected AuthFailure counter == {count} for agent '{agent_name}', got {value}"
        )

        provider.shutdown()

    @given(
        success_count=st.integers(min_value=1, max_value=100),
        failure_count=st.integers(min_value=1, max_value=100),
        agent_name=agent_names,
    )
    def test_mixed_counters_match_respective_call_counts(
        self, success_count: int, failure_count: int, agent_name: str
    ):
        """For mixed sequences, each counter matches exactly its call count.

        **Validates: Requirements 12.1**
        """
        reader = InMemoryMetricReader()
        provider = MeterProvider(metric_readers=[reader])
        metrics = AuthMetrics(agent_name=agent_name, meter_provider=provider)

        for _ in range(success_count):
            metrics.record_auth_success()

        for _ in range(failure_count):
            metrics.record_auth_failure()

        success_value = _get_counter_value(reader, "AuthSuccess", agent_name)
        failure_value = _get_counter_value(reader, "AuthFailure", agent_name)

        assert success_value == success_count, (
            f"Expected AuthSuccess == {success_count}, got {success_value}"
        )
        assert failure_value == failure_count, (
            f"Expected AuthFailure == {failure_count}, got {failure_value}"
        )

        provider.shutdown()
