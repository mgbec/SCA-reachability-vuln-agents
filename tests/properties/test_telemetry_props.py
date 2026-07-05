"""Property-based tests for OpenTelemetry auth span attribute completeness.

**Validates: Requirements 11.5, 11.6**

Property 12: Auth Span Attribute Completeness
Every auth step span contains step_type, agent_identity, and outcome attributes.
When record_failure is called, the span has ERROR status and a span event with
the failure reason.
"""

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.resources import Resource
from opentelemetry.trace import StatusCode

from src.core.telemetry import TelemetryProvider, VALID_AUTH_STEP_TYPES
from tests.properties import agent_arns


# --- Strategies ---

step_types = st.sampled_from(sorted(VALID_AUTH_STEP_TYPES))

failure_reasons = st.text(
    min_size=1,
    max_size=100,
    alphabet=st.characters(whitelist_categories=("L", "N", "P", "Z")),
)


def _create_provider_with_in_memory_exporter():
    """Create a TelemetryProvider with an InMemorySpanExporter for capturing spans in tests."""
    exporter = InMemorySpanExporter()
    provider = TelemetryProvider.__new__(TelemetryProvider)
    # Manually configure with in-memory exporter instead of OTLP
    resource = Resource.create({"service.name": "test-service"})
    tracer_provider = TracerProvider(resource=resource)
    tracer_provider.add_span_processor(SimpleSpanProcessor(exporter))
    provider._service_name = "test-service"
    provider._endpoint = "localhost:4317"
    provider._provider = tracer_provider
    provider._tracer = tracer_provider.get_tracer("test-service")
    return provider, exporter


@pytest.mark.property
class TestAuthSpanAttributeCompleteness:
    """Property 12: Auth Span Attribute Completeness.

    For any step_type and agent_identity, a span created via create_auth_span
    has all 3 required attributes (auth.step_type, auth.agent_identity, auth.outcome).
    When record_failure is called, span has ERROR status and a span event with
    the failure reason.

    **Validates: Requirements 11.5, 11.6**
    """

    @given(
        step_type=step_types,
        agent_identity=agent_arns(),
    )
    @settings(max_examples=50)
    def test_auth_span_contains_all_required_attributes(self, step_type, agent_identity):
        """Every auth step span contains step_type, agent_identity, and outcome attributes."""
        provider, exporter = _create_provider_with_in_memory_exporter()

        with provider.create_auth_span(step_type, agent_identity) as span:
            provider.record_success(span)

        finished_spans = exporter.get_finished_spans()
        assert len(finished_spans) == 1

        span = finished_spans[0]
        attributes = dict(span.attributes)

        # All three required attributes must be present
        assert "auth.step_type" in attributes, "Missing auth.step_type attribute"
        assert "auth.agent_identity" in attributes, "Missing auth.agent_identity attribute"
        assert "auth.outcome" in attributes, "Missing auth.outcome attribute"

        # Values must match what was provided
        assert attributes["auth.step_type"] == step_type
        assert attributes["auth.agent_identity"] == agent_identity
        assert attributes["auth.outcome"] == "success"

        provider.shutdown()
        exporter.clear()

    @given(
        step_type=step_types,
        agent_identity=agent_arns(),
        reason=failure_reasons,
    )
    @settings(max_examples=50)
    def test_failure_span_has_error_status_and_reason_event(self, step_type, agent_identity, reason):
        """When record_failure is called, span has ERROR status and a span event with failure reason."""
        provider, exporter = _create_provider_with_in_memory_exporter()

        with provider.create_auth_span(step_type, agent_identity) as span:
            provider.record_failure(span, reason)

        finished_spans = exporter.get_finished_spans()
        assert len(finished_spans) == 1

        span = finished_spans[0]
        attributes = dict(span.attributes)

        # Required attributes are still present
        assert attributes["auth.step_type"] == step_type
        assert attributes["auth.agent_identity"] == agent_identity
        assert attributes["auth.outcome"] == "failure"

        # Span status must be ERROR
        assert span.status.status_code == StatusCode.ERROR

        # There must be a span event recording the failure reason
        events = span.events
        assert len(events) >= 1, "No span events recorded for failure"

        failure_events = [e for e in events if e.name == "auth.failure"]
        assert len(failure_events) == 1, "Expected exactly one auth.failure event"

        failure_event = failure_events[0]
        assert "auth.failure_reason" in failure_event.attributes
        assert failure_event.attributes["auth.failure_reason"] == reason

        provider.shutdown()
        exporter.clear()
