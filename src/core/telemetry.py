"""OpenTelemetry SDK integration for distributed tracing across agent boundaries.

Provides TelemetryProvider class that configures OTLP export and creates
spans for authentication steps with required attributes: auth.step_type,
auth.agent_identity, and auth.outcome.

Requirements: 11.4, 11.5, 11.6
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Generator

from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.trace import Span, StatusCode

# Valid auth step types as defined in the design document.
VALID_AUTH_STEP_TYPES = frozenset(
    {
        "token_validation",
        "credential_retrieval",
        "token_exchange",
        "resource_access",
        "mtls_validation",
    }
)


class TelemetryProvider:
    """Configures OpenTelemetry tracing with OTLP export and provides span creation for auth steps.

    Attributes:
        service_name: The logical service name attached to all traces from this provider.
        endpoint: The OTLP gRPC collector endpoint (default: localhost:4317).
    """

    def __init__(self, service_name: str, endpoint: str = "localhost:4317") -> None:
        """Initialize the TelemetryProvider with an OTLP exporter and BatchSpanProcessor.

        Args:
            service_name: Name of the service emitting traces (e.g., "orchestrator-agent").
            endpoint: gRPC endpoint for the OpenTelemetry Collector (default: localhost:4317).
        """
        self._service_name = service_name
        self._endpoint = endpoint

        # Configure the resource with service name for trace attribution.
        resource = Resource.create({"service.name": service_name})

        # Create the OTLP gRPC exporter targeting the collector sidecar.
        exporter = OTLPSpanExporter(endpoint=endpoint, insecure=True)

        # Use BatchSpanProcessor for efficient, non-blocking export.
        span_processor = BatchSpanProcessor(exporter)

        # Assemble and set the global TracerProvider.
        self._provider = TracerProvider(resource=resource)
        self._provider.add_span_processor(span_processor)
        trace.set_tracer_provider(self._provider)

        # Obtain a tracer scoped to this service.
        self._tracer = trace.get_tracer(service_name)

    @property
    def service_name(self) -> str:
        """Return the configured service name."""
        return self._service_name

    @property
    def endpoint(self) -> str:
        """Return the configured OTLP endpoint."""
        return self._endpoint

    @property
    def provider(self) -> TracerProvider:
        """Return the underlying TracerProvider for testing or advanced use."""
        return self._provider

    @contextmanager
    def create_auth_span(
        self,
        step_type: str,
        agent_identity: str,
        parent_context: trace.Context | None = None,
    ) -> Generator[Span, None, None]:
        """Create and yield a span representing an authentication step.

        The span is automatically populated with the required attributes:
        - auth.step_type: The type of auth operation (e.g., "token_validation").
        - auth.agent_identity: The ARN or name of the agent performing the step.
        - auth.outcome: Set to "success" by default; call record_failure to change to "failure".

        Usage:
            with provider.create_auth_span("token_validation", agent_arn) as span:
                # perform auth step
                if failed:
                    provider.record_failure(span, "token expired")
                else:
                    provider.record_success(span)

        Args:
            step_type: The authentication step type. Should be one of the VALID_AUTH_STEP_TYPES.
            agent_identity: The agent identity (ARN or name) performing this step.
            parent_context: Optional parent trace context for linking spans across agents.

        Yields:
            The active Span with auth attributes set.
        """
        span_name = f"auth.{step_type}"

        # Start the span, optionally linking to a parent context.
        with self._tracer.start_as_current_span(
            name=span_name,
            context=parent_context,
        ) as span:
            # Set required attributes on the span.
            span.set_attribute("auth.step_type", step_type)
            span.set_attribute("auth.agent_identity", agent_identity)
            # Default outcome is "success"; record_failure overrides this.
            span.set_attribute("auth.outcome", "success")
            yield span

    def record_success(self, span: Span) -> None:
        """Mark the span as a successful auth operation.

        Sets span status to OK and ensures auth.outcome attribute is "success".

        Args:
            span: The span to mark as successful.
        """
        span.set_attribute("auth.outcome", "success")
        span.set_status(StatusCode.OK)

    def record_failure(self, span: Span, reason: str) -> None:
        """Mark the span as a failed auth operation.

        Sets span status to ERROR, updates auth.outcome to "failure",
        and adds an event recording the failure reason.

        Args:
            span: The span to mark as failed.
            reason: A human-readable explanation of the failure (e.g., "token expired").
        """
        span.set_attribute("auth.outcome", "failure")
        span.set_status(StatusCode.ERROR, description=reason)
        span.add_event("auth.failure", attributes={"auth.failure_reason": reason})

    def shutdown(self) -> None:
        """Flush pending spans and shut down the TracerProvider.

        Call this during application teardown to ensure all spans are exported.
        """
        self._provider.shutdown()
