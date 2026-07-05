"""OpenTelemetry SDK integration with direct AWS X-Ray export.

Provides TelemetryProvider class that exports traces directly to AWS X-Ray
without requiring an intermediate OTel Collector sidecar. Uses the
AWS X-Ray ID generator and propagator for native X-Ray trace format.

Falls back to OTLP export if AWS X-Ray exporter is unavailable (e.g., local dev).

Requirements: 11.4, 11.5, 11.6
"""

from __future__ import annotations

import logging
import os
from contextlib import contextmanager
from typing import Generator

from opentelemetry import trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, SpanExporter
from opentelemetry.trace import Span, StatusCode

logger = logging.getLogger(__name__)

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


def _create_trace_exporter(endpoint: str) -> tuple[SpanExporter, object | None, object | None]:
    """Create the best available trace exporter for the environment.

    Attempts AWS X-Ray exporter first (direct export, no Collector needed).
    Falls back to OTLP gRPC exporter if AWS packages are unavailable.

    Args:
        endpoint: OTLP endpoint (used only for fallback).

    Returns:
        Tuple of (exporter, id_generator_or_None, propagator_or_None).
    """
    # Try AWS X-Ray direct export first
    try:
        from opentelemetry.sdk.extension.aws.trace import AwsXRayIdGenerator
        from opentelemetry.propagators.aws import AwsXRayPropagator
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter

        # When running on AWS, the ADOT (AWS Distro for OpenTelemetry) layer
        # configures the OTLP endpoint to point to the X-Ray daemon.
        # The X-Ray ID generator ensures trace IDs are X-Ray compatible.
        xray_endpoint = os.environ.get(
            "OTEL_EXPORTER_OTLP_ENDPOINT",
            os.environ.get("AWS_XRAY_DAEMON_ADDRESS", endpoint),
        )

        exporter = OTLPSpanExporter(endpoint=xray_endpoint, insecure=True)
        id_generator = AwsXRayIdGenerator()
        propagator = AwsXRayPropagator()

        logger.info(
            "Using AWS X-Ray trace export (direct, no Collector sidecar required)",
            extra={"endpoint": xray_endpoint},
        )
        return exporter, id_generator, propagator

    except ImportError:
        pass

    # Fallback: standard OTLP gRPC exporter
    try:
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter

        exporter = OTLPSpanExporter(endpoint=endpoint, insecure=True)
        logger.info(
            "Using OTLP gRPC trace export (fallback)",
            extra={"endpoint": endpoint},
        )
        return exporter, None, None

    except ImportError:
        pass

    # Last resort: console/noop exporter for local dev
    from opentelemetry.sdk.trace.export import ConsoleSpanExporter

    logger.warning("No trace exporter available, using ConsoleSpanExporter")
    return ConsoleSpanExporter(), None, None


class TelemetryProvider:
    """Configures OpenTelemetry tracing with direct AWS X-Ray export.

    Exports traces directly to AWS X-Ray without requiring a Collector sidecar.
    Uses X-Ray-compatible trace ID generation and propagation format.

    Falls back gracefully to OTLP or console export when AWS packages
    are unavailable (e.g., local development).

    Attributes:
        service_name: The logical service name attached to all traces from this provider.
        endpoint: The OTLP/X-Ray endpoint (default: localhost:4317 or AWS_XRAY_DAEMON_ADDRESS).
    """

    def __init__(self, service_name: str, endpoint: str = "localhost:4317") -> None:
        """Initialize the TelemetryProvider with the best available exporter.

        Tries AWS X-Ray direct export first, falls back to OTLP, then console.

        Args:
            service_name: Name of the service emitting traces (e.g., "orchestrator-agent").
            endpoint: Fallback gRPC endpoint if AWS env vars are not set.
        """
        self._service_name = service_name
        self._endpoint = endpoint

        # Configure the resource with service name for trace attribution.
        resource = Resource.create({"service.name": service_name})

        # Get the best available exporter
        exporter, id_generator, propagator = _create_trace_exporter(endpoint)

        # Use BatchSpanProcessor for efficient, non-blocking export.
        span_processor = BatchSpanProcessor(exporter)

        # Build TracerProvider with optional X-Ray ID generator
        provider_kwargs = {"resource": resource}
        if id_generator is not None:
            provider_kwargs["id_generator"] = id_generator

        self._provider = TracerProvider(**provider_kwargs)
        self._provider.add_span_processor(span_processor)
        trace.set_tracer_provider(self._provider)

        # Set X-Ray propagator if available (for cross-service context propagation)
        if propagator is not None:
            from opentelemetry import propagate
            propagate.set_global_textmap(propagator)

        # Obtain a tracer scoped to this service.
        self._tracer = trace.get_tracer(service_name)

    @property
    def service_name(self) -> str:
        """Return the configured service name."""
        return self._service_name

    @property
    def endpoint(self) -> str:
        """Return the configured export endpoint."""
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
        - auth.outcome: Set to "success" by default; call record_failure to change.

        Args:
            step_type: The authentication step type. Should be one of VALID_AUTH_STEP_TYPES.
            agent_identity: The agent identity (ARN or name) performing this step.
            parent_context: Optional parent trace context for linking spans across agents.

        Yields:
            The active Span with auth attributes set.
        """
        span_name = f"auth.{step_type}"

        with self._tracer.start_as_current_span(
            name=span_name,
            context=parent_context,
        ) as span:
            span.set_attribute("auth.step_type", step_type)
            span.set_attribute("auth.agent_identity", agent_identity)
            span.set_attribute("auth.outcome", "success")
            yield span

    def record_success(self, span: Span) -> None:
        """Mark the span as a successful auth operation.

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
            reason: A human-readable explanation of the failure.
        """
        span.set_attribute("auth.outcome", "failure")
        span.set_status(StatusCode.ERROR, description=reason)
        span.add_event("auth.failure", attributes={"auth.failure_reason": reason})

    def shutdown(self) -> None:
        """Flush pending spans and shut down the TracerProvider."""
        self._provider.shutdown()
