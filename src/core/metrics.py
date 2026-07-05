"""OpenTelemetry metrics collection with direct CloudWatch export.

Provides the AuthMetrics class that instruments counters for authentication
events and latency histograms for authentication operations and SCA analysis
steps. Metrics are exported directly to CloudWatch via the OTel SDK without
requiring a Collector sidecar.

When running on AWS, uses the OTLP exporter pointed at the ADOT endpoint
(which forwards to CloudWatch EMF). Falls back to in-memory or console
export for local development.
"""

from __future__ import annotations

import logging
import os

from opentelemetry import metrics
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import (
    InMemoryMetricReader,
    PeriodicExportingMetricReader,
)

from src.core.constants import (
    METRICS_AGGREGATION_INTERVAL_SECONDS,
    METRICS_NAMESPACE,
    MetricNames,
)

logger = logging.getLogger(__name__)


def _create_meter_provider() -> MeterProvider:
    """Create and configure a MeterProvider with the best available exporter.

    Attempts OTLP metric export (works with ADOT layer on AWS or Collector).
    Falls back to InMemoryMetricReader for local development/testing.

    Returns:
        A configured MeterProvider.
    """
    # Try OTLP metric exporter (works with ADOT Lambda layer or Collector)
    try:
        from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter

        endpoint = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT", "localhost:4317")
        exporter = OTLPMetricExporter(endpoint=endpoint, insecure=True)
        reader = PeriodicExportingMetricReader(
            exporter,
            export_interval_millis=METRICS_AGGREGATION_INTERVAL_SECONDS * 1000,
        )
        logger.info(
            "Using OTLP metric export",
            extra={"endpoint": endpoint},
        )
        return MeterProvider(metric_readers=[reader])

    except Exception as e:
        logger.info(f"OTLP metric export unavailable ({e}), using in-memory reader")

    # Fallback: in-memory reader (metrics accessible programmatically, no export)
    reader = InMemoryMetricReader()
    return MeterProvider(metric_readers=[reader])


class AuthMetrics:
    """Collects authentication and SCA metrics via OpenTelemetry Metrics API.

    Instruments counters for authentication success/failure events, token
    refreshes, and authorization denials. Instruments histograms for latency
    measurements of JWT validation, token retrieval, token refresh, mTLS
    validation, call graph builds, and SBOM generation.

    All counters include an "AgentName" attribute/label identifying the agent
    that emitted the metric.

    When deployed on AWS with the ADOT layer, metrics flow directly to
    CloudWatch EMF without a Collector sidecar.

    Args:
        agent_name: The name of the agent (used as the AgentName label on all metrics).
        meter_provider: Optional MeterProvider override for testing.
    """

    def __init__(self, agent_name: str, meter_provider: MeterProvider | None = None) -> None:
        self._agent_name = agent_name
        self._attributes = {"AgentName": agent_name}

        if meter_provider is None:
            meter_provider = _create_meter_provider()
            metrics.set_meter_provider(meter_provider)

        meter = meter_provider.get_meter(METRICS_NAMESPACE)

        # --- Authentication Counters ---
        self._auth_success_counter = meter.create_counter(
            name=MetricNames.AUTH_SUCCESS,
            description="Count of successful authentication events",
            unit="1",
        )
        self._auth_failure_counter = meter.create_counter(
            name=MetricNames.AUTH_FAILURE,
            description="Count of failed authentication events",
            unit="1",
        )
        self._token_refresh_counter = meter.create_counter(
            name=MetricNames.TOKEN_REFRESH,
            description="Count of token refresh operations",
            unit="1",
        )
        self._authz_denial_counter = meter.create_counter(
            name=MetricNames.AUTHZ_DENIAL,
            description="Count of authorization denial events",
            unit="1",
        )

        # --- Latency Histograms (milliseconds) ---
        self._jwt_validation_duration = meter.create_histogram(
            name=MetricNames.JWT_VALIDATION_DURATION,
            description="JWT validation latency in milliseconds",
            unit="ms",
        )
        self._token_retrieval_duration = meter.create_histogram(
            name=MetricNames.TOKEN_RETRIEVAL_DURATION,
            description="OAuth token retrieval latency in milliseconds",
            unit="ms",
        )
        self._token_refresh_duration = meter.create_histogram(
            name=MetricNames.TOKEN_REFRESH_DURATION,
            description="Token refresh latency in milliseconds",
            unit="ms",
        )
        self._mtls_validation_duration = meter.create_histogram(
            name=MetricNames.MTLS_VALIDATION_DURATION,
            description="mTLS certificate validation latency in milliseconds",
            unit="ms",
        )

        # --- SCA Metrics ---
        self._call_graph_build_duration = meter.create_histogram(
            name=MetricNames.CALL_GRAPH_BUILD_DURATION,
            description="Call graph construction latency in milliseconds",
            unit="ms",
        )
        self._vulnerabilities_analyzed = meter.create_counter(
            name=MetricNames.VULNERABILITIES_ANALYZED,
            description="Count of vulnerabilities analyzed",
            unit="1",
        )
        self._reachable_vulnerabilities = meter.create_counter(
            name=MetricNames.REACHABLE_VULNERABILITIES,
            description="Count of reachable vulnerabilities found",
            unit="1",
        )
        self._sbom_generation_duration = meter.create_histogram(
            name=MetricNames.SBOM_GENERATION_DURATION,
            description="SBOM generation latency in milliseconds",
            unit="ms",
        )

    @property
    def agent_name(self) -> str:
        """The agent name used as the AgentName label."""
        return self._agent_name

    # --- Counter Recording Methods ---

    def record_auth_success(self) -> None:
        """Increment the authentication success counter."""
        self._auth_success_counter.add(1, attributes=self._attributes)

    def record_auth_failure(self) -> None:
        """Increment the authentication failure counter."""
        self._auth_failure_counter.add(1, attributes=self._attributes)

    def record_token_refresh(self) -> None:
        """Increment the token refresh counter."""
        self._token_refresh_counter.add(1, attributes=self._attributes)

    def record_authz_denial(self) -> None:
        """Increment the authorization denial counter."""
        self._authz_denial_counter.add(1, attributes=self._attributes)

    # --- Latency Histogram Recording Methods ---

    def record_jwt_validation_duration(self, duration_ms: float) -> None:
        """Record JWT validation latency in milliseconds."""
        self._jwt_validation_duration.record(duration_ms, attributes=self._attributes)

    def record_token_retrieval_duration(self, duration_ms: float) -> None:
        """Record OAuth token retrieval latency in milliseconds."""
        self._token_retrieval_duration.record(duration_ms, attributes=self._attributes)

    def record_token_refresh_duration(self, duration_ms: float) -> None:
        """Record token refresh latency in milliseconds."""
        self._token_refresh_duration.record(duration_ms, attributes=self._attributes)

    def record_mtls_validation_duration(self, duration_ms: float) -> None:
        """Record mTLS certificate validation latency in milliseconds."""
        self._mtls_validation_duration.record(duration_ms, attributes=self._attributes)

    # --- SCA Metric Recording Methods ---

    def record_call_graph_duration(self, duration_ms: float) -> None:
        """Record call graph construction latency in milliseconds."""
        self._call_graph_build_duration.record(duration_ms, attributes=self._attributes)

    def record_vulnerabilities_analyzed(self, count: int) -> None:
        """Record the number of vulnerabilities analyzed."""
        self._vulnerabilities_analyzed.add(count, attributes=self._attributes)

    def record_reachable_vulnerabilities(self, count: int) -> None:
        """Record the number of reachable vulnerabilities found."""
        self._reachable_vulnerabilities.add(count, attributes=self._attributes)

    def record_sbom_generation_duration(self, duration_ms: float) -> None:
        """Record SBOM generation latency in milliseconds."""
        self._sbom_generation_duration.record(duration_ms, attributes=self._attributes)
