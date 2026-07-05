"""Structured logging via OpenTelemetry Logs API for authentication and authorization events.

Emits JSON-structured log records for every authentication attempt, token refresh,
and authorization decision. Each log entry includes correlation_id, agent_identity,
event_type, timestamp (ISO 8601), trace_id, span_id, and outcome.

If the logging service is unavailable, the module retries log writes up to 3 times
within 5 seconds and continues processing without blocking the auth/authz operation.
Falls back to Python standard logging with JSON formatting if OTel logging is unavailable.

Requirements: 10.1, 10.2, 10.3, 10.5, 10.6, 10.8, 12.5
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Optional

from opentelemetry._logs import set_logger_provider, SeverityNumber
from opentelemetry.sdk._logs import LoggerProvider
from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
from opentelemetry.exporter.otlp.proto.grpc._log_exporter import OTLPLogExporter

# Valid event types as defined in the design document.
VALID_EVENT_TYPES = frozenset(
    {
        "INBOUND_AUTH",
        "OUTBOUND_TOKEN",
        "AUTHZ_DECISION",
        "TOKEN_REFRESH",
        "IDENTITY_PROPAGATION",
        "MTLS_VALIDATION",
    }
)

# Valid outcomes for authentication/authorization events.
VALID_OUTCOMES = frozenset({"success", "failure"})

# Retry configuration for log writes.
LOG_RETRY_MAX_ATTEMPTS = 3
LOG_RETRY_MAX_TOTAL_SECONDS = 5.0
LOG_RETRY_BASE_DELAY_MS = 200
LOG_RETRY_MULTIPLIER = 2
LOG_RETRY_MAX_DELAY_MS = 2000

# Module-level fallback logger with JSON formatting.
_fallback_logger = logging.getLogger("agentcore.auth.structured")
_fallback_handler = logging.StreamHandler()
_fallback_handler.setFormatter(logging.Formatter("%(message)s"))
_fallback_logger.addHandler(_fallback_handler)
_fallback_logger.setLevel(logging.INFO)


@dataclass
class AuthEvent:
    """Represents an authentication or authorization event to be logged.

    Attributes:
        correlation_id: UUID v4 correlation ID linking this event to a distributed trace.
        agent_identity: ARN or name of the agent that generated this event.
        event_type: Type of event (one of VALID_EVENT_TYPES).
        timestamp: When the event occurred (ISO 8601).
        trace_id: OpenTelemetry trace ID for correlation with distributed traces.
        span_id: OpenTelemetry span ID for correlation with the specific span.
        outcome: Result of the operation ("success" or "failure").
        details: Optional dictionary with additional context-specific information.
    """

    correlation_id: str
    agent_identity: str
    event_type: str
    timestamp: datetime
    trace_id: str
    span_id: str
    outcome: str
    details: Optional[dict] = field(default_factory=dict)


def _serialize_auth_event(event: AuthEvent) -> str:
    """Serialize an AuthEvent to a JSON string with ISO 8601 timestamp.

    Args:
        event: The AuthEvent to serialize.

    Returns:
        A JSON string representing the event with all required fields.
    """
    data = asdict(event)
    # Ensure timestamp is serialized as ISO 8601 string.
    if isinstance(data["timestamp"], datetime):
        data["timestamp"] = data["timestamp"].isoformat()
    return json.dumps(data, default=str)


class StructuredLogEmitter:
    """Manages OpenTelemetry Logs API emission with retry and fallback.

    Configures an OTel LoggerProvider with OTLP export and provides
    emit_auth_log as the primary interface for writing structured auth logs.

    Args:
        service_name: The service name for log attribution (e.g., "orchestrator-agent").
        endpoint: OTLP gRPC endpoint for the collector (default: localhost:4317).
    """

    def __init__(self, service_name: str, endpoint: str = "localhost:4317") -> None:
        self._service_name = service_name
        self._endpoint = endpoint
        self._logger_provider: Optional[LoggerProvider] = None
        self._otel_logger = None
        self._initialized = False

        self._initialize_otel_logging()

    def _initialize_otel_logging(self) -> None:
        """Attempt to initialize the OpenTelemetry logging pipeline.

        If initialization fails (e.g., collector unreachable), the emitter
        will fall back to Python standard logging on each emit call.
        """
        try:
            exporter = OTLPLogExporter(endpoint=self._endpoint, insecure=True)
            self._logger_provider = LoggerProvider()
            self._logger_provider.add_log_record_processor(
                BatchLogRecordProcessor(exporter)
            )
            set_logger_provider(self._logger_provider)
            self._otel_logger = self._logger_provider.get_logger(self._service_name)
            self._initialized = True
        except Exception:  # noqa: BLE001
            # OTel logging init failed — will use fallback logger.
            self._initialized = False

    def emit_auth_log(self, event: AuthEvent) -> None:
        """Emit a structured authentication log event.

        Attempts to write the log via the OpenTelemetry Logs API. On failure,
        retries up to 3 times with exponential backoff (total within 5 seconds).
        If all retries fail, falls back to Python standard logging and continues
        processing without raising an exception.

        Args:
            event: The AuthEvent to log.
        """
        serialized = _serialize_auth_event(event)

        # Attempt OTel log emission with retry.
        if self._initialized and self._otel_logger is not None:
            success = self._emit_with_retry(event, serialized)
            if success:
                return

        # Fallback: emit via Python standard logging as JSON.
        self._emit_fallback(serialized)

    def _emit_with_retry(self, event: AuthEvent, serialized: str) -> bool:
        """Attempt to emit a log record via OTel with retry logic.

        Retries up to LOG_RETRY_MAX_ATTEMPTS times with exponential backoff,
        bounded by LOG_RETRY_MAX_TOTAL_SECONDS total elapsed time.

        Args:
            event: The AuthEvent being logged.
            serialized: The JSON-serialized event string.

        Returns:
            True if the log was successfully emitted, False otherwise.
        """
        start_time = time.monotonic()

        for attempt in range(LOG_RETRY_MAX_ATTEMPTS):
            try:
                self._emit_otel_log(event, serialized)
                return True
            except Exception:  # noqa: BLE001
                # Check if we've exceeded the time budget.
                elapsed = time.monotonic() - start_time
                if elapsed >= LOG_RETRY_MAX_TOTAL_SECONDS:
                    break

                # Wait before next retry (if not the last attempt).
                if attempt < LOG_RETRY_MAX_ATTEMPTS - 1:
                    delay_ms = min(
                        LOG_RETRY_BASE_DELAY_MS * (LOG_RETRY_MULTIPLIER ** attempt),
                        LOG_RETRY_MAX_DELAY_MS,
                    )
                    delay_seconds = delay_ms / 1000.0

                    # Don't wait longer than remaining time budget.
                    remaining = LOG_RETRY_MAX_TOTAL_SECONDS - elapsed
                    if delay_seconds > remaining:
                        delay_seconds = max(0, remaining)

                    time.sleep(delay_seconds)

        return False

    def _emit_otel_log(self, event: AuthEvent, serialized: str) -> None:
        """Emit a single log record via the OpenTelemetry Logs API.

        Uses the Logger.emit() method with keyword arguments to create
        and emit a log record with the structured event body and attributes.

        Args:
            event: The AuthEvent to log.
            serialized: The JSON-serialized event string (used as body).

        Raises:
            Exception: If the OTel logger fails to emit the record.
        """
        # Determine severity based on outcome.
        severity = (
            SeverityNumber.INFO
            if event.outcome == "success"
            else SeverityNumber.WARN
        )

        # Compute timestamp in nanoseconds for OTel.
        if event.timestamp.tzinfo is None:
            ts_ns = int(event.timestamp.replace(tzinfo=timezone.utc).timestamp() * 1e9)
        else:
            ts_ns = int(event.timestamp.timestamp() * 1e9)

        self._otel_logger.emit(
            timestamp=ts_ns,
            observed_timestamp=int(time.time_ns()),
            severity_number=severity,
            severity_text="INFO" if event.outcome == "success" else "WARN",
            body=serialized,
            attributes={
                "correlation_id": event.correlation_id,
                "agent_identity": event.agent_identity,
                "event_type": event.event_type,
                "trace_id": event.trace_id,
                "span_id": event.span_id,
                "outcome": event.outcome,
            },
        )

    def _emit_fallback(self, serialized: str) -> None:
        """Emit the structured log via Python standard logging as JSON.

        Used when the OTel logging pipeline is unavailable or all retries
        have been exhausted. This ensures log data is not lost entirely.

        Args:
            serialized: The JSON-serialized event string.
        """
        _fallback_logger.info(serialized)

    def shutdown(self) -> None:
        """Flush pending log records and shut down the LoggerProvider.

        Call during application teardown to ensure all logs are exported.
        """
        if self._logger_provider is not None:
            self._logger_provider.shutdown()


# --- Module-level convenience function ---

# Default emitter instance (lazily initialized).
_default_emitter: Optional[StructuredLogEmitter] = None


def get_emitter(service_name: str = "agentcore-auth", endpoint: str = "localhost:4317") -> StructuredLogEmitter:
    """Get or create the default StructuredLogEmitter instance.

    Args:
        service_name: Service name for log attribution.
        endpoint: OTLP gRPC endpoint for the collector.

    Returns:
        The singleton StructuredLogEmitter instance.
    """
    global _default_emitter
    if _default_emitter is None:
        _default_emitter = StructuredLogEmitter(service_name=service_name, endpoint=endpoint)
    return _default_emitter


def emit_auth_log(event: AuthEvent) -> None:
    """Emit a structured authentication log event using the default emitter.

    This is the primary public interface for logging auth events. It uses
    the module-level StructuredLogEmitter, initializing it on first use.

    If the OpenTelemetry logging service is unavailable after retries,
    the function continues without raising — it does not block the
    authentication or authorization operation.

    Args:
        event: The AuthEvent to log. Must contain all required fields:
               correlation_id, agent_identity, event_type, timestamp,
               trace_id, span_id, outcome.
    """
    emitter = get_emitter()
    emitter.emit_auth_log(event)
