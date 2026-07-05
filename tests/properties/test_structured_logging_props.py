"""Property-based tests for structured log event completeness.

**Validates: Requirements 12.5**

Tests that every auth event log serialized to JSON contains all required fields:
correlation_id, agent_identity, event_type, timestamp, trace_id, span_id, outcome.
All fields must be present and non-empty in the serialized output.
"""

import json

import pytest
from hypothesis import given
from hypothesis import strategies as st

from src.core.structured_logging import (
    AuthEvent,
    _serialize_auth_event,
    VALID_EVENT_TYPES,
    VALID_OUTCOMES,
)
from tests.properties import agent_arns, correlation_ids, timestamps


# --- Strategies for structured logging tests ---

# Trace IDs are 32-character hex strings (128-bit, as per OpenTelemetry spec).
trace_ids = st.from_regex(r"[0-9a-f]{32}", fullmatch=True)

# Span IDs are 16-character hex strings (64-bit, as per OpenTelemetry spec).
span_ids = st.from_regex(r"[0-9a-f]{16}", fullmatch=True)

# Event types sampled from the valid set.
event_types = st.sampled_from(sorted(VALID_EVENT_TYPES))

# Outcomes sampled from the valid set.
outcomes = st.sampled_from(sorted(VALID_OUTCOMES))

# Required fields that must be present and non-empty in every serialized log event.
REQUIRED_FIELDS = [
    "correlation_id",
    "agent_identity",
    "event_type",
    "timestamp",
    "trace_id",
    "span_id",
    "outcome",
]


@pytest.mark.property
class TestStructuredLogEventCompleteness:
    """Property 9: Structured Log Event Completeness.

    For any valid AuthEvent with random fields, the serialized JSON
    contains all required fields and each field is non-empty.
    """

    @given(
        correlation_id=correlation_ids,
        agent_identity=agent_arns(),
        event_type=event_types,
        timestamp=timestamps(),
        trace_id=trace_ids,
        span_id=span_ids,
        outcome=outcomes,
    )
    def test_serialized_event_contains_all_required_fields(
        self,
        correlation_id: str,
        agent_identity: str,
        event_type: str,
        timestamp,
        trace_id: str,
        span_id: str,
        outcome: str,
    ):
        """For any valid AuthEvent, the serialized JSON contains all 7 required
        fields and each field has a non-empty value.

        **Validates: Requirements 12.5**
        """
        event = AuthEvent(
            correlation_id=correlation_id,
            agent_identity=agent_identity,
            event_type=event_type,
            timestamp=timestamp,
            trace_id=trace_id,
            span_id=span_id,
            outcome=outcome,
        )

        serialized = _serialize_auth_event(event)
        parsed = json.loads(serialized)

        # All required fields must be present.
        for field_name in REQUIRED_FIELDS:
            assert field_name in parsed, (
                f"Required field '{field_name}' missing from serialized event"
            )

        # All required fields must be non-empty.
        for field_name in REQUIRED_FIELDS:
            value = parsed[field_name]
            assert value is not None and value != "", (
                f"Required field '{field_name}' is empty or None in serialized event"
            )

    @given(
        correlation_id=correlation_ids,
        agent_identity=agent_arns(),
        event_type=event_types,
        timestamp=timestamps(),
        trace_id=trace_ids,
        span_id=span_ids,
        outcome=outcomes,
    )
    def test_serialized_event_fields_match_input(
        self,
        correlation_id: str,
        agent_identity: str,
        event_type: str,
        timestamp,
        trace_id: str,
        span_id: str,
        outcome: str,
    ):
        """For any valid AuthEvent, the serialized JSON field values match the
        original input values exactly (round-trip fidelity).

        **Validates: Requirements 12.5**
        """
        event = AuthEvent(
            correlation_id=correlation_id,
            agent_identity=agent_identity,
            event_type=event_type,
            timestamp=timestamp,
            trace_id=trace_id,
            span_id=span_id,
            outcome=outcome,
        )

        serialized = _serialize_auth_event(event)
        parsed = json.loads(serialized)

        assert parsed["correlation_id"] == correlation_id
        assert parsed["agent_identity"] == agent_identity
        assert parsed["event_type"] == event_type
        assert parsed["timestamp"] == timestamp.isoformat()
        assert parsed["trace_id"] == trace_id
        assert parsed["span_id"] == span_id
        assert parsed["outcome"] == outcome
