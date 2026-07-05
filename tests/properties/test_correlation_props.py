"""Property-based tests for correlation ID propagation.

**Validates: Requirements 11.2, 11.3**

Tests that valid inbound UUID v4 correlation IDs are preserved unchanged,
missing or invalid IDs result in valid UUID v4 generation, and propagation
always sets the correct header value.
"""

import uuid

import pytest
from hypothesis import given, assume
from hypothesis import strategies as st

from src.core.correlation import (
    extract_or_generate_correlation_id,
    propagate_correlation_id,
    CORRELATION_ID_HEADER,
)


def _is_valid_uuid_v4(value: str) -> bool:
    """Helper to verify a string is a valid UUID v4."""
    try:
        parsed = uuid.UUID(value, version=4)
        return str(parsed) == value.lower().strip() and parsed.version == 4
    except (ValueError, AttributeError):
        return False


@pytest.mark.property
class TestCorrelationIDPropagation:
    """Property 11: Correlation ID Propagation.

    Tests:
    1. For any valid UUID v4 in headers, extract returns that exact UUID
    2. For any headers without valid UUID v4, extract returns a valid UUID v4 (but not the invalid value)
    3. propagate_correlation_id always sets the header to the given correlation_id
    """

    @given(valid_uuid=st.uuids(version=4).map(str))
    def test_valid_uuid_preserved(self, valid_uuid: str):
        """For any valid UUID v4 in headers, extract_or_generate_correlation_id
        returns that exact UUID unchanged.

        **Validates: Requirements 11.2**
        """
        headers = {CORRELATION_ID_HEADER: valid_uuid}

        result = extract_or_generate_correlation_id(headers)

        assert result == valid_uuid

    @given(invalid_value=st.text())
    def test_invalid_uuid_generates_new_valid_uuid(self, invalid_value: str):
        """For any headers without a valid UUID v4, extract_or_generate_correlation_id
        returns a valid UUID v4 that is not equal to the invalid value.

        **Validates: Requirements 11.3**
        """
        # Ensure the generated text is not accidentally a valid UUID v4
        assume(not _is_valid_uuid_v4(invalid_value))

        headers = {CORRELATION_ID_HEADER: invalid_value}

        result = extract_or_generate_correlation_id(headers)

        assert _is_valid_uuid_v4(result)
        assert result != invalid_value

    @given(correlation_id=st.uuids(version=4).map(str))
    def test_propagate_sets_header(self, correlation_id: str):
        """propagate_correlation_id always sets the X-Correlation-ID header
        to the given correlation_id value.

        **Validates: Requirements 11.2**
        """
        outbound_headers: dict = {}

        result = propagate_correlation_id(outbound_headers, correlation_id)

        assert result[CORRELATION_ID_HEADER] == correlation_id

    @given(
        correlation_id=st.uuids(version=4).map(str),
        existing_value=st.text(min_size=1, max_size=50),
    )
    def test_propagate_overwrites_existing_header(self, correlation_id: str, existing_value: str):
        """propagate_correlation_id overwrites any existing correlation ID header value.

        **Validates: Requirements 11.2**
        """
        outbound_headers = {CORRELATION_ID_HEADER: existing_value}

        result = propagate_correlation_id(outbound_headers, correlation_id)

        assert result[CORRELATION_ID_HEADER] == correlation_id

    def test_missing_header_generates_valid_uuid(self):
        """When no correlation ID header is present, a valid UUID v4 is generated.

        **Validates: Requirements 11.3**
        """
        headers: dict = {}

        result = extract_or_generate_correlation_id(headers)

        assert _is_valid_uuid_v4(result)
