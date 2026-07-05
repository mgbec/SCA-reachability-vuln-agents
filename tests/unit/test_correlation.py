"""Unit tests for correlation ID propagation utility.

Tests the extract_or_generate_correlation_id and propagate_correlation_id
functions covering:
- Valid UUID v4 extraction from headers (Requirement 11.2)
- Case-insensitive header lookup (Requirement 11.1)
- UUID v4 generation when header is missing or invalid (Requirement 11.3)
- Propagation to outbound headers (Requirement 11.2)
"""

import uuid

import pytest

from src.core.correlation import (
    CORRELATION_ID_HEADER,
    extract_or_generate_correlation_id,
    propagate_correlation_id,
)


class TestExtractOrGenerateWithValidHeader:
    """Tests for Requirement 11.2: valid inbound correlation IDs are preserved."""

    def test_extracts_valid_uuid_v4_from_standard_header(self):
        correlation_id = str(uuid.uuid4())
        headers = {"X-Correlation-ID": correlation_id}

        result = extract_or_generate_correlation_id(headers)

        assert result == correlation_id

    def test_extracts_valid_uuid_v4_case_insensitive_lowercase(self):
        correlation_id = str(uuid.uuid4())
        headers = {"x-correlation-id": correlation_id}

        result = extract_or_generate_correlation_id(headers)

        assert result == correlation_id

    def test_extracts_valid_uuid_v4_case_insensitive_uppercase(self):
        correlation_id = str(uuid.uuid4())
        headers = {"X-CORRELATION-ID": correlation_id}

        result = extract_or_generate_correlation_id(headers)

        assert result == correlation_id

    def test_extracts_valid_uuid_v4_mixed_case(self):
        correlation_id = str(uuid.uuid4())
        headers = {"x-Correlation-Id": correlation_id}

        result = extract_or_generate_correlation_id(headers)

        assert result == correlation_id


class TestExtractOrGenerateWithMissingHeader:
    """Tests for Requirement 11.3: generates new UUID v4 when header is missing."""

    def test_generates_uuid_v4_when_header_absent(self):
        headers = {"Content-Type": "application/json"}

        result = extract_or_generate_correlation_id(headers)

        # Validate it's a proper UUID v4
        parsed = uuid.UUID(result, version=4)
        assert parsed.version == 4
        assert str(parsed) == result

    def test_generates_uuid_v4_when_headers_empty(self):
        headers = {}

        result = extract_or_generate_correlation_id(headers)

        parsed = uuid.UUID(result, version=4)
        assert parsed.version == 4

    def test_generates_unique_ids_across_calls(self):
        headers = {}

        id1 = extract_or_generate_correlation_id(headers)
        id2 = extract_or_generate_correlation_id(headers)

        assert id1 != id2


class TestExtractOrGenerateWithInvalidHeader:
    """Tests for Requirement 11.3: generates new UUID v4 when header value is invalid."""

    def test_generates_new_id_for_non_uuid_string(self):
        headers = {"X-Correlation-ID": "not-a-uuid"}

        result = extract_or_generate_correlation_id(headers)

        # Should be a new valid UUID v4, not the original value
        assert result != "not-a-uuid"
        parsed = uuid.UUID(result, version=4)
        assert parsed.version == 4

    def test_generates_new_id_for_empty_string(self):
        headers = {"X-Correlation-ID": ""}

        result = extract_or_generate_correlation_id(headers)

        parsed = uuid.UUID(result, version=4)
        assert parsed.version == 4

    def test_generates_new_id_for_uuid_v1(self):
        # UUID v1 is valid UUID but not v4
        uuid_v1 = str(uuid.uuid1())
        headers = {"X-Correlation-ID": uuid_v1}

        result = extract_or_generate_correlation_id(headers)

        # Should generate a new UUID v4 since v1 is not valid v4
        assert result != uuid_v1
        parsed = uuid.UUID(result, version=4)
        assert parsed.version == 4

    def test_generates_new_id_for_partial_uuid(self):
        headers = {"X-Correlation-ID": "550e8400-e29b-41d4"}

        result = extract_or_generate_correlation_id(headers)

        parsed = uuid.UUID(result, version=4)
        assert parsed.version == 4


class TestPropagateCorrelationId:
    """Tests for Requirement 11.2: propagation to outbound headers."""

    def test_adds_header_to_empty_dict(self):
        outbound = {}
        correlation_id = str(uuid.uuid4())

        result = propagate_correlation_id(outbound, correlation_id)

        assert result[CORRELATION_ID_HEADER] == correlation_id
        assert result is outbound  # mutates in place and returns same dict

    def test_adds_header_to_existing_headers(self):
        outbound = {"Content-Type": "application/json", "Accept": "text/plain"}
        correlation_id = str(uuid.uuid4())

        result = propagate_correlation_id(outbound, correlation_id)

        assert result[CORRELATION_ID_HEADER] == correlation_id
        assert result["Content-Type"] == "application/json"
        assert result["Accept"] == "text/plain"

    def test_overwrites_existing_correlation_id(self):
        old_id = str(uuid.uuid4())
        new_id = str(uuid.uuid4())
        outbound = {CORRELATION_ID_HEADER: old_id}

        result = propagate_correlation_id(outbound, new_id)

        assert result[CORRELATION_ID_HEADER] == new_id

    def test_returns_same_dict_reference(self):
        outbound = {"Host": "example.com"}
        correlation_id = str(uuid.uuid4())

        result = propagate_correlation_id(outbound, correlation_id)

        assert result is outbound
