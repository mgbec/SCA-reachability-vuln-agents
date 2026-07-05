"""Unit tests for scope intersection logic.

Tests the resolve_scopes function covering:
- Empty requested scopes → grants full maximum (Requirement 7.5)
- Normal intersection (Requirement 7.2)
- Empty intersection → rejection (Requirement 7.4)
- Edge cases
"""

import pytest

from src.core.scope_logic import GrantResult, resolve_scopes


class TestResolveScopesEmptyRequested:
    """Tests for Requirement 7.5: empty request grants all maximum scopes."""

    def test_empty_requested_grants_full_maximum(self):
        maximum = {"read", "write", "admin"}
        result = resolve_scopes(requested=set(), maximum=maximum)

        assert result.is_granted is True
        assert result.granted_scopes == maximum
        assert result.error_message is None

    def test_empty_requested_with_single_max_scope(self):
        maximum = {"repo"}
        result = resolve_scopes(requested=set(), maximum=maximum)

        assert result.is_granted is True
        assert result.granted_scopes == {"repo"}
        assert result.error_message is None


class TestResolveScopesIntersection:
    """Tests for Requirement 7.2: token scopes are intersection of requested and max."""

    def test_full_overlap(self):
        requested = {"read", "write"}
        maximum = {"read", "write", "admin"}
        result = resolve_scopes(requested=requested, maximum=maximum)

        assert result.is_granted is True
        assert result.granted_scopes == {"read", "write"}
        assert result.error_message is None

    def test_partial_overlap(self):
        requested = {"read", "delete"}
        maximum = {"read", "write"}
        result = resolve_scopes(requested=requested, maximum=maximum)

        assert result.is_granted is True
        assert result.granted_scopes == {"read"}
        assert result.error_message is None

    def test_exact_match(self):
        scopes = {"security_events", "repo"}
        result = resolve_scopes(requested=scopes, maximum=scopes)

        assert result.is_granted is True
        assert result.granted_scopes == scopes
        assert result.error_message is None


class TestResolveScopesRejection:
    """Tests for Requirement 7.4: empty intersection results in rejection."""

    def test_no_overlap_rejected(self):
        requested = {"admin", "delete"}
        maximum = {"read", "write"}
        result = resolve_scopes(requested=requested, maximum=maximum)

        assert result.is_granted is False
        assert result.granted_scopes == set()
        assert result.error_message is not None
        assert "No valid scopes could be granted" in result.error_message

    def test_single_scope_no_overlap(self):
        requested = {"admin"}
        maximum = {"read"}
        result = resolve_scopes(requested=requested, maximum=maximum)

        assert result.is_granted is False
        assert result.granted_scopes == set()
        assert result.error_message is not None


class TestGrantResultDataclass:
    """Tests that GrantResult is properly structured."""

    def test_grant_result_fields(self):
        result = GrantResult(
            granted_scopes={"read"},
            is_granted=True,
            error_message=None,
        )
        assert result.granted_scopes == {"read"}
        assert result.is_granted is True
        assert result.error_message is None

    def test_grant_result_immutable(self):
        result = GrantResult(
            granted_scopes={"read"},
            is_granted=True,
            error_message=None,
        )
        # frozen=True means we cannot reassign attributes
        with pytest.raises(AttributeError):
            result.is_granted = False
