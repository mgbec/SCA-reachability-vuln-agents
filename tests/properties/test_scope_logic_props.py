"""Property-based tests for scope intersection logic.

**Validates: Requirements 7.2, 7.4, 7.5**

Tests that the scope resolution algorithm correctly computes set intersections,
rejects empty intersections, and grants full maximum scopes when no scopes are
requested.
"""

import pytest
from hypothesis import given, assume
from hypothesis import strategies as st

from src.core.scope_logic import resolve_scopes

from tests.properties import scope_sets


@pytest.mark.property
class TestScopeIntersectionCorrectness:
    """Property 3: Scope Intersection Correctness.

    Tests:
    1. For any non-empty requested and maximum sets, granted_scopes == requested & maximum (if non-empty intersection)
    2. If requested & maximum is empty, is_granted is False
    3. If requested is empty, granted_scopes == maximum
    """

    @given(requested=scope_sets, maximum=scope_sets)
    def test_granted_scopes_equal_set_intersection(self, requested: frozenset, maximum: frozenset):
        """For any non-empty requested and maximum sets with non-empty intersection,
        granted_scopes equals the set intersection of requested and maximum.

        **Validates: Requirements 7.2**
        """
        # Only test cases where intersection is non-empty
        intersection = requested & maximum
        assume(len(intersection) > 0)

        result = resolve_scopes(set(requested), set(maximum))

        assert result.is_granted is True
        assert result.granted_scopes == set(intersection)
        assert result.error_message is None

    @given(requested=scope_sets, maximum=scope_sets)
    def test_empty_intersection_rejected(self, requested: frozenset, maximum: frozenset):
        """If the intersection of requested and maximum scopes is empty,
        is_granted must be False and an error message is provided.

        **Validates: Requirements 7.4**
        """
        # Only test cases where intersection is empty
        assume(len(requested & maximum) == 0)

        result = resolve_scopes(set(requested), set(maximum))

        assert result.is_granted is False
        assert result.granted_scopes == set()
        assert result.error_message is not None

    @given(maximum=scope_sets)
    def test_empty_request_grants_all_max_scopes(self, maximum: frozenset):
        """If requested is empty, granted_scopes equals the full set of maximum scopes.

        **Validates: Requirements 7.5**
        """
        result = resolve_scopes(set(), set(maximum))

        assert result.is_granted is True
        assert result.granted_scopes == set(maximum)
        assert result.error_message is None
