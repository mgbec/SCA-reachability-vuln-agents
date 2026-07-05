"""Property-based tests for sensitive data masking.

**Validates: Requirements 13.1, 13.2, 13.3**

Tests that sensitive fields are masked while non-sensitive fields remain intact,
and that masking is non-destructive (original dict is not modified).
"""

import copy

import pytest
from hypothesis import given, assume
from hypothesis import strategies as st

from src.core.masking import mask_sensitive, MASK_PLACEHOLDER, DEFAULT_SENSITIVE_FIELDS


# --- Strategies ---

# Non-sensitive field names that will NOT collide with DEFAULT_SENSITIVE_FIELDS
_sensitive_lower = {f.lower() for f in DEFAULT_SENSITIVE_FIELDS}

non_sensitive_field_names = st.text(
    min_size=1,
    max_size=20,
    alphabet=st.characters(whitelist_categories=("Ll", "Nd")),
).filter(lambda name: name.lower() not in _sensitive_lower)

sensitive_field_names = st.sampled_from(DEFAULT_SENSITIVE_FIELDS)

# Values that are simple scalars (not dicts, to avoid deep nesting complexity)
scalar_values = st.one_of(
    st.text(min_size=0, max_size=50),
    st.integers(min_value=-1000, max_value=1000),
    st.floats(allow_nan=False, allow_infinity=False),
    st.booleans(),
    st.none(),
)

# Dicts with a mix of sensitive and non-sensitive fields
mixed_dicts = st.fixed_dictionaries({}).flatmap(
    lambda _: st.builds(
        lambda sens_items, nonsens_items: {**dict(sens_items), **dict(nonsens_items)},
        sens_items=st.lists(
            st.tuples(sensitive_field_names, st.text(min_size=1, max_size=30)),
            min_size=1,
            max_size=3,
        ),
        nonsens_items=st.lists(
            st.tuples(non_sensitive_field_names, scalar_values),
            min_size=1,
            max_size=5,
        ),
    )
)


@pytest.mark.property
class TestSensitiveDataMasking:
    """Property 6: Sensitive Data Masking.

    Tests:
    1. For any dict with sensitive fields, after masking, sensitive values contain MASK_PLACEHOLDER
    2. For any dict with non-sensitive fields, after masking, non-sensitive values are unchanged
    3. Masking is non-destructive (original dict is not modified)
    """

    @given(
        data=st.dictionaries(
            keys=sensitive_field_names,
            values=st.text(min_size=1, max_size=50),
            min_size=1,
            max_size=5,
        )
    )
    def test_sensitive_fields_are_masked(self, data: dict):
        """For any dict with sensitive fields, after masking, sensitive values
        contain the MASK_PLACEHOLDER string.

        **Validates: Requirements 13.1, 13.2, 13.3**
        """
        result = mask_sensitive(data)

        for key in data:
            if key.lower() in _sensitive_lower:
                masked_value = result[key]
                assert MASK_PLACEHOLDER in str(masked_value), (
                    f"Expected MASK_PLACEHOLDER in masked value for field '{key}', "
                    f"got: {masked_value!r}"
                )

    @given(
        data=st.dictionaries(
            keys=non_sensitive_field_names,
            values=scalar_values,
            min_size=1,
            max_size=5,
        )
    )
    def test_non_sensitive_fields_unchanged(self, data: dict):
        """For any dict with only non-sensitive fields, after masking, all values
        remain exactly unchanged.

        **Validates: Requirements 13.1, 13.2**
        """
        result = mask_sensitive(data)

        for key, value in data.items():
            assert result[key] == value, (
                f"Non-sensitive field '{key}' was modified: "
                f"expected {value!r}, got {result[key]!r}"
            )

    @given(data=mixed_dicts)
    def test_masking_is_non_destructive(self, data: dict):
        """Masking does not modify the original dict. The input dict must remain
        identical to its state before mask_sensitive was called.

        **Validates: Requirements 13.1**
        """
        original = copy.deepcopy(data)

        _ = mask_sensitive(data)

        assert data == original, (
            "Original dict was modified by mask_sensitive. "
            f"Before: {original!r}, After: {data!r}"
        )
