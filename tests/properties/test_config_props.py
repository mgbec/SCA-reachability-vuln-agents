"""Property-based tests for configuration precedence resolution.

**Validates: Requirements 8.7**

Tests that the configuration resolver correctly applies precedence rules:
CLI arguments override environment variables, env-only keys use env values,
keys missing from both are absent from the result, and keys not in the
keys list are never included.
"""

import pytest
from hypothesis import given
from hypothesis import strategies as st

from src.core.config import resolve_config


# --- Strategies ---
# Use printable text for config key names and values
config_keys = st.text(min_size=1, max_size=20, alphabet=st.characters(whitelist_categories=("Ll", "Lu", "Nd"), whitelist_characters="_-"))
config_values = st.text(min_size=1, max_size=50, alphabet=st.characters(whitelist_categories=("Ll", "Lu", "Nd", "Zs"), whitelist_characters="/:._-"))

config_dicts = st.dictionaries(keys=config_keys, values=config_values, min_size=0, max_size=10)
key_lists = st.lists(config_keys, min_size=1, max_size=15)


@pytest.mark.property
class TestConfigurationPrecedenceResolution:
    """Property 8: Configuration Precedence Resolution.

    Tests:
    1. For any key present in both cli_args and env_vars, result uses cli_args value
    2. For any key present only in env_vars, result uses env_vars value
    3. For any key absent from both (None), key is absent from result
    4. Keys not in the keys list are never in result
    """

    @given(
        cli_args=config_dicts,
        env_vars=config_dicts,
        keys=key_lists,
    )
    def test_cli_args_override_env_vars(self, cli_args: dict, env_vars: dict, keys: list):
        """For any key present in both cli_args and env_vars, result uses cli_args value.

        **Validates: Requirements 8.7**
        """
        result = resolve_config(cli_args, env_vars, keys)

        for key in keys:
            if key in cli_args and cli_args[key] is not None:
                assert key in result
                assert result[key] == cli_args[key]

    @given(
        cli_args=config_dicts,
        env_vars=config_dicts,
        keys=key_lists,
    )
    def test_env_only_keys_use_env_value(self, cli_args: dict, env_vars: dict, keys: list):
        """For any key present only in env_vars (absent or None in cli_args),
        result uses env_vars value.

        **Validates: Requirements 8.7**
        """
        result = resolve_config(cli_args, env_vars, keys)

        for key in keys:
            cli_value = cli_args.get(key)
            env_value = env_vars.get(key)
            if cli_value is None and env_value is not None:
                assert key in result
                assert result[key] == env_value

    @given(
        cli_args=config_dicts,
        env_vars=config_dicts,
        keys=key_lists,
    )
    def test_missing_from_both_is_absent(self, cli_args: dict, env_vars: dict, keys: list):
        """For any key absent from both cli_args and env_vars (None in both),
        key is absent from result.

        **Validates: Requirements 8.7**
        """
        result = resolve_config(cli_args, env_vars, keys)

        for key in keys:
            cli_value = cli_args.get(key)
            env_value = env_vars.get(key)
            if cli_value is None and env_value is None:
                assert key not in result

    @given(
        cli_args=config_dicts,
        env_vars=config_dicts,
        keys=key_lists,
    )
    def test_keys_not_in_list_never_in_result(self, cli_args: dict, env_vars: dict, keys: list):
        """Keys not in the keys list are never present in the result,
        even if they exist in cli_args or env_vars.

        **Validates: Requirements 8.7**
        """
        result = resolve_config(cli_args, env_vars, keys)

        keys_set = set(keys)
        for result_key in result:
            assert result_key in keys_set
