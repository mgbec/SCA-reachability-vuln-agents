"""Configuration precedence resolver for the Demo CLI.

Resolves configuration values from multiple sources with a defined
precedence order: CLI arguments take priority over environment variables.
If a key is absent from both sources, it is omitted from the result.

This supports the Demo CLI's requirement to accept agent endpoint URLs
and client configuration values from either command-line arguments or
environment variables.

Requirements: 8.7
"""

from __future__ import annotations


def resolve_config(cli_args: dict, env_vars: dict, keys: list) -> dict:
    """Resolve configuration values with CLI args taking precedence over env vars.

    For each key in the provided keys list:
    - If present and non-None in cli_args, use the cli_args value.
    - If absent or None in cli_args but present and non-None in env_vars,
      use the env_vars value.
    - If absent or None in both, the key is omitted from the result.

    Args:
        cli_args: Dictionary of configuration values from command-line arguments.
        env_vars: Dictionary of configuration values from environment variables.
        keys: List of configuration key names to resolve.

    Returns:
        A flat dictionary containing only the resolved keys that have a value
        in at least one source.
    """
    resolved = {}

    for key in keys:
        cli_value = cli_args.get(key)
        if cli_value is not None:
            resolved[key] = cli_value
            continue

        env_value = env_vars.get(key)
        if env_value is not None:
            resolved[key] = env_value

    return resolved
