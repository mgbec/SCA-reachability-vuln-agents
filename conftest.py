"""Root conftest.py — shared fixtures and Hypothesis profiles for the test suite."""

import pytest
from hypothesis import settings, HealthCheck


# Hypothesis profiles
# ci: 100 examples for thorough testing in CI pipelines
settings.register_profile(
    "ci",
    max_examples=100,
    suppress_health_check=[HealthCheck.too_slow],
    deadline=None,
)

# dev: 50 examples for faster iteration during local development
settings.register_profile(
    "dev",
    max_examples=50,
    suppress_health_check=[HealthCheck.too_slow],
    deadline=None,
)

# Load the dev profile by default; CI overrides via --hypothesis-profile=ci
settings.load_profile("dev")


@pytest.fixture
def sample_agent_arns():
    """Provides sample agent ARNs for the three platform agents."""
    return {
        "orchestrator": "arn:aws:bedrock-agentcore:us-east-1:123456789012:workload-identity/directory/default/workload-identity/orchestrator-agent",
        "scanner": "arn:aws:bedrock-agentcore:us-east-1:123456789012:workload-identity/directory/default/workload-identity/scanner-agent",
        "analysis": "arn:aws:bedrock-agentcore:us-east-1:123456789012:workload-identity/directory/default/workload-identity/analysis-agent",
    }


@pytest.fixture
def sample_scopes():
    """Provides the set of OAuth scopes used in the platform."""
    return {"security_events", "repo", "openid", "profile"}


@pytest.fixture
def sample_hmac_key():
    """Provides a test HMAC key for identity context signing."""
    return b"test-hmac-key-for-identity-context-signing-256bit"
