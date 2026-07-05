"""Sanity tests to verify Hypothesis strategies generate valid data."""

import pytest
from hypothesis import given, settings

from tests.properties import (
    agent_arns,
    cvss_scores,
    dependency_trees,
    reachability_statuses,
    scope_sets,
    semver_versions,
    timestamps,
    user_claims,
)


@pytest.mark.property
@given(arn=agent_arns())
def test_agent_arn_format(arn):
    """Agent ARNs follow the expected pattern."""
    assert arn.startswith("arn:aws:bedrock-agentcore:")
    assert "workload-identity/directory/default/workload-identity/" in arn


@pytest.mark.property
@given(score=cvss_scores)
def test_cvss_score_range(score):
    """CVSS scores are within the valid 0.0 to 10.0 range."""
    assert 0.0 <= score <= 10.0


@pytest.mark.property
@given(version=semver_versions())
def test_semver_format(version):
    """Semver versions have exactly three numeric parts separated by dots."""
    parts = version.split(".")
    assert len(parts) == 3
    assert all(part.isdigit() for part in parts)


@pytest.mark.property
@given(claims=user_claims())
def test_user_claims_structure(claims):
    """User claims contain all required fields with valid types."""
    assert "subject" in claims
    assert "issuer" in claims
    assert "audience" in claims
    assert "scopes" in claims
    assert "issued_at" in claims
    assert "expires_at" in claims
    assert claims["expires_at"] > claims["issued_at"]
    assert claims["issuer"].startswith("https://cognito-idp.")


@pytest.mark.property
@given(tree=dependency_trees(min_size=1, max_size=5))
def test_dependency_tree_structure(tree):
    """Dependency trees contain nodes with required fields."""
    assert len(tree) >= 1
    for node in tree:
        assert "name" in node
        assert "version" in node
        assert "purl" in node
        assert "relationship" in node
        assert node["relationship"] in ("direct", "transitive")


@pytest.mark.property
@given(scopes=scope_sets)
def test_scope_sets_non_empty(scopes):
    """Scope sets are always non-empty."""
    assert len(scopes) >= 1


@pytest.mark.property
@given(ts=timestamps())
def test_timestamps_have_timezone(ts):
    """Timestamps are always timezone-aware (UTC)."""
    assert ts.tzinfo is not None


@pytest.mark.property
@given(status=reachability_statuses)
def test_reachability_status_valid(status):
    """Reachability statuses are one of the three valid values."""
    assert status in ("reachable", "unreachable", "indeterminate")
