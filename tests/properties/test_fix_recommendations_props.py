"""Property-based tests for fix recommendation logic.

**Validates: Requirements 19.5**

Tests that the fix recommendation generation correctly groups findings by
dependency name, producing exactly one recommendation per unique dependency
with all relevant CVE IDs aggregated in the resolved_cves list.
"""

import uuid
from collections import defaultdict

import pytest
from hypothesis import given, assume, settings
from hypothesis import strategies as st

from src.sca.fix_recommendations import generate_fix_recommendations
from src.sca.models import (
    DependencyNode,
    DependencyRelationship,
    PriorityTier,
    ReachabilityStatus,
    VulnerabilityFinding,
)

from tests.properties import cve_ids, package_names, semver_versions


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------


@st.composite
def findings_with_shared_dependencies(draw):
    """Generate a list of VulnerabilityFindings where multiple CVEs share
    the same dependency name, ensuring repeated dependency names but
    different CVE IDs.

    Returns a tuple of (findings_list, expected_dep_name_to_cve_ids mapping).
    """
    # Generate 1-5 unique dependency names
    num_deps = draw(st.integers(min_value=1, max_value=5))
    dep_names = draw(
        st.lists(
            package_names,
            min_size=num_deps,
            max_size=num_deps,
            unique=True,
        )
    )

    findings = []
    expected_cves_per_dep: dict[str, set[str]] = defaultdict(set)

    for dep_name in dep_names:
        # Each dependency has 1-4 CVEs
        num_cves = draw(st.integers(min_value=1, max_value=4))
        dep_version = draw(semver_versions())
        dep_cves = draw(
            st.lists(
                cve_ids,
                min_size=num_cves,
                max_size=num_cves,
                unique=True,
            )
        )

        for cve_id in dep_cves:
            finding = VulnerabilityFinding(
                finding_id=str(uuid.uuid4()),
                repository="owner/repo",
                commit_sha="abc123def456",
                cve_id=cve_id,
                dependency=DependencyNode(
                    name=dep_name,
                    version=dep_version,
                    purl=f"pkg:npm/{dep_name}@{dep_version}",
                    relationship=DependencyRelationship.DIRECT,
                ),
                cvss_base_score=7.5,
                reachability_status=ReachabilityStatus.REACHABLE,
                reachability_multiplier=1.0,
                exploitability_score=7.5,
                priority_tier=PriorityTier.HIGH,
            )
            findings.append(finding)
            expected_cves_per_dep[dep_name].add(cve_id)

    return findings, expected_cves_per_dep


class MockFixDB:
    """Mock vulnerability database that returns a fixed version for all CVEs."""

    def __init__(self, fix_version: str = "99.0.0"):
        self.fix_version = fix_version

    def get_fix_version(self, cve_id: str) -> str | None:
        return self.fix_version


# ---------------------------------------------------------------------------
# Property Tests
# ---------------------------------------------------------------------------


@pytest.mark.property
class TestFixRecommendationsGroupedByDependency:
    """Property 17: Fix Recommendations Grouped by Dependency.

    For any list of findings where multiple CVEs share the same dependency
    name, the output has exactly one recommendation per unique dependency
    name, and each recommendation's resolved_cves list contains all CVE IDs
    from the input for that dependency.

    **Validates: Requirements 19.5**
    """

    @given(data=findings_with_shared_dependencies())
    def test_one_recommendation_per_unique_dependency(self, data):
        """Output has exactly one recommendation per unique dependency name.

        **Validates: Requirements 19.5**
        """
        findings, expected_cves_per_dep = data
        assume(len(findings) > 0)

        db = MockFixDB(fix_version="99.0.0")
        recommendations = generate_fix_recommendations(findings, vuln_db=db)

        # Number of recommendations must equal number of unique dependencies
        rec_dep_names = [r.dependency.name for r in recommendations]
        assert len(rec_dep_names) == len(expected_cves_per_dep)
        assert set(rec_dep_names) == set(expected_cves_per_dep.keys())

    @given(data=findings_with_shared_dependencies())
    def test_all_cves_in_resolved_cves_list(self, data):
        """Each recommendation's resolved_cves contains all CVE IDs from
        the input for that dependency.

        **Validates: Requirements 19.5**
        """
        findings, expected_cves_per_dep = data
        assume(len(findings) > 0)

        db = MockFixDB(fix_version="99.0.0")
        recommendations = generate_fix_recommendations(findings, vuln_db=db)

        for rec in recommendations:
            dep_name = rec.dependency.name
            expected_cves = expected_cves_per_dep[dep_name]
            # All expected CVEs must be present in resolved_cves
            assert set(rec.resolved_cves) == expected_cves, (
                f"Dependency {dep_name}: expected CVEs {expected_cves}, "
                f"got {set(rec.resolved_cves)}"
            )

    @given(data=findings_with_shared_dependencies())
    def test_no_duplicate_dependency_names_in_output(self, data):
        """No two recommendations should share the same dependency name.

        **Validates: Requirements 19.5**
        """
        findings, _ = data
        assume(len(findings) > 0)

        db = MockFixDB(fix_version="99.0.0")
        recommendations = generate_fix_recommendations(findings, vuln_db=db)

        dep_names = [r.dependency.name for r in recommendations]
        assert len(dep_names) == len(set(dep_names)), (
            f"Duplicate dependency names found in recommendations: {dep_names}"
        )


# ---------------------------------------------------------------------------
# Property 16: Breaking Change Detection
# ---------------------------------------------------------------------------


class MockBreakingChangeDB:
    """A mock vulnerability database that returns a predetermined fix version."""

    def __init__(self, fix_version: str) -> None:
        self._fix_version = fix_version

    def get_fix_version(self, cve_id: str) -> str | None:  # noqa: ARG002
        return self._fix_version


def _make_finding(dep_name: str, dep_version: str, cve_id: str) -> VulnerabilityFinding:
    """Create a minimal VulnerabilityFinding for testing breaking change detection."""
    return VulnerabilityFinding(
        finding_id="test-finding-breaking",
        repository="owner/repo",
        commit_sha="abc123",
        cve_id=cve_id,
        dependency=DependencyNode(
            name=dep_name,
            version=dep_version,
            purl=f"pkg:npm/{dep_name}@{dep_version}",
            relationship=DependencyRelationship.DIRECT,
        ),
        cvss_base_score=7.5,
        reachability_status=ReachabilityStatus.REACHABLE,
        reachability_multiplier=1.0,
        exploitability_score=7.5,
        priority_tier=PriorityTier.HIGH,
    )


@pytest.mark.property
class TestBreakingChangeDetection:
    """Property 16: Breaking Change Detection.

    For any current_version and fix_version, is_breaking_change == True iff
    parse_semver(fix_version).major > parse_semver(current_version).major.

    **Validates: Requirements 19.2, 19.3**
    """

    @given(
        current_version=semver_versions(),
        fix_version=semver_versions(),
        dep_name=package_names,
        cve_id=cve_ids,
    )
    def test_breaking_change_flag_iff_major_version_bump(
        self,
        current_version: str,
        fix_version: str,
        dep_name: str,
        cve_id: str,
    ) -> None:
        """Breaking change risk flag is set iff recommended major > current major.

        **Validates: Requirements 19.2, 19.3**
        """
        from src.sca.fix_recommendations import parse_semver

        # Arrange
        finding = _make_finding(dep_name, current_version, cve_id)
        mock_db = MockBreakingChangeDB(fix_version)

        # Act
        recommendations = generate_fix_recommendations([finding], vuln_db=mock_db)

        # Assert: exactly one recommendation
        assert len(recommendations) == 1
        rec = recommendations[0]

        # The fix is available since the mock always returns a version
        assert rec.fix_available is True
        assert rec.recommended_version == fix_version

        # Core property: is_breaking_change iff fix major > current major
        current_major = parse_semver(current_version).major
        fix_major = parse_semver(fix_version).major
        expected_breaking = fix_major > current_major

        assert rec.is_breaking_change == expected_breaking, (
            f"Expected is_breaking_change={expected_breaking} for "
            f"current={current_version} (major={current_major}), "
            f"fix={fix_version} (major={fix_major}), "
            f"got is_breaking_change={rec.is_breaking_change}"
        )

        # Verify major version fields are reported correctly
        assert rec.current_major == current_major
        assert rec.target_major == fix_major
