"""Property-based tests for exploitability scoring and sorting.

Tests that the scoring algorithm correctly computes exploitability scores,
classifies priority tiers, and sorts findings by score in descending order.

**Validates: Requirements 18.1, 18.2, 18.3, 18.5**
"""

import uuid

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from src.core.constants import REACHABILITY_MULTIPLIERS
from src.sca.models import (
    DependencyNode,
    DependencyRelationship,
    PriorityTier,
    ReachabilityStatus,
    VulnerabilityFinding,
)
from src.sca.scoring import compute_exploitability_score, classify_priority_tier, sort_findings_by_score

from tests.properties import cvss_scores, reachability_statuses


# --- Strategies for generating VulnerabilityFinding objects ---

def _make_finding(exploitability_score: float) -> VulnerabilityFinding:
    """Create a VulnerabilityFinding with a given exploitability score."""
    return VulnerabilityFinding(
        finding_id=str(uuid.uuid4()),
        repository="owner/test-repo",
        commit_sha="abc123def456",
        cve_id="CVE-2024-00001",
        dependency=DependencyNode(
            name="test-pkg",
            version="1.0.0",
            purl="pkg:npm/test-pkg@1.0.0",
            relationship=DependencyRelationship.DIRECT,
        ),
        cvss_base_score=5.0,
        reachability_status=ReachabilityStatus.REACHABLE,
        reachability_multiplier=1.0,
        exploitability_score=exploitability_score,
        priority_tier=PriorityTier.MEDIUM,
    )


# Strategy for generating a list of exploitability scores
exploitability_scores = st.floats(
    min_value=0.0, max_value=10.0, allow_nan=False, allow_infinity=False
)


@pytest.mark.property
class TestExploitabilityScoreComputationAndTierClassification:
    """Property 14: Exploitability Score Computation and Tier Classification.

    Tests:
    1. score == cvss_base * REACHABILITY_MULTIPLIERS[status] for all valid inputs
    2. Tier boundaries: score >= 9.0 → critical, 7.0 <= score < 9.0 → high,
       4.0 <= score < 7.0 → medium, score < 4.0 → low

    **Validates: Requirements 18.1, 18.2, 18.3**
    """

    @given(cvss_base=cvss_scores, status=reachability_statuses)
    def test_score_equals_cvss_times_multiplier(self, cvss_base: float, status: str):
        """For all valid CVSS scores and reachability statuses,
        the computed score equals cvss_base * REACHABILITY_MULTIPLIERS[status].

        **Validates: Requirements 18.1, 18.2**
        """
        score = compute_exploitability_score(cvss_base, status)
        expected = cvss_base * REACHABILITY_MULTIPLIERS[status]

        assert score == pytest.approx(expected), (
            f"Expected score {expected} for CVSS={cvss_base}, status={status}, "
            f"but got {score}"
        )

    @given(cvss_base=cvss_scores, status=reachability_statuses)
    def test_tier_classification_boundaries(self, cvss_base: float, status: str):
        """Tier classification matches defined boundaries based on computed score.

        - score >= 9.0 → critical
        - 7.0 <= score < 9.0 → high
        - 4.0 <= score < 7.0 → medium
        - score < 4.0 → low

        **Validates: Requirements 18.3**
        """
        score = compute_exploitability_score(cvss_base, status)
        tier = classify_priority_tier(score)

        if score >= 9.0:
            assert tier == "critical", (
                f"Score {score} should be 'critical', got '{tier}'"
            )
        elif score >= 7.0:
            assert tier == "high", (
                f"Score {score} should be 'high', got '{tier}'"
            )
        elif score >= 4.0:
            assert tier == "medium", (
                f"Score {score} should be 'medium', got '{tier}'"
            )
        else:
            assert tier == "low", (
                f"Score {score} should be 'low', got '{tier}'"
            )


@pytest.mark.property
class TestFindingsSortedByExploitabilityScore:
    """Property 18: Findings Sorted by Exploitability Score.

    Tests that sort_findings_by_score returns findings in strictly
    non-increasing order of exploitability score.

    **Validates: Requirements 18.5**
    """

    @given(scores=st.lists(exploitability_scores, min_size=0, max_size=50))
    def test_output_in_non_increasing_order_of_exploitability_score(
        self, scores: list[float]
    ):
        """For any list of findings with random exploitability scores,
        sort_findings_by_score returns them in non-increasing order.

        **Validates: Requirements 18.5**
        """
        findings = [_make_finding(score) for score in scores]

        sorted_findings = sort_findings_by_score(findings)

        # Verify non-increasing order: each score >= the next score
        for i in range(len(sorted_findings) - 1):
            assert sorted_findings[i].exploitability_score >= sorted_findings[i + 1].exploitability_score, (
                f"Findings not in non-increasing order at index {i}: "
                f"{sorted_findings[i].exploitability_score} < {sorted_findings[i + 1].exploitability_score}"
            )

    @given(scores=st.lists(exploitability_scores, min_size=1, max_size=50))
    def test_sorted_output_contains_all_original_findings(
        self, scores: list[float]
    ):
        """Sorting preserves all findings — no findings are lost or duplicated.

        **Validates: Requirements 18.5**
        """
        findings = [_make_finding(score) for score in scores]

        sorted_findings = sort_findings_by_score(findings)

        assert len(sorted_findings) == len(findings)
        # Verify the same set of scores is present
        original_scores = sorted(scores, reverse=True)
        result_scores = [f.exploitability_score for f in sorted_findings]
        assert result_scores == original_scores

    @given(scores=st.lists(exploitability_scores, min_size=0, max_size=50))
    def test_sorted_output_highest_score_is_first(self, scores: list[float]):
        """The first element in sorted output has the maximum exploitability score.

        **Validates: Requirements 18.5**
        """
        if not scores:
            # Empty list should return empty list
            findings = []
            sorted_findings = sort_findings_by_score(findings)
            assert sorted_findings == []
            return

        findings = [_make_finding(score) for score in scores]

        sorted_findings = sort_findings_by_score(findings)

        max_score = max(scores)
        assert sorted_findings[0].exploitability_score == max_score
