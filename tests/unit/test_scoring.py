"""Unit tests for exploitability scoring algorithm.

Tests the compute_exploitability_score, classify_priority_tier, and
sort_findings_by_score functions covering:
- Score computation with all reachability statuses (Requirement 18.1, 18.2)
- Priority tier classification at boundaries (Requirement 18.3)
- Sorting findings by exploitability score (Requirement 18.5)
- Edge cases: CVSS 0.0, invalid reachability status
"""

import uuid
from datetime import UTC, datetime

import pytest

from src.sca.models import (
    DependencyNode,
    DependencyRelationship,
    PriorityTier,
    ReachabilityStatus,
    VulnerabilityFinding,
)
from src.sca.scoring import (
    classify_priority_tier,
    compute_exploitability_score,
    sort_findings_by_score,
)


class TestComputeExploitabilityScore:
    """Tests for Requirement 18.1, 18.2: score = CVSS × reachability multiplier."""

    def test_reachable_multiplier(self):
        score = compute_exploitability_score(9.8, "reachable")
        assert score == pytest.approx(9.8 * 1.0)

    def test_unreachable_multiplier(self):
        score = compute_exploitability_score(9.8, "unreachable")
        assert score == pytest.approx(9.8 * 0.2)

    def test_indeterminate_multiplier(self):
        score = compute_exploitability_score(6.5, "indeterminate")
        assert score == pytest.approx(6.5 * 0.6)

    def test_cvss_zero(self):
        score = compute_exploitability_score(0.0, "reachable")
        assert score == 0.0

    def test_cvss_max_reachable(self):
        score = compute_exploitability_score(10.0, "reachable")
        assert score == pytest.approx(10.0)

    def test_cvss_max_unreachable(self):
        score = compute_exploitability_score(10.0, "unreachable")
        assert score == pytest.approx(2.0)

    def test_accepts_enum_value(self):
        """Should accept the string value of ReachabilityStatus enum."""
        score = compute_exploitability_score(7.0, ReachabilityStatus.REACHABLE.value)
        assert score == pytest.approx(7.0)

    def test_invalid_reachability_status_raises(self):
        with pytest.raises(ValueError, match="Invalid reachability status"):
            compute_exploitability_score(5.0, "unknown")

    def test_empty_reachability_status_raises(self):
        with pytest.raises(ValueError, match="Invalid reachability status"):
            compute_exploitability_score(5.0, "")

    def test_negative_cvss_raises(self):
        with pytest.raises(ValueError, match="non-negative"):
            compute_exploitability_score(-1.0, "reachable")

    def test_case_insensitive_status(self):
        score = compute_exploitability_score(5.0, "REACHABLE")
        assert score == pytest.approx(5.0)


class TestClassifyPriorityTier:
    """Tests for Requirement 18.3: tier classification boundaries."""

    def test_critical_at_threshold(self):
        assert classify_priority_tier(9.0) == PriorityTier.CRITICAL.value

    def test_critical_above_threshold(self):
        assert classify_priority_tier(10.0) == PriorityTier.CRITICAL.value

    def test_high_at_threshold(self):
        assert classify_priority_tier(7.0) == PriorityTier.HIGH.value

    def test_high_just_below_critical(self):
        assert classify_priority_tier(8.9) == PriorityTier.HIGH.value

    def test_medium_at_threshold(self):
        assert classify_priority_tier(4.0) == PriorityTier.MEDIUM.value

    def test_medium_just_below_high(self):
        assert classify_priority_tier(6.9) == PriorityTier.MEDIUM.value

    def test_low_below_medium(self):
        assert classify_priority_tier(3.9) == PriorityTier.LOW.value

    def test_low_at_zero(self):
        assert classify_priority_tier(0.0) == PriorityTier.LOW.value

    def test_design_example_unreachable_98(self):
        """CVE with CVSS 9.8 + unreachable → 1.96 (Low)."""
        score = compute_exploitability_score(9.8, "unreachable")
        tier = classify_priority_tier(score)
        assert tier == PriorityTier.LOW.value

    def test_design_example_reachable_65(self):
        """CVE with CVSS 6.5 + reachable → 6.5 (Medium)."""
        score = compute_exploitability_score(6.5, "reachable")
        tier = classify_priority_tier(score)
        assert tier == PriorityTier.MEDIUM.value


def _make_finding(exploitability_score: float) -> VulnerabilityFinding:
    """Helper to create a VulnerabilityFinding with a specific exploitability score."""
    return VulnerabilityFinding(
        finding_id=str(uuid.uuid4()),
        repository="owner/repo",
        commit_sha="abc123",
        cve_id="CVE-2021-00001",
        dependency=DependencyNode(
            name="test-pkg",
            version="1.0.0",
            purl="pkg:npm/test-pkg@1.0.0",
            relationship=DependencyRelationship.DIRECT,
        ),
        cvss_base_score=exploitability_score,
        reachability_status=ReachabilityStatus.REACHABLE,
        reachability_multiplier=1.0,
        exploitability_score=exploitability_score,
        priority_tier=PriorityTier.HIGH,
    )


class TestSortFindingsByScore:
    """Tests for Requirement 18.5: findings sorted by exploitability score descending."""

    def test_sorts_descending(self):
        findings = [_make_finding(3.0), _make_finding(9.5), _make_finding(6.0)]
        sorted_findings = sort_findings_by_score(findings)

        scores = [f.exploitability_score for f in sorted_findings]
        assert scores == [9.5, 6.0, 3.0]

    def test_empty_list(self):
        assert sort_findings_by_score([]) == []

    def test_single_finding(self):
        findings = [_make_finding(5.0)]
        sorted_findings = sort_findings_by_score(findings)
        assert len(sorted_findings) == 1
        assert sorted_findings[0].exploitability_score == 5.0

    def test_equal_scores_stable(self):
        f1 = _make_finding(7.0)
        f1.cve_id = "CVE-FIRST"
        f2 = _make_finding(7.0)
        f2.cve_id = "CVE-SECOND"

        sorted_findings = sort_findings_by_score([f1, f2])
        assert sorted_findings[0].cve_id == "CVE-FIRST"
        assert sorted_findings[1].cve_id == "CVE-SECOND"

    def test_does_not_mutate_original(self):
        findings = [_make_finding(3.0), _make_finding(9.5)]
        original_order = [f.exploitability_score for f in findings]
        sort_findings_by_score(findings)
        assert [f.exploitability_score for f in findings] == original_order
