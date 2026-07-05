"""Exploitability scoring algorithm for reachability-enhanced SCA.

Computes exploitability scores by combining CVSS base scores with reachability
multipliers, classifies findings into priority tiers, and sorts findings by
exploitability score in descending order.

Requirements: 18.1, 18.2, 18.3, 18.5
"""

from __future__ import annotations

from src.core.constants import (
    PRIORITY_TIER_CRITICAL_THRESHOLD,
    PRIORITY_TIER_HIGH_THRESHOLD,
    PRIORITY_TIER_MEDIUM_THRESHOLD,
    REACHABILITY_MULTIPLIERS,
)
from src.sca.models import PriorityTier, ReachabilityStatus, VulnerabilityFinding


def compute_exploitability_score(cvss_base: float, reachability_status: str) -> float:
    """Compute the exploitability score for a vulnerability finding.

    Formula: exploitability_score = cvss_base * reachability_multiplier

    Args:
        cvss_base: CVSS v3 base score (0.0 - 10.0).
        reachability_status: One of "reachable", "unreachable", or "indeterminate".

    Returns:
        The computed exploitability score.

    Raises:
        ValueError: If reachability_status is not a valid status.
        ValueError: If cvss_base is negative.
    """
    if cvss_base < 0.0:
        raise ValueError(f"CVSS base score must be non-negative, got {cvss_base}")

    # Normalize the status string to handle enum values
    status_key = reachability_status.lower().strip()

    # Accept both raw string and ReachabilityStatus enum value
    if status_key not in REACHABILITY_MULTIPLIERS:
        valid_statuses = ", ".join(sorted(REACHABILITY_MULTIPLIERS.keys()))
        raise ValueError(
            f"Invalid reachability status '{reachability_status}'. "
            f"Must be one of: {valid_statuses}"
        )

    multiplier = REACHABILITY_MULTIPLIERS[status_key]
    return cvss_base * multiplier


def classify_priority_tier(score: float) -> str:
    """Classify an exploitability score into a priority tier.

    Tier boundaries:
        - Critical: score >= 9.0
        - High: 7.0 <= score < 9.0
        - Medium: 4.0 <= score < 7.0
        - Low: score < 4.0

    Args:
        score: The exploitability score to classify.

    Returns:
        The priority tier as a string value from PriorityTier enum
        (e.g., "critical", "high", "medium", "low").
    """
    if score >= PRIORITY_TIER_CRITICAL_THRESHOLD:
        return PriorityTier.CRITICAL.value
    elif score >= PRIORITY_TIER_HIGH_THRESHOLD:
        return PriorityTier.HIGH.value
    elif score >= PRIORITY_TIER_MEDIUM_THRESHOLD:
        return PriorityTier.MEDIUM.value
    else:
        return PriorityTier.LOW.value


def sort_findings_by_score(findings: list[VulnerabilityFinding]) -> list[VulnerabilityFinding]:
    """Sort vulnerability findings by exploitability score in descending order.

    Args:
        findings: List of vulnerability findings to sort.

    Returns:
        A new list sorted by exploitability_score in descending order.
        Findings with equal scores maintain their relative order (stable sort).
    """
    return sorted(findings, key=lambda f: f.exploitability_score, reverse=True)
