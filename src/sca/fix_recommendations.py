"""Fix recommendation logic for reachability-enhanced SCA.

Generates fix recommendations for vulnerable dependencies by querying a
vulnerability database for fixed-in versions, comparing semver to detect
breaking changes, grouping by dependency, and handling the "no fix available"
case with mitigation suggestions.

Requirements: 19.1, 19.2, 19.3, 19.4, 19.5
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from src.sca.models import (
    DependencyNode,
    FixRecommendation,
    VulnerabilityFinding,
)


# ---------------------------------------------------------------------------
# Semver helpers
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SemVer:
    """Parsed semantic version (major.minor.patch)."""

    major: int
    minor: int
    patch: int


def parse_semver(version: str) -> SemVer:
    """Parse a version string into a SemVer dataclass.

    Handles versions with or without a leading 'v', and versions with
    fewer than three numeric components (missing parts default to 0).

    Args:
        version: A version string such as "4.17.21" or "v1.2".

    Returns:
        SemVer with major, minor, patch extracted.

    Raises:
        ValueError: If the version string cannot be parsed at all.
    """
    v = version.strip().lstrip("v")
    parts = v.split(".")
    if not parts or not parts[0]:
        raise ValueError(f"Cannot parse version: {version!r}")

    try:
        major = int(parts[0])
        minor = int(parts[1]) if len(parts) > 1 else 0
        patch = int(parts[2].split("-")[0].split("+")[0]) if len(parts) > 2 else 0
    except (ValueError, IndexError) as exc:
        raise ValueError(f"Cannot parse version: {version!r}") from exc

    return SemVer(major=major, minor=minor, patch=patch)


# ---------------------------------------------------------------------------
# Vulnerability Database protocol
# ---------------------------------------------------------------------------


class VulnerabilityDatabase(Protocol):
    """Protocol for querying a vulnerability database for fix versions.

    Implementations may connect to NVD, OSV, GitHub Advisory DB, or
    provide simulated data for testing.
    """

    def get_fix_version(self, cve_id: str) -> str | None:
        """Look up the fixed-in version for a given CVE.

        Args:
            cve_id: The CVE identifier (e.g., "CVE-2021-23337").

        Returns:
            The minimum version that resolves the vulnerability, or None
            if no fix is currently available.
        """
        ...  # pragma: no cover


# ---------------------------------------------------------------------------
# Default (stub) vulnerability database
# ---------------------------------------------------------------------------


class DefaultVulnerabilityDatabase:
    """A default vulnerability database that always returns None.

    Used as a fallback when no real database connection is configured,
    simulating the "no fix available" scenario.
    """

    def get_fix_version(self, cve_id: str) -> str | None:  # noqa: ARG002
        """Always returns None (no fix available)."""
        return None


# ---------------------------------------------------------------------------
# Fix recommendation generation
# ---------------------------------------------------------------------------


def generate_fix_recommendations(
    findings: list[VulnerabilityFinding],
    vuln_db: VulnerabilityDatabase | None = None,
) -> list[FixRecommendation]:
    """Generate fix recommendations for a list of vulnerability findings.

    This function:
    1. Groups findings by dependency name.
    2. For each group, queries the vulnerability DB for fix versions.
    3. Selects the highest fix version that resolves all CVEs in the group.
    4. Compares current vs. fix version using semver to determine if it's a
       breaking change (different major version).
    5. Handles "no fix available" with mitigation suggestions.

    Args:
        findings: List of VulnerabilityFinding objects to generate
            recommendations for.
        vuln_db: A VulnerabilityDatabase implementation. Defaults to
            DefaultVulnerabilityDatabase (returns None for all lookups).

    Returns:
        A list of FixRecommendation objects, one per unique dependency,
        each aggregating all CVEs resolved by the recommended upgrade.
    """
    if vuln_db is None:
        vuln_db = DefaultVulnerabilityDatabase()

    # Group findings by dependency name
    dependency_groups: dict[str, list[VulnerabilityFinding]] = {}
    for finding in findings:
        dep_name = finding.dependency.name
        if dep_name not in dependency_groups:
            dependency_groups[dep_name] = []
        dependency_groups[dep_name].append(finding)

    recommendations: list[FixRecommendation] = []

    for dep_name, group_findings in dependency_groups.items():
        # Use the first finding's dependency as the representative node
        representative_dep = group_findings[0].dependency

        # Collect all unique CVE IDs for this dependency
        cve_ids = list(dict.fromkeys(f.cve_id for f in group_findings))

        # Query fix versions for each CVE
        fix_versions: list[str] = []
        for cve_id in cve_ids:
            fix_version = vuln_db.get_fix_version(cve_id)
            if fix_version is not None:
                fix_versions.append(fix_version)

        if not fix_versions:
            # No fix available for any CVE in this dependency
            recommendation = FixRecommendation(
                dependency=representative_dep,
                recommended_version=None,
                is_breaking_change=False,
                current_major=_get_major(representative_dep.version),
                target_major=_get_major(representative_dep.version),
                resolved_cves=cve_ids,
                fix_available=False,
                mitigation_note=(
                    f"No fix available for {dep_name}. "
                    f"Consider replacing dependency with an alternative package, "
                    f"or apply network-level mitigations to limit exposure."
                ),
            )
        else:
            # Select the highest fix version to resolve all CVEs
            best_fix = _select_highest_version(fix_versions)

            current_semver = parse_semver(representative_dep.version)
            target_semver = parse_semver(best_fix)

            is_breaking = target_semver.major > current_semver.major

            mitigation_note: str | None = None
            if is_breaking:
                mitigation_note = (
                    f"Major version bump from {current_semver.major}.x to "
                    f"{target_semver.major}.x — review changelog for breaking changes"
                )

            recommendation = FixRecommendation(
                dependency=representative_dep,
                recommended_version=best_fix,
                is_breaking_change=is_breaking,
                current_major=current_semver.major,
                target_major=target_semver.major,
                resolved_cves=cve_ids,
                fix_available=True,
                mitigation_note=mitigation_note,
            )

        recommendations.append(recommendation)

    return recommendations


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _get_major(version: str) -> int:
    """Extract the major version number from a version string."""
    try:
        return parse_semver(version).major
    except ValueError:
        return 0


def _select_highest_version(versions: list[str]) -> str:
    """Select the highest version from a list using semver comparison.

    Args:
        versions: Non-empty list of version strings.

    Returns:
        The version string with the highest semver value.
    """
    best = versions[0]
    best_parsed = parse_semver(best)

    for v in versions[1:]:
        parsed = parse_semver(v)
        if _semver_gt(parsed, best_parsed):
            best = v
            best_parsed = parsed

    return best


def _semver_gt(a: SemVer, b: SemVer) -> bool:
    """Return True if semver a is greater than semver b."""
    return (a.major, a.minor, a.patch) > (b.major, b.minor, b.patch)
