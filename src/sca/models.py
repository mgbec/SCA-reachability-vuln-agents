"""SCA (Software Composition Analysis) data models.

Defines dataclasses for vulnerability findings, exploitability results,
fix recommendations, SBOM components, and dependency nodes used throughout
the reachability-enhanced SCA pipeline.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum


class ReachabilityStatus(str, Enum):
    """Reachability classification for a dependency or vulnerable function."""

    REACHABLE = "reachable"
    UNREACHABLE = "unreachable"
    INDETERMINATE = "indeterminate"


class PriorityTier(str, Enum):
    """Priority tier classification based on exploitability score thresholds."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class DependencyRelationship(str, Enum):
    """Relationship of a dependency to the project."""

    DIRECT = "direct"
    TRANSITIVE = "transitive"


@dataclass(frozen=True)
class DependencyNode:
    """Represents a single dependency in the dependency tree.

    Attributes:
        name: Package name (e.g., "lodash").
        version: Package version string (e.g., "4.17.20").
        purl: Package URL identifier (e.g., "pkg:npm/lodash@4.17.20").
        relationship: Whether the dependency is direct or transitive.
    """

    name: str
    version: str
    purl: str
    relationship: DependencyRelationship


@dataclass
class VulnerabilityFinding:
    """A single vulnerability finding enriched with reachability and exploitability data.

    Attributes:
        finding_id: Unique UUID v4 identifier for this finding.
        repository: Repository identifier (e.g., "owner/repo-name").
        commit_sha: Git commit SHA that was analyzed.
        cve_id: CVE identifier (e.g., "CVE-2021-23337").
        dependency: The vulnerable dependency node.
        cvss_base_score: CVSS v3 base score (0.0 - 10.0).
        reachability_status: Whether the vulnerability is reachable from application code.
        reachability_multiplier: Multiplier applied based on reachability status.
        exploitability_score: Computed score (cvss_base_score * reachability_multiplier).
        priority_tier: Classified priority tier based on exploitability score.
        call_path: Sequence of function calls from entry point to vulnerable function.
        source_database: Vulnerability database source (e.g., "NVD", "OSV", "GHSA").
        analyzed_at: Timestamp when the analysis was performed (ISO 8601).
    """

    finding_id: str
    repository: str
    commit_sha: str
    cve_id: str
    dependency: DependencyNode
    cvss_base_score: float
    reachability_status: ReachabilityStatus
    reachability_multiplier: float
    exploitability_score: float
    priority_tier: PriorityTier
    call_path: list[str] = field(default_factory=list)
    source_database: str = "NVD"
    analyzed_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass
class ExploitabilityResult:
    """Aggregated exploitability analysis result for a repository at a specific commit.

    Attributes:
        repository: Repository identifier (e.g., "owner/repo-name").
        commit_sha: Git commit SHA that was analyzed.
        analyzed_at: Timestamp when the analysis was performed (ISO 8601).
        summary: Summary statistics of the analysis.
        findings: List of individual vulnerability findings.
    """

    repository: str
    commit_sha: str
    analyzed_at: datetime
    summary: ExploitabilitySummary
    findings: list[VulnerabilityFinding] = field(default_factory=list)


@dataclass
class ExploitabilitySummary:
    """Summary statistics for an exploitability analysis run.

    Attributes:
        total_vulnerabilities: Total number of vulnerabilities analyzed.
        reachable: Count of vulnerabilities classified as reachable.
        unreachable: Count of vulnerabilities classified as unreachable.
        indeterminate: Count of vulnerabilities with indeterminate reachability.
        by_tier: Counts of vulnerabilities per priority tier.
    """

    total_vulnerabilities: int
    reachable: int
    unreachable: int
    indeterminate: int
    by_tier: dict[PriorityTier, int] = field(default_factory=dict)


@dataclass
class FixRecommendation:
    """A fix recommendation for a vulnerable dependency.

    Attributes:
        dependency: The vulnerable dependency node.
        recommended_version: The minimum version that resolves the vulnerability.
        is_breaking_change: True if the upgrade involves a major version bump.
        current_major: Current major version number.
        target_major: Recommended major version number.
        resolved_cves: List of CVE IDs resolved by this upgrade.
        fix_available: Whether a fix version exists.
        mitigation_note: Mitigation suggestion when no fix is available, or note about breaking changes.
    """

    dependency: DependencyNode
    recommended_version: str | None
    is_breaking_change: bool
    current_major: int
    target_major: int
    resolved_cves: list[str] = field(default_factory=list)
    fix_available: bool = True
    mitigation_note: str | None = None


@dataclass
class SBOMComponent:
    """A single component entry in the CycloneDX SBOM.

    Attributes:
        type: Component type (e.g., "library").
        bom_ref: BOM reference identifier (typically the purl).
        name: Package name.
        version: Package version string.
        purl: Package URL identifier.
        scope: Component scope (e.g., "required", "optional").
        relationship: Whether the dependency is direct or transitive.
        reachability_status: Reachability classification after analysis (None before enrichment).
        vulnerabilities: List of associated CVE identifiers.
    """

    type: str
    bom_ref: str
    name: str
    version: str
    purl: str
    scope: str
    relationship: DependencyRelationship
    reachability_status: ReachabilityStatus | None = None
    vulnerabilities: list[str] = field(default_factory=list)
