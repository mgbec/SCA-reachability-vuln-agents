"""Unit tests for fix recommendation logic.

Tests the generate_fix_recommendations function, parse_semver helper,
and VulnerabilityDatabase protocol covering:
- Querying vulnerability DB for fix versions (Requirement 19.1)
- Breaking change detection via semver major bump (Requirement 19.2, 19.3)
- No fix available with mitigation suggestions (Requirement 19.4)
- Grouping recommendations by dependency (Requirement 19.5)
"""

import uuid
from datetime import UTC, datetime

import pytest

from src.sca.fix_recommendations import (
    DefaultVulnerabilityDatabase,
    SemVer,
    VulnerabilityDatabase,
    generate_fix_recommendations,
    parse_semver,
)
from src.sca.models import (
    DependencyNode,
    DependencyRelationship,
    FixRecommendation,
    PriorityTier,
    ReachabilityStatus,
    VulnerabilityFinding,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_finding(
    dep_name: str = "lodash",
    dep_version: str = "4.17.20",
    cve_id: str = "CVE-2021-23337",
) -> VulnerabilityFinding:
    """Create a VulnerabilityFinding with minimal required fields."""
    return VulnerabilityFinding(
        finding_id=str(uuid.uuid4()),
        repository="owner/repo",
        commit_sha="abc123",
        cve_id=cve_id,
        dependency=DependencyNode(
            name=dep_name,
            version=dep_version,
            purl=f"pkg:npm/{dep_name}@{dep_version}",
            relationship=DependencyRelationship.DIRECT,
        ),
        cvss_base_score=7.2,
        reachability_status=ReachabilityStatus.REACHABLE,
        reachability_multiplier=1.0,
        exploitability_score=7.2,
        priority_tier=PriorityTier.HIGH,
    )


class MockVulnDB:
    """A mock vulnerability database returning configured fix versions."""

    def __init__(self, fix_map: dict[str, str | None]):
        self.fix_map = fix_map

    def get_fix_version(self, cve_id: str) -> str | None:
        return self.fix_map.get(cve_id)


# ---------------------------------------------------------------------------
# Tests: parse_semver
# ---------------------------------------------------------------------------


class TestParseSemver:
    """Tests for the parse_semver helper function."""

    def test_standard_version(self):
        result = parse_semver("4.17.21")
        assert result == SemVer(major=4, minor=17, patch=21)

    def test_leading_v(self):
        result = parse_semver("v1.2.3")
        assert result == SemVer(major=1, minor=2, patch=3)

    def test_two_parts(self):
        result = parse_semver("1.2")
        assert result == SemVer(major=1, minor=2, patch=0)

    def test_one_part(self):
        result = parse_semver("5")
        assert result == SemVer(major=5, minor=0, patch=0)

    def test_prerelease_stripped(self):
        result = parse_semver("2.0.0-beta.1")
        assert result == SemVer(major=2, minor=0, patch=0)

    def test_build_metadata_stripped(self):
        result = parse_semver("1.0.0+build123")
        assert result == SemVer(major=1, minor=0, patch=0)

    def test_zero_version(self):
        result = parse_semver("0.2.1")
        assert result == SemVer(major=0, minor=2, patch=1)

    def test_empty_string_raises(self):
        with pytest.raises(ValueError, match="Cannot parse version"):
            parse_semver("")

    def test_whitespace_only_raises(self):
        with pytest.raises(ValueError, match="Cannot parse version"):
            parse_semver("   ")

    def test_non_numeric_raises(self):
        with pytest.raises(ValueError, match="Cannot parse version"):
            parse_semver("abc.def.ghi")


# ---------------------------------------------------------------------------
# Tests: DefaultVulnerabilityDatabase
# ---------------------------------------------------------------------------


class TestDefaultVulnerabilityDatabase:
    """Tests for the stub vulnerability database."""

    def test_always_returns_none(self):
        db = DefaultVulnerabilityDatabase()
        assert db.get_fix_version("CVE-2021-23337") is None
        assert db.get_fix_version("CVE-XXXX-XXXXX") is None


# ---------------------------------------------------------------------------
# Tests: generate_fix_recommendations
# ---------------------------------------------------------------------------


class TestGenerateFixRecommendations:
    """Tests for the main recommendation generation function."""

    def test_safe_upgrade_same_major(self):
        """Requirement 19.1, 19.2: Same major → safe upgrade."""
        findings = [_make_finding("lodash", "4.17.20", "CVE-2021-23337")]
        db = MockVulnDB({"CVE-2021-23337": "4.17.21"})

        recs = generate_fix_recommendations(findings, vuln_db=db)

        assert len(recs) == 1
        rec = recs[0]
        assert rec.dependency.name == "lodash"
        assert rec.recommended_version == "4.17.21"
        assert rec.is_breaking_change is False
        assert rec.current_major == 4
        assert rec.target_major == 4
        assert rec.fix_available is True
        assert "CVE-2021-23337" in rec.resolved_cves
        assert rec.mitigation_note is None

    def test_breaking_change_major_bump(self):
        """Requirement 19.2, 19.3: Major bump → breaking change risk."""
        findings = [_make_finding("minimist", "0.2.1", "CVE-2021-44906")]
        db = MockVulnDB({"CVE-2021-44906": "1.2.8"})

        recs = generate_fix_recommendations(findings, vuln_db=db)

        assert len(recs) == 1
        rec = recs[0]
        assert rec.dependency.name == "minimist"
        assert rec.recommended_version == "1.2.8"
        assert rec.is_breaking_change is True
        assert rec.current_major == 0
        assert rec.target_major == 1
        assert rec.fix_available is True
        assert "breaking change" in rec.mitigation_note.lower()

    def test_no_fix_available(self):
        """Requirement 19.4: No fix → mitigation suggestion."""
        findings = [_make_finding("broken-lib", "1.0.0", "CVE-2023-99999")]
        db = MockVulnDB({"CVE-2023-99999": None})

        recs = generate_fix_recommendations(findings, vuln_db=db)

        assert len(recs) == 1
        rec = recs[0]
        assert rec.dependency.name == "broken-lib"
        assert rec.recommended_version is None
        assert rec.is_breaking_change is False
        assert rec.fix_available is False
        assert rec.mitigation_note is not None
        assert "no fix available" in rec.mitigation_note.lower()

    def test_default_db_no_fix_available(self):
        """Using default DB (returns None), all become 'no fix available'."""
        findings = [_make_finding("some-pkg", "2.0.0", "CVE-2024-00001")]

        recs = generate_fix_recommendations(findings)

        assert len(recs) == 1
        assert recs[0].fix_available is False
        assert recs[0].recommended_version is None

    def test_grouping_multiple_cves_same_dependency(self):
        """Requirement 19.5: Group by dependency, single recommendation."""
        findings = [
            _make_finding("lodash", "4.17.20", "CVE-2021-23337"),
            _make_finding("lodash", "4.17.20", "CVE-2020-28500"),
        ]
        db = MockVulnDB({
            "CVE-2021-23337": "4.17.21",
            "CVE-2020-28500": "4.17.21",
        })

        recs = generate_fix_recommendations(findings, vuln_db=db)

        assert len(recs) == 1
        rec = recs[0]
        assert rec.dependency.name == "lodash"
        assert set(rec.resolved_cves) == {"CVE-2021-23337", "CVE-2020-28500"}
        assert rec.recommended_version == "4.17.21"

    def test_grouping_selects_highest_fix_version(self):
        """When multiple CVEs have different fix versions, select the highest."""
        findings = [
            _make_finding("express", "3.0.0", "CVE-A"),
            _make_finding("express", "3.0.0", "CVE-B"),
        ]
        db = MockVulnDB({
            "CVE-A": "3.1.0",
            "CVE-B": "3.2.5",
        })

        recs = generate_fix_recommendations(findings, vuln_db=db)

        assert len(recs) == 1
        assert recs[0].recommended_version == "3.2.5"

    def test_multiple_dependencies_separate_recommendations(self):
        """Each unique dependency gets its own recommendation."""
        findings = [
            _make_finding("lodash", "4.17.20", "CVE-2021-23337"),
            _make_finding("minimist", "0.2.1", "CVE-2021-44906"),
        ]
        db = MockVulnDB({
            "CVE-2021-23337": "4.17.21",
            "CVE-2021-44906": "1.2.8",
        })

        recs = generate_fix_recommendations(findings, vuln_db=db)

        assert len(recs) == 2
        rec_names = {r.dependency.name for r in recs}
        assert rec_names == {"lodash", "minimist"}

    def test_partial_fix_available(self):
        """Some CVEs have fixes, some don't — still recommends available fix."""
        findings = [
            _make_finding("mixed-lib", "1.0.0", "CVE-HAS-FIX"),
            _make_finding("mixed-lib", "1.0.0", "CVE-NO-FIX"),
        ]
        db = MockVulnDB({
            "CVE-HAS-FIX": "1.1.0",
            "CVE-NO-FIX": None,
        })

        recs = generate_fix_recommendations(findings, vuln_db=db)

        assert len(recs) == 1
        rec = recs[0]
        # Since at least one fix is available, fix_available should be True
        assert rec.fix_available is True
        assert rec.recommended_version == "1.1.0"
        assert set(rec.resolved_cves) == {"CVE-HAS-FIX", "CVE-NO-FIX"}

    def test_empty_findings_returns_empty(self):
        """No findings → no recommendations."""
        recs = generate_fix_recommendations([])
        assert recs == []

    def test_duplicate_cve_ids_deduplicated(self):
        """Same CVE appearing multiple times for same dep is deduplicated."""
        findings = [
            _make_finding("lodash", "4.17.20", "CVE-2021-23337"),
            _make_finding("lodash", "4.17.20", "CVE-2021-23337"),
        ]
        db = MockVulnDB({"CVE-2021-23337": "4.17.21"})

        recs = generate_fix_recommendations(findings, vuln_db=db)

        assert len(recs) == 1
        # CVE should appear only once in resolved_cves
        assert recs[0].resolved_cves.count("CVE-2021-23337") == 1
