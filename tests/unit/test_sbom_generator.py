"""Unit tests for SBOM generation (CycloneDX v1.5 format).

Tests the generate_sbom, enrich_sbom, to_json, store_sbom, and retrieve_sbom
functions covering:
- SBOM generation from dependency trees (Requirement 17.2)
- CycloneDX v1.5 format compliance (Requirement 17.2)
- Component classification (direct/transitive) (Requirement 17.2)
- SBOM enrichment with reachability and CVEs (Requirements 17.3, 17.4)
- JSON serialization (Requirement 17.5)
- Versioned storage keyed by repo + commit SHA (Requirement 17.5)
"""

import json

import pytest

from src.core.constants import SBOM_FORMAT, SBOM_FORMAT_VERSION
from src.sca.models import (
    DependencyNode,
    DependencyRelationship,
    ReachabilityStatus,
)
from src.sca.sbom_generator import (
    CycloneDXBOM,
    clear_store,
    enrich_sbom,
    generate_sbom,
    retrieve_sbom,
    store_sbom,
    to_json,
)


@pytest.fixture(autouse=True)
def _clear_sbom_store():
    """Clear the in-memory SBOM store before each test."""
    clear_store()
    yield
    clear_store()


def _make_dependency(
    name: str = "lodash",
    version: str = "4.17.20",
    relationship: DependencyRelationship = DependencyRelationship.DIRECT,
) -> DependencyNode:
    """Helper to create a DependencyNode."""
    return DependencyNode(
        name=name,
        version=version,
        purl=f"pkg:npm/{name}@{version}",
        relationship=relationship,
    )


class TestGenerateSbom:
    """Tests for generate_sbom: converting dependency tree to CycloneDX BOM."""

    def test_generates_bom_with_correct_format(self):
        deps = [_make_dependency()]
        bom = generate_sbom(deps, "owner/repo", "abc123")

        assert bom.bom_format == SBOM_FORMAT
        assert bom.spec_version == SBOM_FORMAT_VERSION
        assert bom.version == 1

    def test_generates_serial_number_as_uuid(self):
        deps = [_make_dependency()]
        bom = generate_sbom(deps, "owner/repo", "abc123")

        # UUID format: 8-4-4-4-12 hex digits
        import uuid
        uuid.UUID(bom.serial_number)  # Raises ValueError if invalid

    def test_metadata_contains_repo_and_commit(self):
        deps = [_make_dependency()]
        bom = generate_sbom(deps, "owner/repo", "abc123def")

        assert bom.metadata["repository"] == "owner/repo"
        assert bom.metadata["commit_sha"] == "abc123def"
        assert "timestamp" in bom.metadata

    def test_all_dependencies_become_components(self):
        deps = [
            _make_dependency("lodash", "4.17.20"),
            _make_dependency("express", "4.18.2"),
            _make_dependency("debug", "4.3.4", DependencyRelationship.TRANSITIVE),
        ]
        bom = generate_sbom(deps, "owner/repo", "abc123")

        assert len(bom.components) == 3

    def test_component_has_correct_fields(self):
        dep = _make_dependency("lodash", "4.17.20", DependencyRelationship.DIRECT)
        bom = generate_sbom([dep], "owner/repo", "abc123")

        comp = bom.components[0]
        assert comp.type == "library"
        assert comp.bom_ref == "pkg:npm/lodash@4.17.20"
        assert comp.name == "lodash"
        assert comp.version == "4.17.20"
        assert comp.purl == "pkg:npm/lodash@4.17.20"
        assert comp.scope == "required"
        assert comp.relationship == DependencyRelationship.DIRECT

    def test_direct_vs_transitive_classification(self):
        deps = [
            _make_dependency("express", "4.18.2", DependencyRelationship.DIRECT),
            _make_dependency("debug", "4.3.4", DependencyRelationship.TRANSITIVE),
        ]
        bom = generate_sbom(deps, "owner/repo", "abc123")

        assert bom.components[0].relationship == DependencyRelationship.DIRECT
        assert bom.components[1].relationship == DependencyRelationship.TRANSITIVE

    def test_empty_dependency_tree(self):
        bom = generate_sbom([], "owner/repo", "abc123")

        assert bom.components == []
        assert bom.bom_format == SBOM_FORMAT

    def test_components_initially_have_no_reachability(self):
        deps = [_make_dependency()]
        bom = generate_sbom(deps, "owner/repo", "abc123")

        for comp in bom.components:
            assert comp.reachability_status is None

    def test_components_initially_have_no_vulnerabilities(self):
        deps = [_make_dependency()]
        bom = generate_sbom(deps, "owner/repo", "abc123")

        for comp in bom.components:
            assert comp.vulnerabilities == []


class TestEnrichSbom:
    """Tests for enrich_sbom: adding reachability and CVE associations."""

    def test_adds_reachability_status(self):
        deps = [_make_dependency("lodash", "4.17.20")]
        bom = generate_sbom(deps, "owner/repo", "abc123")

        reachability_map = {
            "pkg:npm/lodash@4.17.20": ReachabilityStatus.REACHABLE,
        }
        enriched = enrich_sbom(bom, reachability_map, {})

        assert enriched.components[0].reachability_status == ReachabilityStatus.REACHABLE

    def test_adds_vulnerability_associations(self):
        deps = [_make_dependency("lodash", "4.17.20")]
        bom = generate_sbom(deps, "owner/repo", "abc123")

        vulnerability_map = {
            "pkg:npm/lodash@4.17.20": [
                {"id": "CVE-2021-23337", "ratings": [{"score": 7.2, "severity": "high"}]},
                {"id": "CVE-2020-28500", "ratings": [{"score": 5.3, "severity": "medium"}]},
            ],
        }
        enriched = enrich_sbom(bom, {}, vulnerability_map)

        assert "CVE-2021-23337" in enriched.components[0].vulnerabilities
        assert "CVE-2020-28500" in enriched.components[0].vulnerabilities

    def test_defaults_to_indeterminate_when_not_in_map(self):
        deps = [_make_dependency("unknown-pkg", "1.0.0")]
        bom = generate_sbom(deps, "owner/repo", "abc123")

        enriched = enrich_sbom(bom, {}, {})

        assert enriched.components[0].reachability_status == ReachabilityStatus.INDETERMINATE

    def test_enriches_multiple_components(self):
        deps = [
            _make_dependency("lodash", "4.17.20"),
            _make_dependency("express", "4.18.2"),
        ]
        bom = generate_sbom(deps, "owner/repo", "abc123")

        reachability_map = {
            "pkg:npm/lodash@4.17.20": ReachabilityStatus.REACHABLE,
            "pkg:npm/express@4.18.2": ReachabilityStatus.UNREACHABLE,
        }
        vulnerability_map = {
            "pkg:npm/lodash@4.17.20": [{"id": "CVE-2021-23337"}],
        }
        enriched = enrich_sbom(bom, reachability_map, vulnerability_map)

        assert enriched.components[0].reachability_status == ReachabilityStatus.REACHABLE
        assert enriched.components[0].vulnerabilities == ["CVE-2021-23337"]
        assert enriched.components[1].reachability_status == ReachabilityStatus.UNREACHABLE
        assert enriched.components[1].vulnerabilities == []

    def test_returns_same_bom_instance(self):
        deps = [_make_dependency()]
        bom = generate_sbom(deps, "owner/repo", "abc123")
        enriched = enrich_sbom(bom, {}, {})

        assert enriched is bom


class TestToJson:
    """Tests for to_json: serialization to CycloneDX JSON v1.5 format."""

    def test_produces_valid_json(self):
        deps = [_make_dependency()]
        bom = generate_sbom(deps, "owner/repo", "abc123")
        json_str = to_json(bom)

        parsed = json.loads(json_str)
        assert isinstance(parsed, dict)

    def test_json_has_required_top_level_fields(self):
        deps = [_make_dependency()]
        bom = generate_sbom(deps, "owner/repo", "abc123")
        parsed = json.loads(to_json(bom))

        assert parsed["bomFormat"] == "CycloneDX"
        assert parsed["specVersion"] == "1.5"
        assert parsed["serialNumber"].startswith("urn:uuid:")
        assert parsed["version"] == 1
        assert "metadata" in parsed
        assert "components" in parsed

    def test_component_has_relationship_property(self):
        deps = [_make_dependency("lodash", "4.17.20", DependencyRelationship.DIRECT)]
        bom = generate_sbom(deps, "owner/repo", "abc123")
        parsed = json.loads(to_json(bom))

        comp = parsed["components"][0]
        props = {p["name"]: p["value"] for p in comp["properties"]}
        assert props["cdx:dependency:relationship"] == "direct"

    def test_enriched_component_has_reachability_property(self):
        deps = [_make_dependency("lodash", "4.17.20")]
        bom = generate_sbom(deps, "owner/repo", "abc123")
        enrich_sbom(
            bom,
            {"pkg:npm/lodash@4.17.20": ReachabilityStatus.REACHABLE},
            {},
        )
        parsed = json.loads(to_json(bom))

        comp = parsed["components"][0]
        props = {p["name"]: p["value"] for p in comp["properties"]}
        assert props["sca:reachability:status"] == "reachable"

    def test_unenriched_component_has_no_reachability_property(self):
        deps = [_make_dependency()]
        bom = generate_sbom(deps, "owner/repo", "abc123")
        parsed = json.loads(to_json(bom))

        comp = parsed["components"][0]
        prop_names = [p["name"] for p in comp["properties"]]
        assert "sca:reachability:status" not in prop_names

    def test_vulnerabilities_included_in_json(self):
        deps = [_make_dependency("lodash", "4.17.20")]
        bom = generate_sbom(deps, "owner/repo", "abc123")
        enrich_sbom(
            bom,
            {},
            {"pkg:npm/lodash@4.17.20": [{"id": "CVE-2021-23337"}]},
        )
        parsed = json.loads(to_json(bom))

        comp = parsed["components"][0]
        assert "vulnerabilities" in comp
        assert comp["vulnerabilities"][0]["id"] == "CVE-2021-23337"

    def test_no_vulnerabilities_key_when_empty(self):
        deps = [_make_dependency()]
        bom = generate_sbom(deps, "owner/repo", "abc123")
        parsed = json.loads(to_json(bom))

        comp = parsed["components"][0]
        assert "vulnerabilities" not in comp


class TestStoreSbom:
    """Tests for store_sbom and retrieve_sbom: versioned storage by repo + commit SHA."""

    def test_stores_and_retrieves_sbom(self):
        deps = [_make_dependency()]
        bom = generate_sbom(deps, "owner/repo", "abc123")

        key = store_sbom(bom, "owner/repo", "abc123")
        assert key == "owner/repo/abc123"

        retrieved = retrieve_sbom("owner/repo", "abc123")
        assert retrieved is not None
        parsed = json.loads(retrieved)
        assert parsed["bomFormat"] == "CycloneDX"

    def test_retrieve_nonexistent_returns_none(self):
        assert retrieve_sbom("owner/repo", "nonexistent") is None

    def test_overwrites_existing_key(self):
        deps1 = [_make_dependency("lodash", "4.17.20")]
        bom1 = generate_sbom(deps1, "owner/repo", "abc123")
        store_sbom(bom1, "owner/repo", "abc123")

        deps2 = [_make_dependency("express", "4.18.2")]
        bom2 = generate_sbom(deps2, "owner/repo", "abc123")
        store_sbom(bom2, "owner/repo", "abc123")

        retrieved = retrieve_sbom("owner/repo", "abc123")
        parsed = json.loads(retrieved)
        assert parsed["components"][0]["name"] == "express"

    def test_different_commits_stored_separately(self):
        deps = [_make_dependency()]
        bom1 = generate_sbom(deps, "owner/repo", "commit1")
        bom2 = generate_sbom(deps, "owner/repo", "commit2")

        store_sbom(bom1, "owner/repo", "commit1")
        store_sbom(bom2, "owner/repo", "commit2")

        assert retrieve_sbom("owner/repo", "commit1") is not None
        assert retrieve_sbom("owner/repo", "commit2") is not None

    def test_stored_json_is_valid(self):
        deps = [_make_dependency("lodash", "4.17.20")]
        bom = generate_sbom(deps, "owner/repo", "abc123")
        enrich_sbom(
            bom,
            {"pkg:npm/lodash@4.17.20": ReachabilityStatus.REACHABLE},
            {"pkg:npm/lodash@4.17.20": [{"id": "CVE-2021-23337"}]},
        )
        store_sbom(bom, "owner/repo", "abc123")

        retrieved = retrieve_sbom("owner/repo", "abc123")
        parsed = json.loads(retrieved)
        assert parsed["specVersion"] == "1.5"
        assert len(parsed["components"]) == 1
        comp = parsed["components"][0]
        props = {p["name"]: p["value"] for p in comp["properties"]}
        assert props["sca:reachability:status"] == "reachable"


class TestCycloneDXBOMDataclass:
    """Tests for the CycloneDXBOM dataclass defaults."""

    def test_default_bom_format(self):
        bom = CycloneDXBOM()
        assert bom.bom_format == "CycloneDX"

    def test_default_spec_version(self):
        bom = CycloneDXBOM()
        assert bom.spec_version == "1.5"

    def test_default_version_is_one(self):
        bom = CycloneDXBOM()
        assert bom.version == 1

    def test_serial_number_is_unique(self):
        bom1 = CycloneDXBOM()
        bom2 = CycloneDXBOM()
        assert bom1.serial_number != bom2.serial_number
