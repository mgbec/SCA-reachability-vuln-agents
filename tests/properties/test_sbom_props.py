"""Property-based tests for SBOM generation completeness.

Tests that generated SBOMs contain every dependency from the input tree with
correct name/version/purl/classification, and that enrichment produces valid
reachability statuses for all components.

**Validates: Requirements 17.2, 17.3, 17.4**
"""

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from src.sca.models import (
    DependencyNode,
    DependencyRelationship,
    ReachabilityStatus,
)
from src.sca.sbom_generator import generate_sbom, enrich_sbom

from tests.properties import dependency_trees, reachability_statuses


# --- Strategy for generating reachability and vulnerability maps from a tree ---

def _reachability_map_from_tree(tree: list[dict]) -> dict[str, ReachabilityStatus]:
    """Build a reachability map covering every purl in the dependency tree."""
    status_values = list(ReachabilityStatus)
    result = {}
    for i, node in enumerate(tree):
        result[node["purl"]] = status_values[i % len(status_values)]
    return result


def _vulnerability_map_from_tree(tree: list[dict]) -> dict[str, list[dict]]:
    """Build a vulnerability map with at least one CVE per component."""
    result = {}
    for i, node in enumerate(tree):
        result[node["purl"]] = [
            {"id": f"CVE-2024-{i:05d}", "ratings": [{"score": 5.0, "severity": "medium"}]}
        ]
    return result


def _tree_to_dependency_nodes(tree: list[dict]) -> list[DependencyNode]:
    """Convert strategy-generated dicts to DependencyNode objects."""
    return [
        DependencyNode(
            name=node["name"],
            version=node["version"],
            purl=node["purl"],
            relationship=DependencyRelationship(node["relationship"]),
        )
        for node in tree
    ]


@pytest.mark.property
class TestSBOMGenerationCompleteness:
    """Property 15: SBOM Generation Completeness.

    Tests:
    1. For any dependency tree, generate_sbom produces SBOM with
       len(components) == len(tree), each component has matching name/version/purl.
    2. After enrichment, all components have a non-None reachability_status.

    **Validates: Requirements 17.2, 17.3, 17.4**
    """

    @given(tree=dependency_trees(min_size=1, max_size=20))
    def test_sbom_contains_all_dependencies_with_correct_fields(self, tree: list[dict]):
        """For any dependency tree, generate_sbom produces an SBOM where
        len(components) == len(tree) and each component has matching
        name, version, purl, and classification (relationship).

        **Validates: Requirements 17.2**
        """
        nodes = _tree_to_dependency_nodes(tree)

        sbom = generate_sbom(nodes, repo="owner/test-repo", commit_sha="abc123")

        # Number of components matches number of dependencies
        assert len(sbom.components) == len(tree), (
            f"Expected {len(tree)} components, got {len(sbom.components)}"
        )

        # Each component has matching fields from the original tree
        for i, (component, original) in enumerate(zip(sbom.components, tree)):
            assert component.name == original["name"], (
                f"Component {i}: expected name '{original['name']}', "
                f"got '{component.name}'"
            )
            assert component.version == original["version"], (
                f"Component {i}: expected version '{original['version']}', "
                f"got '{component.version}'"
            )
            assert component.purl == original["purl"], (
                f"Component {i}: expected purl '{original['purl']}', "
                f"got '{component.purl}'"
            )
            assert component.relationship.value == original["relationship"], (
                f"Component {i}: expected relationship '{original['relationship']}', "
                f"got '{component.relationship.value}'"
            )

    @given(tree=dependency_trees(min_size=1, max_size=20))
    def test_enriched_sbom_has_valid_reachability_status_for_all_components(
        self, tree: list[dict]
    ):
        """After enrichment, all components have a non-None reachability_status
        that is a valid ReachabilityStatus enum value.

        **Validates: Requirements 17.3, 17.4**
        """
        nodes = _tree_to_dependency_nodes(tree)

        sbom = generate_sbom(nodes, repo="owner/test-repo", commit_sha="abc123")
        reachability_map = _reachability_map_from_tree(tree)
        vulnerability_map = _vulnerability_map_from_tree(tree)

        enriched = enrich_sbom(sbom, reachability_map, vulnerability_map)

        valid_statuses = set(ReachabilityStatus)
        for i, component in enumerate(enriched.components):
            assert component.reachability_status is not None, (
                f"Component {i} ({component.name}) has None reachability_status "
                f"after enrichment"
            )
            assert component.reachability_status in valid_statuses, (
                f"Component {i} ({component.name}) has invalid reachability_status "
                f"'{component.reachability_status}'"
            )

    @given(tree=dependency_trees(min_size=1, max_size=20))
    def test_enriched_sbom_has_cve_associations_for_all_components(
        self, tree: list[dict]
    ):
        """After enrichment with a complete vulnerability map, all components
        have non-empty CVE associations.

        **Validates: Requirements 17.4**
        """
        nodes = _tree_to_dependency_nodes(tree)

        sbom = generate_sbom(nodes, repo="owner/test-repo", commit_sha="abc123")
        reachability_map = _reachability_map_from_tree(tree)
        vulnerability_map = _vulnerability_map_from_tree(tree)

        enriched = enrich_sbom(sbom, reachability_map, vulnerability_map)

        for i, component in enumerate(enriched.components):
            assert len(component.vulnerabilities) > 0, (
                f"Component {i} ({component.name}) has no CVE associations "
                f"after enrichment with vulnerability map"
            )
