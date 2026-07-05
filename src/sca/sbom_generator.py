"""SBOM (Software Bill of Materials) generation in CycloneDX JSON v1.5 format.

Provides functions to generate, enrich, serialize, and store CycloneDX SBOMs
from a dependency tree. SBOMs are versioned and keyed by repository + commit SHA.

Requirements: 17.2, 17.3, 17.4, 17.5
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from src.core.constants import SBOM_FORMAT, SBOM_FORMAT_VERSION
from src.sca.models import (
    DependencyNode,
    DependencyRelationship,
    ReachabilityStatus,
    SBOMComponent,
)


@dataclass
class CycloneDXBOM:
    """CycloneDX Bill of Materials in v1.5 format.

    Attributes:
        bom_format: The BOM format identifier ("CycloneDX").
        spec_version: The CycloneDX specification version ("1.5").
        serial_number: Unique UUID identifying this BOM instance.
        version: BOM version number (starts at 1).
        metadata: Contextual metadata including repo, commit SHA, and timestamp.
        components: List of SBOM components in the BOM.
    """

    bom_format: str = field(default_factory=lambda: SBOM_FORMAT)
    spec_version: str = field(default_factory=lambda: SBOM_FORMAT_VERSION)
    serial_number: str = field(default_factory=lambda: str(uuid.uuid4()))
    version: int = 1
    metadata: dict[str, Any] = field(default_factory=dict)
    components: list[SBOMComponent] = field(default_factory=list)


# --- In-memory SBOM storage keyed by "{repo}/{commit_sha}" ---
_sbom_store: dict[str, str] = {}


def generate_sbom(
    dependency_tree: list[DependencyNode],
    repo: str,
    commit_sha: str,
) -> CycloneDXBOM:
    """Generate a CycloneDX BOM from a dependency tree.

    Converts each DependencyNode into an SBOMComponent with name, version,
    purl, and direct/transitive classification.

    Args:
        dependency_tree: List of DependencyNode objects representing all dependencies.
        repo: Repository identifier (e.g., "owner/repo-name").
        commit_sha: Git commit SHA being analyzed.

    Returns:
        A CycloneDXBOM instance with all components populated.
    """
    components: list[SBOMComponent] = []

    for node in dependency_tree:
        component = SBOMComponent(
            type="library",
            bom_ref=node.purl,
            name=node.name,
            version=node.version,
            purl=node.purl,
            scope="required",
            relationship=node.relationship,
            reachability_status=None,
            vulnerabilities=[],
        )
        components.append(component)

    bom = CycloneDXBOM(
        metadata={
            "repository": repo,
            "commit_sha": commit_sha,
            "timestamp": datetime.now(UTC).isoformat(),
        },
        components=components,
    )

    return bom


def enrich_sbom(
    sbom: CycloneDXBOM,
    reachability_map: dict[str, ReachabilityStatus],
    vulnerability_map: dict[str, list[dict[str, Any]]],
) -> CycloneDXBOM:
    """Enrich an SBOM with reachability status and CVE associations.

    Updates each component in the SBOM with its reachability classification
    and associated vulnerability data (CVE IDs and severity ratings).

    Args:
        sbom: The CycloneDX BOM to enrich.
        reachability_map: Mapping of purl -> ReachabilityStatus for each component.
        vulnerability_map: Mapping of purl -> list of vulnerability dicts.
            Each vulnerability dict should have at minimum an "id" key (CVE ID).
            Optionally includes "ratings" with severity information.

    Returns:
        The enriched CycloneDXBOM (modified in place and returned).
    """
    for component in sbom.components:
        # Add reachability status
        if component.purl in reachability_map:
            component.reachability_status = reachability_map[component.purl]
        else:
            # Default to indeterminate if not in reachability map
            component.reachability_status = ReachabilityStatus.INDETERMINATE

        # Add CVE associations
        if component.purl in vulnerability_map:
            vulns = vulnerability_map[component.purl]
            component.vulnerabilities = [v["id"] for v in vulns if "id" in v]

    return sbom


def to_json(sbom: CycloneDXBOM) -> str:
    """Serialize a CycloneDX BOM to JSON format (v1.5 compliant).

    Produces a JSON string representation following the CycloneDX v1.5
    specification structure.

    Args:
        sbom: The CycloneDX BOM to serialize.

    Returns:
        A JSON string representing the BOM.
    """
    components_json = []
    for comp in sbom.components:
        comp_dict: dict[str, Any] = {
            "type": comp.type,
            "bom-ref": comp.bom_ref,
            "name": comp.name,
            "version": comp.version,
            "purl": comp.purl,
            "scope": comp.scope,
            "properties": [
                {
                    "name": "cdx:dependency:relationship",
                    "value": comp.relationship.value,
                },
            ],
        }

        # Add reachability status property if enriched
        if comp.reachability_status is not None:
            comp_dict["properties"].append(
                {
                    "name": "sca:reachability:status",
                    "value": comp.reachability_status.value,
                }
            )

        # Add vulnerabilities if present
        if comp.vulnerabilities:
            comp_dict["vulnerabilities"] = [
                {"id": cve_id} for cve_id in comp.vulnerabilities
            ]

        components_json.append(comp_dict)

    bom_dict: dict[str, Any] = {
        "bomFormat": sbom.bom_format,
        "specVersion": sbom.spec_version,
        "serialNumber": f"urn:uuid:{sbom.serial_number}",
        "version": sbom.version,
        "metadata": sbom.metadata,
        "components": components_json,
    }

    return json.dumps(bom_dict, indent=2)


def store_sbom(sbom: CycloneDXBOM, repo: str, commit_sha: str) -> str:
    """Store a versioned SBOM artifact keyed by repo + commit SHA.

    Serializes the SBOM to JSON and stores it in the in-memory store.

    Args:
        sbom: The CycloneDX BOM to store.
        repo: Repository identifier (e.g., "owner/repo-name").
        commit_sha: Git commit SHA.

    Returns:
        The storage key used ("{repo}/{commit_sha}").
    """
    key = f"{repo}/{commit_sha}"
    _sbom_store[key] = to_json(sbom)
    return key


def retrieve_sbom(repo: str, commit_sha: str) -> str | None:
    """Retrieve a stored SBOM artifact by repo + commit SHA.

    Args:
        repo: Repository identifier.
        commit_sha: Git commit SHA.

    Returns:
        The JSON string of the stored SBOM, or None if not found.
    """
    key = f"{repo}/{commit_sha}"
    return _sbom_store.get(key)


def clear_store() -> None:
    """Clear the in-memory SBOM store. Useful for testing."""
    _sbom_store.clear()
