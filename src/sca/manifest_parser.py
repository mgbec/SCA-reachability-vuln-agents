"""Dependency manifest parsing for multiple package ecosystems.

Provides parsers for:
- package.json (npm/Node.js)
- requirements.txt (Python/PyPI)
- pom.xml (Java/Maven)
- go.mod (Go)
- Cargo.toml (Rust/Cargo)

Each parser extracts direct dependencies and constructs DependencyNode objects
with proper Package URLs (purls). Parse failures are handled gracefully with
partial results and error reporting.
"""

from __future__ import annotations

import json
import re
import tomllib
import xml.etree.ElementTree as ET
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from src.sca.models import DependencyNode, DependencyRelationship


@dataclass
class ParseResult:
    """Result of parsing a dependency manifest.

    Attributes:
        dependencies: Successfully parsed dependency nodes.
        parse_errors: Error messages for entries that could not be parsed.
        filename: The manifest filename that was parsed.
    """

    dependencies: list[DependencyNode] = field(default_factory=list)
    parse_errors: list[str] = field(default_factory=list)
    filename: str = ""


class ManifestParser(ABC):
    """Base class for dependency manifest parsers."""

    @abstractmethod
    def parse(self, content: str) -> list[DependencyNode]:
        """Parse manifest content and return dependency nodes.

        Args:
            content: Raw text content of the manifest file.

        Returns:
            List of parsed DependencyNode objects.

        Raises:
            ParseError: If the entire file is unparseable.
        """
        ...


class PackageJsonParser(ManifestParser):
    """Parser for npm package.json files."""

    def parse(self, content: str) -> list[DependencyNode]:
        """Parse package.json content.

        Extracts dependencies from both 'dependencies' and 'devDependencies'
        sections. Version strings are cleaned of npm range specifiers.
        """
        data = json.loads(content)
        nodes: list[DependencyNode] = []

        for section in ("dependencies", "devDependencies"):
            deps = data.get(section, {})
            if not isinstance(deps, dict):
                continue
            for name, version_spec in deps.items():
                version = _clean_npm_version(version_spec)
                if not name or not version:
                    continue
                purl = f"pkg:npm/{name}@{version}"
                nodes.append(
                    DependencyNode(
                        name=name,
                        version=version,
                        purl=purl,
                        relationship=DependencyRelationship.DIRECT,
                    )
                )

        return nodes


class RequirementsTxtParser(ManifestParser):
    """Parser for Python requirements.txt files."""

    # Matches: package==version, package>=version, package~=version, etc.
    _REQ_PATTERN = re.compile(
        r"^\s*([A-Za-z0-9][\w.\-]*(?:\[[^\]]*\])?)\s*(?:([=!<>~]=?)\s*([^\s,;#]+))?"
    )

    def parse(self, content: str) -> list[DependencyNode]:
        """Parse requirements.txt content.

        Handles pinned versions (==), minimum versions (>=), compatible releases (~=),
        and packages without version specifiers. Skips comments, blank lines, and
        option lines (-r, -e, --index-url, etc.).
        """
        nodes: list[DependencyNode] = []

        for line in content.splitlines():
            line = line.strip()
            # Skip empty lines, comments, and options
            if not line or line.startswith("#") or line.startswith("-"):
                continue

            match = self._REQ_PATTERN.match(line)
            if not match:
                continue

            name = match.group(1)
            # Strip extras like [security]
            if "[" in name:
                name = name[: name.index("[")]
            version = match.group(3) or ""

            if not name:
                continue

            purl = f"pkg:pypi/{name.lower()}@{version}" if version else f"pkg:pypi/{name.lower()}"
            nodes.append(
                DependencyNode(
                    name=name,
                    version=version,
                    purl=purl,
                    relationship=DependencyRelationship.DIRECT,
                )
            )

        return nodes


class PomXmlParser(ManifestParser):
    """Parser for Maven pom.xml files."""

    _NS = {"m": "http://maven.apache.org/POM/4.0.0"}

    def parse(self, content: str) -> list[DependencyNode]:
        """Parse pom.xml content.

        Extracts dependencies from the <dependencies> section.
        Handles both namespaced and non-namespaced pom.xml files.
        """
        root = ET.fromstring(content)  # noqa: S314
        nodes: list[DependencyNode] = []

        # Detect namespace
        ns = ""
        if root.tag.startswith("{"):
            ns = root.tag.split("}")[0] + "}"

        # Find all dependency elements
        deps_sections = root.iter(f"{ns}dependency") if ns else root.iter("dependency")

        for dep in deps_sections:
            group_id_el = dep.find(f"{ns}groupId") if ns else dep.find("groupId")
            artifact_id_el = dep.find(f"{ns}artifactId") if ns else dep.find("artifactId")
            version_el = dep.find(f"{ns}version") if ns else dep.find("version")

            if group_id_el is None or artifact_id_el is None:
                continue

            group_id = (group_id_el.text or "").strip()
            artifact_id = (artifact_id_el.text or "").strip()
            version = (version_el.text or "").strip() if version_el is not None else ""

            if not group_id or not artifact_id:
                continue

            name = f"{group_id}:{artifact_id}"
            purl = f"pkg:maven/{group_id}/{artifact_id}@{version}" if version else f"pkg:maven/{group_id}/{artifact_id}"
            nodes.append(
                DependencyNode(
                    name=name,
                    version=version,
                    purl=purl,
                    relationship=DependencyRelationship.DIRECT,
                )
            )

        return nodes


class GoModParser(ManifestParser):
    """Parser for Go go.mod files."""

    _REQUIRE_LINE = re.compile(r"^\s*([^\s]+)\s+v?([^\s/]+)\s*(?://.*)?$")

    def parse(self, content: str) -> list[DependencyNode]:
        """Parse go.mod content.

        Extracts dependencies from both single-line 'require' statements
        and multi-line 'require (...)' blocks.
        """
        nodes: list[DependencyNode] = []
        in_require_block = False

        for line in content.splitlines():
            stripped = line.strip()

            # Detect require block start
            if stripped.startswith("require") and "(" in stripped:
                in_require_block = True
                continue

            # Detect require block end
            if in_require_block and stripped == ")":
                in_require_block = False
                continue

            # Single-line require
            if stripped.startswith("require ") and "(" not in stripped:
                # e.g., require github.com/pkg/errors v0.9.1
                parts = stripped[len("require "):].strip()
                match = self._REQUIRE_LINE.match(parts)
                if match:
                    name = match.group(1)
                    version = match.group(2)
                    purl = f"pkg:golang/{name}@v{version}"
                    nodes.append(
                        DependencyNode(
                            name=name,
                            version=f"v{version}",
                            purl=purl,
                            relationship=DependencyRelationship.DIRECT,
                        )
                    )
                continue

            # Lines inside a require block
            if in_require_block:
                # Skip comments and empty lines
                if not stripped or stripped.startswith("//"):
                    continue
                match = self._REQUIRE_LINE.match(stripped)
                if match:
                    name = match.group(1)
                    version = match.group(2)
                    purl = f"pkg:golang/{name}@v{version}"
                    nodes.append(
                        DependencyNode(
                            name=name,
                            version=f"v{version}",
                            purl=purl,
                            relationship=DependencyRelationship.DIRECT,
                        )
                    )

        return nodes


class CargoTomlParser(ManifestParser):
    """Parser for Rust Cargo.toml files."""

    def parse(self, content: str) -> list[DependencyNode]:
        """Parse Cargo.toml content.

        Extracts dependencies from [dependencies] and [dev-dependencies] sections.
        Handles both simple version strings and table specifications with 'version' key.
        """
        data = tomllib.loads(content)
        nodes: list[DependencyNode] = []

        for section in ("dependencies", "dev-dependencies"):
            deps = data.get(section, {})
            if not isinstance(deps, dict):
                continue
            for name, spec in deps.items():
                version = ""
                if isinstance(spec, str):
                    version = spec
                elif isinstance(spec, dict):
                    version = spec.get("version", "")
                else:
                    continue

                if not name:
                    continue

                # Clean version specifiers (e.g., "^1.0", "~1.0", ">=1.0")
                version = _clean_cargo_version(version)
                purl = f"pkg:cargo/{name}@{version}" if version else f"pkg:cargo/{name}"
                nodes.append(
                    DependencyNode(
                        name=name,
                        version=version,
                        purl=purl,
                        relationship=DependencyRelationship.DIRECT,
                    )
                )

        return nodes


# --- Factory and utility functions ---


_PARSER_MAP: dict[str, type[ManifestParser]] = {
    "package.json": PackageJsonParser,
    "requirements.txt": RequirementsTxtParser,
    "pom.xml": PomXmlParser,
    "go.mod": GoModParser,
    "Cargo.toml": CargoTomlParser,
}


def get_parser(filename: str) -> ManifestParser | None:
    """Get the appropriate parser for a given manifest filename.

    Args:
        filename: The manifest filename (e.g., "package.json", "requirements.txt").

    Returns:
        A ManifestParser instance, or None if the filename is not supported.
    """
    # Extract just the filename from paths
    basename = filename.rsplit("/", 1)[-1] if "/" in filename else filename
    basename = basename.rsplit("\\", 1)[-1] if "\\" in basename else basename

    parser_cls = _PARSER_MAP.get(basename)
    if parser_cls is None:
        return None
    return parser_cls()


def parse_manifest(filename: str, content: str) -> ParseResult:
    """Parse a dependency manifest file and return structured results.

    This is the main entry point for manifest parsing. It selects the appropriate
    parser based on the filename, parses the content, and returns a ParseResult
    with both successfully parsed dependencies and any errors encountered.

    Args:
        filename: The manifest filename (used to select the parser).
        content: The raw text content of the manifest file.

    Returns:
        ParseResult containing parsed dependencies and any error messages.
    """
    result = ParseResult(filename=filename)

    parser = get_parser(filename)
    if parser is None:
        result.parse_errors.append(f"Unsupported manifest format: {filename}")
        return result

    try:
        dependencies = parser.parse(content)
        result.dependencies = dependencies
    except json.JSONDecodeError as e:
        result.parse_errors.append(f"JSON parse error in {filename}: {e}")
    except ET.ParseError as e:
        result.parse_errors.append(f"XML parse error in {filename}: {e}")
    except tomllib.TOMLDecodeError as e:
        result.parse_errors.append(f"TOML parse error in {filename}: {e}")
    except Exception as e:
        result.parse_errors.append(f"Unexpected error parsing {filename}: {e}")

    return result


# --- Private helpers ---


def _clean_npm_version(version_spec: str) -> str:
    """Clean npm version specifier to extract the base version.

    Strips range characters (^, ~, >=, <=, >, <, =) and handles
    common patterns like "^1.2.3", "~4.5.6", ">=2.0.0".
    Returns the version number without range prefixes.
    """
    if not isinstance(version_spec, str):
        return ""
    # Strip common range prefixes
    cleaned = re.sub(r"^[\^~>=<]*\s*", "", version_spec.strip())
    # Handle "x" ranges like "1.x" or "1.2.x" by replacing x with 0
    cleaned = re.sub(r"\.x", ".0", cleaned)
    # Take first version if it's an OR range (e.g., ">=1.0.0 <2.0.0")
    if " " in cleaned:
        cleaned = cleaned.split(" ")[0]
    return cleaned


def _clean_cargo_version(version_spec: str) -> str:
    """Clean Cargo version specifier to extract the base version.

    Strips range characters (^, ~, >=, <=, >, <, =, *).
    """
    if not version_spec:
        return ""
    cleaned = re.sub(r"^[\^~>=<*]*\s*", "", version_spec.strip())
    # Handle wildcard versions like "1.*" or "1.2.*"
    cleaned = re.sub(r"\.\*", ".0", cleaned)
    return cleaned
