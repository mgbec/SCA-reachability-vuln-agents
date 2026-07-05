"""Unit tests for the dependency manifest parser module."""

import pytest

from src.sca.manifest_parser import (
    CargoTomlParser,
    GoModParser,
    PackageJsonParser,
    PomXmlParser,
    RequirementsTxtParser,
    get_parser,
    parse_manifest,
)
from src.sca.models import DependencyRelationship


class TestPackageJsonParser:
    """Tests for npm package.json parsing."""

    def test_parses_dependencies_and_dev_dependencies(self):
        content = """{
  "name": "my-app",
  "dependencies": {
    "lodash": "^4.17.21",
    "express": "~4.18.2"
  },
  "devDependencies": {
    "jest": ">=29.0.0"
  }
}"""
        parser = PackageJsonParser()
        result = parser.parse(content)
        assert len(result) == 3
        assert result[0].name == "lodash"
        assert result[0].version == "4.17.21"
        assert result[0].purl == "pkg:npm/lodash@4.17.21"
        assert result[0].relationship == DependencyRelationship.DIRECT
        assert result[1].name == "express"
        assert result[1].version == "4.18.2"
        assert result[2].name == "jest"

    def test_handles_exact_versions(self):
        content = '{"dependencies": {"react": "18.2.0"}}'
        parser = PackageJsonParser()
        result = parser.parse(content)
        assert result[0].version == "18.2.0"

    def test_handles_empty_dependencies(self):
        content = '{"name": "app", "dependencies": {}}'
        parser = PackageJsonParser()
        result = parser.parse(content)
        assert len(result) == 0

    def test_handles_no_dependencies_key(self):
        content = '{"name": "app", "version": "1.0.0"}'
        parser = PackageJsonParser()
        result = parser.parse(content)
        assert len(result) == 0

    def test_skips_empty_name_entries(self):
        content = '{"dependencies": {"valid": "1.0.0", "": "2.0.0"}}'
        parser = PackageJsonParser()
        result = parser.parse(content)
        assert len(result) == 1
        assert result[0].name == "valid"

    def test_raises_on_invalid_json(self):
        parser = PackageJsonParser()
        with pytest.raises(Exception):
            parser.parse("{not valid json}")

    def test_scoped_packages(self):
        content = '{"dependencies": {"@types/node": "^20.0.0", "@babel/core": "7.23.0"}}'
        parser = PackageJsonParser()
        result = parser.parse(content)
        assert len(result) == 2
        assert result[0].name == "@types/node"
        assert result[0].purl == "pkg:npm/@types/node@20.0.0"


class TestRequirementsTxtParser:
    """Tests for Python requirements.txt parsing."""

    def test_parses_pinned_versions(self):
        content = "flask==2.3.3\nrequests==2.28.0\n"
        parser = RequirementsTxtParser()
        result = parser.parse(content)
        assert len(result) == 2
        assert result[0].name == "flask"
        assert result[0].version == "2.3.3"
        assert result[0].purl == "pkg:pypi/flask@2.3.3"

    def test_parses_minimum_versions(self):
        content = "boto3>=1.34.0\n"
        parser = RequirementsTxtParser()
        result = parser.parse(content)
        assert result[0].version == "1.34.0"

    def test_parses_compatible_release(self):
        content = "requests~=2.28.0\n"
        parser = RequirementsTxtParser()
        result = parser.parse(content)
        assert result[0].version == "2.28.0"

    def test_handles_no_version(self):
        content = "numpy\n"
        parser = RequirementsTxtParser()
        result = parser.parse(content)
        assert result[0].name == "numpy"
        assert result[0].version == ""
        assert result[0].purl == "pkg:pypi/numpy"

    def test_skips_comments(self):
        content = "# comment\nflask==1.0\n# another comment\n"
        parser = RequirementsTxtParser()
        result = parser.parse(content)
        assert len(result) == 1

    def test_skips_option_lines(self):
        content = "-r other.txt\n-e ./local-pkg\n--index-url https://pypi.org/simple\nflask==1.0\n"
        parser = RequirementsTxtParser()
        result = parser.parse(content)
        assert len(result) == 1
        assert result[0].name == "flask"

    def test_skips_blank_lines(self):
        content = "flask==1.0\n\n\nrequests==2.0\n"
        parser = RequirementsTxtParser()
        result = parser.parse(content)
        assert len(result) == 2

    def test_strips_extras(self):
        content = "requests[security]==2.28.0\nurllib3[brotli]>=1.26.0\n"
        parser = RequirementsTxtParser()
        result = parser.parse(content)
        assert result[0].name == "requests"
        assert result[1].name == "urllib3"

    def test_package_names_lowercased_in_purl(self):
        content = "Flask==2.0.0\nDjango==4.0\n"
        parser = RequirementsTxtParser()
        result = parser.parse(content)
        assert result[0].purl == "pkg:pypi/flask@2.0.0"
        assert result[1].purl == "pkg:pypi/django@4.0"


class TestPomXmlParser:
    """Tests for Maven pom.xml parsing."""

    def test_parses_namespaced_pom(self):
        content = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <dependencies>
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-core</artifactId>
      <version>6.1.0</version>
    </dependency>
  </dependencies>
</project>"""
        parser = PomXmlParser()
        result = parser.parse(content)
        assert len(result) == 1
        assert result[0].name == "org.springframework:spring-core"
        assert result[0].version == "6.1.0"
        assert result[0].purl == "pkg:maven/org.springframework/spring-core@6.1.0"

    def test_parses_non_namespaced_pom(self):
        content = """<project>
  <dependencies>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
      <version>4.13.2</version>
    </dependency>
  </dependencies>
</project>"""
        parser = PomXmlParser()
        result = parser.parse(content)
        assert len(result) == 1
        assert result[0].name == "junit:junit"

    def test_handles_missing_version(self):
        content = """<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <dependencies>
    <dependency>
      <groupId>org.example</groupId>
      <artifactId>lib</artifactId>
    </dependency>
  </dependencies>
</project>"""
        parser = PomXmlParser()
        result = parser.parse(content)
        assert len(result) == 1
        assert result[0].version == ""
        assert result[0].purl == "pkg:maven/org.example/lib"

    def test_skips_missing_artifact_id(self):
        content = """<project>
  <dependencies>
    <dependency>
      <groupId>org.example</groupId>
    </dependency>
  </dependencies>
</project>"""
        parser = PomXmlParser()
        result = parser.parse(content)
        assert len(result) == 0

    def test_raises_on_invalid_xml(self):
        parser = PomXmlParser()
        with pytest.raises(Exception):
            parser.parse("<not valid xml>></")


class TestGoModParser:
    """Tests for Go go.mod parsing."""

    def test_parses_require_block(self):
        content = """module github.com/example/app

go 1.21

require (
\tgithub.com/gin-gonic/gin v1.9.1
\tgolang.org/x/crypto v0.14.0
)
"""
        parser = GoModParser()
        result = parser.parse(content)
        assert len(result) == 2
        assert result[0].name == "github.com/gin-gonic/gin"
        assert result[0].version == "v1.9.1"
        assert result[0].purl == "pkg:golang/github.com/gin-gonic/gin@v1.9.1"

    def test_parses_single_line_require(self):
        content = """module example.com/app

require github.com/pkg/errors v0.9.1
"""
        parser = GoModParser()
        result = parser.parse(content)
        assert len(result) == 1
        assert result[0].name == "github.com/pkg/errors"
        assert result[0].version == "v0.9.1"

    def test_skips_comments_in_require_block(self):
        content = """module example.com/app

require (
\t// This is a comment
\tgithub.com/pkg/errors v0.9.1
)
"""
        parser = GoModParser()
        result = parser.parse(content)
        assert len(result) == 1

    def test_handles_version_with_hash(self):
        content = """module example.com/app

require (
\tgithub.com/some/pkg v1.2.3+incompatible
)
"""
        parser = GoModParser()
        result = parser.parse(content)
        assert len(result) == 1
        assert result[0].version == "v1.2.3+incompatible"

    def test_handles_empty_file(self):
        content = """module example.com/app

go 1.21
"""
        parser = GoModParser()
        result = parser.parse(content)
        assert len(result) == 0


class TestCargoTomlParser:
    """Tests for Rust Cargo.toml parsing."""

    def test_parses_simple_versions(self):
        content = """[package]
name = "my-app"

[dependencies]
serde = "1.0"
tokio = "1.34"
"""
        parser = CargoTomlParser()
        result = parser.parse(content)
        assert len(result) == 2
        assert result[0].name == "serde"
        assert result[0].version == "1.0"
        assert result[0].purl == "pkg:cargo/serde@1.0"

    def test_parses_table_dependencies(self):
        content = """[dependencies]
tokio = { version = "1.34", features = ["full"] }
reqwest = { version = "^0.11", features = ["json"] }
"""
        parser = CargoTomlParser()
        result = parser.parse(content)
        assert len(result) == 2
        assert result[0].name == "tokio"
        assert result[0].version == "1.34"
        assert result[1].name == "reqwest"
        assert result[1].version == "0.11"

    def test_parses_dev_dependencies(self):
        content = """[dependencies]
serde = "1.0"

[dev-dependencies]
criterion = "0.5"
"""
        parser = CargoTomlParser()
        result = parser.parse(content)
        assert len(result) == 2
        assert result[1].name == "criterion"

    def test_cleans_caret_version(self):
        content = '[dependencies]\nrand = "^0.8"'
        parser = CargoTomlParser()
        result = parser.parse(content)
        assert result[0].version == "0.8"

    def test_cleans_tilde_version(self):
        content = '[dependencies]\nrand = "~0.8"'
        parser = CargoTomlParser()
        result = parser.parse(content)
        assert result[0].version == "0.8"

    def test_handles_empty_dependencies(self):
        content = """[package]
name = "app"
[dependencies]
"""
        parser = CargoTomlParser()
        result = parser.parse(content)
        assert len(result) == 0

    def test_raises_on_invalid_toml(self):
        parser = CargoTomlParser()
        with pytest.raises(Exception):
            parser.parse("[invalid\ntoml = ")


class TestGetParser:
    """Tests for the get_parser factory function."""

    def test_returns_correct_parser_types(self):
        assert isinstance(get_parser("package.json"), PackageJsonParser)
        assert isinstance(get_parser("requirements.txt"), RequirementsTxtParser)
        assert isinstance(get_parser("pom.xml"), PomXmlParser)
        assert isinstance(get_parser("go.mod"), GoModParser)
        assert isinstance(get_parser("Cargo.toml"), CargoTomlParser)

    def test_returns_none_for_unsupported(self):
        assert get_parser("Gemfile.lock") is None
        assert get_parser("build.gradle") is None
        assert get_parser("random.txt") is None

    def test_handles_path_prefixes(self):
        assert isinstance(get_parser("path/to/package.json"), PackageJsonParser)
        assert isinstance(get_parser("some\\path\\Cargo.toml"), CargoTomlParser)
        assert isinstance(get_parser("/root/project/go.mod"), GoModParser)


class TestParseManifest:
    """Tests for the parse_manifest entry point function."""

    def test_successful_parse(self):
        content = '{"dependencies": {"axios": "^1.6.0"}}'
        result = parse_manifest("package.json", content)
        assert result.filename == "package.json"
        assert len(result.dependencies) == 1
        assert result.dependencies[0].name == "axios"
        assert len(result.parse_errors) == 0

    def test_json_parse_error(self):
        result = parse_manifest("package.json", "{invalid}")
        assert len(result.dependencies) == 0
        assert len(result.parse_errors) == 1
        assert "JSON parse error" in result.parse_errors[0]
        assert result.filename == "package.json"

    def test_xml_parse_error(self):
        result = parse_manifest("pom.xml", "<broken>><xml")
        assert len(result.dependencies) == 0
        assert len(result.parse_errors) == 1
        assert "XML parse error" in result.parse_errors[0]

    def test_toml_parse_error(self):
        result = parse_manifest("Cargo.toml", "[bad\ntoml")
        assert len(result.dependencies) == 0
        assert len(result.parse_errors) == 1
        assert "TOML parse error" in result.parse_errors[0]

    def test_unsupported_format(self):
        result = parse_manifest("Gemfile.lock", "content")
        assert len(result.dependencies) == 0
        assert len(result.parse_errors) == 1
        assert "Unsupported manifest format" in result.parse_errors[0]

    def test_all_dependencies_are_direct(self):
        """All dependencies parsed from manifests are classified as direct."""
        content = '{"dependencies": {"a": "1.0", "b": "2.0"}}'
        result = parse_manifest("package.json", content)
        for dep in result.dependencies:
            assert dep.relationship == DependencyRelationship.DIRECT
