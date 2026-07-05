"""Unit tests for call graph analysis engine.

Tests the CallGraphAnalyzer class covering:
- CallGraph data structure operations (add_node, add_edge)
- Entry point detection patterns (Requirement 17.3)
- BFS reachability traversal (Requirement 18.4)
- Reachability classification (reachable, unreachable, indeterminate)
- Symbol resolution across modules
- Graceful handling of unavailable parsers
"""

import pytest

from src.sca.call_graph import (
    CallGraph,
    CallGraphAnalyzer,
    CallSite,
    FunctionDefinition,
    FunctionNode,
    SourceFile,
)
from src.sca.models import ReachabilityStatus


class TestCallGraph:
    """Tests for the CallGraph data structure."""

    def test_add_node(self):
        graph = CallGraph()
        node = FunctionNode(
            id="file.py:main", name="main", file_path="file.py", line=1
        )
        graph.add_node(node)
        assert "file.py:main" in graph.nodes
        assert graph.nodes["file.py:main"] is node

    def test_add_node_initializes_edges(self):
        graph = CallGraph()
        node = FunctionNode(
            id="file.py:foo", name="foo", file_path="file.py", line=5
        )
        graph.add_node(node)
        assert "file.py:foo" in graph.edges
        assert graph.edges["file.py:foo"] == []

    def test_add_edge(self):
        graph = CallGraph()
        caller = FunctionNode(
            id="a.py:main", name="main", file_path="a.py", line=1
        )
        callee = FunctionNode(
            id="b.py:helper", name="helper", file_path="b.py", line=1
        )
        graph.add_node(caller)
        graph.add_node(callee)
        graph.add_edge("a.py:main", "b.py:helper")
        assert "b.py:helper" in graph.edges["a.py:main"]

    def test_add_edge_no_duplicates(self):
        graph = CallGraph()
        graph.add_node(FunctionNode(
            id="a.py:f", name="f", file_path="a.py", line=1
        ))
        graph.add_node(FunctionNode(
            id="a.py:g", name="g", file_path="a.py", line=5
        ))
        graph.add_edge("a.py:f", "a.py:g")
        graph.add_edge("a.py:f", "a.py:g")
        assert graph.edges["a.py:f"].count("a.py:g") == 1

    def test_add_edge_creates_edge_list_if_missing(self):
        graph = CallGraph()
        graph.add_edge("unknown:caller", "unknown:callee")
        assert "unknown:callee" in graph.edges["unknown:caller"]


class TestEntryPointDetection:
    """Tests for entry point detection logic."""

    def setup_method(self):
        self.analyzer = CallGraphAnalyzer()

    def test_main_function_is_entry_point(self):
        graph = CallGraph()
        node = FunctionNode(
            id="app.py:main", name="main", file_path="app.py", line=1
        )
        graph.add_node(node)
        entry_points = self.analyzer.detect_entry_points(graph)
        assert len(entry_points) == 1
        assert entry_points[0].name == "main"
        assert entry_points[0].is_entry_point is True

    def test_handler_function_is_entry_point(self):
        graph = CallGraph()
        node = FunctionNode(
            id="lambda.py:handler",
            name="handler",
            file_path="lambda.py",
            line=1,
        )
        graph.add_node(node)
        entry_points = self.analyzer.detect_entry_points(graph)
        assert len(entry_points) == 1

    def test_lambda_handler_is_entry_point(self):
        graph = CallGraph()
        node = FunctionNode(
            id="app.py:lambda_handler",
            name="lambda_handler",
            file_path="app.py",
            line=1,
        )
        graph.add_node(node)
        entry_points = self.analyzer.detect_entry_points(graph)
        assert len(entry_points) == 1

    def test_dunder_main_file_is_entry_point(self):
        graph = CallGraph()
        node = FunctionNode(
            id="__main__.py:run",
            name="run",
            file_path="__main__.py",
            line=1,
        )
        graph.add_node(node)
        entry_points = self.analyzer.detect_entry_points(graph)
        assert len(entry_points) == 1

    def test_http_handler_names_are_entry_points(self):
        """doGet, doPost etc. from Java Servlets should be entry points."""
        graph = CallGraph()
        for name in ("doGet", "doPost", "ServeHTTP"):
            graph.add_node(FunctionNode(
                id=f"server.java:{name}",
                name=name,
                file_path="server.java",
                line=1,
            ))
        entry_points = self.analyzer.detect_entry_points(graph)
        assert len(entry_points) == 3

    def test_regular_function_is_not_entry_point(self):
        graph = CallGraph()
        node = FunctionNode(
            id="utils.py:format_string",
            name="format_string",
            file_path="utils.py",
            line=1,
        )
        graph.add_node(node)
        entry_points = self.analyzer.detect_entry_points(graph)
        assert len(entry_points) == 0


class TestReachabilityAnalysis:
    """Tests for BFS reachability traversal and classification."""

    def setup_method(self):
        self.analyzer = CallGraphAnalyzer()

    def _build_linear_graph(self) -> tuple[CallGraph, list[FunctionNode]]:
        """Build: main -> helper -> utility (linear chain)."""
        graph = CallGraph()
        main_node = FunctionNode(
            id="app.py:main", name="main", file_path="app.py", line=1
        )
        helper_node = FunctionNode(
            id="app.py:helper", name="helper", file_path="app.py", line=10
        )
        utility_node = FunctionNode(
            id="lib.py:utility", name="utility", file_path="lib.py", line=1
        )
        graph.add_node(main_node)
        graph.add_node(helper_node)
        graph.add_node(utility_node)
        graph.add_edge("app.py:main", "app.py:helper")
        graph.add_edge("app.py:helper", "lib.py:utility")
        return graph, [main_node]

    def test_entry_point_is_reachable(self):
        graph, entry_points = self._build_linear_graph()
        result = self.analyzer.determine_reachability(graph, entry_points)
        assert result["app.py:main"] == ReachabilityStatus.REACHABLE

    def test_directly_called_function_is_reachable(self):
        graph, entry_points = self._build_linear_graph()
        result = self.analyzer.determine_reachability(graph, entry_points)
        assert result["app.py:helper"] == ReachabilityStatus.REACHABLE

    def test_transitively_called_function_is_reachable(self):
        graph, entry_points = self._build_linear_graph()
        result = self.analyzer.determine_reachability(graph, entry_points)
        assert result["lib.py:utility"] == ReachabilityStatus.REACHABLE

    def test_disconnected_function_is_unreachable(self):
        graph, entry_points = self._build_linear_graph()
        # Add an isolated node
        isolated = FunctionNode(
            id="orphan.py:dead_code",
            name="dead_code",
            file_path="orphan.py",
            line=1,
        )
        graph.add_node(isolated)
        result = self.analyzer.determine_reachability(graph, entry_points)
        assert result["orphan.py:dead_code"] == ReachabilityStatus.UNREACHABLE

    def test_dynamic_dispatch_function_is_indeterminate(self):
        graph = CallGraph()
        main_node = FunctionNode(
            id="app.py:main", name="main", file_path="app.py", line=1
        )
        dynamic_node = FunctionNode(
            id="app.py:getattr",
            name="getattr",
            file_path="app.py",
            line=5,
        )
        graph.add_node(main_node)
        graph.add_node(dynamic_node)
        graph.add_edge("app.py:main", "app.py:getattr")

        result = self.analyzer.determine_reachability(graph, [main_node])
        assert result["app.py:getattr"] == ReachabilityStatus.INDETERMINATE

    def test_multiple_entry_points(self):
        """Functions reachable from any entry point should be REACHABLE."""
        graph = CallGraph()
        ep1 = FunctionNode(
            id="a.py:handler", name="handler", file_path="a.py", line=1
        )
        ep2 = FunctionNode(
            id="b.py:main", name="main", file_path="b.py", line=1
        )
        shared = FunctionNode(
            id="shared.py:util", name="util", file_path="shared.py", line=1
        )
        only_from_ep1 = FunctionNode(
            id="a.py:private", name="private", file_path="a.py", line=10
        )
        graph.add_node(ep1)
        graph.add_node(ep2)
        graph.add_node(shared)
        graph.add_node(only_from_ep1)
        graph.add_edge("a.py:handler", "shared.py:util")
        graph.add_edge("a.py:handler", "a.py:private")
        graph.add_edge("b.py:main", "shared.py:util")

        result = self.analyzer.determine_reachability(graph, [ep1, ep2])
        assert result["shared.py:util"] == ReachabilityStatus.REACHABLE
        assert result["a.py:private"] == ReachabilityStatus.REACHABLE

    def test_empty_graph_returns_empty(self):
        graph = CallGraph()
        result = self.analyzer.determine_reachability(graph, [])
        assert result == {}

    def test_no_entry_points_all_unreachable(self):
        graph = CallGraph()
        node = FunctionNode(
            id="lib.py:foo", name="foo", file_path="lib.py", line=1
        )
        graph.add_node(node)
        result = self.analyzer.determine_reachability(graph, [])
        assert result["lib.py:foo"] == ReachabilityStatus.UNREACHABLE

    def test_cyclic_graph_does_not_infinite_loop(self):
        """Graph with cycles should still terminate."""
        graph = CallGraph()
        main_node = FunctionNode(
            id="app.py:main", name="main", file_path="app.py", line=1
        )
        a_node = FunctionNode(
            id="app.py:a", name="a", file_path="app.py", line=5
        )
        b_node = FunctionNode(
            id="app.py:b", name="b", file_path="app.py", line=10
        )
        graph.add_node(main_node)
        graph.add_node(a_node)
        graph.add_node(b_node)
        graph.add_edge("app.py:main", "app.py:a")
        graph.add_edge("app.py:a", "app.py:b")
        graph.add_edge("app.py:b", "app.py:a")  # cycle!

        result = self.analyzer.determine_reachability(graph, [main_node])
        assert result["app.py:a"] == ReachabilityStatus.REACHABLE
        assert result["app.py:b"] == ReachabilityStatus.REACHABLE


class TestSymbolResolution:
    """Tests for inter-procedural symbol resolution."""

    def setup_method(self):
        self.analyzer = CallGraphAnalyzer()

    def test_build_call_graph_resolves_direct_calls(self):
        """Functions calling each other by name should be connected."""
        graph = CallGraph()
        definitions = {
            "foo": FunctionNode(
                id="a.py:foo", name="foo", file_path="a.py", line=1
            ),
            "bar": FunctionNode(
                id="b.py:bar", name="bar", file_path="b.py", line=1
            ),
        }
        # Test the _resolve_symbol method directly
        result = self.analyzer._resolve_symbol("bar", definitions)
        assert result is not None
        assert result.id == "b.py:bar"

    def test_resolve_qualified_name(self):
        """module.function should resolve to function."""
        definitions = {
            "process": FunctionNode(
                id="utils.py:process",
                name="process",
                file_path="utils.py",
                line=1,
            ),
        }
        result = self.analyzer._resolve_symbol("utils.process", definitions)
        assert result is not None
        assert result.name == "process"

    def test_unresolvable_symbol_returns_none(self):
        definitions = {
            "foo": FunctionNode(
                id="a.py:foo", name="foo", file_path="a.py", line=1
            ),
        }
        result = self.analyzer._resolve_symbol("nonexistent", definitions)
        assert result is None


class TestCallGraphAnalyzerInit:
    """Tests for analyzer initialization and graceful fallback."""

    def test_creates_instance(self):
        """Analyzer should be instantiable even without tree-sitter grammars."""
        analyzer = CallGraphAnalyzer()
        assert analyzer is not None

    def test_available_languages_is_subset_of_supported(self):
        """Available languages should be a subset of SUPPORTED_LANGUAGES."""
        from src.core.constants import SUPPORTED_LANGUAGES
        analyzer = CallGraphAnalyzer()
        for lang in analyzer.available_languages:
            assert lang in SUPPORTED_LANGUAGES

    def test_parse_source_with_unavailable_language_returns_empty(self):
        """Parsing an unsupported language should return empty list."""
        analyzer = CallGraphAnalyzer()
        result = analyzer.parse_source("fn main() {}", "klingon")
        assert result == []

    def test_extract_calls_with_unavailable_language_returns_empty(self):
        """Extracting calls for unsupported language should return empty."""
        analyzer = CallGraphAnalyzer()
        result = analyzer.extract_call_sites("fn main() {}", "klingon")
        assert result == []


class TestBuildCallGraphWithoutParsers:
    """Tests for build_call_graph when tree-sitter grammars are not available."""

    def test_files_with_unavailable_language_produce_empty_graph(self):
        """Files in unsupported language should produce an empty graph."""
        analyzer = CallGraphAnalyzer()
        files = [
            SourceFile(
                path="app.klingon",
                content="function main() {}",
                language="klingon",
            )
        ]
        graph = analyzer.build_call_graph(files)
        assert len(graph.nodes) == 0


class TestBuildCallGraphWithPythonParser:
    """Tests that exercise the Python parser if available."""

    def setup_method(self):
        self.analyzer = CallGraphAnalyzer()
        self.has_python = "python" in self.analyzer.available_languages

    @pytest.mark.skipif(
        "python" not in CallGraphAnalyzer().available_languages,
        reason="tree-sitter Python grammar not installed",
    )
    def test_parse_python_functions(self):
        source = '''
def main():
    helper()

def helper():
    print("hello")
'''
        definitions = self.analyzer.parse_source(source, "python")
        names = [d.name for d in definitions]
        assert "main" in names
        assert "helper" in names

    @pytest.mark.skipif(
        "python" not in CallGraphAnalyzer().available_languages,
        reason="tree-sitter Python grammar not installed",
    )
    def test_extract_python_call_sites(self):
        source = '''
def main():
    helper()
    utils.process()

def helper():
    pass
'''
        calls = self.analyzer.extract_call_sites(source, "python", "app.py")
        callee_names = [c.callee_name for c in calls]
        assert "helper" in callee_names

    @pytest.mark.skipif(
        "python" not in CallGraphAnalyzer().available_languages,
        reason="tree-sitter Python grammar not installed",
    )
    def test_build_graph_from_python_source(self):
        source = '''
def main():
    helper()

def helper():
    utility()

def utility():
    pass
'''
        files = [SourceFile(path="app.py", content=source, language="python")]
        graph = self.analyzer.build_call_graph(files)
        assert len(graph.nodes) >= 3
        # main should have an edge to helper
        assert "app.py:helper" in graph.edges.get("app.py:main", [])

    @pytest.mark.skipif(
        "python" not in CallGraphAnalyzer().available_languages,
        reason="tree-sitter Python grammar not installed",
    )
    def test_full_reachability_analysis_python(self):
        """End-to-end: parse → build graph → detect entry → reachability."""
        source = '''
def main():
    helper()

def helper():
    pass

def dead_code():
    pass
'''
        files = [SourceFile(path="app.py", content=source, language="python")]
        graph = self.analyzer.build_call_graph(files)
        entry_points = self.analyzer.detect_entry_points(graph)
        reachability = self.analyzer.determine_reachability(graph, entry_points)

        assert reachability["app.py:main"] == ReachabilityStatus.REACHABLE
        assert reachability["app.py:helper"] == ReachabilityStatus.REACHABLE
        assert reachability["app.py:dead_code"] == ReachabilityStatus.UNREACHABLE
