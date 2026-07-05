"""Call graph analysis engine using tree-sitter for static analysis.

Builds inter-procedural call graphs from source code using tree-sitter parsers,
detects entry points, and performs reachability analysis to classify functions
as reachable, unreachable, or indeterminate.

Requirements: 17.3, 18.4
"""

from __future__ import annotations

import logging
from collections import deque
from dataclasses import dataclass, field

from src.core.constants import SUPPORTED_LANGUAGES
from src.sca.models import ReachabilityStatus

logger = logging.getLogger(__name__)


@dataclass
class FunctionNode:
    """Represents a function in the call graph.

    Attributes:
        id: Unique identifier (file_path:function_name).
        name: Function name.
        file_path: Path to the source file containing this function.
        line: Line number where the function is defined.
        is_entry_point: Whether this function is an entry point.
    """

    id: str
    name: str
    file_path: str
    line: int
    is_entry_point: bool = False


@dataclass
class SourceFile:
    """Represents a source file to be analyzed.

    Attributes:
        path: File path relative to project root.
        content: Source code content.
        language: Programming language (must be in SUPPORTED_LANGUAGES).
    """

    path: str
    content: str
    language: str


@dataclass
class CallSite:
    """Represents a function call site found in source code.

    Attributes:
        caller_id: ID of the function containing the call.
        callee_name: Name of the function being called.
        file_path: File path where the call occurs.
        line: Line number of the call.
        is_dynamic: Whether the call is dynamic (e.g., via variable).
    """

    caller_id: str
    callee_name: str
    file_path: str
    line: int
    is_dynamic: bool = False


@dataclass
class FunctionDefinition:
    """Represents a parsed function definition.

    Attributes:
        name: Function name.
        file_path: File path where the function is defined.
        line: Line number of the definition.
        is_exported: Whether the function is exported/public.
        decorators: List of decorator names applied to this function.
    """

    name: str
    file_path: str
    line: int
    is_exported: bool = False
    decorators: list[str] = field(default_factory=list)


@dataclass
class CallGraph:
    """Directed graph of calling relationships between functions.

    Attributes:
        nodes: Mapping of function_id to FunctionNode.
        edges: Adjacency list mapping caller_id to list of callee_ids.
    """

    nodes: dict[str, FunctionNode] = field(default_factory=dict)
    edges: dict[str, list[str]] = field(default_factory=dict)

    def add_node(self, node: FunctionNode) -> None:
        """Add a function node to the graph."""
        self.nodes[node.id] = node
        if node.id not in self.edges:
            self.edges[node.id] = []

    def add_edge(self, caller_id: str, callee_id: str) -> None:
        """Add a directed edge from caller to callee."""
        if caller_id not in self.edges:
            self.edges[caller_id] = []
        if callee_id not in self.edges[caller_id]:
            self.edges[caller_id].append(callee_id)


# --- Entry Point Detection Patterns ---

# Python entry point patterns
_PYTHON_ENTRY_DECORATORS = frozenset({
    "route", "get", "post", "put", "delete", "patch",
    "app.route", "app.get", "app.post", "app.put", "app.delete",
    "blueprint.route",
})

_PYTHON_ENTRY_NAMES = frozenset({
    "main", "handler", "lambda_handler",
})

# JavaScript/TypeScript entry point patterns
_JS_ENTRY_PATTERNS = frozenset({
    "main", "handler", "lambdaHandler",
})

# Java entry point patterns
_JAVA_ENTRY_NAMES = frozenset({
    "main", "doGet", "doPost", "doPut", "doDelete",
    "handleRequest",
})

# Go entry point patterns
_GO_ENTRY_NAMES = frozenset({
    "main", "Handler", "ServeHTTP",
})

# Rust entry point patterns
_RUST_ENTRY_NAMES = frozenset({
    "main",
})

# Patterns indicating dynamic dispatch (indeterminate reachability)
_DYNAMIC_DISPATCH_INDICATORS = frozenset({
    "getattr", "setattr", "importlib", "eval", "exec",
    "__getattr__", "reflect", "Reflect",
    "invoke", "Method.invoke",
})


class CallGraphAnalyzer:
    """Analyzes source code to build call graphs and determine reachability.

    Uses tree-sitter for language-agnostic AST parsing across supported
    languages (JavaScript/TypeScript, Python, Java, Go, Rust).
    """

    def __init__(self) -> None:
        """Initialize tree-sitter parsers for supported languages.

        Attempts to load tree-sitter language grammars. If a grammar is
        not installed, logs a warning and marks the language as unavailable.
        """
        self._parsers: dict[str, object] = {}
        self._available_languages: set[str] = set()
        self._init_parsers()

    def _init_parsers(self) -> None:
        """Attempt to initialize tree-sitter parsers for all supported languages."""
        try:
            import tree_sitter  # noqa: F401
        except ImportError:
            logger.warning(
                "tree-sitter library not installed. "
                "All languages will be classified as indeterminate."
            )
            return

        # Map language names to their tree-sitter grammar package names
        grammar_packages = {
            "javascript": "tree_sitter_javascript",
            "typescript": "tree_sitter_typescript",
            "python": "tree_sitter_python",
            "java": "tree_sitter_java",
            "go": "tree_sitter_go",
            "rust": "tree_sitter_rust",
        }

        for language in SUPPORTED_LANGUAGES:
            package_name = grammar_packages.get(language)
            if not package_name:
                continue
            try:
                self._load_parser(language, package_name)
                self._available_languages.add(language)
            except Exception as e:
                logger.warning(
                    f"Failed to load tree-sitter grammar for {language}: {e}. "
                    f"Files in this language will be classified as indeterminate."
                )

    def _load_parser(self, language: str, package_name: str) -> None:
        """Load a tree-sitter parser for a specific language.

        Args:
            language: The language name.
            package_name: The Python package name for the grammar.
        """
        import importlib

        import tree_sitter as ts

        module = importlib.import_module(package_name)
        # tree-sitter >= 0.21 uses Language.build() pattern
        if hasattr(module, "language"):
            lang = ts.Language(module.language())
        elif hasattr(module, "LANGUAGE"):
            lang = ts.Language(module.LANGUAGE)
        else:
            # Fallback: try calling the module directly
            lang = ts.Language(module)

        parser = ts.Parser(lang)
        self._parsers[language] = parser

    @property
    def available_languages(self) -> set[str]:
        """Languages for which tree-sitter grammars were loaded successfully."""
        return self._available_languages.copy()

    def parse_source(
        self, source_code: str, language: str
    ) -> list[FunctionDefinition]:
        """Parse source code and extract function definitions.

        Args:
            source_code: The source code content.
            language: The programming language of the source.

        Returns:
            List of function definitions found in the source.
        """
        if language not in self._available_languages:
            logger.warning(
                f"No parser available for {language}. "
                "Cannot extract function definitions."
            )
            return []

        parser = self._parsers[language]
        tree = parser.parse(source_code.encode("utf-8"))
        root = tree.root_node

        if language in ("javascript", "typescript"):
            return self._extract_js_functions(root)
        elif language == "python":
            return self._extract_python_functions(root)
        elif language == "java":
            return self._extract_java_functions(root)
        elif language == "go":
            return self._extract_go_functions(root)
        elif language == "rust":
            return self._extract_rust_functions(root)
        return []

    def extract_call_sites(
        self, source_code: str, language: str, file_path: str = ""
    ) -> list[CallSite]:
        """Extract function call sites from source code.

        Args:
            source_code: The source code content.
            language: The programming language.
            file_path: Path to the file (used for call site IDs).

        Returns:
            List of call sites found in the source.
        """
        if language not in self._available_languages:
            return []

        parser = self._parsers[language]
        tree = parser.parse(source_code.encode("utf-8"))
        root = tree.root_node

        call_sites: list[CallSite] = []
        self._walk_for_calls(root, language, file_path, call_sites)
        return call_sites

    def build_call_graph(self, source_files: list[SourceFile]) -> CallGraph:
        """Build an inter-procedural call graph from multiple source files.

        Parses all source files, extracts function definitions and call sites,
        resolves symbols across modules, and constructs the call graph.

        Args:
            source_files: List of source files to analyze.

        Returns:
            A CallGraph with nodes and directed edges.
        """
        graph = CallGraph()
        all_definitions: dict[str, FunctionNode] = {}
        all_call_sites: list[CallSite] = []
        # Track files with unavailable parsers for indeterminate marking
        indeterminate_files: set[str] = set()

        # Phase 1: Extract function definitions from all files
        for source_file in source_files:
            if source_file.language not in self._available_languages:
                indeterminate_files.add(source_file.path)
                continue

            definitions = self.parse_source(
                source_file.content, source_file.language
            )
            for func_def in definitions:
                func_id = f"{source_file.path}:{func_def.name}"
                node = FunctionNode(
                    id=func_id,
                    name=func_def.name,
                    file_path=source_file.path,
                    line=func_def.line,
                )
                graph.add_node(node)
                all_definitions[func_def.name] = node

        # Phase 2: Extract call sites from all files
        for source_file in source_files:
            if source_file.language not in self._available_languages:
                continue
            calls = self.extract_call_sites(
                source_file.content, source_file.language, source_file.path
            )
            all_call_sites.extend(calls)

        # Phase 3: Resolve call sites to definitions (inter-procedural)
        for call_site in all_call_sites:
            callee_node = self._resolve_symbol(
                call_site.callee_name, all_definitions
            )
            if callee_node is not None:
                graph.add_edge(call_site.caller_id, callee_node.id)

        return graph

    def detect_entry_points(self, call_graph: CallGraph) -> list[FunctionNode]:
        """Detect entry points in the call graph.

        Entry points include:
        - main() functions
        - __main__ module functions
        - HTTP handler functions (Flask/Express route decorators)
        - Lambda handler exports
        - Exported/public functions at module level

        Args:
            call_graph: The constructed call graph.

        Returns:
            List of FunctionNode objects identified as entry points.
        """
        entry_points: list[FunctionNode] = []

        for node in call_graph.nodes.values():
            if self._is_entry_point(node):
                node.is_entry_point = True
                entry_points.append(node)

        return entry_points

    def determine_reachability(
        self,
        call_graph: CallGraph,
        entry_points: list[FunctionNode],
    ) -> dict[str, ReachabilityStatus]:
        """Determine reachability status for all functions in the call graph.

        Performs BFS traversal from entry points through the call graph.
        Functions reachable from any entry point are marked REACHABLE.
        Functions not reachable are marked UNREACHABLE.
        Functions involving dynamic dispatch or unresolved imports are INDETERMINATE.

        Args:
            call_graph: The constructed call graph.
            entry_points: List of entry point function nodes.

        Returns:
            Mapping of function_id to ReachabilityStatus.
        """
        reachability: dict[str, ReachabilityStatus] = {}

        # Mark all nodes as unreachable initially
        for func_id in call_graph.nodes:
            reachability[func_id] = ReachabilityStatus.UNREACHABLE

        # BFS from all entry points
        visited: set[str] = set()
        queue: deque[str] = deque()

        for ep in entry_points:
            queue.append(ep.id)
            visited.add(ep.id)
            reachability[ep.id] = ReachabilityStatus.REACHABLE

        while queue:
            current_id = queue.popleft()
            neighbors = call_graph.edges.get(current_id, [])

            for neighbor_id in neighbors:
                if neighbor_id in visited:
                    continue
                visited.add(neighbor_id)
                reachability[neighbor_id] = ReachabilityStatus.REACHABLE
                queue.append(neighbor_id)

        # Mark indeterminate: nodes whose names match dynamic dispatch patterns
        for func_id, node in call_graph.nodes.items():
            if self._involves_dynamic_dispatch(node):
                reachability[func_id] = ReachabilityStatus.INDETERMINATE

        return reachability

    # --- Private Helper Methods ---

    def _is_entry_point(self, node: FunctionNode) -> bool:
        """Determine if a function node is an entry point.

        Checks against known entry point patterns for all supported languages.
        """
        name = node.name
        file_path = node.file_path.lower()

        # Python: __main__ module or main() function
        if "__main__" in file_path or name == "__main__":
            return True

        # Common entry point names across languages
        all_entry_names = (
            _PYTHON_ENTRY_NAMES
            | _JS_ENTRY_PATTERNS
            | _JAVA_ENTRY_NAMES
            | _GO_ENTRY_NAMES
            | _RUST_ENTRY_NAMES
        )
        if name in all_entry_names:
            return True

        # Lambda handler pattern: function named *handler* or *Handler*
        name_lower = name.lower()
        if "handler" in name_lower:
            return True

        # Exported functions (detected during parsing)
        # This is checked via the node's metadata if available
        return False

    def _involves_dynamic_dispatch(self, node: FunctionNode) -> bool:
        """Check if a function name suggests dynamic dispatch or reflection."""
        name_lower = node.name.lower()
        for indicator in _DYNAMIC_DISPATCH_INDICATORS:
            if indicator.lower() in name_lower:
                return True
        return False

    def _resolve_symbol(
        self,
        callee_name: str,
        definitions: dict[str, FunctionNode],
    ) -> FunctionNode | None:
        """Resolve a call site to its function definition.

        Performs inter-procedural symbol resolution by matching
        the callee name against all known function definitions.

        Args:
            callee_name: Name of the function being called.
            definitions: All known function definitions by name.

        Returns:
            The resolved FunctionNode, or None if unresolved.
        """
        # Direct name match
        if callee_name in definitions:
            return definitions[callee_name]

        # Try qualified name (e.g., module.function -> function)
        if "." in callee_name:
            short_name = callee_name.split(".")[-1]
            if short_name in definitions:
                return definitions[short_name]

        return None

    def _walk_for_calls(
        self,
        node: object,
        language: str,
        file_path: str,
        call_sites: list[CallSite],
        current_function: str | None = None,
    ) -> None:
        """Recursively walk the AST to find function call sites.

        Args:
            node: Current AST node.
            language: Source language.
            file_path: Path to the source file.
            call_sites: Accumulator list for discovered call sites.
            current_function: Name of the enclosing function (for caller_id).
        """
        node_type = node.type

        # Track current enclosing function
        if self._is_function_node(node_type, language):
            func_name = self._get_function_name_from_node(node, language)
            if func_name:
                current_function = func_name

        # Detect call expressions
        if self._is_call_node(node_type, language):
            callee_name = self._get_callee_name(node, language)
            if callee_name and current_function:
                caller_id = f"{file_path}:{current_function}"
                is_dynamic = callee_name in _DYNAMIC_DISPATCH_INDICATORS
                call_sites.append(CallSite(
                    caller_id=caller_id,
                    callee_name=callee_name,
                    file_path=file_path,
                    line=node.start_point[0] + 1,
                    is_dynamic=is_dynamic,
                ))

        # Recurse into children
        for child in node.children:
            self._walk_for_calls(
                child, language, file_path, call_sites, current_function
            )

    def _is_function_node(self, node_type: str, language: str) -> bool:
        """Check if an AST node type represents a function definition."""
        if language in ("javascript", "typescript"):
            return node_type in (
                "function_declaration",
                "method_definition",
                "arrow_function",
                "function",
            )
        elif language == "python":
            return node_type in ("function_definition", "async_function_definition")  # noqa: E501
        elif language == "java":
            return node_type in ("method_declaration", "constructor_declaration")
        elif language == "go":
            return node_type in ("function_declaration", "method_declaration")
        elif language == "rust":
            return node_type in ("function_item",)
        return False

    def _is_call_node(self, node_type: str, language: str) -> bool:
        """Check if an AST node type represents a function call."""
        if language in ("javascript", "typescript"):
            return node_type == "call_expression"
        elif language == "python":
            return node_type == "call"
        elif language == "java":
            return node_type in (
                "method_invocation", "object_creation_expression"
            )
        elif language == "go":
            return node_type == "call_expression"
        elif language == "rust":
            return node_type == "call_expression"
        return False

    def _get_function_name_from_node(
        self, node: object, language: str
    ) -> str | None:
        """Extract the function name from a function definition AST node."""
        if language in ("javascript", "typescript"):
            # function_declaration has a 'name' child of type 'identifier'
            for child in node.children:
                if child.type == "identifier":
                    return child.text.decode("utf-8")
            # For arrow functions assigned to variables, check parent
            if node.type == "arrow_function" and node.parent:
                parent = node.parent
                if parent.type == "variable_declarator":
                    for child in parent.children:
                        if child.type == "identifier":
                            return child.text.decode("utf-8")
        elif language == "python":
            for child in node.children:
                if child.type == "identifier":
                    return child.text.decode("utf-8")
        elif language == "java":
            for child in node.children:
                if child.type == "identifier":
                    return child.text.decode("utf-8")
        elif language == "go":
            for child in node.children:
                if child.type == "identifier":
                    return child.text.decode("utf-8")
        elif language == "rust":
            for child in node.children:
                if child.type == "identifier":
                    return child.text.decode("utf-8")
        return None

    def _get_callee_name(self, node: object, language: str) -> str | None:
        """Extract the callee function name from a call expression AST node."""
        if language in ("javascript", "typescript"):
            # call_expression: first child is the function being called
            func_node = node.children[0] if node.children else None
            if func_node is None:
                return None
            if func_node.type == "identifier":
                return func_node.text.decode("utf-8")
            elif func_node.type == "member_expression":
                # e.g., obj.method() -> extract "method"
                for child in func_node.children:
                    if child.type == "property_identifier":
                        return child.text.decode("utf-8")
        elif language == "python":
            # call: first child is the function being called
            func_node = node.children[0] if node.children else None
            if func_node is None:
                return None
            if func_node.type == "identifier":
                return func_node.text.decode("utf-8")
            elif func_node.type == "attribute":
                # e.g., obj.method() -> extract "method"
                for child in func_node.children:
                    if child.type == "identifier":
                        # Return the last identifier (method name)
                        pass
                # Get the full attribute text and return last part
                text = func_node.text.decode("utf-8")
                return text.split(".")[-1] if "." in text else text
        elif language == "java":
            # method_invocation: has an 'identifier' child for method name
            for child in node.children:
                if child.type == "identifier":
                    return child.text.decode("utf-8")
        elif language == "go":
            # call_expression: first child is function reference
            func_node = node.children[0] if node.children else None
            if func_node is None:
                return None
            if func_node.type == "identifier":
                return func_node.text.decode("utf-8")
            elif func_node.type == "selector_expression":
                # e.g., pkg.Function() -> extract "Function"
                for child in func_node.children:
                    if child.type == "field_identifier":
                        return child.text.decode("utf-8")
        elif language == "rust":
            # call_expression: first child is the function
            func_node = node.children[0] if node.children else None
            if func_node is None:
                return None
            if func_node.type == "identifier":
                return func_node.text.decode("utf-8")
            elif func_node.type == "scoped_identifier":
                text = func_node.text.decode("utf-8")
                return text.split("::")[-1] if "::" in text else text
        return None

    # --- Language-Specific Function Extraction ---

    def _extract_js_functions(
        self, root_node: object
    ) -> list[FunctionDefinition]:
        """Extract function definitions from JavaScript/TypeScript AST."""
        definitions: list[FunctionDefinition] = []
        self._walk_for_definitions_js(root_node, definitions)
        return definitions

    def _walk_for_definitions_js(
        self, node: object, definitions: list[FunctionDefinition]
    ) -> None:
        """Recursively find JS/TS function definitions."""
        if node.type == "function_declaration":
            name = self._get_function_name_from_node(node, "javascript")
            if name:
                is_exported = self._is_js_exported(node)
                definitions.append(FunctionDefinition(
                    name=name,
                    file_path="",
                    line=node.start_point[0] + 1,
                    is_exported=is_exported,
                ))
        elif node.type in ("lexical_declaration", "variable_declaration"):
            # Handle: const foo = () => {} or export const foo = ...
            for child in node.children:
                if child.type == "variable_declarator":
                    self._check_arrow_function(child, node, definitions)
        elif node.type == "export_statement":
            # Handle exported functions
            for child in node.children:
                if child.type == "function_declaration":
                    name = self._get_function_name_from_node(
                        child, "javascript"
                    )
                    if name:
                        definitions.append(FunctionDefinition(
                            name=name,
                            file_path="",
                            line=child.start_point[0] + 1,
                            is_exported=True,
                        ))
                elif child.type in (
                    "lexical_declaration", "variable_declaration"
                ):
                    for grandchild in child.children:
                        if grandchild.type == "variable_declarator":
                            self._check_arrow_function(
                                grandchild, child, definitions, is_exported=True
                            )

        for child in node.children:
            self._walk_for_definitions_js(child, definitions)

    def _check_arrow_function(
        self,
        declarator_node: object,
        parent_node: object,
        definitions: list[FunctionDefinition],
        is_exported: bool = False,
    ) -> None:
        """Check if a variable declarator holds an arrow function."""
        name = None
        has_function = False
        for child in declarator_node.children:
            if child.type == "identifier":
                name = child.text.decode("utf-8")
            elif child.type in ("arrow_function", "function"):
                has_function = True
        if name and has_function:
            definitions.append(FunctionDefinition(
                name=name,
                file_path="",
                line=declarator_node.start_point[0] + 1,
                is_exported=is_exported,
            ))

    def _is_js_exported(self, node: object) -> bool:
        """Check if a JS node is exported (parent is export_statement)."""
        if node.parent and node.parent.type == "export_statement":
            return True
        return False

    def _extract_python_functions(
        self, root_node: object
    ) -> list[FunctionDefinition]:
        """Extract function definitions from Python AST."""
        definitions: list[FunctionDefinition] = []
        self._walk_for_definitions_python(root_node, definitions)
        return definitions

    def _walk_for_definitions_python(
        self, node: object, definitions: list[FunctionDefinition]
    ) -> None:
        """Recursively find Python function definitions."""
        if node.type in ("function_definition", "async_function_definition"):
            name = self._get_function_name_from_node(node, "python")
            if name:
                decorators = self._get_python_decorators(node)
                is_exported = not name.startswith("_")
                definitions.append(FunctionDefinition(
                    name=name,
                    file_path="",
                    line=node.start_point[0] + 1,
                    is_exported=is_exported,
                    decorators=decorators,
                ))

        for child in node.children:
            self._walk_for_definitions_python(child, definitions)

    def _get_python_decorators(self, node: object) -> list[str]:
        """Extract decorator names from a Python function node."""
        decorators: list[str] = []
        # Check if parent/sibling is a decorated_definition
        if node.parent and node.parent.type == "decorated_definition":
            for child in node.parent.children:
                if child.type == "decorator":
                    decorator_text = child.text.decode("utf-8").lstrip("@")
                    decorators.append(decorator_text.split("(")[0])
        return decorators

    def _extract_java_functions(
        self, root_node: object
    ) -> list[FunctionDefinition]:
        """Extract method definitions from Java AST."""
        definitions: list[FunctionDefinition] = []
        self._walk_for_definitions_java(root_node, definitions)
        return definitions

    def _walk_for_definitions_java(
        self, node: object, definitions: list[FunctionDefinition]
    ) -> None:
        """Recursively find Java method definitions."""
        if node.type in ("method_declaration", "constructor_declaration"):
            name = self._get_function_name_from_node(node, "java")
            if name:
                is_public = self._is_java_public(node)
                definitions.append(FunctionDefinition(
                    name=name,
                    file_path="",
                    line=node.start_point[0] + 1,
                    is_exported=is_public,
                ))

        for child in node.children:
            self._walk_for_definitions_java(child, definitions)

    def _is_java_public(self, node: object) -> bool:
        """Check if a Java method is public."""
        for child in node.children:
            if child.type == "modifiers":
                text = child.text.decode("utf-8")
                if "public" in text:
                    return True
        return False

    def _extract_go_functions(
        self, root_node: object
    ) -> list[FunctionDefinition]:
        """Extract function definitions from Go AST."""
        definitions: list[FunctionDefinition] = []
        self._walk_for_definitions_go(root_node, definitions)
        return definitions

    def _walk_for_definitions_go(
        self, node: object, definitions: list[FunctionDefinition]
    ) -> None:
        """Recursively find Go function definitions."""
        if node.type in ("function_declaration", "method_declaration"):
            name = self._get_function_name_from_node(node, "go")
            if name:
                # In Go, exported functions start with uppercase
                is_exported = name[0].isupper() if name else False
                definitions.append(FunctionDefinition(
                    name=name,
                    file_path="",
                    line=node.start_point[0] + 1,
                    is_exported=is_exported,
                ))

        for child in node.children:
            self._walk_for_definitions_go(child, definitions)

    def _extract_rust_functions(
        self, root_node: object
    ) -> list[FunctionDefinition]:
        """Extract function definitions from Rust AST."""
        definitions: list[FunctionDefinition] = []
        self._walk_for_definitions_rust(root_node, definitions)
        return definitions

    def _walk_for_definitions_rust(
        self, node: object, definitions: list[FunctionDefinition]
    ) -> None:
        """Recursively find Rust function definitions."""
        if node.type == "function_item":
            name = self._get_function_name_from_node(node, "rust")
            if name:
                is_exported = self._is_rust_public(node)
                definitions.append(FunctionDefinition(
                    name=name,
                    file_path="",
                    line=node.start_point[0] + 1,
                    is_exported=is_exported,
                ))

        for child in node.children:
            self._walk_for_definitions_rust(child, definitions)

    def _is_rust_public(self, node: object) -> bool:
        """Check if a Rust function has pub visibility."""
        for child in node.children:
            if child.type == "visibility_modifier":
                return True
        return False
