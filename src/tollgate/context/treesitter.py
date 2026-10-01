"""Enclosing symbol and import extraction for the grammar bundle in ADR 0002."""

from __future__ import annotations

from functools import lru_cache

from tree_sitter import Language, Node, Parser

from tollgate.context.fallback import fallback_context
from tollgate.models import Hunk

_ENCLOSING: dict[str, set[str]] = {
    "python": {"function_definition", "class_definition"},
    "javascript": {
        "function_declaration",
        "class_declaration",
        "method_definition",
        "arrow_function",
    },
    "typescript": {
        "function_declaration",
        "class_declaration",
        "method_definition",
        "arrow_function",
    },
    "java": {"method_declaration", "constructor_declaration", "class_declaration"},
    "go": {"function_declaration", "method_declaration", "type_declaration"},
    "csharp": {"method_declaration", "class_declaration", "constructor_declaration"},
}
_IMPORTS: dict[str, set[str]] = {
    "python": {"import_statement", "import_from_statement"},
    "javascript": {"import_statement"},
    "typescript": {"import_statement"},
    "java": {"import_declaration", "package_declaration"},
    "go": {"import_declaration", "package_clause"},
    "csharp": {"using_directive"},
}


def structural_context(language: str, source: str, hunks: tuple[Hunk, ...]) -> str:
    """Return import and enclosing-symbol text, or the fallback window."""
    if language not in _ENCLOSING:
        return fallback_context(source, hunks)
    tree = _parse(language, source)
    if tree is None:
        return fallback_context(source, hunks)
    source_bytes = source.encode("utf-8", errors="replace")
    imports = _nodes_of(tree, _IMPORTS[language])
    import_text = "\n".join(_snippet(source_bytes, node) for node in imports[:40])
    sections = [f"imports:\n{import_text}".rstrip()]
    for hunk in hunks:
        line = hunk.new_start or 1
        node = _smallest_enclosing(tree, line, _ENCLOSING[language])
        if node is None:
            sections.append(fallback_context(source, (hunk,)))
            continue
        start = node.start_point[0] + 1
        end = node.end_point[0] + 1
        sections.append(
            f"enclosing {node.type} lines {start}-{end}:\n{_snippet(source_bytes, node)}"
        )
    return "\n".join(sections)


def _parse(language: str, source: str) -> Node | None:
    try:
        parser = _parser(language)
        tree = parser.parse(source.encode("utf-8", errors="replace"))
    except Exception:
        return None
    root = tree.root_node
    if root.type == "ERROR":
        return None
    return root


@lru_cache(maxsize=8)
def _parser(language: str) -> Parser:
    return Parser(Language(_language_pointer(language)))


def _language_pointer(language: str) -> object:
    if language == "python":
        import tree_sitter_python

        return tree_sitter_python.language()
    if language == "javascript":
        import tree_sitter_javascript

        return tree_sitter_javascript.language()
    if language == "typescript":
        import tree_sitter_typescript

        return tree_sitter_typescript.language_typescript()
    if language == "java":
        import tree_sitter_java

        return tree_sitter_java.language()
    if language == "go":
        import tree_sitter_go

        return tree_sitter_go.language()
    if language == "csharp":
        import tree_sitter_c_sharp

        return tree_sitter_c_sharp.language()
    raise ValueError(language)


def _nodes_of(node: Node, types: set[str]) -> list[Node]:
    found: list[Node] = []

    def walk(current: Node) -> None:
        if current.type in types:
            found.append(current)
            return
        for child in current.children:
            walk(child)

    walk(node)
    return found


def _smallest_enclosing(node: Node, line: int, types: set[str]) -> Node | None:
    match: Node | None = None
    candidates = _nodes_of(node, types)
    for candidate in candidates:
        start = candidate.start_point[0] + 1
        end = candidate.end_point[0] + 1
        if start <= line <= end and (match is None or _span(candidate) < _span(match)):
            match = candidate
    return match


def _span(node: Node) -> int:
    return node.end_byte - node.start_byte


def _snippet(source: bytes, node: Node) -> str:
    text = source[node.start_byte : node.end_byte].decode("utf-8", errors="replace")
    lines = text.splitlines()
    if len(lines) > 200:
        lines = [*lines[:200], "..."]
    return "\n".join(lines)
