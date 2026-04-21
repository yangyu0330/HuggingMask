"""AST candidate extraction for stage-4 code-validation scope.

This module only parses source text with ``ast.parse()`` and extracts static
candidates. It does not import or execute model code, does not run whitelist
policy decisions, and does not assign final grades.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field


_DANGEROUS_IMPORT_ROOTS = {"subprocess", "socket", "requests", "urllib", "httpx"}
_DANGEROUS_CALL_LEAVES = {"eval", "exec", "compile", "__import__"}
_DANGEROUS_EXACT_CALLS = {"os.system", "os.popen", "torch.load", "pickle.load", "numpy.load"}
_DANGEROUS_PREFIX_CALLS = ("subprocess.", "os.exec", "os.spawn")
_DYNAMIC_CALL_LEAVES = {"getattr", "setattr", "delattr", "globals", "locals"}
_OBFUSCATION_CALL_LEAVES = {"chr", "ord"}


@dataclass
class AstScanResult:
    repo_path: str
    imports: list[str] = field(default_factory=list)
    functions: list[str] = field(default_factory=list)
    methods: list[str] = field(default_factory=list)
    classes: list[str] = field(default_factory=list)
    base_classes: list[str] = field(default_factory=list)
    method_flags: dict[str, bool] = field(
        default_factory=lambda: {
            "has_init": False,
            "has_forward": False,
            "has_generate": False,
            "has_call": False,
        }
    )
    raw_api_calls: list[str] = field(default_factory=list)
    dangerous_imports: list[str] = field(default_factory=list)
    dangerous_calls: list[str] = field(default_factory=list)
    dynamic_patterns: list[str] = field(default_factory=list)
    obfuscation_patterns: list[str] = field(default_factory=list)
    contextual_api_candidates: list[str] = field(default_factory=list)
    parse_error: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "repo_path": self.repo_path,
            "imports": list(self.imports),
            "functions": list(self.functions),
            "methods": list(self.methods),
            "classes": list(self.classes),
            "base_classes": list(self.base_classes),
            "method_flags": dict(self.method_flags),
            "raw_api_calls": list(self.raw_api_calls),
            "dangerous_imports": list(self.dangerous_imports),
            "dangerous_calls": list(self.dangerous_calls),
            "dynamic_patterns": list(self.dynamic_patterns),
            "obfuscation_patterns": list(self.obfuscation_patterns),
            "contextual_api_candidates": list(self.contextual_api_candidates),
            "parse_error": self.parse_error,
        }


def extract_ast_candidates(repo_path: str, source: str | bytes) -> AstScanResult:
    source_text = source.decode("utf-8", errors="replace") if isinstance(source, bytes) else source

    try:
        tree = ast.parse(source_text)
    except SyntaxError as exc:
        return AstScanResult(repo_path=repo_path, parse_error=str(exc))

    alias_map, imports = _build_alias_map_and_imports(tree)

    result = AstScanResult(repo_path=repo_path)
    result.imports = sorted(imports)
    result.dangerous_imports = sorted(
        {
            imported_root
            for imported in imports
            for imported_root in [imported.split(".", 1)[0]]
            if imported_root in _DANGEROUS_IMPORT_ROOTS
        }
    )

    class_methods: set[str] = set()
    classes: set[str] = set()
    base_classes: set[str] = set()
    functions: set[str] = set()
    raw_api_calls: set[str] = set()
    dangerous_calls: set[str] = set()
    dynamic_patterns: set[str] = set()
    obfuscation_patterns: set[str] = set()
    contextual_candidates: set[str] = set()

    for stmt in tree.body:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            functions.add(stmt.name)
        elif isinstance(stmt, ast.ClassDef):
            classes.add(stmt.name)
            for base in stmt.bases:
                base_name = _resolve_alias(_dotted_name(base), alias_map)
                if base_name:
                    base_classes.add(base_name)
            for child in stmt.body:
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    method_name = f"{stmt.name}.{child.name}"
                    class_methods.add(method_name)
                    if child.name == "__init__":
                        result.method_flags["has_init"] = True
                    elif child.name == "forward":
                        result.method_flags["has_forward"] = True
                    elif child.name == "generate":
                        result.method_flags["has_generate"] = True
                    elif child.name == "__call__":
                        result.method_flags["has_call"] = True

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        raw_name = _call_name(node.func)
        if not raw_name:
            continue

        raw_api_calls.add(raw_name)
        resolved_name = _resolve_alias(raw_name, alias_map)
        leaf = resolved_name.split(".")[-1]

        if leaf in _DANGEROUS_CALL_LEAVES:
            dangerous_calls.add(resolved_name)
        if resolved_name in _DANGEROUS_EXACT_CALLS:
            dangerous_calls.add(resolved_name)
        if resolved_name.startswith(_DANGEROUS_PREFIX_CALLS):
            dangerous_calls.add(resolved_name)

        if leaf in _DYNAMIC_CALL_LEAVES:
            dynamic_patterns.add(resolved_name)
        if leaf == "type" and _is_three_arg_type_call(node):
            dynamic_patterns.add("type(name,bases,dict)")
        if _contains_dunder_dict_access(node):
            dynamic_patterns.add("__dict___access")

        if leaf in _OBFUSCATION_CALL_LEAVES:
            obfuscation_patterns.add(leaf)
        if _is_bytes_decode_pattern(node):
            obfuscation_patterns.add("bytes.decode")

        contextual = _contextual_candidate_name(raw_name, resolved_name)
        if contextual is not None:
            contextual_candidates.add(contextual)

    if _contains_conditional_import(tree):
        dynamic_patterns.add("conditional_import")

    result.classes = sorted(classes)
    result.base_classes = sorted(base_classes)
    result.functions = sorted(functions)
    result.methods = sorted(class_methods)
    result.raw_api_calls = sorted(raw_api_calls)
    result.dangerous_calls = sorted(dangerous_calls)
    result.dynamic_patterns = sorted(dynamic_patterns)
    result.obfuscation_patterns = sorted(obfuscation_patterns)
    result.contextual_api_candidates = sorted(contextual_candidates)

    return result


def _build_alias_map_and_imports(tree: ast.AST) -> tuple[dict[str, str], set[str]]:
    alias_map: dict[str, str] = {}
    imports: set[str] = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.add(alias.name)
                alias_map[alias.asname or alias.name.split(".", 1)[0]] = alias.name
        elif isinstance(node, ast.ImportFrom):
            if not node.module:
                continue
            imports.add(node.module)
            for alias in node.names:
                if alias.name == "*":
                    continue
                alias_map[alias.asname or alias.name] = f"{node.module}.{alias.name}"

    return alias_map, imports


def _dotted_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _dotted_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Call):
        parent = _dotted_name(node.value.func)
        return f"{parent}.{node.attr}" if parent else node.attr
    return _dotted_name(node)


def _resolve_alias(path: str, alias_map: dict[str, str]) -> str:
    if not path:
        return ""
    if "." not in path:
        return alias_map.get(path, path)
    root, rest = path.split(".", 1)
    if root in alias_map:
        return f"{alias_map[root]}.{rest}"
    return path


def _is_three_arg_type_call(node: ast.Call) -> bool:
    return (
        isinstance(node.func, ast.Name)
        and node.func.id == "type"
        and len(node.args) >= 3
    )


def _contains_conditional_import(tree: ast.AST) -> bool:
    for node in ast.walk(tree):
        if not isinstance(node, ast.If):
            continue
        for child in ast.walk(node):
            if child is node:
                continue
            if isinstance(child, (ast.Import, ast.ImportFrom)):
                return True
    return False


def _contains_dunder_dict_access(node: ast.Call) -> bool:
    for child in ast.walk(node):
        if isinstance(child, ast.Attribute) and child.attr == "__dict__":
            return True
    return False


def _is_bytes_decode_pattern(node: ast.Call) -> bool:
    if not isinstance(node.func, ast.Attribute):
        return False
    if node.func.attr != "decode":
        return False
    value = node.func.value
    if isinstance(value, ast.Call):
        return _dotted_name(value.func) == "bytes"
    return isinstance(value, ast.Constant) and isinstance(value.value, bytes)


def _contextual_candidate_name(raw_name: str, resolved_name: str) -> str | None:
    if resolved_name == "open":
        return "open"
    if resolved_name in {"pathlib.Path.open", "Path.open"} or raw_name.endswith("Path.open"):
        return "Path.open"
    if resolved_name in {"pathlib.Path.read_text", "Path.read_text"} or raw_name.endswith("Path.read_text"):
        return "Path.read_text"
    if resolved_name.startswith("os.path."):
        return resolved_name
    if resolved_name == "os.getenv":
        return "os.getenv"
    if resolved_name == "os.environ.get":
        return "os.environ.get"
    return None
