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
_CONFIG_BASE_SUFFIXES = ("PretrainedConfig",)
_MODELING_BASE_SUFFIXES = ("Module", "PreTrainedModel")
_CONFIG_EXECUTION_METHODS = {"forward", "generate", "__call__"}
_CONFIG_DISALLOWED_CALL_ROOTS = {"importlib"}


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
    configuration_metadata: dict[str, object] = field(default_factory=dict)
    parse_error: str | None = None

    def to_dict(self) -> dict[str, object]:
        inherits_pretrained_config = bool(self.configuration_metadata.get("inherits_pretrained_config") is True)
        inherits_nn_module = any(base.endswith(_MODELING_BASE_SUFFIXES) for base in self.base_classes)
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
            "contextual_call_candidates": list(self.contextual_api_candidates),
            "has_forward_method": bool(self.method_flags.get("has_forward")),
            "inherits_pretrained_config": inherits_pretrained_config,
            "inherits_nn_module": inherits_nn_module,
            "configuration_metadata": dict(self.configuration_metadata),
            "parse_error": self.parse_error,
        }


def extract_ast_candidates(repo_path: str, source: str | bytes) -> AstScanResult:
    source_text = source.decode("utf-8", errors="replace") if isinstance(source, bytes) else source

    try:
        tree = ast.parse(source_text)
    except SyntaxError as exc:
        return AstScanResult(repo_path=repo_path, parse_error=str(exc))

    alias_map, imports = _build_alias_map_and_imports(tree)
    var_alias = _build_var_alias(tree, alias_map)

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
        if _is_super_init_call(node):
            continue
        raw_name = _call_name(node.func)
        if not raw_name:
            continue
        if raw_name == "super":
            continue

        raw_api_calls.add(raw_name)
        resolved_name = _resolve_alias(raw_name, alias_map)
        # 변수 별칭 역추적: ``s = os.system; s(cmd)`` → resolved_name "s" → "os.system"
        resolved_name = var_alias.get(resolved_name, resolved_name)
        leaf = resolved_name.split(".")[-1]

        if leaf in _DANGEROUS_CALL_LEAVES:
            dangerous_calls.add(resolved_name)
        if resolved_name in _DANGEROUS_EXACT_CALLS:
            dangerous_calls.add(resolved_name)
        if resolved_name.startswith(_DANGEROUS_PREFIX_CALLS):
            dangerous_calls.add(resolved_name)

        # getattr(obj, "name") / getattr(obj, "sys"+"tem") → obj.name 으로 해소해
        # 위험 호출 탐지(표적 우회를 dynamic/PENDING이 아니라 BLOCK으로 끌어올림).
        getattr_target, string_built = _resolve_getattr_target(node, alias_map, var_alias)
        if getattr_target is not None:
            raw_api_calls.add(getattr_target)
            g_leaf = getattr_target.split(".")[-1]
            if (
                g_leaf in _DANGEROUS_CALL_LEAVES
                or getattr_target in _DANGEROUS_EXACT_CALLS
                or getattr_target.startswith(_DANGEROUS_PREFIX_CALLS)
            ):
                dangerous_calls.add(getattr_target)
        if string_built:
            # 함수/속성명을 문자열로 조립하는 것 자체가 난독화 신호
            obfuscation_patterns.add("getattr_string_concat")

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
    result.configuration_metadata = _extract_configuration_metadata(
        tree=tree,
        alias_map=alias_map,
        repo_path=repo_path,
    )

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


# ─────────────────────────────────────────────
# 데이터플로우 보강 — 표적 우회(별칭/getattr/문자열조립)를 정적 정확매칭으로 해소
# ─────────────────────────────────────────────

def _fold_str(node: ast.AST) -> str | None:
    """문자열 상수 또는 상수들의 ``+`` 연결을 접어 값으로 반환. 아니면 None.

    ``"sys" + "tem"`` → ``"system"`` 처럼 함수명을 문자열로 조립해 탐지를
    우회하는 패턴을 풀어낸다.
    """
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _fold_str(node.left)
        right = _fold_str(node.right)
        if left is not None and right is not None:
            return left + right
    return None


def _build_var_alias(tree: ast.AST, alias_map: dict[str, str]) -> dict[str, str]:
    """단순 변수 별칭 추적: ``s = os.system`` / ``e = eval`` → {s: os.system, e: eval}.

    flow-insensitive(마지막 대입 기준)지만, 위험 함수를 변수에 담아 호출하는
    표적 우회(``s = os.system; s(cmd)``)를 정적 정확매칭으로 끌어올린다.
    """
    var_alias: dict[str, str] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if not isinstance(target, ast.Name) or not isinstance(node.value, (ast.Name, ast.Attribute)):
            continue
        dotted = _resolve_alias(_dotted_name(node.value), alias_map)
        if dotted and dotted != target.id:
            var_alias[target.id] = dotted
    return var_alias


def _resolve_getattr_target(
    node: ast.Call, alias_map: dict[str, str], var_alias: dict[str, str]
) -> tuple[str | None, bool]:
    """``getattr(obj, "name")`` → ``obj.name`` 으로 해소.

    Returns ``(resolved_dotted_or_None, string_built)``. string_built=True면 attr가
    문자열 상수 연결로 조립된 경우(난독화 신호). attr가 비상수(동적)면 해소 불가.
    """
    func = node.func
    if not (isinstance(func, ast.Name) and func.id == "getattr") or len(node.args) < 2:
        return None, False
    obj_name = _resolve_alias(_dotted_name(node.args[0]), alias_map)
    obj_name = var_alias.get(obj_name, obj_name)
    attr = _fold_str(node.args[1])
    string_built = isinstance(node.args[1], ast.BinOp)
    if not obj_name or attr is None:
        return None, string_built
    return f"{obj_name}.{attr}", string_built


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


def _extract_configuration_metadata(
    *,
    tree: ast.Module,
    alias_map: dict[str, str],
    repo_path: str,
) -> dict[str, object]:
    class_defs = [stmt for stmt in tree.body if isinstance(stmt, ast.ClassDef)]
    file_hint = _is_configuration_file_hint(repo_path)
    selected = _select_configuration_candidate(class_defs, alias_map=alias_map, file_hint=file_hint)
    top_level_reasons = _top_level_block_reasons(tree)

    metadata: dict[str, object] = {
        "class_name": None,
        "base_classes": [],
        "model_type": None,
        "init_parameters": [],
        "assigned_attributes": [],
        "attribute_map": None,
        "inherits_pretrained_config": False,
        "config_regenerable": False,
        "config_regeneration_block_reasons": [],
    }

    reasons: list[str] = list(top_level_reasons)
    if selected is None:
        reasons.append("no_config_class_candidate")
        metadata["config_regeneration_block_reasons"] = _dedupe(reasons)
        return metadata

    class_node, base_classes = selected
    metadata["class_name"] = class_node.name
    metadata["base_classes"] = list(base_classes)
    metadata["inherits_pretrained_config"] = any(base.endswith(_CONFIG_BASE_SUFFIXES) for base in base_classes)

    model_type, has_model_type = _extract_class_attribute_value(class_node, "model_type")
    metadata["model_type"] = model_type if has_model_type else None
    if not metadata["inherits_pretrained_config"]:
        reasons.append("class_not_inheriting_pretrained_config")
    if not has_model_type:
        reasons.append("missing_model_type_class_attribute")

    attribute_map, has_attribute_map = _extract_class_attribute_value(class_node, "attribute_map")
    if has_attribute_map:
        metadata["attribute_map"] = attribute_map

    methods = {
        child.name: child
        for child in class_node.body
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    execution_methods = sorted(method_name for method_name in methods if method_name in _CONFIG_EXECUTION_METHODS)
    if execution_methods:
        reasons.append(f"execution_methods_present:{','.join(execution_methods)}")

    init_node = methods.get("__init__")
    if init_node is None:
        reasons.append("missing_init_method")
        metadata["config_regeneration_block_reasons"] = _dedupe(reasons)
        return metadata

    init_parameters = _function_parameter_names(init_node)
    metadata["init_parameters"] = list(init_parameters)
    init_ok, init_reasons, assigned_attrs = _analyze_init_method(
        init_node,
        init_parameters=init_parameters,
        alias_map=alias_map,
    )
    metadata["assigned_attributes"] = sorted(assigned_attrs)
    if not init_ok:
        reasons.extend(init_reasons)

    deduped_reasons = _dedupe(reasons)
    metadata["config_regeneration_block_reasons"] = deduped_reasons
    metadata["config_regenerable"] = not deduped_reasons
    return metadata


def _select_configuration_candidate(
    class_defs: list[ast.ClassDef],
    *,
    alias_map: dict[str, str],
    file_hint: bool,
) -> tuple[ast.ClassDef, list[str]] | None:
    if not class_defs:
        return None

    analyzed: list[tuple[ast.ClassDef, list[str]]] = []
    for class_node in class_defs:
        base_classes = [
            _resolve_alias(_dotted_name(base), alias_map)
            for base in class_node.bases
            if _dotted_name(base)
        ]
        analyzed.append((class_node, base_classes))

    for class_node, base_classes in analyzed:
        if any(base.endswith(_CONFIG_BASE_SUFFIXES) for base in base_classes):
            return class_node, base_classes

    if file_hint:
        return analyzed[0]
    return None


def _is_configuration_file_hint(repo_path: str) -> bool:
    normalized = str(repo_path).replace("\\", "/")
    file_name = normalized.rsplit("/", 1)[-1].lower()
    return file_name.startswith("configuration_") or file_name == "generation_config.py"


def _top_level_block_reasons(tree: ast.Module) -> list[str]:
    reasons: list[str] = []
    for index, stmt in enumerate(tree.body):
        if index == 0 and _is_docstring_expr(stmt):
            continue
        if isinstance(stmt, (ast.Import, ast.ImportFrom, ast.ClassDef, ast.Pass)):
            continue
        if isinstance(stmt, ast.Assign):
            if _is_constant_assignment(stmt.targets, stmt.value):
                continue
            reasons.append("top_level_non_constant_assignment")
            continue
        if isinstance(stmt, ast.AnnAssign):
            if _is_constant_assignment([stmt.target], stmt.value):
                continue
            reasons.append("top_level_non_constant_assignment")
            continue
        reasons.append(f"top_level_executable_statement:{type(stmt).__name__}")
    return _dedupe(reasons)


def _is_docstring_expr(stmt: ast.stmt) -> bool:
    return (
        isinstance(stmt, ast.Expr)
        and isinstance(stmt.value, ast.Constant)
        and isinstance(stmt.value.value, str)
    )


def _is_constant_assignment(targets: list[ast.expr], value: ast.expr | None) -> bool:
    if value is None:
        return False
    if not all(isinstance(target, ast.Name) for target in targets):
        return False
    return _is_simple_literal(value)


def _is_simple_literal(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.UAdd, ast.USub)):
        return _is_simple_literal(node.operand)
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return all(_is_simple_literal(item) for item in node.elts)
    if isinstance(node, ast.Dict):
        return all(
            (key is None or _is_simple_literal(key))
            and (value is None or _is_simple_literal(value))
            for key, value in zip(node.keys, node.values, strict=False)
        )
    return False


def _extract_class_attribute_value(class_node: ast.ClassDef, attr_name: str) -> tuple[object | None, bool]:
    for child in class_node.body:
        if isinstance(child, ast.Assign):
            if len(child.targets) != 1 or not isinstance(child.targets[0], ast.Name):
                continue
            if child.targets[0].id != attr_name:
                continue
            value, parsed = _parse_literal_value(child.value)
            return (value if parsed else _node_repr(child.value)), True
        if isinstance(child, ast.AnnAssign):
            if not isinstance(child.target, ast.Name) or child.target.id != attr_name:
                continue
            if child.value is None:
                return None, True
            value, parsed = _parse_literal_value(child.value)
            return (value if parsed else _node_repr(child.value)), True
    return None, False


def _function_parameter_names(node: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    names: list[str] = []
    positional = list(node.args.posonlyargs) + list(node.args.args)
    for index, arg in enumerate(positional):
        if index == 0 and arg.arg == "self":
            continue
        names.append(arg.arg)
    for arg in node.args.kwonlyargs:
        names.append(arg.arg)
    if node.args.vararg is not None:
        names.append(node.args.vararg.arg)
    if node.args.kwarg is not None:
        names.append(node.args.kwarg.arg)
    return names


def _analyze_init_method(
    init_node: ast.FunctionDef | ast.AsyncFunctionDef,
    *,
    init_parameters: list[str],
    alias_map: dict[str, str],
) -> tuple[bool, list[str], set[str]]:
    reasons: list[str] = []
    assigned_attrs: set[str] = set()
    allowed_param_names = set(init_parameters)

    for stmt in init_node.body:
        if _is_docstring_expr(stmt):
            continue
        if isinstance(stmt, ast.Pass):
            continue
        if _is_super_init_statement(stmt, allowed_param_names):
            continue
        if _is_self_assignment_statement(stmt, allowed_param_names, assigned_attrs):
            continue
        reasons.append(f"init_unsupported_statement:{type(stmt).__name__}")

    for node in ast.walk(init_node):
        if not isinstance(node, ast.Call):
            continue
        if _is_super_init_call(node, allowed_param_names):
            continue
        call_name = _call_name(node.func)
        if call_name == "super":
            continue
        resolved = _resolve_alias(call_name, alias_map)
        if not resolved:
            reasons.append("init_disallowed_call:<unknown>")
            continue
        reasons.append(f"init_disallowed_call:{resolved}")
        root = resolved.split(".", 1)[0]
        if root in _CONFIG_DISALLOWED_CALL_ROOTS:
            reasons.append("init_disallowed_dynamic_import")

    return (len(reasons) == 0), _dedupe(reasons), assigned_attrs


def _is_super_init_statement(stmt: ast.stmt, allowed_param_names: set[str]) -> bool:
    if not isinstance(stmt, ast.Expr) or not isinstance(stmt.value, ast.Call):
        return False
    return _is_super_init_call(stmt.value, allowed_param_names)


def _is_super_init_call(node: ast.Call, allowed_param_names: set[str] | None = None) -> bool:
    if not isinstance(node.func, ast.Attribute):
        return False
    if node.func.attr != "__init__":
        return False
    parent = node.func.value
    if not isinstance(parent, ast.Call):
        return False
    if not isinstance(parent.func, ast.Name) or parent.func.id != "super":
        return False
    if parent.args or parent.keywords:
        return False
    if node.args:
        return False
    if not node.keywords:
        return True
    for keyword in node.keywords:
        if keyword.arg is not None:
            return False
        if not isinstance(keyword.value, ast.Name):
            return False
        if allowed_param_names is not None and keyword.value.id not in allowed_param_names:
            return False
    return True


def _is_self_assignment_statement(
    stmt: ast.stmt,
    allowed_param_names: set[str],
    assigned_attrs: set[str],
) -> bool:
    if isinstance(stmt, ast.Assign):
        targets = stmt.targets
        value = stmt.value
    elif isinstance(stmt, ast.AnnAssign):
        targets = [stmt.target]
        value = stmt.value
    else:
        return False

    if value is None:
        return False
    if not all(_is_self_attribute(target) for target in targets):
        return False
    if not _is_allowed_init_value(value, allowed_param_names):
        return False

    for target in targets:
        if isinstance(target, ast.Attribute):
            assigned_attrs.add(target.attr)
    return True


def _is_self_attribute(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id == "self"
    )


def _is_allowed_init_value(node: ast.AST, allowed_param_names: set[str]) -> bool:
    if _is_simple_literal(node):
        return True
    if isinstance(node, ast.Name):
        return node.id in allowed_param_names
    if isinstance(node, (ast.List, ast.Tuple)):
        return all(_is_allowed_init_value(item, allowed_param_names) for item in node.elts)
    if isinstance(node, ast.Dict):
        return all(
            (key is None or _is_allowed_init_value(key, allowed_param_names))
            and (value is None or _is_allowed_init_value(value, allowed_param_names))
            for key, value in zip(node.keys, node.values, strict=False)
        )
    return False


def _parse_literal_value(node: ast.AST) -> tuple[object | None, bool]:
    try:
        return ast.literal_eval(node), True
    except (ValueError, TypeError, SyntaxError):
        return None, False


def _node_repr(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return _dotted_name(node)
    return type(node).__name__


def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        ordered.append(item)
    return ordered
