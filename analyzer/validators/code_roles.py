"""Python role classification for stage-3 code-validation scope.

This module only classifies Python file roles. It does not execute or import
model code, does not perform API safe/review/block decisions, and does not
assign final A/B-1/B-2/C grades.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from enum import Enum
from pathlib import PurePosixPath


class StringEnum(str, Enum):
    def __str__(self) -> str:
        return self.value


class PythonFileRole(StringEnum):
    CONFIGURATION = "CONFIGURATION"
    MODELING = "MODELING"
    PREPROCESSING = "PREPROCESSING"
    AUXILIARY = "AUXILIARY"
    UNKNOWN = "UNKNOWN"


class PreprocessKind(StringEnum):
    TOKENIZER = "TOKENIZER"
    PROCESSOR = "PROCESSOR"
    IMAGE_PROCESSOR = "IMAGE_PROCESSOR"
    VIDEO_PROCESSOR = "VIDEO_PROCESSOR"
    FEATURE_EXTRACTOR = "FEATURE_EXTRACTOR"
    PREPROCESS_HELPER = "PREPROCESS_HELPER"
    NONE = "NONE"


class AuxiliaryKind(StringEnum):
    INIT_EXPORT_ONLY = "INIT_EXPORT_ONLY"
    CONVERT_SCRIPT = "CONVERT_SCRIPT"
    HELPER = "HELPER"
    UNKNOWN = "UNKNOWN"


class RoleConfidence(StringEnum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


NON_AUTO_APPROVAL_REASON = "ROLE_NOT_AUTO_APPROVAL_TARGET"

_CONFIG_BASE_SUFFIX = ("PretrainedConfig",)
_MODELING_BASE_SUFFIX = ("Module", "PreTrainedModel")
_TOKENIZER_BASE_SUFFIX = ("PreTrainedTokenizer", "PreTrainedTokenizerBase")
_PROCESSOR_BASE_SUFFIX = ("ProcessorMixin",)
_IMAGE_PROCESSOR_BASE_SUFFIX = ("ImageProcessingMixin", "BaseImageProcessor")
_VIDEO_PROCESSOR_BASE_SUFFIX = ("VideoProcessingMixin",)
_FEATURE_EXTRACTOR_BASE_SUFFIX = ("FeatureExtractionMixin",)


@dataclass
class RoleClassification:
    role: PythonFileRole
    preprocess_kind: PreprocessKind = PreprocessKind.NONE
    auxiliary_kind: AuxiliaryKind | None = None
    confidence: RoleConfidence = RoleConfidence.LOW
    reasons: list[str] = field(default_factory=list)
    auto_approval_candidate: bool = False
    auto_approval_block_reason: str | None = NON_AUTO_APPROVAL_REASON
    parse_error: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "role": self.role.value,
            "preprocess_kind": self.preprocess_kind.value,
            "auxiliary_kind": self.auxiliary_kind.value if self.auxiliary_kind is not None else None,
            "confidence": self.confidence.value,
            "reasons": list(self.reasons),
            "auto_approval_candidate": self.auto_approval_candidate,
            "auto_approval_block_reason": self.auto_approval_block_reason,
            "parse_error": self.parse_error,
        }


def classify_python_role(repo_path: str, source: str | bytes | None = None) -> RoleClassification:
    normalized = _normalize_repo_path(repo_path)
    file_name = PurePosixPath(normalized).name.lower()

    source_text = _to_source_text(source)
    tree: ast.Module | None = None
    parse_error: str | None = None
    if source_text is not None:
        try:
            tree = ast.parse(source_text)
        except SyntaxError as exc:
            parse_error = str(exc)

    alias_map = _build_alias_map(tree) if tree is not None else {}
    path_role = _classify_by_file_name(file_name)

    if file_name == "__init__.py":
        return _classify_init_module(tree=tree, parse_error=parse_error)

    if tree is not None:
        role_from_ast = _classify_by_ast_shape(tree, alias_map)
        if role_from_ast is not None:
            role_from_ast.parse_error = parse_error
            return _apply_auto_approval_flag(role_from_ast)

    if path_role is not None:
        path_role.parse_error = parse_error
        return _apply_auto_approval_flag(path_role)

    if parse_error is not None:
        return RoleClassification(
            role=PythonFileRole.UNKNOWN,
            confidence=RoleConfidence.LOW,
            reasons=["ROLE_AST_PARSE_ERROR", "ROLE_UNDETERMINED"],
            parse_error=parse_error,
        )

    return RoleClassification(
        role=PythonFileRole.UNKNOWN,
        confidence=RoleConfidence.LOW,
        reasons=["ROLE_UNDETERMINED"],
    )


def _normalize_repo_path(path: str) -> str:
    return str(path).replace("\\", "/")


def _to_source_text(source: str | bytes | None) -> str | None:
    if source is None:
        return None
    if isinstance(source, bytes):
        return source.decode("utf-8", errors="replace")
    return source


def _classify_by_file_name(file_name: str) -> RoleClassification | None:
    if file_name.startswith("configuration_") or file_name == "generation_config.py":
        return RoleClassification(
            role=PythonFileRole.CONFIGURATION,
            confidence=RoleConfidence.HIGH,
            reasons=["ROLE_FILE_HINT_CONFIGURATION"],
        )
    if file_name.startswith("modeling_"):
        return RoleClassification(
            role=PythonFileRole.MODELING,
            confidence=RoleConfidence.HIGH,
            reasons=["ROLE_FILE_HINT_MODELING"],
        )
    if file_name.startswith("tokenization_"):
        return RoleClassification(
            role=PythonFileRole.PREPROCESSING,
            preprocess_kind=PreprocessKind.TOKENIZER,
            confidence=RoleConfidence.HIGH,
            reasons=["ROLE_FILE_HINT_TOKENIZER"],
        )
    if file_name.startswith("processing_"):
        return RoleClassification(
            role=PythonFileRole.PREPROCESSING,
            preprocess_kind=PreprocessKind.PROCESSOR,
            confidence=RoleConfidence.HIGH,
            reasons=["ROLE_FILE_HINT_PROCESSOR"],
        )
    if file_name.startswith("image_processing_"):
        return RoleClassification(
            role=PythonFileRole.PREPROCESSING,
            preprocess_kind=PreprocessKind.IMAGE_PROCESSOR,
            confidence=RoleConfidence.HIGH,
            reasons=["ROLE_FILE_HINT_IMAGE_PROCESSOR"],
        )
    if file_name.startswith("video_processing_"):
        return RoleClassification(
            role=PythonFileRole.PREPROCESSING,
            preprocess_kind=PreprocessKind.VIDEO_PROCESSOR,
            confidence=RoleConfidence.HIGH,
            reasons=["ROLE_FILE_HINT_VIDEO_PROCESSOR"],
        )
    if file_name.startswith("feature_extraction_"):
        return RoleClassification(
            role=PythonFileRole.PREPROCESSING,
            preprocess_kind=PreprocessKind.FEATURE_EXTRACTOR,
            confidence=RoleConfidence.HIGH,
            reasons=["ROLE_FILE_HINT_FEATURE_EXTRACTOR"],
        )
    if file_name.startswith("convert_"):
        return RoleClassification(
            role=PythonFileRole.AUXILIARY,
            auxiliary_kind=AuxiliaryKind.CONVERT_SCRIPT,
            confidence=RoleConfidence.HIGH,
            reasons=["ROLE_FILE_HINT_CONVERT_SCRIPT"],
        )
    if file_name in {"utils.py", "helper.py"}:
        return RoleClassification(
            role=PythonFileRole.AUXILIARY,
            auxiliary_kind=AuxiliaryKind.HELPER,
            confidence=RoleConfidence.HIGH,
            reasons=["ROLE_FILE_HINT_HELPER"],
        )
    return None


def _classify_init_module(tree: ast.Module | None, parse_error: str | None) -> RoleClassification:
    if tree is None:
        reasons = ["ROLE_INIT_DYNAMIC_OR_UNKNOWN"]
        if parse_error is not None:
            reasons.insert(0, "ROLE_AST_PARSE_ERROR")
        return RoleClassification(
            role=PythonFileRole.UNKNOWN,
            confidence=RoleConfidence.LOW,
            reasons=reasons,
            parse_error=parse_error,
        )

    if _is_export_only_init(tree):
        return RoleClassification(
            role=PythonFileRole.AUXILIARY,
            auxiliary_kind=AuxiliaryKind.INIT_EXPORT_ONLY,
            confidence=RoleConfidence.MEDIUM,
            reasons=["ROLE_INIT_EXPORT_ONLY"],
            parse_error=parse_error,
        )

    return RoleClassification(
        role=PythonFileRole.UNKNOWN,
        confidence=RoleConfidence.LOW,
        reasons=["ROLE_INIT_DYNAMIC_OR_UNKNOWN"],
        parse_error=parse_error,
    )


def _build_alias_map(tree: ast.Module) -> dict[str, str]:
    alias_map: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                bound_name = alias.asname or alias.name.split(".", 1)[0]
                alias_map[bound_name] = alias.name
        elif isinstance(node, ast.ImportFrom):
            if not node.module:
                continue
            for alias in node.names:
                bound_name = alias.asname or alias.name
                alias_map[bound_name] = f"{node.module}.{alias.name}"
    return alias_map


def _classify_by_ast_shape(tree: ast.Module, alias_map: dict[str, str]) -> RoleClassification | None:
    config = _looks_like_config_class(tree, alias_map)
    if config:
        return RoleClassification(
            role=PythonFileRole.CONFIGURATION,
            confidence=RoleConfidence.HIGH,
            reasons=["ROLE_AST_CONFIG_CLASS_SHAPE"],
        )

    model = _looks_like_model_class(tree, alias_map)
    if model:
        return RoleClassification(
            role=PythonFileRole.MODELING,
            confidence=RoleConfidence.HIGH,
            reasons=["ROLE_AST_MODEL_CLASS_SHAPE"],
        )

    preprocess_kind = _looks_like_preprocess_class(tree, alias_map)
    if preprocess_kind is not None:
        return RoleClassification(
            role=PythonFileRole.PREPROCESSING,
            preprocess_kind=preprocess_kind,
            confidence=RoleConfidence.MEDIUM,
            reasons=["ROLE_AST_PREPROCESS_CLASS_SHAPE"],
        )

    return None


def _looks_like_config_class(tree: ast.Module, alias_map: dict[str, str]) -> bool:
    for node in tree.body:
        if not isinstance(node, ast.ClassDef):
            continue
        bases = {_resolve_alias(_dotted_name(base), alias_map) for base in node.bases}
        if any(base.endswith(_CONFIG_BASE_SUFFIX) for base in bases):
            return True
    return False


def _looks_like_model_class(tree: ast.Module, alias_map: dict[str, str]) -> bool:
    for node in tree.body:
        if not isinstance(node, ast.ClassDef):
            continue
        bases = {_resolve_alias(_dotted_name(base), alias_map) for base in node.bases}
        if not any(base.endswith(_MODELING_BASE_SUFFIX) for base in bases):
            continue
        methods = {
            child.name
            for child in node.body
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        if "forward" in methods or "generate" in methods:
            return True
    return False


def _looks_like_preprocess_class(tree: ast.Module, alias_map: dict[str, str]) -> PreprocessKind | None:
    for node in tree.body:
        if not isinstance(node, ast.ClassDef):
            continue
        bases = {_resolve_alias(_dotted_name(base), alias_map) for base in node.bases}
        if any(base.endswith(_TOKENIZER_BASE_SUFFIX) for base in bases):
            return PreprocessKind.TOKENIZER
        if any(base.endswith(_PROCESSOR_BASE_SUFFIX) for base in bases):
            return PreprocessKind.PROCESSOR
        if any(base.endswith(_IMAGE_PROCESSOR_BASE_SUFFIX) for base in bases):
            return PreprocessKind.IMAGE_PROCESSOR
        if any(base.endswith(_VIDEO_PROCESSOR_BASE_SUFFIX) for base in bases):
            return PreprocessKind.VIDEO_PROCESSOR
        if any(base.endswith(_FEATURE_EXTRACTOR_BASE_SUFFIX) for base in bases):
            return PreprocessKind.FEATURE_EXTRACTOR
    return None


def _resolve_alias(path: str, alias_map: dict[str, str]) -> str:
    if not path:
        return ""
    if "." not in path:
        return alias_map.get(path, path)
    root, rest = path.split(".", 1)
    if root in alias_map:
        return f"{alias_map[root]}.{rest}"
    return path


def _dotted_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        root = _dotted_name(node.value)
        return f"{root}.{node.attr}" if root else node.attr
    return ""


def _is_export_only_init(tree: ast.Module) -> bool:
    allowed_names = {"__all__", "__version__", "VERSION", "version"}

    for index, stmt in enumerate(tree.body):
        if index == 0 and _is_docstring_stmt(stmt):
            continue
        if isinstance(stmt, (ast.Import, ast.ImportFrom, ast.Pass)):
            continue
        if isinstance(stmt, ast.Assign):
            if not _is_allowed_assignment(stmt.targets, stmt.value, allowed_names):
                return False
            continue
        if isinstance(stmt, ast.AnnAssign):
            targets = [stmt.target]
            if not _is_allowed_assignment(targets, stmt.value, allowed_names):
                return False
            continue
        return False

    return True


def _is_docstring_stmt(stmt: ast.stmt) -> bool:
    return (
        isinstance(stmt, ast.Expr)
        and isinstance(stmt.value, ast.Constant)
        and isinstance(stmt.value.value, str)
    )


def _is_allowed_assignment(targets: list[ast.expr], value: ast.expr | None, allowed_names: set[str]) -> bool:
    if value is None:
        return False
    for target in targets:
        if not isinstance(target, ast.Name):
            return False
        if target.id not in allowed_names:
            return False
    return _is_literal_container(value)


def _is_literal_container(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return all(_is_literal_container(item) for item in node.elts)
    if isinstance(node, ast.Dict):
        return all(
            _is_literal_container(key) and _is_literal_container(value)
            for key, value in zip(node.keys, node.values, strict=False)
            if key is not None and value is not None
        )
    return False


def _apply_auto_approval_flag(result: RoleClassification) -> RoleClassification:
    if result.role in {PythonFileRole.CONFIGURATION, PythonFileRole.MODELING}:
        result.auto_approval_candidate = True
        result.auto_approval_block_reason = None
        return result

    result.auto_approval_candidate = False
    result.auto_approval_block_reason = NON_AUTO_APPROVAL_REASON
    if NON_AUTO_APPROVAL_REASON not in result.reasons:
        result.reasons.append(NON_AUTO_APPROVAL_REASON)
    return result

