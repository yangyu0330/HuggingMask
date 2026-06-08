"""Preprocessing file AST validator.

Validates tokenizer / processor / image processor / feature extractor .py
files referenced by config.json auto_map or custom_pipelines fields.

This module uses the shared ArtifactValidationResult contract from
analyzer.schemas and does NOT auto-approve preprocessing files at B-1
without semantic/invariant checks.

Policy (fixed):
  - Preprocessing files (TOKENIZER / PROCESSOR / IMAGE_PROCESSOR /
    FEATURE_EXTRACTOR) are NOT auto-approved at B-1/PASS.
  - If no dangerous pattern is found, the default is B-2/PENDING_REVIEW.
  - B-1/PASS is only allowed after tokenizer semantic check and
    processor/image processor invariant check are separately designed
    and verified with tests.
"""

from __future__ import annotations

import ast
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ── 팀 공통 계약 import ──────────────────────────────────────────────────────
try:
    from analyzer.schemas import (
        ArtifactRef,
        ArtifactValidationResult,
        CodeGrade,
        FileKind,
        ReasonEntry,
        ReviewAction,
        RouteKind,
        ValidationStatus,
    )
    _USING_TEAM_SCHEMA = True
except ImportError:
    _USING_TEAM_SCHEMA = False


# ────────────────────────────────────────────────────────────────────────────
# 파일 종류 분류
# ────────────────────────────────────────────────────────────────────────────

FILE_TYPE_PATTERNS: dict[str, list[str]] = {
    "TOKENIZER":         ["tokenization_", "tokenizer_"],
    "PROCESSOR":         ["processing_", "processor_"],
    "IMAGE_PROCESSOR":   ["image_processing_", "image_processor_"],
    "FEATURE_EXTRACTOR": ["feature_extraction_", "feature_extractor_"],
    "MODELING":          ["modeling_", "model_"],
    "CONFIGURATION":     ["configuration_", "config_"],
}

# semantic/invariant check 없이 B-1 자동 승인 불가 파일 종류
PREPROCESSING_FILE_TYPES: set[str] = {
    "TOKENIZER", "PROCESSOR", "IMAGE_PROCESSOR", "FEATURE_EXTRACTOR",
}


def classify_file(filename: str) -> str:
    name = Path(filename).name.lower()
    for file_type, patterns in FILE_TYPE_PATTERNS.items():
        for pattern in patterns:
            if name.startswith(pattern):
                return file_type
    return "UNKNOWN"


# ────────────────────────────────────────────────────────────────────────────
# 위험 패턴 정의
# ────────────────────────────────────────────────────────────────────────────

DANGEROUS_CALL_NAMES: set[str] = {
    "eval", "exec", "compile",
    "__import__",
    "setattr", "delattr",
}

DANGEROUS_ATTR_CALLS: set[tuple[str, str]] = {
    ("torch",      "load"),
    ("torch",      "hub"),
    ("pickle",     "load"),
    ("pickle",     "loads"),
    ("subprocess", "run"),
    ("subprocess", "Popen"),
    ("subprocess", "call"),
    ("os",         "system"),
    ("os",         "popen"),
    ("os",         "environ"),
    ("importlib",  "import_module"),
    ("requests",   "get"),
    ("requests",   "post"),
    ("urllib",     "urlopen"),
    ("urllib",     "urlretrieve"),
    ("yaml",       "load"),
    ("tarfile",    "extractall"),
    ("joblib",     "load"),
}

DANGEROUS_FROM_IMPORTS: set[tuple[str, str]] = {
    ("os",         "system"),
    ("os",         "popen"),
    ("os",         "environ"),
    ("subprocess", "run"),
    ("subprocess", "Popen"),
    ("subprocess", "call"),
    ("pickle",     "load"),
    ("pickle",     "loads"),
    ("importlib",  "import_module"),
    ("builtins",   "eval"),
    ("builtins",   "exec"),
    ("builtins",   "compile"),
}

DANGEROUS_IMPORTS: set[str] = {
    "subprocess", "socket", "pickle",
    "ctypes", "cffi", "pty",
}

SUSPICIOUS_IMPORTS: set[str] = {
    "os", "sys", "shutil", "tempfile",
    "importlib", "builtins",
}

OBFUSCATION_PATTERNS: set[str] = {
    "base64", "b64decode", "b64encode",
    "codecs", "zlib", "marshal",
}

# 네트워크 접근 가능 라이브러리 → 즉시 차단
NETWORK_CAPABLE_IMPORTS: set[str] = {
    "requests", "httpx", "aiohttp",
    "paramiko", "ftplib", "smtplib",
    "boto3",
}

URL_PATTERN = re.compile(r"https?://", re.IGNORECASE)

# 파일 종류별 허용 import 목록
ALLOWED_IMPORTS_BY_TYPE: dict[str, set[str]] = {
    "TOKENIZER": {
        "re", "unicodedata", "collections", "json",
        "os", "string", "itertools", "functools",
        "typing", "abc", "copy", "math",
        "logging", "warnings",
    },
    "PROCESSOR": {
        "numpy", "torch", "math",
        "collections", "typing", "functools",
        "copy", "itertools", "logging", "warnings", "abc",
    },
    "IMAGE_PROCESSOR": {
        "numpy", "PIL", "torch",
        "torchvision", "cv2",
        "math", "typing", "collections",
        "copy", "logging", "warnings",
        "functools", "itertools",
    },
    "FEATURE_EXTRACTOR": {
        "numpy", "torch", "math",
        "typing", "collections", "copy",
        "logging", "warnings", "functools",
    },
    "MODELING": {
        "torch", "math", "typing",
        "collections", "copy", "functools",
        "logging", "warnings", "abc",
    },
    "CONFIGURATION": {
        "json", "os", "typing",
        "collections", "copy", "logging",
        "warnings", "math",
    },
    "UNKNOWN": {
        "torch", "math", "typing",
        "logging", "warnings",
    },
}


# ────────────────────────────────────────────────────────────────────────────
# 내부 결과 구조
# ────────────────────────────────────────────────────────────────────────────

class _InternalResult:
    def __init__(self, filename: str, file_type: str) -> None:
        self.filename = filename
        self.file_type = file_type
        self.blocked = False
        self.block_reason: str | None = None
        self.flags: list[str] = []
        self.new_apis: list[str] = []
        self.reason_codes: list[str] = []
        # 등급 결정 후 저장 (데모용)
        self.grade: str = "B-2"
        self.status: str = "PENDING_REVIEW"
        self.verification_step: str = "CODE_SANDBOX_RUNTIME"

    def block(self, reason: str) -> None:
        self.blocked = True
        self.block_reason = reason
        if "DANGEROUS_CALL" not in self.reason_codes:
            self.reason_codes.append("DANGEROUS_CALL")

    def flag(self, message: str) -> None:
        self.flags.append(message)

    def add_new_api(self, api: str) -> None:
        if api not in self.new_apis:
            self.new_apis.append(api)
        if "UNREGISTERED_API" not in self.reason_codes:
            self.reason_codes.append("UNREGISTERED_API")


# ────────────────────────────────────────────────────────────────────────────
# 검증 단계별 함수
# ────────────────────────────────────────────────────────────────────────────

def _step1_parse(code: str, result: _InternalResult) -> ast.Module | None:
    try:
        return ast.parse(code)
    except SyntaxError as e:
        result.block(f"문법 오류: {e}")
        result.reason_codes.append("PARSE_ERROR")
        return None


def _build_import_alias_map(tree: ast.Module) -> dict[str, str]:
    alias_map: dict[str, str] = {}

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                local_name = alias.asname or root
                alias_map[local_name] = alias.name if alias.asname else root

        elif isinstance(node, ast.ImportFrom):
            if node.module is None:
                continue
            for alias in node.names:
                if alias.name == "*":
                    continue
                local_name = alias.asname or alias.name
                alias_map[local_name] = f"{node.module}.{alias.name}"

    return alias_map


def _attribute_chain(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _attribute_chain(node.value)
        if parent is None:
            return None
        return f"{parent}.{node.attr}"
    return None


def _resolve_call_name(func: ast.AST, alias_map: dict[str, str]) -> str | None:
    raw_name = _attribute_chain(func)
    if raw_name is None:
        return None

    parts = raw_name.split(".")
    root = parts[0]
    if root not in alias_map:
        return raw_name

    resolved_root = alias_map[root]
    if len(parts) == 1:
        return resolved_root
    return ".".join([resolved_root, *parts[1:]])


def _dangerous_attr_pair(call_name: str) -> tuple[str, str] | None:
    parts = call_name.split(".")
    if len(parts) < 2:
        return None

    direct_pair = (parts[0], parts[1])
    if direct_pair in DANGEROUS_ATTR_CALLS:
        return direct_pair

    final_pair = (parts[0], parts[-1])
    if final_pair in DANGEROUS_ATTR_CALLS:
        return final_pair

    return None


def _is_numpy_load_with_pickle(call_name: str, node: ast.Call) -> bool:
    parts = call_name.split(".")
    if len(parts) < 2 or parts[0] != "numpy" or parts[-1] != "load":
        return False

    for kw in node.keywords:
        if kw.arg == "allow_pickle":
            return isinstance(kw.value, ast.Constant) and bool(kw.value.value)

    return False


def _step2_danger_scan(tree: ast.Module, result: _InternalResult) -> None:
    alias_map = _build_import_alias_map(tree)

    for node in ast.walk(tree):

        # __builtins__는 런타임 builtins dict 그 자체 — __builtins__["eval"] /
        # __builtins__.exec / getattr(__builtins__, ...) 등 첨자·속성·별칭으로
        # eval/exec/__import__를 꺼내는 우회 진입점이다. 전처리 코드에 정당한
        # 사용이 없으므로 어떤 형태의 참조든 차단한다.
        if isinstance(node, ast.Name) and node.id == "__builtins__":
            result.block("__builtins__ 참조 — eval/exec/__import__ 우회 진입점")
            return

        if isinstance(node, ast.Import):
            for alias in node.names:
                mod = alias.name.split(".")[0]
                if mod in DANGEROUS_IMPORTS:
                    result.block(f"위험 모듈 import: '{alias.name}'")
                    return
                if mod in NETWORK_CAPABLE_IMPORTS:
                    result.block(f"네트워크 접근 가능 모듈: '{alias.name}'")
                    return

        if isinstance(node, ast.ImportFrom):
            mod = (node.module or "").split(".")[0]
            if mod in DANGEROUS_IMPORTS:
                result.block(f"위험 모듈 from import: '{node.module}'")
                return
            if mod in NETWORK_CAPABLE_IMPORTS:
                result.block(f"네트워크 접근 가능 모듈: 'from {node.module} import ...'")
                return
            for alias in node.names:
                pair = (mod, alias.name)
                if pair in DANGEROUS_FROM_IMPORTS:
                    result.block(
                        f"위험 함수 from import 탐지: "
                        f"from {node.module} import {alias.name}"
                    )
                    return

        if not isinstance(node, ast.Call):
            continue

        resolved_call = _resolve_call_name(node.func, alias_map)
        if resolved_call is None:
            continue

        if resolved_call in DANGEROUS_CALL_NAMES:
            result.block(f"위험 함수 호출: {resolved_call}()")
            return

        if "." in resolved_call:
            root, attr = resolved_call.split(".", 1)
            if root == "builtins" and attr in DANGEROUS_CALL_NAMES:
                result.block(f"위험 함수 호출: {resolved_call}()")
                return

        if isinstance(node.func, ast.Name) and node.func.id == "getattr":
            if len(node.args) >= 2:
                first = node.args[0]
                second = node.args[1]
                obj_name = first.id if isinstance(first, ast.Name) else None
                attr_val = second.value if isinstance(second, ast.Constant) else None
                resolved_obj = alias_map.get(obj_name, obj_name) if obj_name else None
                synthetic_call = (
                    f"{resolved_obj}.{attr_val}"
                    if resolved_obj and isinstance(attr_val, str)
                    else None
                )
                if (
                    resolved_obj
                    and resolved_obj.split(".")[0] in {"os", "subprocess", "sys", "builtins"}
                ):
                    result.block(
                        f"위험한 getattr 탐지: getattr({resolved_obj}, '{attr_val}') "
                        f"— 동적 속성 접근으로 탐지 우회 시도"
                    )
                    return
                if synthetic_call is not None and _dangerous_attr_pair(synthetic_call):
                    result.block(
                        f"위험한 getattr 탐지: getattr({resolved_obj}, '{attr_val}') "
                        f"— 동적 속성 접근으로 탐지 우회 시도"
                    )
                    return

        pair = _dangerous_attr_pair(resolved_call)
        if pair is not None:
            if pair == ("os", "environ"):
                result.flag("os.environ 접근 탐지 — API 키 탈취 가능성")
            else:
                result.block(f"위험 메서드 호출: {resolved_call}()")
                return

        if _is_numpy_load_with_pickle(resolved_call, node):
            result.block("numpy.load(allow_pickle=True) — pickle 역직렬화 위험")
            return

    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id in OBFUSCATION_PATTERNS:
            result.flag(f"난독화 의심 패턴: '{node.id}'")
        if isinstance(node, ast.Attribute) and node.attr in OBFUSCATION_PATTERNS:
            result.flag(f"난독화 의심 패턴: '.{node.attr}'")

    chr_count = sum(
        1 for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "chr"
    )
    if chr_count >= 3:
        result.flag(f"chr() 연속 조합 ({chr_count}회) — 문자열 난독화 의심")


def _step3_api_check(tree: ast.Module, result: _InternalResult) -> None:
    allowed = ALLOWED_IMPORTS_BY_TYPE.get(result.file_type, set())

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                mod = alias.name.split(".")[0]
                if mod in allowed or mod in DANGEROUS_IMPORTS or mod in NETWORK_CAPABLE_IMPORTS:
                    continue
                if mod in SUSPICIOUS_IMPORTS:
                    result.flag(f"주의 모듈 import: '{alias.name}'")
                else:
                    result.add_new_api(f"import {alias.name}")

        if isinstance(node, ast.ImportFrom):
            mod = (node.module or "").split(".")[0]
            if mod in allowed or mod in DANGEROUS_IMPORTS or mod in NETWORK_CAPABLE_IMPORTS:
                continue
            if mod not in SUSPICIOUS_IMPORTS:
                result.add_new_api(f"from {node.module} import ...")

    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if URL_PATTERN.match(node.value):
                result.flag(f"코드 내 외부 URL: '{node.value[:60]}'")


# ────────────────────────────────────────────────────────────────────────────
# 등급 결정
# ────────────────────────────────────────────────────────────────────────────

def _decide_grade(
    result: _InternalResult,
) -> tuple[str, str, str, str]:
    """
    (grade, status, route_kind, review_action) 반환.

    전처리 파일은 위험 패턴 없어도 기본 B-2/PENDING_REVIEW.
    """
    if result.blocked:
        return ("C", "BLOCK", "CODE_AST_SCAN", "BLOCK_IMMEDIATELY")

    non_safe_flags = [f for f in result.flags if "계산 전용" not in f]
    if non_safe_flags or result.new_apis:
        return ("B-2", "PENDING_REVIEW", "CODE_SANDBOX_RUNTIME", "SECURITY_OWNER_GATE")

    # 전처리 파일 — semantic check 없이 B-1 불가
    if result.file_type in PREPROCESSING_FILE_TYPES:
        return ("B-2", "PENDING_REVIEW", "CODE_SANDBOX_RUNTIME", "SECURITY_OWNER_GATE")

    # 비전처리 파일 (modeling 등)
    return ("B-1", "PASS", "CODE_RESTRICTED_RUNTIME", "AUTO_APPROVE")


# ────────────────────────────────────────────────────────────────────────────
# 팀 계약 변환
# ────────────────────────────────────────────────────────────────────────────

def validate_preprocessing_artifact(
    filename: str,
    source: str | bytes,
    artifact: Any | None = None,
) -> "ArtifactValidationResult":
    """
    전처리 파일 AST 검증 진입점 (팀 계약 반환).
    analyzer.schemas 가 없으면 ImportError.
    """
    if not _USING_TEAM_SCHEMA:
        raise ImportError(
            "analyzer.schemas 를 import 할 수 없습니다. "
            "HuggingMask 프로젝트 루트에서 실행해 주세요."
        )

    code = source.decode("utf-8", errors="replace") if isinstance(source, bytes) else source
    result = _InternalResult(filename=filename, file_type=classify_file(filename))

    tree = _step1_parse(code, result)
    if tree is not None:
        _step2_danger_scan(tree, result)
        if not result.blocked:
            _step3_api_check(tree, result)

    grade, status, route_kind, review_action = _decide_grade(result)

    reason_entries: list[ReasonEntry] = []

    if result.blocked and result.block_reason:
        reason_entries.append(ReasonEntry(
            code="DANGEROUS_CALL",
            message=result.block_reason,
            severity="HIGH",
            evidence=[result.block_reason],
            review_required=False,
        ))

    if result.new_apis:
        reason_entries.append(ReasonEntry(
            code="UNREGISTERED_API",
            message="unregistered API requires security review",
            severity="MEDIUM",
            evidence=result.new_apis,
            review_required=True,
        ))

    for flag in result.flags:
        reason_entries.append(ReasonEntry(
            code="FLAG",
            message=flag,
            severity="MEDIUM",
            evidence=[],
            review_required=True,
        ))

    if result.file_type in PREPROCESSING_FILE_TYPES and grade == "B-2" and not result.blocked:
        reason_entries.append(ReasonEntry(
            code="GRADE_B2_GATE_REQUIRED",
            message=(
                f"전처리 파일({result.file_type})은 "
                "semantic/invariant check 없이 자동 승인 불가 — B-2/PENDING_REVIEW 고정"
            ),
            severity="MEDIUM",
            evidence=[],
            review_required=True,
        ))

    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    if artifact is None:
        dummy_sha256 = "0" * 64
        artifact = ArtifactRef(
            artifact_id=f"sha256:{dummy_sha256}",
            repo_path=filename,
            file_name=Path(filename).name,
            file_kind=FileKind.PYTHON,
            detected_extension=".py",
            size_bytes=0,
            sha256=dummy_sha256,
            source_url="",
            temp_local_path="",
        )

    return ArtifactValidationResult(
        artifact=artifact,
        route_kind=RouteKind(route_kind),
        status=ValidationStatus(status),
        grade=CodeGrade(grade),
        review_action=ReviewAction(review_action),
        cache_key=f"{artifact.sha256}:PYTHON:policy-unknown",
        cache_hit=False,
        reason_entries=reason_entries,
        started_at=now,
        finished_at=now,
        details={
            "file_type": result.file_type,
            "flags": result.flags,
            "new_apis": result.new_apis,
            "block_reason": result.block_reason,
            "preprocessing_auto_approve_policy": (
                "B-1/PASS 자동 승인 불가 — semantic/invariant check 필요"
                if result.file_type in PREPROCESSING_FILE_TYPES
                else "N/A"
            ),
        },
    )


def validate_preprocessing_file(
    code: str,
    filename: str = "unknown.py",
) -> _InternalResult:
    """데모/테스트용 함수. _InternalResult 반환."""
    result = _InternalResult(filename=filename, file_type=classify_file(filename))

    tree = _step1_parse(code, result)
    if tree is not None:
        _step2_danger_scan(tree, result)
        if not result.blocked:
            _step3_api_check(tree, result)

    grade, status, route_kind, _ = _decide_grade(result)
    result.grade = grade
    result.status = status
    result.verification_step = route_kind

    return result
