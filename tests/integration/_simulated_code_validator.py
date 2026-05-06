"""
양유상의 코드 검증자(CODE_AST_SCAN)가 할 일을 시뮬레이션하는 stub.

실제 양유상 측 구현이 들어오면 이 stub을 import해서 사용하거나,
이 stub의 동작을 명세로 참고하면 된다.

책임 경계 (engine.md:21):
  이 모듈 = 코드에서 API 추출만 담당
  whitelist 엔진 = 추출된 API의 ALLOWED/BLOCKED/UNKNOWN/PENDING 판정
  코드 검증자 = 양쪽 결과를 합쳐 최종 코드 등급(A/B-1/B-2/C) 결정
"""

import ast


# 이름이 그대로 나오면 builtins.X로 정규화할 위험 식별자
# 양유상의 실제 검증자도 이 매핑을 가져야 한다 (builtins은 import 없이 호출 가능)
BARE_BUILTINS_TO_NORMALIZE = {
    "__import__", "eval", "exec", "compile",
    "open", "input", "vars", "globals", "locals",
}


def _attribute_chain(node: ast.expr) -> str | None:
    """a.b.c 형태의 속성 체인을 문자열로. 중간에 Call/Subscript 등이
    들어오면 None (정적으로 해소 불가).
    """
    parts: list[str] = []
    current: ast.expr = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
        return ".".join(reversed(parts))
    return None


def _build_alias_map(tree: ast.AST) -> dict[str, str]:
    """import 문을 분석해 로컬명 → 전체 모듈 경로 매핑 생성.

    예: `from torch import nn` → {"nn": "torch.nn"}
        `import torch.nn as nn` → {"nn": "torch.nn"}
        `import numpy as np` → {"np": "numpy"}
    """
    alias_map: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                key = alias.asname or alias.name.split(".")[0]
                alias_map[key] = alias.name
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for alias in node.names:
                key = alias.asname or alias.name
                full = f"{module}.{alias.name}" if module else alias.name
                alias_map[key] = full
    return alias_map


def extract_apis(source: str) -> set[str]:
    """소스 코드에서 import + 함수 호출 + 클래스 베이스를 모두 추출.

    반환값은 화이트리스트 엔진에 그대로 던질 API 경로 set.
    실패는 조용히 무시 (SyntaxError 시 빈 set).
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return set()

    alias_map = _build_alias_map(tree)
    apis: set[str] = set()

    # 1. import 자체를 후보로 (예: torch.nn, transformers.AutoModel)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                apis.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for alias in node.names:
                if module:
                    apis.add(f"{module}.{alias.name}")

    # 2. 함수 호출 — alias 해소 + bare builtins 정규화
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            chain = _attribute_chain(node.func)
            if not chain:
                continue
            resolved = _resolve(chain, alias_map)
            if resolved:
                apis.add(resolved)

    # 3. 클래스 베이스 (nn.Module 같은 상속 — 실행은 안 되지만 의존성)
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            for base in node.bases:
                chain = _attribute_chain(base)
                if chain:
                    resolved = _resolve(chain, alias_map)
                    if resolved:
                        apis.add(resolved)

    return apis


def _resolve(chain: str, alias_map: dict[str, str]) -> str | None:
    """체인의 root를 alias_map으로 치환. bare builtins는 builtins.X로 정규화.

    None을 반환하는 경우:
      - self/cls.X 같은 인스턴스 메서드 호출 (API 아님 — instance attribute)
      - super().X 호출 (해소 불가)
    """
    parts = chain.split(".", 1)
    root = parts[0]

    # 인스턴스 메서드는 API 호출이 아니므로 제외
    if root in ("self", "cls", "super"):
        return None

    # bare builtins 정규화 (예: __import__ → builtins.__import__)
    if root in BARE_BUILTINS_TO_NORMALIZE and root not in alias_map:
        return f"builtins.{chain}"

    if root in alias_map:
        if len(parts) > 1:
            return f"{alias_map[root]}.{parts[1]}"
        return alias_map[root]

    return chain
