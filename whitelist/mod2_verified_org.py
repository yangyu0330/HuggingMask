"""
모듈 2: 검증된 조직 모델 분석기 (mockable 추상 인터페이스 + AST 추출)

HuggingFace Verified Organization (Meta, Google, Mistral, ...)이 배포한
모델들이 사용하는 API를 집계하여, 미등록 API의 "verified org 사용 여부"를
판단하는 신호를 생성한다.

주 경로: 모델 저장소의 .py 파일을 AST 파싱하여 API 호출 추출.
폴백 경로: .py가 없는 표준 HF 모델은 ``config.json``의 ``architectures`` /
          ``auto_map`` 필드에서 transformers 클래스 참조 추출.

이 파일은 ``HfApiFetcher`` Protocol을 받는다. 실제 HuggingFace Hub 호출은
``mod2_real_fetcher.py``의 ``HuggingFaceApiFetcher``를 주입한다.
"""

import ast
import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Protocol

from whitelist.rules import VERIFIED_ORGANIZATIONS


logger = logging.getLogger(__name__)


@dataclass
class ApiUsage:
    """미등록 API의 verified org 사용 현황."""
    api_path: str
    used_by_orgs: list[str] = field(default_factory=list)
    used_by_models: list[str] = field(default_factory=list)
    total_count: int = 0


@dataclass
class OrgAnalysisResult:
    org_id: str
    org_name: str
    models_analyzed: list[str]
    apis_found: dict[str, int]
    analyzed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    errors: list[str] = field(default_factory=list)


class HfApiFetcher(Protocol):
    def list_models(self, org_id: str, limit: int) -> list[dict]: ...
    def get_file(self, model_id: str, filename: str) -> str: ...


# ─────────────────────────────────────────────
# Python 소스에서 API 추출
# ─────────────────────────────────────────────

class PythonApiExtractor:
    """import + 함수 호출을 AST로 추출 (alias 해소 포함)."""

    def extract_imports(self, source: str) -> list[str]:
        try:
            tree = ast.parse(source)
        except SyntaxError as e:
            logger.warning("AST 파싱 실패: %s", e)
            return []
        apis: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    apis.append(alias.name)
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                for alias in node.names:
                    apis.append(f"{module}.{alias.name}" if module else alias.name)
        return apis

    def extract_api_calls(self, source: str) -> list[str]:
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return []
        alias_map: dict[str, str] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    key = alias.asname or alias.name
                    alias_map[key] = alias.name
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                for alias in node.names:
                    key = alias.asname or alias.name
                    full = f"{module}.{alias.name}" if module else alias.name
                    alias_map[key] = full

        calls: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                chain = self._get_attribute_chain(node.func)
                if chain:
                    parts = chain.split(".", 1)
                    root = alias_map.get(parts[0], parts[0])
                    resolved = f"{root}.{parts[1]}" if len(parts) > 1 else root
                    calls.append(resolved)
        return calls

    def extract_all(self, source: str) -> set[str]:
        return set(self.extract_imports(source)) | set(self.extract_api_calls(source))

    @staticmethod
    def _get_attribute_chain(node: ast.expr) -> str | None:
        parts: list[str] = []
        current: ast.expr = node
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
            return ".".join(reversed(parts))
        return None


def extract_apis_from_config(config_text: str) -> set[str]:
    """``config.json``의 ``architectures`` / ``auto_map`` / ``model_type`` 에서
    transformers 클래스 참조를 추출한다.

    표준 HF 모델은 .py 없이 config.json만으로 동작하는 경우가 많아,
    .py 추출 결과가 빈 모델에 대해 폴백 신호로 쓴다.
    ``auto_map``의 값에 ``.``이 포함되면 ``trust_remote_code`` 트리거이므로
    제외 (모듈 2 신호 대상 아님).
    """
    apis: set[str] = set()
    try:
        config = json.loads(config_text)
    except (json.JSONDecodeError, ValueError):
        return apis
    if not isinstance(config, dict):
        return apis

    for cls in config.get("architectures", []) or []:
        if isinstance(cls, str) and re.match(r"^[A-Za-z][A-Za-z0-9_]*$", cls):
            apis.add(f"transformers.{cls}")

    auto_map = config.get("auto_map") or {}
    if isinstance(auto_map, dict):
        for auto_cls in auto_map:
            if isinstance(auto_cls, str) and re.match(r"^Auto[A-Za-z0-9_]*$", auto_cls):
                apis.add(f"transformers.{auto_cls}")

    model_type = config.get("model_type")
    if isinstance(model_type, str) and re.match(r"^[a-z][a-z0-9_]*$", model_type):
        apis.add(f"transformers.{model_type.title().replace('_', '')}Config")
    return apis


# ─────────────────────────────────────────────
# 분석기
# ─────────────────────────────────────────────

class VerifiedOrgAnalyzer:
    """주 경로(.py AST) + 폴백(config.json) 통합 분석기."""

    def __init__(self, fetcher: HfApiFetcher) -> None:
        self._fetcher = fetcher
        self._extractor = PythonApiExtractor()

    def analyze_org(self, org_id: str, model_limit: int = 10) -> OrgAnalysisResult:
        org_name = VERIFIED_ORGANIZATIONS.get(org_id, org_id)
        try:
            models = self._fetcher.list_models(org_id, limit=model_limit)
        except Exception as e:
            return OrgAnalysisResult(
                org_id=org_id, org_name=org_name,
                models_analyzed=[], apis_found={},
                errors=[f"모델 목록 조회 실패: {e}"],
            )

        all_apis: dict[str, int] = {}
        analyzed_models: list[str] = []
        errors: list[str] = []

        for model_info in models:
            model_id = model_info.get("id", "")
            files = model_info.get("files", [])
            py_files = [f for f in files if f.endswith(".py")]
            extracted_anything = False

            for filename in py_files:
                try:
                    source = self._fetcher.get_file(model_id, filename)
                    if not source:
                        continue
                    apis = self._extractor.extract_all(source)
                    for api in apis:
                        all_apis[api] = all_apis.get(api, 0) + 1
                    if apis:
                        extracted_anything = True
                except Exception as e:
                    errors.append(f"{model_id}/{filename}: {e}")

            if not extracted_anything and "config.json" in files:
                try:
                    config_text = self._fetcher.get_file(model_id, "config.json")
                    if config_text:
                        config_apis = extract_apis_from_config(config_text)
                        for api in config_apis:
                            all_apis[api] = all_apis.get(api, 0) + 1
                        if config_apis:
                            logger.info(
                                "config.json 폴백: %s에서 %d개 API 추출",
                                model_id, len(config_apis),
                            )
                except Exception as e:
                    errors.append(f"{model_id}/config.json: {e}")

            analyzed_models.append(model_id)

        return OrgAnalysisResult(
            org_id=org_id, org_name=org_name,
            models_analyzed=analyzed_models,
            apis_found=all_apis, errors=errors,
        )

    def analyze_all_orgs(self, model_limit: int = 10) -> list[OrgAnalysisResult]:
        results: list[OrgAnalysisResult] = []
        for org_id in VERIFIED_ORGANIZATIONS:
            result = self.analyze_org(org_id, model_limit=model_limit)
            results.append(result)
            logger.info(
                "조직 분석 완료: %s (%s) — %d개 API, %d개 모델",
                org_id, result.org_name,
                len(result.apis_found), len(result.models_analyzed),
            )
        return results


def aggregate_org_results(
    results: list[OrgAnalysisResult],
    existing_whitelist: set[str],
) -> list[ApiUsage]:
    """미등록 API들을 verified org 사용 횟수 기준으로 집계."""
    usage_map: dict[str, ApiUsage] = {}
    for result in results:
        for api_path, count in result.apis_found.items():
            if api_path in existing_whitelist:
                continue
            if api_path not in usage_map:
                usage_map[api_path] = ApiUsage(api_path=api_path)
            usage = usage_map[api_path]
            if result.org_id not in usage.used_by_orgs:
                usage.used_by_orgs.append(result.org_id)
            for model in result.models_analyzed:
                if model not in usage.used_by_models:
                    usage.used_by_models.append(model)
            usage.total_count += count
    return sorted(
        usage_map.values(),
        key=lambda u: len(u.used_by_orgs),
        reverse=True,
    )


__all__ = [
    "ApiUsage", "OrgAnalysisResult", "HfApiFetcher",
    "PythonApiExtractor", "extract_apis_from_config",
    "VerifiedOrgAnalyzer", "aggregate_org_results",
]
