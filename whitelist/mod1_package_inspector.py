"""
모듈 1 대안: 설치된 패키지에서 직접 API 추출

공식 문서 HTML 크롤링 대신, 설치된 PyTorch/Transformers/NumPy 패키지의
모듈 구조를 ``importlib`` + ``inspect``로 검사해 공개 API를 추출한다.

장점:
- Cloudflare 등 웹 보호에 영향받지 않음
- HTML 파싱보다 정확 (실제 공개 API만 추출)
- 설치된 버전 기준이라 버전 태그가 정확

한계:
- 검사 머신에 해당 라이브러리가 설치돼 있어야 함
- 동적 임포트로 인한 사이드 이펙트 가능 (공식 라이브러리는 안전한 편)

CLI 진입점::

    python -m whitelist.mod1_package_inspector --library pytorch --output data/api_pytorch.json
"""

import importlib
import inspect
import json
import logging
import pkgutil
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path


logger = logging.getLogger(__name__)


@dataclass
class ExtractedApi:
    full_path: str
    namespace: str
    api_type: str = ""      # "class" | "function" | "module" | "constant"
    version_tag: str = ""
    signature: str = ""
    source_file: str = ""


@dataclass
class InspectionResult:
    library: str
    version: str
    total_extracted: int
    apis: list[ExtractedApi]
    new_apis: list[ExtractedApi] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    inspected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


# ─────────────────────────────────────────────
# 인스펙터
# ─────────────────────────────────────────────

class PackageInspector:
    """설치된 패키지의 공개 API를 재귀적으로 추출.

    - ``__all__`` 정의 시 그 멤버만
    - 없으면 ``_``로 시작하지 않는 public 멤버
    - 서브모듈도 재귀 (max_depth까지)
    """

    def __init__(self, max_depth: int = 3) -> None:
        self._max_depth = max_depth
        self._visited: set[str] = set()

    def inspect_module(
        self, module_name: str, prefix: str = "", depth: int = 0,
    ) -> list[ExtractedApi]:
        if depth > self._max_depth:
            return []
        full_name = f"{prefix}.{module_name}" if prefix else module_name
        if full_name in self._visited:
            return []
        self._visited.add(full_name)

        try:
            module = importlib.import_module(full_name)
        except Exception as e:
            logger.debug("import 실패: %s — %s", full_name, e)
            return []

        apis: list[ExtractedApi] = []
        members_to_inspect = getattr(module, "__all__", None)
        if members_to_inspect is None:
            members_to_inspect = [
                name for name in dir(module) if not name.startswith("_")
            ]

        for name in members_to_inspect:
            try:
                obj = getattr(module, name, None)
                if obj is None:
                    continue
                api_path = f"{full_name}.{name}"
                if inspect.isclass(obj):
                    api_type = "class"
                elif inspect.isfunction(obj) or inspect.isbuiltin(obj):
                    api_type = "function"
                elif inspect.ismodule(obj):
                    apis.extend(self.inspect_module(name, prefix=full_name, depth=depth + 1))
                    continue
                else:
                    continue  # 상수는 화이트리스트 대상 아님

                sig = ""
                try:
                    if api_type in ("function", "class"):
                        sig = str(inspect.signature(obj))
                except (ValueError, TypeError):
                    pass

                source_file = ""
                try:
                    source_file = inspect.getfile(obj) or ""
                except (TypeError, OSError):
                    pass

                apis.append(ExtractedApi(
                    full_path=api_path,
                    namespace=full_name,
                    api_type=api_type,
                    signature=sig,
                    source_file=source_file,
                ))
            except Exception as e:
                logger.debug("멤버 검사 실패: %s.%s — %s", full_name, name, e)

        if hasattr(module, "__path__"):
            try:
                for _, submod_name, _ in pkgutil.iter_modules(module.__path__):
                    if submod_name.startswith("_"):
                        continue
                    apis.extend(self.inspect_module(
                        submod_name, prefix=full_name, depth=depth + 1,
                    ))
            except Exception as e:
                logger.debug("서브모듈 탐색 실패: %s — %s", full_name, e)
        return apis


# ─────────────────────────────────────────────
# 라이브러리별 진입 모듈
# ─────────────────────────────────────────────

LIBRARY_CONFIGS = {
    "pytorch": {
        "modules": [
            "torch.nn", "torch.nn.functional", "torch.optim", "torch.autograd",
            "torch.linalg", "torch.fft", "torch.special", "torch.cuda",
            "torch.amp", "torch.utils", "torch.distributed", "torch.jit",
        ],
        "version_attr": "torch",
    },
    "transformers": {
        "modules": ["transformers"],
        "version_attr": "transformers",
    },
    "numpy": {
        "modules": ["numpy"],
        "version_attr": "numpy",
    },
}


def get_library_version(lib_key: str) -> str:
    config = LIBRARY_CONFIGS.get(lib_key, {})
    version_mod = config.get("version_attr", "")
    if not version_mod:
        return "unknown"
    try:
        mod = importlib.import_module(version_mod)
        return getattr(mod, "__version__", "unknown")
    except ImportError:
        return "not_installed"


def inspect_library(
    lib_key: str, existing_apis: set[str] | None = None,
) -> InspectionResult:
    config = LIBRARY_CONFIGS.get(lib_key)
    if not config:
        return InspectionResult(
            library=lib_key, version="unknown",
            total_extracted=0, apis=[],
            errors=[f"Unknown library: {lib_key}"],
        )
    version = get_library_version(lib_key)
    if version == "not_installed":
        return InspectionResult(
            library=lib_key, version=version,
            total_extracted=0, apis=[],
            errors=[f"{lib_key} is not installed"],
        )

    inspector = PackageInspector(max_depth=3)
    all_apis: list[ExtractedApi] = []
    errors: list[str] = []
    for module_name in config["modules"]:
        logger.info("검사 중: %s", module_name)
        try:
            apis = inspector.inspect_module(module_name)
            for api in apis:
                api.version_tag = f"{lib_key}=={version}"
            all_apis.extend(apis)
            logger.info("  → %d개 API 추출", len(apis))
        except Exception as e:
            errors.append(f"{module_name}: {e}")
            logger.error("추출 실패: %s — %s", module_name, e)

    seen: set[str] = set()
    unique_apis: list[ExtractedApi] = []
    for api in all_apis:
        if api.full_path not in seen:
            seen.add(api.full_path)
            unique_apis.append(api)

    new_apis: list[ExtractedApi] = []
    if existing_apis is not None:
        new_apis = [a for a in unique_apis if a.full_path not in existing_apis]

    logger.info(
        "%s %s: 전체 %d개, 신규 %d개",
        lib_key, version, len(unique_apis), len(new_apis),
    )
    return InspectionResult(
        library=lib_key, version=version,
        total_extracted=len(unique_apis), apis=unique_apis,
        new_apis=new_apis, errors=errors,
    )


def inspect_all(existing_apis: set[str] | None = None) -> list[InspectionResult]:
    return [inspect_library(lib_key, existing_apis) for lib_key in LIBRARY_CONFIGS]


# ─────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────

def main() -> None:
    import argparse

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(message)s",
    )
    p = argparse.ArgumentParser(
        description="HuggingMask Mod1 — 패키지 직접 검사 (크롤링 대안)",
    )
    p.add_argument(
        "--library",
        choices=["pytorch", "transformers", "numpy", "all"],
        default="all",
    )
    p.add_argument("--output", default="data/api_inspection.json")
    args = p.parse_args()

    from whitelist.seed import ALL_SEED_APIS
    existing = set(ALL_SEED_APIS)
    logger.info("시드 데이터 로드: %d개 API", len(existing))

    if args.library == "all":
        results = inspect_all(existing)
    else:
        results = [inspect_library(args.library, existing)]

    summary = {
        "libraries": {
            r.library: {"version": r.version, "count": r.total_extracted}
            for r in results
        },
        "total_apis": sum(r.total_extracted for r in results),
        "total_new": sum(len(r.new_apis) for r in results),
        "errors": sum(len(r.errors) for r in results),
    }
    print("=" * 60)
    print("  패키지 API 추출 완료")
    for lib, info in summary["libraries"].items():
        print(f"  {lib} {info.get('version', '?')}: {info['count']}개 API")
    print(f"  전체: {summary['total_apis']}개")
    print(f"  신규 (시드 대비): {summary['total_new']}개")
    print(f"  오류: {summary['errors']}건")
    print("=" * 60)

    serializable = {
        "inspected_at": datetime.now(timezone.utc).isoformat(),
        "summary": summary,
        "apis": [
            {
                "full_path": api.full_path,
                "namespace": api.namespace,
                "api_type": api.api_type,
                "version": api.version_tag,
                "signature": api.signature[:200] if api.signature else "",
            }
            for r in results
            for api in r.apis
        ],
    }
    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps(serializable, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(f"  결과 저장: {args.output}")


if __name__ == "__main__":
    main()
