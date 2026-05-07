"""
검증2: 제한 런타임 (RESTRICTED_RUNTIME) — B-1 후보 PASS gate

정적 분석(AST + API)만으론 못 잡는 동적 위험을 거르기 위해, 위험 builtins/
import를 제거한 격리 환경에서 코드를 실제 실행해보고 시그널을 수집한다.
양유상의 ``code_validator``가 받는 ``runtime_check`` dict 스키마를 정확히
충족하는 결과를 반환한다.

설계 (docs/코드검증_최종_설계서.md:151, 778-786):
- B-1 후보 (정적 분석 안전, 정형 modeling 코드)만 대상
- 위험 API 발견 코드는 호출 전에 BLOCK되므로 여기까지 오지 않음
- 격리 수준은 in-process Python (OS 레벨은 검증3 ``CODE_SANDBOX_RUNTIME`` 영역)

격리 메커니즘 (별 4 / Phase 2~3):
1. Python 서브프로세스 격리 (multiprocessing.Process)
2. builtins 화이트리스트 overlay (``__builtins__``를 안전 dict로 교체)
3. import allowlist (sys.meta_path import hook)
4. audit hook (sys.addaudithook)
5. 시간 제한 (Process.join(timeout) + Process.kill)
6. 메모리 제한 (Linux: resource.setrlimit, Windows: psutil 모니터)

이 파일은 Phase 1 skeleton — 핵심 인터페이스와 결과 dataclass만 정의.
실제 격리 메커니즘은 Phase 2~3에서 구현.
"""

from __future__ import annotations

import logging
from dataclasses import asdict, dataclass, field
from typing import Any


logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────
# 결과 모델 — 양유상 _normalize_runtime_check 스키마 호환
# ─────────────────────────────────────────────

# 위험 builtins — 제거 대상 (양유상 PERMANENTLY_BLOCKED와 정합)
RESTRICTED_BUILTINS: tuple[str, ...] = (
    "eval", "exec", "compile", "__import__",
    "open", "input",
    "globals", "locals", "vars",
    "getattr", "setattr", "delattr",
    "breakpoint", "memoryview",
)

# import 허용 목록 — 모델링 코드에 필요한 안전한 라이브러리
IMPORT_ALLOWLIST: frozenset[str] = frozenset({
    "torch", "torch.nn", "torch.nn.functional", "torch.optim",
    "torch.autograd", "torch.linalg", "torch.fft", "torch.special",
    "torch.cuda", "torch.amp", "torch.backends",
    "numpy",
    "transformers",
    "math", "typing", "dataclasses", "enum", "functools", "itertools",
    "abc", "collections", "collections.abc",
})

# 명시적 차단 — 즉시 abort
IMPORT_DENYLIST: frozenset[str] = frozenset({
    "subprocess", "socket", "requests", "urllib", "urllib.request",
    "httpx", "aiohttp",
    "os", "shutil", "sys",
    "pickle", "marshal", "shelve", "ctypes",
    "importlib",
})


# 결과 status 값 (양유상 _runtime_gate_passed가 "PASS"만 통과시킴)
class RuntimeStatus:
    PASS = "PASS"
    FAIL = "FAIL"
    TIMEOUT = "TIMEOUT"
    MEMORY_LIMIT = "MEMORY_LIMIT"
    ERROR = "ERROR"
    SKIPPED = "SKIPPED"


@dataclass
class RestrictedRuntimeResult:
    """제한 런타임 실행 결과.

    양유상 ``code_validator._normalize_runtime_check`` 키 셋을 정확히
    포함한다. 추가 필드(``audit_events``, ``exec_time_ms``, ``peak_memory_mb``,
    ``exception_class`` 등)는 디버깅·증거 수집용.
    """
    # 양유상 호환 키
    runtime_mode: str = "RESTRICTED_RUNTIME"
    status: str = RuntimeStatus.SKIPPED
    builtins_removed: list[str] = field(default_factory=list)
    import_allowlist_applied: bool = False
    dummy_forward_executed: bool = False
    sandbox_runtime: str | None = None      # gVisor 영역 — 항상 None
    syscall_anomaly_detected: bool | None = None  # gVisor 영역 — 항상 None
    logs_ref: str | None = None

    # 우리 추가 필드 (audit / 증거 수집용)
    blocked_imports: list[str] = field(default_factory=list)
    audit_events: list[str] = field(default_factory=list)
    exec_time_ms: float = 0.0
    peak_memory_mb: float = 0.0
    exception_class: str | None = None
    traceback: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """양유상 ``runtime_check_loader`` 가 받는 dict 형식으로 변환."""
        return asdict(self)


# ─────────────────────────────────────────────
# 메인 진입점 (Phase 2~3에서 구현)
# ─────────────────────────────────────────────

def restricted_exec(
    source: str,
    *,
    timeout_seconds: float = 5.0,
    memory_limit_mb: int = 256,
    extra_import_allowlist: frozenset[str] | None = None,
) -> RestrictedRuntimeResult:
    """제한 런타임에서 ``source`` 코드를 실행하고 시그널을 수집한다.

    Args:
        source: 실행할 Python 소스 코드 (str)
        timeout_seconds: 시간 제한 (초)
        memory_limit_mb: 메모리 제한 (MB)
        extra_import_allowlist: 기본 ``IMPORT_ALLOWLIST``에 추가할 모듈

    Returns:
        ``RestrictedRuntimeResult``. ``status``가 ``"PASS"``이면 양유상의
        ``_runtime_gate_passed()``가 통과 인정 → B-1 PASS gate.

    구현 단계:
        Phase 1 (현재): skeleton — SKIPPED 반환
        Phase 2: subprocess + builtins overlay + import hook + audit hook
        Phase 3: 시간/메모리 제한 + cross-platform
    """
    # Phase 1 skeleton — 실제 실행 없이 안전하게 SKIPPED 반환.
    # 양유상 _runtime_gate_passed()는 PASS만 통과시키므로 SKIPPED는
    # B-1 gate를 통과 못 시킨다 — 따라서 안전 (false positive 0).
    logger.info(
        "restricted_exec skeleton: source %d bytes, timeout=%.1fs, memory=%dMB",
        len(source), timeout_seconds, memory_limit_mb,
    )
    return RestrictedRuntimeResult(
        runtime_mode="RESTRICTED_RUNTIME",
        status=RuntimeStatus.SKIPPED,
        builtins_removed=[],
        import_allowlist_applied=False,
        dummy_forward_executed=False,
    )


# ─────────────────────────────────────────────
# code_validator 통합용 어댑터 (Phase 4에서 사용)
# ─────────────────────────────────────────────

def runtime_check_loader(
    repo_path: str,
    *,
    source_loader: Any,
    timeout_seconds: float = 5.0,
    memory_limit_mb: int = 256,
) -> dict[str, Any] | None:
    """양유상 ``run_validation_job(..., runtime_check_loader=...)``에 주입할 어댑터.

    ``repo_path``를 받아 ``source_loader``로 소스를 로드하고 ``restricted_exec``
    실행 결과 dict를 반환. ``code_validator``의 ``_normalize_runtime_check``가
    이 dict를 받아 grade 결정에 사용한다.

    Phase 1: skeleton — 항상 SKIPPED 반환 (양유상 stub 동작과 동일).
    """
    # source_loader가 callable 또는 mapping
    source: str | bytes | None
    if callable(source_loader):
        source = source_loader(repo_path)
    elif hasattr(source_loader, "get"):
        source = source_loader.get(repo_path)
    else:
        return None

    if source is None:
        return None
    if isinstance(source, bytes):
        source = source.decode("utf-8", errors="replace")

    result = restricted_exec(
        source,
        timeout_seconds=timeout_seconds,
        memory_limit_mb=memory_limit_mb,
    )
    return result.to_dict()


__all__ = [
    "RestrictedRuntimeResult", "RuntimeStatus",
    "RESTRICTED_BUILTINS", "IMPORT_ALLOWLIST", "IMPORT_DENYLIST",
    "restricted_exec", "runtime_check_loader",
]
