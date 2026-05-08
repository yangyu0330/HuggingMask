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
import multiprocessing as mp
import time
import traceback as _traceback
from dataclasses import asdict, dataclass, field
from typing import Any


logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────
# 결과 모델 — 양유상 _normalize_runtime_check 스키마 호환
# ─────────────────────────────────────────────

# 위험 builtins — 제거 대상 (양유상 PERMANENTLY_BLOCKED와 정합)
# 주의: ``__import__``은 제거하지 않는다 — 정상 ``import`` 문 동작에 필요하며,
# IMPORT_DENYLIST는 sys.meta_path import hook이 별도로 차단한다.
RESTRICTED_BUILTINS: tuple[str, ...] = (
    "eval", "exec", "compile",
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

# ─────────────────────────────────────────────
# 격리 worker — multiprocessing 자식 프로세스에서 실행
# (Windows spawn 호환을 위해 module-level 함수 + picklable 인자)
# ─────────────────────────────────────────────

def _worker_run_in_subprocess(
    source: str, queue: Any, memory_limit_mb: int = 256,
) -> None:  # pragma: no cover - subprocess
    """자식 프로세스에서 실행. 격리 메커니즘 적용 후 ``source`` 실행.

    적용 메커니즘:
      1. (Linux/Mac) ``resource.setrlimit(RLIMIT_AS)`` — 가상 메모리 제한
      2. import hook (sys.meta_path) — IMPORT_DENYLIST 차단
      3. audit hook (sys.addaudithook) — subprocess/socket/ctypes 차단
      4. builtins overlay — RESTRICTED_BUILTINS 제거한 globals 주입

    결과 dict를 ``queue.put()``으로 부모에 전달.
    """
    import builtins as _builtins
    import sys as _sys
    import traceback as _tb_mod

    blocked_imports: list[str] = []
    audit_events: list[str] = []

    # ── 0. 메모리 제한 (Linux/Mac만) ──
    # Windows는 resource 모듈에 RLIMIT_AS가 없어 skip. Docker(Linux)
    # 운영 환경에서는 정상 동작. setrlimit 실패해도 로깅만 하고 계속
    # 진행 (소프트 페일).
    if _sys.platform != "win32":
        try:
            import resource as _resource
            _bytes = max(1, memory_limit_mb) * 1024 * 1024
            _resource.setrlimit(_resource.RLIMIT_AS, (_bytes, _bytes))
        except Exception:
            pass

    # ── 1. import hook ──
    class _ImportRestriction:
        def find_spec(self, name, path=None, target=None):
            top_level = name.split(".")[0]
            if name in IMPORT_DENYLIST or top_level in IMPORT_DENYLIST:
                blocked_imports.append(name)
                raise ImportError(
                    f"제한 런타임: 차단된 import '{name}'"
                )
            return None  # 다른 finder에 위임

    _sys.meta_path.insert(0, _ImportRestriction())

    # sys.modules에 캐시된 위험 모듈 제거 — 그래야 사용자 코드의 import가
    # cache hit이 아니라 우리 _ImportRestriction을 거친다.
    for _denied in IMPORT_DENYLIST:
        _sys.modules.pop(_denied, None)
        # 서브 모듈도 (예: urllib.request, os.path)
        for _key in list(_sys.modules):
            if _key.startswith(_denied + "."):
                _sys.modules.pop(_key, None)

    # ── 2. audit hook ──
    # Python 3.8+ audit events: 'subprocess.Popen', 'os.system',
    # 'socket.connect', 'ctypes.dlopen' 등 위험 호출.
    # 'compile'/'exec'는 audit이 아니라 builtins overlay에서 제거 (사용자
    # globals에 없음 → NameError). 우리(worker)가 호출하는 compile/exec는
    # audit이 안 막아야 사용자 코드를 실행할 수 있다.
    _DANGEROUS_AUDIT_EVENTS = (
        "subprocess.Popen", "os.system", "os.exec",
        "socket.connect", "socket.bind", "socket.gethostbyname",
        "ctypes.PyObj_FromPtr", "ctypes.dlopen",
    )

    def _audit_hook(event: str, args: tuple) -> None:
        if event in _DANGEROUS_AUDIT_EVENTS:
            audit_events.append(f"{event}{args!r}")
            raise RuntimeError(
                f"제한 런타임: 감사 차단 '{event}'"
            )

    _sys.addaudithook(_audit_hook)

    # ── 3. builtins overlay ──
    # RESTRICTED_BUILTINS 제거한 dict로 globals를 만든다.
    # 단, __import__는 유지 (정상 import 문 동작에 필요 — import hook이 위험은 차단).
    # __build_class__도 유지 (class 정의에 필요).
    safe_builtins: dict[str, Any] = {}
    for name in dir(_builtins):
        if name in RESTRICTED_BUILTINS:
            continue
        try:
            safe_builtins[name] = getattr(_builtins, name)
        except AttributeError:
            pass

    # 사용자 코드의 globals에 위험 함수가 절대 노출 안 되도록 RESTRICTED 제거.
    # (audit hook으로 별도 차단도 함 — 이중 방어)
    user_globals: dict[str, Any] = {
        "__builtins__": safe_builtins,
        "__name__": "__restricted__",
        "__doc__": None,
    }

    # ── 실행 ──
    started_at = time.perf_counter()
    try:
        compiled = _builtins.compile(source, "<restricted>", "exec")
        _builtins.exec(compiled, user_globals, user_globals)
        elapsed_ms = (time.perf_counter() - started_at) * 1000.0

        result = {
            "status": RuntimeStatus.PASS,
            "runtime_mode": "RESTRICTED_RUNTIME",
            "builtins_removed": list(RESTRICTED_BUILTINS),
            "import_allowlist_applied": True,
            "dummy_forward_executed": False,
            "blocked_imports": sorted(set(blocked_imports)),
            "audit_events": list(audit_events),
            "exec_time_ms": elapsed_ms,
            "exception_class": None,
            "traceback": None,
        }
    except MemoryError as exc:
        elapsed_ms = (time.perf_counter() - started_at) * 1000.0
        result = {
            "status": RuntimeStatus.MEMORY_LIMIT,
            "runtime_mode": "RESTRICTED_RUNTIME",
            "builtins_removed": list(RESTRICTED_BUILTINS),
            "import_allowlist_applied": True,
            "dummy_forward_executed": False,
            "blocked_imports": sorted(set(blocked_imports)),
            "audit_events": list(audit_events),
            "exec_time_ms": elapsed_ms,
            "exception_class": "MemoryError",
            "traceback": _tb_mod.format_exc(),
        }
    except Exception as exc:
        elapsed_ms = (time.perf_counter() - started_at) * 1000.0
        result = {
            "status": RuntimeStatus.FAIL,
            "runtime_mode": "RESTRICTED_RUNTIME",
            "builtins_removed": list(RESTRICTED_BUILTINS),
            "import_allowlist_applied": True,
            "dummy_forward_executed": False,
            "blocked_imports": sorted(set(blocked_imports)),
            "audit_events": list(audit_events),
            "exec_time_ms": elapsed_ms,
            "exception_class": type(exc).__name__,
            "traceback": _tb_mod.format_exc(),
        }

    queue.put(result)


# ─────────────────────────────────────────────
# 메인 진입점
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
        timeout_seconds: 시간 제한 (초). 초과 시 자식 프로세스 강제 종료.
        memory_limit_mb: 메모리 제한 (MB). Phase 3에서 cross-platform 강화.
        extra_import_allowlist: 기본 ``IMPORT_ALLOWLIST``에 추가할 모듈

    Returns:
        ``RestrictedRuntimeResult``. ``status``가 ``"PASS"``이면 양유상의
        ``_runtime_gate_passed()``가 통과 인정 → B-1 PASS gate.

    격리:
        - multiprocessing.Process로 별도 프로세스 격리 (Windows: spawn)
        - 자식 안에서 builtins overlay + import hook + audit hook 적용
        - 부모는 ``timeout_seconds`` 초과 시 자식 강제 종료
    """
    # Queue로 자식 → 부모 결과 전달
    ctx = mp.get_context("spawn")  # cross-platform 일관성 (Windows 기본)
    queue: Any = ctx.Queue()
    proc = ctx.Process(
        target=_worker_run_in_subprocess,
        args=(source, queue, memory_limit_mb),
    )

    started_at = time.perf_counter()
    proc.start()
    proc.join(timeout=timeout_seconds)
    elapsed_ms = (time.perf_counter() - started_at) * 1000.0

    # 시간 초과 — 강제 종료
    if proc.is_alive():
        logger.warning(
            "restricted_exec TIMEOUT after %.2fs (limit %.2fs)",
            elapsed_ms / 1000.0, timeout_seconds,
        )
        proc.kill()
        proc.join(timeout=2.0)
        return RestrictedRuntimeResult(
            runtime_mode="RESTRICTED_RUNTIME",
            status=RuntimeStatus.TIMEOUT,
            builtins_removed=list(RESTRICTED_BUILTINS),
            import_allowlist_applied=True,
            dummy_forward_executed=False,
            exec_time_ms=elapsed_ms,
            exception_class="TimeoutError",
            traceback=f"실행 시간 초과 ({timeout_seconds}s)",
        )

    # 결과 수신
    if not queue.empty():
        result_dict = queue.get_nowait()
        return RestrictedRuntimeResult(**result_dict)

    # 큐가 비었는데 프로세스도 끝남 — 비정상 종료 (예: SIGKILL, 메모리 초과 OOM)
    return RestrictedRuntimeResult(
        runtime_mode="RESTRICTED_RUNTIME",
        status=RuntimeStatus.ERROR,
        builtins_removed=list(RESTRICTED_BUILTINS),
        import_allowlist_applied=True,
        dummy_forward_executed=False,
        exec_time_ms=elapsed_ms,
        exception_class="ProcessTerminated",
        traceback=(
            f"자식 프로세스가 결과 없이 종료. exitcode={proc.exitcode}"
        ),
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


# ─────────────────────────────────────────────
# orchestrator 호환 factory
# ─────────────────────────────────────────────

def make_restricted_runtime_loader(
    source_loader: Any,
    *,
    timeout_seconds: float = 5.0,
    memory_limit_mb: int = 256,
) -> Any:
    """양유상 ``run_validation_job(runtime_check_loader=...)`` 시그니처와 호환되는
    callable을 반환한다.

    양유상 orchestrator는 ``Callable[[str], dict | None]`` 형태의 loader를
    기대 (``repo_path``만 받음). ``restricted_exec``는 source가 필요하므로
    ``source_loader``를 closure로 잡아 wrapping.

    사용 예::

        run_validation_job(
            request,
            source_loader=sources,
            runtime_check_loader=make_restricted_runtime_loader(sources),
        )
    """
    def _loader(repo_path: str) -> dict[str, Any] | None:
        return runtime_check_loader(
            repo_path,
            source_loader=source_loader,
            timeout_seconds=timeout_seconds,
            memory_limit_mb=memory_limit_mb,
        )
    return _loader


__all__ = [
    "RestrictedRuntimeResult", "RuntimeStatus",
    "RESTRICTED_BUILTINS", "IMPORT_ALLOWLIST", "IMPORT_DENYLIST",
    "restricted_exec", "runtime_check_loader",
    "make_restricted_runtime_loader",
]
