# Worklog — PR #17 양유상 리뷰 응답 (P1 4건 + P2 3건 + P3 1건)

- **작성자:** 김민우 (KMW)
- **일시:** 2026-05-09
- **브랜치:** `feature/restricted-runtime-impl` (PR #17)
- **리뷰 입력:** 양유상 3차 CHANGES_REQUESTED (2026-05-09T12:08:46Z)

## 양유상 리뷰 항목

| 우선순위 | 항목 | 위치 |
|---|---|---|
| P1 | dispatch_artifacts가 정적 분석 전에 runtime 실행 | `analyzer/orchestrator.py:112-121` |
| P1 | `object.__subclasses__()` → `catch_warnings` → real builtins 회수 | `analyzer/validators/code_restricted_runtime.py:303` 근처 |
| P1 | `_SafeSysProxy._getframe` 노출 → worker frame `_builtins` 회수 | `analyzer/validators/code_restricted_runtime.py:280-291` |
| P1 | `_io.FileIO`를 객체 그래프로 찾아 임의 파일 read | `analyzer/validators/code_restricted_runtime.py:235` 근처 |
| P2 | sanitizer가 dataclasses 정상 사용 깨뜨림 | 같은 파일 :303 근처 |
| P2 | torch/numpy allowlist vs 실제 fail-closed 명세 정리 | 같은 파일 :55, 190-199 |
| P2 | Windows 메모리 제한 docstring vs 코드 불일치 | 같은 파일 :20, 181-187 |
| P3 | evidence 파일 테스트 수치 stale | `evidence/worklog/20260508_*` |

## 수정 요약

### P1 #1 — orchestrator 순서

`analyzer/orchestrator.py:dispatch_artifacts`에서 PYTHON artifact 처리 시
`runtime_check_loader`를 무조건 먼저 호출하던 흐름을 분리:

1. 첫 번째 `validate_python_artifact` 호출은 `runtime_check=None`으로 정적 게이트만 평가
2. 결과가 `ValidationStatus.BLOCK`이면 그 결과 그대로 반환 — runtime check **미호출**
3. BLOCK이 아닐 때만 `runtime_check_loader`를 호출하고 두 번째 `validate_python_artifact`로 최종 결과 도출

회귀 테스트 (`TestPr17ReviewP1OrchestratorOrder`):
- `test_static_block_skips_runtime` — 위험 코드 → `runtime_call_count == 0`
- `test_safe_code_calls_runtime` — 안전 코드 → `runtime_call_count == 1`

### P1 #2 + #4 — 객체 그래프 우회 차단

새 AST 사전 검사(`_scan_dangerous_dunders`) 추가. 위험 dunder attribute가
사용자 코드에 등장하면 자식 spawn 전에 즉시 `RuntimeStatus.FAIL`
(`exception_class="DangerousDunderAccess"`).

차단 dunder 목록 (`DANGEROUS_DUNDER_ATTRS`):

```
__class__, __bases__, __base__, __mro__, __subclasses__, __init_subclass__,
__globals__, __builtins__, __import__, __loader__, __spec__, __file__,
__path__, __package__, __dict__, __weakref__,
__getattribute__, __setattr__, __delattr__,
__code__, __func__, __self__, __closure__, __defaults__, __kwdefaults__,
__wrapped__, __qualname__, __annotations__
```

정상 dunder(`__init__`, `__name__`, `__doc__`, `__repr__`, `__str__`,
`__call__`, `__enter__`, `__exit__`, `__iter__` 등)는 허용.

회귀 테스트 (`TestPr17ReviewP1Bypass` + `TestPr17ReviewAstScan`):
- `test_subclasses_chain_to_real_builtins` — `().__class__.__mro__[1].__subclasses__()` → FAIL
- `test_io_fileio_via_subclasses` — `_io.FileIO` 회수 → FAIL
- `test_dataclasses_builtins_dict_eval` — `dataclasses.__builtins__["eval"]` → FAIL
- `test_functools_builtins_dict_open` — `functools.__builtins__["open"]` → FAIL
- `test_typing_sys_modules_builtins` — `typing.sys.modules['builtins']` → FAIL
- `test_function_globals_builtins` — `dataclass.__globals__["__builtins__"]` → FAIL
- `test_dangerous_dunder_attribute_blocked` (parametrize 10건) — 각 dunder 단독 access → FAIL
- `test_safe_dunders_allowed` — `__init__/__repr__` 정의는 PASS

### P1 #3 — `_SafeSysProxy` frame/trace 차단

`_blocked_attrs` 셋에 frame/trace introspection 항목 추가:

```python
_blocked_attrs = {
    "meta_path", "path_hooks", "path_importer_cache",  # 기존
    "_getframe", "_current_frames",                    # 신규
    "settrace", "gettrace", "setprofile", "getprofile",
    "_clear_type_cache", "_debugmallocstats",
    "set_coroutine_origin_tracking_depth",
    "audit", "addaudithook",
}
```

또한 `typing` 모듈을 `_SANITIZE_PRESERVE_STDLIB`에서 제거. typing은
사용자에게 `typing.sys`로 real `sys`를 노출시켜 우회 면을 만들기 때문.
이제 `import typing; typing.sys.<attr>`는 `safe_sys_proxy`를 거치고,
`_blocked_attrs`에 있으면 `RuntimeError`.

회귀 테스트 (`TestPr17ReviewSysProxyFrame`, `TestPr17ReviewP1Bypass`):
- `test_sys_getframe_to_worker_locals` — `typing.sys._getframe()` → FAIL
- `test_sys_proxy_blocks_frame_attrs` (parametrize 6건) — 각 frame/trace
  attribute 접근 → FAIL

### P2 #5 — dataclasses 정상 사용 보호

`_SANITIZE_PRESERVE_STDLIB` 화이트리스트 도입:

```python
_SANITIZE_PRESERVE_STDLIB = frozenset({
    "dataclasses", "functools", "itertools",
    "abc", "collections", "collections.abc",
    "enum", "math",
})
```

이 모듈은 `_sanitize_user_visible_object`에서 `__builtins__` 교체 면제.
`@dataclass` 데코레이터는 내부적으로 `exec`로 `__init__`을 동적 생성하므로
`__builtins__`를 safe overlay로 바꾸면 정상 사용이 깨졌었음.

추가로, 사용자 코드를 `__restricted__` 이름의 fake module로 만들어
real `sys.modules`에 등록한다. dataclass 데코레이터는
`sys.modules.get(cls.__module__).__dict__`로 클래스 정의 위치를 조회하므로
fake module이 등록돼 있어야 정상 동작. (사용자가 `__restricted__`를
직접 import하려 해도 `IMPORT_ALLOWLIST`에 없어 차단됨.)

`typing`은 sys 노출 우회 면 때문에 preserve list에서 제외 — 사용자가
`import typing; typing.sys`를 하면 sanitize된 `safe_sys_proxy`를 받음.

회귀 테스트 (`TestPr17ReviewP2Dataclasses`):
- `test_dataclass_decorator_normal_use` — `@dataclass class Point: x: int` → PASS
- `test_functools_lru_cache_normal_use` — `@functools.lru_cache` 데코레이터 → PASS

### P2 #6 — torch/numpy 명세 정리

모듈 docstring에 fail-closed 정책 명시:

> `IMPORT_ALLOWLIST`는 사용자 코드의 직접 import 화이트리스트.
> `torch`/`numpy` 등 라이브러리는 내부에서 `ctypes`/`os`를 import하므로
> fail-closed 정책으로 실제로는 통과하지 않는다 (의도된 동작).

코드 동작 변경 없음 — 명세-실제 정합성 확보.

### P2 #7 — Windows 메모리 제한 docstring

모듈 docstring 정정:

> 메모리 제한 — Linux/Mac: `resource.setrlimit(RLIMIT_AS)`.
> Windows에는 `RLIMIT_AS`가 없어 skip한다 (운영은 Docker(Linux) 전제).

이전 docstring의 "Windows: psutil 모니터" 표기 제거 (코드는 skip이라 일치).

### P3 #8 — evidence 갱신

본 worklog 자체가 갱신. 새 pytest raw:
[evidence/tests/20260509_pr17_review_response_pytest_raw_KMW_v1.txt](../tests/20260509_pr17_review_response_pytest_raw_KMW_v1.txt)

## 추가 보강 — audit hook 'open' 시도 후 철회

리뷰 응답 검토 중 audit hook에 `open` 이벤트 추가를 시도했으나, 이 이벤트는
사용자 코드뿐 아니라 import 처리 중 Python이 .py/.pyc 파일을 여는 것까지
잡혀 정상 import가 깨진다. 따라서 추가하지 않고 모듈 코멘트로 사유 명시.
P1 #4의 `_io.FileIO` 우회는 `__subclasses__` AST 차단으로 잡힌다.

## 검증 결과

```
287 passed, 3 skipped in 21.33s
```

| 시점 | 케이스 |
|---|---|
| 양유상 마지막 push 시점(`dd3f8db`) | 259 passed, 1 skipped |
| **본 리뷰 응답** | **287 passed, 3 skipped** (+28) |

신규 28 케이스 분포:
- `TestPr17ReviewP1Bypass` — 7
- `TestPr17ReviewP1OrchestratorOrder` — 2
- `TestPr17ReviewP2Dataclasses` — 2
- `TestPr17ReviewAstScan` — 12 (parametrize 10 + 정상 dunder + 형식 검증)
- `TestPr17ReviewSysProxyFrame` — 6 (parametrize)
- 추가 skip 2건 — Windows 환경 detection 강화

회귀 없음 — 기존 259 (양유상 fix 포함) 그대로 통과.

## 책임 경계 (변경 없음)

- 양유상 production 코드 무수정 — `runtime_check_loader` hook + `dispatch_artifacts` 흐름 조정만 추가
- gVisor / OS-level syscall 격리는 검증 3 영역 (다른 사람) — 본 PR은 in-process Python 격리만
- 코드 등급 결정은 양유상 책임 — 우리는 result dict만 정확히 채움

## 양유상 force-push 메시지 정정 안내 (commit `15f813d`/`fccbd25`)

별도로 양유상이 직접 push한 두 fix 커밋(`dd3f8db`, `400c134`)이 깃 규칙
형식(`[타입] 작업대상: 내용`)과 어긋나 force-with-lease로 메시지만 reword함:

- `dd3f8db fix: sanitize ...` → `15f813d [fix] runtime: sanitize ...`
- `400c134 fix: enforce ...` → `fccbd25 [fix] runtime: enforce ...`

cherry-pick + amend로 처리해 author 정보(yangyu0330)와 코드 diff(0줄)는
완전 보존. 본 worklog의 P1+P2+P3 fix는 그 위에 추가됨.
