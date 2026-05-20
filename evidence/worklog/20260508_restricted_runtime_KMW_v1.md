# Worklog — 검증2 제한 런타임 (CODE_RESTRICTED_RUNTIME) 구현

- **작성자:** 김민우 (KMW)
- **일시:** 2026-05-08
- **브랜치:** `feature/restricted-runtime-impl` (← `origin/dev`)
- **PR 대상:** `dev`
- **배경:** 양유상 영역의 검증 파이프라인 재할당 — 4 작업 중 #2 "제한 런타임 실행 구현 (별 4개)"이 김민우에게 배정됨. 양유상이 [code_validator.py](../../analyzer/validators/code_validator.py)의 B-1 PASS gate를 외부 `runtime_check` dict input + 테스트 stub으로만 두고 비워둔 자리를 진짜 격리 실행으로 채움.

## 작업 내용

### 신규 파일

| 파일 | 역할 |
|---|---|
| [analyzer/validators/code_restricted_runtime.py](../../analyzer/validators/code_restricted_runtime.py) | 격리 실행 엔진 (multiprocessing + builtins overlay + import hook + audit hook + 시간/메모리 제한) + orchestrator 호환 factory |
| [tests/test_restricted_runtime.py](../../tests/test_restricted_runtime.py) | 30 단위 + 통합 테스트 |

### 격리 메커니즘 (별 4 깊이)

```
restricted_exec(source, timeout_seconds=5, memory_limit_mb=256)
   │
   ├─ multiprocessing.Process (spawn)        ── 메인 프로세스 보호
   │   │
   │   ├─ [worker, Linux/Mac]
   │   │   resource.setrlimit(RLIMIT_AS, ...)  ── 가상 메모리 제한
   │   │
   │   ├─ sys.meta_path.insert(_ImportRestriction)   ── import hook
   │   │   • IMPORT_DENYLIST(subprocess/socket/pickle/ctypes/os 등) 차단
   │   │   • blocked_imports 리스트 누적
   │   │
   │   ├─ sys.modules cache 정리
   │   │   • 위험 모듈 제거 → cache hit 우회 방지
   │   │
   │   ├─ sys.addaudithook(_audit_hook)              ── audit hook
   │   │   • subprocess.Popen / os.system / socket.connect /
   │   │     ctypes.dlopen 즉시 raise
   │   │
   │   ├─ builtins overlay
   │   │   • RESTRICTED_BUILTINS(eval/exec/compile/open/getattr 등) 제거
   │   │   • __import__은 유지 (정상 import 문 동작 — hook이 차단)
   │   │
   │   └─ exec(compiled, user_globals)
   │
   └─ Process.join(timeout) + proc.kill              ── 시간 제한
```

### 결과 dict (양유상 호환)

`_normalize_runtime_check`의 키 셋을 정확히 충족 + 디버깅용 추가 필드:
```python
{
    "runtime_mode": "RESTRICTED_RUNTIME",
    "status": "PASS"|"FAIL"|"TIMEOUT"|"MEMORY_LIMIT"|"ERROR"|"SKIPPED",
    "builtins_removed": [...],
    "import_allowlist_applied": True,
    "dummy_forward_executed": False,        # 양유상 향후 확장
    "sandbox_runtime": None,                 # gVisor 영역 (다른 사람)
    "syscall_anomaly_detected": None,        # gVisor 영역
    "logs_ref": None,
    # 우리 추가 필드
    "blocked_imports": [...],
    "audit_events": [...],
    "exec_time_ms": 0.07,
    "exception_class": "ImportError"|None,
    "traceback": "..."|None,
}
```

`status == "PASS"`만 양유상 `_runtime_gate_passed()` 통과 → B-1/PASS/AUTO_APPROVE.

### Orchestrator 통합 — factory 패턴

양유상 `run_validation_job(runtime_check_loader=...)` 시그니처는 `Callable[[str], dict | None]`. 우리 `restricted_exec`는 source가 필요해서 wrapping factory:

```python
loader = make_restricted_runtime_loader(sources, timeout_seconds=5.0)
run_validation_job(
    request,
    source_loader=sources,
    runtime_check_loader=loader,        # ← 자동으로 우리 격리 실행
    ...
)
```

## 검증 결과

```
238 passed, 1 skipped in 11.17s
```

`test_memory_limit_triggers_memory_status`만 Windows에서 skip (RLIMIT_AS 미지원). Docker(Linux) 환경에서는 동작.

### 시나리오별 검증 (TestPhase2Isolation 10 + Phase3 2 + Phase4 3)

| 입력 | 결과 |
|---|---|
| `x = 1+2*3` | PASS, exception 없음 |
| `import subprocess; subprocess.run([...])` | FAIL + blocked_imports=[subprocess] |
| `eval('1+1')` | FAIL (NameError, builtins overlay) |
| `exec('y=1')` | FAIL (NameError) |
| `open('/etc/passwd')` | FAIL (NameError) |
| `1/0` | FAIL + traceback 캡처 |
| `while True: pass` | TIMEOUT (TimeoutError) |
| `class Demo: ...; Demo().forward(...)` | PASS (정상 모델링 시나리오) |
| `bytearray(1GB)` (Linux only) | MEMORY_LIMIT (MemoryError) |
| 양유상 e2e via run_validation_job | runtime_check dict가 양유상에 정상 forward |

| 시점 | 케이스 |
|---|---|
| origin/dev | 209 |
| **본 PR (Phase 1+2+3+4)** | **238 passed + 1 skipped** (+30) |

원본 로그: [evidence/tests/20260508_restricted_runtime_pytest_raw_KMW_v1.txt](../tests/20260508_restricted_runtime_pytest_raw_KMW_v1.txt)

## 책임 경계

- 양유상 production 코드 **무수정** — `runtime_check_loader`라는 이미 정의된 hook에 우리 함수 주입만.
- 결과 dict가 `_normalize_runtime_check` 키 셋 정확히 충족 → 양유상 grade 결정 로직 그대로 사용.
- gVisor / OS-level syscall 격리는 검증3 영역(다른 사람) — 우리는 in-process Python 격리만 책임.
- `dummy_forward_executed`는 양유상 향후 확장 (모델 클래스 forward 한 번 호출까지 검증). 1차 구현 범위 밖, future work.

## 변경 파일

- 신규: `analyzer/validators/code_restricted_runtime.py` (~360줄)
- 신규: `tests/test_restricted_runtime.py` (~290줄)
- 신규: `evidence/tests/20260508_restricted_runtime_pytest_raw_KMW_v1.txt`
- 신규: `evidence/worklog/20260508_restricted_runtime_KMW_v1.md` (이 파일)

코드 변경 없음 (양유상 / 박용담 / 정은미 영역 전부 무수정).

## 확인 요청 사항

1. **@yangyu0330** — 결과 dict 스키마(`_normalize_runtime_check` 키 셋)를 정확히 충족했는지 확인 부탁. 추가 필드(`blocked_imports`, `audit_events`, `exec_time_ms` 등)가 grade 결정 로직에 노이즈 안 되는지.

2. **@yangyu0330** — `dummy_forward_executed=False` 기본값. 모델 클래스 `forward()` 호출까지 자동 시도하는 휴리스틱이 별 4 범위인지, 별 5 범위인지 의견 부탁. 별 4 범위라면 후속 PR로 추가.

3. **메모리 제한 cross-platform** — Windows는 RLIMIT_AS 없어서 skip. 운영 환경 Docker(Linux)에서는 동작. Windows 개발 환경에서 메모리 제한 필요하면 psutil 모니터링 추가 가능 (의존성 +1).

4. **별 4 기준** — 본 PR 깊이가 별 4 기대치에 부합하는지 확인 부탁. 별 5 (gVisor)는 검증3 영역으로 다른 사람.

## 후속

- mock_hf hm-04 (악성 코드 시나리오)에서 우리 제한 런타임이 `import subprocess` 등을 잡는지 통합 검증 (Phase 5 후속 PR)
- `dummy_forward_executed` 휴리스틱 (양유상 합의 후)
- `code_validator` 호출 진입점에 wrapper 추가 (PR #14 wrapper와 통합)
