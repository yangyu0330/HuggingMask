# Worklog — PR #14 양유상 리뷰 응답

- **작성자:** 김민우 (KMW)
- **일시:** 2026-05-06
- **PR:** #14 (`feature/whitelist-code-validator-integration` → `dev`)
- **응답 대상:** 양유상 리뷰 (2026-05-06 05:59 UTC, CHANGES_REQUESTED)

## 양유상 지적 (요약)

> `WhitelistEngineLookup`만 주입하는 기존 validation job 경로에서는
> `build_compatible_policy()`가 자동으로 적용되지 않아, 우리 PERMANENTLY_BLOCKED_APIS에만
> 있는 API(예: `pickle.loads`)가 BLOCK이 아닌 PENDING_REVIEW로 처리됩니다.
>
> **해결 방향**: 어댑터 사용 진입점을 하나로 묶어 `WhitelistEngineLookup`과
> `build_compatible_policy()`를 항상 함께 적용하거나, validate_python_artifact /
> run_validation_job 쪽 policy resolution에 compatible policy를 연결.

지적 정확합니다. 우리가 어댑터·정책을 따로 export하면서 사용 시점에 둘 다 명시 주입해야 하는 구조였고, 호출자가 한쪽만 쓰면 빈틈 발생.

## 해결 — 단일 진입점 wrapper 두 개

### 1. `validate_python_with_whitelist_engine(...)` (single artifact)

양유상 `validate_python_artifact`가 `policy: PolicyInfo | ApiPolicy | None`을 받으므로 **ApiPolicy를 직접 주입** (monkey-patch 불필요):

```python
def validate_python_with_whitelist_engine(
    artifact, source, *, db, engine=None, job_id="", model=None,
    api_policy=None, **forward,
):
    resolved_policy = api_policy or build_compatible_policy()
    with WhitelistEngineLookup(db=db, engine=engine, ...) as lookup:
        return validate_python_artifact(
            artifact, source,
            policy=resolved_policy,         # ApiPolicy 직접
            whitelist_lookup=lookup,
            **forward,
        )
```

### 2. `run_validation_job_with_whitelist_engine(...)` (orchestrator)

orchestrator는 `request.policy: PolicyInfo`만 forward하고 `_resolve_api_policy`가 `default_api_policy(policy_version=...)`로 변환. ApiPolicy 직접 주입 불가.

**해결**: `_patched_default_policy()` contextmanager로 `default_api_policy`를 임시 교체. **모든 from-import 사이트** (`code_api_policy`, `code_api`, `code_validator`)에서 함께 교체해야 함 (Python `from x import y`는 import 시점에 이름 바인딩되므로 한 사이트만 patch하면 다른 사이트는 옛날 함수를 가리킴).

```python
@contextmanager
def _patched_default_policy():
    sites = [code_api_policy, code_api, code_validator]
    originals = []
    for mod in sites:
        if hasattr(mod, "default_api_policy"):
            originals.append((mod, mod.default_api_policy))
            mod.default_api_policy = build_compatible_policy
    try:
        yield
    finally:
        for mod, original in originals:
            mod.default_api_policy = original
```

### Limitation 명시

monkey-patch는 module-level이라 multi-thread 동시 호출에 한 번에 한 흐름만 안전. 단일 스레드(CLI/테스트/데모)에 한정. 향후 양유상 측에서 `_resolve_api_policy`가 우리 합집합 정책을 직접 인식하도록 개선되면 monkey-patch 제거 가능.

## 회귀 테스트 (5 신규)

[tests/integration/test_yangyu_whitelist_e2e.py::TestYangyuReviewRegression](../../tests/integration/test_yangyu_whitelist_e2e.py):

| 테스트 | 검증 |
|---|---|
| `test_validate_python_wrapper_blocks_pickle_loads` | wrapper 통한 `pickle.loads` 코드 검증 → BLOCK |
| `test_run_validation_job_wrapper_blocks_pickle_loads` | **양유상 재현 시나리오 그대로** — orchestrator wrapper로 BLOCK |
| `test_other_perm_blocked_apis_also_caught` | `marshal.loads` / `ctypes.CDLL` / `importlib.import_module` 모두 BLOCK |
| `test_patched_default_policy_restores_after_exit` | 정상 종료 후 `default_api_policy` 복원 |
| `test_patched_default_policy_restores_on_exception` | 예외 발생해도 복원 |

## 변경 파일

수정:
- `whitelist/integration.py` — `_patched_default_policy`, `validate_python_with_whitelist_engine`, `run_validation_job_with_whitelist_engine` 추가 (+~120줄)
- `tests/integration/test_yangyu_whitelist_e2e.py` — 5 회귀 테스트 + ValidationJobRequest 빌더 헬퍼

## 테스트 결과

```
238 passed in 6.01s
```

| 시점 | 케이스 |
|---|---|
| PR #14 commit 전 (Step D 포함) | 233 |
| **양유상 리뷰 응답 (본 commit)** | **238** (+5) |

원본 로그: [evidence/tests/20260506_pr14_review_response_pytest_raw_KMW_v1.txt](../tests/20260506_pr14_review_response_pytest_raw_KMW_v1.txt)

## 호출 가이드 (PR #14 본문 추가 권장)

이전:
```python
# 호출자가 lookup만 주입하면 빈틈 발생 ❌
with WhitelistEngineLookup(db, ...) as lookup:
    run_validation_job(req, whitelist_lookup=lookup, ...)
```

수정 후:
```python
# wrapper 한 번으로 lookup + compatible policy 자동 ✅
run_validation_job_with_whitelist_engine(
    req, db=db, engine=..., source_loader=...,
)
```

## 후속

- 본 monkey-patch는 임시 해결. 양유상 측 `_resolve_api_policy`가 우리 합집합 정책을 인식하도록 개선되면 wrapper 내부 patch 제거 (호출 인터페이스는 유지).
- README/data/integration 문서에 wrapper 사용 권장 명시 (별도 PR 또는 Step C 시).
