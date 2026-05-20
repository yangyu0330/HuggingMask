# Worklog — 양유상 코드 검증자 통합 어댑터

- **작성자:** 김민우 (KMW)
- **일시:** 2026-05-06
- **브랜치:** `feature/whitelist-code-validator-integration` (← `origin/dev`)
- **PR 대상:** `dev`
- **선행 PR:** #9 (whitelist engine 초기 구현, 4-22 머지), #10 (양유상 코드 검증 풀파이프라인, 5-04 머지)

## 작업 내용

양유상 PR #10이 dev에 머지되면서 [analyzer/validators/code_api_policy.py](../../analyzer/validators/code_api_policy.py)에 `WhitelistLookup` Protocol(`whitelist_version` 속성 + `is_allowed_exact(api) -> bool`)이 정의됐다. 이 Protocol을 만족하는 어댑터를 우리 엔진 측에 만들어, 양유상 코드 변경 없이 production 코드 검증자 ↔ 우리 화이트리스트 엔진을 실연동했다.

### 신규 파일

| 파일 | 역할 |
|---|---|
| [whitelist/integration.py](../../whitelist/integration.py) | `WhitelistEngineLookup`(Protocol 만족 어댑터), `build_compatible_policy`(양유상 기본 + 우리 PERMANENTLY_BLOCKED 합집합), `register_pending_from_apis`(배치 등록 헬퍼) |
| [tests/test_whitelist_integration.py](../../tests/test_whitelist_integration.py) | 어댑터 단위 테스트 19 케이스 |
| [tests/integration/test_yangyu_whitelist_e2e.py](../../tests/integration/test_yangyu_whitelist_e2e.py) | 양유상 production 코드(`extract_ast_candidates` + `scan_api_policy`)와 우리 어댑터의 end-to-end 통합 테스트 5 케이스 |

### 호출 흐름

```
[Python source]
   │
   ▼
extract_ast_candidates()   ── 양유상 stage-4 (변경 없음)
   │
   ▼
scan_api_policy(
    ast_scan,
    policy=build_compatible_policy(),       ─┐  우리가 주입
    whitelist_lookup=WhitelistEngineLookup(  ─┤
        db, engine, job_id, model           ─┘
    ),
)
   │  내부 우선순위:
   │    1) unresolved + dynamic/obfuscation → BLOCKED
   │    2) blocked_exact (양유상 기본 ∪ 우리 PERMANENTLY_BLOCKED)
   │    3) risk_exact (양유상 기본 ∪ 우리 PERMANENTLY_BLOCKED)
   │    4) contextual_exact / contextual_prefix
   │    5) lookup.is_allowed_exact(api)  ← 우리 어댑터 호출
   │    6) 그 외 → unregistered + pending_api_refs
   ▼
ApiScanResult (allowed/blocked/unregistered)
   │
   ▼ (context exit)
WhitelistEngineLookup.flush_pending()
   │  누적된 미등록 API → engine.check_batch() → 4-state 판정
   │   + PendingApi.upsert (auto_classification 권고 포함)
   │   + audit log entry
   │   + db.commit()
   ▼
PendingApi 테이블에 PENDING 등록 완료
```

### 책임 경계 (engine.md:21 준수)

- 우리 어댑터는 단지 per-API status만 반환. 코드 등급(A/B-1/B-2/C) 결정은 양유상의 [analyzer/validators/code_validator.py](../../analyzer/validators/code_validator.py) 책임.
- `WhitelistEngineLookup`이 BLOCKED 정보를 잃는 경우(양유상 정책에 없지만 우리 PERMANENTLY_BLOCKED인 API)도 `engine.check_batch`가 BLOCKED로 마킹하고 audit log에 남김 — `ApprovedApi`엔 등록 안 됨.
- hm-05 안전 코드 시나리오에서 우리 lookup이 BLOCKED 신호를 주지 않음을 회귀로 검증 (config trigger 차단은 박용담 config_validator 책임).

## 수정 이유

### 1. PR #9 시점에 통합 미구현

PR #9 머지 직후 [tests/integration/test_mock_hf_scenarios.py](../../tests/integration/test_mock_hf_scenarios.py)가 사용한 [_simulated_code_validator.py](../../tests/integration/_simulated_code_validator.py)는 양유상 production이 없을 때 만든 stub. 그 시점엔 양유상 production이 dev에 없었으므로 stub 검증이 최선이었다.

5-04에 양유상 PR #10이 dev에 들어오면서 production `analyzer/validators/code_*.py`가 14000줄 추가됐고, 그가 정의한 `WhitelistLookup` Protocol이 통합 hook으로 노출됐다. 이를 활용하지 않으면 **양유상의 등급 결정이 우리 PendingApi/ApprovedApi DB와 단절된 상태로 운영**된다.

### 2. 양유상 정책 vs 우리 정책 정합성

양유상 `_DEFAULT_BLOCKED_EXACT = {torch.load, pickle.load, numpy.load, os.system}` 4개. 우리 `PERMANENTLY_BLOCKED_APIS` 23개. 양유상에 없지만 우리만 있는 항목(`pickle.loads`, `numpy.save`, `marshal.loads`, `yaml.unsafe_load`, `builtins.compile`, `os.popen`, `os.exec`, `os.spawn`, `subprocess.call`, `subprocess.run`, `subprocess.Popen`, `importlib.import_module`, `ctypes.cdll`, `ctypes.CDLL` 등)이 양유상 1·2·3번에서 잡히지 않으면 5번 우리 lookup으로 와서 unregistered로 처리될 수 있다.

`build_compatible_policy()`로 양유상 기본 + 우리 PERMANENTLY_BLOCKED를 union해서 양유상 측이 우리 정책을 그대로 따르게 했다. 추가로 `ctypes.*` prefix를 보강.

### 3. PENDING 자동 등록의 부수효과 통합

양유상 `scan_api_policy`는 `pending_api_refs: list[str]`를 결과로만 반환하고 영속화하지 않는다. 우리 어댑터가 context manager 형태로 `__exit__`에서 자동 flush하면 호출 측이 별도로 `register_pending` 호출을 신경 쓸 필요가 없다.

## 테스트 결과

- **233 passed / 0 failed** (소요 3.99s ~ 10.51s)
- 신규 24개 (단위 19 + e2e 5), dev 회귀 209개 그대로 유지
- 상세: [evidence/tests/20260506_pytest_summary_KMW_v1.md](../tests/20260506_pytest_summary_KMW_v1.md)
- 원본 로그: [evidence/tests/20260506_pytest_raw_KMW_v1.txt](../tests/20260506_pytest_raw_KMW_v1.txt)

| 시점 | 케이스 | 비고 |
|---|---|---|
| PR #9 머지 직후 (4-21) | 87 | whitelist 단독 |
| dev (PR #10 추가, 5-04) | 209 | + 양유상 122 |
| **본 PR (5-06)** | **233** | + 통합 어댑터 24 |

## 변경 파일 (요약)

신규:
- `whitelist/integration.py` (177줄)
- `tests/test_whitelist_integration.py` (159줄)
- `tests/integration/test_yangyu_whitelist_e2e.py` (158줄)
- `evidence/tests/20260506_pytest_raw_KMW_v1.txt`
- `evidence/tests/20260506_pytest_summary_KMW_v1.md`
- `evidence/worklog/20260506_yangyu_integration_adapter_KMW_v1.md` (이 파일)

수정 없음 (양유상 production은 그대로).

## 확인 요청 사항 (양유상 / 박용담)

1. **`build_compatible_policy()`의 정책 합집합 방식 OK인가**
   양유상 측이 자체 정책을 점진적으로 변경할 때 우리 union이 자동으로 따라가도록 `default_api_policy()`를 베이스로 사용. 향후 양유상이 새 BLOCKED API를 추가하면 우리 어댑터는 자동 반영. 반대로 우리가 PERMANENTLY_BLOCKED를 추가하면 양유상도 자동 반영.

2. **`is_allowed_exact`의 BLOCKED 정보 손실**
   양유상 정책 없이 우리만 BLOCKED인 API가 5번에 도달하면 양유상은 unregistered로 본다. 이 차이가 양유상의 등급 결정에 영향을 주는지 검토 필요. 1·2·3번 정책 union으로 사실상 5번 도달 전에 잡히지만, 향후 양유상 정책이 줄어들면 영향 가능.

3. **PENDING 자동 등록의 commit 시점**
   현재 context manager `__exit__`에서 `engine.check_batch()` → `db.commit()`. 양유상 orchestrator가 자체 트랜잭션을 가진다면 외부에서 with 블록을 닫는 시점이 commit 시점과 충돌할 수 있는지.

4. **`_placeholder_model()` 사용 시점**
   `WhitelistEngineLookup(db, engine)`로 model 생략 시 placeholder가 audit에 기록된다. 박용담 config_validator가 호출하는 흐름에서는 ModelRef를 못 받을 수도 있는데, 박용담 측에서 ModelRef를 끌어올 수 있는지 확인 부탁.

## Future Work (이번 PR 범위 밖)

- `analyzer/orchestrator.py`의 `run_validation_job`을 우리 어댑터로 자동 wrapping하는 헬퍼 (`run_with_whitelist_engine(...)`)
- mod1 공식 문서 크롤러 이식 — `ApprovedApi(source=AUTO_CRAWL)` 자동 갱신
- mod2 Verified Org 분석 이식 — `PendingApi.verified_org_count` / `in_official_docs` 자동 채움
- 대시보드(`dashboard.html`) 이식
- `bulk_approve.py` / `bulk_conditional.py` 운영 스크립트 이식
- 정은미 가중치 검증자(`feature/eunmi-wip`)는 dev 통합 미완 — 별도 처리 필요
