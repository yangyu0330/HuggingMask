# Pytest Summary — 2026-05-06 (KMW)

- **브랜치:** `feature/whitelist-code-validator-integration`
- **베이스:** `origin/dev` (PR #9, #10, #11, #12 통합 후)
- **Python:** 3.12.10
- **소요:** 3.99s (cold start), 10.51s (full integration suite)
- **pytest:** 9.0.3, sqlalchemy 2.0.49, pydantic 2.13.3
- **원본 로그:** `evidence/tests/20260506_pytest_raw_KMW_v1.txt`

## 결과

```
233 passed in 3.99s
```

## 구성

| 영역 | 파일 | 케이스 수 |
|---|---|---|
| (기존) whitelist 단위 — engine | `tests/test_whitelist_engine.py` | 28 |
| (기존) pending store | `tests/test_pending_store.py` | 10 |
| (기존) audit chain | `tests/test_audit_chain.py` | 8 |
| (기존) feedback | `tests/test_feedback.py` | 5 |
| (기존) router e2e | `tests/test_router_e2e.py` | 9 |
| (기존) pending upsert contract | `tests/test_pending_upsert_contract.py` | 14 |
| (기존) mock_hf 시뮬 통합 | `tests/integration/test_mock_hf_scenarios.py` | 12 |
| (기존) health | `tests/test_health.py` | 1 |
| **(기존 양유상)** code_ast / code_api / code_context / code_roles / code_validator / code_validation_flow | `tests/test_code_*.py` | 약 80 |
| **(기존 양유상)** validation_flow / config_validator / json_schema / file_classifier | 동일 | 약 42 |
| **(신규)** 통합 어댑터 단위 | `tests/test_whitelist_integration.py` | **19** |
| **(신규)** 양유상 ↔ 우리 엔진 e2e | `tests/integration/test_yangyu_whitelist_e2e.py` | **5** |
| **합계** | | **233** |

## PR #9 (4-21) 시점 대비 증가

| 시점 | 케이스 |
|---|---|
| PR #9 머지 직후 (4-21) | 87 |
| dev에 양유상 PR #10 추가 후 (5-04) | 209 |
| **이번 PR (5-06)** | **233** (+24) |

## 주요 검증 포인트 (이번 PR 신규)

1. `WhitelistEngineLookup`이 양유상 `WhitelistLookup` Protocol(`runtime_checkable`)을 만족
2. `is_allowed_exact` 분기:
   - ApprovedApi(is_blocked=False) → True
   - ApprovedApi(is_blocked=True) → False
   - 미등록 → False + 누적
3. `flush_pending`/context manager 종료 시 누적 미등록을 4-state 판정 + PendingApi 자동 등록 + commit
4. 양유상의 자체 정책에 없는 우리 PERMANENTLY_BLOCKED API(예: `pickle.loads`)가 lookup에 도달했을 때 우리 엔진이 BLOCKED로 마킹
5. `build_compatible_policy`가 양유상 기본 정책 + 우리 PERMANENTLY_BLOCKED + `ctypes.*` prefix를 합집합으로 제공
6. `extract_ast_candidates(modeling_evil.py)` → `scan_api_policy(policy=우리정책, whitelist_lookup=우리어댑터)` 호출 시 위험 호출이 BLOCKED로 분류됨 (hm-04)
7. 안전 코드(hm-05 modeling_safe.py)는 우리 lookup 단계에서 BLOCKED 신호 안 줌 — 책임 경계 준수

## 알려진 차이

- `tests/integration/test_mock_hf_scenarios.py`는 `_simulated_code_validator.py`의 stub AST 추출기를 사용 (이전 PR #9 시점에 양유상 production이 없을 때 만든 시뮬레이션). production 통합은 신규 `test_yangyu_whitelist_e2e.py`가 담당. 두 파일은 의도적으로 공존 — 시뮬은 책임 경계 회귀, production은 실연동 회귀.
