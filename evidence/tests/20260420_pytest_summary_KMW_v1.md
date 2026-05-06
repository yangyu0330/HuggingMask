# Pytest 결과 요약 — Whitelist Engine 초기 구현

- **작성자:** 김민우 (KMW)
- **일시:** 2026-04-20
- **브랜치:** `feature/whitelist-engine-impl`
- **대상 모듈:** `whitelist/` (engine, rules, pending_store, audit, feedback, router, bootstrap)
- **원본 로그:** `evidence/tests/20260420_pytest_raw_KMW_v1.txt`

## 결과
- **61 passed / 0 failed / 0 skipped** (소요 11.82s)

## 테스트 파일별 분포

| 파일 | 케이스 수 | 검증 영역 |
|---|---|---|
| `tests/test_audit_chain.py` | 8 | 해시 체인 형성·검증 (변조 탐지 포함) |
| `tests/test_feedback.py` | 5 | 모듈 5 오탐 피드백 (정상/자동거부/엣지) |
| `tests/test_health.py` | 1 | 기존 헬스 체크 (회귀 방지) |
| `tests/test_pending_store.py` | 10 | upsert 누적, 모델 dedup, 콜사이트 cap, 권고≠승인 |
| `tests/test_router_e2e.py` | 9 | FastAPI TestClient — 인터페이스 정의서 14·15장 예시 페이로드 |
| `tests/test_whitelist_engine.py` | 28 | 4-state 판정, block 우선, 결정론, namespace 격상 |

## 인터페이스 정의서 준수 검증

| 절 | 항목 | 검증 케이스 |
|---|---|---|
| 14.1 | `WhitelistCheckRequest` 페이로드 형식 | `test_router_e2e::TestSpecExample::test_check_three_apis` |
| 14.2 | `WhitelistCheckResponse` 4-state | `TestAllowed`, `TestBlocked`, `TestPending`, `TestUnknown` |
| 14.2 | `whitelist_version` 필수 포함 | `test_response_envelope_propagates_request_ids` |
| 15.1 | `PendingApiRecord` 15필드 | `TestRecordSerialization::test_to_record_round_trips` |
| 15.2 | `PendingApiUpsertRequest` 외부 호출 | `POST /internal/v1/pending/upsert` 라우터 노출 (회귀 케이스 추후) |
| engine.md:21 | block > allow 우선순위 | `TestBlocked::test_block_overrides_allow` |
| pending_store.md:23 | AUTO_APPROVE ≠ 즉시 승인 | `TestAutoApproveIsRecommendationOnly` |

## 안 한 것 (다음 회차 작업)
- `mock_hf/hm-04-bad-py-import` 픽스처를 활용한 코드 검증자(양유상) 통합 시나리오
- 분석 캐시(모듈 1·2 백그라운드 갱신) 자동 로드
- 대시보드 UI (현재는 API만)

## 실행 환경
- Python 3.12.10 / pytest 9.0.3 / Windows 11
- DB: 인메모리 SQLite (단위), 임시 파일 SQLite (E2E)
