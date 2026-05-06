# Worklog — PR #9 리뷰 대응 (양유상 코멘트)

- **작성자:** 김민우 (KMW)
- **일시:** 2026-04-21
- **PR:** #9 (`feature/whitelist-engine-impl` → `dev`)
- **응답 대상:** 양유상 리뷰 코멘트 (2026-04-21 01:56 UTC)

## 작업 내용

양유상 리뷰의 두 가지 계약 위반을 인터페이스 정의서 v1.0 기준으로 수정.

### 수정 1 — `/internal/v1/whitelist/check` 응답 배열로 변경

| 항목 | 이전 | 수정 |
|---|---|---|
| 응답 형식 | wrapper `{schema_version, request_id, job_id, whitelist_version, results: [...]}` | 인터페이스 14.2 기준 `WhitelistCheckResponse[]` 배열 |
| `whitelist/models.py` | `WhitelistCheckBatchResponse` 클래스 export | 제거 (NOTE 주석으로 정책 명시) |
| `whitelist/engine.py` | `check_batch()` → `WhitelistCheckBatchResponse` | `check_batch()` → `list[WhitelistCheckResponse]` |
| `whitelist/router.py` | `response_model=WhitelistCheckBatchResponse` | `response_model=list[WhitelistCheckResponse]` |
| `tests/test_router_e2e.py` | `body["results"][0]` | `body[0]` |
| 통합 테스트 | `resp.results[i]` | `resp[i]` |

`request_id` / `job_id` 추적은 응답 body가 아닌 `audit_log`에 남는다 (양유상 리뷰의 권고).

### 수정 2 — `/internal/v1/pending/upsert`가 `PendingApiRecord` 손실 없이 보존

| 필드 | 이전 동작 | 수정 동작 |
|---|---|---|
| `first_seen_at` | 무시 (자동 now()) | record 값 그대로 |
| `last_seen_at` | 무시 | record 값 그대로 |
| `seen_count` | 무시 (자동 1) | record 값 그대로 |
| `model_list` | `[0]`만 저장 | 전체 보존 |
| `sample_callsites` | `[0]`만 저장 | 전체 보존 |
| `verified_org_list` | 부분만 | 전체 보존 |
| `created_from_job_id` | `req.job_id`로 덮어씀 | `record.created_from_job_id` 사용 |
| `review_status` | 암묵적 PENDING 강제 | PENDING만 허용, 그 외 400 (양유상 옵션 2 채택) |

신규 함수: `whitelist/pending_store.py:upsert_pending_record(db, record: PendingApiRecord)` — 외부 input을 그대로 반영. 기존 `upsert_pending()`은 검증 흐름 중 자동 등록용으로 그대로 유지.

### 부가 수정 — SQLite tzinfo 정규화
`PendingApi.first_seen_at` / `last_seen_at`은 `DateTime(timezone=True)`이지만 SQLite가 읽을 때 tzinfo를 잃는다. `to_record()`에서 UTC tzinfo를 다시 부착하도록 `_ensure_utc()` 헬퍼 추가. PostgreSQL 환경에서는 no-op.

## 신규 테스트 (`tests/test_pending_upsert_contract.py` — 14 케이스)

양유상 리뷰의 "테스트 추가 요청" 5개 항목 + 추가 케이스:

| 클래스 | 케이스 수 | 검증 |
|---|---|---|
| `TestRoundTrip` | 1 | record → upsert → DB → to_record() 무결성 |
| `TestMultiElementPreservation` | 4 | model_list / sample_callsites / verified_org_list / risk_keywords 전체 보존 |
| `TestCreatedFromJobId` | 1 | `record.created_from_job_id` 우선 |
| `TestReviewStatusPolicy` | 5 | PENDING은 OK, UNDER_REVIEW/APPROVED/REJECTED/DEFERRED는 ValueError |
| `TestUpdateBehavior` | 1 | 기존 record 재호출 시 record 값으로 덮어씀 |
| `TestRouterRoundTrip` | 2 | router 핸들러를 통한 round-trip + non-PENDING 400 |

## 수정 이유

양유상 리뷰의 원칙 "**`origin/dev` 기준 공통 인터페이스 계약과 어긋난 부분 수정**"에 동의.

- 1번(wrapper 응답)은 내가 FastAPI response_model 명시 편의로 추가한 임의 확장이었음. 인터페이스 정의서 14.2가 분명히 배열로 정의되어 있어 호출 측 역직렬화가 깨질 수 있음.
- 2번(PendingApiRecord 손실)은 router 핸들러가 record 필드를 축약해서 `upsert_pending()`(검증 흐름용)에 넘긴 게 원인. 외부 input 처리에는 별도 함수가 필요함.

## 테스트 결과

- **87 passed / 0 failed** (소요 4.61s) ← 이전 60에서 27개 추가
  - 신규: round-trip 14 + 통합 12 + 회귀 1
- 상세 로그: `evidence/tests/20260421_pytest_raw_KMW_v1.txt`

## 변경 파일 (수정)
- `whitelist/models.py` — `WhitelistCheckBatchResponse` 제거
- `whitelist/engine.py` — `check_batch()` 반환 타입 변경
- `whitelist/router.py` — `/check` 배열, `/pending/upsert` 신규 함수 사용 + 400
- `whitelist/pending_store.py` — `upsert_pending_record()` 신규, `_ensure_utc()` 헬퍼
- `tests/test_whitelist_engine.py` — `resp.results` → `resp`
- `tests/test_router_e2e.py` — `body["results"]` → `body`
- `tests/integration/test_mock_hf_scenarios.py` — 동일

## 변경 파일 (신규)
- `tests/test_pending_upsert_contract.py` — 14 케이스 round-trip 계약 테스트

## 호환성 알림

이 변경은 `/internal/v1/whitelist/check` 응답 형식의 **breaking change**입니다.
호출 측(양유상의 코드 검증자, 박용담의 analyzer)이 이미 wrapper 형태에 맞춰 코드를 작성했다면 그쪽도 수정 필요.
다만 PR이 아직 merge 전이고 호출 측도 미구현이므로, 지금이 바꾸기 가장 좋은 시점.
