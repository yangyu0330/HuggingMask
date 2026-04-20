# Worklog — Whitelist Engine 초기 구현

- **작성자:** 김민우 (KMW)
- **일시:** 2026-04-20
- **브랜치:** `feature/whitelist-engine-impl` (← `dev` 기준)
- **PR 대상:** `dev`

## 작업 내용

`whitelist/` 패키지를 빈 상태(`.gitkeep` + `.md` 스펙 4개)에서 동작하는 코드로 채움.

### 신규 파일

| 파일 | 역할 |
|---|---|
| `whitelist/__init__.py` | 공개 API: `get_engine`, `WHITELIST_VERSION` |
| `whitelist/models.py` | Pydantic 스키마 — 인터페이스 정의서 14·15장 정확 일치 |
| `whitelist/rules.py` | namespace 규칙, 영구 차단, 위험 키워드, SLA, `WHITELIST_VERSION` |
| `whitelist/seed.py` | 초기 145개 API (torch.nn / functional / transformers / numpy) |
| `whitelist/database.py` | SQLAlchemy 엔진/세션 (`HUGGINGMASK_DB_URL` 환경변수 지원) |
| `whitelist/tables.py` | DB 테이블: ApprovedApi, PendingApi, AuditLog, FeedbackReport |
| `whitelist/audit.py` | 해시 체인 (prev_hash → entry_hash) + 무결성 검증 |
| `whitelist/pending_store.py` | upsert / list / record 변환 |
| `whitelist/engine.py` | 4-state 판정 코어 + 보안 담당자 판정 적용 |
| `whitelist/feedback.py` | 모듈 5 — 오탐 피드백 루프 |
| `whitelist/router.py` | FastAPI 라우터 (`/internal/v1/...`) |
| `whitelist/bootstrap.py` | 시작 훅: 테이블 생성 + 시드 로드 |

### 변경 파일
- `proxy/app/main.py`: `lifespan`에서 `init_whitelist()` 호출 + `whitelist_router` 마운트
- `requirements.txt`: `sqlalchemy>=2.0`, `pydantic>=2.0` 추가

### 신규 테스트
- `tests/conftest.py`: 인메모리 DB fixture, `ModelRef`, request factory
- `tests/test_whitelist_engine.py`: 28 케이스
- `tests/test_pending_store.py`: 10 케이스
- `tests/test_audit_chain.py`: 8 케이스
- `tests/test_feedback.py`: 5 케이스
- `tests/test_router_e2e.py`: 9 케이스 (TestClient + 임시 SQLite)

## 수정 이유

`whitelist/` 폴더는 `.md` 스펙만 있고 실제 구현 없음. 양유상의 코드 검증자가 호출할 엔드포인트(`POST /internal/v1/whitelist/check`)와 데이터 계약이 비어있어서, 통합 검증 흐름이 막힘.

본 작업으로 다음을 만족:
- 인터페이스 정의서 v1.0의 14·15장 계약 준수 (`WhitelistCheckRequest/Response`, `PendingApiRecord`)
- `engine.md:21`의 우선순위 (block > allow)
- `pending_store.md:23`의 게이팅 원칙 (AUTO_APPROVE 권고 ≠ 즉시 승인)
- 양유상의 `CODE_AST_SCAN` 결과로부터 받는 API 목록을 4-state로 매핑하여 등급 결정 근거 제공

## 테스트 결과

- **61 passed / 0 failed** (소요 11.82s)
- 상세: `evidence/tests/20260420_pytest_summary_KMW_v1.md`
- 원본 로그: `evidence/tests/20260420_pytest_raw_KMW_v1.txt`

## 확인 요청 사항

1. **인터페이스 미준수 항목 확인** — `WhitelistCheckResponse` 14.2절 6필드 (api_path, status, matched_rule, source, whitelist_version, review_required, reason) 모두 포함 여부, 박용담 측 `analyzer/json_validator`의 schema 정의와 충돌 없는지
2. **양유상 코드 검증자와의 호출 경로** — 우리 엔진은 `POST /internal/v1/whitelist/check`로 받음. 양유상 측 클라이언트 호출 코드가 같은 경로/페이로드인지
3. **`whitelist_version` 운영 정책** — 현재 `wl-2026.04.20` 하드코딩. 정책 변경 시 갱신 절차 (캐시 무효화와 연계) 합의 필요
4. **DB URL 운영 정책** — 기본 SQLite 파일 (`./whitelist.db`). 통합 컨테이너에서 PostgreSQL로 갈지 결정 필요 → 환경변수 `HUGGINGMASK_DB_URL`로 이미 교체 가능

## Future Work (이번 PR 범위 밖)
- `mock_hf/hm-04` 시나리오로 코드 검증자 ↔ 화이트리스트 통합 테스트
- 모듈 1 (공식 문서 크롤링) 백그라운드 작업화
- 모듈 2 (Verified Org 분석) 캐시 데이터 → `verified_org_count` 자동 채움
- 대시보드 UI (현재는 API만 노출)
