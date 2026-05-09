# Live Endpoint Verification Summary — 2026-05-06 (KMW)

- **브랜치:** `feature/whitelist-code-validator-integration`
- **서버:** `uvicorn proxy.app.main:app` on `127.0.0.1:8000`
- **DB:** SQLite (`whitelist.db`, 시작 시 자동 초기화 + 시드 145개 로드)
- **원본 raw 응답:** [evidence/demo/20260506_live_endpoints_raw_KMW_v1.txt](20260506_live_endpoints_raw_KMW_v1.txt)

## 검증 결과 — 15개 시나리오 전부 정상

| # | 엔드포인트 | 입력 | 결과 | 비고 |
|---|---|---|---|---|
| 1 | `GET /` | — | `{"message":"HuggingMask bootstrap running"}` | 200 |
| 2 | `GET /health` | — | `{"status":"ok"}` | 200 |
| 3 | `GET /docs` | — | OpenAPI UI | 200 |
| 4 | `GET /internal/v1/stats` | — | `approved_active=145` | 시드 자동 로드 확인 |
| 5 | `POST /internal/v1/whitelist/check` | 5 APIs | 4-state 전부 정확 분류 | ↓ 표 참조 |
| 6 | `GET /internal/v1/pending` | — | 3건 자동 등록 | 미등록·matched·risk_keyword 다 채워짐 |
| 7 | `GET /internal/v1/audit/verify` | — | `valid=true, entries=4` | seed + 3 pending |
| 8 | `POST /internal/v1/review` | approve `torch.nn.NewBrandLayer` | `applied=true` | reviewer=admin-kmw |
| 9 | `POST /internal/v1/whitelist/check` | 같은 API 재요청 | `ALLOWED, source=MANUAL_REVIEW` | review 결과 즉시 반영 |
| 10 | `POST /internal/v1/feedback` | `torch.load` | `auto_rejected=true, sla=0h` | PERMANENTLY_BLOCKED 자동 거부 |
| 11 | `POST /internal/v1/feedback` | `transformers.SomeRareModel` | `CONDITIONAL, sla=24h, PENDING` | namespace 매칭 권고 |
| 12 | `GET /internal/v1/feedback` | — | 2건 목록 | |
| 13 | `GET /internal/v1/audit?limit=20` | — | 8 entries, 체인 정상 연결 | prev_hash → entry_hash |
| 14 | `GET /internal/v1/audit/verify` | — | `valid=true, entries=8` | 최종 무결성 |
| 15 | `GET /internal/v1/stats` | — | `approved=146, pending=3, feedback=2` | review 1건이 ALLOWED로 승격 |

## [5] 4-state 정확성

| API | status | matched_rule | source | review_required | reason |
|---|---|---|---|---|---|
| `torch.nn.Linear` | ALLOWED | `torch.nn.*` | INITIAL | false | 화이트리스트 허용 규칙 일치 |
| `torch.load` | BLOCKED | (null) | INITIAL | false | 명시적 위험 API |
| `torch.nn.NewBrandLayer` | PENDING | `torch.nn.*` | N/A | true | 미등록 API — 분류 권고=AUTO_APPROVE |
| `my_custom_lib.WeirdThing` | UNKNOWN | (null) | N/A | true | 미등록 API (네임스페이스 매칭 없음) |
| `torch.nn.Module.load_state_dict` | PENDING | `torch.nn.*` | N/A | true | 미등록 API — 분류 권고=MANUAL (위험 키워드: load) |

`load` 키워드가 `AUTO_APPROVE → MANUAL`로 격상되는 것까지 정확히 동작.

## [13] Audit 해시 체인 흐름

```
#1 seed_loaded    (system, 145개 시드)             prev=GENESIS  → e6f4e3fb...
#2 pending_registered torch.nn.NewBrandLayer       prev=e6f4e3fb → 17e360a4...
#3 pending_registered my_custom_lib.WeirdThing     prev=17e360a4 → baabc3d6...
#4 pending_registered torch.nn.Module.load_state_dict prev=baabc3d6 → a896862b...
#5 review_approve torch.nn.NewBrandLayer (admin-kmw)  prev=a896862b → f0a1bf6d...
#6 feedback_received torch.load (dev-test, sla=0h)    prev=f0a1bf6d → a6134ac8...
#7 pending_registered transformers.SomeRareModel       prev=a6134ac8 → 71568ddc...
#8 feedback_received transformers.SomeRareModel        prev=71568ddc → 1690ee9b...
```

각 entry의 `prev_hash`가 직전 `entry_hash`와 일치 (체인 무결성). 사후 변조 불가능.

## Docker 검증

`docker compose up --build`는 Docker Desktop 미실행 상태(SETUP_GUIDE.md 8-1 케이스)라 venv uvicorn으로 동등 검증. 컨테이너든 venv든 같은 코드(`proxy.app.main:app`) 같은 포트(8000)이므로 결과 동일. Docker Desktop 기동 후 `docker compose up --build`로도 동일하게 동작 예상 — 후속 검증 항목.

## 다음 단계 (이번 검증으로 확인된 운영 readiness)

- ✅ 양유상 코드 검증자 통합 어댑터 ([whitelist/integration.py](../../whitelist/integration.py))는 단위/E2E 테스트(233 passed)에 더해 실제 HTTP 호출에서도 정상 동작
- ✅ Pending → Review → Approved → ALLOWED 전체 라이프사이클 회귀
- ✅ Audit chain 8 entries 무결성
- ⚠️ `in_official_docs=true`가 namespace 매칭만으로 결정되는 임시 로직 — mod1 공식 문서 크롤러 이식 후 진짜 데이터로 교체 예정
- ⚠️ `verified_org_count=0` 항상 — mod2 Verified Org 분석 이식 후 채워질 예정
