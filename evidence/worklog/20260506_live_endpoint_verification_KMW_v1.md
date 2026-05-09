# Worklog — Live Endpoint Verification (Step D)

- **작성자:** 김민우 (KMW)
- **일시:** 2026-05-06
- **브랜치:** `feature/whitelist-code-validator-integration` (PR #14에 추가 commit)
- **목적:** PR #14 어댑터가 단위/E2E 테스트(233 passed) 외에 **실제 HTTP 서버에서도** 정상 동작하는지 라이브 검증

## 작업 내용

uvicorn(`proxy.app.main:app`)을 127.0.0.1:8000에서 띄우고 15개 시나리오를 curl로 호출, 응답 raw + summary를 evidence/demo에 저장.

### 검증 시나리오 (15개)

1. `GET /` `GET /health` `GET /docs` — 기본 헬스/문서
2. `GET /internal/v1/stats` — 시드 145 자동 로드 확인
3. `POST /internal/v1/whitelist/check` — 4-state(ALLOWED·BLOCKED·PENDING·UNKNOWN) + 위험 키워드 격상(load → MANUAL)
4. `GET /internal/v1/pending` — 자동 등록된 3건 (matched_namespace_rule, documentation_url, risk_keywords 채워짐)
5. `POST /internal/v1/review` — 보안 담당자 승인 적용
6. 같은 API 재 `POST /whitelist/check` — `ALLOWED, source=MANUAL_REVIEW` 즉시 반영
7. `POST /internal/v1/feedback`(`torch.load`) — `auto_rejected=true, sla=0h`
8. `POST /internal/v1/feedback`(transformers.*) — `CONDITIONAL, sla=24h, PENDING`
9. `GET /internal/v1/feedback` — 2건 목록
10. `GET /internal/v1/audit?limit=20` — 8 entries 체인 정상
11. `GET /internal/v1/audit/verify` — `valid=true`, 무결성 확인
12. `GET /internal/v1/stats` — 최종 `approved=146, pending=3, feedback=2`

### 신규 evidence 파일

- [evidence/demo/20260506_live_endpoints_raw_KMW_v1.txt](../demo/20260506_live_endpoints_raw_KMW_v1.txt) — 모든 curl 응답 raw JSON (8134 bytes, UTF-8)
- [evidence/demo/20260506_live_endpoints_summary_KMW_v1.md](../demo/20260506_live_endpoints_summary_KMW_v1.md) — 시나리오별 결과 표 + audit chain 흐름

## 수정 이유

PR #14의 233 passed pytest는 인메모리 SQLite + TestClient 기반. 실제 운영 환경에 가까운 (file-based SQLite, uvicorn ASGI server, HTTP wire) 검증이 누락된 상태였다. 발표/캡스톤 데모를 앞두고 다음 두 가지를 실증해야 함:
1. **양유상 통합 어댑터**가 실제 HTTP 호출에서도 4-state 분류와 PENDING 자동 등록을 정확히 수행
2. **Audit hash chain**이 운영 환경에서도 무결성 유지 (sqlite tzinfo 정규화 포함)

## 테스트 결과

- 15개 시나리오 모두 의도한 결과
- 한국어 reason/message 정상 (UTF-8)
- audit chain 8 entries `valid=true`, `violations=0`
- `approved_active`가 시드(145) → review approve 1건 후 (146)로 정확히 증가

## Docker 보강 필요

`docker compose up --build`는 Docker Desktop 미실행으로 이번엔 venv uvicorn으로 동등 검증. 같은 코드 같은 포트라 결과 동일 예상. Docker Desktop 기동 후 별도 검증해서 evidence/demo에 추가 예정.

## 알려진 임시 로직 (mod1·mod2 이식 후 교체)

- `feedback.py:71` `in_official_docs = matched is not None` — namespace 매칭됐다고 공식 문서 등록 표시. 진짜 mod1 크롤 결과로 교체 필요.
- `verified_org_count=0` 하드코딩 — mod2 Verified Org 분석 캐시 연동으로 채워질 예정.

## 변경 파일 (이번 commit)

- `evidence/demo/20260506_live_endpoints_raw_KMW_v1.txt` (신규)
- `evidence/demo/20260506_live_endpoints_summary_KMW_v1.md` (신규)
- `evidence/worklog/20260506_live_endpoint_verification_KMW_v1.md` (이 파일, 신규)

코드 변경 없음 — 검증 + 증빙만.

## 다음 단계

- Step A: mod1 공식 문서 크롤러 이식 (`whitelist/mod1_*.py` + `data/crawl_cache/`)
- Step B: mod2 Verified Org 분석 이식 (`whitelist/mod2_*.py` + `data/org_analysis_cache/`)
- Step C: dashboard.html + bulk 스크립트 이식
