# Proxy App Main Guide

## 담당자
공통

## 목적
`proxy/app/main.py`는 HuggingMask FastAPI 앱의 실행 진입점이다. health, validation API, whitelist 운영 API, dashboard 정적 페이지를 제공한다.

## 입력
- `GET /`, `GET /health`
- `POST /internal/v1/validation/jobs`
- `POST /internal/v1/validation/full`
- `GET /dashboard`
- `whitelist.router`가 제공하는 `/internal/v1/*` 운영 API

## 출력
- `{"status": "ok"}`
- `ValidationJobResponse`
- whitelist/pending/review/feedback/audit 응답
- 운영 dashboard HTML

## 구현 시 주의사항
- 검증 API를 추가할 때도 공통 schema를 먼저 통과시킨다.
- proxy는 파일 분류, opcode 분석, whitelist 판단을 직접 구현하지 않는다.
- dashboard는 `whitelist/static/dashboard.html`을 읽어서 서빙한다.

## 관련 테스트
- `tests/test_health.md`
- `tests/test_validation_jobs.py`
- `tests/test_full_pipeline.py`
- `tests/test_dashboard_and_ops.py`
