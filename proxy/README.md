# Proxy Module Guide

## 담당자
공통

## 목적
프록시는 HuggingMask의 FastAPI 실행 진입점이다. health endpoint를 유지하면서 analyzer 검증 API, whitelist 운영 API, dashboard를 제공한다.

## 입력
- `GET /health`
- `POST /internal/v1/validation/jobs`
- `POST /internal/v1/validation/full`
- `/internal/v1/whitelist/*`, `/pending/*`, `/review`, `/feedback`, `/audit/*`

## 출력
- health 응답
- `ValidationJobResponse`
- whitelist/pending/review/audit 운영 응답
- `/dashboard` 정적 HTML 운영 화면

## 구현 시 주의사항
- 검증 로직을 proxy 내부에 직접 넣지 않는다.
- 실제 검증 판단은 `analyzer`와 `whitelist`에서 수행한다.
- 프록시 변경은 기존 `tests/test_health.py`를 깨뜨리지 않아야 한다.
- API를 추가할 때는 `analyzer.schemas` 또는 `whitelist.models`의 공통 계약을 먼저 사용한다.

## 관련 테스트
- `tests/test_health.md`
- `tests/test_validation_flow.md`
- `tests/test_router_e2e.py`
- `tests/test_dashboard_and_ops.py`
