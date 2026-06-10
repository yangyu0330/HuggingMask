# 단계 7 - Proxy Smoke Optional

## 목적

초기 목적은 analyzer orchestrator가 안정화된 뒤 FastAPI proxy에서 내부 검증 endpoint를 smoke 수준으로 연결하는 것이었다. 현재는 endpoint가 구현되어 있으므로, 이 문서는 proxy가 검증 정책을 소유하지 않는다는 경계와 회귀 테스트 기준을 기록한다.

## 구현 반영 상태 (2026-05-22)

- 상태: 완료. `/internal/v1/validation/jobs`와 `/internal/v1/validation/full`이 proxy에 연결되어 있다.
- 경계: 검증 정책은 analyzer/whitelist/sandbox 각 모듈에 남고, proxy는 schema validate와 함수 호출용 얇은 진입점으로 둔다.

## 담당 범위

코드검증 구현자가 직접 소유하지 않는 proxy 영역과의 얇은 연결만 다룬다.

- `/internal/v1/validation/jobs` endpoint 연결
- `/internal/v1/validation/full` 통합 검증 endpoint 연결
- request JSON을 `ValidationJobRequest`로 변환
- analyzer orchestrator 호출
- `ValidationJobResponse` JSON 반환
- 기존 `/health` 유지
- 오류 응답 skeleton 반환

## 비범위

- proxy 내부에 검증 정책 구현
- 코드검증 로직 복사
- 인증/인가
- 외부 Hub 다운로드
- 파일 캐시/registry 반영
- whitelist approval/review endpoint의 세부 정책 구현
- 운영용 timeout/retry 전체 정책
- ML-BOM/audit/report 저장

## 입력

- HTTP request JSON
- `ValidationJobRequest` schema
- analyzer orchestrator callable
- 테스트용 artifact local path 또는 fixture

## 출력

- HTTP response JSON `ValidationJobResponse`
- 오류 시 `ErrorResponse` skeleton

## 생성/수정 파일

문서 분리 작업에서 생성하는 파일:

- `docs/code_validation_plans/07_proxy_smoke_optional.md`

구현 단계에서 생성/수정할 파일:

- `proxy/app/main.py`
- `tests/test_health.py`
- `tests/test_validation_jobs.py`
- `tests/test_full_pipeline.py`

## 구현 규칙

- proxy는 검증 정책을 소유하지 않는다.
- proxy는 schema validate 후 analyzer orchestrator를 호출한다.
- code validator, config validator, whitelist adapter를 proxy 내부에 직접 구현하지 않는다.
- proxy 내부에 검증 로직, whitelist 판단, pending store 갱신 로직을 넣지 않는다.
- request/response enum 문자열은 인터페이스 정의서를 따른다.
- proxy smoke는 analyzer 단위 테스트를 대체하지 않는다.
- 내부 endpoint 변경은 단계 1~6 및 통합 파이프라인 테스트가 통과하는 상태에서만 진행한다.

## 테스트

추가할 pytest:

- `tests/test_health.py`
- `tests/test_validation_jobs.py`
- `tests/test_full_pipeline.py`

핵심 케이스:

- `/health` 기존 응답 유지
- `/internal/v1/validation/jobs`가 valid weight request에 대해 가중치 검증 결과 반환
- `/internal/v1/validation/full`이 weight + code/config + whitelist + restricted runtime 결과를 병합
- invalid schema request에 대해 오류 skeleton 반환
- proxy endpoint response의 `overall_status`와 `artifact_results`가 orchestrator 결과와 일치
- proxy에 검증 세부 정책 mock이 들어가지 않았는지 구조 테스트 또는 import 경계 확인

## 완료 기준

- endpoint smoke/integration test가 통과한다.
- proxy는 analyzer orchestrator 호출 외의 검증 판단을 하지 않는다.
- 기존 health test를 깨지 않는다.

## 다음 단계 연결

단계 8의 pending/review 연결도 구현되어 있다. 이후에는 proxy endpoint와 pending/review 운영 경로의 회귀 테스트를 함께 유지한다.
