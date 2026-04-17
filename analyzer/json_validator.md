# JSON Validator Guide

## 담당자
박용담

## 목적
공통 JSON 계약을 기준으로 요청과 응답이 직렬화 가능한지 검증한다.

## 입력
- `ValidationJobRequest`
- `ArtifactValidationResult`
- `ValidationJobResponse`
- whitelist 관련 payload

## 출력
- 검증 성공 여부
- 실패한 필드와 실패 이유
- `ERROR` 또는 `BLOCK`으로 연결할 수 있는 reason entry

## 구현 시 주의사항
- 구현 초기에는 schema contract 검증을 우선하고, 실제 보안 판단은 정은미/양유상/김민우 담당 모듈에 맡긴다.
- 날짜는 RFC3339 UTC 문자열을 사용한다.
- `request_id`, `job_id`, `schema_version`은 모든 주요 payload에 유지한다.
- 누락 필드는 빈 문자열로 대체하지 말고 실패로 처리한다.

## 관련 테스트
- `tests/test_json_schema.md`
- `tests/test_validation_flow.md`
