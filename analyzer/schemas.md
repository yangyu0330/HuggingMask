# Schemas Guide

## 담당자
박용담

## 목적
검증 파이프라인에서 사용하는 공통 JSON 계약을 정의한다. 정은미, 양유상, 김민우 담당 모듈은 이 계약을 기준으로 결과를 반환한다.

## 입력
- 모델 참조 정보
- artifact 메타데이터
- 정책 버전 정보
- whitelist 조회 결과
- 검증 결과 상세 정보

## 출력
- `ArtifactRef`
- `ValidationJobRequest`
- `ArtifactValidationResult`
- `ValidationJobResponse`
- `ReasonEntry`
- `WhitelistCheckRequest`
- `WhitelistCheckResponse`
- `PendingApiRecord`

## 구현 시 주의사항
- 필수 필드는 누락하지 않는다.
- 상태값은 `PASS`, `BLOCK`, `PENDING_REVIEW`, `ERROR`, `SKIPPED`로 통일한다.
- reason code는 문서화된 문자열을 사용하고, 임의 문자열을 추가할 때는 먼저 계약 문서에 반영한다.
- 담당자 이름과 `CodeGrade A/B-1/B-2/C`는 별도 의미다.

## 관련 테스트
- `tests/test_json_schema.md`
- `tests/test_validation_flow.md`
