# Test JSON Schema Guide

## 담당자
박용담

## 목적
공통 JSON 계약이 직렬화와 역직렬화를 안정적으로 지원하는지 검증한다.

## 입력
- `ValidationJobRequest`
- `ArtifactValidationResult`
- `ValidationJobResponse`
- whitelist payload 예시

## 출력
- schema validation 성공 여부
- 필수 필드 누락 시 실패 결과

## 구현 시 주의사항
- 필수 필드 누락은 조용히 보정하지 않는다.
- enum 값이 계약과 다르면 실패해야 한다.
- 실명 담당자 표기와 `CodeGrade` 값은 별도 의미로 검증한다.

## 관련 테스트
- 향후 `tests/test_json_schema.py`
