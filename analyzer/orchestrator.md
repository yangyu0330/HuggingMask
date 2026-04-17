# Orchestrator Guide

## 담당자
박용담

## 목적
정은미, 양유상, 김민우 담당 모듈의 결과를 조립해 최종 `ValidationJobResponse`를 만든다.

## 입력
- `ArtifactRef` 목록
- 정은미의 가중치 검증 결과
- 양유상의 코드 검증 결과
- 김민우의 whitelist 및 pending 결과

## 출력
- `ValidationJobResponse`
- 파일별 status와 grade
- 승인, 차단, pending artifact 목록
- 전체 reason entries

## 구현 시 주의사항
- 하나라도 `BLOCK`이면 전체 상태는 `BLOCK`이다.
- `BLOCK`이 없고 하나라도 `PENDING_REVIEW`이면 전체 상태는 `PENDING_REVIEW`이다.
- 모든 파일이 `PASS`이면 전체 상태는 `PASS`이다.
- release 가능한 결과는 자동 통과된 artifact만 포함한다.

## 관련 테스트
- `tests/test_validation_flow.md`
- `tests/test_weight_validator.md`
- `tests/test_code_validator.md`
- `tests/test_whitelist_engine.md`
