# Test Validation Flow Guide

## 담당자
공통: 박용담, 정은미, 양유상, 김민우

## 목적
파일 분류, 가중치 검증, 코드 검증, whitelist 판정, 최종 응답 조립까지 전체 흐름을 검증한다.

## 입력
- 전체 `mock_hf` fixture 세트
- 공통 정책 정보
- whitelist 규칙

## 출력
- fixture별 최종 `ValidationJobResponse`
- `APPROVE`, `DENY`, `REVIEW_REQUIRED` 판단
- artifact별 reason code

## 구현 시 주의사항
- 하나라도 `BLOCK`이면 전체 결과는 `BLOCK`이어야 한다.
- `BLOCK` 없이 pending이 있으면 전체 결과는 `PENDING_REVIEW`이어야 한다.
- 모든 artifact가 `PASS`일 때만 전체 pass가 가능하다.
- fixture의 `expected_result.json`과 비교 가능한 형태로 출력한다.

## 관련 테스트
- 향후 `tests/test_validation_flow.py`
