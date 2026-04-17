# Pending Store Guide

## 담당자
김민우

## 목적
미등록 API를 pending 목록에 저장하고 재등장 횟수와 관련 모델 정보를 갱신한다.

## 입력
- unknown API 경로
- 모델 repo 정보
- job id와 request id
- 자동 분류 근거

## 출력
- `PendingApiRecord`
- 갱신된 seen count
- review status

## 구현 시 주의사항
- 같은 API가 반복 등장하면 새 레코드를 만들지 않고 `seen_count`와 `last_seen_at`을 갱신한다.
- `review_status` 기본값은 `PENDING`이다.
- 자동 분류가 `AUTO_APPROVE`여도 실제 allow 규칙으로 즉시 승격하지 않는다.
- sample callsite와 risk keyword를 저장해 리뷰 근거를 남긴다.

## 관련 테스트
- `tests/test_whitelist_engine.md`
- `tests/test_validation_flow.md`
