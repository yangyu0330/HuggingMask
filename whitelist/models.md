# Whitelist Models Guide

## 담당자
김민우

## 목적
whitelist와 pending API 처리에 필요한 데이터 구조를 정리한다.

## 입력
- API 경로
- whitelist 규칙 매칭 결과
- pending 저장소 레코드

## 출력
- `WhitelistCheckRequest`
- `WhitelistCheckResponse`
- `PendingApiRecord`
- review decision 반영 결과

## 구현 시 주의사항
- 공통 schema와 중복되는 타입은 `analyzer/schemas.md` 계약을 따른다.
- status 값은 `ALLOWED`, `BLOCKED`, `UNKNOWN`, `PENDING`으로 제한한다.
- pending classification은 추천값이며 최종 승인 상태가 아니다.
- 모델 정의가 변경되면 JSON 검증 테스트도 함께 갱신한다.

## 관련 테스트
- `tests/test_json_schema.md`
- `tests/test_whitelist_engine.md`
