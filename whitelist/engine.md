# Whitelist Engine Guide

## 담당자
김민우

## 목적
API 경로가 현재 정책에서 허용되는지 판단한다.

## 입력
- API 경로 목록
- allow/block 규칙
- whitelist version
- 요청/job 메타데이터

## 출력
- API별 `WhitelistCheckResponse`
- status: `ALLOWED`, `BLOCKED`, `UNKNOWN`, `PENDING`
- matched rule과 reason

## 구현 시 주의사항
- 명시적 block 규칙은 allow 규칙보다 우선한다.
- unknown API는 pending 등록 대상으로 넘긴다.
- 결과에는 항상 `whitelist_version`을 포함한다.
- 네임스페이스 패턴 매칭은 예측 가능하게 동작해야 하며, 과도한 wildcard는 피한다.

## 관련 테스트
- `tests/test_whitelist_engine.md`
- `tests/test_validation_flow.md`
