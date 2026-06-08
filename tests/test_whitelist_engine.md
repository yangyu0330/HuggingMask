# Test Whitelist Engine Guide

## 담당자
김민우

## 목적
API allow/block/unknown/pending 판정과 pending 저장 갱신이 올바르게 동작하는지 검증한다.

## 입력
- 허용 API 예시
- 차단 API 예시
- 미등록 API 예시
- 반복 등장 API 예시

## 출력
- `WhitelistCheckResponse`
- `PendingApiRecord`
- whitelist version
- review decision
- audit/feedback 운영 결과

## 구현 시 주의사항
- block 규칙은 allow 규칙보다 우선한다.
- unknown API는 pending record로 남아야 한다.
- 같은 API가 반복 등장하면 `seen_count`가 증가해야 한다.
- `AUTO_APPROVE` 분류는 실제 승인 상태와 분리해서 검증한다.
- 운영 API는 `/internal/v1/*` prefix로 노출되며 dashboard와 함께 검증한다.

## 관련 테스트
- `tests/test_whitelist_engine.py`
- `tests/test_pending_store.py`
- `tests/test_router_e2e.py`
- `tests/test_dashboard_and_ops.py`
- `tests/test_audit_chain.py`
