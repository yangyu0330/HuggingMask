# Test Health Guide

## 담당자
공통

## 목적
프록시 서버의 최소 상태 확인 endpoint가 계속 동작하는지 검증한다.

## 입력
- `GET /health`

## 출력
- HTTP 200
- JSON body: `{"status": "ok"}`

## 구현 시 주의사항
- 이 테스트는 validation API, dashboard, whitelist router 변경 중에도 깨지면 안 된다.
- 검증 엔진 문서 추가나 모듈 구조 변경이 health endpoint에 영향을 주지 않아야 한다.

## 관련 테스트
- `tests/test_health.py`
