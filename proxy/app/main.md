# Proxy App Main Guide

## 담당자
공통

## 목적
`proxy/app/main.py`는 현재 FastAPI bootstrap과 `/health` endpoint를 제공한다. 향후 검증 API가 추가되면 analyzer orchestrator를 호출하는 진입점이 된다.

## 입력
- 현재: `GET /health`
- 향후: 모델 검증 요청 payload

## 출력
- 현재: `{"status": "ok"}`
- 향후: `ValidationJobResponse`

## 구현 시 주의사항
- 현재 서버 코드는 문서 정리 작업에서 변경하지 않는다.
- 검증 API를 추가할 때도 공통 schema를 먼저 통과시킨다.
- proxy는 파일 분류, opcode 분석, whitelist 판단을 직접 구현하지 않는다.

## 관련 테스트
- `tests/test_health.md`
