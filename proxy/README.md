# Proxy Module Guide

## 담당자
공통

## 목적
프록시는 현재 단계에서 후순위이다. 지금은 health endpoint를 유지하고, 나중에 analyzer orchestrator를 호출하는 얇은 FastAPI 진입점으로 확장한다.

## 입력
- 향후 모델 검증 요청
- 현재는 `/health` 요청

## 출력
- 현재는 health 응답
- 향후 `ValidationJobResponse`

## 구현 시 주의사항
- 검증 로직을 proxy 내부에 직접 넣지 않는다.
- 실제 검증 판단은 `analyzer`와 `whitelist`에서 수행한다.
- 프록시 변경은 기존 `tests/test_health.py`를 깨뜨리지 않아야 한다.

## 관련 테스트
- `tests/test_health.md`
- `tests/test_validation_flow.md`
