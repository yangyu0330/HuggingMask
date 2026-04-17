# 테스트 결과 요약
- 실행일: 2026-04-01
- 작성자: Codex
- 작업 위치: `test_HuggingMask`
- 관련 모듈: `proxy`, `analyzer`

## 환경 기준선 확인
- Python 버전 확인: `20260401_environment_raw_CX_v1.txt`
- Docker Compose 설정 확인: `20260401_compose_config_raw_CX_v1.txt`
- `/health` 확인: `20260401_health_raw_CX_v1.txt`

## 자동 테스트(pytest)
- 실행 명령: `python -m pytest -q`
- 결과: `16 passed`
- 원본 로그: `20260401_pytest_raw_CX_v1.txt`

## 검증 항목 상태
| 항목 | 결과 |
|---|---|
| `/health` 응답 확인 | PASS |
| pickle opcode 단위 테스트 | PASS |
| AST 위험 호출 탐지 테스트 | PASS |
| config trigger 탐지 테스트 | PASS |
| 5개 시나리오 expected 일치 테스트 | PASS |
| 5개 시나리오 재실행 일관성 테스트 | PASS |
