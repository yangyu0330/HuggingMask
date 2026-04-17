# Sandbox Module Guide

## 담당자
정은미, 양유상, 공통

## 목적
`sandbox`는 현재 직접 구현 대상이 아니다. 가중치 검증 Path B 또는 코드 runtime 검증이 필요해질 때 제한 실행 환경을 제공한다.

## 입력
- sandbox 실행이 필요한 artifact
- runtime profile
- 네트워크와 파일시스템 제한 정책

## 출력
- 실행 로그
- syscall 또는 runtime anomaly 결과
- validator가 사용할 검증 근거

## 구현 시 주의사항
- sandbox 결과가 있어도 최종 release 판단은 orchestrator에서 한다.
- 네트워크 차단, read-only filesystem, timeout 정책을 기본 전제로 둔다.
- 구현 전까지 정은미/양유상 담당 모듈은 sandbox가 없을 수 있음을 명시적으로 처리해야 한다.

## 관련 테스트
- `tests/test_weight_validator.md`
- `tests/test_code_validator.md`
- `tests/test_validation_flow.md`
