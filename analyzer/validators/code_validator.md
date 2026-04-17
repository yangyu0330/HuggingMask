# Code Validator Guide

## 담당자
양유상

## 목적
Python 코드 파일을 정적 분석하고, 위험 import/call/API와 동적 패턴을 탐지한다.

## 입력
- `PYTHON`으로 분류된 `ArtifactRef`
- whitelist engine 조회 결과
- 코드 파일 내용

## 출력
- `ArtifactValidationResult`
- route kind: `CODE_AST_SCAN`, `CODE_RESTRICTED_RUNTIME`, `CODE_SANDBOX_RUNTIME`
- `CodeGrade A/B-1/B-2/C`
- reason entries

## 코드 검증 경로
- 검증1(`CODE_AST_SCAN`): AST 기반 정적 분석
- 검증2(`CODE_RESTRICTED_RUNTIME`): 제한 런타임 검증
- 검증3(`CODE_SANDBOX_RUNTIME`): 샌드박스 런타임 검증

## 구현 시 주의사항
- 담당자 양유상과 `CodeGrade C`를 혼동하지 않는다.
- `eval`, `exec`, `__import__`, 위험한 파일/네트워크 접근은 우선 차단 대상으로 본다.
- whitelist에 없는 API는 자동 승인하지 않고 `PENDING_REVIEW`로 연결한다.
- 동적 import, obfuscation, getattr 기반 우회는 reason entry에 근거를 남긴다.

## 관련 테스트
- `tests/test_code_validator.md`
- `tests/test_whitelist_engine.md`
- `tests/test_validation_flow.md`
