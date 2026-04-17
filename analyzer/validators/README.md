# Validators Guide

## 담당자
정은미, 양유상

## 목적
`validators`는 파일 종류별 검증 경로를 담당한다. 정은미는 가중치 파일을, 양유상은 Python 코드 검증 경로를 맡는다. `config.json`과 `tokenizer_config.json`의 1차 검증은 박용담이 맡고, config가 참조한 `.py` 파일은 양유상 코드 검증 경로로 넘긴다.

## 입력
- `ArtifactRef`
- 정책 버전과 runtime profile
- whitelist 조회 함수 또는 결과

## 출력
- 파일별 `ArtifactValidationResult`
- route kind
- reason entries

## 구현 시 주의사항
- 각 validator는 최종 job 상태를 직접 결정하지 않는다. 최종 조립은 `orchestrator`가 담당한다.
- 경로 이름은 `SAFETENSORS_FAST_PATH`, `PICKLE_PATH_A`, `PICKLE_PATH_B`, `CODE_AST_SCAN`, `CODE_RESTRICTED_RUNTIME`, `CODE_SANDBOX_RUNTIME`, `CONFIG_SCHEMA_VALIDATION`을 사용한다.
- 양유상 코드 검증은 팀 표현과 표준 route를 함께 쓴다: 검증1(`CODE_AST_SCAN`), 검증2(`CODE_RESTRICTED_RUNTIME`), 검증3(`CODE_SANDBOX_RUNTIME`).

## 관련 테스트
- `tests/test_weight_validator.md`
- `tests/test_code_validator.md`
- `tests/test_validation_flow.md`
