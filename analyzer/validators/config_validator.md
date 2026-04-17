# Config Validator Guide

## 담당자
박용담, 양유상

## 목적
박용담이 `config.json`과 `tokenizer_config.json`을 1차 검증하고, 코드 실행을 유도할 수 있는 trigger field가 참조한 `.py` 파일은 양유상 코드 검증 경로로 재라우팅한다.

## 입력
- `CONFIG_JSON` 또는 `TOKENIZER_CONFIG_JSON`으로 분류된 `ArtifactRef`
- config/tokenizer JSON 내용
- 같은 저장소에 있는 Python 파일 목록

## 출력
- config 검증 결과
- route kind: `CONFIG_SCHEMA_VALIDATION`
- trigger field 목록
- 재라우팅된 Python artifact 목록

## 구현 시 주의사항
- `auto_map`, `custom_pipelines`, `trust_remote_code`는 trigger field로 본다.
- trigger field가 참조하는 `.py` 파일은 검증1(`CODE_AST_SCAN`) 경로로 연결한다.
- 제한 실행이 필요한 경우 검증2(`CODE_RESTRICTED_RUNTIME`) 또는 검증3(`CODE_SANDBOX_RUNTIME`)로 이어질 수 있음을 결과에 남긴다.
- config schema 자체가 잘못된 경우 `BLOCK` 또는 `ERROR` 기준을 명확히 기록한다.
- tokenizer 설정은 코드 실행 트리거를 열 수 있는 필드와 알 수 없는 필드를 별도 reason entry로 남긴다.
- 참조 파일이 없으면 누락된 파일명을 reason entry에 남긴다.

## 관련 테스트
- `tests/test_code_validator.md`
- `tests/test_validation_flow.md`
