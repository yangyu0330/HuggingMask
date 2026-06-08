# Test Code Validator Guide

## 담당자
양유상

## 목적
Python 코드, config trigger field, tokenizer/config semantic 정보가 코드 검증 경로로 올바르게 처리되는지 검증한다.

## 입력
- `mock_hf/hm-04-bad-py-import`
- `mock_hf/hm-05-bad-config-automap`
- whitelist 응답 fixture

## 출력
- dangerous import/call/API 탐지 결과
- 검증1(`CODE_AST_SCAN`) 결과
- 검증2(`CODE_RESTRICTED_RUNTIME`) 결과
- 검증3(`CODE_SANDBOX_RUNTIME`) 결과
- `CONFIG_SCHEMA_VALIDATION` 후 코드 검증 재라우팅 결과

## 구현 시 주의사항
- 위험 import는 `DANGEROUS_IMPORT` reason code를 포함해야 한다.
- config trigger field가 발견되면 연결된 Python 파일을 코드 검증에 넘긴다.
- 미등록 API는 자동 승인하지 않고 whitelist engine 결과를 따른다.
- 원본 Python 파일은 검증 단계에서 import/실행하지 않는다.
- `tokenizer_config.json`의 `chat_template`은 semantic inventory와 finding으로 보존한다.

## 관련 테스트
- `tests/test_code_validator.py`
- `tests/test_code_semantic.py`
- `tests/test_config_validator.py`
- `tests/test_whitelist_engine.py`
