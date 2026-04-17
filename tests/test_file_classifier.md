# Test File Classifier Guide

## 담당자
박용담

## 목적
파일 확장자와 경로 기준으로 artifact가 올바르게 분류되는지 검증한다.

## 입력
- `mock_hf` fixture 파일 목록
- safetensors, pickle, Python, config, 기타 파일 예시

## 출력
- 기대한 `file_kind`
- 분류 실패 reason entry

## 구현 시 주의사항
- `config.json`은 단순 `.json`보다 우선해 `CONFIG_JSON`으로 분류한다.
- `tokenizer_config.json`은 `TOKENIZER_CONFIG_JSON`으로 분류한다.
- 알 수 없는 파일은 실패가 아니라 `OTHER`로 안전하게 분류한다.
- fixture별 `expected_result.json`과 비교할 수 있게 결과 구조를 맞춘다.

## 관련 테스트
- 향후 `tests/test_file_classifier.py`
