# Test Weight Validator Guide

## 담당자
정은미

## 목적
safetensors와 pickle 계열 가중치 검증 경로가 의도대로 pass/block을 반환하는지 검증한다.

## 입력
- `mock_hf/hm-01-safe-st`
- `mock_hf/hm-02-safe-pkl`
- `mock_hf/hm-03-bad-pkl-reduce`

## 출력
- safetensors pass 결과
- safe pickle pass 또는 제한 결과
- bad pickle block 결과

## 구현 시 주의사항
- 위험 opcode가 발견된 pickle은 `PICKLE_OPCODE_BLOCKED` reason code를 포함해야 한다.
- safetensors fast path는 `SAFE_TENSORS_HASH_OK` 같은 근거를 남긴다.
- Path A/B 결과가 다를 경우 release 판단이 안전하게 막혀야 한다.

## 관련 테스트
- 향후 `tests/test_weight_validator.py`
