# 피피티용 테스트 결과 정리

## 1. 테스트 목적
- HuggingMask의 코드 검증 기능이 실제로 동작하는지 확인했다.
- 정상 입력은 통과하고, 위험 신호가 있는 입력은 차단되는지 검증했다.
- 내부 mock 시나리오와 실제 Hugging Face 공개 모델을 모두 대상으로 테스트했다.

## 2. 테스트 환경
- 실행 위치: `test_HuggingMask`
- Python: `3.13.7`
- 테스트 명령
  - `python -m pytest -q`
  - `python -m analyzer.smoke_validate --all --assert-expected --format text --repo-root .`
  - `python -m analyzer.hf_real_test --repo hf-internal-testing/tiny-random-gpt2 --repo hf-internal-testing/tiny-random-BertModel --repo jinaai/jina-embeddings-v2-base-en --profile strict_default --max-file-bytes 8000000 --format text`

## 3. 전체 결과 요약
- 자동 테스트: `16 passed`
- mock 시나리오 5건: 모두 기대 결과와 일치
- 실제 Hugging Face 공개 모델 3건: 1건 통과, 2건 차단

## 4. mock 시나리오 결과
| 시나리오 | 기대 결과 | 실제 결과 | 주요 사유 |
|---|---|---|---|
| 정상 safetensors | PASS | PASS | `SAFE_TENSORS_HASH_OK` |
| 정상 pickle | PASS | PASS | `PICKLE_OPCODE_ALLOWED_ONLY` |
| 악성 pickle | BLOCK | BLOCK | `PICKLE_OPCODE_BLOCKED` |
| 악성 Python 코드 | BLOCK | BLOCK | `DANGEROUS_CALL` |
| 악성 config | BLOCK | BLOCK | `CONFIG_TRIGGER_FIELD_FOUND` |

## 5. 실제 Hugging Face 공개 모델 결과
| 모델 | 실제 결과 | 검증 단계 | 주요 사유 | 해석 |
|---|---|---|---|---|
| `hf-internal-testing/tiny-random-gpt2` | PASS | `VALIDATE_SAFETENSORS` | `SAFE_TENSORS_HASH_OK` | safetensors 기반 안전 경로 통과 |
| `hf-internal-testing/tiny-random-BertModel` | BLOCK | `VALIDATE_PICKLE_PATH_A` | `PICKLE_PARSE_ERROR` | pickle 계열 아티팩트 차단 |
| `jinaai/jina-embeddings-v2-base-en` | BLOCK | `VALIDATE_CONFIG` | `CONFIG_TRIGGER_FIELD_FOUND` | `auto_map` 탐지로 config 단계 차단 |

## 6. 발표용 핵심 해석
- HuggingMask는 파일 유형별로 다른 기준으로 검증한다.
- safetensors 기반 모델은 정상 통과했다.
- pickle 계열 모델은 안전하지 않거나 파싱 불가하면 차단됐다.
- config에 코드 실행 트리거가 있으면 실제 공개 모델도 차단됐다.
- 즉, 설계 문서 수준이 아니라 실제 입력에 대해 통과/차단 동작이 재현됐다.

## 7. 발표 슬라이드에 넣을 문장
- "mock 시나리오 5건 모두 기대 결과와 정확히 일치했다."
- "실제 Hugging Face 공개 모델을 내려받아 검증한 결과, safetensors 모델은 통과했고 pickle/config 위험 신호가 있는 모델은 차단되었다."
- "정상 모델은 허용하고 위험 모델은 사전에 막는 최소 코드 검증 기능이 동작함을 확인했다."

## 8. 주의사항
- 현재 구현은 사전 검증용 최소 엔진이므로, 실제 모든 Hugging Face 모델 형식을 완전하게 해석하는 수준은 아니다.
- 실제 공개 모델 `hf-internal-testing/tiny-random-BertModel`은 `PICKLE_PARSE_ERROR`로 차단되었으며, 이는 보수적 차단 정책에 따른 결과다.
- 따라서 발표에서는 "완전한 상용 검증기"가 아니라 "위험 신호가 있는 입력을 보수적으로 차단하는 초기 검증 엔진"이라고 설명하는 것이 정확하다.

## 9. 증빙 파일
- mock 시나리오 raw: `evidence/demo/20260401_smoke_validate_raw_CX_v1.json`
- mock 시나리오 요약: `evidence/demo/20260401_smoke_validate_summary_CX_v1.md`
- 실제 HF 테스트 raw: `evidence/demo/20260401_hf_real_download_test_raw_CX_v1.json`
- 실제 HF 테스트 요약: `evidence/demo/20260401_hf_real_download_test_summary_CX_v1.md`
- pytest raw: `evidence/tests/20260401_pytest_raw_CX_v1.txt`
- pytest 요약: `evidence/tests/20260401_pytest_summary_CX_v1.md`
