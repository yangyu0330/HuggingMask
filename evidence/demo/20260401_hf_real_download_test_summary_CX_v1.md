# 실제 Hugging Face 다운로드 검증 요약
- 실행일: 2026-04-01
- 작성자: Codex
- 실행 명령:
  - `python -m analyzer.hf_real_test --repo hf-internal-testing/tiny-random-gpt2 --repo hf-internal-testing/tiny-random-BertModel --repo jinaai/jina-embeddings-v2-base-en --profile strict_default --max-file-bytes 8000000 --format json --output evidence/demo/20260401_hf_real_download_test_raw_CX_v1.json`
- 원본 로그: `20260401_hf_real_download_test_raw_CX_v1.json`

## 결과 요약
| repo_id | 상태 | 단계 | reason_code | 판정 |
|---|---|---|---|---|
| `hf-internal-testing/tiny-random-gpt2` | PASS | `VALIDATE_SAFETENSORS` | `SAFE_TENSORS_HASH_OK` | 통과 |
| `hf-internal-testing/tiny-random-BertModel` | BLOCK | `VALIDATE_PICKLE_PATH_A` | `PICKLE_PARSE_ERROR` | 차단 |
| `jinaai/jina-embeddings-v2-base-en` | BLOCK | `VALIDATE_CONFIG` | `CONFIG_TRIGGER_FIELD_FOUND` | 차단 |

## 해석
- 실제 공개 모델 파일을 내려받아도 safetensors 기반 모델은 통과할 수 있다.
- pickle 계열 아티팩트는 파싱 실패 또는 정책 위반 시 차단된다.
- config에 `auto_map` 같은 트리거 필드가 있으면 `strict_default` 프로파일에서 즉시 차단된다.
