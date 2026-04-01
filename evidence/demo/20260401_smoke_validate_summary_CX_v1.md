# 데모 시나리오 검증 요약
- 실행일: 2026-04-01
- 작성자: Codex
- 실행 명령: `python -m analyzer.smoke_validate --all --assert-expected --format json --repo-root .`
- 원본 로그: `20260401_smoke_validate_raw_CX_v1.json`

## 시나리오 결과
| 시나리오 | 기대 상태 | 실제 상태 | reason_code | 판정 |
|---|---|---|---|---|
| `hm-01-safe-st` | PASS | PASS | `SAFE_TENSORS_HASH_OK` | PASS |
| `hm-02-safe-pkl` | PASS | PASS | `PICKLE_OPCODE_ALLOWED_ONLY` | PASS |
| `hm-03-bad-pkl-reduce` | BLOCK | BLOCK | `PICKLE_OPCODE_BLOCKED` | PASS |
| `hm-04-bad-py-import` | BLOCK | BLOCK | `DANGEROUS_CALL` | PASS |
| `hm-05-bad-config-automap` | BLOCK | BLOCK | `CONFIG_TRIGGER_FIELD_FOUND` | PASS |

## 결론
- 5개 시나리오 모두 `expected_result.json`과 일치한다.
- 정상 입력은 허용되고 악성 입력은 차단되는 최소 사전 검증 기준을 충족했다.
