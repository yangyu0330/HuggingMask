# HuggingMask Mock HF Fixture Pack

5개 데모 시나리오를 실제 fixture repo 형태로 관리하기 위한 디렉터리입니다.

## 1. 목적
- 발표용 5개 시나리오를 코드/테스트/증빙과 같은 기준으로 고정한다.
- 동일한 tiny base model을 재사용해 비교가 쉽게 만든다.
- 시나리오별 기대 판정과 기대 로그를 미리 정해 개발 방향이 흔들리지 않게 한다.

## 2. 공통 구성
각 시나리오 폴더는 아래 파일을 기본으로 갖습니다.

- `README.md`: 시나리오 목적, 차단/통과 포인트, 발표 포인트
- `config.json`: 최소 구성 설정 파일
- `fixture_manifest.json`: 실제 mock HF repo에 들어갈 파일 목록과 생성 상태
- `expected_result.json`: 기대 판정값, reason code, 정책 프로파일
- `expected_log.md`: 발표 때 보여줄 핵심 로그 예시

필요한 경우 추가 파일:
- `.py`: 악성 코드/정상 코드 fixture
- `malicious_marker.py`: harmless marker-only pickle 생성 보조 코드

## 3. 공통 base model
공통 base model 명세는 [base_model_spec.json](/c:/Users/andyw/OneDrive%20-%20중부대학교/바탕%20화면/HuggingMask/mock_hf/base_model_spec.json)에 둡니다.

핵심 조건:
- 작은 텐서 2개만 사용
- safetensors / pickle / config / code 시나리오 모두 같은 기반 사용
- 최종 비교는 `torch.allclose()`와 SHA256로 단순화 가능

## 4. 정책 프로파일

### `strict_default`
- 기본 정책
- `auto_map`, `custom_pipelines`, `trust_remote_code` 탐지 시 config 단계에서 차단 또는 리뷰 전환
- 악성 config 시나리오 기본 프로파일

### `allow_custom_code_scan`
- 데모 전용 프로파일
- custom code를 코드 분석 단계까지 통과시켜 AST 차단을 보여주기 위한 프로파일
- 악성 코드(.py) 시나리오 전용

이 분리가 필요한 이유:
- 시나리오 4는 "코드가 악성이라서 차단"을 보여줘야 함
- 시나리오 5는 "config 트리거가 문제라서 차단"을 보여줘야 함
- 두 시나리오가 같은 단계에서 막히면 발표 메시지가 흐려짐

## 5. 시나리오 매트릭스

| 시나리오 | 폴더 | 정책 프로파일 | 기대 판정 | 핵심 reason code |
|---|---|---|---|---|
| 정상 safetensors | `hm-01-safe-st` | `strict_default` | `APPROVE` | `SAFE_TENSORS_HASH_OK` |
| 정상 pickle | `hm-02-safe-pkl` | `strict_default` | `APPROVE_WITH_TRANSFORM` | `PICKLE_OPCODE_ALLOWED_ONLY` |
| 악성 pickle | `hm-03-bad-pkl-reduce` | `strict_default` | `DENY` | `PICKLE_OPCODE_BLOCKED` |
| 악성 코드 | `hm-04-bad-py-import` | `allow_custom_code_scan` | `DENY` | `DANGEROUS_CALL` |
| 악성 config | `hm-05-bad-config-automap` | `strict_default` | `DENY` | `CONFIG_TRIGGER_FIELD_FOUND` |

## 6. 구현 우선순위
1. `hm-01-safe-st`
2. `hm-02-safe-pkl`
3. `hm-03-bad-pkl-reduce`
4. `hm-04-bad-py-import`
5. `hm-05-bad-config-automap`

## 7. 발표 전 체크
- 각 시나리오의 `expected_result.json`과 실제 판정이 일치하는지 확인
- 각 시나리오의 핵심 로그가 `expected_log.md`와 비슷한지 확인
- 데모 캡처 파일을 `evidence/demo/`에 같은 시나리오명으로 저장
