# HuggingMask Hugging Face 실데이터 평가 부족점 보고서

작성일: 2026-05-27  
최신화: 2026-06-08  
대상: HuggingMask 현재 작업트리 `feature/docs-status-refresh`  
목적: 실제 Hugging Face Hub 모델 파일을 기준으로 HuggingMask 검증 성능과 부족점, 이후 보완 상태를 초심자도 이해할 수 있게 정리한다.

## 0. 2026-06-08 최신화 요약

이 문서는 2026-05-27 실데이터 평가에서 발견한 부족점을 보존하고, 2026-06-08 발표 전 기준으로 해결/잔여 상태를 덧붙인 것이다. 아래 원 진단 문구는 이력 추적을 위해 유지하며, 현재 상태 판단은 이 표를 우선한다.

| 번호 | 원 진단 | 2026-06-08 상태 |
|---:|---|---|
| 1 | `/full`이 전처리 메타데이터를 누락 | 해결. `/full`에서 preprocessing metadata route와 결과 생성을 테스트로 고정 |
| 2 | `tokenizer_config.json`의 `chat_template` semantic 검증 누락 | 해결. semantic inventory와 chat template hint/details를 결과에 보존 |
| 3 | demo script classifier와 core classifier 불일치 | 해결. demo script가 core classifier를 사용하고 테스트로 고정 |
| 4 | Hub common file이 조용히 누락 | 부분 해결. preprocessing 계열은 결과를 남기며, 모든 Hub 보조 파일 정책은 후속 범위 |
| 5 | remote-code config가 snapshot Python 파일을 충분히 추적하지 못함 | 부분 해결. 요청 artifact/source loader 기반 추적은 보강됐고, production Hub snapshot 수집은 후속 범위 |
| 6 | config 참조 Python과 요청 Python 중복 결과 | 후속 개선. 발표 MVP의 핵심 차단 흐름에는 영향 작음 |
| 7 | B-2 sandbox evidence가 `/full`에 항상 붙지 않음 | 부분 해결. fixture/데모 경로와 opt-in runner 계약은 있음. 실제 runsc 운영은 별도 증빙 경로 |
| 8 | 일반 `pytorch_model.bin` Path B fallback 부족 | 정책 보강. raw pickle은 자동 release하지 않고 review/conversion 기준으로 분리 |
| 9 | `training_args.bin`이 전체 release block을 유발 | 해결. auxiliary pickle role과 release neutral 정책을 테스트로 고정 |
| 10 | YARA/modelscan availability 불명확 | 부분 해결. Docker 기준 Python 3.12로 modelscan/yara 설치 가능. 환경별 health/report 노출은 후속 범위 |

발표용 결론은 다음과 같다.

- HuggingMask는 발표 MVP 기준으로 safetensors, pickle, Python code, config, preprocessing metadata의 핵심 검증 흐름을 보여줄 수 있다.
- 가장 위험했던 “검증 누락이 승인처럼 보이는 문제”는 전처리 메타데이터와 demo classifier 범위에서 보완됐다.
- production 수준 Hub 저장소 전체 수집, 모든 보조 파일 정책, 실 runsc 운영 자동화는 후속 과제로 남긴다.

## 1. 한 줄 요약

HuggingMask는 위험한 모델 파일을 사전에 걸러내기 위한 검증기다. 2026-05-27 실데이터 평가에서는 전처리 메타데이터, remote code 연결, 일반 PyTorch weight, 평가 스크립트 일관성에서 누락과 오탐이 확인됐고, 2026-06-08 발표 전 기준으로 전처리 routing, tokenizer semantic inventory, demo classifier 일치, pickle role/release 정책은 보완됐다.

## 2. HuggingMask가 하려는 일

Hugging Face 모델 저장소에는 보통 다음과 같은 파일이 함께 들어 있다.

| 파일 종류 | 예시 | 왜 중요한가 |
|---|---|---|
| 안전 weight | `model.safetensors` | 실행 없이 tensor 구조를 읽을 수 있어 상대적으로 안전하다. |
| pickle/PyTorch weight | `pytorch_model.bin`, `training_args.bin`, `*.pkl` | Python pickle은 로딩 시 코드 실행 위험이 있어 엄격히 봐야 한다. |
| 모델 설정 | `config.json` | `auto_map`, `custom_pipelines`, `trust_remote_code` 같은 필드가 있으면 Hub의 Python 코드를 로컬에서 실행하게 만들 수 있다. |
| 모델 코드 | `modeling_*.py`, `configuration_*.py` | custom model 구현 코드다. 위험 API, 동적 import, subprocess 등을 봐야 한다. |
| 전처리 설정 | `tokenizer_config.json`, `tokenizer.json`, `preprocessor_config.json`, `processor_config.json` | 입력 텍스트, 이미지, 음성을 모델 입력으로 바꾸는 규칙이다. chat template이나 processor 설정이 바뀌면 모델 동작과 보안 경계가 달라진다. |

HuggingMask의 이상적인 흐름은 다음과 같다.

1. Hub 저장소의 파일을 빠짐없이 분류한다.
2. 파일 종류에 맞는 검증기로 보낸다.
3. 안전한 파일은 `PASS`, 위험한 파일은 `BLOCK`, 증거가 부족하면 `PENDING_REVIEW`로 남긴다.
4. 어떤 파일이 왜 통과/차단/검토대기인지 사람이 추적할 수 있게 증거를 남긴다.

이번 평가는 이 흐름이 실제 Hub 파일에서도 지켜지는지 확인한 것이다.

## 3. 평가에 사용한 실제 Hub 모델

| 모델 | 사용 목적 | 확인한 대표 파일 |
|---|---|---|
| `openai/whisper-tiny` | audio preprocessor와 tokenizer 메타데이터 확인 | `preprocessor_config.json`, `tokenizer_config.json`, `tokenizer.json`, `merges.txt` |
| `Qwen/Qwen2.5-0.5B-Instruct` | chat template 검증 확인 | `tokenizer_config.json` |
| `HuggingFaceTB/SmolLM2-135M-Instruct` | 정상 instruct 모델과 보조 pickle 파일 오탐 확인 | `training_args.bin`, `tokenizer_config.json` |
| `sentence-transformers-testing/stsb-bert-tiny-safetensors` | safetensors 정상 경로 확인 | `model.safetensors` |
| `fxmarty/tiny-testing-gpt2-remote-code` | `auto_map` remote code 경로 확인 | `config.json`, `modeling_gpt2.py`, `pytorch_model.bin` |
| `FIRSTACCOUNT69/auto-map-test` | 최소 custom code config 확인 | `config.json`, `model.py` |
| `drhyrum/bert-tiny-torch-picklebomb` | pickle 위험 탐지 확인 | `archive/data.pkl` |
| `timotejKralik/pickle_malicious_test` | 악성 pickle PoC 확인 | `params.pkl` |

## 4. 실제 테스트에서 확인한 긍정 신호

부족점만 있는 것은 아니다. 현재 구현에서 동작하는 부분도 확인됐다.

| 확인 항목 | 결과 |
|---|---|
| 작은 safetensors 파일 검증 | `sentence-transformers-testing/stsb-bert-tiny-safetensors/model.safetensors`는 `PASS` 처리됐다. |
| 명백한 malicious pickle 탐지 | `timotejKralik/pickle_malicious_test/params.pkl`은 `PICKLE_OPCODE_BLOCKED`로 차단됐다. |
| picklebomb 계열 pickle 탐지 | `drhyrum/bert-tiny-torch-picklebomb/archive/data.pkl`도 `PICKLE_OPCODE_BLOCKED`로 차단됐다. |
| `auto_map` 기본 감지 | `FIRSTACCOUNT69/auto-map-test/config.json`은 `auto_map`을 감지했고 연결된 `model.py` 검증까지 시도했다. |

따라서 문제는 “아무것도 안 된다”가 아니라, 실제 Hub의 다양한 파일 구조를 만나면 일부 경로가 빠지거나 너무 거칠게 판정된다는 것이다.

## 5. 부족한 점 10가지

아래 항목은 2026-05-27 원 진단이다. 현재 해결/잔여 상태는 문서 상단의 `2026-06-08 최신화 요약`을 우선해서 본다.

### 1) `/full` 검증이 전처리 메타데이터를 거의 버린다

실제 `openai/whisper-tiny/preprocessor_config.json`만 `/internal/v1/validation/full`에 넣었을 때 결과는 `PASS / APPROVE`, `artifact_results=0`이었다.

같은 파일을 `/internal/v1/validation/jobs`에 넣으면 `PREPROCESSING_SEMANTIC_SCAN`, `PENDING_REVIEW`, `BASELINE_MISSING`으로 처리된다.

즉 검증기는 전처리 파일을 다룰 능력이 일부 있지만, 통합 검증 endpoint인 `/full`에서는 그 경로가 연결되지 않았다.

관련 코드:

- `whitelist/full_pipeline.py`의 `CODE_CONFIG_KINDS`가 `PYTHON`, `CONFIG_JSON`, `TOKENIZER_CONFIG_JSON`만 허용한다.
- 그 결과 `TOKENIZER_JSON`, `SPECIAL_TOKENS_MAP_JSON`, `ADDED_TOKENS_JSON`, `VOCAB_JSON`, `MERGES_TXT`, `PREPROCESSOR_CONFIG_JSON`, `PROCESSOR_CONFIG_JSON`, `CHAT_TEMPLATE_JINJA`가 `/full`에서 결과 없이 사라질 수 있다.

위험:

- 전처리 파일이 실제 모델 동작을 바꾸는데도 최종 응답은 승인처럼 보일 수 있다.
- 보안 검토자가 “검증 대상에서 빠졌다”는 사실을 알기 어렵다.

### 2) `tokenizer_config.json`의 `chat_template` 검증이 빠진다

`Qwen/Qwen2.5-0.5B-Instruct/tokenizer_config.json`에는 다음과 같은 중요한 값이 있었다.

- `chat_template` 있음
- `system`, `tools`, `add_generation_prompt` 관련 분기 있음
- `model_max_length=131072`

하지만 HuggingMask 결과는 `CONFIG_SCHEMA_VALIDATION PASS`였고, `semantic_check`나 `semantic_findings`가 붙지 않았다.

관련 코드:

- `analyzer/orchestrator.py`는 `TOKENIZER_CONFIG_JSON`을 `validate_config_artifact()`로 먼저 보낸다.
- `analyzer/validators/code_semantic.py`에는 `TOKENIZER_CONFIG_JSON`이 전처리 메타데이터 종류로 들어 있지만, `/full` 실제 경로에서는 semantic 검증이 보존되지 않는다.

위험:

- chat template은 모델이 system/user/assistant/tool 메시지를 어떻게 합치는지 결정한다.
- prompt boundary나 tool call 경계를 바꾸는 template이 있어도 단순 config로 통과할 수 있다.

### 3) 실제 평가 스크립트와 core classifier가 서로 다르다

실제 Hub 평가용 스크립트 `scripts/demo_validate_hf.py`는 자체 classifier를 갖고 있다. 그런데 core classifier인 `analyzer/classifier.py`와 매핑이 다르다.

예시:

| 파일 | core classifier | demo script |
|---|---|---|
| `preprocessor_config.json` | `PREPROCESSOR_CONFIG_JSON` | 제출 안 함 |
| `processor_config.json` | `PROCESSOR_CONFIG_JSON` | 제출 안 함 |
| `tokenizer.json` | `TOKENIZER_JSON` | 제출 안 함 |
| `special_tokens_map.json` | `SPECIAL_TOKENS_MAP_JSON` | 제출 안 함 |
| `merges.txt` | `MERGES_TXT` | 제출 안 함 |
| `model.pth` | `OTHER` | `PICKLE` |
| `model.ckpt` | `OTHER` | `PICKLE` |

위험:

- demo 결과가 실제 production routing을 대표하지 못한다.
- 보고서나 시연에서 “검증했다”고 말해도 core에서는 다르게 동작할 수 있다.

### 4) 실제 Hub에서 흔한 파일들이 조용히 `OTHER` 또는 누락된다

이번 실제 모델에서 다음 파일들이 검증 결과에서 빠졌다.

- `generation_config.json`
- `normalizer.json`
- `vocab.txt`
- `trainer_state.json`
- `eval_results.json`
- `all_results.json`
- `pytorch_model.bin.index.json`
- `model.safetensors.index.json`
- `tokenizer.model`

모든 파일을 반드시 위험 파일로 봐야 한다는 뜻은 아니다. 문제는 “검증 대상 아님”이라는 결과도 남기지 않고 사라지는 점이다.

관련 코드:

- `analyzer/classifier.py`는 일부 고정 파일명만 분류한다.
- `whitelist/full_pipeline.py`는 routing 대상이 아닌 artifact에 `SKIPPED` 결과를 만들지 않는다.

위험:

- reviewer는 어떤 파일이 실제로 검증됐고 어떤 파일이 제외됐는지 알 수 없다.
- sharded model index 같은 파일은 weight 구성과 연결되는데도 검증 증거가 없다.

### 5) remote-code config만으로는 Hub snapshot의 Python 파일을 따라가지 못한다

`fxmarty/tiny-testing-gpt2-remote-code/config.json`만 검증하면 `auto_map -> modeling_gpt2.py` 참조를 찾아낸다. 하지만 `modeling_gpt2.py` 파일을 요청 artifact에 같이 넣지 않으면 `referenced_source_not_found`로 남는다.

관련 코드:

- `analyzer/validators/config_validator.py`는 `auto_map`에서 Python 파일명을 추출한다.
- 그러나 `/full`은 `model_snapshot_inventory`나 `SnapshotSourceResolver`를 넘기지 않고, 요청에 들어온 artifact만 `source_loader`로 제공한다.

위험:

- 실제 Hub 저장소 단위 검증이 아니라 “요청에 같이 넣은 파일만” 검증하는 형태가 된다.
- config가 remote code를 가리켜도 downloader/snapshot 연결이 없으면 코드 검증이 누락된다.

### 6) config가 참조한 Python 파일과 요청 Python 파일이 중복 결과로 나타난다

`FIRSTACCOUNT69/auto-map-test`에서 `config.json`과 `model.py`를 함께 넣었을 때 `model.py` 결과가 두 번 나타났다. 하나는 config가 연결한 linked code 결과이고, 다른 하나는 원래 요청 artifact 결과다.

위험:

- 차단/검토 건수가 실제 파일 수보다 부풀려진다.
- 보고서의 artifact count, blocked count, pending count가 혼란스러워진다.
- 같은 파일에 대해 서로 다른 경로의 결과가 생기면 최종 판단을 해석하기 어렵다.

### 7) B-2 sandbox evidence가 `/full` 실제 경로에 붙지 않는다

`fxmarty/tiny-testing-gpt2-remote-code`의 `__init__.py`, `create_model.py`는 `CODE_SANDBOX_RUNTIME`, `B-2`, `PENDING_REVIEW`로 나왔다. 그런데 결과 detail에 `sandbox_check`가 없었다.

관련 코드:

- `whitelist/full_pipeline.py`가 `run_validation_job_with_whitelist_engine()` 호출 시 `b2_runner`와 `source_resolver`를 넘기지 않는다.
- `analyzer/orchestrator.py`의 `_requires_b2_sandbox()` 조건도 `MODELING` role 중심이라 auxiliary/unknown B-2 파일에는 sandbox evidence가 붙기 어렵다.

위험:

- `CODE_SANDBOX_RUNTIME`이라는 route 이름은 실제 sandbox 실행이 있었던 것처럼 보인다.
- 그러나 실제 응답에는 실행 evidence가 없으므로 reviewer가 오해할 수 있다.

### 8) 일반 `pytorch_model.bin`은 Path B를 켜도 Path A에서 먼저 막힌다

`fxmarty/tiny-testing-gpt2-remote-code/pytorch_model.bin`은 크기가 약 1.8MB인 실제 PyTorch weight 파일이다. 현재 weight validator 결과는 `PICKLE_PARSE_ERROR`로 `BLOCK`이었다.

`enable_path_b=True`로도 확인했지만 `path_b` 결과가 없었다. Path A에서 block되면 Path B로 넘어가지 않기 때문이다.

관련 코드:

- `analyzer/validators/weight/pipeline.py`의 `validate_pickle_pipeline()`은 Path A block 시 바로 return한다.
- `analyzer/validators/weight/validators/pickle_opcode_parser.py`는 HuggingMask 전용 `__tensor_dict__` safe schema만 지원한다.

위험:

- 실제 Hub의 정상 `pytorch_model.bin` 상당수가 오탐으로 차단될 수 있다.
- Path B가 “보완 경로”처럼 문서화되어 있어도 실제로는 Path A block을 회복하지 못한다.

### 9) `training_args.bin` 같은 보조 파일도 모델 release block으로 처리된다

`HuggingFaceTB/SmolLM2-135M-Instruct/training_args.bin`은 모델 weight가 아니라 학습 설정 보조 파일에 가깝다. 하지만 `.bin`이라는 이유로 `PICKLE`로 분류되어 `PICKLE_PARSE_ERROR`가 발생했고, 전체 모델 결과가 `DENY`가 됐다.

위험:

- 실제 모델 저장소에는 학습 로그, trainer state, argument dump 파일이 섞여 있다.
- 파일 역할을 구분하지 않으면 정상 공개 모델도 전체 차단될 수 있다.

개선 방향:

- `pytorch_model.bin`, `tf_model.h5`, `flax_model.msgpack`, `training_args.bin`처럼 파일명/역할별 정책을 분리해야 한다.
- release 대상 weight와 부속 evidence 파일을 다르게 처리해야 한다.

### 10) 선택 보안 스캐너가 실제 환경에서 빠져 있었다

실제 pickle 평가에서 `YARA_UNAVAILABLE`, `MODELSCAN_UNAVAILABLE`가 나왔다. `requirements.txt`에는 `modelscan`, `yara-python`이 있지만 현재 실행 환경에서는 로딩되지 않았다.

위험:

- 실제 위험 판단이 `pickletools` 기반 Path A에 크게 의존한다.
- 운영자가 “YARA/modelscan까지 돌았다”고 오해할 수 있다.

개선 방향:

- scanner가 unavailable이면 단순 detail이 아니라 job-level warning으로 보여야 한다.
- CI나 demo 환경에서 scanner 설치 여부를 별도 health check로 확인해야 한다.

## 6. 별도 에이전트 검증 결과

사용자 요청에 따라 다른 에이전트에게 같은 repo를 독립적으로 검토시켰다. 검토 에이전트는 파일을 수정하지 않았고, 다음 항목을 주요 약점으로 지적했다.

| 에이전트 지적 | 최종 보고서 반영 |
|---|---|
| classifier coverage가 좁고 실제 Hub 파일이 `OTHER`로 빠진다 | 3, 4번 |
| demo script classifier와 core classifier가 다르다 | 3번 |
| `/full`이 preprocessing metadata를 무시한다 | 1번 |
| `tokenizer_config.json`이 semantic validator를 우회한다 | 2번 |
| remote-code config handling이 snapshot 기반으로 이어지지 않는다 | 5번 |
| B-2 sandbox가 `/full`에 실제 연결되지 않는다 | 7번 |
| 일반 PyTorch pickle/state_dict 지원이 부족하다 | 8번 |
| YARA/modelscan이 unavailable일 수 있고 evidence 품질이 약하다 | 10번 |

즉 위 10개는 단순 추측이 아니라 실제 Hub 파일 실행 결과와 독립 에이전트 코드 검토가 함께 지지한 항목이다.

## 7. 우선순위 제안

| 우선순위 | 작업 | 이유 |
|---|---|---|
| 완료 | preprocessing metadata routing을 `/full`에 연결 | `preprocessor_config.json`, `processor_config.json`, `tokenizer.json`, `chat_template.jinja` 계열 결과 보존 |
| 완료 | `tokenizer_config.json`에 semantic inventory 적용 | chat template hint/details와 semantic summary 보존 |
| 완료 | demo script classifier를 core classifier로 통합 | 시연/보고서와 실제 엔진 결과 불일치 축소 |
| 완료 | pickle 파일 역할 분류 추가 | `training_args.bin` 같은 auxiliary pickle을 release artifact와 분리 |
| P1 | Hub snapshot inventory/source resolver 운영화 | `auto_map` remote code를 저장소 단위로 안정 추적하려면 필요 |
| P1 | PyTorch state_dict 비실행 파서 또는 Path B fallback 운영 정책 정교화 | 정상 `pytorch_model.bin` review evidence 품질 개선 |
| P2 | scanner availability를 health/report에 노출 | YARA/modelscan 누락을 운영자가 바로 알 수 있게 함 |
| P2 | 중복 artifact result dedupe | 보고서 count와 reviewer 해석 안정화 |
| P2 | sharded index, SentencePiece, vocab txt 등 common Hub 파일 정책 추가 | 실제 Hub coverage 확대 |

## 8. 결론

현재 HuggingMask는 safetensors fast path, 명백한 악성 pickle 탐지, 기본 `auto_map` 감지, tokenizer/config semantic inventory, auxiliary pickle role 분리까지 작동한다. 발표 MVP로는 핵심 보안 흐름을 설명할 수 있다.

가장 큰 문제였던 검증 누락은 preprocessing metadata와 demo classifier 범위에서 보완됐다. 다만 실제 Hugging Face Hub 모델을 production 저장소 단위로 평가하려면 snapshot inventory/source resolver 운영화, 보조 파일 정책 확대, scanner availability 노출이 남아 있다.

다음 단계는 새 기능을 크게 추가하기보다, 발표 이후 다음 세 가지를 안정화하는 것이 현실적이다.

1. Hub snapshot 단위로 config가 참조한 Python 파일과 전처리 파일을 빠짐없이 따라간다.
2. 모든 보조 파일에 대해 `검증 대상`, `release 대상`, `증빙 대상`, `무시 대상`을 명확히 분리한다.
3. YARA/modelscan/runsc 같은 선택 보안 구성요소의 availability를 health/report에 노출한다.

이 세 가지가 잡히면 이후 B-2 sandbox 실제 실행 자동화, PyTorch weight 호환성, scanner 운영화를 단계적으로 붙일 수 있다.
