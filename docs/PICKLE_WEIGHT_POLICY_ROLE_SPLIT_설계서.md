# HuggingMask Pickle Weight Policy Role Split 설계서

문서 버전: v0.1  
작성일: 2026-06-07  
최신화: 2026-06-08  
대상 이슈: #37 `[policy] Split pickle weight policy by file role and safetensors path`  
대상 범위: `FileKind.PICKLE` 내부 역할 분리, release 정책, Path B 증빙 의미

## 0. 구현 상태 요약

2026-06-08 발표 전 기준으로 이 문서의 핵심 정책은 구현과 테스트에 반영됐다.

| 항목 | 상태 |
|---|---|
| public `FileKind.PICKLE` 유지 | 완료 |
| 내부 `pickle_role` 분리 | 완료 |
| `training_args.bin` auxiliary role 분리 | 완료 |
| raw pickle 자동 release 금지 | 완료 |
| generated safetensors만 release 대상 허용 | 완료 |
| Path B 통과만으로 raw pickle 승인 금지 | 완료 |
| `.pth`, `.ckpt` 별도 지원 제외 | 유지 |
| production runsc 운영 자동화 | 후속 범위 |

관련 테스트:
- `tests/test_file_classifier.py`
- `tests/test_weight_validation.py`
- `tests/test_full_pipeline.py`

## 1. 목적

이 문서는 기존 weight validator 설계를 폐기하지 않고, 실제 Hugging Face Hub 저장소를 더 정확히 다루기 위해 `PICKLE` 정책 해상도를 높이는 기준을 정의한다.

현재 설계는 보안 중심 MVP로서 다음 원칙을 이미 잘 지키고 있다.

- `safetensors`를 안전한 fast path로 우선 처리한다.
- pickle 계열 artifact는 untrusted input으로 보고 fail-closed한다.
- malicious opcode, YARA/modelscan 차단, parse error를 자동 승인하지 않는다.
- raw pickle 원본을 그대로 release 대상으로 승인하지 않는다.

다만 실제 HF 저장소에는 deployable weight, training args, trainer state, checkpoint, auxiliary metadata가 섞여 있다. 모든 `.bin`, `.pkl`, `.pt` 파일을 같은 `PICKLE` release 정책으로 처리하면 정상 모델 저장소도 과하게 차단되거나, 차단 사유가 악성/미지원/보조 파일 중 무엇인지 불명확해진다.

따라서 이번 범위는 public `FileKind.PICKLE` 계약을 유지하면서, 내부 역할과 결과 사유를 분리하는 것이다.

## 2. 현재 문제

현재 classifier는 `.pkl`, `.pt`, `.bin`을 모두 `FileKind.PICKLE`로 분류한다. 이 때문에 `pytorch_model.bin`과 `training_args.bin`이 같은 weight validator와 release gate를 탄다.

문제는 세 가지다.

| 문제 | 현재 영향 | 개선 방향 |
|---|---|---|
| deployable weight와 auxiliary artifact가 같은 정책을 탄다 | `training_args.bin` 같은 보조 파일이 전체 release를 차단할 수 있다 | 내부 role을 분리하고 release 대상 여부를 다르게 처리한다 |
| Path A block 시 Path B 증빙이 남지 않는다 | 일반 PyTorch weight가 왜 실패했는지 보조 증빙을 확보하기 어렵다 | 유용한 경우 Path B를 review evidence로 남긴다 |
| reason code가 정책 의미를 충분히 구분하지 못한다 | malicious, parse error, unsupported, conversion required가 같은 block처럼 보인다 | 결과 code를 세분화한다 |

이 문서는 classifier와 API를 크게 바꾸지 않고, 결과 의미와 release 정책을 먼저 고정한다.

## 3. 파일 역할 정책

public `FileKind`는 변경하지 않는다. 외부 요청과 응답의 기본 파일 종류는 계속 `PICKLE`을 사용한다. 대신 validator/service 내부에서 `pickle_role`을 계산해 `details`와 reason code에 남긴다.

| 내부 role | 대표 파일 | 의미 | 이번 범위 정책 |
|---|---|---|---|
| `DEPLOYABLE_WEIGHT` | `pytorch_model.bin` | 배포용 PyTorch weight 후보 | raw pickle은 자동 release 금지. 변환 safetensors 또는 명시 리뷰 필요 |
| `AUXILIARY_TRAINING` | `training_args.bin`, trainer state 계열 | 학습 설정/상태 보조 artifact | release 목록에서 제외. 악성 증거가 없으면 전체 승인을 단독 차단하지 않음 |
| `GENERIC_PICKLE` | `*.pkl`, `*.pt`, 이름만으로 역할이 불명확한 `.bin` | 역할 확정이 어려운 pickle artifact | 자동 release 금지. 안전 schema 변환 성공 시 generated safetensors만 release 가능 |
| `UNSUPPORTED_CHECKPOINT` | `*.pth`, `*.ckpt` | checkpoint 또는 학습 중간 산출물 후보 | 이번 #37 구현 범위에서 제외. core classifier 기준 `OTHER` 또는 unsupported로 고정 |

역할 분류는 서버 내부에서 repo path와 file name 기준으로 결정한다. 클라이언트가 새 필드를 보내도록 요구하지 않는다.

## 4. 결과 및 release 판정 정책

`status`와 release 대상은 분리해서 판단한다. 어떤 파일이 `PASS` 또는 `SKIPPED`에 가깝더라도 release artifact 목록에 들어가는지는 별도 정책으로 정한다.

| 입력/상황 | artifact status | overall 영향 | release 대상 |
|---|---|---|---|
| `model.safetensors` 검증 통과 | `PASS` | 전체 승인 가능 | 원본 safetensors |
| `PICKLE` safe schema가 Path A를 통과하고 safetensors 변환 성공 | `PASS` | 전체 승인 가능 | generated safetensors만 |
| raw pickle weight가 악성 증거 없이 Path A unsupported/parse fail | `PENDING_REVIEW` | 전체 `REVIEW_REQUIRED` | 없음 |
| auxiliary pickle이 악성 증거 없이 unsupported/parse fail | `SKIPPED` 또는 정책상 neutral result | 단독으로 전체 `DENY`를 만들지 않음 | 없음 |
| malicious opcode, YARA block, modelscan block | `BLOCK` | 전체 `DENY` | 없음 |
| `.pth`, `.ckpt` | `OTHER` 또는 unsupported | 이번 범위에서 자동 검증하지 않음 | 없음 |

raw pickle weight는 Path B가 통과해도 그대로 release하지 않는다. Path B 결과는 review evidence이며, release를 위해서는 safetensors 변환 산출물 또는 보안 책임자의 명시적 승인 경로가 필요하다.

## 5. Reason Code 후보

구현 시 다음 code를 우선 사용한다. 기존 code와 호환이 필요하면 alias 또는 nested detail로 병행 기록할 수 있다.

| reason code | 사용 조건 |
|---|---|
| `PICKLE_WEIGHT_REQUIRES_REVIEW_OR_CONVERSION` | deployable raw pickle weight가 자동 release 조건을 만족하지 못함 |
| `PICKLE_AUXILIARY_NOT_RELEASE_ARTIFACT` | training args/trainer state 등 release 대상이 아닌 보조 pickle |
| `UNSUPPORTED_PICKLE_CHECKPOINT` | `.pth`, `.ckpt` 등 이번 범위에서 지원하지 않는 checkpoint 후보 |
| `PICKLE_PARSE_ERROR` | pickle stream 파싱 실패. malicious 확정과 구분 |
| `UNSUPPORTED_PICKLE_FORMAT` | opcode는 즉시 악성이 아니지만 현재 safe schema/지원 parser 범위 밖 |
| `PICKLE_OPCODE_BLOCKED` | 실행성/위험 opcode가 확인되어 즉시 차단 |

malicious finding은 항상 `BLOCK` 우선이다. auxiliary role이어도 malicious opcode, YARA, modelscan block이 나오면 release neutral이 아니라 전체 `DENY`로 전파한다.

## 6. Path B 증빙 원칙

Path B는 raw pickle을 승인하는 우회로가 아니다. Path B의 역할은 다음으로 제한한다.

- 일반 PyTorch weight가 Path A에서 unsupported/parse fail일 때 tensor report를 얻을 수 있는지 확인한다.
- Path A 결과와 Path B 결과가 모두 tensor report를 제공하면 diff evidence를 남긴다.
- Docker/runsc infra failure는 artifact 악성 증거가 아니므로 `ERROR` 또는 `PENDING_REVIEW` 계열로 분리한다.
- Path B 통과만으로 raw pickle 원본을 `approved_artifact_ids`에 넣지 않는다.

Path A가 malicious opcode 또는 scanner block으로 차단한 경우에는 Path B를 실행하지 않아도 된다. 반대로 Path A가 unsupported/parse error이고 `enable_path_b=True`인 경우에는 review evidence로 Path B 결과를 남길 수 있어야 한다.

## 7. 구현 기준

구현은 다음 순서로 진행한다.

1. `FileKind`는 그대로 둔다.
2. `PICKLE` artifact에 대해 내부 `pickle_role` helper를 추가한다.
3. weight pipeline 결과에 `pickle_role`, `release_eligible`, `release_target` 성격의 detail을 남긴다.
4. service release gate에서 original raw pickle과 auxiliary pickle을 구분한다.
5. Path A unsupported/parse fail + `enable_path_b=True`인 경우 Path B evidence 보존 경로를 추가한다.
6. reason code와 테스트를 이 문서 기준으로 정렬한다.

이번 범위에서는 `.pth`, `.ckpt`를 `PICKLE`로 새로 지원하지 않는다. 해당 확장자를 배포/리뷰 대상으로 포함하는 정책은 별도 이슈에서 다룬다.

## 8. 테스트 기준

최소 회귀 테스트는 다음 시나리오를 포함해야 한다.

| 시나리오 | 기대 결과 |
|---|---|
| `model.safetensors` 단독 | `PASS`, `APPROVE`, 원본 safetensors release |
| `model.safetensors + training_args.bin` | 보조 파일 때문에 전체 `DENY`가 되지 않음 |
| `pytorch_model.bin` raw pickle weight | 자동 release되지 않고 `PENDING_REVIEW` |
| malicious pickle | 기존처럼 `BLOCK`, 전체 `DENY` |
| `.pth`, `.ckpt` | 이번 범위에서 `OTHER` 또는 unsupported로 고정 |
| demo script 분류 | core classifier와 같은 결과 유지 |

테스트는 status뿐 아니라 `approved_artifact_ids`, `blocked_artifact_ids`, `pending_artifact_ids`, `generated_artifacts`, `reason_entries`, `details["pickle_role"]`를 함께 확인해야 한다.

## 9. 결정 사항

- public `FileKind`는 변경하지 않는다.
- `training_args.bin`은 release artifact가 아니라 auxiliary artifact로 본다.
- raw pickle weight는 Path B가 통과해도 변환 또는 명시 리뷰 없이는 release 승인하지 않는다.
- `.pth`, `.ckpt`는 이번 #37 구현 범위에서 제외한다.
- 기존 safetensors fast path와 malicious pickle block 정책은 유지한다.
