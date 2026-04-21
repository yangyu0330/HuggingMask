# 단계 4 - Grade Decision

## 목적

역할 분류, AST scan, API scan, context analyzer, 제한 런타임 gate 결과를 합쳐 코드 파일별 최종 등급과 상태를 결정한다. 이 단계는 코드검증이 반환할 `ArtifactValidationResult`를 완성한다.

## 담당 범위

코드검증이 직접 구현한다.

- `validate_python_artifact(...)` 형태의 통합 함수
- A/B-1/B-2/C 등급 판정
- `ValidationStatus`, `ReviewAction`, `runtime_mode` 매핑
- `ArtifactValidationResult.details` 조립
- B-1 runtime gate 결과 입력 반영
- out-of-scope role의 자동 승인 차단
- 위험 API 발견 시 즉시 `BLOCK`

## 비범위

- 제한 런타임 자체의 완성 구현
- gVisor/Docker sandbox 운영 구현
- sandbox 로그 저장소
- 보안 담당자 review queue 생성/운영
- 정식 whitelist DB 업데이트
- config trigger 라우팅 구현
- orchestrator의 job-level overall decision 계산

## 입력

- `ArtifactRef`
- Python source text
- `PolicyInfo`
- `WhitelistLookup`
- `RoleClassification`
- `AstScanResult`
- `ApiScanResult`
- `ContextApiScanResult`
- 선택 입력: `runtime_check`

## 출력

- `ArtifactValidationResult`
  - `artifact_id`
  - `repo_path`
  - `file_kind`
  - `route_kind`
  - `status`
  - `grade`
  - `review_action`
  - `reason_entries`
  - `details`

`details.grade_result` 권장 필드:

- `grade`
- `status`
- `review_action`
- `runtime_mode`
- `grade_reasons`
- `is_auto_approval_candidate`
- `requires_runtime_gate`
- `requires_security_review`

## 생성/수정 파일

문서 분리 작업에서 생성하는 파일:

- `docs/code_validation_plans/04_grade_decision.md`

구현 단계에서 생성/수정할 파일:

- `analyzer/validators/code_validator.py`
- `tests/test_code_validator.py`

## 구현 규칙

- 위험 import/call/API는 즉시 `BLOCK`, `C`, `BLOCK_IMMEDIATELY`로 매핑한다.
- 명확한 위험 API가 있으면 제한 런타임이나 sandbox를 실행하지 않는다.
- 동적/난독화 패턴은 `C/PENDING_REVIEW/MANUAL_REVIEW_REQUIRED`로 매핑한다. 위험 호출이 함께 있으면 `BLOCK`이 우선한다.
- context analyzer 결과가 `block`이면 `BLOCK`, `C`, `BLOCK_IMMEDIATELY`로 매핑한다.
- context analyzer 결과가 `review`이면 `B-2/PENDING_REVIEW/SECURITY_OWNER_GATE`로 매핑한다.
- unregistered API는 `B-2/PENDING_REVIEW/SECURITY_OWNER_GATE`로 매핑한다.
- 모델 실행형 `B-1/PASS`는 allowed API만 사용하고 context 결과가 모두 `safe`이며 runtime gate가 통과한 경우에만 허용한다.
- 제한 런타임은 B-1 후보를 최종 `PASS`시키기 위한 gate다.
- runtime gate가 미구현, skipped, fixture 부족이면 `B-1/PASS`가 아니라 `B-2/PENDING_REVIEW` 또는 명시적 B-1 candidate detail로 남긴다.
- gVisor/Docker 샌드박스는 B-2/C 후보의 증거 수집과 리뷰 보조용이지 자동 승인 증명이 아니다.
- A 등급 config는 원본 `configuration_*.py`를 import하거나 `to_dict()`를 호출하지 않는다.
- A 등급은 AST/source metadata로 class name, `model_type`, 생성자 인자, 기본값, `self.xxx`, `attribute_map`, 하위 config 필드를 확인한다.
- `PREPROCESSING`, `AUXILIARY`, `UNKNOWN`은 1차 구현에서 자동 승인하지 않는다. 위험이 있으면 `BLOCK`, 그 외에는 `PENDING_REVIEW` 또는 `SKIPPED`다.

## 테스트

추가할 pytest:

- `tests/test_code_validator.py`

핵심 케이스:

- 단순 `configuration_*.py` + `PretrainedConfig` + 단순 속성 할당 -> `A/PASS/AUTO_APPROVE_REGENERATED`
- config 검증 중 import/to_dict 호출이 필요 없음을 테스트 double로 확인
- 정형 `modeling_*.py` + allowed API + context safe + runtime_check passed -> `B-1/PASS/AUTO_APPROVE`
- 정형 `modeling_*.py` + allowed API + runtime_check skipped -> `B-2/PENDING_REVIEW/SECURITY_OWNER_GATE`
- unregistered API -> `B-2/PENDING_REVIEW`
- context review -> `B-2/PENDING_REVIEW`
- context block -> `BLOCK`
- `eval` -> `BLOCK`
- `torch.load` -> `BLOCK`
- dynamic `getattr` -> `C/PENDING_REVIEW`
- `tokenization_*.py` 위험 없음 -> 자동 `PASS` 아님
- export-only `__init__.py` 위험 없음 -> 자동 `PASS` 아님

## 완료 기준

- `validate_python_artifact(...)`가 `ArtifactValidationResult`를 반환한다.
- `details`에 `role_classification`, `ast_scan`, `api_scan`, `context_api_scan`, `grade_result`, `runtime_check`, `pending_api_refs`가 들어갈 수 있다.
- B-1 최종 PASS가 runtime gate에 의해 통제된다.
- 즉시 위험 API가 sandbox/runtime으로 넘어가지 않는다.
- 1차 범위 밖 역할이 자동 승인되지 않는다.

## 다음 단계 연결

단계 5는 config와 tokenizer config에서 참조된 `.py` 파일을 코드검증으로 라우팅한다. 단계 4의 `ArtifactValidationResult.status`는 config 결과의 `effective_status` 계산에 사용된다.
