# 단계 5 - Config Routing

## 목적

`config.json`과 `tokenizer_config.json`에서 코드 실행 trigger field를 탐지하고, 참조된 `.py` 파일을 코드검증 경로로 강제 연결한다. config 자체의 상태는 참조 코드 결과를 반영해 결정한다.

## 구현 반영 상태 (2026-04-21)

- 상태: 완료. config trigger field 탐지와 참조 `.py` code routing이 구현되어 code validator 결과를 config 상태에 반영한다.
- 경계: config validator는 원본 Python code를 실행하지 않고, 코드검증 로직을 복사하지 않는다.

## 담당 범위

코드검증과 config validator의 접점만 직접 다룬다.

- `auto_map`, `custom_pipelines`, `trust_remote_code` 탐지
- tokenizer/processor custom class reference 후보 탐지
- module/class reference를 `.py` repo path 후보로 변환
- 참조 `.py` artifact 목록 생성 또는 연결 요청
- 참조 코드 결과의 `status`를 config detail에 반영
- `ConfigValidationResultDetail` 또는 `ArtifactValidationResult.details`에 라우팅 결과 기록

## 비범위

- 전체 JSON schema validator 완성
- tokenizer semantic 검증
- config downloader 또는 Hub metadata fetch
- 실제 파일 목록 수집/다운로드
- 원본 `configuration_*.py` import
- 원본 config 객체 생성 또는 `to_dict()` 호출
- 최종 `ValidationJobResponse` 조립

## 입력

- `ArtifactRef(file_kind="CONFIG_JSON")`
- `ArtifactRef(file_kind="TOKENIZER_CONFIG_JSON")`
- config/tokenizer_config JSON object
- 저장소 artifact 목록 또는 repo path index
- 참조 `.py`의 `ArtifactValidationResult` 목록

## 출력

`ConfigValidationResultDetail` 권장 필드:

- `route_kind`: `CONFIG_SCHEMA_VALIDATION`
- `schema_valid`
- `trigger_fields_detected`
- `unknown_fields`
- `referenced_python_files`
- `rerouted_to_code_validation`
- `linked_code_artifact_ids`
- `linked_code_statuses`
- `effective_status`

config artifact의 최종 `status`:

- trigger 없음 + schema valid -> `PASS`
- trigger 있음 + 참조 코드 모두 `PASS` -> `PASS`
- trigger 있음 + 참조 코드 중 `PENDING_REVIEW` 존재 -> `PENDING_REVIEW`
- trigger 있음 + 참조 코드 중 `BLOCK` 존재 -> `BLOCK`
- 참조 파일 누락 -> 정책에 따라 `PENDING_REVIEW` 또는 `BLOCK`

## 생성/수정 파일

문서 분리 작업에서 생성하는 파일:

- `docs/code_validation_plans/05_config_routing.md`

구현 단계에서 생성/수정할 파일:

- `analyzer/validators/config_validator.py`
- `tests/test_config_validator.py`

## 구현 규칙

- config trigger field가 있으면 반드시 참조 `.py`를 코드검증 경로로 연결한다.
- `trust_remote_code`가 true이면 단독으로도 코드검증 필요 신호로 기록한다.
- `auto_map` 값에서 `module.ClassName` 형태를 찾아 `module.py` 후보로 변환한다.
- `custom_pipelines`에서 커스텀 pipeline implementation 후보를 추출한다.
- `tokenizer_config.json`의 custom tokenizer/processor class 참조도 라우팅 후보로 남긴다.
- 참조 파일이 artifact 목록에 없으면 조용히 무시하지 않는다.
- 참조 코드 중 하나라도 `BLOCK`이면 config도 `BLOCK`이다.
- 참조 코드 중 하나라도 `PENDING_REVIEW`이면 config도 `PENDING_REVIEW`다.
- `configuration_*.py` 검증을 위해 원본 파일을 import하거나 `to_dict()`를 호출하지 않는다.
- config validator 안에 코드검증 로직을 복사하지 않는다. 참조 `.py`는 code validator에 위임한다.

## 테스트

추가할 pytest:

- `tests/test_config_validator.py`

핵심 케이스:

- trigger field 없음 + schema valid -> `PASS`
- `auto_map: {"AutoModel": "modeling_demo.DemoModel"}` -> `modeling_demo.py` 추출
- `custom_pipelines`에 implementation 참조 -> `.py` 추출
- `trust_remote_code: true` -> trigger 기록
- tokenizer custom class 참조 -> `.py` 후보 추출
- 참조 파일 누락 -> `PENDING_REVIEW` 또는 정책상 `BLOCK`
- 참조 코드 결과 모두 `PASS` -> config `PASS`
- 참조 코드 중 `PENDING_REVIEW` -> config `PENDING_REVIEW`
- 참조 코드 중 `BLOCK` -> config `BLOCK`

## 완료 기준

- config detail에 trigger와 referenced python file 목록이 남는다.
- code validator로 넘길 참조 `.py` 목록이 결정된다.
- linked code status를 반영해 config `effective_status`를 계산한다.
- config 단계가 원본 Python code를 실행하지 않는다.

## 다음 단계 연결

단계 6은 orchestrator/adapter에서 artifact별 validator dispatch와 config -> code routing 흐름을 연결한다. 단계 5의 referenced file 목록과 linked status는 job-level 결과 계산의 입력이 된다.
