# 단계 1 - Schema/Classifier 최소계약

## 목적

모든 validator가 같은 객체를 입력받고 같은 형태의 결과를 반환하도록 공통 schema와 파일 분류기의 최소 계약을 고정한다. 이 단계가 끝나야 코드검증, config 라우팅, orchestrator 통합 단계가 서로 다른 결과 포맷을 만들지 않는다. 단, `analyzer/schemas.py`와 `analyzer/classifier.py`는 Analyzer Core 정식 구현 전까지 코드검증 테스트용 최소 dataclass/helper로 한정한다.

## 구현 반영 상태 (2026-04-21)

- 상태: 완료. schema 최소 계약과 file classifier가 구현되어 이후 validator, config routing, orchestrator adapter의 공통 입출력으로 사용된다.
- 경계: `analyzer/schemas.py`, `analyzer/classifier.py`는 Analyzer Core 정식 구현 전의 코드검증 테스트용 최소 dataclass/helper 계약이다.

## 담당 범위

코드검증 구현자가 직접 다루는 범위는 schema를 소비하고 테스트하는 최소 계약이다.

- `ArtifactValidationResult`에 코드검증 결과를 담는 방식 정의
- `details` 확장을 깨지 않도록 dict 기반 세부 결과 허용
- `FileKind.PYTHON`, `CONFIG_JSON`, `TOKENIZER_CONFIG_JSON` 분류 결과를 코드검증 라우팅 입력으로 사용
- `CodeGrade`, `ValidationStatus`, `ReviewAction`, `RouteKind` enum 값이 인터페이스 정의서와 일치하는지 확인
- 파일 경로는 저장소 기준 POSIX 상대경로로 다룬다는 전제 확인
- Analyzer Core 정식 schema/classifier가 나오면 이 단계의 최소 helper는 그 계약에 맞춰 교체 또는 흡수

## 비범위

- Analyzer Core의 최종 공통 schema/classifier 소유권 확정
- schema 전체를 Pydantic으로 교체하는 작업
- 외부 REST endpoint request validation
- proxy 인증/권한 검증
- 최종 `ValidationJobResponse` 조립 정책 전체
- 가중치 검증용 safetensors/pickle 세부 검사 구현
- 정식 whitelist DB 또는 pending store 모델 완성

## 입력

- 저장소 내 파일 경로와 파일 bytes 또는 local path
- 인터페이스 정의서의 공통 enum과 객체 정의
- `PolicyInfo`, `RuntimeContext`, `ModelRef`에 해당하는 정책/요청 metadata

## 출력

구현 단계 출력:

- `ArtifactRef`
- `ReasonEntry`
- `ArtifactValidationResult`
- `ValidationJobRequest`
- `ValidationJobResponse`
- enum: `FileKind`, `ValidationStatus`, `ReviewAction`, `CodeGrade`, `RouteKind`, `OverallDecision`

코드검증 detail에서 최소 보장할 하위 key:

- `ast_scan`
- `api_scan`
- `context_api_scan`
- `grade_result`
- `runtime_check`
- `pending_api_refs`

## 생성/수정 파일

문서 분리 작업에서 생성하는 파일:

- `docs/code_validation_plans/01_schema_classifier_최소계약.md`

구현 단계에서 생성/수정할 파일:

- `analyzer/__init__.py`
- `analyzer/schemas.py`
- `analyzer/classifier.py`
- `tests/test_json_schema.py`
- `tests/test_file_classifier.py`

## 구현 규칙

- 초기 구현은 표준 라이브러리 `dataclasses`, `Enum`, `asdict` 기반을 우선한다.
- 이 파일들은 코드검증 테스트를 위한 최소 계약이며, Analyzer Core 최종 책임을 대체하지 않는다.
- enum 값은 인터페이스 정의서의 문자열과 정확히 일치해야 한다.
- 필수 배열은 비어 있어도 필드 자체를 생략하지 않는다.
- 없음은 빈 문자열이 아니라 `None`/JSON `null`로 표현한다.
- `artifact_id`는 `sha256:<64자리 hex>` 형식을 따른다.
- 파일 경로는 Windows 입력을 받아도 저장소 기준 POSIX 상대경로로 정규화한다.
- `ArtifactValidationResult.details`는 하위 단계가 확장할 수 있도록 dict로 유지한다.
- `REVIEW_REQUIRED`는 파일 단위 `ValidationStatus`로 추가하지 않는다.

## 테스트

추가할 pytest:

- `tests/test_json_schema.py`
- `tests/test_file_classifier.py`

핵심 케이스:

- `ArtifactValidationResult`가 `details` 확장을 포함해 serialize 가능
- `ValidationStatus`가 `PASS/BLOCK/PENDING_REVIEW/ERROR/SKIPPED`만 포함
- `CodeGrade`가 `A/B-1/B-2/C/N/A`를 문자열로 보존
- `.py` -> `PYTHON`
- `config.json` -> `CONFIG_JSON`
- `tokenizer_config.json` -> `TOKENIZER_CONFIG_JSON`
- `.safetensors` -> `SAFETENSORS`
- `.pkl`, `.pt`, `.bin` -> `PICKLE`
- 기타 파일 -> `OTHER`
- Windows path 입력 시 `repo_path`가 `/` 기준으로 정규화
- bytes 또는 파일 내용 기준 sha256과 `artifact_id` 생성

## 완료 기준

- schema와 classifier 테스트가 통과한다.
- 이후 코드검증 단계가 별도 schema를 만들지 않고 `analyzer/schemas.py`를 사용할 수 있다.
- `details`에 코드검증 전용 세부 결과를 추가해도 상위 인터페이스 계약이 깨지지 않는다.
- config 라우팅과 orchestrator가 `ArtifactRef.file_kind`만 보고 dispatch할 수 있다.

## 다음 단계 연결

단계 2는 `FileKind.PYTHON` artifact의 source를 받아 역할 분류와 AST 분석을 수행한다. 이 단계의 `ArtifactRef`, enum, `ArtifactValidationResult`가 단계 2~6의 공통 입출력 계약이 된다.
