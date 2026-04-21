# 단계 6 - Orchestrator Adapter

## 목적

schema, file classifier, config routing, code validator 결과를 연결해 analyzer 단위에서 최소 `ValidationJobResponse` 형태를 만들 수 있게 한다. 이 단계는 최종 Analyzer Core 조립 책임이 아니라 proxy 없이 코드검증 흐름을 end-to-end로 테스트하는 adapter 계층이다.

## 담당 범위

코드검증 선행 구현에서는 analyzer 내부 연결과 smoke/integration test에 필요한 최소 조립까지만 담당한다.

- `ValidationJobRequest` artifact별 validator dispatch
- `PYTHON` artifact를 code validator로 전달
- `CONFIG_JSON`, `TOKENIZER_CONFIG_JSON` artifact를 config validator로 전달
- config가 참조한 `.py`를 code validator로 재라우팅
- `stop_on_first_block` 처리
- artifact별 결과 병합
- job-level `overall_status`, `overall_decision` 계산에 필요한 최소 adapter 로직
- approved/blocked/pending artifact id 목록 계산

## 비범위

- FastAPI proxy endpoint 최종 구현
- 외부 요청 인증/권한
- 실제 Hub 다운로드
- ML-BOM, audit log, report 저장소
- review queue 생성
- 정식 whitelist/pending store 연동
- gVisor/Docker runtime 실행 orchestration

## 입력

- `ValidationJobRequest`
- `ArtifactRef[]`
- artifact local path/source loader
- `WhitelistLookup` in-memory adapter
- 선택 입력: runtime gate adapter 또는 stub

## 출력

- `ValidationJobResponse`
  - `overall_status`
  - `overall_decision`
  - `release_action`
  - `artifact_results`
  - `approved_artifact_ids`
  - `blocked_artifact_ids`
  - `pending_artifact_ids`
  - `summary_reason_codes`

## 생성/수정 파일

문서 분리 작업에서 생성하는 파일:

- `docs/code_validation_plans/06_orchestrator_adapter.md`

구현 단계에서 생성/수정할 파일:

- `analyzer/orchestrator.py`
- `tests/test_validation_flow.py`

## 구현 규칙

- orchestrator는 각 validator의 결과를 조립하되, code validator 내부 정책을 복사하지 않는다.
- 이 adapter는 박용담 Analyzer Core의 최종 `ValidationJobResponse` 조립 정책을 대체하지 않는다.
- code validator는 파일별 `ArtifactValidationResult`만 반환한다.
- job-level 상태 계산은 인터페이스 정의서의 상태 전이 규칙을 따른다.
- 하나라도 `BLOCK`이면 `overall_status = BLOCK`, `overall_decision = DENY`다.
- `BLOCK`이 없고 하나라도 `PENDING_REVIEW`이면 `overall_status = PENDING_REVIEW`, `overall_decision = REVIEW_REQUIRED`다.
- 전부 `PASS`이면 `overall_status = PASS`, `overall_decision = APPROVE` 또는 재생성 포함 시 `APPROVE_WITH_TRANSFORM`이다.
- 인프라 오류가 있으면 결정 불가 상태를 `ERROR`로 올릴 수 있다.
- `PENDING_REVIEW` artifact는 release 대상이 아니다.
- A 등급 재생성 결과가 있는 경우 원본이 아니라 `effective_output_artifact_id`를 승인 대상으로 사용한다.
- proxy에는 검증 로직을 넣지 않고, 이후 proxy는 이 orchestrator만 호출한다.

## 테스트

추가할 pytest:

- `tests/test_validation_flow.py`

핵심 케이스:

- 모든 artifact `PASS` -> overall `PASS`
- 하나라도 `BLOCK` -> overall `BLOCK`/`DENY`
- `BLOCK` 없음 + `PENDING_REVIEW` 존재 -> overall `PENDING_REVIEW`/`REVIEW_REQUIRED`
- config `auto_map`이 참조한 `.py`가 code validator로 연결됨
- 참조 code `BLOCK`이면 config와 overall이 `BLOCK`
- 참조 code `PENDING_REVIEW`이면 config와 overall이 `PENDING_REVIEW`
- `stop_on_first_block = true`일 때 이후 dispatch 중단
- `PREPROCESSING` artifact가 자동 승인되지 않고 pending/skipped로 남음

## 완료 기준

- proxy 없이 analyzer 단위 통합 테스트가 가능하다.
- config -> code 라우팅이 end-to-end로 확인된다.
- 파일별 `ArtifactValidationResult`가 `ValidationJobResponse`로 조립된다.
- job-level 상태값이 인터페이스 정의서와 일치한다.

## 다음 단계 연결

단계 7은 proxy smoke endpoint를 선택적으로 연결한다. 단계 6이 끝나면 proxy는 검증 로직을 소유하지 않고 orchestrator를 호출하는 얇은 진입점으로만 구현할 수 있다.
