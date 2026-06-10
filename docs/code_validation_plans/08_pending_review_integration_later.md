# 단계 8 - Pending Review Integration Later

## 목적

미등록 API와 B-2/C 결과를 whitelist/review 담당 모듈이 처리할 수 있도록 연결 구조를 정한다. 코드검증은 `pending_api_refs`와 review finding을 `details`에 안정적으로 남기고, 영속 저장과 승인 workflow는 `whitelist` 모듈이 처리한다.

## 구현 반영 상태 (2026-05-22)

- 상태: 완료. 코드검증은 미등록 API와 리뷰 필요 근거를 `pending_api_refs` 및 `review_findings`로 남기고, whitelist 모듈은 pending store, review, audit, feedback, dashboard를 제공한다.
- 경계: code validator는 운영 저장소를 직접 호출하지 않는다. `whitelist.integration`과 router/API 계층이 pending upsert와 review 상태 전환을 담당한다.

## 담당 범위

코드검증이 직접 구현하는 최소 범위:

- `pending_api_refs` 후보 생성
- 미등록 API의 callsite, namespace, risk keyword, reason code 기록
- context analyzer `review` 결과의 evidence 기록
- B-2/C artifact에 리뷰 보조용 finding 목록 기록
- `WhitelistLookup` protocol을 통해 정식 whitelist engine 교체 지점 확보
- in-memory adapter로 테스트 가능한 구조 유지

## 비범위

- code validator 내부에서 persistent pending store 직접 호출
- code validator 내부에서 보안 담당자 workflow 처리
- code validator 내부에서 whitelist DB 업데이트
- LLM을 승인 판단자로 사용하는 구조

## 입력

- `ApiScanResult.unregistered`
- `ApiScanResult.pending_api_refs`
- `ContextApiScanResult` 중 `decision = review`
- `GradeResult` 중 `B-2` 또는 `C`
- `ArtifactRef`
- `ModelRef`, `job_id`, `request_id`

## 출력

`ArtifactValidationResult.details`에 남길 최소 구조:

- `pending_api_refs`
  - `api_path`
  - `callsite`
  - `namespace`
  - `risk_keywords`
  - `matched_namespace_rule`
  - `reason_code`
- `review_findings`
  - `finding_type`
  - `severity`
  - `reason_code`
  - `evidence`
  - `suggested_review_action`
- `review_queue_entry_id`: 정식 리뷰 큐가 없으면 `null`

whitelist/review 모듈이 생성/관리하는 구조:

- `PendingApiRecord`
- `PendingApiUpsertRequest`
- `ReviewQueueEntry`
- `ReviewDecisionResult`

## 생성/수정 파일

문서 분리 작업에서 생성하는 파일:

- `docs/code_validation_plans/08_pending_review_integration_later.md`

선행 구현에서 생성/수정할 수 있는 파일:

- `analyzer/validators/code_api.py`
- `analyzer/validators/code_validator.py`
- `tests/test_code_api.py`
- `tests/test_code_validator.py`

whitelist/review 담당 모듈에서 생성/수정한 파일:

- `whitelist/pending_store.py`
- `tests/test_pending_store.py`
- `tests/test_whitelist_engine.py`

## 구현 규칙

- 미등록 API는 자동 승인하지 않고 `B-2/PENDING_REVIEW`로 남긴다.
- `pending_api_refs`는 연결용 최소 구조이며 persistent pending store가 아니다.
- `PendingApiRecord.auto_classification`이 `AUTO_APPROVE` 권고로 나오더라도 실제 whitelist 반영은 `review_status = APPROVED` 이후에만 가능하다.
- LLM은 승인 판단자가 아니라 리뷰 설명 보조기로만 사용할 수 있다.
- 코드검증은 정식 DB를 직접 조작하지 않고 protocol/adapter 경계까지만 담당한다.
- review queue id가 아직 없으면 `review_queue_entry_id = null`로 둔다.
- B-2/C 후보를 sandbox에서 실행하더라도 그 결과는 자동 승인 증명이 아니라 리뷰 evidence다.
- 명확한 위험 API가 있는 파일은 pending/review로 미루지 않고 즉시 `BLOCK`한다.

## 테스트

선행 구현에서 추가할 pytest:

- `tests/test_code_api.py`
- `tests/test_code_validator.py`

whitelist/review 통합에서 유지할 pytest:

- `tests/test_pending_store.py`
- `tests/test_whitelist_engine.py`

핵심 케이스:

- `torch.special.expit` 같은 미등록 API가 `pending_api_refs`에 기록
- risk keyword가 있는 API가 `risk_keywords`에 기록
- context `review` 결과가 `review_findings`에 기록
- B-2 result가 `SECURITY_OWNER_GATE`와 pending detail을 포함
- C result가 `MANUAL_REVIEW_REQUIRED`와 finding detail을 포함
- 같은 API를 여러 번 발견했을 때 persistent store는 seen count와 last_seen_at을 갱신
- `torch.load` 같은 위험 API는 pending이 아니라 `BLOCK`

## 완료 기준

- 코드검증 결과만 보고 후속 whitelist/review 담당자가 어떤 API와 artifact를 검토해야 하는지 알 수 있다.
- 코드검증은 정식 pending store를 직접 호출하지 않는다.
- `pending_api_refs`와 `review_findings`가 `ArtifactValidationResult.details`에 안정적으로 남는다.
- 운영용 review queue가 없어도 테스트 가능한 in-memory 흐름이 있다.

## 다음 단계 연결

whitelist/review 담당 모듈은 `pending_api_refs`를 `PendingApiRecord` 또는 upsert 요청으로 변환하고, B-2/C artifact finding을 review/audit 흐름에 연결한다. 리뷰 결과가 승인되면 whitelist engine이 정책 버전을 갱신하고, 이후 재검증에서 코드검증은 새 `WhitelistLookup` 결과를 입력으로 받는다.
