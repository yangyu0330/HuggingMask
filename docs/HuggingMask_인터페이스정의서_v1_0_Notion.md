# HuggingMask 인터페이스 정의서 v1.0  
_Notion 업로드용 / 구현 기준 문서_

## 문서 정보

- 문서명: HuggingMask 인터페이스 정의서
- 버전: v1.0
- 상태: Freeze Candidate
- 적용 범위: 박용담 파일분류/JSON/config/tokenizer, 정은미 가중치검증경로, 양유상 코드검증경로, 김민우 적응형 화이트리스트 엔진, Proxy 후순위 진입점
- 인터페이스 기준: 코드 제작 착수 전 고정
- 변경 정책: 공통 JSON 계약 변경은 팀장 승인 + 영향 모듈 담당자 동의 후 진행
- 비고: 이 문서는 구현 편의를 위해 기존 계획서/상세설계 문서의 요구사항을 **실행 가능한 JSON 계약 형태**로 재구성한 통합 문서다.

---

## 1. 문서 목적

이 문서는 HuggingMask의 모듈 간 계약을 고정하기 위한 기준 문서다.  
정의 대상은 다음 네 가지다.

1. 모듈 간 **입력/출력(JSON) 스키마**
2. 파일 유형별 **판정 규칙과 상태값**
3. Pending / 승인 / 배포 / 감사 로그까지 이어지는 **운영 흐름**
4. 구현 시 흔들리기 쉬운 **공통 규칙(해시, 시간, 버전, 캐시, 오류 구조)**

이 문서의 목표는 **각 모듈 담당자가 서로 내부 구현을 몰라도 연결 가능하도록 만드는 것**이다.

---

## 2. 시스템 범위

### 2.1 전체 흐름

1. 박용담이 fixture 또는 모델 저장소 파일 목록을 받아 파일을 분류하고 `ArtifactRef`를 만든다.
2. 박용담이 `ValidationJobRequest`와 공통 JSON 계약을 검증한다.
3. 박용담이 `config.json`과 `tokenizer_config.json`을 1차 검증한다.
4. 정은미가 safetensors/pickle 등 가중치 검증 경로를 실행한다.
5. 양유상이 Python 코드 검증 경로와 config가 참조한 `.py` 파일 검증을 실행한다.
6. 양유상의 코드 검증 중 API 판정이 필요하면 김민우의 Whitelist Engine에 질의한다.
7. 김민우가 미등록 API를 Pending List에 등록하거나 갱신한다.
8. 박용담이 정은미/양유상/김민우 결과를 종합해 `ValidationJobResponse`를 만든다.
9. Proxy는 후순위로 두며, 나중에 박용담 기준의 orchestrator를 호출하는 진입점으로 연결한다.

### 2.2 모듈 경계

| 모듈 | 책임 | 입력 | 출력 | 담당 |
|---|---|---|---|---|
| Analyzer Core | 파일 분류, JSON 계약 검증, `ArtifactRef` 생성, 최종 응답 조립 | 파일 목록, 정책 정보, 정은미/양유상/김민우 결과 | ValidationJobRequest, ValidationJobResponse | 박용담 |
| Config / Tokenizer Validator | `config.json`, `tokenizer_config.json` 1차 검증, 참조 `.py` 코드 검증 재라우팅 | config/tokenizer artifact | ConfigValidationResult, 추가 code job | 박용담 + 양유상 |
| Weight Validator | safetensors / pickle Path A / pickle Path B 검증 | 가중치 artifact | ArtifactValidationResult | 정은미 |
| Code Validator | 검증1(`CODE_AST_SCAN`), 검증2(`CODE_RESTRICTED_RUNTIME`), 검증3(`CODE_SANDBOX_RUNTIME`) | Python artifact, whitelist 결과 | ArtifactValidationResult | 양유상 |
| Whitelist Engine | API 허용 여부 확인, Pending List 등록/갱신, 리뷰 반영 | API 목록, 미등록 API, 리뷰 결정 | WhitelistCheckResponse, PendingApiRecord, ReviewDecisionResult | 김민우 |
| Proxy | 후순위 FastAPI 진입점, analyzer orchestrator 호출 | 외부 요청 | ValidationJobResponse | 공통 |

### 2.3 내부 API 엔드포인트 계약 (v1.0)

> 구현체는 REST/Message Queue 중 하나를 선택할 수 있지만, **payload 스키마와 상태값은 본 문서를 반드시 준수**한다.

| 제공 모듈 | Method | Path | Request | Response | 비고 |
|---|---|---|---|---|---|
| Analyzer Core | `POST` | `/internal/v1/validation/jobs` | `ValidationJobRequest` | `ValidationJobResponse` | 후순위 Proxy가 호출 |
| Code Validator | `POST` | `/internal/v1/whitelist/check` | `WhitelistCheckRequest` | `WhitelistCheckResponse[]` | AST 결과 API 목록 조회 |
| Whitelist Engine | `POST` | `/internal/v1/pending/upsert` | `PendingApiUpsertRequest` | `PendingApiRecord` | 미등록 API 등록/갱신 |
| Review Gate | `POST` | `/internal/v1/reviews/decide` | `ReviewDecisionRequest` | `ReviewDecisionResult` | 보안 담당자 판단 반영 |
| Analyzer Core | `POST` | `/internal/v1/reports` | `ValidationReport` | `{report_id, report_path}` | 검증 리포트 저장 |
| Governance | `POST` | `/internal/v1/mlbom` | `MLBOM` | `{mlbom_id}` | ML-BOM 저장 |
| Governance | `POST` | `/internal/v1/audit/events` | `AuditEvent` | `{event_id, event_hash}` | append-only 감사 로그 |
| Proxy | `POST` | `/internal/v1/approvals` | `ApprovalPackage` | `{release_ids, cache_keys}` | 후순위 승인 결과물 배포/캐시 반영 |

### 2.4 전송/재시도 규칙

- 전송 포맷: `application/json; charset=utf-8`
- 공통 헤더: `X-Request-Id`, `X-Job-Id`, `X-Schema-Version`
- 타임아웃 기본값:
  - `validation/jobs`: 120s
  - `whitelist/check`, `pending/upsert`: 10s
  - `reviews/decide`: 30s
  - `reports`, `mlbom`, `audit/events`, `approvals`: 15s
- 재시도 규칙:
  - `retryable=true`인 오류만 지수 백오프(최대 3회) 재시도
  - `reviews/decide`는 중복 승인 방지를 위해 `review_id` 기준 멱등 처리
  - `audit/events`는 `event_id` 기준 중복 쓰기 금지

---

## 3. 공통 설계 원칙

### 3.1 절대 규칙

1. **최종 배포는 항상 Path A 결과물만 사용한다.**
2. **dangerous import / dangerous call / dangerous API는 즉시 BLOCK한다.**
3. **미등록 API는 무조건 B-2로 라우팅한다.**
4. **동적/난독화 패턴은 C로 분류한다.**
5. **config의 코드 실행 트리거 필드는 반드시 `.py` 코드 검증 경로를 강제 호출한다.**
6. **검증 리포트에는 스캔 결과, 등급, 해시, 타임스탬프, 승인/차단 사유가 남아야 한다.**
7. **캐시는 정책 버전까지 포함해 검증해야 하며, 정책 변경 시 재검증한다.**

### 3.2 구현 원칙

- JSON 인코딩은 UTF-8
- 시간은 RFC3339 UTC 문자열
- 해시는 소문자 64자리 SHA256 hex
- enum 값은 문자열로 저장
- 필수 배열은 빈 배열이어도 **필드 자체는 생략하지 않음**
- 없음은 빈 문자열이 아니라 `null`
- 파일 경로는 저장소 기준 **POSIX 상대경로**
- review queue에 들어가는 모든 항목은 `reason_codes`를 반드시 가져야 함

---

## 4. 공통 식별자 및 버전 규칙

| 필드 | 타입 | 예시 | 규칙 |
|---|---|---|---|
| `schema_version` | string | `"1.0"` | 문서/응답 스키마 버전 |
| `request_id` | string | `"0c7d3f5a-0f86-4f8d-a9df-8c0c315e7284"` | 외부 요청 단위 UUIDv4 |
| `job_id` | string | `"9a7675b3-c726-45c8-9dae-98e5a6df7da2"` | 검증 배치 단위 UUIDv4 |
| `artifact_id` | string | `"sha256:8d2a..."` | `sha256:<hex>` 고정 |
| `report_id` | string | `"vr_2026_04_20_001"` | 검증 리포트 ID |
| `review_id` | string | `"rev_2026_04_20_003"` | 리뷰 판단 ID |
| `event_id` | string | `"evt_2026_04_20_1001"` | 감사 로그 이벤트 ID |
| `policy_version` | string | `"policy-2026.04.20"` | 전체 정책 묶음 버전 |
| `whitelist_version` | string | `"wl-2026.04.20"` | 화이트리스트 버전 |
| `opcode_policy_version` | string | `"opcode-2026.04.20"` | pickle opcode 정책 버전 |
| `config_schema_version` | string | `"cfg-2026.04.20"` | config 검증 스키마 버전 |
| `runtime_profile_version` | string | `"rt-2026.04.20"` | 샌드박스/제한 런타임 프로파일 버전 |

### 4.1 정책 fingerprint 규칙

캐시와 재검증은 다음 문자열을 기준으로 판단한다.

```text
policy_fingerprint =
  policy_version + "|" +
  whitelist_version + "|" +
  opcode_policy_version + "|" +
  config_schema_version + "|" +
  runtime_profile_version
```

### 4.2 캐시 키 규칙

```text
cache_key = sha256 + ":" + file_kind + ":" + policy_fingerprint
```

같은 파일이어도 정책이 바뀌면 캐시 재사용 금지다.

---

## 5. 공통 enum 정의

### 5.1 FileKind

| 값 | 의미 |
|---|---|
| `SAFETENSORS` | `.safetensors` |
| `PICKLE` | `.pkl`, `.pt`, `.bin` 등 pickle 계열 |
| `PYTHON` | `.py` |
| `CONFIG_JSON` | `config.json` |
| `TOKENIZER_CONFIG_JSON` | `tokenizer_config.json` |
| `OTHER` | 지원 범위 외 |

### 5.2 ValidationStatus

| 값 | 의미 |
|---|---|
| `PASS` | 자동 통과 |
| `BLOCK` | 즉시 차단 |
| `PENDING_REVIEW` | 자동 승인 불가, 리뷰 필요 |
| `ERROR` | 인프라/실행 오류 |
| `SKIPPED` | 해당 경로 실행 안 함 |

### 5.3 ReviewAction

| 값 | 의미 |
|---|---|
| `NONE` | 추가 액션 없음 |
| `AUTO_APPROVE` | 자동 승인 |
| `AUTO_APPROVE_REGENERATED` | 재생성 결과물 기준 자동 승인 |
| `SECURITY_OWNER_GATE` | 보안 담당자 게이트 필요 |
| `MANUAL_REVIEW_REQUIRED` | 사람의 수동 리뷰 필요 |
| `BLOCK_IMMEDIATELY` | 즉시 차단 |
| `AUTO_LOG_REVIEW` | 로그 자동 생성 + 리뷰 큐 등록 |

### 5.4 CodeGrade

| 값 | 의미 |
|---|---|
| `A` | 설정성 코드, AST 재생성 가능 |
| `B-1` | 정형 모델 코드, 허용 API만 사용 |
| `B-2` | 정형 구조지만 미등록 API 포함 |
| `C` | 동적/난독화/비정형 |
| `N/A` | 코드 파일 아님 |

### 5.5 PendingClassification

| 값 | 의미 |
|---|---|
| `AUTO_APPROVE` | 안전 namespace 기반 자동 승인 권고 |
| `CONDITIONAL` | 조건부 승인 권고 |
| `MANUAL` | 수동 검토 필요 |
| `BLOCKED` | 위험 API로 즉시 차단 |

### 5.6 ReviewStatus

| 값 | 의미 |
|---|---|
| `PENDING` | 리뷰 대기 |
| `UNDER_REVIEW` | 검토 중 |
| `APPROVED` | 승인됨 |
| `REJECTED` | 거부됨 |
| `DEFERRED` | 보류됨 |

### 5.7 RouteKind

| 값 | 의미 |
|---|---|
| `SAFETENSORS_FAST_PATH` | safetensors 경량 검증 |
| `PICKLE_PATH_A` | opcode 기반 안전 파서 |
| `PICKLE_PATH_B` | gVisor/Docker 샌드박스 |
| `CODE_AST_SCAN` | AST 구조 분석 |
| `CODE_RESTRICTED_RUNTIME` | B-1 제한 런타임 |
| `CODE_SANDBOX_RUNTIME` | B-2/C 샌드박스 |
| `CONFIG_SCHEMA_VALIDATION` | config 스키마 검증 |

### 5.8 OverallDecision

| 값 | 의미 |
|---|---|
| `APPROVE` | 전체 승인 |
| `APPROVE_WITH_TRANSFORM` | 변환/재생성 결과물로 승인 |
| `DENY` | 전체 차단 |
| `REVIEW_REQUIRED` | 전체 수동 리뷰 필요 |
| `ERROR` | 시스템 오류 |

---

## 6. 공통 reason code 정의

아래 reason code는 구현 전부가 공통으로 사용한다.

| 코드 | 설명 |
|---|---|
| `CACHE_HIT` | 동일 fingerprint 캐시 적중 |
| `UNKNOWN_FILE_TYPE` | 지원하지 않는 파일 유형 |
| `SAFE_TENSORS_HASH_OK` | safetensors 해시 확인 성공 |
| `SAFE_TENSORS_METADATA_INVALID` | safetensors 메타데이터 실패 |
| `PICKLE_OPCODE_ALLOWED_ONLY` | 허용 opcode만 존재 |
| `PICKLE_OPCODE_BLOCKED` | 금지 opcode 탐지 |
| `PICKLE_PATH_B_SYSCALL_ANOMALY` | 샌드박스 이상 syscall 탐지 |
| `PICKLE_PATH_AB_MISMATCH` | Path A/B 결과 불일치 |
| `DANGEROUS_IMPORT` | 위험 import 탐지 |
| `DANGEROUS_CALL` | eval/exec/open/__import__ 등 위험 호출 |
| `DANGEROUS_API` | torch.load/pickle.load/numpy.load 등 위험 API |
| `OBFUSCATION_PATTERN` | chr/ord/bytes.decode 등 난독화 |
| `DYNAMIC_PATTERN` | getattr/type/조건부 import 등 동적 패턴 |
| `UNREGISTERED_API` | 화이트리스트 미등록 API |
| `GRADE_A_REGENERATED` | 등급 A 재생성 성공 |
| `GRADE_B1_RUNTIME_OK` | B-1 제한 런타임 성공 |
| `GRADE_B2_GATE_REQUIRED` | B-2 보안 담당자 게이트 필요 |
| `GRADE_C_MANUAL_REVIEW` | C 수동 리뷰 필요 |
| `CONFIG_TRIGGER_FIELD_FOUND` | auto_map/custom_pipelines/trust_remote_code 탐지 |
| `CONFIG_REFERENCED_CODE_ROUTED` | 참조 코드 파일 검증 경로 연결 |
| `POLICY_VERSION_CHANGED` | 정책 변경으로 캐시 무효화 |
| `REVIEW_APPROVED` | 리뷰 승인 |
| `REVIEW_REJECTED` | 리뷰 거부 |
| `AUDIT_LOG_WRITTEN` | 감사 로그 기록 완료 |
| `MLBOM_GENERATED` | ML-BOM 생성 완료 |

---

## 7. 공통 객체 정의

## 7.1 `ModelRef`

| 필드 | 타입 | 필수 | 설명 |
|---|---|---|---|
| `repo_id` | string | Y | 예: `meta-llama/Llama-3-8B` |
| `revision` | string | Y | commit sha / tag / branch |
| `source_host` | string | Y | 예: `huggingface.co` |
| `source_url` | string | Y | 원본 모델 URL |
| `requested_by` | string | N | 호출 사용자/서비스 ID |
| `requested_at` | string | Y | RFC3339 UTC |
| `endpoint_mode` | string | Y | `HF_ENDPOINT_PROXY` 고정 |

### 예시

```json
{
  "repo_id": "meta-llama/Llama-3-8B",
  "revision": "main",
  "source_host": "huggingface.co",
  "source_url": "https://huggingface.co/meta-llama/Llama-3-8B",
  "requested_by": "developer-a",
  "requested_at": "2026-04-20T09:00:00Z",
  "endpoint_mode": "HF_ENDPOINT_PROXY"
}
```

---

## 7.2 `ArtifactRef`

| 필드 | 타입 | 필수 | 설명 |
|---|---|---|---|
| `artifact_id` | string | Y | `sha256:<hex>` |
| `repo_path` | string | Y | 저장소 기준 상대경로 |
| `file_name` | string | Y | 파일명 |
| `file_kind` | string(enum) | Y | `FileKind` |
| `detected_extension` | string | Y | 예: `.safetensors` |
| `media_type` | string | N | MIME type |
| `size_bytes` | integer | Y | 파일 크기 |
| `sha256` | string | Y | 원본 파일 SHA256 |
| `source_url` | string | Y | 원본 다운로드 URL |
| `temp_local_path` | string | Y | 프록시/분석 엔진의 임시 로컬 경로 |
| `referenced_by` | array[string] | Y | config가 참조하면 그 파일명 |
| `is_generated` | boolean | Y | 변환/재생성 산출물 여부 |

### 예시

```json
{
  "artifact_id": "sha256:2c1c7d10d4f8c0a1175b3b733d3c62b8a2f...",
  "repo_path": "model.safetensors",
  "file_name": "model.safetensors",
  "file_kind": "SAFETENSORS",
  "detected_extension": ".safetensors",
  "media_type": "application/octet-stream",
  "size_bytes": 523456789,
  "sha256": "2c1c7d10d4f8c0a1175b3b733d3c62b8a2f...",
  "source_url": "https://huggingface.co/org/model/resolve/main/model.safetensors",
  "temp_local_path": "/tmp/jobs/9a7675/model.safetensors",
  "referenced_by": [],
  "is_generated": false
}
```

---

## 7.3 `PolicyInfo`

| 필드 | 타입 | 필수 | 설명 |
|---|---|---|---|
| `policy_version` | string | Y | 전체 정책 버전 |
| `whitelist_version` | string | Y | API 화이트리스트 버전 |
| `opcode_policy_version` | string | Y | pickle opcode 버전 |
| `config_schema_version` | string | Y | config schema 버전 |
| `runtime_profile_version` | string | Y | runtime profile 버전 |
| `policy_fingerprint` | string | Y | 4.1 규칙 적용 값 |

### 예시

```json
{
  "policy_version": "policy-2026.04.20",
  "whitelist_version": "wl-2026.04.20",
  "opcode_policy_version": "opcode-2026.04.20",
  "config_schema_version": "cfg-2026.04.20",
  "runtime_profile_version": "rt-2026.04.20",
  "policy_fingerprint": "policy-2026.04.20|wl-2026.04.20|opcode-2026.04.20|cfg-2026.04.20|rt-2026.04.20"
}
```

---

## 7.4 `ReasonEntry`

| 필드 | 타입 | 필수 | 설명 |
|---|---|---|---|
| `code` | string | Y | `reason code` |
| `severity` | string | Y | `INFO`, `WARN`, `HIGH`, `CRITICAL` |
| `message` | string | Y | 사람이 읽는 설명 |
| `evidence` | array[string] | Y | 탐지 근거 (opcode 이름, API 경로, 필드명 등) |
| `review_required` | boolean | Y | 리뷰 필요 여부 |

### 예시

```json
{
  "code": "UNREGISTERED_API",
  "severity": "HIGH",
  "message": "화이트리스트에 없는 API가 탐지되어 B-2로 분류됨",
  "evidence": ["torch.nn.functional.scaled_dot_product_attention"],
  "review_required": true
}
```

---

## 7.5 `RuntimeContext`

| 필드 | 타입 | 필수 | 설명 |
|---|---|---|---|
| `sandbox_runtime` | string | Y | `gvisor` 또는 `docker_seccomp` |
| `network_disabled` | boolean | Y | 샌드박스 네트워크 차단 여부 |
| `read_only_fs` | boolean | Y | 읽기 전용 FS 여부 |
| `compare_mode` | string | Y | `TORCH_ALLCLOSE_THEN_SHA256` |
| `allow_cache_lookup` | boolean | Y | 캐시 조회 허용 |
| `generate_mlbom` | boolean | Y | ML-BOM 생성 여부 |
| `write_audit_log` | boolean | Y | 감사 로그 작성 여부 |

---

## 8. 상위 배치 인터페이스

## 8.1 `ValidationJobRequest`  
_Proxy → Validation Engine_

| 필드 | 타입 | 필수 | 설명 |
|---|---|---|---|
| `schema_version` | string | Y | `"1.0"` |
| `request_id` | string | Y | 외부 요청 ID |
| `job_id` | string | Y | 검증 배치 ID |
| `model` | object(`ModelRef`) | Y | 모델 식별 정보 |
| `policy` | object(`PolicyInfo`) | Y | 정책 버전 |
| `runtime_context` | object(`RuntimeContext`) | Y | 실행 프로파일 |
| `artifacts` | array[`ArtifactRef`] | Y | 다운로드된 파일 목록 |
| `requested_routes` | array[string] | Y | 사전 지정 경로가 있으면 명시 |
| `stop_on_first_block` | boolean | Y | true면 즉시 중단 |
| `notes` | string/null | N | 임시 메모 |

### 예시

```json
{
  "schema_version": "1.0",
  "request_id": "0c7d3f5a-0f86-4f8d-a9df-8c0c315e7284",
  "job_id": "9a7675b3-c726-45c8-9dae-98e5a6df7da2",
  "model": {
    "repo_id": "org/demo-model",
    "revision": "main",
    "source_host": "huggingface.co",
    "source_url": "https://huggingface.co/org/demo-model",
    "requested_by": "developer-a",
    "requested_at": "2026-04-20T09:00:00Z",
    "endpoint_mode": "HF_ENDPOINT_PROXY"
  },
  "policy": {
    "policy_version": "policy-2026.04.20",
    "whitelist_version": "wl-2026.04.20",
    "opcode_policy_version": "opcode-2026.04.20",
    "config_schema_version": "cfg-2026.04.20",
    "runtime_profile_version": "rt-2026.04.20",
    "policy_fingerprint": "policy-2026.04.20|wl-2026.04.20|opcode-2026.04.20|cfg-2026.04.20|rt-2026.04.20"
  },
  "runtime_context": {
    "sandbox_runtime": "gvisor",
    "network_disabled": true,
    "read_only_fs": true,
    "compare_mode": "TORCH_ALLCLOSE_THEN_SHA256",
    "allow_cache_lookup": true,
    "generate_mlbom": true,
    "write_audit_log": true
  },
  "artifacts": [
    {
      "artifact_id": "sha256:2c1c7d10...",
      "repo_path": "model.safetensors",
      "file_name": "model.safetensors",
      "file_kind": "SAFETENSORS",
      "detected_extension": ".safetensors",
      "media_type": "application/octet-stream",
      "size_bytes": 523456789,
      "sha256": "2c1c7d10...",
      "source_url": "https://huggingface.co/org/demo-model/resolve/main/model.safetensors",
      "temp_local_path": "/tmp/jobs/9a7675/model.safetensors",
      "referenced_by": [],
      "is_generated": false
    }
  ],
  "requested_routes": [],
  "stop_on_first_block": false,
  "notes": null
}
```

---

## 8.2 `ValidationJobResponse`  
_Validation Engine → Proxy_

| 필드 | 타입 | 필수 | 설명 |
|---|---|---|---|
| `schema_version` | string | Y | `"1.0"` |
| `request_id` | string | Y | 요청 ID |
| `job_id` | string | Y | 검증 ID |
| `overall_decision` | string(enum) | Y | `OverallDecision` |
| `overall_status` | string(enum) | Y | `PASS`, `BLOCK`, `PENDING_REVIEW`, `ERROR` |
| `release_action` | string | Y | `CACHE_RETURN`, `APPROVE_AND_STORE`, `DENY`, `REVIEW_QUEUE` |
| `artifact_results` | array[`ArtifactValidationResult`] | Y | 파일별 결과 |
| `approved_artifact_ids` | array[string] | Y | 승인 artifact |
| `blocked_artifact_ids` | array[string] | Y | 차단 artifact |
| `pending_artifact_ids` | array[string] | Y | 리뷰 대상 artifact |
| `generated_artifacts` | array[`ArtifactRef`] | Y | 변환/재생성 결과 |
| `report_id` | string | Y | 검증 리포트 ID |
| `report_path` | string | Y | 저장된 report 경로 |
| `reason_entries` | array[`ReasonEntry`] | Y | 전체 요약 사유 |
| `created_at` | string | Y | RFC3339 UTC |

### overall status 계산 규칙

1. `artifact_results` 중 하나라도 `BLOCK`이면 전체는 `BLOCK`
2. `BLOCK`이 없고 하나라도 `PENDING_REVIEW`면 전체는 `PENDING_REVIEW`
3. 모든 artifact가 `PASS`면 전체는 `PASS`
4. 인프라 실패가 있고 안전한 fallback이 없으면 `ERROR`

---

## 9. 파일별 결과 공통 인터페이스

## 9.1 `ArtifactValidationResult`

| 필드 | 타입 | 필수 | 설명 |
|---|---|---|---|
| `artifact` | object(`ArtifactRef`) | Y | 대상 파일 |
| `route_kind` | string(enum) | Y | 주 경로 |
| `status` | string(enum) | Y | `ValidationStatus` |
| `grade` | string(enum) | Y | `CodeGrade` 또는 `N/A` |
| `review_action` | string(enum) | Y | `ReviewAction` |
| `cache_key` | string | Y | 계산된 캐시 키 |
| `cache_hit` | boolean | Y | 캐시 적중 여부 |
| `reason_entries` | array[`ReasonEntry`] | Y | 상세 사유 |
| `details` | object | Y | 유형별 상세 구조 |
| `started_at` | string | Y | 시작 시각 |
| `finished_at` | string | Y | 종료 시각 |

---

## 10. safetensors 결과 스키마

## 10.1 `SafeTensorsResultDetail`

| 필드 | 타입 | 필수 | 설명 |
|---|---|---|---|
| `route_kind` | string | Y | `SAFETENSORS_FAST_PATH` |
| `hash_verified` | boolean | Y | SHA256 확인 여부 |
| `metadata_schema_valid` | boolean | Y | 메타데이터 스키마 통과 여부 |
| `checked_metadata_fields` | array[string] | Y | 검사한 필드 목록 |
| `output_artifact_id` | string | Y | 통상 input과 동일 |
| `final_release_source` | string | Y | `ORIGINAL_SAFETENSORS` |
| `metrics` | object | Y | 처리 시간, 바이트 등 |

### 판정 규칙

- 해시와 메타데이터가 모두 유효하면 `status = PASS`
- 하나라도 실패하면 `status = BLOCK`
- `grade = N/A`
- `review_action = NONE`

### 예시

```json
{
  "route_kind": "SAFETENSORS_FAST_PATH",
  "hash_verified": true,
  "metadata_schema_valid": true,
  "checked_metadata_fields": ["format", "dtype", "tensor_count"],
  "output_artifact_id": "sha256:2c1c7d10...",
  "final_release_source": "ORIGINAL_SAFETENSORS",
  "metrics": {
    "elapsed_ms": 143,
    "bytes_scanned": 523456789
  }
}
```

---

## 11. pickle 결과 스키마

## 11.1 `PickleValidationResultDetail`

| 필드 | 타입 | 필수 | 설명 |
|---|---|---|---|
| `path_a` | object | Y | 안전 파서 결과 |
| `path_b` | object | Y | 샌드박스 결과 |
| `compare_result` | object | Y | A/B 비교 결과 |
| `final_release_source` | string | Y | `PATH_A_ONLY` 고정 |
| `released_artifact_id` | string/null | Y | 최종 배포 artifact |
| `path_a_required` | boolean | Y | 항상 true |
| `path_b_enabled` | boolean | Y | gVisor 또는 Docker fallback 여부 |

### 11.2 `path_a` 상세

| 필드 | 타입 | 필수 | 설명 |
|---|---|---|---|
| `route_kind` | string | Y | `PICKLE_PATH_A` |
| `executed_user_code` | boolean | Y | 항상 false |
| `total_opcode_count` | integer | Y | 전체 opcode 수 |
| `allowed_opcode_count` | integer | Y | 허용 opcode 수 |
| `blocked_opcode_count` | integer | Y | 금지 opcode 수 |
| `blocked_opcodes` | array[string] | Y | 탐지된 금지 opcode |
| `converted_artifact_id` | string/null | Y | safetensors 변환 결과 |
| `status` | string(enum) | Y | `PASS`/`BLOCK`/`ERROR` |
| `reason_entries` | array[`ReasonEntry`] | Y | 상세 사유 |

### 11.3 `path_b` 상세

| 필드 | 타입 | 필수 | 설명 |
|---|---|---|---|
| `route_kind` | string | Y | `PICKLE_PATH_B` |
| `runtime` | string | Y | `gvisor` 또는 `docker_seccomp` |
| `network_disabled` | boolean | Y | 네트워크 차단 여부 |
| `read_only_fs` | boolean | Y | 읽기 전용 FS 여부 |
| `syscall_anomaly_detected` | boolean | Y | 이상 syscall 여부 |
| `logs_ref` | string/null | Y | strace/seccomp 로그 위치 |
| `converted_artifact_id` | string/null | Y | 샌드박스 변환 결과 |
| `status` | string(enum) | Y | `PASS`/`BLOCK`/`ERROR`/`SKIPPED` |
| `reason_entries` | array[`ReasonEntry`] | Y | 상세 사유 |

### 11.4 `compare_result` 상세

| 필드 | 타입 | 필수 | 설명 |
|---|---|---|---|
| `allclose_passed` | boolean/null | Y | `torch.allclose` 비교 결과 |
| `sha256_match` | boolean/null | Y | 직렬화 후 해시 일치 여부 |
| `comparison_status` | string | Y | `MATCH`, `MISMATCH`, `NOT_APPLICABLE` |

### 판정 규칙

- Path A에서 금지 opcode가 탐지되면 **즉시 BLOCK**
- Path A가 실패하면 Path B가 성공해도 **배포 금지**
- 최종 배포 가능 조건:
  - Path A = PASS
  - Path B = PASS 또는 정책상 허용된 fallback
  - A/B 비교 결과가 일치
- `final_release_source`는 항상 `"PATH_A_ONLY"`

### 예시

```json
{
  "path_a": {
    "route_kind": "PICKLE_PATH_A",
    "executed_user_code": false,
    "total_opcode_count": 218,
    "allowed_opcode_count": 218,
    "blocked_opcode_count": 0,
    "blocked_opcodes": [],
    "converted_artifact_id": "sha256:converted_path_a_001",
    "status": "PASS",
    "reason_entries": [
      {
        "code": "PICKLE_OPCODE_ALLOWED_ONLY",
        "severity": "INFO",
        "message": "허용 opcode만 존재함",
        "evidence": [],
        "review_required": false
      }
    ]
  },
  "path_b": {
    "route_kind": "PICKLE_PATH_B",
    "runtime": "gvisor",
    "network_disabled": true,
    "read_only_fs": true,
    "syscall_anomaly_detected": false,
    "logs_ref": "/logs/jobs/9a7675/path_b.strace",
    "converted_artifact_id": "sha256:converted_path_b_001",
    "status": "PASS",
    "reason_entries": []
  },
  "compare_result": {
    "allclose_passed": true,
    "sha256_match": true,
    "comparison_status": "MATCH"
  },
  "final_release_source": "PATH_A_ONLY",
  "released_artifact_id": "sha256:converted_path_a_001",
  "path_a_required": true,
  "path_b_enabled": true
}
```

---

## 12. code 결과 스키마

## 12.1 `CodeValidationResultDetail`

| 필드 | 타입 | 필수 | 설명 |
|---|---|---|---|
| `ast_scan` | object | Y | AST 분석 결과 |
| `api_scan` | object | Y | API 화이트리스트 결과 |
| `grade_result` | object | Y | A/B-1/B-2/C 판정 |
| `runtime_check` | object | Y | 등급별 실행/샌드박스 결과 |
| `review_queue_entry_id` | string/null | Y | 리뷰 큐 등록 시 ID |
| `effective_output_artifact_id` | string/null | Y | 등급 A 재생성 결과 등 |

### 12.2 `ast_scan`

| 필드 | 타입 | 필수 | 설명 |
|---|---|---|---|
| `imports` | array[string] | Y | import 목록 |
| `dangerous_imports` | array[string] | Y | `os`, `subprocess`, `socket`, `requests` 등 |
| `dangerous_calls` | array[string] | Y | `eval`, `exec`, `open`, `__import__` 등 |
| `dynamic_patterns` | array[string] | Y | `getattr`, `type(3-arg)`, `conditional_import` |
| `obfuscation_patterns` | array[string] | Y | `chr`, `ord`, `bytes.decode` 체인 |
| `has_forward_method` | boolean | Y | `forward()` 존재 여부 |
| `inherits_pretrained_config` | boolean | Y | A 판정용 |
| `inherits_nn_module` | boolean | Y | B 계열 판정용 |

### 12.3 `api_scan`

| 필드 | 타입 | 필수 | 설명 |
|---|---|---|---|
| `used_apis` | array[string] | Y | 전체 추출 API |
| `allowed_apis` | array[string] | Y | 허용된 API |
| `blocked_apis` | array[string] | Y | 위험 API |
| `unregistered_apis` | array[string] | Y | 미등록 API |
| `whitelist_version` | string | Y | 사용 화이트리스트 버전 |
| `pending_api_refs` | array[string] | Y | pending 등록된 API 경로 |

### 12.4 `grade_result`

| 필드 | 타입 | 필수 | 설명 |
|---|---|---|---|
| `grade` | string(enum) | Y | `A`, `B-1`, `B-2`, `C` |
| `grade_reason` | string | Y | 등급 판정 요약 |
| `review_action` | string(enum) | Y | `ReviewAction` |
| `reason_codes` | array[string] | Y | 관련 reason code |

### 12.5 `runtime_check`

| 필드 | 타입 | 필수 | 설명 |
|---|---|---|---|
| `runtime_mode` | string | Y | `NONE`, `REGENERATE`, `RESTRICTED_RUNTIME`, `SANDBOX` |
| `builtins_removed` | array[string] | Y | 제한 런타임에서 제거된 builtins |
| `import_allowlist_applied` | boolean | Y | import 제한 적용 여부 |
| `dummy_forward_executed` | boolean | Y | B-1 더미 실행 여부 |
| `sandbox_runtime` | string/null | Y | B-2/C 샌드박스 |
| `syscall_anomaly_detected` | boolean/null | Y | 샌드박스 이상 탐지 |
| `logs_ref` | string/null | Y | 로그 위치 |
| `status` | string(enum) | Y | `PASS`, `BLOCK`, `PENDING_REVIEW`, `ERROR`, `SKIPPED` |

### 12.6 코드 등급별 고정 규칙

| 조건 | grade | status | review_action | runtime_mode |
|---|---|---|---|---|
| PretrainedConfig 상속 + 단순 속성 저장 + 실행 메서드 없음 | `A` | `PASS` | `AUTO_APPROVE_REGENERATED` | `REGENERATE` |
| `nn.Module`/`PreTrainedModel` + forward 존재 + 허용 API만 사용 + 동적 패턴 없음 | `B-1` | `PASS` | `AUTO_APPROVE` | `RESTRICTED_RUNTIME` |
| 정형 구조 + 미등록 API 존재 | `B-2` | `PENDING_REVIEW` | `SECURITY_OWNER_GATE` | `SANDBOX` |
| 동적/난독화/비정형 구조 | `C` | `PENDING_REVIEW` | `MANUAL_REVIEW_REQUIRED` | `SANDBOX` |
| 위험 import / 위험 call / 위험 API | `C` | `BLOCK` | `BLOCK_IMMEDIATELY` | `NONE` |

### 12.7 등급 판정 우선순위

다음 순서를 **반드시 고정**한다.

1. dangerous import / dangerous call / dangerous API → `BLOCK`
2. 동적/난독화 패턴 탐지 → `C`
3. 미등록 API 존재 → `B-2`
4. `forward()` 존재 + 허용 API만 사용 → `B-1`
5. `PretrainedConfig` 단순 설정 클래스 → `A`

### 예시

```json
{
  "ast_scan": {
    "imports": ["torch", "torch.nn", "torch.nn.functional"],
    "dangerous_imports": [],
    "dangerous_calls": [],
    "dynamic_patterns": [],
    "obfuscation_patterns": [],
    "has_forward_method": true,
    "inherits_pretrained_config": false,
    "inherits_nn_module": true
  },
  "api_scan": {
    "used_apis": [
      "torch.nn.Linear",
      "torch.nn.functional.relu",
      "torch.nn.functional.scaled_dot_product_attention"
    ],
    "allowed_apis": [
      "torch.nn.Linear",
      "torch.nn.functional.relu"
    ],
    "blocked_apis": [],
    "unregistered_apis": [
      "torch.nn.functional.scaled_dot_product_attention"
    ],
    "whitelist_version": "wl-2026.04.20",
    "pending_api_refs": [
      "torch.nn.functional.scaled_dot_product_attention"
    ]
  },
  "grade_result": {
    "grade": "B-2",
    "grade_reason": "정형 구조지만 미등록 API가 존재함",
    "review_action": "SECURITY_OWNER_GATE",
    "reason_codes": ["UNREGISTERED_API", "GRADE_B2_GATE_REQUIRED"]
  },
  "runtime_check": {
    "runtime_mode": "SANDBOX",
    "builtins_removed": [],
    "import_allowlist_applied": true,
    "dummy_forward_executed": false,
    "sandbox_runtime": "gvisor",
    "syscall_anomaly_detected": false,
    "logs_ref": "/logs/jobs/9a7675/code_b2.strace",
    "status": "PENDING_REVIEW"
  },
  "review_queue_entry_id": "rq_2026_04_20_001",
  "effective_output_artifact_id": null
}
```

---

## 13. config 결과 스키마

## 13.1 `ConfigValidationResultDetail`

| 필드 | 타입 | 필수 | 설명 |
|---|---|---|---|
| `route_kind` | string | Y | `CONFIG_SCHEMA_VALIDATION` |
| `schema_valid` | boolean | Y | config schema 통과 여부 |
| `trigger_fields_detected` | array[string] | Y | `auto_map`, `custom_pipelines`, `trust_remote_code` |
| `unknown_fields` | array[string] | Y | 허용 외 필드 |
| `referenced_python_files` | array[string] | Y | config가 참조한 `.py` 파일 |
| `rerouted_to_code_validation` | boolean | Y | 코드 검증 라우팅 여부 |
| `linked_code_artifact_ids` | array[string] | Y | 라우팅된 코드 artifact |
| `linked_code_statuses` | array[string] | Y | 해당 코드의 결과 상태 |
| `effective_status` | string(enum) | Y | config 최종 상태 |

### config 판정 규칙

| 조건 | config status |
|---|---|
| schema invalid | `BLOCK` |
| trigger field 없음 + schema valid | `PASS` |
| trigger field 있음 + 참조 코드 모두 PASS | `PASS` |
| trigger field 있음 + 참조 코드 중 PENDING_REVIEW 존재 | `PENDING_REVIEW` |
| trigger field 있음 + 참조 코드 중 BLOCK 존재 | `BLOCK` |

### 예시

```json
{
  "route_kind": "CONFIG_SCHEMA_VALIDATION",
  "schema_valid": true,
  "trigger_fields_detected": ["auto_map"],
  "unknown_fields": [],
  "referenced_python_files": ["modeling_custom.py"],
  "rerouted_to_code_validation": true,
  "linked_code_artifact_ids": ["sha256:py001"],
  "linked_code_statuses": ["PENDING_REVIEW"],
  "effective_status": "PENDING_REVIEW"
}
```

---

## 14. Whitelist 인터페이스

## 14.1 `WhitelistCheckRequest`  
_Validation Engine → Whitelist Engine_

| 필드 | 타입 | 필수 | 설명 |
|---|---|---|---|
| `schema_version` | string | Y | `"1.0"` |
| `request_id` | string | Y | 요청 ID |
| `job_id` | string | Y | 검증 ID |
| `model` | object(`ModelRef`) | Y | 모델 정보 |
| `apis` | array[string] | Y | 조회 대상 API 목록 |

### 예시

```json
{
  "schema_version": "1.0",
  "request_id": "0c7d3f5a-0f86-4f8d-a9df-8c0c315e7284",
  "job_id": "9a7675b3-c726-45c8-9dae-98e5a6df7da2",
  "model": {
    "repo_id": "org/demo-model",
    "revision": "main",
    "source_host": "huggingface.co",
    "source_url": "https://huggingface.co/org/demo-model",
    "requested_by": "developer-a",
    "requested_at": "2026-04-20T09:00:00Z",
    "endpoint_mode": "HF_ENDPOINT_PROXY"
  },
  "apis": [
    "torch.nn.Linear",
    "torch.load",
    "torch.nn.functional.scaled_dot_product_attention"
  ]
}
```

---

## 14.2 `WhitelistCheckResponse`

| 필드 | 타입 | 필수 | 설명 |
|---|---|---|---|
| `api_path` | string | Y | API 전체 경로 |
| `status` | string | Y | `ALLOWED`, `BLOCKED`, `UNKNOWN`, `PENDING` |
| `matched_rule` | string/null | Y | 예: `torch.nn.*` |
| `source` | string | Y | `INITIAL`, `AUTO_CRAWL`, `MANUAL_REVIEW` |
| `whitelist_version` | string | Y | 사용 버전 |
| `review_required` | boolean | Y | 추가 리뷰 필요 여부 |
| `reason` | string | Y | 사람이 읽는 설명 |

### 예시

```json
[
  {
    "api_path": "torch.nn.Linear",
    "status": "ALLOWED",
    "matched_rule": "torch.nn.*",
    "source": "INITIAL",
    "whitelist_version": "wl-2026.04.20",
    "review_required": false,
    "reason": "초기 화이트리스트 허용 규칙 일치"
  },
  {
    "api_path": "torch.load",
    "status": "BLOCKED",
    "matched_rule": null,
    "source": "INITIAL",
    "whitelist_version": "wl-2026.04.20",
    "review_required": false,
    "reason": "명시적 위험 API"
  },
  {
    "api_path": "torch.nn.functional.scaled_dot_product_attention",
    "status": "UNKNOWN",
    "matched_rule": null,
    "source": "N/A",
    "whitelist_version": "wl-2026.04.20",
    "review_required": true,
    "reason": "미등록 API"
  }
]
```

---

## 15. Pending API 인터페이스

## 15.1 `PendingApiRecord`

| 필드 | 타입 | 필수 | 설명 |
|---|---|---|---|
| `api_path` | string | Y | 미등록 API 전체 경로 |
| `first_seen_at` | string | Y | 최초 탐지 시각 |
| `last_seen_at` | string | Y | 마지막 탐지 시각 |
| `seen_count` | integer | Y | 누적 탐지 횟수 |
| `auto_classification` | string(enum) | Y | `PendingClassification` |
| `verified_org_count` | integer | Y | Verified Org 사용 수 |
| `verified_org_list` | array[string] | Y | 조직 목록 |
| `in_official_docs` | boolean | Y | 공식 문서 등재 여부 |
| `review_status` | string(enum) | Y | `ReviewStatus` |
| `model_list` | array[string] | Y | 사용 모델 목록 |
| `risk_keywords` | array[string] | Y | `load`, `file_path` 등 |
| `matched_namespace_rule` | string/null | Y | 분류 근거 namespace |
| `documentation_url` | string/null | Y | 공식 문서 링크 |
| `sample_callsites` | array[string] | Y | 사용 예시 |
| `created_from_job_id` | string | Y | 생성 배치 ID |

### 운영 정책 결정

문서들 사이의 표현 차이를 해소하기 위해, **v1.0에서는 `auto_classification`을 “권고”로만 취급**한다.  
즉, `AUTO_APPROVE`로 분류되더라도 실제 화이트리스트 반영은 `review_status = APPROVED` 이후에만 수행한다.

이렇게 해야:
- 보안 담당자 최종 승인 워크플로를 유지할 수 있고
- 문서별 표현 차이로 인한 구현 충돌을 막을 수 있다.

### 예시

```json
{
  "api_path": "torch.nn.functional.scaled_dot_product_attention",
  "first_seen_at": "2026-04-20T09:10:11Z",
  "last_seen_at": "2026-04-20T09:10:11Z",
  "seen_count": 1,
  "auto_classification": "AUTO_APPROVE",
  "verified_org_count": 3,
  "verified_org_list": ["Meta", "Google", "Mistral"],
  "in_official_docs": true,
  "review_status": "PENDING",
  "model_list": ["org/demo-model"],
  "risk_keywords": [],
  "matched_namespace_rule": "torch.nn.functional.*",
  "documentation_url": "https://pytorch.org/docs/stable/generated/...",
  "sample_callsites": ["F.scaled_dot_product_attention(q, k, v)"],
  "created_from_job_id": "9a7675b3-c726-45c8-9dae-98e5a6df7da2"
}
```

---

## 15.2 `PendingApiUpsertRequest`

```json
{
  "schema_version": "1.0",
  "request_id": "0c7d3f5a-0f86-4f8d-a9df-8c0c315e7284",
  "job_id": "9a7675b3-c726-45c8-9dae-98e5a6df7da2",
  "record": {
    "api_path": "torch.nn.functional.scaled_dot_product_attention",
    "first_seen_at": "2026-04-20T09:10:11Z",
    "last_seen_at": "2026-04-20T09:10:11Z",
    "seen_count": 1,
    "auto_classification": "AUTO_APPROVE",
    "verified_org_count": 3,
    "verified_org_list": ["Meta", "Google", "Mistral"],
    "in_official_docs": true,
    "review_status": "PENDING",
    "model_list": ["org/demo-model"],
    "risk_keywords": [],
    "matched_namespace_rule": "torch.nn.functional.*",
    "documentation_url": "https://pytorch.org/docs/stable/generated/...",
    "sample_callsites": ["F.scaled_dot_product_attention(q, k, v)"],
    "created_from_job_id": "9a7675b3-c726-45c8-9dae-98e5a6df7da2"
  }
}
```

---

## 16. 리뷰 인터페이스

## 16.1 `ReviewQueueEntry`

| 필드 | 타입 | 필수 | 설명 |
|---|---|---|---|
| `queue_entry_id` | string | Y | 리뷰 큐 ID |
| `queue_type` | string | Y | `MODEL_ARTIFACT_REVIEW` 또는 `API_REVIEW` |
| `job_id` | string | Y | 관련 검증 ID |
| `artifact_id` | string/null | Y | artifact 대상이면 값 |
| `api_path` | string/null | Y | API 대상이면 값 |
| `priority` | string | Y | `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `review_action` | string(enum) | Y | `SECURITY_OWNER_GATE` 등 |
| `assigned_to` | string/null | Y | 담당자 |
| `status` | string(enum) | Y | `PENDING`, `UNDER_REVIEW`, `APPROVED`, `REJECTED`, `DEFERRED` |
| `reason_codes` | array[string] | Y | 리뷰 필요 사유 |
| `created_at` | string | Y | 생성 시각 |

---

## 16.2 `ReviewDecisionRequest`

| 필드 | 타입 | 필수 | 설명 |
|---|---|---|---|
| `schema_version` | string | Y | `"1.0"` |
| `review_id` | string | Y | 리뷰 ID |
| `queue_entry_id` | string | Y | 대상 큐 ID |
| `decision` | string | Y | `APPROVE`, `CONDITIONAL`, `REJECT`, `DEFER` |
| `reviewer_id` | string | Y | 판단자 ID |
| `review_note` | string | Y | 판단 사유 |
| `conditions` | object/null | Y | 조건부 승인 시 추가 제약 |
| `decided_at` | string | Y | RFC3339 UTC |

### 예시

```json
{
  "schema_version": "1.0",
  "review_id": "rev_2026_04_20_003",
  "queue_entry_id": "rq_2026_04_20_001",
  "decision": "APPROVE",
  "reviewer_id": "security_admin_01",
  "review_note": "공식 문서 등재 및 Verified Org 사용 확인. 위험 키워드 없음.",
  "conditions": null,
  "decided_at": "2026-04-20T10:00:00Z"
}
```

---

## 16.3 `ReviewDecisionResult`

| 필드 | 타입 | 필수 | 설명 |
|---|---|---|---|
| `review_id` | string | Y | 리뷰 ID |
| `applied_to` | string | Y | `API`, `ARTIFACT` |
| `target_key` | string | Y | API path 또는 artifact_id |
| `final_review_status` | string | Y | `APPROVED`, `REJECTED`, `DEFERRED` |
| `updated_whitelist_version` | string/null | Y | API 승인 시 업데이트된 버전 |
| `updated_job_status` | string/null | Y | 관련 job 상태 변경 |
| `reason_entries` | array[`ReasonEntry`] | Y | 결과 사유 |

---

## 17. 승인/배포 인터페이스

## 17.1 `ApprovalPackage`

| 필드 | 타입 | 필수 | 설명 |
|---|---|---|---|
| `schema_version` | string | Y | `"1.0"` |
| `request_id` | string | Y | 요청 ID |
| `job_id` | string | Y | 검증 ID |
| `model` | object(`ModelRef`) | Y | 모델 정보 |
| `overall_decision` | string | Y | `APPROVE`, `APPROVE_WITH_TRANSFORM` 등 |
| `approved_artifact_ids` | array[string] | Y | 승인 artifact |
| `released_artifact_ids` | array[string] | Y | 실제 배포 artifact |
| `generated_artifact_ids` | array[string] | Y | 변환/재생성 결과 |
| `report_id` | string | Y | 검증 리포트 ID |
| `mlbom_id` | string | Y | ML-BOM ID |
| `signature_status` | string | Y | `SIGNED`, `SKIPPED`, `FAILED` |
| `cache_keys` | array[string] | Y | 저장 캐시 키 |
| `created_at` | string | Y | 생성 시각 |

### 승인 규칙

- `PASS`이면서 release 가능한 artifact만 `released_artifact_ids`에 들어간다.
- pickle 계열은 항상 **Path A 변환 결과물**만 들어간다.
- 등급 A 코드는 원본이 아니라 **재생성 결과물**이 release 대상이다.
- `PENDING_REVIEW` 상태의 artifact는 절대 release 대상이 아니다.

---

## 18. Validation Report 스키마

## 18.1 `ValidationReport`

| 필드 | 타입 | 필수 | 설명 |
|---|---|---|---|
| `schema_version` | string | Y | `"1.0"` |
| `report_id` | string | Y | 검증 리포트 ID |
| `request_id` | string | Y | 요청 ID |
| `job_id` | string | Y | 검증 ID |
| `model` | object(`ModelRef`) | Y | 모델 정보 |
| `policy` | object(`PolicyInfo`) | Y | 사용 정책 |
| `overall_status` | string | Y | 전체 상태 |
| `overall_decision` | string | Y | 전체 결정 |
| `artifact_results` | array[`ArtifactValidationResult`] | Y | 파일별 결과 |
| `summary_reason_codes` | array[string] | Y | 전체 요약 reason |
| `created_at` | string | Y | 생성 시각 |

### 최소 필수 보존 필드

이 리포트에는 최소한 아래가 남아야 한다.

- 스캔 결과
- 등급
- 해시
- 타임스탬프
- 승인/차단 사유
- 정책 버전

---

## 19. ML-BOM 스키마

## 19.1 `MLBOM`

| 필드 | 타입 | 필수 | 설명 |
|---|---|---|---|
| `schema_version` | string | Y | `"1.0"` |
| `mlbom_id` | string | Y | ML-BOM ID |
| `generated_at` | string | Y | 생성 시각 |
| `model` | object(`ModelRef`) | Y | 모델 정보 |
| `validation_report_id` | string | Y | 연결된 리포트 ID |
| `policy_fingerprint` | string | Y | 당시 정책 fingerprint |
| `artifacts` | array[object] | Y | artifact별 해시/상태/등급 |
| `review_refs` | array[string] | Y | 관련 review ID |
| `signature` | object | Y | Cosign/Sigstore 정보 |
| `final_release_action` | string | Y | 최종 배포 액션 |

### `artifacts[]` 최소 필드

| 필드 | 타입 | 필수 |
|---|---|---|
| `artifact_id` | string | Y |
| `repo_path` | string | Y |
| `file_kind` | string | Y |
| `input_sha256` | string | Y |
| `output_sha256` | string/null | Y |
| `grade` | string | Y |
| `status` | string | Y |
| `reason_codes` | array[string] | Y |

### `signature` 예시

```json
{
  "status": "SKIPPED",
  "tool": "cosign",
  "signature_ref": null,
  "note": "v1.0 단계에서는 해시 기반 무결성만 필수, 서명은 선택"
}
```

---

## 20. 감사 로그 스키마

## 20.1 `AuditEvent`

| 필드 | 타입 | 필수 | 설명 |
|---|---|---|---|
| `event_id` | string | Y | 이벤트 ID |
| `prev_event_hash` | string/null | Y | 이전 이벤트 해시 |
| `event_hash` | string | Y | 현재 이벤트 해시 |
| `event_type` | string | Y | 이벤트 종류 |
| `occurred_at` | string | Y | 발생 시각 |
| `request_id` | string | Y | 요청 ID |
| `job_id` | string/null | Y | 검증 ID |
| `actor_type` | string | Y | `SYSTEM`, `USER`, `REVIEWER` |
| `actor_id` | string | Y | 실행 주체 |
| `model_repo_id` | string/null | Y | 모델 식별자 |
| `artifact_id` | string/null | Y | 관련 artifact |
| `payload_digest` | string | Y | 본문 요약 SHA256 |
| `payload_inline` | object | Y | 작은 이벤트 요약 |

### 권장 event_type 목록

- `REQUEST_RECEIVED`
- `FILE_CLASSIFIED`
- `VALIDATION_STARTED`
- `VALIDATION_COMPLETED`
- `PENDING_API_REGISTERED`
- `REVIEW_DECISION_RECORDED`
- `MODEL_APPROVED`
- `MODEL_BLOCKED`
- `CACHE_HIT`
- `CACHE_INVALIDATED`
- `MLBOM_GENERATED`

---

## 21. 오류 응답 스키마

## 21.1 `ErrorResponse`

| 필드 | 타입 | 필수 | 설명 |
|---|---|---|---|
| `schema_version` | string | Y | `"1.0"` |
| `request_id` | string | Y | 요청 ID |
| `job_id` | string/null | Y | 검증 ID |
| `error_code` | string | Y | 내부 오류 코드 |
| `error_stage` | string | Y | 오류 발생 단계 |
| `error_message` | string | Y | 사람이 읽는 메시지 |
| `retryable` | boolean | Y | 재시도 가능 여부 |
| `reason_entries` | array[`ReasonEntry`] | Y | 세부 사유 |
| `created_at` | string | Y | 생성 시각 |

### `error_stage` 표준값

- `DOWNLOAD`
- `CLASSIFY`
- `VALIDATE_SAFETENSORS`
- `VALIDATE_PICKLE_PATH_A`
- `VALIDATE_PICKLE_PATH_B`
- `VALIDATE_CODE_AST`
- `VALIDATE_CODE_RUNTIME`
- `VALIDATE_CONFIG`
- `WHITELIST_CHECK`
- `PENDING_API_UPSERT`
- `REVIEW_APPLY`
- `REGISTRY_WRITE`
- `MLBOM_WRITE`
- `AUDIT_WRITE`

### 예시

```json
{
  "schema_version": "1.0",
  "request_id": "0c7d3f5a-0f86-4f8d-a9df-8c0c315e7284",
  "job_id": "9a7675b3-c726-45c8-9dae-98e5a6df7da2",
  "error_code": "PICKLE_A_OPCODE_PARSE_FAILED",
  "error_stage": "VALIDATE_PICKLE_PATH_A",
  "error_message": "pickle opcode 파싱 중 정책에 없는 opcode가 발견됨",
  "retryable": false,
  "reason_entries": [
    {
      "code": "PICKLE_OPCODE_BLOCKED",
      "severity": "CRITICAL",
      "message": "금지 opcode 탐지",
      "evidence": ["REDUCE"],
      "review_required": false
    }
  ],
  "created_at": "2026-04-20T09:11:00Z"
}
```

---

## 22. 상태 전이 규칙

### 22.1 파일 단위

| 시작 | 조건 | 결과 |
|---|---|---|
| `NEW` | 캐시 적중 | `PASS` + `cache_hit = true` |
| `NEW` | safetensors 검증 성공 | `PASS` |
| `NEW` | pickle Path A 금지 opcode | `BLOCK` |
| `NEW` | dangerous import/call/api | `BLOCK` |
| `NEW` | 미등록 API | `PENDING_REVIEW` |
| `NEW` | 동적/난독화 패턴 | `PENDING_REVIEW` |
| `NEW` | 인프라 오류 | `ERROR` |

### 22.2 job 단위

| artifact 조합 | overall_status |
|---|---|
| 하나라도 `BLOCK` | `BLOCK` |
| `BLOCK`는 없고 하나라도 `PENDING_REVIEW` | `PENDING_REVIEW` |
| 전부 `PASS` | `PASS` |
| `PASS`/`PENDING_REVIEW`/`BLOCK` 결정 불가 + 인프라 실패 | `ERROR` |

---

## 23. 구현 시 필수 결정 사항

### 23.1 박용담이 반드시 넣어야 하는 값

- `request_id`
- `job_id`
- `policy_fingerprint`
- 다운로드된 모든 파일의 `sha256`
- `file_kind`
- `temp_local_path`

### 23.2 정은미/양유상이 반드시 반환해야 하는 값

- 파일별 `status`
- 파일별 `grade`
- 파일별 `review_action`
- `reason_entries`
- 변환/재생성 결과물의 새 `artifact_id`
- `report_id`

### 23.3 김민우가 반드시 보장해야 하는 값

- `status` (`ALLOWED` / `BLOCKED` / `UNKNOWN` / `PENDING`)
- `whitelist_version`
- Pending 등록 시 `api_path`, `auto_classification`, `review_status`, `model_list`

### 23.4 Review Gate가 반드시 남겨야 하는 값

- `review_id`
- 판단자
- 판단 시각
- 판정 결과
- 판정 사유
- 영향을 받은 whitelist/job 상태

---

## 24. 팀 구현 분담 기준 (이 문서 기준)

| 담당 | 구현 항목 |
|---|---|
| 팀장 | 이 문서 유지, 모듈 간 계약 충돌 조정, 최종 인터페이스 기준 관리 |
| 박용담 | 파일분류, `config.json`, `tokenizer_config.json`, `ArtifactRef` 생성 기준, JSON 검증, 최종 응답 조립 |
| 정은미 | 가중치검증경로, safetensors 검증, pickle Path A/Path B 검증 |
| 양유상 | 코드검증경로, 검증1(`CODE_AST_SCAN`), 검증2(`CODE_RESTRICTED_RUNTIME`), 검증3(`CODE_SANDBOX_RUNTIME`), 참조 `.py` 코드 검증 |
| 김민우 | 적응형 화이트리스트 엔진, whitelist check/upsert, pending list 구조, review 적용 |

---

## 25. 최소 acceptance checklist

아래가 충족되면 인터페이스 정의는 완료로 본다.

- [ ] 모든 모듈이 `request_id`, `job_id`, `schema_version`을 공통으로 사용한다.
- [ ] `ArtifactRef`를 기준으로 파일 목록을 교환한다.
- [ ] `ValidationJobRequest/Response`가 실제 코드로 serialize/deserialize 된다.
- [ ] `ArtifactValidationResult`가 safetensors/pickle/code/config 전부를 표현한다.
- [ ] `review_action`이 A/B-1/B-2/C에 대해 고정된다.
- [ ] 미등록 API가 `PendingApiRecord`로 저장된다.
- [ ] `ValidationReport`가 파일로 저장된다.
- [ ] `MLBOM`과 `AuditEvent` 최소 스키마가 구현된다.
- [ ] 정책 fingerprint 변경 시 캐시가 무효화된다.
- [ ] Path A 실패 시 Path B 성공 여부와 무관하게 release가 막힌다.

---

## 26. 바로 구현해야 할 우선순위

1. `ArtifactRef`, `PolicyInfo`, `ValidationJobRequest`, `ValidationJobResponse`
2. `ArtifactValidationResult` + safetensors/pickle/code/config detail
3. `WhitelistCheckResponse`, `PendingApiRecord`
4. `ValidationReport`
5. `ApprovalPackage`
6. `MLBOM`
7. `AuditEvent`
8. `ErrorResponse`

---

## 27. 최종 요약

이 문서에서 실제로 동결되는 핵심은 아래 다섯 가지다.

1. **공통 envelope**: `request_id`, `job_id`, `schema_version`, `policy_fingerprint`
2. **공통 결과 포맷**: `status`, `grade`, `review_action`, `reason_entries`
3. **파일별 detail 구조**: safetensors / pickle / code / config
4. **거버넌스 구조**: whitelist check, pending list, review decision
5. **운영 산출물 구조**: validation report, ML-BOM, audit log, approval package

이 다섯 가지만 코드로 고정되면, 각자 내부 구현이 달라도 모듈 연동은 깨지지 않는다.
