# HuggingMask B-2 gVisor 구현 상세 설계서

문서 버전: v1.0  
작성일: 2026-05-19  
최신화: 2026-06-08
기준 브랜치: `origin/dev`  
기준 커밋: `14b3eb5`  
대상 저장소: `C:/Users/andyw/Desktop/HuggingMask`

## 0. 2026-06-08 구현 상태 메모

이 문서의 본문은 2026-05-19 기준 상세 설계 이력이다. 2026-06-08 발표 전 기준으로는 다음 항목이 구현/테스트에 반영됐다.

- B-2 sandbox 대상 경계와 optional runner 계약
- SnapshotSourceResolver 기반 source loading/staging
- config `auto_map` sibling Python promotion
- B-2 input manifest, manifest hash, trusted entrypoint 계약
- Docker/runsc command planning, inspect fixture validator, runsc log parser
- fake runner 기반 fixture e2e와 로컬 Docker demo script 계약

아직 남은 범위:

- production validation job에서 실제 Docker/runsc를 기본 실행하는 운영 자동화
- Linux runsc 실환경 e2e CI
- production queue/DB/review UI와 B-2 evidence의 완전한 통합

## 1. 목적

이 문서는 HuggingMask의 Python 커스텀 코드 검증 경로 중 `B-2` 등급을 실제 코드로 구현하기 위한 상세 설계서다.

이 문서를 보고 구현자가 바로 파일을 만들 수 있도록 다음을 고정한다.

- B-2 gVisor sandbox의 입력과 출력
- `ArtifactValidationResult.details`에 들어갈 `sandbox_check` 계약
- host runner, manifest, Docker/runsc 실행, inspect 검증, runsc log 파싱, decision builder의 파일별 책임
- B-1 `runtime_check`와 B-2 `sandbox_check`의 결합 방식
- whitelist/pending store와 연결되는 지점
- block/review/clean 판정 규칙
- 구현 순서와 테스트 케이스

### 1.1 문서 구조

gVisor 공통 운영 기준은 `docs/gVisor_공통_운영_원칙.md`를 따른다.

이 문서는 공통 Docker/runsc 원칙을 반복 정의하지 않고, Python 코드 B-2 sandbox에만 해당하는 내용을 고정한다.

| 문서 | 역할 |
|---|---|
| `docs/gVisor_공통_운영_원칙.md` | Docker/runsc 실행, inspect, runsc log, evidence, infra error 공통 기준 |
| `docs/B-2_gVisor_구현_상세_설계서.md` | Python 코드 B-2 manifest, entrypoint, `sandbox_check`, decision mapping |
| `docs/PICKLE_PATH_B_gVisor_구현_상세_설계서.md` | weight/pickle Path B gVisor host evidence 보강 |

### 1.2 구현 전 no-go gate

아래 조건이 구현되지 않은 상태에서는 B-2 gVisor runner를 연결하지 않는다. 이 항목들은 기능 우선순위가 아니라 안전 경계다.

| gate | 이유 | 미충족 시 처리 |
|---|---|---|
| `_requires_b2_sandbox()` 단일 진입점 | 현재 `CODE_SANDBOX_RUNTIME`은 `C`, `CONFIGURATION`, `UNKNOWN` 결과에도 붙을 수 있어 단독 gate로 부적합하다. | sandbox 미실행, `NOT_RUN/SANDBOX_NOT_CONFIGURED` 또는 기존 review 유지 |
| `SnapshotSourceResolver` | `source_loader`나 `ArtifactRef.temp_local_path`만으로는 host path 신뢰, symlink/path traversal, hash 재검증을 보장할 수 없다. | sandbox 미실행, `MISSING_SOURCE` 또는 resolver error |
| config-linked Python sibling promotion | `config.json -> auto_map -> modeling_*.py`가 nested summary에만 남으면 B-2 hook을 타지 못한다. | parent config는 `PASS` 금지, linked source missing/review 유지 |
| B-1 runtime status 세분화 | `FAIL`, `TIMEOUT`, `MEMORY_LIMIT`, infra error를 단순 B-2 escalation으로 처리하면 위험 이벤트가 review로 낮아질 수 있다. | status/reason별 block/review 분기 후에만 B-2 후보 계산 |
| host inspect assertion | `--runtime runsc` 문자열이나 container 내부 출력만으로 gVisor 실행을 증명할 수 없다. | infra error 또는 runtime policy violation |

## 2. 핵심 원칙

B-2에서 gVisor는 승인 장치가 아니라 관찰 장치다.

따라서 다음 규칙은 구현에서 바꾸면 안 된다.

- B-2 sandbox 실행 성공만으로 모델 코드를 `PASS` 처리하지 않는다.
- 신규 API는 sandbox clean 이후에도 pending 또는 whitelist 정책 처리를 거친다.
- 위험 import, 위험 call, 위험 API가 이미 정적 분석에서 발견된 코드는 sandbox에 넣지 않고 즉시 `BLOCK`한다.
- 동적 실행, 난독화, dunder 기반 escape 의심 패턴은 B-2가 아니라 `C/PENDING_REVIEW` 또는 `BLOCK`으로 남긴다.
- 컨테이너 내부 stdout, stderr, runner JSON은 최종 보안 판정의 단독 근거가 아니다.
- 최종 보안 판정은 host-side evidence만 사용한다.
- proxy 내부에는 sandbox 검증 로직을 넣지 않는다.

## 3. 현재 dev 기준 프로젝트 경계

최신 `origin/dev` 기준으로 B-2 구현은 아직 직접 구현 대상이 아니다.

이 문서는 `origin/dev` 기준 구현 문서다. 현재 `feature/*` 브랜치에서 구현하려면 먼저 `dev`를 병합/rebase하거나, `analyzer/service.py`가 없는 브랜치용 연결 절을 별도로 따른다.

현재 존재하는 경계는 다음과 같다.

| 영역 | 현재 책임 | B-2 구현 시 변경 |
|---|---|---|
| `analyzer/validators/code_validator.py` | Python 정적 분석, API 정책 분류, grade 결정 | B-2 결과에 `sandbox_check`를 붙이는 연결점 추가 |
| `analyzer/orchestrator.py` | artifact별 validator dispatch | 선택적으로 B-2 sandbox runner 호출 |
| `analyzer/service.py` | 최신 dev의 validation job service. 현재 weight artifact 중심 | Python artifact는 code orchestrator로 위임하도록 확장 |
| `analyzer/schemas.py` | 공통 결과 schema | `details` 확장 또는 `SandboxCheck` dataclass 추가 |
| `whitelist/` | allow/block/pending API 정책 | sandbox clean 이후 pending API 처리 |
| `sandbox/` | 현재는 placeholder | B-2 gVisor 실제 구현 위치 |
| `proxy/` | API endpoint, analyzer 호출 | sandbox 직접 구현 금지 |

최신 `origin/dev`의 `/internal/v1/validation/jobs` 경로는 `proxy/app/main.py`에서 `analyzer.service.validate_job()`로 연결된다. 현재 `analyzer/service.py`는 `SAFETENSORS`, `PICKLE` 중심이며 그 외 artifact는 `SKIPPED`로 돌린다. B-2 구현 시에는 service에 sandbox 로직을 직접 넣지 말고, Python artifact를 code orchestrator로 위임하는 얇은 dispatch만 추가한다.

권장 구조:

```text
proxy/app/main.py
      -> analyzer.service.validate_job()
      -> weight artifact: analyzer.validators.weight.pipeline.validate()
      -> python/config artifact: analyzer.orchestrator.run_validation_job()
          -> code/config validator
          -> auto_map referenced Python result sibling promotion
          -> optional sandbox_check_loader
```

`analyzer/service.py` 수정 범위:

- `WEIGHT_FILE_KINDS` 외에 `CODE_FILE_KINDS = {"PYTHON", "CONFIG_JSON", "TOKENIZER_CONFIG_JSON"}` 추가
- code artifact면 `analyzer.orchestrator.run_validation_job()`에 위임
- repo snapshot 전체를 읽을 수 있는 snapshot-backed `source_loader`를 만들어 orchestrator에 전달
- `ValidationJobRequest`에 snapshot 입력 계약을 먼저 추가한 뒤 service dispatch를 구현
- `job.policy`가 없는 최신 dev payload도 처리할 수 있도록 기본 `PolicyInfo` 생성
- service 내부에서 Docker/runsc를 직접 호출하지 않음
- response schema는 기존 `ValidationJobResponse` 유지
- `tests/test_validation_jobs.py`에 Python artifact가 `SKIPPED`가 아니라 code validator로 전달되는 smoke test 추가
- `config.json -> auto_map -> modeling_*.py`가 sibling `ArtifactValidationResult`로 승격되고 B-2 sandbox hook을 타는 smoke test 추가

### 3.1 최신 dev와 맞춘 snapshot 입력 계약

최신 `origin/dev`의 `ValidationJobRequest`에는 아직 repo snapshot 필드가 없다. 따라서 B-2 구현은 `analyzer.service`를 고치기 전에 schema 계약부터 닫아야 한다.

`analyzer/schemas.py`에 아래 dataclass와 optional field를 추가한다.

```python
@dataclass
class SnapshotFileRef(Serializable):
    repo_path: str
    temp_local_path: str
    sha256: str
    size_bytes: int
    file_kind: FileKind = FileKind.OTHER


@dataclass
class ValidationJobRequest(Serializable):
    ...
    model_snapshot_root: str | None = None
    model_snapshot_inventory: list[SnapshotFileRef] = field(default_factory=list)
```

`__post_init__()`는 `model_snapshot_inventory`의 dict 항목을 `SnapshotFileRef`로 정규화한다. `model_snapshot_root`와 `model_snapshot_inventory`는 검증 대상 repo snapshot을 읽기 위한 입력 계약이며, 최종 승인 근거가 아니다.

service에서 사용할 source loader는 payload artifact만 읽는 loader가 아니다. B-2 manifest와 auto_map 검증은 repo 내부 relative import closure, `__init__.py`, helper, tokenizer/processor dependency를 읽어야 하므로 service 계약은 아래 입력 중 하나를 반드시 제공한다.

- `model_snapshot_root`: 검증 대상 repo snapshot이 풀린 host directory
- `model_snapshot_inventory`: repo-relative path, temp local path, sha256, size를 가진 파일 목록

둘 다 없고 job payload에 `config.json`만 들어온 경우 auto_map 참조 Python을 신뢰성 있게 읽을 수 없다. 이 경우 config 검증은 참조 Python을 `MISSING_SOURCE`로 기록하고 전체 결과를 `PENDING_REVIEW`로 둔다. B-2 sandbox를 실행하지 않는다. loader 자체 오류, snapshot root 경로 탈출, hash mismatch처럼 검증 인프라 무결성이 깨진 경우만 `ERROR`로 둔다.

service는 단순 `repo_path -> bytes` 함수만 만들지 않는다. 먼저 검증된 snapshot resolver를 만들고, orchestrator용 `source_loader`는 그 resolver 위의 얇은 adapter로 둔다.

```python
class SnapshotResolveError(StringEnum):
    MISSING_SOURCE = "MISSING_SOURCE"
    PATH_ESCAPE = "PATH_ESCAPE"
    HASH_MISMATCH = "HASH_MISMATCH"
    SIZE_MISMATCH = "SIZE_MISMATCH"
    UNTRUSTED_LOCAL_PATH = "UNTRUSTED_LOCAL_PATH"
    INVALID_REPO_PATH = "INVALID_REPO_PATH"


@dataclass(frozen=True)
class ResolvedSnapshotFile:
    repo_path: str
    local_path: Path
    sha256: str
    size_bytes: int
    file_kind: FileKind
    source_kind: str  # "root" | "inventory" | "artifact"


class SnapshotSourceResolver:
    def resolve(self, repo_path: str) -> ResolvedSnapshotFile | SnapshotResolveError:
        ...

    def read_bytes(self, repo_path: str) -> bytes | SnapshotResolveError:
        ...


def build_source_loader(resolver: SnapshotSourceResolver) -> SourceLoader:
    def _loader(repo_path: str) -> str | bytes | None:
        value = resolver.read_bytes(repo_path)
        return None if isinstance(value, SnapshotResolveError) else value

    return _loader
```

resolver 구현 규칙:

- `repo_path`는 POSIX relative path로 정규화한다. 절대 경로, `..`, drive prefix, backslash 혼용, NUL byte는 `INVALID_REPO_PATH`다.
- `model_snapshot_inventory.temp_local_path`는 service가 신뢰하는 snapshot/temp base 하위만 허용한다. 사용자가 임의 host path를 지정하는 형태는 금지한다.
- symlink는 `Path.resolve()` 후 trusted base 밖을 가리키면 `PATH_ESCAPE`다.
- 파일을 읽기 직전에 `size_bytes`와 `sha256`을 재검증한다. 불일치는 각각 `SIZE_MISMATCH`, `HASH_MISMATCH`다.
- `model_snapshot_root`도 trusted fetcher가 만든 root만 허용한다. root fallback으로 읽은 파일도 `sha256`를 계산해 `ResolvedSnapshotFile`에 기록한다.
- `ArtifactRef.temp_local_path`는 payload artifact 자체를 읽을 때만 보조 입력으로 사용한다. `auto_map` sibling Python이나 manifest staging에서는 반드시 resolver가 재검증한 `ResolvedSnapshotFile.local_path`를 사용한다.

service는 weight 결과와 code 결과를 같은 `ValidationJobResponse` 안에 병합한다. 병합 규칙은 `BLOCK > ERROR > PENDING_REVIEW > PASS > SKIPPED` 순서로 전체 status를 계산한다.

전체 status/decision/release_action 매핑:

| artifact 결과 집합 | overall_status | overall_decision | release_action |
|---|---|---|---|
| 하나라도 `BLOCK` | `BLOCK` | `DENY` | `DENY` |
| `BLOCK` 없음, 하나라도 `ERROR` | `ERROR` | `ERROR` | `ERROR` |
| `BLOCK/ERROR` 없음, 하나라도 `PENDING_REVIEW` | `PENDING_REVIEW` | `REVIEW_REQUIRED` | `REVIEW_QUEUE` |
| 하나 이상 결과가 있고 모두 `PASS` | `PASS` | `APPROVE` | `APPROVE_AND_STORE` |
| 결과가 없거나 모두 `SKIPPED` | `ERROR` | `ERROR` | `NO_VALIDATABLE_ARTIFACT` |

`SKIPPED`만 있는 job을 `PASS`로 올리면 안 된다. service가 non-weight artifact를 임시로 `SKIPPED` 처리하는 dev 상태에서는 특히 이 규칙을 테스트로 고정한다.

## 4. B-1과 B-2 결과 결합 방식

### 4.1 결론

`runtime_check`와 `sandbox_check`는 반드시 분리한다.

`runtime_check`는 B-1 제한 런타임 gate 결과다.  
`sandbox_check`는 B-2 gVisor/runsc evidence 결과다.

두 결과를 하나의 dict로 union하면 다음 문제가 생긴다.

- `runtime_mode`, `status`, `logs_ref` 같은 키 충돌
- B-2의 `runtime_evidence`, `security_events`, `artifacts` 정보 손실
- B-1 실패 후 B-2 관찰을 수행한 경우 audit trail 불명확

### 4.2 `details` 구조

`ArtifactValidationResult.details`는 아래 구조를 유지한다.

```json
{
  "role_classification": {},
  "ast_scan": {},
  "configuration_metadata": {},
  "api_scan": {},
  "context_api_scan": {},
  "grade_result": {},
  "runtime_check": {},
  "sandbox_check": null,
  "pending_api_refs": [],
  "review_queue_entry_id": null,
  "effective_output_artifact_id": null
}
```

`sandbox_check` shape는 아래 규칙으로 고정한다.

- B-2 sandbox 대상이면 runner가 비활성화되어도 항상 structured object를 넣는다.
- B-2 sandbox 대상의 비활성 상태는 `sandbox_check.decision = "NOT_RUN"`으로 표현한다.
- B-2 대상이 아닌 artifact만 `sandbox_check = null` 또는 field absent를 허용한다.

B-2 runner가 비활성화된 경우 값은 아래와 같다.

```json
{
  "schema_version": "1.0",
  "request_id": "req-...",
  "job_id": "job-...",
  "artifact_id": "sha256:...",
  "repo_path": "modeling_demo.py",
  "grade": "B-2",
  "sandbox_runtime": null,
  "profile": "B2_STANDARD",
  "decision": "NOT_RUN",
  "deployable": false,
  "runtime_evidence": {},
  "execution": {
    "import_status": "not_run",
    "instantiate_status": "not_run",
    "forward_status": "not_run"
  },
  "security_events": {
    "network_events": [],
    "unexpected_execve": [],
    "blocked_writes": [],
    "secret_path_access": [],
    "blocked_reads": [],
    "review_events": []
  },
  "manifest_evidence": {
    "host_manifest_sha256": null,
    "manifest_errors": [],
    "input_hash_errors": []
  },
  "artifacts": {},
  "policy_gate": {
    "reason_code": "SANDBOX_NOT_CONFIGURED"
  },
  "created_at": "2026-05-19T00:00:00Z",
  "reason": "B-2 sandbox runner is not configured"
}
```

`SANDBOX_NOT_CONFIGURED`는 `decision` 값이 아니라 `policy_gate.reason_code` 또는 `reason_entries`에 남기는 reason code다. `decision`은 `B2Decision` enum의 `NOT_RUN`을 사용한다.

### 4.3 B-1 실패와 B-2 escalation

B-1 결과를 B-2로 넘길 때는 실패 원인을 구분한다.

| B-1 `runtime_check.status` | 처리 |
|---|---|
| `PASS` | runtime gate 사유만 해소. pending API나 context review가 없을 때만 B-1 `PASS` 유지 |
| `SKIPPED` | B-2 후보 유지 가능 |
| `ERROR` | infra/loader/policy 원인을 구분한다. 원인 불명이면 B-2를 실행해도 최종은 `PENDING_REVIEW` |
| `FAIL` + blocked import/audit event | B-2로 낮추지 말고 `BLOCK` 또는 `C/PENDING_REVIEW` |
| `TIMEOUT` | 보안 이벤트가 있으면 `BLOCK`, 없으면 `FUNCTIONAL_REVIEW_REQUIRED` |
| `MEMORY_LIMIT` | fork/thread runaway 증거가 있으면 `BLOCK`, 없으면 resource review |

구현에서는 B-1 결과를 그대로 B-2 승인 근거로 사용하지 않는다. `runtime_check.status == "PASS"`여도 `pending_api_refs`가 남아 있거나 `context_api_scan.summary_decision == "review"`이면 B-2 또는 policy review 후보를 유지한다. 최종 `PASS`는 pending API 없음, context review 없음, 위험 정적 신호 없음, whitelist 정책 충족이 모두 맞을 때만 가능하다.

현재 `code_validator._decide_grade()`는 B-1 후보의 runtime gate가 통과하지 않으면 `B-2/PENDING_REVIEW`로 내리는 단순 경로를 가진다. B-2 runner를 붙이기 전에 이 단순 경로는 위 표와 일치하도록 분리한다. 특히 `runtime_check.status != "PASS"`라는 사실만으로 sandbox 실행을 결정하지 않는다.

## 5. B-2 진입 조건

B-2 sandbox는 아래 조건을 모두 만족할 때만 실행한다.

`route_kind == CODE_SANDBOX_RUNTIME`은 필요 조건일 뿐 충분 조건이 아니다. 구현은 반드시 16.2의 `_requires_b2_sandbox()` 결과만으로 B-2 runner 호출 여부를 결정한다.

| 조건 | 설명 |
|---|---|
| file kind | `PYTHON` |
| role | 기본 대상은 `MODELING` |
| grade | `B-2` |
| route kind | `CODE_SANDBOX_RUNTIME` |
| status | `PENDING_REVIEW` |
| 위험 API | 없음 |
| 위험 import/call | 없음 |
| dynamic/obfuscation | 없음 |
| B-2 전환 사유 | unregistered API, context review, 또는 B-1 runtime gate 미실행/미통과 |

다음은 sandbox 실행 대상이 아니다.

| 조건 | 처리 |
|---|---|
| `eval`, `exec`, `compile`, `__import__` | `BLOCK` |
| `subprocess`, `socket`, `requests`, `urllib`, `httpx` | `BLOCK` |
| `torch.load`, `pickle.load`, `numpy.load` | `BLOCK` |
| `object.__subclasses__`, `__globals__`, `sys._getframe` 등 escape pattern | `C/PENDING_REVIEW` 또는 `BLOCK` |
| `PREPROCESSING`, `AUXILIARY`, `UNKNOWN` | 별도 review. B-2 modeling sandbox로 자동 처리하지 않음 |
| `custom_pipelines` | 별도 pipeline review. modeling B-2로 자동 승인하지 않음 |

role source 규칙:

- `MODELING` role은 analyzer가 repo path, config trigger, `auto_map` key, 정책 context를 해석해 산출한 값만 신뢰한다.
- 사용자 payload, artifact metadata, 파일 내부 선언만으로 `MODELING` role을 부여하지 않는다.
- `AutoModel`, `AutoModelForCausalLM`, `AutoModelForSeq2SeqLM` 계열은 다른 gate 조건을 모두 만족할 때만 B-2 후보가 될 수 있다.
- `AutoTokenizer`, processor/image processor/feature extractor, `custom_pipelines`, unknown key는 modeling B-2 sandbox 대상이 아니다.

## 6. 정적 우회 차단 보강

B-2 전제는 "위험 패턴 없음"이다. 따라서 아래 dunder 속성 접근은 B-2 진입 전에 정적 분석에서 잡아야 한다.

구현 파일:

- `analyzer/validators/common_security_policy.py`
- `analyzer/validators/code_ast.py`

추가할 공통 상수:

```python
DANGEROUS_DUNDER_ATTRS: frozenset[str] = frozenset({
    "__class__",
    "__bases__",
    "__base__",
    "__mro__",
    "__subclasses__",
    "__init_subclass__",
    "__globals__",
    "__builtins__",
    "__import__",
    "__loader__",
    "__spec__",
    "__file__",
    "__path__",
    "__package__",
    "__dict__",
    "__weakref__",
    "__getattribute__",
    "__setattr__",
    "__delattr__",
    "__code__",
    "__func__",
    "__self__",
    "__closure__",
    "__defaults__",
    "__kwdefaults__",
    "__wrapped__",
    "__qualname__",
    "__annotations__",
})
```

`code_ast.py` 구현 규칙:

- `ast.Attribute.attr`가 위 목록에 있으면 `dynamic_patterns`에 `dunder_attr:<name>` 추가
- `ast.Subscript`에서 key가 위 문자열이면 `dynamic_patterns`에 `dunder_key:<name>` 추가
- `sys._getframe` 호출은 `dynamic_patterns` 또는 `dangerous_calls`에 기록
- `object.__subclasses__()` chain은 `dynamic_patterns`에 기록
- 이 신호가 있으면 B-2로 보내지 않고 `C/PENDING_REVIEW` 또는 `BLOCK` 처리

severity tier:

- hard/high risk: `__subclasses__`, `__globals__`, `__builtins__`, `__code__`, `__closure__`, `sys._getframe`, `object.__subclasses__()` chain
- review/metadata risk: `__annotations__`, `__qualname__`, metadata-only `__dict__` access

초기 구현은 false negative를 피하기 위해 둘 다 B-2 sandbox 진입 전 차단 신호로 보되, reason detail에는 severity를 남긴다. 이후 오탐이 크면 metadata risk만 별도 review-low로 조정할 수 있다.

테스트:

- `tests/test_code_ast.py::test_dangerous_dunder_attrs_are_extracted`
- `tests/test_code_validator.py::test_dangerous_dunder_pattern_is_not_b2`

## 7. 신규 파일 구조

B-2 구현은 아래 파일을 추가한다.

```text
sandbox/
  b2/
    __init__.py
    schemas.py
    repo_manifest.py
    host_runner.py
    inspect_validator.py
    runsc_log_parser.py
    event_policy.py
    decision_builder.py
    entrypoint.py
  image/
    b2/
      Dockerfile
      requirements.txt
  policies/
    b2_runtime_policy.yaml
    b2_filesystem_policy.yaml
    b2_execve_policy.yaml
tests/
  test_b2_repo_manifest.py
  test_b2_inspect_validator.py
  test_b2_event_policy.py
  test_b2_decision_builder.py
  test_b2_host_runner_command.py
```

초기 구현에서 Docker/runsc가 없는 Windows 개발 환경을 고려해 host runner는 command build와 decision logic을 unit test로 먼저 고정한다.

## 8. `sandbox/b2/schemas.py`

### 8.1 Dataclass

아래 dataclass를 만든다.

```python
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from analyzer.schemas import StringEnum

B2_SCHEMA_VERSION = "1.0"

class B2Decision(StringEnum):
    NOT_RUN = "NOT_RUN"
    SANDBOX_INFRA_ERROR = "SANDBOX_INFRA_ERROR"
    BLOCKED_RUNTIME_INVALID = "BLOCKED_RUNTIME_INVALID"
    BLOCKED_SECURITY_EVENT = "BLOCKED_SECURITY_EVENT"
    FUNCTIONAL_REVIEW_REQUIRED = "FUNCTIONAL_REVIEW_REQUIRED"
    FORWARD_SKIPPED_REVIEW = "FORWARD_SKIPPED_REVIEW"
    HIGH_RISK_REVIEW = "HIGH_RISK_REVIEW"
    B2_SANDBOX_OBSERVED_CLEAN = "B2_SANDBOX_OBSERVED_CLEAN"
    B2_POLICY_REVIEW_REQUIRED = "B2_POLICY_REVIEW_REQUIRED"
    LOG_INCOMPLETE = "LOG_INCOMPLETE"
    ERROR = "ERROR"

class RunnerDiagnosticsStatus(StringEnum):
    PRESENT_VALID = "present_valid"
    MISSING = "missing"
    MALFORMED = "malformed"
    NONCE_MISMATCH = "nonce_mismatch"

@dataclass(frozen=True)
class B2SandboxJob:
    request_id: str
    job_id: str
    artifact_id: str
    repo_id: str
    repo_path: str
    job_input_dir: str
    revision: str
    policy_version: str
    image_ref: str
    runner_entrypoint: str
    output_dir: str
    docker_runtime: str
    profile: str = "B2_STANDARD"
    timeout_seconds: int = 30
    memory_limit: str = "4g"
    cpu_limit: str = "2"
    pids_limit: int = 128
    run_forward: bool = False

@dataclass(frozen=True)
class B2RuntimePolicy:
    require_runsc_strace: bool = True
    log_incomplete_action: str = "review"  # "review" | "block"

@dataclass(frozen=True)
class B2Target:
    source: str  # "auto_map" | "direct_python"
    target_module: str
    target_class: str | None = None
    auto_map_key: str | None = None
    primary_repo_path: str = ""
    import_root: str = "/sandbox/input"

@dataclass
class B2ManifestFile:
    path: str
    sha256: str
    size_bytes: int
    role: str
    ast_grade: str
    content_kind: str = "PYTHON"
    import_allowed: bool = False
    target_allowed: bool = False
    is_primary: bool = False
    validation_status: str | None = None
    unknown_apis: list[str] = field(default_factory=list)
    risk_flags: list[str] = field(default_factory=list)

@dataclass
class B2InputManifest:
    schema_version: str
    request_id: str
    job_id: str
    primary_artifact_id: str
    primary_repo_path: str
    revision: str
    policy_version: str
    grade: str
    target: B2Target
    manifest_sha256: str
    files: list[B2ManifestFile]

@dataclass
class RuntimeEvidence:
    runtime: str | None = None
    image_ref: str | None = None
    network_mode: str | None = None
    rootfs_readonly: bool | None = None
    cap_drop_all: bool | None = None
    no_new_privileges: bool | None = None
    non_root_user: bool | None = None
    pids_limit: int | None = None
    memory_limit: str | int | None = None
    cpu_limit: str | int | None = None
    env_allowlist_ok: bool | None = None
    mounts_ok: bool | None = None

@dataclass
class ExecutionEvidence:
    import_status: str = "not_run"
    instantiate_status: str = "not_run"
    forward_status: str = "not_run"
    exit_code: int | None = None
    timeout: bool = False
    oom_killed: bool = False
    pids_limit_hit: bool = False

@dataclass
class SecurityEvents:
    network_events: list[dict[str, Any]] = field(default_factory=list)
    unexpected_execve: list[dict[str, Any]] = field(default_factory=list)
    blocked_writes: list[dict[str, Any]] = field(default_factory=list)
    secret_path_access: list[dict[str, Any]] = field(default_factory=list)
    blocked_reads: list[dict[str, Any]] = field(default_factory=list)
    review_events: list[dict[str, Any]] = field(default_factory=list)

@dataclass
class ManifestEvidence:
    host_manifest_sha256: str | None = None
    manifest_errors: list[str] = field(default_factory=list)
    input_hash_errors: list[str] = field(default_factory=list)

@dataclass
class B2SandboxCheck:
    schema_version: str
    request_id: str
    job_id: str
    artifact_id: str
    repo_path: str
    grade: str
    sandbox_runtime: str | None
    profile: str
    decision: B2Decision
    deployable: bool
    runtime_evidence: RuntimeEvidence
    execution: ExecutionEvidence
    security_events: SecurityEvents
    manifest_evidence: ManifestEvidence
    artifacts: dict[str, str]
    policy_gate: dict[str, Any]
    created_at: str
    reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        ...
```

`to_dict()`는 `analyzer.schemas.to_jsonable()` 패턴과 맞춰 JSON 직렬화 가능한 dict를 반환한다.

`B2SandboxJob`의 경로 필드는 아래 의미로 고정한다.

| 필드 | 의미 |
|---|---|
| `job_input_dir` | manifest에 포함된 파일만 복사한 sanitized staging directory. 이 경로만 `/sandbox/input:ro`로 mount한다. |
| `runner_entrypoint` | image 내부 trusted runner 절대 경로. 예: `/app/huggingmask_runner/b2_entrypoint.py` |
| `output_dir` | host evidence 저장 경로. Docker inspect, logs, runsc logs, decision JSON을 저장한다. |
| `docker_runtime` | Docker daemon에 등록된 gVisor runtime 이름. 예: `runsc`, `runsc-b2`, `runsc-debug`. policy에서 주입하고 inspect에서 동일 값을 검증한다. |

`job_input_dir`는 반드시 원본 repo root 또는 snapshot root와 분리한다. 원본 repo 전체를 mount하면 정적 분석과 manifest에 포함되지 않은 파일이 컨테이너 안으로 들어갈 수 있기 때문이다.

`B2SandboxCheck.sandbox_runtime`은 `"gvisor"` 같은 의미적 sandbox runtime을 기록하고, Docker daemon runtime entry 이름은 `B2SandboxJob.docker_runtime`과 `RuntimeEvidence.runtime`에 기록한다. 둘을 섞지 않는다.

`B2SandboxCheck.artifacts`는 임의 key를 쓰지 않는다. evidence root 기준 relative path 또는 opaque artifact id만 값으로 둔다.

```json
{
  "docker_inspect_pre": "inspect/pre.json",
  "docker_inspect_post": "inspect/post.json",
  "docker_logs": "logs/docker.log",
  "runsc_logs": "logs/runsc/",
  "runner_diagnostics": "runner/runner_diagnostics.json",
  "host_decision": "decision/b2_sandbox_check.json",
  "input_manifest": "input/b2_input_manifest.json"
}
```

### 8.2 Decision과 global status 매핑

| `sandbox_check.decision` | `ArtifactValidationResult.status` | `review_action` |
|---|---|---|
| `NOT_RUN` | `PENDING_REVIEW` | `SECURITY_OWNER_GATE` |
| `SANDBOX_INFRA_ERROR` | `ERROR` | `MANUAL_REVIEW_REQUIRED` |
| `BLOCKED_RUNTIME_INVALID` | `BLOCK` only if untrusted code already had execution opportunity under invalid runtime | `BLOCK_IMMEDIATELY` |
| `BLOCKED_SECURITY_EVENT` | `BLOCK` | `BLOCK_IMMEDIATELY` |
| `FUNCTIONAL_REVIEW_REQUIRED` | `PENDING_REVIEW` | `SECURITY_OWNER_GATE` |
| `FORWARD_SKIPPED_REVIEW` | `PENDING_REVIEW` | `SECURITY_OWNER_GATE` |
| `HIGH_RISK_REVIEW` | `PENDING_REVIEW` | `SECURITY_OWNER_GATE` |
| `B2_SANDBOX_OBSERVED_CLEAN` | `PENDING_REVIEW` | `SECURITY_OWNER_GATE` |
| `B2_POLICY_REVIEW_REQUIRED` | `PENDING_REVIEW` | `SECURITY_OWNER_GATE` |
| `LOG_INCOMPLETE` | `PENDING_REVIEW` or `BLOCK` by policy | `SECURITY_OWNER_GATE` |
| `ERROR` | `ERROR` | `MANUAL_REVIEW_REQUIRED` |

초기 구현에서는 sandbox decision이 직접 `PASS`를 만들지 않는다. whitelist/pending 승인 이후의 `PASS` 승격은 sandbox 모듈이 아니라 orchestrator 또는 후속 review adapter가 별도 policy decision으로 처리한다.

`SANDBOX_INFRA_ERROR`와 `BLOCKED_RUNTIME_INVALID`는 구분한다.

- `SANDBOX_INFRA_ERROR`: Docker create/inspect가 실행 전 실패했거나, runsc runtime entry가 없거나, image digest 검증이 불가능해 untrusted code가 시작되지 않은 상태다. artifact 악성 증거가 아니므로 job은 `ERROR`다.
- `BLOCKED_RUNTIME_INVALID`: host evidence상 untrusted code가 정책과 다른 runtime, mount, env, capability 상태에서 이미 실행될 기회가 있었고 그 실행 결과를 신뢰할 수 없는 상태다. 이 경우 artifact 결과를 `BLOCK`으로 승격한다.

## 9. `sandbox/b2/repo_manifest.py`

### 9.1 책임

`repo_manifest.py`는 sandbox에 넣을 파일 집합을 고정하고 hash를 계산한다.

원본 Python 파일은 import하지 않는다.

sandbox 실행 단위는 artifact 1개당 1회다. 하나의 `B2SandboxCheck`는 하나의 `ArtifactValidationResult.details["sandbox_check"]`에만 대응한다. manifest는 primary B-2 artifact 1개와 그 artifact를 import하기 위해 필요한 repo 내부 dependency closure를 함께 담는다.

manifest에는 Python 파일과 read-only support 파일을 구분해 기록한다. Python 파일은 import 후보이고, support 파일은 config/metadata read 전용이다. support 파일은 B-2 승인 근거가 될 수 없다.

### 9.2 함수 시그니처

```python
from pathlib import Path
from analyzer.schemas import ArtifactValidationResult
from sandbox.b2.schemas import B2InputManifest

def build_b2_input_manifest(
    *,
    request_id: str,
    job_id: str,
    source_resolver: SnapshotSourceResolver,
    revision: str,
    policy_version: str,
    primary_result: ArtifactValidationResult,
    candidate_results: list[ArtifactValidationResult],
) -> B2InputManifest:
    ...

def write_manifest(manifest: B2InputManifest, output_path: Path) -> None:
    ...

def verify_manifest_files(manifest: B2InputManifest, source_resolver: SnapshotSourceResolver) -> list[str]:
    ...

def prepare_job_input_dir(
    *,
    source_resolver: SnapshotSourceResolver,
    manifest: B2InputManifest,
    output_dir: Path,
) -> Path:
    ...
```

`SnapshotSourceResolver`는 `model_snapshot_root`와 `model_snapshot_inventory` 양쪽을 모두 추상화한다. inventory-only job도 이 API로 staging할 수 있어야 한다. `prepare_job_input_dir()`는 `output_dir/input/` 아래에 staging directory를 만들고, resolver가 검증한 파일만 원래 상대 경로를 유지해 복사한다. 그 다음 canonical manifest JSON을 staging directory root의 `b2_input_manifest.json`으로 쓴다. Docker는 원본 repo root가 아니라 이 staging directory만 read-only bind mount한다.

### 9.3 포함 파일 규칙

포함 대상:

- B-2로 판정된 `modeling_*.py`
- `configuration_*.py`
- config 또는 tokenizer config에서 `auto_map`으로 참조된 `.py`
- repo 내부 relative import closure
- `__init__.py`
- local custom module
- model class instantiate에 필요한 read-only support 파일: `config.json`, `tokenizer_config.json`, `preprocessor_config.json`, `generation_config.json`, small JSON metadata

제외 또는 별도 review:

- repo 밖 symlink
- absolute path import
- `custom_pipelines`
- `tokenization_*.py`, `processing_*.py`, `image_processing_*.py`는 독립 자동 승인 대상에서 제외하고 preprocessing review로 표시

주의: tokenizer/processor 파일을 "승인 대상에서 제외"하는 것과 "sandbox input에서 제외"하는 것은 다르다. `modeling_*.py`의 relative import closure에 필요한 tokenizer/processor/helper 파일은 manifest와 staging directory에 포함한다. 다만 해당 파일의 의미 검증 결과는 modeling B-2 승인 근거로 쓰지 않고 별도 review signal로 남긴다.

support 파일을 "sandbox input에 포함"하는 것과 "Python import 후보로 취급"하는 것은 다르다. `B2ManifestFile.content_kind`는 `PYTHON`, `JSON_SUPPORT`, `TEXT_SUPPORT` 중 하나로 기록한다. support 파일은 entrypoint가 config 준비를 위해 읽을 수 있지만, import path나 module target으로 사용하지 않는다.

Python 파일은 다시 `import_allowed`와 `target_allowed`를 구분한다. primary B-2 artifact만 `target_allowed=true`이고, repo 내부 dependency closure의 Python 파일은 필요할 때 `import_allowed=true`, `target_allowed=false`다. Python import는 dependency module의 top-level code도 실행하므로, manifest에 포함되는 모든 `content_kind == "PYTHON"` 파일은 full `ArtifactValidationResult`를 가져야 한다. 하나라도 dangerous import/call/API, dynamic/obfuscation, dunder escape, context block이 있으면 B-2 sandbox를 실행하지 않는다.

support 파일의 `role`은 `SUPPORT`, `ast_grade`는 `N/A`, `validation_status`는 `SUPPORT_ONLY`, `unknown_apis`는 빈 목록으로 둔다. Python 파일만 `role`, `ast_grade`, `validation_status`, `unknown_apis`, `risk_flags`를 code validator 결과에서 채운다.

### 9.4 안전 규칙

구현자는 아래 체크를 넣는다.

- `SnapshotSourceResolver.resolve()`가 반환한 verified local path만 사용
- symlink가 repo 밖을 가리키면 manifest 생성 실패
- Python 파일 크기 상한 기본 5 MB
- support 파일 크기 상한 기본 1 MB
- 파일 개수 상한 기본 200개
- manifest에는 hash, size, role, grade, content kind, import_allowed, target_allowed, validation_status, unknown APIs를 기록

manifest hash 계산은 canonical JSON을 기준으로 한다.

```python
payload = json.dumps(manifest_without_hash, sort_keys=True, separators=(",", ":")).encode("utf-8")
manifest_sha256 = hashlib.sha256(payload).hexdigest()
```

deterministic hash 규칙:

- path는 POSIX `/` separator만 사용한다.
- `files`는 `(path, content_kind)` 기준으로 stable sort한다.
- normalized path 중복은 manifest error다.
- `manifest_sha256` field는 hash 계산에서 반드시 제외한다.
- enum/dataclass는 plain JSON dict로 변환한 뒤 hash를 계산한다.

## 10. `sandbox/b2/host_runner.py`

### 10.1 책임

host runner는 Docker/runsc 실행과 host-side evidence 수집을 담당한다.

컨테이너 내부 runner가 출력한 JSON은 diagnostic으로만 보관한다.

### 10.2 함수 시그니처

```python
from sandbox.b2.schemas import B2SandboxJob, B2SandboxCheck

def run_b2_sandbox(job: B2SandboxJob) -> B2SandboxCheck:
    ...

def build_docker_create_command(job: B2SandboxJob, manifest_container_path: str) -> list[str]:
    ...

def collect_host_artifacts(job: B2SandboxJob, container_id: str) -> dict[str, str]:
    ...
```

### 10.3 Docker lifecycle

`docker run --rm`을 사용하지 않는다. 종료 후 `docker inspect`, `docker logs`, `docker cp`가 필요하기 때문이다.

구현 순서:

1. output dir 생성
2. manifest 생성 및 hash 기록
3. staging directory와 manifest file host-side hash 재검증
4. `docker create`
5. `docker inspect` 수집
6. inspect validator 실행
7. 실행 전 inspect 실패 시 container 제거 후 `SANDBOX_INFRA_ERROR`
8. `docker start`
9. `docker wait` with host timeout
10. timeout이면 `docker kill`
11. `docker inspect` 재수집
12. post-start inspect validator 실행
13. `docker logs` 수집
14. `docker cp <container>:/tmp/huggingmask/runner_result.json` 시도
15. runsc log 매핑 및 복사
16. decision builder 실행
17. `docker rm -f`

### 10.4 Docker create command

기본 command는 아래 옵션을 만족해야 한다.

```text
docker create
  --name huggingmask-b2-<request_id>
  --runtime=<docker_runtime>
  --entrypoint /usr/bin/env
  --network=none
  --read-only
  --tmpfs /tmp:rw,nosuid,nodev,size=512m
  --cap-drop=ALL
  --security-opt=no-new-privileges
  --pids-limit=128
  --memory=4g
  --cpus=2
  --user=1000:1000
  -v <job_input_dir>:/sandbox/input:ro
  <image_ref>
  -i \
    PATH=/usr/local/bin:/usr/bin:/bin \
    PYTHONNOUSERSITE=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    TRANSFORMERS_OFFLINE=1 \
    HF_HUB_OFFLINE=1 \
    HOME=/tmp \
    HF_HOME=/tmp/hf \
    TORCH_HOME=/tmp/torch \
    XDG_CACHE_HOME=/tmp/cache \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    OMP_NUM_THREADS=4 \
    MKL_NUM_THREADS=4 \
    TORCH_NUM_THREADS=4 \
    HUGGINGMASK_REQUEST_ID=<request_id> \
    HUGGINGMASK_NONCE=<nonce> \
    /usr/local/bin/python -I -S /app/huggingmask_runner/b2_entrypoint.py \
    --manifest /sandbox/input/b2_input_manifest.json \
    --request-id <request_id>
```

host runner는 `docker create -e`로 환경변수를 전달하지 않는다. 컨테이너 프로세스는 `--entrypoint /usr/bin/env`와 `-i`로 비운 환경에서 시작하고, 위 allowlist만 command argv에 명시한다. Docker image 자체에 `ENTRYPOINT`가 있으면 command가 예상과 다르게 실행될 수 있으므로 반드시 `--entrypoint /usr/bin/env`를 지정한다. inspect 검증은 `Path`가 `/usr/bin/env`이고 `Args`가 `-i`와 allowlist env, trusted Python entrypoint로 구성되는지 확인한다.

Docker image 자체의 `Config.Env`에는 base image 기본값이 남을 수 있으므로 inspect 검증은 image baseline env와 runner command env allowlist를 분리해 검사한다.

`docker_runtime`은 하드코딩하지 않는다. `B2SandboxJob.docker_runtime` 또는 runtime policy에서 받은 Docker runtime 이름을 사용한다. 운영에서는 evidence용 runtime을 `runsc-b2` 또는 `runsc-debug`처럼 별도로 등록할 수 있다.

`PYTHONPATH`는 어떤 형태로도 컨테이너 실행 env나 `env -i` allowlist에 넣지 않는다. `/sandbox/input`은 비신뢰 repo 영역이므로 Python 시작 시점의 import path에 올라가면 안 된다. trusted runner가 manifest hash 검증을 끝낸 뒤 entrypoint 내부에서만 `/sandbox/input`을 `sys.path`에 추가한다.

`/usr/local/bin/python -I -S`를 쓰는 이유는 Python 시작 시 `PYTHONPATH`, user site, `sitecustomize.py` 자동 실행을 막기 위해서다. entrypoint의 top-level import는 stdlib-only로 유지한다. runner image 내부 dependency가 필요해지는 시점은 manifest 검증 이후이며, 그때 entrypoint 내부에서 trusted 경로만 명시적으로 추가한다.

### 10.5 차단 env

아래 env는 host에서 전달하지 않는다. `docker create -e`로 넘기지 않고, `--entrypoint /usr/bin/env` 뒤의 `-i` allowlist에도 넣지 않는다.

- `HF_TOKEN`
- `HUGGINGFACE_HUB_TOKEN`
- `GITHUB_TOKEN`
- `AWS_ACCESS_KEY_ID`
- `AWS_SECRET_ACCESS_KEY`
- `HTTP_PROXY`
- `HTTPS_PROXY`
- `ALL_PROXY`
- `NO_PROXY`
- `PIP_INDEX_URL`
- `PIP_EXTRA_INDEX_URL`
- `PYTHONSTARTUP`
- `PYTHONHOME`
- `PYTHONPATH`
- `LD_LIBRARY_PATH`
- `LD_PRELOAD`
- `CUDA_VISIBLE_DEVICES`

Docker image baseline에 기본 env가 존재하는 것은 허용할 수 있지만, 아래 이름이 `Config.Env` 또는 runner command allowlist에 나타나면 실패로 처리한다. `PYTHONPATH=/sandbox/input`도 금지한다. 모델 repo 경로는 Python 프로세스 시작 후, runner가 manifest를 검증한 다음에만 추가한다.

### 10.6 runsc 로그 설정

runsc 로그 파싱을 하려면 Docker daemon의 B-2용 gVisor runtime이 debug/strace 로그를 남기도록 먼저 설정되어 있어야 한다. 이 설정이 없으면 `runsc_log_parser.py`는 신뢰 가능한 입력을 받을 수 없고, sandbox 결과는 `LOG_INCOMPLETE`로 처리해야 한다.

Linux 운영 환경의 `/etc/docker/daemon.json` 예시:

```json
{
  "runtimes": {
    "runsc": {
      "path": "/usr/local/bin/runsc",
      "runtimeArgs": [
        "--debug",
        "--strace",
        "--debug-log=/var/log/huggingmask/runsc/runsc.%ID%.%COMMAND%.log"
      ]
    },
    "runsc-b2": {
      "path": "/usr/local/bin/runsc",
      "runtimeArgs": [
        "--debug",
        "--strace",
        "--debug-log=/var/log/huggingmask/runsc/runsc.%ID%.%COMMAND%.log"
      ]
    }
  }
}
```

운영 규칙:

- runsc log directory는 host root만 쓰기 가능해야 한다.
- host runner는 `container_id`와 runsc `%ID%` 로그 파일을 매핑한다.
- 매핑 실패 또는 로그 파일 누락은 `LOG_INCOMPLETE`다.
- 운영에서 strace 비용이 크면 policy로 sampling할 수 있지만, B-2 security evidence가 필요한 job은 반드시 활성화한다.

## 11. `sandbox/b2/inspect_validator.py`

### 11.1 책임

`docker inspect` 결과가 policy와 일치하는지 검증한다.

### 11.2 함수 시그니처

```python
from sandbox.b2.schemas import RuntimeEvidence

def validate_docker_inspect(
    inspect_payload: dict,
    *,
    expected_docker_runtime: str,
    expected_image_ref: str,
    expected_entrypoint: str,
    expected_pids_limit: int,
    expected_memory_limit: str,
    expected_cpu_limit: str,
) -> tuple[bool, RuntimeEvidence, list[str]]:
    ...
```

반환:

- `ok`: 모든 필수 runtime 조건 통과 여부
- `runtime_evidence`: host decision에 들어갈 evidence
- `errors`: 실패 reason code 목록

### 11.3 필수 검증

| 항목 | 기대값 |
|---|---|
| runtime | job/policy의 `docker_runtime` 값과 일치 |
| network mode | `none` |
| readonly rootfs | `true` |
| privileged | `false` |
| user | root가 아닌 UID/GID |
| cap add | 없음 |
| cap drop | `ALL` |
| no-new-privileges | enabled |
| bind mounts | `/sandbox/input` read-only만 허용 |
| writable mount | `/tmp` tmpfs만 허용 |
| entrypoint/path | `Path`가 `/usr/bin/env`이고 `Args[0]`가 `-i` |
| env | Docker `Config.Env`는 image baseline env만 허용. runner command의 `env -i` allowlist는 정책 env만 허용. 차단 env는 양쪽 모두 금지 |
| image | job의 digest 또는 ref와 일치 |
| pids limit | policy와 일치 |
| memory/cpu | policy와 일치 |

Docker inspect field mapping은 아래처럼 정규화한다.

- `HostConfig.Runtime == expected_docker_runtime`
- `HostConfig.NetworkMode == "none"`
- `HostConfig.ReadonlyRootfs is True`
- `HostConfig.Privileged is False`
- `HostConfig.Memory == parse_bytes(expected_memory_limit)` (`4g` -> `4294967296`)
- `HostConfig.NanoCpus == parse_cpus(expected_cpu_limit)` 또는 `CpuQuota/CpuPeriod` 환산값과 일치
- `HostConfig.PidsLimit == expected_pids_limit`
- `Path == "/usr/bin/env"`
- `Args[0] == "-i"`
- `Args` 안의 env assignment는 allowlist만 포함하고, trusted python entrypoint는 `/app/huggingmask_runner/b2_entrypoint.py` 절대 경로다.

실행 전 inspect 실패는 `SANDBOX_INFRA_ERROR`다. 이 단계에서는 untrusted code가 아직 시작되지 않았으므로 artifact 자체를 `BLOCK`으로 판단하지 않는다. 실행 후 재수집한 inspect에서 정책 위반 drift가 확인되거나, host evidence상 untrusted code가 잘못된 runtime/mount/env/capability 상태에서 실행된 정황이 있으면 `BLOCKED_RUNTIME_INVALID`로 승격할 수 있다.

## 12. `sandbox/b2/entrypoint.py`

### 12.1 책임

entrypoint는 컨테이너 내부에서 최소 실행을 수행한다.

이 결과는 diagnostic이다. 최종 보안 판정의 단독 근거가 아니다.

entrypoint는 image 내부 trusted 절대 경로에서 실행한다.

```text
docker create --entrypoint /usr/bin/env ... <image_ref> -i ... /usr/local/bin/python -I -S /app/huggingmask_runner/b2_entrypoint.py ...
```

entrypoint는 시작 직후 비신뢰 repo 경로를 import path에 올리지 않는다. 초기 단계의 top-level import는 Python stdlib만 허용한다. runner의 sibling module이 필요하면 entrypoint 안에서 `__file__` 기준 trusted directory를 계산해 추가하거나, `importlib.util.spec_from_file_location()`으로 절대 경로 로드한다.

### 12.2 실행 단계

1. manifest 로드
2. `/sandbox/input` 아래 파일 hash 재검증
3. trusted site-packages 경로만 `sys.path`에 추가
4. manifest 검증이 끝난 뒤 `/sandbox/input`을 `sys.path`에 추가
5. manifest의 `target.target_module` import
6. manifest의 `target.target_class`가 있으면 해당 class 선택, 없으면 model class 탐색
7. config 준비
8. class instantiate
9. optional dummy forward
10. `/tmp/huggingmask/runner_result.json` 기록
11. stdout에 nonce 포함 prefix 1회 출력

entrypoint는 filename heuristic으로 target class를 추정하지 않는다. `B2InputManifest.target`에 기록된 `target_module`, `target_class`, `auto_map_key`만 사용한다.

trusted dependency 경로 추가 예시:

```python
import sys
import sysconfig

for key in ("purelib", "platlib"):
    path = sysconfig.get_paths().get(key)
    if path and path not in sys.path:
        sys.path.append(path)
```

`site.main()`은 호출하지 않는다. `site.main()`은 site customization 흐름을 다시 활성화할 수 있어 비신뢰 repo가 import path에 섞인 경우 위험하다.

### 12.3 금지

entrypoint는 아래를 하지 않는다.

- `from_pretrained(..., trust_remote_code=True)` 호출
- 외부 다운로드
- pip install
- 대형 weight load
- 실제 추론 배치 실행
- 학습
- GPU 사용

### 12.4 runner result schema

```json
{
  "schema_version": "1.0",
  "request_id": "...",
  "nonce": "...",
  "manifest_verified": true,
  "import_status": "success|failed|skipped",
  "instantiate_status": "success|failed|skipped",
  "forward_status": "success|failed|skipped_schema_unknown",
  "exception_class": null,
  "exception_message": null
}
```

host runner는 이 파일을 `runner_diagnostics.json`으로 보관한다.  
decision builder는 이 값만으로 `BLOCK`을 내리지 않는다.

## 13. `sandbox/b2/runsc_log_parser.py`

### 13.1 책임

runsc debug/strace log에서 보안 이벤트 후보를 추출한다.

### 13.2 함수 시그니처

```python
def parse_runsc_logs(log_paths: list[str]) -> list[dict]:
    ...
```

반환 이벤트 형식:

```json
{
  "event_type": "execve|connect|socket|dns|open|openat|write|clone|unknown",
  "syscall": "openat",
  "path": "/proc/cpuinfo",
  "argv": ["sh"],
  "family": "AF_INET",
  "pid": 123,
  "raw": "short original log line"
}
```

### 13.3 파서 규칙

초기 구현은 완벽한 syscall parser가 아니어도 된다. 다만 아래 이벤트는 반드시 추출한다.

- `execve`
- `connect`
- `socket(AF_INET`
- `socket(AF_INET6`
- `sendto`, `recvfrom`, `sendmsg`, `recvmsg`
- `open`, `openat`
- `/etc/resolv.conf`, `/etc/hosts` read
- `write`, `creat`, `mkdir`, `rename`, `unlink`
- `clone`, `clone3`

DNS 시도는 `connect`만으로 보이지 않을 수 있다. UDP socket, resolver file read, `sendto`/`recvfrom`도 network review/block 후보 event로 남긴다.

## 14. `sandbox/b2/event_policy.py`

### 14.1 책임

runsc 이벤트와 Docker exit evidence를 block/review/allow로 분류한다.

### 14.2 함수 시그니처

```python
from sandbox.b2.schemas import SecurityEvents

def classify_security_events(
    events: list[dict],
    *,
    entrypoint_argv: list[str],
    pids_limit: int,
) -> SecurityEvents:
    ...
```

### 14.3 Hard-block 이벤트

아래 이벤트가 하나라도 있으면 `BLOCKED_SECURITY_EVENT`다.

| 이벤트 | 조건 |
|---|---|
| network | AF_INET/AF_INET6 socket, DNS, connect |
| unexpected execve | entrypoint Python 이후 `sh`, `bash`, `pip`, `curl`, `wget`, `gcc`, `make`, `cmake`, 별도 `python` |
| file write | `/tmp`, `/tmp/hf`, `/tmp/torch`, `/tmp/cache` 외 write |
| input write | `/sandbox/input` write |
| secret access | `/run/secrets`, mounted secret path, cloud credential path |
| docker socket | `/var/run/docker.sock` read/write |
| system path | `/sys`, `/dev/nvidia*`, GPU device |

manifest mismatch는 이 표에서 판정하지 않는다. host-side `ManifestEvidence.manifest_errors`와 `input_hash_errors`만 block 근거로 사용한다. 컨테이너 내부 `runner_result.json.manifest_verified=false`는 runner diagnostic 또는 review event로만 남긴다.

### 14.4 Review 이벤트

아래 이벤트는 단독 block이 아니라 review다.

| 이벤트 | 조건 |
|---|---|
| import syntax error | 기능 실패 |
| missing dependency | 기능 실패 |
| instantiate required arg 부족 | 기능 실패 |
| dummy forward schema mismatch | forward skipped |
| timeout without hard-block evidence | 기능 또는 resource review |
| OOM without fork/exec evidence | resource review |
| excessive thread | pids가 임계값 초과했지만 execve 없음 |
| `/proc/cpuinfo`, `/proc/meminfo` | baseline 초과 또는 사용자 코드 직접 접근 의심 |

### 14.5 허용 이벤트

아래는 기본 허용한다.

- `/sandbox/input` read
- Python stdlib read
- image 내부 `site-packages` read
- shared library load
- `/etc/ld.so.cache`
- `/etc/nsswitch.conf`
- `/dev/null`
- `/dev/urandom`
- `/proc/self`
- `/proc/<pid>` limited read
- PyTorch/OpenMP/MKL thread 생성

`/proc/cpuinfo`, `/proc/meminfo`는 정상 PyTorch 초기화에서 자주 발생하므로 기본 block이 아니다. 초기 구현은 count 기반으로 처리한다.

권장 기본값:

```python
PROC_INFO_REVIEW_THRESHOLD = 20
THREAD_REVIEW_THRESHOLD = 96
PIDS_LIMIT = 128
```

## 15. `sandbox/b2/decision_builder.py`

### 15.1 책임

host evidence를 하나의 `B2SandboxCheck`로 합친다.

### 15.2 함수 시그니처

```python
from sandbox.b2.schemas import (
    B2SandboxCheck,
    B2RuntimePolicy,
    RuntimeEvidence,
    ExecutionEvidence,
    SecurityEvents,
    ManifestEvidence,
    RunnerDiagnosticsStatus,
)

def build_b2_decision(
    *,
    request_id: str,
    job_id: str,
    artifact_id: str,
    repo_path: str,
    grade: str,
    sandbox_runtime: str | None,
    profile: str,
    created_at: str,
    runtime_evidence: RuntimeEvidence,
    execution: ExecutionEvidence,
    security_events: SecurityEvents,
    manifest_evidence: ManifestEvidence,
    artifacts: dict[str, str],
    pending_api_refs: list[str],
    runtime_policy: B2RuntimePolicy,
    runtime_setup_errors: list[str],
    post_start_runtime_errors: list[str],
    runner_diagnostics_status: RunnerDiagnosticsStatus,
    log_complete: bool,
) -> B2SandboxCheck:
    ...
```

### 15.3 판정 우선순위

판정 순서는 반드시 아래와 같다.

1. 실행 전 Docker/create/inspect/runtime setup 실패 -> `SANDBOX_INFRA_ERROR`
2. 실행 후 runtime/mount/env/capability drift 확인 -> `BLOCKED_RUNTIME_INVALID`
3. host-side manifest mismatch 또는 input hash mismatch -> `BLOCKED_SECURITY_EVENT`
4. hard-block security event -> `BLOCKED_SECURITY_EVENT`
5. log mapping 누락 또는 log incomplete -> `LOG_INCOMPLETE`
6. runner diagnostics missing/malformed/nonce mismatch -> `FUNCTIONAL_REVIEW_REQUIRED`
7. timeout + hard-block 없음 -> `FUNCTIONAL_REVIEW_REQUIRED`
8. OOM + hard-block 없음 -> `FUNCTIONAL_REVIEW_REQUIRED`
9. import/instantiate 기능 실패 -> `FUNCTIONAL_REVIEW_REQUIRED`
10. forward skipped/fail only -> `FORWARD_SKIPPED_REVIEW`
11. high-risk namespace event -> `HIGH_RISK_REVIEW`
12. pending API 남음 -> `B2_POLICY_REVIEW_REQUIRED`
13. sandbox clean + pending 없음 -> `B2_SANDBOX_OBSERVED_CLEAN`

`B2_SANDBOX_OBSERVED_CLEAN`도 단독 deployable이 아니다.

manifest mismatch는 컨테이너 내부 `runner_result.json`의 `manifest_verified`만으로 판정하지 않는다. host runner가 staging directory의 `b2_input_manifest.json`과 모든 input file hash를 직접 재검증하고, 그 결과를 `ManifestEvidence.manifest_errors`와 `ManifestEvidence.input_hash_errors`에 기록한다. decision builder는 이 두 목록 중 하나라도 비어 있지 않으면 runner diagnostic보다 먼저 `BLOCKED_SECURITY_EVENT`를 낸다.

`LOG_INCOMPLETE`의 global status는 `runtime_policy.log_incomplete_action`으로 결정한다. 초기 기본값은 `"review"`이며 `PENDING_REVIEW/SECURITY_OWNER_GATE`로 둔다. 운영 정책에서 `"block"`으로 올린 경우에만 `BLOCK/BLOCK_IMMEDIATELY`로 승격한다.

### 15.4 `deployable`

초기 구현에서 `deployable`은 항상 `False`다.

예외:

- whitelist/pending review가 승인 완료
- ML-BOM/audit 기록 완료
- security owner approval 기록 존재

위 조건이 모두 구현되기 전에는 `deployable=False`로 둔다. sandbox 모듈은 deployable을 `True`로 만들지 않는다. 승인 완료 후 deployable 승격은 후속 review adapter 또는 최종 orchestrator policy layer에서 수행한다.

## 16. analyzer 연결

### 16.1 `analyzer/orchestrator.py`

`run_validation_job`에 선택 인자를 추가한다. `source_loader`는 최신 dev의 orchestrator에서 필수 입력이므로 optional로 바꾸지 않는다.

```python
@dataclass(frozen=True)
class SandboxInputContext:
    request: ValidationJobRequest
    primary_result: ArtifactValidationResult
    all_results: list[ArtifactValidationResult]
    linked_parent_result: ArtifactValidationResult | None
    source_resolver: SnapshotSourceResolver
    output_base_dir: Path
    runtime_policy: B2RuntimePolicy


SandboxCheckLoader = Callable[[SandboxInputContext], dict[str, Any] | None]

LinkedCodeResultCollector = Callable[[ArtifactValidationResult], None]

def run_validation_job(
    request: ValidationJobRequest,
    *,
    source_loader: SourceLoader,
    whitelist_lookup: WhitelistLookup | None = None,
    runtime_check_loader: RuntimeCheckLoader | None = None,
    ast_call_metadata_loader: AstCallMetadataLoader | None = None,
    source_resolver: SnapshotSourceResolver | None = None,
    sandbox_check_loader: SandboxCheckLoader | None = None,
) -> ValidationJobResponse:
    ...
```

기존 `origin/dev`의 `whitelist_lookup`와 `ast_call_metadata_loader` 인자는 유지한다. sandbox hook 추가 때문에 기존 API/context 판단 입력 경로가 끊기면 B-2 대상 판정 자체가 달라진다.

처리 규칙:

1. 기존 code/config validator 실행
2. `CONFIG_JSON`/`TOKENIZER_CONFIG_JSON` 검증 중 auto_map 참조 Python을 검증하면 full `ArtifactValidationResult`를 sibling result로 승격
3. config result에는 기존처럼 `details["linked_code_results"]` summary를 남기되, 이 값은 sandbox 전 정적 검증 summary로 취급
4. 모든 direct/sibling artifact result를 만든 뒤 B-2 sandbox 대상인지 확인
5. B-2 대상인데 `sandbox_check_loader`가 없으면 structured `details["sandbox_check"].decision = "NOT_RUN"` 저장
6. loader가 있지만 `source_resolver`가 없으면 `NOT_RUN/SANDBOX_NOT_CONFIGURED`로 남기고 sandbox를 실행하지 않음
7. loader와 resolver가 모두 있으면 `SandboxInputContext`를 넘겨 sandbox 실행 결과를 `details["sandbox_check"]`에 저장
8. sandbox decision이 block이면 result status/review_action/reason_entries를 block으로 승격
9. sandbox decision이 review/clean이면 기존 `PENDING_REVIEW` 유지
10. sibling Python result의 sandbox 반영이 끝난 뒤 parent config result의 linked code summary를 다시 계산

`auto_map` linked code는 sandbox 이후 상태가 바뀔 수 있으므로 parent config result를 stale summary 상태로 두면 안 된다. orchestrator는 아래 후처리 helper를 둔다.

```python
def _refresh_config_linked_code_summary(
    config_result: ArtifactValidationResult,
    sibling_results: list[ArtifactValidationResult],
) -> None:
    ...
```

후처리 규칙:

- `config_result.details["linked_code_results"]`의 각 항목에 `post_sandbox_status`, `post_sandbox_review_action`, `sandbox_decision`을 추가한다.
- `config_result.details["linked_code_statuses"]`는 post-sandbox status 기준으로 갱신한다.
- 기존 정적 요약이 필요하면 `linked_code_statuses_static`과 `linked_code_results_static`에 복사해 보존한다.
- sibling 중 하나라도 `BLOCK`이면 config result도 `BLOCK/BLOCK_IMMEDIATELY`로 승격한다.
- sibling 중 하나라도 `ERROR`이면 config result도 `ERROR/MANUAL_REVIEW_REQUIRED`로 승격한다.
- sibling 중 하나라도 `PENDING_REVIEW`이면 config result는 `PENDING_REVIEW/SECURITY_OWNER_GATE`를 유지한다.
- 모든 linked Python이 `PASS`인 경우에만 config result가 기존 config scan 규칙에 따라 `PASS`가 될 수 있다.

`stop_on_first_block=True`여도 final result construction은 생략하지 않는다. 추가 artifact 실행은 중단할 수 있지만, 이미 확인된 block child, parent config의 non-PASS 상태, sandbox skip reason, unresolved linked child 여부는 결과에 남긴다.

`SandboxInputContext`가 필요한 이유는 `ArtifactValidationResult` 하나만으로는 `request_id`, `job_id`, `repo_id`, `revision`, `policy_version`, `runtime_context`, evidence output directory뿐 아니라 auto_map sibling, parent config, dependency closure 후보, verified local path를 알 수 없기 때문이다. sandbox loader는 `primary_result`만 보고 repo를 다시 임의 스캔하지 않는다. `all_results`와 `source_resolver`를 사용해 검증된 후보만 manifest에 넣는다.

`config.json -> auto_map -> Python`은 B-2의 주 경로이므로 nested dict에만 묻으면 안 된다. `validate_config_artifact()`에는 아래 선택 인자를 추가한다.

```python
def validate_config_artifact(
    artifact: ArtifactRef,
    source: str | bytes,
    policy: PolicyInfo | None = None,
    whitelist_lookup: WhitelistLookup | None = None,
    *,
    source_loader: SourceLoader | None = None,
    runtime_check_loader: RuntimeCheckLoader | None = None,
    ast_call_metadata_loader: AstCallMetadataLoader | None = None,
    linked_code_result_collector: LinkedCodeResultCollector | None = None,
) -> ArtifactValidationResult:
    ...
```

config validator가 referenced Python을 `validate_python_artifact()`로 검증한 직후 `linked_code_result_collector(code_result)`를 호출한다. collector는 `code_result.details["linked_from_config"] = artifact.repo_path`와 `code_result.artifact.referenced_by`를 유지한 뒤 orchestrator artifact result list에 sibling으로 추가한다. 이 sibling result가 B-2이면 일반 Python artifact와 동일하게 sandbox hook을 탄다.

최신 dev의 `build_artifact_ref(content=...)` 경로는 referenced Python의 `temp_local_path`를 실제 host temp path가 아니라 repo path로 채울 수 있다. B-2 manifest는 이 값을 신뢰하지 않는다. orchestrator는 sibling result를 sandbox에 넘기기 전에 `model_snapshot_inventory` 또는 `model_snapshot_root`로 실제 host path를 다시 resolve하고, hash가 `code_result.artifact.sha256`와 일치할 때만 manifest candidate로 사용한다. 실제 host path를 확인할 수 없으면 sibling result에는 `sandbox_check.decision = "NOT_RUN"`과 `SANDBOX_NOT_CONFIGURED` 또는 `MISSING_SOURCE` reason을 남기고 sandbox를 실행하지 않는다.

`auto_map`에서 추출한 target 정보는 sibling result에 반드시 남긴다.

```json
{
  "linked_from_config": "config.json",
  "auto_map_key": "AutoModelForCausalLM",
  "target_module": "modeling_demo",
  "target_class": "DemoForCausalLM",
  "target_repo_path": "modeling_demo.py"
}
```

동일 Python 파일이 여러 `auto_map` key에서 참조될 수 있으므로 sibling result는 `artifact_id` 기준으로 dedupe한다. parent config에는 key별 edge를 별도로 남긴다.

```json
{
  "linked_code_edges": [
    {
      "auto_map_key": "AutoModelForCausalLM",
      "artifact_id": "sha256:...",
      "repo_path": "modeling_demo.py",
      "target_class": "DemoForCausalLM",
      "post_sandbox_status": "PENDING_REVIEW",
      "sandbox_decision": "B2_POLICY_REVIEW_REQUIRED"
    }
  ]
}
```

### 16.2 B-2 대상 판정 함수

`analyzer/orchestrator.py` 또는 별도 helper에 추가한다.

```python
def _requires_b2_sandbox(result: ArtifactValidationResult) -> bool:
    details = result.details
    role = (details.get("role_classification") or {}).get("role")
    ast_scan = details.get("ast_scan") or {}
    api_scan = details.get("api_scan") or {}
    context_scan = details.get("context_api_scan") or {}
    grade_result = details.get("grade_result") or {}

    has_b2_reason = (
        bool(details.get("pending_api_refs"))
        or context_scan.get("summary_decision") == "review"
        or (
            grade_result.get("requires_runtime_gate") is True
            and grade_result.get("status") == "PENDING_REVIEW"
        )
    )

    return (
        result.artifact.file_kind == FileKind.PYTHON
        and result.route_kind == RouteKind.CODE_SANDBOX_RUNTIME
        and result.grade == CodeGrade.B2
        and result.status == ValidationStatus.PENDING_REVIEW
        and result.review_action == ReviewAction.SECURITY_OWNER_GATE
        and role == "MODELING"
        and context_scan.get("summary_decision") != "block"
        and not ast_scan.get("dangerous_imports")
        and not ast_scan.get("dangerous_calls")
        and not ast_scan.get("dynamic_patterns")
        and not ast_scan.get("obfuscation_patterns")
        and not api_scan.get("blocked_apis")
        and has_b2_reason
    )
```

이 helper는 route/grade만 보지 않는다. `configuration_*.py`, tokenizer/processor/helper, unknown role, dynamic/obfuscation, 위험 API가 섞인 결과가 modeling B-2 sandbox로 들어가면 안 되기 때문이다. enum 비교는 deserialization/cache round-trip을 고려해 `==`를 사용한다. dependency closure에 포함되는 파일과 primary sandbox 대상 파일은 구분한다.

구현 규칙:

- orchestrator와 service는 `result.route_kind == CODE_SANDBOX_RUNTIME` 조건만으로 sandbox runner를 호출하지 않는다.
- `requested_routes`는 실행 희망 route를 나타내는 입력일 뿐 sandbox 실행 권한 부여 근거가 아니다.
- `C/PENDING_REVIEW`, `CONFIGURATION`, `PREPROCESSING`, `AUXILIARY`, `UNKNOWN` 결과는 같은 route kind를 가져도 primary B-2 sandbox 대상이 아니다.
- B-2 대상이 아니지만 review가 필요한 결과에는 `sandbox_check = null` 또는 field absent를 허용한다. B-2 대상인데 runner/resolver가 없을 때만 `sandbox_check.decision = "NOT_RUN"`을 남긴다.
- dependency closure에 포함되는 Python 파일은 `target_allowed=false`로 stage할 수 있지만, 그 파일도 full `ArtifactValidationResult`가 있고 정적 위험 신호가 없어야 한다.
- dependency closure를 resolve하거나 검증하지 못하면 whole-repo mount로 대체하지 않고 sandbox를 실행하지 않는다.

### 16.3 reason code 추가

공통 reason code가 아직 없다면 `details["sandbox_check"]["decision"]`에만 기록한다.  
추가가 가능하면 아래 reason code를 쓴다.

| reason code | 의미 |
|---|---|
| `SANDBOX_NOT_CONFIGURED` | B-2 sandbox runner가 설정되지 않아 실행하지 않음 |
| `SANDBOX_INFRA_NOT_STARTED` | 실행 전 Docker/runsc/image/inspect 준비 실패 |
| `SANDBOX_RUNTIME_DRIFT_AFTER_START` | 실행 후 runtime/mount/env/capability 정책 위반 확인 |
| `SANDBOX_SECURITY_EVENT` | sandbox hard-block 이벤트 |
| `SANDBOX_FUNCTIONAL_REVIEW` | 기능 실패로 리뷰 필요 |
| `SANDBOX_LOG_INCOMPLETE` | runsc log 불완전 |
| `SANDBOX_OBSERVED_CLEAN` | hard-block event 없음 |
| `SANDBOX_POLICY_GATE_REQUIRED` | sandbox clean 이후 정책 승인 필요 |

## 17. whitelist/pending 연결

B-2 sandbox는 whitelist를 직접 승인하지 않는다.

연결 흐름:

1. code validator가 `pending_api_refs` 생성
2. sandbox가 clean 또는 review 결과 생성
3. 초기 구현은 `ArtifactValidationResult.details["sandbox_check"]`와 `details["pending_api_refs"]`에 evidence를 남긴다
4. 후속 adapter가 `pending_api_refs`를 `PendingApiUpsertRequest`로 변환한다
5. review owner가 승인 또는 거절한다
6. 승인된 API만 whitelist rule로 승격한다
7. 다음 검증부터 B-1 또는 approved B-2로 처리 가능하다

초기 B-2 sandbox 구현은 `whitelist.pending_store`를 직접 호출하지 않는다. 현재 `PendingApiRecord` 계약에 sandbox-specific field가 없다면 `sandbox_decision`, `sandbox_artifacts`, `artifact_id`, `revision`, `request_id`는 pending store에 억지로 넣지 말고 `sandbox_check.policy_gate`, `sandbox_check.artifacts`, review queue entry, 또는 별도 `SandboxEvidenceRecord`에 남긴다.

초기 구현 테스트는 이 경계를 고정한다.

- `tests/test_b2_policy_boundary.py::test_sandbox_does_not_call_pending_store`
- `tests/test_b2_policy_boundary.py::test_pending_refs_remain_in_result_after_clean_sandbox`

후속 pending/review adapter가 매핑해야 할 정보:

- `api_path`
- `repo_id`
- `revision`
- `artifact_id`
- `request_id`
- `job_id`
- `sandbox_decision`
- `sandbox_artifacts`
- `sample_callsite`
- `risk_keywords`
- `review_status = PENDING`

## 18. image 설계

### 18.1 `sandbox/image/b2/Dockerfile`

초기 Dockerfile 요구사항:

```Dockerfile
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONNOUSERSITE=1

RUN useradd -u 1000 -m sandboxuser

WORKDIR /app
COPY sandbox/b2/entrypoint.py /app/huggingmask_runner/b2_entrypoint.py
COPY sandbox/image/b2/requirements.txt /app/requirements.txt

RUN pip install --no-cache-dir --require-hashes -r /app/requirements.txt

USER 1000:1000
WORKDIR /app
```

runner는 `/app/huggingmask_runner/` 아래 trusted 경로에 둔다. 컨테이너 시작 command는 module import가 아니라 absolute script path를 사용한다. `/sandbox/input`을 `WORKDIR`로 두지 않는다. 현재 작업 디렉터리가 비신뢰 repo이면 Python의 import path와 상대 파일 접근 해석이 오염될 수 있기 때문이다. `b2_entrypoint.py`는 `python -I -S`에서 동작하도록 top-level stdlib-only로 유지한다.

`sandbox/image/b2/requirements.txt`는 version pin과 hash pin을 사용한다. 초기 개발에서 hash pin이 어렵다면 최소 version pin을 먼저 적용하되, Linux e2e와 운영 이미지는 digest로만 참조한다.

운영 이미지는 digest로 고정한다. `inspect_validator.py`는 운영 모드에서 tag-only image ref를 실패로 처리한다.

```text
huggingmask-b2-sandbox@sha256:<digest>
```

### 18.2 SBOM/서명

초기 구현은 SBOM/서명 파일을 artifact로 남기기만 한다.

필드:

- `image_digest`
- `sbom_path`
- `signature_path`
- `image_policy_version`

서명 검증이 구현되기 전에는 `image_signature_verified=false`를 기록하고 `deployable=false`를 유지한다.

## 19. 운영 환경

gVisor/runsc 운영은 Linux Docker 기준이다.

Windows 또는 macOS 개발자는 아래 중 하나를 사용한다.

- WSL2 Linux Docker
- remote Linux host
- CI Linux runner

로컬 Windows 환경에서는 아래 테스트만 수행한다.

- manifest 생성
- Docker command build
- inspect payload fixture 검증
- runsc log fixture 파싱
- decision builder
- orchestrator sandbox loader mock

실제 runsc e2e는 Linux 환경에서만 실행한다.

## 20. 테스트 계획

### 20.1 Unit tests

| 파일 | 테스트 |
|---|---|
| `tests/test_b2_repo_manifest.py` | manifest hash, symlink escape 차단, import closure, path stable sort, duplicate path error |
| `tests/test_b2_inspect_validator.py` | runsc/network/mount/env/cap 검증, memory/cpu 단위 정규화, entrypoint/args 검증 |
| `tests/test_b2_event_policy.py` | network, DNS resolver, execve, write, proc, thread 분류 |
| `tests/test_b2_decision_builder.py` | decision priority, runner diagnostics missing/malformed/nonce mismatch, log incomplete policy |
| `tests/test_b2_host_runner_command.py` | docker create command option 고정, configured `docker_runtime` 사용, `docker create -e` 미사용, `--entrypoint /usr/bin/env` 사용, `env -i` allowlist 고정, `PYTHONPATH` 미전달, absolute trusted entrypoint 사용 |
| `tests/test_b2_policy_boundary.py` | sandbox가 pending_store를 직접 호출하지 않음, clean 이후 pending refs 유지 |
| `tests/test_code_ast.py` | dangerous dunder extraction |
| `tests/test_code_validator.py` | dunder pattern이 B-2로 가지 않음, B-1 runtime failure status별 grade/review 분기 |
| `tests/test_validation_flow.py` | direct B-2와 auto_map sibling B-2 결과에 sandbox_check 부착, route-only sandbox 호출 금지, sandbox 후 parent config linked summary 갱신, duplicate auto_map dedupe |
| `tests/test_validation_jobs.py` | snapshot resolver 입력 계약, service overall status/release_action 매핑, all-skipped non-pass, snapshot 없는 auto_map parent PASS 금지 |

### 20.2 Fixture scenarios

추가 fixture 경로:

```text
tests/fixtures/b2_sandbox/
  b2_01_clean_new_torch_api/
  b2_02_network_import_block/
  b2_03_unexpected_execve/
  b2_04_input_write_block/
  b2_05_forward_schema_mismatch/
  b2_06_timeout_no_event/
  b2_07_runtime_invalid/
  b2_08_log_incomplete/
  b2_09_proc_cpuinfo_baseline/
  b2_10_dangerous_dunder_static_block/
  b2_11_route_kind_only_not_sandboxed/
  b2_12_config_auto_map_missing_snapshot/
  b2_13_runtime_fail_not_escalated_to_b2/
```

### 20.3 Expected outcomes

| ID | 시나리오 | 기대 결과 |
|---|---|---|
| B2-01 | 신규 `torch.nn.*` API, hard-block 없음 | `B2_POLICY_REVIEW_REQUIRED` |
| B2-02 | import 시점 network | `BLOCKED_SECURITY_EVENT` |
| B2-03 | `sh` 또는 `pip` execve | `BLOCKED_SECURITY_EVENT` |
| B2-04 | `/sandbox/input` write | `BLOCKED_SECURITY_EVENT` |
| B2-05 | dummy forward schema mismatch | `FORWARD_SKIPPED_REVIEW` |
| B2-06 | timeout, hard-block 없음 | `FUNCTIONAL_REVIEW_REQUIRED` |
| B2-07 | 실행 전 runtime 설정 누락 또는 inspect 실패 | `SANDBOX_INFRA_ERROR` |
| B2-07b | 실행 후 runtime/mount/env drift 확인 | `BLOCKED_RUNTIME_INVALID` |
| B2-08 | runsc log 매핑 누락 | `LOG_INCOMPLETE` |
| B2-09 | 정상 PyTorch `/proc/cpuinfo` read | allow 또는 review threshold 이하 |
| B2-10 | `__subclasses__` escape chain | sandbox 실행 전 `C/PENDING_REVIEW` 또는 `BLOCK` |
| B2-11 | route kind만 `CODE_SANDBOX_RUNTIME`이고 role/grade/status 조건 불일치 | sandbox 미실행 |
| B2-12 | `config.json -> auto_map` referenced Python이 있지만 snapshot resolve 불가 | parent config `PASS` 금지, linked Python `NOT_RUN/MISSING_SOURCE` |
| B2-13 | B-1 runtime `FAIL`에 blocked audit event 존재 | B-2 실행 없이 `BLOCK` 또는 `C/PENDING_REVIEW` |

## 21. 구현 순서

### Phase 0 - 최신 dev schema/service 계약 고정

수정:

- `analyzer/schemas.py`
- `analyzer/service.py`
- `tests/test_validation_jobs.py`

완료 기준:

- `ValidationJobRequest`가 `model_snapshot_root`와 `model_snapshot_inventory`를 optional field로 받는다.
- `SnapshotFileRef`가 repo-relative path, host temp path, sha256, size를 표현한다.
- service가 payload artifact와 snapshot inventory를 합쳐 `SnapshotSourceResolver`를 만든다.
- resolver가 path escape, untrusted local path, size mismatch, sha256 mismatch를 구분해 반환한다.
- snapshot이 없는 `config.json -> auto_map` 입력은 `PASS`가 아니라 `PENDING_REVIEW/MISSING_SOURCE`가 된다.
- loader 경로 탈출 또는 hash mismatch는 `ERROR`가 된다.
- `source_loader`와 `ArtifactRef.temp_local_path`만으로 B-2 manifest를 만들지 않는다.

### Phase 1 - 정적 우회 차단

수정:

- `analyzer/validators/common_security_policy.py`
- `analyzer/validators/code_ast.py`
- `tests/test_code_ast.py`
- `tests/test_code_validator.py`

완료 기준:

- dangerous dunder 접근이 `dynamic_patterns`에 기록된다.
- dunder escape 코드는 B-2 sandbox로 가지 않는다.

### Phase 2 - B-2 schema와 manifest

추가:

- `sandbox/b2/schemas.py`
- `sandbox/b2/repo_manifest.py`
- `tests/test_b2_repo_manifest.py`

완료 기준:

- primary B-2 artifact와 repo 내부 dependency closure가 manifest로 생성된다.
- manifest builder는 `repo_root` 단독 전제가 아니라 `SnapshotSourceResolver` 기반으로 동작한다.
- `B2Target`이 auto_map key, target module, target class를 기록한다.
- 모든 Python dependency는 full validator result를 갖고, 위험 신호가 있으면 sandbox 실행 전 중단된다.
- repo 밖 symlink가 차단된다.
- manifest hash가 deterministic하다.

### Phase 3 - inspect validator와 event policy

추가:

- `sandbox/b2/inspect_validator.py`
- `sandbox/b2/event_policy.py`
- `sandbox/b2/runsc_log_parser.py`
- 관련 tests

완료 기준:

- fixture inspect JSON으로 실행 전 infra error와 실행 후 runtime drift를 구분한다.
- fixture runsc log로 network/DNS/execve/write event를 분류한다.

### Phase 4 - decision builder

추가:

- `sandbox/b2/decision_builder.py`
- `tests/test_b2_decision_builder.py`

완료 기준:

- 판정 우선순위가 테스트로 고정된다.
- host-side manifest/input hash error가 runner diagnostic보다 먼저 `BLOCKED_SECURITY_EVENT`가 된다.
- runner diagnostics missing/malformed/nonce mismatch는 clean으로 내려가지 않는다.
- `LOG_INCOMPLETE`는 runtime policy에 따라 review/block으로 매핑된다.
- clean이어도 deployable은 false다.

### Phase 5 - host runner command

추가:

- `sandbox/b2/host_runner.py`
- `tests/test_b2_host_runner_command.py`

완료 기준:

- `docker create` 옵션이 policy와 일치한다.
- `--runtime`은 하드코딩된 `runsc`가 아니라 job/policy의 `docker_runtime` 값을 사용한다.
- image `ENTRYPOINT` 오염을 막기 위해 `--entrypoint /usr/bin/env`를 사용한다.
- `--rm`을 쓰지 않는다.
- `docker create -e`로 host env를 전달하지 않는다.
- `env -i` allowlist만 사용한다.
- `PYTHONPATH`를 전달하지 않는다.
- command가 `/app/huggingmask_runner/b2_entrypoint.py` 절대 경로를 사용한다.
- command builder는 shell string이 아니라 `list[str]`를 반환하고 `subprocess.run(..., shell=False)`로 실행한다.
- env allowlist가 고정된다.

### Phase 6 - analyzer 연결

수정:

- `analyzer/orchestrator.py`
- `analyzer/schemas.py`는 필요한 경우만 확장
- `tests/test_validation_flow.py`

완료 기준:

- B-2 결과에 `details["sandbox_check"]`가 붙는다.
- 기존 `run_validation_job()`의 `whitelist_lookup`, `ast_call_metadata_loader` 입력 경로가 유지된다.
- `config.json -> auto_map -> modeling_*.py` referenced code result가 sibling `ArtifactValidationResult`로 승격된다.
- auto_map sibling B-2 결과에도 `details["sandbox_check"]`가 붙는다.
- sibling sandbox 결과가 반영된 뒤 parent config `linked_code_statuses`와 `linked_code_results`가 post-sandbox 기준으로 갱신된다.
- duplicate auto_map reference는 artifact_id 기준으로 dedupe되고 key별 edge는 보존된다.
- sibling Python의 실제 host path는 `model_snapshot_inventory` 또는 `model_snapshot_root`에서 resolve하고 hash를 재검증한다.
- sandbox block decision이 artifact result를 `BLOCK`으로 승격한다.
- sandbox clean은 `PASS`가 아니라 `PENDING_REVIEW` 유지다.

### Phase 7 - Linux runsc e2e

Linux 환경에서만 실행:

- policy에 지정한 Docker runtime(`runsc`, `runsc-b2` 등) 설치와 daemon 등록 확인
- image build
- B2-01 clean scenario
- B2-02 network block scenario
- B2-07 runtime setup invalid scenario

완료 기준:

- evidence 파일이 `evidence/sandbox/<date>_<request_id>/`에 남는다.
- `docker inspect`, `runsc log`, `host_decision`, `b2_input_manifest` hash가 기록된다.

## 22. 완료 기준

B-2 구현은 아래를 모두 만족해야 완료로 본다.

- sandbox runner 호출은 `_requires_b2_sandbox()`를 통과한 결과에만 발생한다.
- `CODE_SANDBOX_RUNTIME` 단독 조건으로는 sandbox를 실행하지 않는다.
- 정적 우회 패턴이 B-2로 들어가지 않는다.
- B-1 `runtime_check`와 B-2 `sandbox_check`가 분리되어 저장된다.
- B-1 runtime `FAIL/TIMEOUT/MEMORY_LIMIT/ERROR`가 status/reason별로 분기된다.
- B-2 clean 결과가 단독 `PASS`가 되지 않는다.
- `config.json -> auto_map -> Python` sibling 결과가 parent config summary에 post-sandbox 기준으로 반영된다.
- snapshot resolver 없이 auto_map sibling을 sandbox에 넣지 않는다.
- unresolved dependency closure를 whole-repo mount로 대체하지 않는다.
- `stop_on_first_block=True`에서도 parent/child 결과와 skip reason이 보존된다.
- Docker runtime 설정은 host-side `docker inspect`로 검증한다.
- 컨테이너 내부 stdout/runner JSON은 diagnostic으로만 저장한다.
- `docker run --rm` 대신 create/start/wait/inspect/logs/cp/rm lifecycle을 사용한다.
- network, unexpected execve, 비허용 write, secret access는 block된다.
- PyTorch 정상 thread/proc read baseline은 false positive를 줄이도록 허용 또는 review threshold로 처리한다.
- pending API는 whitelist 승인 전 자동 allow로 승격하지 않는다.
- Windows 개발 환경에서도 unit test는 돌고, Linux에서만 runsc e2e가 돈다.

## 23. 구현자가 처음 열 파일

구현 시작 시 아래 순서로 파일을 열고 작업한다.

1. `docs/gVisor_공통_운영_원칙.md`
2. `docs/B-2_gVisor_구현_상세_설계서.md`
3. `docs/code_validation_plans/00_공통_범위와_담당경계.md`
4. `analyzer/schemas.py`
5. `analyzer/validators/code_validator.py`
6. `analyzer/validators/code_ast.py`
7. `analyzer/validators/config_validator.py`
8. `analyzer/orchestrator.py`
9. `whitelist/pending_store.py`
10. `sandbox/README.md`

이 문서의 Phase 순서대로 구현하면 된다.
