# 단계 3 - API Context Policy

## 목적

AST에서 추출한 호출을 API 단위로 해석하고, 정책 순서에 따라 `ALLOWED`, `BLOCKED`, `UNREGISTERED`, `CONTEXTUAL`로 분류한다. 문맥 의존 API 분석은 독립 단계가 아니라 검증 2 `API_POLICY_SCAN` 내부 하위 단계이며, context analyzer로 보내 `safe/review/block`을 판정한다.

## 구현 반영 상태 (2026-04-21)

- 상태: 완료. API 호출 해석, 정책 분류, 문맥 의존 API 분석이 구현되어 `api_scan`, `context_api_scan`, `pending_api_refs` 후보를 만든다.
- 경계: 정식 whitelist DB는 없으며, 선행 구현용 protocol/in-memory policy로만 연결한다. pending API는 persistent store가 아니라 `pending_api_refs`와 `review_findings` 입력으로 남긴다.

## 담당 범위

코드검증이 직접 구현한다.

- alias resolution
- blocked exact/prefix 및 위험 범주 선차단
- allowed exact 기반 허용 판정
- unregistered API 수집
- contextual API 매칭과 `code_context.py` 디스패처 호출
- `WhitelistLookup` protocol
- 선행 구현용 in-memory whitelist adapter
- `pending_api_refs` 후보 생성
- `api_scan`, `context_api_scan` detail 생성

## 비범위

- 정식 whitelist DB 구현
- 미등록 API persistent pending store
- 공식 문서 등재 여부 crawling
- Verified Org 사용 여부 판단
- 보안 담당자 승인 workflow
- LLM 기반 승인 판정
- prefix allowlist를 넓게 열어 운영 정책을 확정하는 작업

## 입력

- `AstScanResult.raw_api_calls`
- `AstScanResult.imports`
- `AstScanResult.contextual_api_candidates`
- `RoleClassification`
- `PolicyInfo`
- `WhitelistLookup`

## 출력

구현 단계 출력 예시:

- `ApiScanResult`
  - `allowed`
  - `blocked`
  - `unregistered`
  - `contextual`
  - `alias_resolution`
  - `policy_version`
  - `pending_api_refs`
- `ContextApiScanResult`
  - `open_calls`
  - `os_calls`
  - `path_helper_calls`
  - `env_access_calls`
  - `network_calls`
  - `file_mutation_calls`
  - `command_exec_calls`

context analyzer의 개별 결과 필드:

- `api`
- `category`
- `decision`: `safe`, `review`, `block`
- `reason_code`
- `evidence`

## 생성/수정 파일

문서 분리 작업에서 생성하는 파일:

- `docs/code_validation_plans/03_api_context_policy.md`

구현 단계에서 생성/수정할 파일:

- `analyzer/validators/code_api.py`
- `analyzer/validators/code_api_policy.py`
- `analyzer/validators/code_context.py`
- `tests/test_code_api.py`
- `tests/test_code_context.py`

## 구현 규칙

- 검증 2 판정 순서는 고정한다.
  1. 호출 대상 해석 실패 + 동적/난독화 패턴 존재
  2. `blocked_exact` 또는 `blocked_prefix`
  3. 네트워크/프로세스/역직렬화/native loading 위험 범주
  4. `contextual_exact` 또는 `contextual_prefix`
  5. `allowed_exact`
  6. 그 외 `UNREGISTERED`
- `BLOCKED`와 위험 범주는 `ALLOWED`보다 항상 우선한다.
- `torch.nn.*`, `torch.nn.functional.*`, `torch.Tensor.*` 같은 넓은 prefix allowlist를 초기 구현에 넣지 않는다.
- 초기 allowlist는 exact API 중심으로 둔다.
- prefix rule이 반드시 필요하면 좁은 namespace만 쓰고 `allowed_by_prefix` detail을 남긴다.
- `load`, `save`, `open`, `download`, `exec`, `compile`, `jit`, `distributed`, `rpc`, `hub` 같은 위험 keyword가 있으면 prefix로 자동 허용하지 않는다.
- `requests`, `urllib`, `httpx`, `socket` 같은 네트워크 API는 모델 코드 내부에서 기본 `BLOCK`이다.
- `torch.load`, `pickle.load`, `numpy.load`는 whitelist 질의 전에 `BLOCK` 가능하다.
- 문맥 의존 API의 실제 판정은 이 검증 2 내부에서 한다.
- 문맥 의존 API 분석은 B-2로 보낸 뒤 하는 검사가 아니라 B-1 후보 유지 / B-2 전환 / BLOCK을 가르는 하위 분석이다.
- `open`, `os.path`, `Path`는 이름만으로 `DANGEROUS_CALL`에 넣지 않고 `CONTEXTUAL`로 라우팅한다.
- context analyzer 결과가 `safe`이면 B-1 후보를 유지할 수 있다.
- context analyzer 결과가 `review`이면 B-2/PENDING_REVIEW 후보로 올린다.
- context analyzer 결과가 `block`이면 즉시 `BLOCK` 후보로 올린다.
- `WhitelistLookup` protocol은 연결용 최소 구조만 제공하고, 정식 DB 저장소를 만들지 않는다.

## 테스트

추가할 pytest:

- `tests/test_code_api.py`
- `tests/test_code_context.py`

API 정책 케이스:

- `import torch.nn.functional as F`; `F.relu(x)` -> `torch.nn.functional.relu` allowed
- `from torch import nn`; `nn.Linear(...)` -> `torch.nn.Linear` allowed
- `torch.load(path)` -> blocked
- `pickle.load(f)` -> blocked
- `numpy.load(path)` -> blocked
- `torch.special.expit(x)` -> unregistered
- `requests.get(url)` -> blocked
- blocked exact가 prefix allow보다 우선
- broad prefix allowlist 없이 unknown API가 unregistered로 남음

context 케이스:

- `open("vocab.json", "r")` -> role에 따라 `safe` 또는 `review` 후보
- `open(user_input, "w")` -> `block`
- `os.path.join(a, b)` -> path helper 결과
- `os.getenv("X")` 또는 `os.environ.get("X")` -> `review`
- `os.system("ls")` -> `block`
- `Path("x").read_text()` -> role/경로 기준 `safe` 또는 `review`
- `Path("x").write_text(...)` -> `block`

## 완료 기준

- API scan 결과가 serialize 가능한 dict로 남는다.
- context analyzer가 API 유형별 함수로 분리되어 있다.
- `WhitelistLookup` in-memory adapter만으로 테스트가 가능하다.
- 미등록 API가 `pending_api_refs` 후보로 남는다.
- 명확한 위험 API는 sandbox나 runtime 단계로 보내지 않고 `BLOCK` 후보가 된다.

## 다음 단계 연결

단계 4는 role, AST, API, context 결과를 합쳐 A/B-1/B-2/C와 상태값을 결정한다. 특히 `context_api_scan.decision`과 `pending_api_refs`는 B-1 유지, B-2 전환, BLOCK 판정의 직접 입력이 된다.
