# 단계 2 - Code Role AST

## 목적

Python 파일을 실행하지 않고 역할을 분류하고, AST만으로 위험 후보와 API 호출 후보를 추출한다. 이 단계는 검증 1: AST 후보 추출(`CODE_AST_SCAN`)에 해당하며, 이후 API 정책 검사와 등급 판정의 입력을 만든다.

## 담당 범위

코드검증이 직접 구현한다.

- Python 파일 역할 분류
- `CONFIGURATION`, `MODELING`, `PREPROCESSING`, `AUXILIARY`, `UNKNOWN` role 산출
- `PREPROCESSING`의 `preprocess_kind` 산출
- `AUXILIARY`의 subtype 산출
- import 목록, class/base class, function/method 목록 추출
- `forward`, `generate`, `__call__`, `__init__` 존재 여부 추출
- 위험 import/call 후보 추출
- 동적/난독화 패턴 추출
- API raw call path 추출
- 문맥 의존 API 후보 추출

## 비범위

- 원본 Python 파일 import 또는 실행
- `from_pretrained(..., trust_remote_code=True)` 호출
- 문맥 의존 API의 `safe/review/block` 판정
- whitelist 조회 또는 allowed/blocked/unregistered 최종 판정
- A/B-1/B-2/C 최종 등급 결정
- tokenizer/processor 의미 검증
- 보조/변환/패키징형 자동 승인 정책

## 입력

- `ArtifactRef(file_kind="PYTHON")`
- Python source text
- repo path와 file name
- 선택 입력: 이미 파싱된 AST는 허용하지 않는다. 단계 내부에서 source text에 대해 `ast.parse()`를 수행한다.

## 출력

구현 단계 출력 예시:

- `RoleClassification`
  - `role`
  - `preprocess_kind`
  - `auxiliary_kind`
  - `confidence`
  - `reasons`
- `AstScanResult`
  - `imports`
  - `classes`
  - `functions`
  - `base_classes`
  - `method_flags`
  - `dangerous_imports`
  - `dangerous_calls`
  - `dynamic_patterns`
  - `obfuscation_patterns`
  - `raw_api_calls`
  - `contextual_api_candidates`
  - `parse_error`

`ArtifactValidationResult.details` 연결 시 하위 key:

- `role_classification`
- `ast_scan`

## 생성/수정 파일

문서 분리 작업에서 생성하는 파일:

- `docs/code_validation_plans/02_code_role_ast.md`

구현 단계에서 생성/수정할 파일:

- `analyzer/validators/__init__.py`
- `analyzer/validators/code_roles.py`
- `analyzer/validators/code_ast.py`
- `tests/test_code_roles.py`
- `tests/test_code_ast.py`

## 구현 규칙

- 원본 Python 모델 파일은 검증 단계에서 import하지 않는다.
- 검증 1단계는 `ast.parse()`만 사용한다.
- source text 읽기와 AST node 순회는 허용하지만 top-level 코드를 실행하면 안 된다.
- AST parse error는 안전한 통과가 아니라 `BLOCK` 가능한 reason 또는 `ERROR` 후보로 표현한다.
- 문맥 의존 API는 이 단계에서 후보로만 추출한다.
- `open`, `os.path`, `Path.read_text`, `Path.open`, `os.getenv`, `os.environ` 등은 `safe/review/block`으로 판정하지 않는다.
- `PREPROCESSING`, `AUXILIARY`, `UNKNOWN`은 1차 구현에서 자동 승인 후보가 아니다.
- `__init__.py`는 이름만으로 즉시 차단하지 않는다. export-only인지, top-level 실행/동적 import/외부 접근이 있는지 AST 신호로 분리한다.
- `getattr`, `setattr`, `delattr`, 3인자 `type()`, 조건부 import, `chr/ord/bytes.decode`, `globals()/locals()/__dict__` 접근은 동적/난독화 후보로 남긴다.
- `eval`, `exec`, `compile`, `__import__`, `subprocess`, `socket`, `os.system`, `os.popen`, `os.exec*`, `os.spawn*`는 위험 후보로 남긴다.

## 테스트

추가할 pytest:

- `tests/test_code_roles.py`
- `tests/test_code_ast.py`

역할 분류 케이스:

- `configuration_demo.py` -> `CONFIGURATION`
- `generation_config.py` -> `CONFIGURATION`
- `modeling_demo.py` -> `MODELING`
- `tokenization_demo.py` -> `PREPROCESSING` + `TOKENIZER`
- `processing_demo.py` -> `PREPROCESSING` + `PROCESSOR`
- `image_processing_demo.py` -> `PREPROCESSING` + `IMAGE_PROCESSOR`
- `convert_demo.py` -> `AUXILIARY` + `CONVERT_SCRIPT`
- export-only `__init__.py` -> `AUXILIARY` + `INIT_EXPORT_ONLY`
- 애매한 파일 -> `UNKNOWN`

AST scan 케이스:

- `eval()` 호출이 `dangerous_calls`에 기록
- `subprocess` import가 `dangerous_imports`에 기록
- 조건부 import가 `dynamic_patterns`에 기록
- 3인자 `type()`이 `dynamic_patterns`에 기록
- `bytes(...).decode()`가 `obfuscation_patterns`에 기록
- `F.relu(x)` 같은 raw call이 수집
- `open("vocab.json", "r")`가 contextual candidate로만 수집
- `Path("x").read_text()`가 contextual candidate로만 수집

## 완료 기준

- 원본 코드 import 없이 role과 AST scan 결과를 만들 수 있다.
- `ast.parse()` 외 실행 경로가 없다.
- 문맥 의존 API 후보가 다음 단계로 전달 가능한 구조로 남는다.
- 위험 후보, 동적 후보, 난독화 후보가 등급 판정 전에 손실되지 않는다.
- `PREPROCESSING`, `AUXILIARY`, `UNKNOWN`의 자동 승인 금지가 role 결과에 반영될 수 있다.

## 다음 단계 연결

다음 구현 단계는 `raw_api_calls`, import alias 정보, `contextual_api_candidates`, 위험 후보를 받아 검증 2 `API_POLICY_SCAN`을 수행한다. 이 단계에서 후보로만 남긴 문맥 의존 API는 검증 2 내부의 context analyzer 디스패처에서 실제 판정된다.
