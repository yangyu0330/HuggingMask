# PR #23 박용담 전처리 AST 검증 — 코드 리뷰

- 작성일: 2026-05-18
- 작성자: 김민우 (vmaca123)
- 대상: 박용담 (ydam113) — `[feat] validator: 전처리 파일 AST 검증 엔진 구현`
- PR: https://github.com/yangyu0330/HuggingMask/pull/23
- 검토 범위: `analyzer/validators/preprocessing_validator.py` (610줄) + `tests/preprocessing_validator_demo.py` (11 시나리오)
- 검토 기준: 2026-05-13 작성한 `박용담_설계서_리뷰_KMW.docx` 8 권고

---

## 0. 요약

11 시나리오 데모는 의도대로 동작하는 견고한 단일 파일 구조. 5/13 설계 리뷰 권고 8건 중 **3건 반영 / 2건 부분 반영 / 3건 미반영**. 추가로 PR을 머지하기 전에 짚어야 할 신규 이슈 5건을 발견함.

---

## 1. 설계 리뷰 8 권고 — 코드 반영 매핑

| # | 권고 (5/13 .docx) | PR #23 코드 반영 | 코드 위치 |
|---|---|---|---|
| 1 | A 등급 분류 추가 (정적으로 100% 안전한 파일) | ❌ 미반영 — `grade` 초기값 "B-1", A 분기 없음 | `ASTValidationResult.grade = "B-1"` |
| 2 | `analyzer/validators/code_roles.py` PreprocessKind 재사용 | ❌ 미반영 — `FILE_TYPE_PATTERNS` 자체 정의, code_roles import 없음 | `preprocessing_validator.py:55-62` |
| 3 | UNKNOWN 세분화 (강제 BLOCK 아니라 등급 조정) | ❌ 미반영 — UNKNOWN도 `ALLOWED_IMPORTS_BY_TYPE`에 들어가 정상 분기됨 (오히려 너무 관대) | `ALLOWED_IMPORTS_BY_TYPE["UNKNOWN"]` |
| 4 | 인자 검사 한계 명시 + 우회 패턴 차단 | ✅ 반영 — `DANGEROUS_FROM_IMPORTS` + `getattr(os, "system")` 탐지 | `step2_common_danger_scan` |
| 5 | 난독화 차단 구체화 | ✅ 반영 — `OBFUSCATION_PATTERNS` (base64/codecs/zlib/marshal) + `chr()` 연속 조합 카운트 | step2 후반부 |
| 6 | B-1 호출 인터페이스 명시 | △ 부분 반영 — `verification_step = "CODE_RESTRICTED_RUNTIME"` 문자열로만 라우팅 명시. 실제 호출은 orchestrator 책임 | `step4_grade_finalize` |
| 7 | 결과 JSON 정합성 (인터페이스 정의서 v1.0과 키 셋) | △ 부분 반영 — `ASTValidationResult` dataclass는 있지만 인터페이스 정의서의 `WhitelistCheckResponse` / `ArtifactValidationResult` 키 셋과 비교 없음. PR 본문에 "양유상 확인 요청" 명시 | dataclass |
| 8 | modeling 파일 책임 경계 (modeling_*.py는 양유상 영역) | ✅ 반영 — PR 본문에 명시. 다만 코드에선 MODELING도 `FILE_TYPE_PATTERNS`에 포함되어 분류는 됨 (검증은 안 함) | line 56 |

---

## 2. 신규 이슈 (5/13 리뷰에 없었으나 코드에서 발견)

### P1 — 양유상·김민우 영역과 충돌 가능성

**(A) `analyzer/validators/code_roles.py` 와 분류 로직 중복**
- `preprocessing_validator.py:55` `FILE_TYPE_PATTERNS`가 양유상의 `code_roles.py` PreprocessKind 분류(prefix 매칭)와 별도 코드.
- 결과: 같은 입력에 두 분류기가 다른 결과 반환할 위험. 특히 양유상 orchestrator가 분류한 다음 박용담 validator를 부르면 `file_type` 두 번 결정됨.
- 권고: `from analyzer.validators.code_roles import classify_preprocess_kind` 사용 또는 박용담 분류기를 단일 진실 소스로 합의.

**(B) `ALLOWED_IMPORTS_BY_TYPE["MODELING"]` 존재**
- modeling 파일은 양유상 검증1(`CODE_AST_SCAN`) 책임이라 박용담 코드에서 검증하면 책임 경계 위반.
- 권고: MODELING 키 삭제하고 분류만 한 뒤 즉시 `verification_step = "CODE_AST_SCAN"` 라우팅 + 검증 자체 skip.

### P1 — 단독 구현 시 위험

**(C) JSON 출력 누락**
- `validate_preprocessing_file()`이 `print()`만 함. JSON 직렬화 / 호출자 반환 없음.
- `if __name__ == "__main__"` 만으로 동작하기 때문에 orchestrator가 `import`해서 호출하는 경로가 ANSI 컬러 코드와 함께 stdout에 박힘.
- 권고: `to_dict()` 추가 + `print_result`는 별도 분기.

**(D) `numpy` 검사 부분이 `import numpy as np`를 못 잡음**
- `step3_allowed_api_check`에서 `alias.name.split(".")[0]`로 root 모듈만 보지만, `numpy.load(allow_pickle=True)` 검사(step2 후반)는 `node.func.value.id == "numpy"` 로 alias 별칭(np) 처리 안 함.
- 데모에는 `np.load(allow_pickle=True)` 시나리오가 없어서 통과되는 것처럼 보임.
- 권고: AST 처음에 alias 맵 생성 → `node.func.value.id`를 alias로 거꾸로 매핑.

### P2 — 정합성·운영

**(E) `DANGEROUS_ATTR_CALLS`의 `("os", "environ")` 처리 일관성**
- 환경변수 단순 접근(`os.environ.get("HF_TOKEN")`)도 flag만 됨 (block 아님).
- 다만 docstring·주석에 "API 키 탈취 가능성"으로 표현된 것은 운영에선 false-positive 폭발 가능 (Transformers 자체 코드에 흔함).
- 권고: HF/USER 등 특정 키만 flag, 일반 환경변수는 PASS.

**(F) `evidence/` / `tests/` 위치**
- 데모 파일이 `tests/preprocessing_validator_demo.py`에 들어가 pytest collection 대상이지만 pytest test 함수가 없음 (`__main__`만). pytest 회귀 회수에 잡히지 않음.
- 권고: `tests/test_preprocessing_validator.py`로 이름 바꾸고 `def test_scenario_N():` assertion 추가.

---

## 3. 김민우 영역과의 결합 포인트

- 박용담 `verification_step = "CODE_RESTRICTED_RUNTIME"` → 김민우 `make_restricted_runtime_loader()` 호출은 **orchestrator 책임** (양유상이 dispatch). 박용담 PR 자체에 호출 코드 없음 — 정상.
- 단 박용담 `ASTValidationResult` dataclass와 김민우 `RestrictedRuntimeResult` 키 셋이 다름. orchestrator가 두 결과를 합칠 때 키 충돌 가능. **PR 머지 전 양유상이 결합 인터페이스를 정의해야 안전.**
- 김민우 `code_restricted_runtime.py:DANGEROUS_DUNDER_ATTRS` 30개 dunder 셋과 박용담 `DANGEROUS_CALL_NAMES / DANGEROUS_ATTR_CALLS` 셋도 공통 상수 모듈로 추출 후보 (5/13 양유상 리뷰 .docx에서도 같은 권고).

---

## 4. 머지 전 추천 액션

1. 박용담: 권고 (A), (B), (D)는 머지 전 수정 권장 (책임 경계 + 정합성)
2. 박용담: (C), (F)는 후속 PR로 분리 가능 (운영 품질)
3. 양유상: 박용담 ASTValidationResult vs 김민우 RestrictedRuntimeResult 결합 인터페이스 정의 후 박용담 PR 리뷰
4. 김민우: 권고 4·5는 양유상·박용담 합의 후 DANGEROUS_DUNDER_ATTRS / DANGEROUS_FROM_IMPORTS 공통 상수 PR로 분리 가능

---

## 5. 본인 영역에 미치는 영향

- 즉시 영향 없음. PR #23 머지돼도 김민우 코드 무수정.
- 단 PR #23 머지 후 orchestrator가 `RestrictedRuntimeResult.to_dict()`와 박용담 dataclass를 합치는 경로가 생기면, 본인 `code_restricted_runtime.py`의 result dict 키 셋을 박용담과 다시 맞춰야 할 수 있음.

---

## 6. 결론

박용담 PR #23은 단일 파일 단독 검증으로는 잘 만들어졌고 본인 5/13 리뷰 권고 50%+를 반영. 다만 **권고 #1·#2·#3 미반영**으로 인해 코드베이스의 다른 분류기·등급 정책과 분리됨. 권고 (A)(B)(D)는 머지 전 수정 권장. 책임 경계 (modeling 분류 / code_roles 재사용)는 양유상 확인 후 결정 가능.

본 문서는 GitHub PR 코멘트로 등재할지 또는 박용담에게 직접 전달할지 본인 선택.

---

## 부록 — 데모 11 시나리오 예상 동작 (코드 기반 정적 검토)

| # | 입력 | 예상 결과 | 검증 결과 |
|---|---|---|---|
| 1 | tokenization_bert.py 정상 | PASS, B-1 | OK |
| 2 | image_processing_clip.py 정상 | PASS, B-1 | OK |
| 3 | eval(config[...]) | BLOCKED, C | OK (`DANGEROUS_CALL_NAMES` hit) |
| 4 | torch.load(model) | BLOCKED, C | OK (`DANGEROUS_ATTR_CALLS` hit) |
| 5 | os.system('...') | BLOCKED, C | OK |
| 6 | base64.b64decode + exec | BLOCKED, C | OK (exec가 먼저 hit, base64는 그 뒤로) |
| 7 | scipy.signal.butter | PASS, B-1 유지 | OK (`SAFE_NEW_APIS`) |
| 8 | yaml.load (safe_load 아님) | BLOCKED, C | OK |
| 9 | from os import system | BLOCKED, C | OK (`DANGEROUS_FROM_IMPORTS`) |
| 10 | getattr(os, 'system') | BLOCKED, C | OK (`step2_common_danger_scan` getattr 분기) |
| 11 | import custom_audio_lib | FLAGGED, B-2 격상 | OK (`add_new_api`) |
