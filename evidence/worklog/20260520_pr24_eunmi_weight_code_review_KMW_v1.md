# PR #24 정은미 weight validator 보안 피드백 반영 — 코드 리뷰

- 작성일: 2026-05-20
- 작성자: 김민우 (vmaca123)
- 대상: 정은미 (Eunmi04) — `[CORE][fix] weight validator 보안 피드백 반영`
- PR: https://github.com/yangyu0330/HuggingMask/pull/24
- 검토 범위: 단일 commit `439ed7e` — 16 files, +1108 / -181
- 검토 기준: 2026-05-12 작성한 [GitHub Issue #21](https://github.com/yangyu0330/HuggingMask/issues/21) — P0 5건 + P1 5건 + P2 5건 = 15건

---

## 0. 한 줄 결론

**Issue #21 15건 중 12건 정확 반영 + 2건 부분 반영 + 1건 미반영. 보안 피드백 응답 품질 매우 높음.** 다만 **신규 P0 버그 1건**(`import yara_scanner as yara`)과 **dev drift**(PR #24 머지 시 PR #14·#16 손실 위험)는 머지 전 반드시 해결.

---

## 1. Issue #21 15건 매핑 — 결과 표

### P0 보안 치명 5건 — **5/5 ✅ 반영**

| # | 권고 | PR #24 반영 | 위치 |
|---|---|---|---|
| P0-1 | `torch.load(weights_only=False)` + `pickle.load` fallback 제거 | ✅ 완전 반영 — `load_torch_weights_only` 단일 함수로 통합, `weights_only=True` 고정 | `sandbox/load_and_extract.py:58-63` |
| P0-2 | Path B sandbox `runtime` 기본값 `runc` → `runsc` | ✅ 완전 반영 — `docker_runner.run_in_docker`, `pipeline.validate_pickle_pipeline` 양쪽 default 변경 | `sandbox/docker_runner.py:31`, `pipeline.py:66` |
| P0-3 | Path B stdout 신뢰 → nonce 검증 | ✅ 완전 반영 — `secrets.token_hex(16)` nonce 환경변수 주입, `RESULT_PREFIX:nonce:json` 패턴, status whitelist `{PASS, BLOCK, SKIP, SKIPPED}` | `docker_runner.py:11-30`, `load_and_extract.py:73-81` |
| P0-4 | YARA `RULE_PATH` 상대경로 → 절대경로 | ✅ 완전 반영 — `Path(__file__).resolve().parents[3] / "assets" / "malicious_pickle.yar"` | `validators/yara_scanner.py:11` |
| P0-5 | YARA 문자열 룰 → pickle opcode hex 패턴 | ✅ 완전 반영 — 13개 opcode hex(`{ 63 }` 등) + `uint8(0) == 0x80` (pickle PROTO opcode) prefilter | `assets/malicious_pickle.yar` |

### P1 정합성·운영 5건 — **3 ✅ + 1 △ + 1 ❌**

| # | 권고 | PR #24 반영 |
|---|---|---|
| P1-1 | `cache.py` race condition (atomic write / lock) | ✅ 완전 반영 — Windows `msvcrt.locking` + Linux `fcntl.flock` 분기, `tempfile.mkstemp` + `os.replace` atomic, **HMAC 서명**으로 cache tampering 방지 추가 (요구 사항 초과) |
| P1-2 | `ValidationStatus` enum 사용 | ✅ 반영 — `service.py:_validate_job`에서 `ValidationStatus.BLOCK` / `ValidationStatus.PASS` 분기 사용 |
| P1-3 | 화이트리스트 audit chain hook 결합 | ❌ **미반영** — `whitelist.audit.append_audit_log` 호출 없음. 본 PR 범위 외라 의도된 미반영일 가능성 큼 (별도 PR 필요) |
| P1-4 | A/B diff `B-only` 키 누락 / shape·dtype mismatch | ✅ 완전 반영 — `diff/checker.py:compare_tensor_reports`가 `MISSING_IN_B`, `MISSING_IN_A`, `SHAPE_MISMATCH`, `DTYPE_MISMATCH`, `HASH_MISMATCH` 5종 분리 |
| P1-5 | 일반 PyTorch `state_dict` 형식 미지원 명시 | △ 부분 반영 — `pipeline.py:198-211`에서 `PICKLE_PATH_A_NO_CONVERTIBLE_TENSOR_DICT` BLOCK 처리 + 사유 명시. **다만 PR 본문 §4 확인 요청에서 "non-executing storage parser 구현 여부는 양유상 조율"로 명시 → 본 PR엔 의도된 BLOCK** |

### P2 코드 품질 5건 — **4 ✅ + 1 △**

| # | 권고 | PR #24 반영 |
|---|---|---|
| P2-1 | `DTYPE_MAP` 중복 제거 → 공통 모듈 | ✅ **완전 반영** — 새 `analyzer/validators/weight/dtypes.py` 신설, `pickle_opcode_parser.py` / `load_and_extract.py` 양쪽에서 import |
| P2-2 | bf16 tensor hash 계산 numpy 변환 문제 | ✅ 완전 반영 — `_tensor_raw_bytes` 헬퍼 도입, `tensor.numpy().tobytes()` 실패 시 `tensor.view(torch.uint8).numpy().tobytes()` fallback. `load_and_extract.py:24-29`, `reporting.py:9-15` 둘 다 동일 패턴 |
| P2-3 | `except Exception` 광범위 catch | ✅ 반영 — `except yara.Error` / `except (json.JSONDecodeError, ValueError)` / `except subprocess.TimeoutExpired` / `except FileNotFoundError` / `except OSError` 등 specific |
| P2-4 | modelscan fragile attribute 접근 | ✅ 완전 반영 — `_load_modelscan` lazy import, `_normalize_issue` (dict/object 둘 다 지원), severity/category/message 키별 fallback, severities 집합 추가 |
| P2-5 | CLI `policy_fingerprint` 기본값 `"cli-policy"` 제거 | ✅ 반영 — `required=True`, help text 명시. 다만 **breaking change** (아래 신규 이슈 #4 참조) |

### 종합 점수
- **P0: 5/5** (100%)
- **P1: 3/5 + 1 부분** (70%)
- **P2: 4/5 + 1 부분** (90%)
- **합계: 12/15 완전 + 2 부분 + 1 미반영 = 87% 정확 반영**

---

## 2. 🚨 PR #24가 새로 도입한 P0 버그

### **P0-NEW: `yara_scanner.py` import 명문 오류**

```python
# analyzer/validators/weight/validators/yara_scanner.py (수정 후)
try:
    import yara_scanner as yara   # ⚠️ 잘못됨
except ImportError:
    yara = None
```

**문제:**
- requirements.txt에 추가된 패키지는 `yara-python>=4.5.0` → 정확한 import는 `import yara`
- `yara_scanner`는 PyPI에 있는 별개 패키지 (Florian Roth wrapper)인데 본 프로젝트엔 미설치
- 결과: `yara`가 항상 `None`이 되어 **YARA 스캔이 모두 SKIP**. P0-4 / P0-5 fix가 무력화됨

**추가 부정합:**
```python
except yara.Error as e:
```
`yara`가 `None`일 때 도달하면 `AttributeError: 'NoneType' object has no attribute 'Error'`. try block 내부에서 `yara.compile()` 호출 직후 분기되니 빈 yara=None인 경우 entry가 안 되지만, 만약 잘못된 yara_scanner module이 import되면 `Error` attr 부재로 폭주.

**권고 (머지 전 필수):**
```python
try:
    import yara
except ImportError:
    yara = None

# ...
except (yara.Error if yara else Exception) as e:
```
또는 단순히:
```python
try:
    import yara
except ImportError:
    yara = None
```
그대로 두고 `except` 분기는 `yara.Error if yara is not None else Exception`로 안전화.

---

## 3. 신규 발견 P1 이슈 3건

### **P1-NEW-1: `load_and_extract.py` 이중 import 의도 불명**

```python
try:
    from dtypes import DTYPE_MAP
except ImportError:
    from analyzer.validators.weight.dtypes import DTYPE_MAP
```

**문제:** 첫 번째 `from dtypes import` 는 일반 실행 시 항상 실패 → 의도가 Path B sandbox 내부 (working dir이 weight/ 하위라 dtypes.py가 top-level에 보임) 케이스라면 주석 권장.

**권고:** 한 줄 주석 추가
```python
# Path B sandbox는 working dir=/sandbox 위에서 실행되므로 dtypes 모듈을 top-level에서 찾는다.
# 일반 호출 시엔 패키지 경로로 fallback.
```

### **P1-NEW-2: HMAC dev fallback 키 하드코딩**

```python
return os.getenv(
    "WEIGHT_CACHE_HMAC_KEY",
    "dev-only-weight-cache-hmac-key",
).encode("utf-8")
```

**문제:**
- 운영 환경에서 환경변수 누락 시 동일 fallback 키 사용 → cache HMAC signature가 알려진 키로 계산됨 (공격자가 cache 위조 가능)
- PR 본문 §4에 "운영 환경에서는 WEIGHT_CACHE_HMAC_KEY 주입 필요" 명시했지만 코드 자체는 silent fallback

**권고 (P1):** 운영 환경에서 환경변수 누락 시 fail-loud
```python
def _hmac_key() -> bytes:
    key = os.getenv("WEIGHT_CACHE_HMAC_KEY")
    if key is None:
        if os.getenv("HM_ENV") == "production":
            raise RuntimeError("WEIGHT_CACHE_HMAC_KEY required in production")
        key = "dev-only-weight-cache-hmac-key"
    return key.encode("utf-8")
```

### **P1-NEW-3: CLI breaking change — 기존 스크립트 호환성**

`--policy-fingerprint` default(`"cli-policy"`) 제거 후 `required=True`. 기존 CI / 스크립트가 인자 누락 시 즉시 SystemExit. P2-5 권고에 부합하지만 **마이그레이션 가이드 누락**.

**권고:** PR 본문 §1에 "기존 호출자는 `--policy-fingerprint dev-cli`를 명시 전달 필요" 한 줄 추가.

---

## 4. 🚨 dev drift — PR #17과 동일 위험

```
git diff --stat origin/dev origin/feature/eunmi-wip
37 files changed, 1108 insertions(+), 4025 deletions(-)
```

**-4025 삭제분 = PR #14·#16(김민우 영역)이 PR #24 머지 시 사라짐**

삭제 위험 파일:
- `whitelist/cache_loader.py` (-251)
- `whitelist/integration.py` (-365)
- `whitelist/mod1_doc_crawler.py` / `mod1_package_inspector.py` / `mod1_real_crawler.py` (-1163)
- `whitelist/mod2_real_fetcher.py` / `mod2_verified_org.py` (-590)
- `tests/test_cache_loader.py` (-250)
- `tests/test_mod1_doc_crawler.py` (-158)
- `tests/test_mod2_verified_org.py` (-362)
- `whitelist/feedback.py`, `whitelist/pending_store.py`, `whitelist/rules.py` 일부

**원인:** `feature/eunmi-wip` 브랜치가 PR #15 머지 직전 base에서 PR #24 작업으로 직행. dev에 PR #14·#16이 머지되었지만 본 브랜치엔 흡수 안 됨.

**권고 (머지 전 필수):**
```powershell
git checkout feature/eunmi-wip
git fetch origin
git merge origin/dev
# 충돌 가능성: 없음 (정은미 변경 파일과 PR #14·#16 변경 파일 disjoint 예상)
python -m pytest -q
git push
```

PR #17과 동일 패턴 — 본인이 5/18에 해결한 것과 같은 절차. **정은미 본인이 진행 필요.** GitHub UI도 `mergeable: CONFLICTING` 상태로 알림 중.

---

## 5. 추가 칭찬할 점 (요구 사항 초과)

1. **HMAC cache 서명** — Issue #21 P1-1은 race condition만 지적했지만 정은미가 tampering 방지까지 자발적으로 추가
2. **`PICKLE_RELEASE_REQUIRES_CONVERTED_SAFETENSORS`** — `service.py`에서 원본 pickle을 approved_artifact_ids에서 제외하고 변환된 safetensors만 release. Issue #21 P0 권고에 없던 추가 보안 강화
3. **YARA `uint8(0) == 0x80` prefilter** — pickle protocol 2+ 매직 바이트 검사로 false positive 줄임. 권고에 없던 추가
4. **diff `SHAPE_MISMATCH` / `DTYPE_MISMATCH` 분리** — Issue #21은 `MISSING_IN_B`만 요구했지만 shape/dtype mismatch 분리 분류 추가

---

## 6. 머지 전 액션 우선순위

| 우선순위 | 항목 | 책임자 |
|---|---|---|
| **P0 (필수)** | `import yara_scanner as yara` → `import yara` 수정 | 정은미 |
| **P0 (필수)** | dev drift 해소 — `git merge origin/dev` | 정은미 |
| **P1 (권장)** | HMAC dev fallback fail-loud | 정은미 |
| **P1 (권장)** | CLI breaking change 마이그레이션 가이드 PR 본문 추가 | 정은미 |
| **P2** | `from dtypes import` 의도 주석 | 정은미 |
| **별도 PR** | audit chain hook 결합 (Issue #21 P1-3) | 본인(김민우) 협업 가능 |

---

## 7. 본인(김민우) 영역과의 결합 포인트

1. **`whitelist.audit.append_audit_log` 호출 없음** — 가중치 검증 결과가 4-state 화이트리스트의 감사 chain에 들어가지 않음. **본인이 hook 제공 가능** (whitelist/audit.py에 `register_weight_validator()` helper 추가). 별도 PR로 분리 권장.
2. **`approved_artifact_ids` / `blocked_artifact_ids` / `pending_artifact_ids`** — service.py가 화이트리스트 PendingApi와 동일 구조. **본인 pending_store에 입출력 연동 가능**. 정은미 PR #24 머지 후 별도 PR.
3. **`PICKLE_RELEASE_REQUIRES_CONVERTED_SAFETENSORS`** BLOCK 시 PendingApi 등록 흐름이 명세에 없음 — 양유상 orchestrator에서 결정.

---

## 8. 본 PR 머지 후 본인 작업 후보

1. 화이트리스트 audit chain hook 결합 PR — 정은미·양유상 합의 후
2. mod2 결과를 weight validator의 신뢰 기준에 활용 (현재 mod2는 코드 API 단위, weight는 별도) — 장기 후보
3. 본인 PR #17 + PR #20도 발표 전 dev 재merge → 정은미 PR #24 머지 직후 다시 정합화 필요할 수 있음

---

## 9. 결론

정은미 PR #24는 **Issue #21에 대한 매우 성실하고 깊이 있는 응답**. 보안 P0 5건 완전 반영 + cache HMAC 추가 + pickle release 정책 강화 등 요구 초과 작업. 다만 **`yara` import 오타가 치명적**이라 머지 전 반드시 수정 + dev drift 해소 필수.

머지 후엔 본인 영역(audit chain 결합 / mod2 활용)과 결합 가능 포인트 3가지 후속 PR로 분리 권장.

본 문서는 GitHub PR 코멘트로 등재할지, 정은미에게 직접 .md 전달할지, 양유상 검토 거친 후 정리할지는 본인 선택.
