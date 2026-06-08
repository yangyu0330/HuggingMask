# HuggingMask 작업 점검 — 본인(김민우) 할 일 전체 리스트

- 작성일: 2026-05-20
- 깃 상태 기준일: 2026-05-20 (양유상 5-18 일제 리뷰 반영)
- 출처: PR #17/#20/#23/#24 reviews + comments + inline + Issue #21/#25 본문

---

## 0. 한눈에 보기

| 우선순위 | 항목 | 책임자 | 상태 |
|---|---|---|---|
| **🚨 P0** | Issue #25 fix — PR #17 preserve stdlib 우회 4건 | **본인** | 대기 |
| **🚨 P0** | PR #20 inline 2건 fix (bulk_approve / bulk_conditional) | **본인** | 대기 |
| **🟡 P1** | PR #24 정은미 리뷰 등재 (yara 오타·drift) | 본인 결정 | draft 완료 |
| **🟡 P1** | PR #23 박용담 리뷰 등재 (양유상과 중복) | 본인 결정 | draft 완료 |
| **🟢 P2** | PR #17 / PR #20 dev 재흡수 (PR #24 머지 후) | 본인 | 대기 |
| **🟢 P2** | 비교과 자료 / 주간 보고 push 여부 | 본인 결정 | 로컬 완료 |

본인 코드 작업 시급도: **Issue #25 > PR #20 inline > 나머지**.

---

## 1. 🚨 [P0] Issue #25 — PR #17 preserve stdlib 우회 (본인 영역)

**Issue 작성:** 양유상, 2026-05-18 22:09
**PR #17 동일 리뷰:** 5-18 21:53, 5-18 22:09 (CHANGES_REQUESTED, head `3cdb453`)
**침묵 9일 깬 첫 리뷰** — 본인이 5-18 dev merge 직후 양유상이 즉시 검증한 흐름

### 재현 payload (양유상이 제공)
```python
import dataclasses
dataclasses.sys.modules["builtins"].open("probe.txt", "w").write("x")  # PASS + side_effect_exists=True

import enum
enum.bltns.open("probe.txt", "w").write("x")  # PASS + side_effect=True

import collections
collections._sys.modules["builtins"].open("probe.txt", "w").write("x")  # PASS + side_effect=True
```

### 원인
본인이 5-9 PR #17 P2 #5 응답에서 추가한 `_SANITIZE_PRESERVE_STDLIB` 화이트리스트:
```python
_SANITIZE_PRESERVE_STDLIB = frozenset({
    dataclasses, functools, itertools,
    abc, collections, collections.abc,
    enum, math,
})
```
이 모듈들은 sanitize 없이 raw module 그대로 반환 → 내부 globals의 real `sys` / `builtins` 참조가 노출됨.

### 수정 방향 (양유상이 제안한 4단계)
1. preserve 대상 모듈을 raw module 그대로 반환하지 않게 변경
2. 최소한 preserve 모듈 내부의 `sys`/`builtins` 참조를 `_SafeSysProxy`/`restricted_builtins_module`로 대체
3. 회귀 테스트 3건 + 정상 `@dataclass` 유지 검증 1건 = **4건 추가**
4. `tests/test_restricted_runtime.py` + 전체 pytest 결과 evidence에 갱신

### 본인 접근 후보
- **옵션 A**: preserve 모듈을 만들 때 `sys`/`builtins` attribute를 SafeSysProxy로 패치한 사본 반환 (사용자 가시 모듈만 영향)
- **옵션 B**: preserve 목록 자체 축소 — `dataclasses`/`enum`/`collections` 제외, `functools`/`itertools`/`math`만 유지. 5-9 sanitize 완화의 원래 의도(dataclass 정상 사용)는 깨짐 → `@dataclass` 정상 사용 회귀 깨질 가능성
- **옵션 C**: 두 방법 혼합 — `functools`/`itertools`/`math`/`abc`는 raw 유지, `dataclasses`/`enum`/`collections`만 사본 + sys/builtins 패치
- **추천: 옵션 C** — 양유상의 정상 `@dataclass` 보존 요구도 충족하면서 우회 차단

### 예상 작업량
- 코드: `_sanitize_user_visible_object()` + preserve 처리 부분 약 50줄 수정
- 테스트: 4건 추가 (~80줄)
- evidence worklog + pytest raw 갱신
- 1~2시간 예상

---

## 2. 🚨 [P0] PR #20 inline 2건 fix (본인 영역)

**리뷰:** 양유상 2026-05-18 22:50 (CHANGES_REQUESTED)
**양유상 의견:** "대시보드 엔드포인트와 신규 테스트 자체는 동작하고 전체 테스트도 통과. 다만 bulk 승인 스크립트에 실제 운영 결과를 틀리게 만들 수 있는 논리 오류가 있어 머지 전에 수정 요청."

### Fix #1 — `scripts/bulk_conditional.py:110` pagination offset 버그
**문제:**
```python
# 현재 (의사 코드)
while True:
    pending = fetch(offset=offset, limit=50)  # 50건 조회
    for item in pending:
        approve(item)                          # 승인 → pending에서 제거
    offset += 50                                # ← 버그
```
승인하면서 목록이 줄어드는데 `offset += 50`을 하면 앞으로 당겨진 항목을 건너뜀. 60건 대상이면 첫 50건 승인 후 남은 10건이 offset 0에 위치하지만 offset 50으로 조회해 빈 목록 받고 종료.

**Fix (양유상 제안):**
- `bulk_approve.py`처럼 매번 `offset=0` 조회
- 또는 먼저 안정적 대상 목록(`item_ids`)을 수집한 뒤 처리

### Fix #2 — `scripts/bulk_approve.py:66` 응답 검증 누락
**문제:**
```python
client.post("/review", json=...)  # 결과 무시
counted += 1                       # 무조건 성공으로 카운트
```
500 응답이나 `applied: false`도 성공처럼 카운트됨. pending에 남은 항목은 다음 루프에서 다시 시도.

**Fix:**
```python
resp = client.post("/review", json=...)
resp.raise_for_status()
if resp.json().get("applied") is True:
    counted += 1
```

### 양유상의 추가 의견
- 대시보드 인증 / HTML escaping / model-id 입력값 미반영 같은 이슈는 **이번 데모/운영 범위에 따라 후속 이슈로 분리 가능** — 즉 머지 자체엔 미블록
- bulk script 2건만 블로커

### 예상 작업량
- `bulk_conditional.py` 수정 약 20줄
- `bulk_approve.py` 수정 약 10줄
- 회귀 테스트 2건 추가 (`tests/test_dashboard_and_ops.py`)
- 30분 예상

---

## 3. 🟡 [P1] PR #24 정은미 리뷰 등재 결정

**상태:** 본인 리뷰 `evidence/worklog/20260520_pr24_eunmi_weight_code_review_KMW_v1.md` 로컬 작성 완료
**핵심 발견:** Issue #21 87% 반영 + 새 P0 2건 (`yara` import 오타 / dev drift -4025줄)

### 선택지
1. **GitHub PR #24 코멘트로 등재** — 양유상이 아직 PR #24 안 봤으니 본인이 먼저 가는 패턴 가능. 단 GitHub 코멘트는 모두에게 보임.
2. **카톡·메일로 .md 정은미에게 직접 전달** — Issue #21 작성 패턴 연장. 본인이 5/12에 Issue로 올린 건 의도적으로 공개 트랙. PR #24엔 다른 톤도 가능.
3. **양유상 검토 후 등재** — 양유상이 본인 영역 검증자 역할이라 정확성 검증 가치 있음. 단 양유상 PR #17 응답 대기 중이라 부담 가중.
4. **draft 보관만 + 양유상이 PR #24 리뷰할 때까지 대기** — 양유상이 yara 오타 / drift 발견 가능성 큼

**본인 추천:** **옵션 1 (등재)**. 이유:
- yara 오타는 정은미가 모를 가능성 큼 → 빨리 알릴수록 좋음
- drift는 GitHub UI도 알려주지만 명시적 가이드 필요
- Issue #21에 본인이 P0 5건 올린 패턴과 일치 — 가독성 / 추적성

### 등재 시 형식 (draft `.claude/drafts_20260518.md` 참조)

---

## 4. 🟡 [P1] PR #23 박용담 리뷰 등재 결정

**상태:** 본인 리뷰 `evidence/worklog/20260518_pr23_park_preprocessing_code_review_KMW_v1.md` 로컬 작성 완료
**양유상 5-18 리뷰와 비교:**

| 본인 5-18 권고 | 양유상 5-18 리뷰 | 중복도 |
|---|---|---|
| #1 미반영: `code_roles.py` 분류 중복 | (없음) | 본인 단독 |
| #2 미반영: A 등급 분류 | (없음) | 본인 단독 |
| #3 미반영: UNKNOWN 세분화 | 양유상 #1 "자동 PASS 금지" 와 부분 부합 | 부분 중복 |
| #4 (D) numpy alias 미처리 | 양유상 #4 "alias/from-import 우회" | **중복** |
| (C) JSON 직렬화 누락 | 양유상 #3 "ArtifactValidationResult 계약 미준수" | **중복** |
| (F) pytest 함수 없음 | 양유상 #5 "pytest 회귀 추가" | **중복** |
| (B) modeling 책임 경계 위반 | 양유상 #2 "SAFE_NEW_APIS 정책" | 부분 중복 |

**겹침 4건 + 본인 단독 3건.** 박용담이 양유상 리뷰만으로도 부담스러울 가능성 — 본인 단독 3건만 발신하는 게 합리적.

### 선택지
1. **본인 단독 3건만 PR 코멘트로 등재** (`code_roles.py` 중복 / A 등급 분류 / UNKNOWN 세분화)
2. **양유상 리뷰 끝난 후 박용담이 응답 PR 올린 뒤 대조 리뷰**
3. **카톡으로 .md 통째 전달**
4. **draft 보관만**

**본인 추천:** **옵션 2** — 양유상 리뷰가 더 권위 있고 박용담은 그것부터 응답해야 함. 본인 단독 3건은 응답 PR에서 다시 검증.

---

## 5. 🟢 [P2] PR #17 / PR #20 dev 재흡수 (PR #24 머지 후)

**현재:** 본인이 5-18 PR #17은 dev merge 완료 (commit `3cdb453`). PR #20도 1 커밋 앞섬, drift 없음.

**문제:** 정은미 PR #24가 dev에 머지되면 PR #17 / PR #20이 다시 dev 뒤처짐 — 같은 패턴 반복.

**대응:**
- PR #24 머지 직후 `git merge origin/dev` 한 번 더 (PR #17, PR #20 둘 다)
- 또는 PR #17 / PR #20을 먼저 머지하고 정은미 PR #24가 본인 PR 흡수
- **머지 순서는 양유상 결정** — 본인 책임 영역 아님

**본인 행동:** PR #24가 머지되는 시점에 알림 받으면 즉시 흡수 push.

---

## 6. 🟢 [P2] 발신 결정 — 비교과 자료 / 주간 보고 / .docx

| 산출물 | 상태 |
|---|---|
| `evidence/worklog/20260519_project_overview_for_external_KMW_v1.md` (비교과 자료) | 로컬, 본인 결정 |
| `김민우 주간 보고서fin.hwp` (5월 셋째 주) | 로컬, 본인 결정 |
| `박용담_설계서_리뷰_KMW.docx` | 5/13 작성, 미전달 |
| `양유상_B2_gVisor_설계서_리뷰_KMW.docx` | 5/13 작성, 미전달 |
| `제한_런타임_설계서_KMW.docx` (5겹) | 5/9 작성, stale (현재 9겹) |
| `제한런타임_초보설명_KMW.docx` (9겹) | 5/13 작성, 최신 |

**선택:** 비교과 자료는 본인 영역 단독 발신 OK. 양유상·박용담 .docx는 PR 응답 끝난 후 자연스러운 시점에.

---

## 7. 머지 순서 / 발표 일정 가시화

### 현재 OPEN 4 PR + 2 Issue
| | 작성자 | 상태 | 침묵·블로킹 |
|---|---|---|---|
| PR #17 | 본인 | CHANGES_REQUESTED | **Issue #25 본인 작업** |
| PR #20 | 본인 | CHANGES_REQUESTED | **본인 작업 2건** |
| PR #23 | 박용담 | CHANGES_REQUESTED | 박용담 작업 5건 |
| PR #24 | 정은미 | REVIEW_REQUIRED + CONFLICTING | 정은미 dev merge + yara 오타 + 양유상 리뷰 |
| Issue #21 | 본인→정은미 | OPEN | PR #24가 사실상 응답 (87% 반영) |
| Issue #25 | 양유상→본인 | OPEN | **본인 작업** = PR #17 fix |

### 권장 머지 순서 (양유상 결정 사항이나 합리적 안)
1. **본인 PR #20 fix 2건 → 머지** (가장 작음, 운영 도구라 다른 모듈 영향 적음)
2. **본인 PR #17 Issue #25 fix → 머지** (검증2 보안 핵심)
3. **정은미 PR #24 yara 오타 + dev merge → 머지** (가중치 검증 보안)
4. **박용담 PR #23 5건 응답 → 머지** (전처리 검증, 기존 코드 무수정)
5. 위 4건 머지 후 **main 브랜치 통합 PR** (캡스톤 발표 전)

### 발표·캡스톤 데모 D-Day
- 일정 미확정 — 6월 초·중순 추정
- 시연 항목: `docker compose up --build` → 4탭 대시보드 → 시나리오 A/B/C
- 필수 머지: PR #17·#20 본인 두 건은 발표 전 반드시 dev → main

---

## 8. 본인 작업 후 commit / push 절차 (참고)

PR #17 Issue #25 fix 작업 예시:

```powershell
# 1. PR #17 작업 브랜치로 이동 (worktree 또는 직접)
git checkout feature/restricted-runtime-impl

# 2. 코드 수정
# analyzer/validators/code_restricted_runtime.py — preserve module 사본 + sys/builtins 패치
# tests/test_restricted_runtime.py — 회귀 4건 추가

# 3. pytest
python -m pytest tests/test_restricted_runtime.py -v
python -m pytest -q

# 4. evidence
# evidence/worklog/20260520_pr17_issue25_response_KMW_v1.md
# evidence/tests/20260520_pr17_issue25_pytest_raw_KMW_v1.txt

# 5. commit + push
git add ...
git commit -m "[fix] runtime: sanitize preserve stdlib modules (Issue #25)"
git push

# 6. PR #17 코멘트로 양유상에게 응답 — 회귀 4건 + side_effect_exists=False 확인
```

PR #20 fix도 동일 패턴, 더 짧음.

---

## 9. 즉시 다음 행동 추천

본인이 yes 누르면 들어갈 후보:
1. **PR #17 Issue #25 fix 시작** — 양유상이 가장 시급하게 본 보안 우회. 양유상 침묵 깬 직후라 응답 속도가 신뢰 회복에 결정적.
2. **PR #20 bulk script 2건 fix** — 30분 작업, 발표 데모 코드라 빠르게 클리어
3. **PR #24 정은미 리뷰 코멘트 등재** — yara 오타 알릴 가치 큼
4. **위 3건 병렬** — 본인 단독 가능 작업이라 사실상 다 가능

본인이 다음 행동 선택하면 그 작업부터 진행.
