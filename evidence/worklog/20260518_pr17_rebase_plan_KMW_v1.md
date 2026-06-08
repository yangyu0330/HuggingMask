# PR #17 (제한 런타임) rebase 계획서

- 작성일: 2026-05-18
- 작성자: 김민우 (vmaca123)
- 대상: `feature/restricted-runtime-impl` → `origin/dev`
- 실행 여부: **미실행** — 사용자 confirm 후 진행

---

## 1. 현재 상태

| 항목 | 값 |
|---|---|
| 본인 브랜치 HEAD | `16e71a9` |
| origin/dev HEAD | `14b3eb5` |
| 분기 base | PR #9 머지 직후 (4-22, `38ef039`) |
| 본인 → dev 추가 커밋 | 9개 (Phase 1~5 + P1+P2+P3 응답) |
| dev → 본인 미수신 커밋 | **23개** (PR #14, #15, #16 머지 포함) |

## 2. 문제 — `git diff origin/dev origin/feature/restricted-runtime-impl --stat` 결과

PR #17이 origin/dev에 **rebase / merge 없이 4-22 시점에 머물러 있어**, diff가 다음을 보임:

```
 67 files changed, 2294 insertions(+), 7709 deletions(-)
```

**-7709 삭제분 = 본인 영역 PR #14·#16에서 머지한 코드** (`whitelist/cache_loader.py`, `whitelist/integration.py`, `whitelist/mod1_*`, `whitelist/mod2_*`, `tests/integration/test_yangyu_whitelist_e2e.py`, `tests/test_mod1_*`, `tests/test_mod2_*`, `tests/test_cache_loader.py`, `tests/test_validation_jobs.py`, `tests/test_weight_validation.py`, `tests/test_whitelist_integration.py`)

**즉 PR #17이 지금 머지되면 PR #14·#16 작업이 전부 사라짐.** 양유상이 머지 버튼 누르기 전에 본인이 rebase로 정리 필수.

## 3. 작업 절차 (사용자 confirm 후 실행)

```powershell
# 1. 새 working tree 또는 새 branch에서 (현재 dashboard-ops 작업 보호)
git fetch origin
git checkout feature/restricted-runtime-impl
git pull --rebase  # 본인 force-push 했던 5/9 이후 동기화

# 2. dev 머지 (rebase 대신 merge — 9개 커밋 보존 + dev 23 커밋 합류)
git merge origin/dev
# 충돌 가능 지점:
#   - whitelist/feedback.py (PR #16에서 +10줄, 본인 PR도 손댔는지 확인)
#   - whitelist/pending_store.py (PR #16에서 +15줄)
#   - requirements.txt (PR #16에서 +2줄: bs4, lxml — 본인 PR과 비충돌 예상)

# 3. 머지 후 pytest 풀 실행
python -m pytest -q
# 기준선: 287 passed / 3 skipped 가 유지되거나 더 늘어야 함
# (PR #14·#16 테스트들이 다시 들어와 총 ~330개+ 예상)

# 4. force-with-lease push (양유상이 reviews 안 봤으므로 안전)
git push --force-with-lease origin feature/restricted-runtime-impl

# 5. PR #17에 코멘트 — "dev rebase 완료, diff 정상화" 알림
```

### 대안 A — merge 대신 rebase
- pros: 히스토리 깔끔
- cons: 9개 커밋 각각 충돌 해결, 5/9에 한 번 force-push 했던 author 보존 작업 다시 필요할 수 있음
- 추천: **merge 사용** (이미 force-push 두 번째라 깔끔함보단 안전성 우선)

### 대안 B — 안 함
- pros: 본인이 안 건드리면 안 깨짐
- cons: 양유상이 PR #17 머지하는 순간 dev 폭망 → revert 사태 (PR #18 → PR #19 revert 재현)
- **위험. 결국 누군가 해야 함.**

## 4. 사전 점검 — 충돌 가능 파일

| 파일 | 본인 PR #17 변경 | dev 변경 (PR #14·#16) | 충돌 가능성 |
|---|---|---|---|
| `whitelist/feedback.py` | ? | +10줄 (cache_loader 연동) | 본인이 안 만졌으면 충돌 없음 |
| `whitelist/pending_store.py` | ? | +15줄 (cache_loader 연동) | 동일 |
| `whitelist/rules.py` | ? | +68줄 (CRAWL_TARGETS 등) | 동일 |
| `analyzer/orchestrator.py` | **수정함** (P1 #1 dispatch_artifacts) | PR #14 wrapper도 손댐 | **충돌 가능 — 가장 주의** |
| `tests/conftest.py` | ? | PR #14·#16에서 변경 | 가능 |
| `requirements.txt` | ? | +2줄 | 본인 PR이 안 만졌으면 OK |

본인 PR #17 변경 파일 정확 확인은 `git diff --name-only origin/dev origin/feature/restricted-runtime-impl` 후속 작업.

## 5. 권장 다음 행동

1. 사용자 본인이 rebase 시점 선택 (지금 / 양유상 코멘트 받은 후 / 발표 전)
2. 실제 작업은 `worktree` 또는 별도 powershell 세션에서 (현재 `feature/whitelist-dashboard-ops` 보호)
3. rebase 후 PR #17에 코멘트로 양유상에게 알림 — 양유상 9일 침묵 깰 reminder 역할도 됨
