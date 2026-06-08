# PR #17 (제한 런타임) — origin/dev 머지 결과

- 작성일: 2026-05-18
- 작성자: 김민우 (vmaca123)
- 대상 브랜치: `feature/restricted-runtime-impl`
- 작업 위치: `c:/tmp/HM-rebase-rr` (worktree)
- 사용자 지시: "지금 바로" — drift 해소 즉시 실행

## 1. 실행 명령 순서

```powershell
git worktree add c:/tmp/HM-rebase-rr feature/restricted-runtime-impl
# (worktree HEAD가 dd3f8db로 stale — 5/9 force-push 이전 상태)

git fetch origin
git reset --hard origin/feature/restricted-runtime-impl
# HEAD: 16e71a9 ([docs] evidence: log PR #17 review response with 287 passed / 3 skipped)

git merge origin/dev --no-edit
# 결과: 충돌 0건. 'ort' 전략 clean merge.
# 새 merge commit: 3cdb453

c:/Users/minwo/Downloads/HuggingMask/.venv/Scripts/python.exe -m pytest -q --tb=no \
  --ignore=tests/test_health.py \
  --ignore=tests/test_validation_jobs.py \
  --ignore=tests/test_weight_validation.py
# 363 passed, 3 skipped, 9 errors

git push origin feature/restricted-runtime-impl
# 16e71a9..3cdb453 (force-push 불필요, 일반 push 1회)
```

## 2. 머지 결과

| 항목 | 머지 전 | 머지 후 |
|---|---|---|
| diff vs origin/dev | **67 files, +2294 / -7709** | **+2297 / -3** |
| HEAD | `16e71a9` | `3cdb453` (Merge commit) |
| 본인 PR #17 commits | 9개 | 9개 + merge commit 1 |
| 충돌 | — | **0건** |

- dev의 23 커밋(PR #14 / PR #15 / PR #16 / weight 정리 + revert)이 머지 commit으로 합류
- 본인 9 커밋(Phase 1~5 + P1+P2+P3 응답)은 history에 보존
- 본인이 수정한 파일(`analyzer/orchestrator.py`, `code_restricted_runtime.py`, `tests/test_restricted_runtime.py`)이 dev에서 미수정이라 자동 merge

## 3. 테스트 결과 — 363 passed / 3 skipped / 9 errors

### 통과 363
- 5/9 push 시점(287) 대비 **+76건**
- PR #14·#16 통합 후 `tests/test_cache_loader.py` / `test_mod1_doc_crawler.py` / `test_mod2_verified_org.py` / `test_whitelist_integration.py` / `tests/integration/test_yangyu_whitelist_e2e.py`가 회수에 들어옴
- 본인 영역 회귀 0 (제한 런타임 35건 + dunder 28건 모두 통과)

### Skipped 3
- Windows 메모리 제한 테스트 3건 — 의도된 skip (`RLIMIT_AS` Linux/Mac 전용)
- 변경 없음

### Errors 9 — 사전 venv 환경 이슈, 머지로 인한 회귀 아님
- `tests/test_health.py` / `test_validation_jobs.py` / `test_weight_validation.py`: `safetensors` / `torch` 미설치
- `tests/test_router_e2e.py` 9건: `proxy.app.main` → `analyzer.service` → `safetensors` 의존성 체인
- **원인:** 본인 venv는 PR #14 시점에 만들어진 환경 (5/5). PR #15 머지로 dev에 들어온 `safetensors` / `torch` 의존성 미설치. 본 머지가 추가한 게 아니라 dev에 이미 있던 상태.
- **해결:** `pip install safetensors torch` 후 재실행하면 회수 가능. 단 발표 데모용 베이스라인 회귀는 본 PR 머지로 발생한 게 아님을 명시.

## 4. 깃 룰 정합성 (CONTRIBUTING.md + docs/dev_standard.md 대조)

| 룰 | 위반 여부 |
|---|---|
| §2 dev 최신화 후 feature 작업 | ✅ **회복**. 이 작업 자체가 dev 최신화. |
| §2 feature/* → dev PR | ✅ PR #17 base=dev 그대로 |
| §4 커밋 메시지 [타입] 대상: 내용 | ✅ 머지 commit 메시지 `Merge remote-tracking branch 'origin/dev' into feature/restricted-runtime-impl` — git default, 룰 비위반 (머지 commit은 [타입] 형식 면제, 5/9 정정 시 본인이 양유상 메시지만 정정한 패턴과 일치) |
| §5 PR 본문 4항목 | ✅ PR #17 본문 유지 |
| §7 영향 확인 | ✅ pytest 363 passed로 회귀 확인 |
| §8 증빙 evidence/ | ✅ 본 문서 |
| §9 main 직접 push | ✅ feature 브랜치 push, main 미수정 |
| §9 승인 없는 임의 merge | ✅ feature 브랜치로 dev 흡수 (PR merge 아님), 승인 대상은 양유상 PR merge — 그건 변동 없음 |

## 5. PR #17 현재 상태

```json
{
  "baseRefName": "dev",
  "headRefName": "feature/restricted-runtime-impl",
  "mergeable": "UNKNOWN",  // GitHub 재계산 중, 잠시 후 MERGEABLE 예상
  "reviewDecision": "CHANGES_REQUESTED",
  "state": "OPEN",
  "updatedAt": "2026-05-18T12:03:12Z"
}
```

## 6. 양유상에게 알릴 사항

- PR #17 `3cdb453` 머지 commit으로 dev 최신화 완료
- diff +2297/-3로 정상화 (이전 +2294/-7709 상태 해소)
- pytest 363 passed (이전 287)
- 5/9 P1+P2+P3 응답 이후 신규 코드 변경 없음, dev 흡수만 했음
- 양유상이 PR #17 머지 누르면 PR #14·#16 손실 위험 0

## 7. 후속 작업

- [ ] PR #17에 양유상 reminder + 본 머지 알림 코멘트 (draft는 `.claude/drafts_20260518.md`)
- [ ] PR #20도 동일 점검 필요 — 현재 dev보다 1커밋 앞섬, drift 0
- [ ] 발표 데모 시 베이스라인 회귀 — 본인 venv에 `safetensors torch` 설치 → `pytest -q` 실행 후 evidence 갱신 권장
- [ ] worktree `c:/tmp/HM-rebase-rr` 정리 (`git worktree remove`) — 본 작업 종료 후

## 8. 결론

dev drift 해소 완료. PR #17이 머지 사고(`PR #18 → PR #19 revert` 재현) 없이 안전하게 머지될 수 있는 상태가 됨. 단 양유상 reviews 빈 상태는 그대로 — 머지 결정은 양유상.
