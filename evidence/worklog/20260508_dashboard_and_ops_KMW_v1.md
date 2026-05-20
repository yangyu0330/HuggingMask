# Worklog — 운영 대시보드 + bulk 스크립트 이식 (Step C)

- **작성자:** 김민우 (KMW)
- **일시:** 2026-05-08
- **브랜치:** `feature/whitelist-dashboard-ops` (← `origin/dev`)
- **PR 대상:** `dev`
- **목적:** 적응형 화이트리스트 엔진 5개 모듈 풀스택 데모를 위한 **보안 담당자 운영 UI** + **일괄 승인 스크립트**

## 작업 내용

### 신규 파일
| 파일 | 역할 |
|---|---|
| `whitelist/static/dashboard.html` | 4탭 운영 대시보드 (분류 테스트 / 리뷰 대기 / 승인 / 오탐 / 감사) |
| `scripts/bulk_approve.py` | AUTO_APPROVE 분류 PENDING API 일괄 승인 CLI |
| `scripts/bulk_conditional.py` | CONDITIONAL 중 안전 namespace + 위험 키워드 없음 일괄 승인 CLI |
| `scripts/__init__.py` | 패키지 인식 |
| `tests/test_dashboard_and_ops.py` | 15 단위/통합 테스트 |

### 수정 파일
| 파일 | 변경 |
|---|---|
| `proxy/app/main.py` | `/dashboard` HTML 엔드포인트 추가 |
| `whitelist/router.py` | `GET /internal/v1/approved` 엔드포인트 신규 (검색·namespace·source 필터·페이지네이션) |

## 원본 → HuggingMask 적응 사항

원본 `adaptive-whitelist-engine`에서 가져온 자료를 우리 인터페이스 정의서 v1.0에 맞춰 변환:

| 항목 | 원본 | HuggingMask |
|---|---|---|
| API base | `/api/v1` | `/internal/v1` |
| Pending classification enum | `auto_approve` | `AUTO_APPROVE` |
| Review status enum | `pending` | `PENDING` |
| WhitelistStatus 4-state | (없음, /classify 응답) | `ALLOWED` / `BLOCKED` / `PENDING` / `UNKNOWN` |
| ApprovedApi.added_by | `added_by` (lowercase) | `source` (대문자 `INITIAL` / `AUTO_CRAWL` / `MANUAL_REVIEW`) |
| 위험 키워드 키 | `danger_keywords_found` | `risk_keywords` |
| 분류 endpoint | `POST /classify` | `POST /whitelist/check` (인터페이스 14.1 → 14.2) |
| Approved 엔드포인트 | `GET /approved` (있음) | `GET /approved` 신규 추가 (없었음) |

## 검증 결과

```
224 passed in 13.04s
```

| 시점 | 케이스 |
|---|---|
| origin/dev | 209 |
| **본 PR (Step C)** | **224** (+15) |

### 회귀 분류

- **TestDashboardEndpoint** (5) — `GET /dashboard` 200 + HTML body + `/internal/v1` prefix + 대문자 enum + 4탭 마크업 + `risk_keywords` 키 사용
- **TestApprovedListEndpoint** (6) — 시드 145 nx page / search / namespace / source filter / pagination / 응답 키
- **TestBulkScripts** (3) — bulk_approve / bulk_conditional 모듈 import + 정합성 (SAFE_NAMESPACES, SKIP_KEYWORDS와 우리 DANGER_KEYWORDS 교집합) + DEFAULT_API_BASE 대소문자
- **TestDashboardFlow** (1) — 대시보드 시뮬: check → pending 등록 → review approve → approved 목록 등장

상세: [evidence/tests/20260508_dashboard_ops_pytest_raw_KMW_v1.txt](../tests/20260508_dashboard_ops_pytest_raw_KMW_v1.txt)

## 책임 경계

- 양유상/박용담/정은미 영역 무수정
- 대시보드는 정적 HTML — JS가 우리 `/internal/v1` API 호출만
- bulk 스크립트는 외부 운영 도구 — `httpx` 클라이언트로 우리 endpoint 호출

## 데모 흐름 (발표용)

```bash
# 1. 서버 기동
docker compose up --build

# 2. 브라우저로 대시보드 접속
http://127.0.0.1:8000/dashboard

# 3. (선택) bulk 승인 - 시연 후 PENDING 가득 찬 상태에서
python scripts/bulk_approve.py
python scripts/bulk_conditional.py
```

## 변경 통계

- 신규 코드: ~830줄 (dashboard.html JS 적응 + bulk × 2 + tests)
- 변경 파일: 6개 (신규 5 + 수정 2)
- 회귀: 209 → 224 (+15)

## 후속 (Step C 범위 밖)

- mod1 / mod2 데이터 보강 후 대시보드 "verified org" 컬럼 추가 (PR #16 머지 후 별도)
- 대시보드 i18n (현재 한국어 only)
- bulk 스크립트 dry-run 옵션 (현재 즉시 적용)
