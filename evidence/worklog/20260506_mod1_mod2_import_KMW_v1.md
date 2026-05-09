# Worklog — 모듈 1 (공식 문서 크롤러) + 모듈 2 (Verified Org 분석) 이식

- **작성자:** 김민우 (KMW)
- **일시:** 2026-05-06
- **브랜치:** `feature/whitelist-mod1-mod2-import` (← `origin/dev`)
- **PR 대상:** `dev`
- **선행 PR:** 무관 (PR #14 어댑터와는 독립)
- **목적:** 적응형 화이트리스트 엔진의 5개 모듈 중 mod1·mod2를 HuggingMask로 이식해 `verified_org_count` / `in_official_docs`를 진짜 데이터로 채움

## 배경

PR #9 머지 직후 worklog의 Future Work에 적었던 항목 — `adaptive-whitelist-engine` 별도 디렉토리에 이미 구현되어 있던 mod1·mod2 코드와 캐시 데이터를 HuggingMask `whitelist/`로 들여온다. 이전까지 `feedback.py`에서 `in_official_docs = matched is not None` 임시 로직, `verified_org_count = 0` 하드코딩이었던 부분을 진짜 데이터 기반으로 교체한다.

## 작업 내용

### 신규 파일 (`whitelist/`)

| 파일 | 역할 |
|---|---|
| `whitelist/mod1_doc_crawler.py` | mockable 추상 인터페이스 + regex 파서 (PyTorch/Transformers/Numpy) + `OfficialDocCrawler` |
| `whitelist/mod1_real_crawler.py` | `HttpxFetcher` (HTTPS+TLS+rate limit+재시도) + BS4 정밀 파서 + `CrawlCache` (TTL 7일) + `RealDocCrawler` + CLI(`--library`/`--apply`/`--dry-run`) |
| `whitelist/mod1_package_inspector.py` | `importlib + inspect`로 설치 패키지 직접 검사 (크롤링 대안) + CLI |
| `whitelist/mod2_verified_org.py` | `PythonApiExtractor` (AST alias 해소) + `VerifiedOrgAnalyzer` + `extract_apis_from_config` (auto_map / architectures / model_type 폴백) |
| `whitelist/mod2_real_fetcher.py` | `HuggingFaceApiFetcher` (HF Hub `/api/models` + raw 파일) + `RealOrgAnalyzer` + 캐시 자동 저장 + CLI |
| `whitelist/cache_loader.py` | `OrgCache` 메모리 싱글턴 + `is_in_official_docs` DB 조회 + `apply_crawl_results_to_db` (mod1 결과 → ApprovedApi 자동 등록) |

### 수정 파일 (`whitelist/`)

| 파일 | 변경 |
|---|---|
| `whitelist/rules.py` | `CRAWL_TARGETS` (PyTorch 10페이지 + Transformers 4 + Numpy 4), `VERIFIED_ORGANIZATIONS` (9개 org), `ALLOWED_CRAWL_DOMAINS`, `CRAWL_SPIKE_THRESHOLD=100` 추가 |
| `whitelist/pending_store.py` | `upsert_pending`에서 호출자가 `verified_org_count`/`list`/`in_official_docs` 명시 안 하면 cache_loader에서 자동 채움 |
| `whitelist/feedback.py` | 임시 `in_official = matched is not None` 제거 → `is_in_official_docs(db, api_path)`. `verified_org_count = 0` → `org_cache.lookup_verified_org_count` |

### 신규 테스트 (49 케이스)

- `tests/test_mod1_doc_crawler.py` (15)
- `tests/test_mod2_verified_org.py` (19)
- `tests/test_cache_loader.py` (15)

### 신규 데이터

- `data/org_analysis_cache/latest_analysis.json` — 원본에서 가져온 mod2 분석 결과 (6 org × 18 모델 메타데이터, `unregistered_apis` 빈 결과 — mod2 재실행으로 갱신 가능)
- `data/crawl_cache/.gitkeep` — mod1 HTML 캐시 디렉토리 placeholder
- `data/README.md` — mod1/mod2 사용법 + 보안 원칙

### 의존성

- `beautifulsoup4>=4.12` (mod1 BS4 파서)
- `lxml>=5.0` (BS4 백엔드, 빠른 파싱)

### .gitignore 추가

```
data/crawl_cache/*.json       # HTML 캐시 (TTL 7일, 갱신될 때마다 변동)
data/crawl_output.json        # mod1 임시 출력
data/api_inspection.json      # package_inspector 임시
data/api_pytorch.json         # PyTorch API 추출 (~9MB)
data/org_analysis_output.json # mod2 임시
```

## 수정 이유

### 1. 적응형이 진짜 적응형이 되려면 mod1·mod2가 필수

이전까지:
```json
"in_official_docs": false,      // 항상
"verified_org_count": 0,         // 항상
```

이는 [메모리 기록](C:\Users\minwo\.claude\projects\c--Users-minwo-Downloads-adaptive-whitelist-engine\memory\project_context.md)에 따른 "5개 모듈 중 ①②③④⑤" 중 ①②가 빠진 상태. 캡스톤 발표/논문 관점에선 이 데이터가 진짜로 채워져야 "적응형 화이트리스트"라는 이름값을 함.

### 2. 원본 코드 거의 그대로 재사용

`adaptive-whitelist-engine/whitelist_engine/modules/mod1_*`, `mod2_*`이 이미 production-quality. 변경한 건:
- import 경로: `whitelist_engine.*` → `whitelist.*`
- 분류기: `mod3_api_classifier.get_classifier()` → 우리 `engine._Classifier()`
- DB 모델: `AddedBy.AUTO_CRAWL` → `WhitelistSource.AUTO_CRAWL`
- 캐시 위치: `./crawl_cache` → `data/crawl_cache`, `./org_analysis_cache` → `data/org_analysis_cache`

### 3. Cache loader 통합 패턴

`pending_store.upsert_pending`이 호출자가 명시 안 한 필드만 자동 채우도록 했다. 즉:
- 검증 흐름 자동 등록 (`engine.check_batch`): cache_loader에서 자동 채움
- 외부 `/pending/upsert` API: record 값을 그대로 저장 (PR #9의 양유상 리뷰 옵션 2 정책 유지)
- 명시적 호출 (테스트 등): cache_loader 무시

이로써 기존 PR #9의 round-trip 계약(`test_pending_upsert_contract.py` 14 케이스)이 그대로 통과.

## 테스트 결과

```
258 passed in 4.41s
```

| 시점 | 케이스 |
|---|---|
| PR #9 머지 직후 | 87 |
| dev (PR #10·#11·#12 머지 후) | 209 |
| **본 PR (mod1·mod2 이식)** | **258** (+49) |

상세: [evidence/tests/20260506_mod1_mod2_pytest_summary_KMW_v1.md](../tests/20260506_mod1_mod2_pytest_summary_KMW_v1.md)
원본 로그: [evidence/tests/20260506_mod1_mod2_pytest_raw_KMW_v1.txt](../tests/20260506_mod1_mod2_pytest_raw_KMW_v1.txt)

## 데모 시나리오 (수동 검증 가능)

```bash
# mod1: 패키지 직접 검사 (네트워크 없이도 가능, 설치된 torch/transformers 필요)
python -m whitelist.mod1_package_inspector --library pytorch --output data/api_pytorch.json

# mod1: 공식 문서 크롤 (네트워크 필요, 결과를 ApprovedApi에 자동 등록)
python -m whitelist.mod1_real_crawler --library all --apply --dry-run
python -m whitelist.mod1_real_crawler --library all --apply

# mod2: Verified Org 분석 (HuggingFace Hub API, latest_analysis.json 갱신)
python -m whitelist.mod2_real_fetcher --models 5

# 갱신 후 서버 재시작 또는 cache_loader.reset_org_cache() 호출하면
# 다음 upsert_pending부터 verified_org_count / in_official_docs 자동 반영
```

## 변경 통계

- 신규 코드: ~2400줄 (whitelist/ 6 파일 + tests/ 3 파일)
- 캐시 데이터: 2 KB (latest_analysis.json) + 빈 placeholder
- 의존성: bs4 + lxml 2개
- 회귀 테스트: 209 → 258 (+49)

## 확인 요청 사항

1. **자동 등록 분류 정책** — `apply_crawl_results_to_db`의 기본값을 `AUTO_APPROVE`만으로 했는데, CONDITIONAL도 자동 등록할지(보안 vs 운영 편의 트레이드오프). 현재는 명시적 옵션(`--apply-classifications`)으로 운영자가 결정.
2. **mod1 크롤 주기** — 현재는 수동 CLI. 추후 cron/celery 등 백그라운드 워커가 필요한지, 아니면 발표/캡스톤 관점에선 수동으로 충분한지.
3. **mod2 캐시 갱신 trigger** — `cache_loader.reset_org_cache()`를 명시적 호출해야 메모리 갱신. 운영 환경에서 file watcher나 TTL 자동 reload가 필요한지.
4. **빈 캐시 처리** — 현재 원본 `latest_analysis.json`은 unregistered_apis가 비어있는 상태. 데모 직전 한 번 `python -m whitelist.mod2_real_fetcher --models 5`로 갱신하면 의미 있는 데이터로 교체됨. 발표 직전 절차에 추가 필요.

## 다음 단계

- Step C: dashboard.html 이식 + `/internal/v1` 경로 수정 + proxy `/dashboard` 라우트
- Step C: bulk_approve.py / bulk_conditional.py 운영 스크립트
- (별개) PR #14 양유상 리뷰 응답
