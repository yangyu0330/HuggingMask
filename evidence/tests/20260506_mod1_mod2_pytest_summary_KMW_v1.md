# Pytest Summary — mod1 / mod2 / cache_loader (2026-05-06 KMW)

- **브랜치:** `feature/whitelist-mod1-mod2-import`
- **베이스:** `origin/dev`
- **결과:** **258 passed in 4.41s**
- **원본 로그:** [20260506_mod1_mod2_pytest_raw_KMW_v1.txt](20260506_mod1_mod2_pytest_raw_KMW_v1.txt)

## 신규 49개 분류

| 파일 | 케이스 수 | 검증 |
|---|---|---|
| `tests/test_mod1_doc_crawler.py` | 15 | regex 파서, OfficialDocCrawler, 도메인 화이트리스트, spike, 분류기 통합 |
| `tests/test_mod2_verified_org.py` | 19 | PythonApiExtractor, extract_apis_from_config, VerifiedOrgAnalyzer, aggregate |
| `tests/test_cache_loader.py` | 15 | OrgCache 로드/degrade, is_in_official_docs, apply_crawl_results_to_db, pending_store auto-fill |

## 회귀 변화

| 시점 | 케이스 |
|---|---|
| dev 기준 (PR #10·#11·#12 머지 후) | 209 |
| **본 PR (mod1·mod2 이식)** | **258** (+49) |

## 핵심 검증 포인트

- 4-state 우선순위(block > allow > pending > unknown) 영향 없음
- `upsert_pending`이 호출자 명시 안 한 경우만 자동 채움 (기존 `test_pending_upsert_contract` 14 케이스 모두 통과)
- mod1 자동 등록은 기본 `AUTO_APPROVE`만 (`PERMANENTLY_BLOCKED` 방어 회귀)
- mod2 캐시 미존재/깨진 JSON일 때 graceful degrade (verified_org_count=0, empty list)
- ApprovedApi `source=MANUAL_REVIEW`는 "공식 문서 등록"으로 보지 않음 (`is_in_official_docs` False)

## 책임 경계 (engine.md:21 준수)

- mod1·mod2는 **데이터 보강** 모듈로만 동작
- 4-state 판정 권한은 여전히 `WhitelistEngine`만 보유
- 코드 등급(A/B-1/B-2/C) 결정은 양유상 코드 검증자 책임 (변경 없음)
