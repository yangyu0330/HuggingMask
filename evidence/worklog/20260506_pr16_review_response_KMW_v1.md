# Worklog — PR #16 양유상 리뷰 응답

- **작성자:** 김민우 (KMW)
- **일시:** 2026-05-06
- **PR:** #16 (`feature/whitelist-mod1-mod2-import` → `dev`)
- **응답 대상:** 양유상 리뷰 (2026-05-06 07:04 UTC, CHANGES_REQUESTED)

## 양유상 지적 (요약)

### 1. 도메인 화이트리스트 suffix 우회 취약점

> `host.endswith(d)`로 허용 도메인을 검사하면 `pytorch.org`가 허용된 상태에서
> `evilpytorch.org` 같은 전혀 다른 도메인도 통과할 수 있습니다.
>
> `host == d or host.endswith("." + d)`처럼 정확한 도메인 또는 하위 도메인만
> 허용하도록 수정하고, 같은 패턴이 있는 `mod1_doc_crawler.py`의
> `_is_allowed_url()`도 함께 수정하면 좋겠습니다.

### 2. API별 사용 모델 evidence가 조직 전체 모델로 부풀려집니다

> `aggregate_org_results()`가 특정 API를 실제 사용한 모델만 넣는 게 아니라,
> 해당 org에서 분석한 모든 모델을 각 API의 `used_by_models`에 붙이고 있습니다.
> 예를 들어 model A만 `torch.nn.Linear`를 쓰고 model B만 `numpy.zeros`를 써도
> 두 API 모두 `used_by_models=[A, B]`가 됩니다.

둘 다 정확한 지적. 보안(1) + 데이터 정확성(2) 모두 핵심.

## 해결

### 1. 정확 매칭 + dot 경계

`whitelist/mod1_doc_crawler.py::OfficialDocCrawler._is_allowed_domain`:
```python
return any(
    host == d or host.endswith("." + d)
    for d in ALLOWED_CRAWL_DOMAINS
)
```

`whitelist/mod1_real_crawler.py::HttpxFetcher.get`도 같은 패턴 적용.

이제 `evilpytorch.org`, `pytorch.org.attacker.com`, `fakehuggingface.co` 같은 우회는 차단되고, `docs.pytorch.org`, `www.numpy.org` 같은 정상 하위 도메인은 통과.

### 2. `apis_by_model` — API별 실제 사용 모델 추적

`OrgAnalysisResult`에 `apis_by_model: dict[str, list[str]]` 필드 추가:
```python
@dataclass
class OrgAnalysisResult:
    ...
    apis_found: dict[str, int]
    apis_by_model: dict[str, list[str]] = field(default_factory=dict)  # ★
    ...
```

`VerifiedOrgAnalyzer.analyze_org`가 모델 단위로 추출 결과를 누적:
```python
for model_info in models:
    apis_for_this_model: set[str] = set()
    for filename in py_files:
        apis = self._extractor.extract_all(source)
        for api in apis:
            apis_for_this_model.add(api)
    # 이 모델이 실제 사용한 API에만 model_id 등록
    for api in apis_for_this_model:
        apis_by_model.setdefault(api, []).append(model_id)
```

`aggregate_org_results`가 `apis_by_model.get(api_path, [])`만 누적 — `models_analyzed` (조직 전체 모델) 사용하지 않음.

`apis_found: dict[str, int]`는 호환성 유지 (카운트 요약). source of truth는 `apis_by_model`.

## 회귀 테스트 (8 신규)

| 테스트 | 검증 |
|---|---|
| `TestYangyuPR16Regression::test_used_by_models_only_actual_users` | **양유상 재현 시나리오 그대로** — A만 X, B만 Y → used_by_models 부풀어오르지 않음 |
| `TestYangyuPR16Regression::test_apis_by_model_populated_by_analyzer` | analyze_org가 모델 단위 추출을 정확히 누적 |
| `TestDomainAllowlistSuffixBypass::test_exact_domain_allowed` | pytorch.org / numpy.org / huggingface.co 자체 OK |
| `TestDomainAllowlistSuffixBypass::test_subdomain_allowed` | docs.pytorch.org / www.numpy.org OK |
| `TestDomainAllowlistSuffixBypass::test_suffix_bypass_blocked` | **양유상 재현** evilpytorch.org / fakehuggingface.co / pytorch.org.attacker.com 차단 |
| `TestDomainAllowlistSuffixBypass::test_unrelated_domain_blocked` | evil.com 차단 |
| `TestDomainAllowlistSuffixBypass::test_real_fetcher_blocks_suffix_bypass` | HttpxFetcher.get도 동일 강화 |
| `TestDomainAllowlistSuffixBypass::test_real_fetcher_rejects_non_https` | https 외 scheme 거부 (분리 책임) |

## 변경 파일

수정:
- `whitelist/mod1_doc_crawler.py` — `_is_allowed_domain` 정확 매칭
- `whitelist/mod1_real_crawler.py` — `HttpxFetcher.get` 정확 매칭
- `whitelist/mod2_verified_org.py` — `OrgAnalysisResult.apis_by_model`, `analyze_org` 모델별 누적, `aggregate_org_results` source 변경
- `tests/test_mod2_verified_org.py` — `_make_result` 시그니처 + 8 회귀 테스트

## 테스트 결과

```
266 passed in 8.53s
```

| 시점 | 케이스 |
|---|---|
| PR #16 commit 전 | 258 |
| **양유상 리뷰 응답 (본 commit)** | **266** (+8) |

원본 로그: [evidence/tests/20260506_pr16_review_response_pytest_raw_KMW_v1.txt](../tests/20260506_pr16_review_response_pytest_raw_KMW_v1.txt)

## 호환성

`OrgAnalysisResult.apis_by_model`은 default `{}`인 신규 필드. 기존 `_make_result(...)` 호출자가 이 인자 없이도 동작 (호환). 이전 PR #9의 round-trip 계약과 무관.
