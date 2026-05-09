# data/ — 모듈 1·2 캐시 및 출력

이 디렉토리는 적응형 화이트리스트 엔진 모듈 1·2의 캐시 데이터와 임시 출력
파일을 둔다.

## 구조

```
data/
├── crawl_cache/                 # 모듈 1 HTML 캐시 (TTL 7일, gitignored)
│   └── <sha16>.json
├── org_analysis_cache/
│   └── latest_analysis.json    # 모듈 2 분석 결과 (commit 대상)
├── crawl_output.json            # mod1 임시 결과 (gitignored)
├── api_inspection.json          # mod1 package_inspector 임시 (gitignored)
├── api_pytorch.json             # mod1 PyTorch API 추출 (gitignored, ~9MB)
└── org_analysis_output.json     # mod2 임시 출력 (gitignored)
```

## 사용

### mod1 — 공식 문서 크롤러

```bash
# 크롤만
python -m whitelist.mod1_real_crawler --library pytorch

# 크롤 + ApprovedApi 자동 등록 (AUTO_APPROVE만)
python -m whitelist.mod1_real_crawler --library all --apply

# 크롤 + dry-run (DB 변경 없이 카운트만)
python -m whitelist.mod1_real_crawler --library all --apply --dry-run
```

설치된 패키지에서 직접 추출 (크롤링 대안):
```bash
python -m whitelist.mod1_package_inspector --library pytorch
```

### mod2 — Verified Org 분석

```bash
# 모든 verified org 분석 (latest_analysis.json 갱신)
python -m whitelist.mod2_real_fetcher --models 5

# 특정 조직만
python -m whitelist.mod2_real_fetcher --org meta-llama --models 10
```

`latest_analysis.json`이 갱신되면 다음 ``upsert_pending`` 호출부터
``verified_org_count`` / ``verified_org_list``가 자동 채워진다 (서버 재시작 또는
``cache_loader.reset_org_cache()`` 호출 후).

## 보안

- mod1 크롤링은 HTTPS + 도메인 화이트리스트(pytorch.org / huggingface.co / numpy.org)만 허용
- mod2 HuggingFace Hub API도 HTTPS만 사용
- 코드 실행 없음 (HTML/AST 파싱만)
- 급격한 변화 탐지: 한 번의 크롤에서 100+ 신규 API 발견 시 자동 플래그
