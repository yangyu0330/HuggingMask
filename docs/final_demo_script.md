# HuggingMask 최종 데모 스크립트

최종 확인일: 2026-06-08
발표 기준 상태: Docker build 통과, 컨테이너 `/health` 200, `/docs` 200, `python -m pytest -q` 결과 `700 passed, 1 skipped`

## 1. 문서 목적
- 발표용 5개 시나리오의 실행 순서와 설명 포인트를 고정한다.
- 개발/테스트/증빙이 같은 기준을 공유하도록 만든다.
- 발표 직전에도 "무엇을 왜 보여주는지" 흔들리지 않게 한다.

## 2. 데모 전 준비

### 공통 준비
- Docker Desktop 실행
- `docker compose up --build`
- `/health` 200 확인
- `/docs` Swagger UI 로드 확인
- `/dashboard` 운영 화면 로드 확인
- 데모 대상 fixture repo 5개 준비
- 화면 녹화 또는 캡처 저장 경로 준비: `evidence/demo/`

### 포트 점검
표준 발표 포트는 `8000`이다. 발표 전 아래 명령으로 충돌 여부를 확인한다.

```powershell
Get-NetTCPConnection -LocalPort 8000
```

이미 다른 서버가 `8000`을 쓰고 있으면 해당 프로세스를 종료한 뒤 `docker compose up --build`를 다시 실행한다. 임시 점검용으로는 `docker run -p 8010:8000 huggingmask-proxy:latest`처럼 다른 host port를 사용할 수 있지만, 발표 대본은 `8000` 기준으로 통일한다.

### 정책 프로파일
- 시나리오 1, 2, 3, 5: `strict_default`
- 시나리오 4: `allow_custom_code_scan`

### 실데이터 리허설 명령
실제 Hugging Face 모델을 넣는 경우, 다운로드된 파일 경로를 API가 직접 읽어야 하므로 리허설은 로컬 `uvicorn`으로 실행한다.

```powershell
python -m uvicorn proxy.app.main:app --host 127.0.0.1 --port 8011
```

정상 safetensors fast path:

```powershell
python scripts/demo_validate_hf.py sentence-transformers-testing/stsb-bert-tiny-safetensors --api http://127.0.0.1:8011 --cache-dir .cache\hf_demo --include model.safetensors
```

기대 결과:
- `overall_decision=APPROVE`
- `status=PASS`
- `reason=SAFE_TENSORS_HASH_OK`

실제 repo 전체 검증:

```powershell
python scripts/demo_validate_hf.py sentence-transformers-testing/stsb-bert-tiny-safetensors --api http://127.0.0.1:8011 --cache-dir .cache\hf_demo
```

기대 결과:
- `overall_decision=REVIEW_REQUIRED`
- safetensors는 `PASS`
- legacy `pytorch_model.bin`과 preprocessing metadata는 review로 분리

악성 pickle 실데이터:

```powershell
python scripts/demo_validate_hf.py timotejKralik/pickle_malicious_test --api http://127.0.0.1:8011 --cache-dir .cache\hf_demo --include params.pkl
```

기대 결과:
- `overall_decision=DENY`
- `status=BLOCK`
- `reason=PICKLE_OPCODE_BLOCKED`

악성 config/custom code 실데이터:

```powershell
python scripts/demo_validate_hf.py FIRSTACCOUNT69/auto-map-test --api http://127.0.0.1:8011 --cache-dir .cache\hf_demo --include config.json --include model.py
```

기대 결과:
- `overall_decision=DENY`
- `config.json`: `CONFIG_TRIGGER_FIELD_FOUND`
- `model.py`: `DANGEROUS_IMPORT`

## 3. 발표 흐름 요약

| 순서 | 시나리오 | 핵심 메시지 | 기대 판정 |
|---|---|---|---|
| 1 | 정상 safetensors | 안전 포맷은 빠르게 통과 | PASS |
| 2 | 정상 pickle | legacy 포맷도 안전 서브셋이면 변환 산출물만 release | PASS |
| 3 | 악성 pickle | 실행 opcode 하나로 즉시 차단 | BLOCK |
| 4 | 악성 코드 | AST 단계에서 실행 없이 차단 | BLOCK |
| 5 | 악성 config | 설정 파일의 실행 트리거도 차단 | BLOCK |

## 4. 시나리오별 대본

## 4.1 시나리오 1 - 정상 safetensors
- 발표 멘트:
  - "먼저 정상 safetensors 모델입니다."
  - "안전한 포맷은 fast-path로 처리해 성능을 해치지 않습니다."
- 운영자 확인 포인트:
  - file type = `SAFETENSORS`
  - SHA256 확인
  - PASS
  - 2회차 요청 시 `CACHE_HIT`
- 캡처 권장 파일명:
  - `evidence/demo/2026XXXX_demo_s01_pass.png`

## 4.2 시나리오 2 - 정상 pickle
- 발표 멘트:
  - "다음은 정상 pickle이지만 실행 가능한 pickle 전체를 허용하지는 않습니다."
  - "안전한 data-only subset만 Path A로 통과시키고 최종 배포는 safetensors로 변환합니다."
- 운영자 확인 포인트:
  - file type = `PICKLE`
  - opcode whitelist 통과
  - safetensors 변환 성공
  - raw pickle 원본은 release 대상이 아님
  - PASS
- 캡처 권장 파일명:
  - `evidence/demo/2026XXXX_demo_s02_pass_transform.png`

## 4.3 시나리오 3 - 악성 pickle
- 발표 멘트:
  - "겉보기엔 정상 pickle과 비슷하지만, 실행 opcode 하나 때문에 차단됩니다."
  - "핵심은 REDUCE 탐지 즉시 차단입니다."
- 운영자 확인 포인트:
  - `REDUCE` 탐지
  - BLOCK
  - release 없음
- 캡처 권장 파일명:
  - `evidence/demo/2026XXXX_demo_s03_block_pickle.png`

## 4.4 시나리오 4 - 악성 코드
- 발표 멘트:
  - "이 시나리오는 config가 아니라 .py 코드 본문 자체가 문제입니다."
  - "실행하지 않고 AST 단계에서 위험 호출을 차단합니다."
- 운영자 확인 포인트:
  - 데모 프로파일 = `allow_custom_code_scan`
  - AST parse 성공
  - `__import__` 또는 `eval` 탐지
  - BLOCK
- 캡처 권장 파일명:
  - `evidence/demo/2026XXXX_demo_s04_block_code.png`

## 4.5 시나리오 5 - 악성 config
- 발표 멘트:
  - "마지막은 코드가 아니라 설정 파일 자체가 문제인 경우입니다."
  - "`auto_map`과 `custom_pipelines`가 실행 경로를 열기 때문에 차단합니다."
- 운영자 확인 포인트:
  - route = `CONFIG_SCHEMA_VALIDATION`
  - trigger field 탐지
  - BLOCK
- 캡처 권장 파일명:
  - `evidence/demo/2026XXXX_demo_s05_block_config.png`

## 5. 발표 시간 배분 권장

| 구간 | 시간 |
|---|---:|
| 프로젝트 한 줄 소개 | 30초 |
| 시나리오 1 | 40초 |
| 시나리오 2 | 50초 |
| 시나리오 3 | 50초 |
| 시나리오 4 | 50초 |
| 시나리오 5 | 50초 |
| 정리 멘트 | 30초 |

총 권장 시간: 약 4분 20초

## 6. 정리 멘트
- "HuggingMask는 모델 파일, 코드, 설정을 각각 다른 기준으로 검사합니다."
- "정상 모델은 빠르게 통과시키고, 위험한 입력은 실행 전에 차단합니다."
- "특히 pickle, custom code, config trigger를 분리해 설명 가능한 보안 흐름을 제공합니다."

## 7. 데모 직전 점검표
- [ ] fixture repo 5개 준비 완료
- [ ] 정책 프로파일 구분 확인
- [ ] 기대 판정과 실제 로그 일치 확인
- [ ] `evidence/demo/` 저장 경로 준비
- [ ] 인터넷 없이도 데모 가능한지 확인
- [ ] `python -m pytest -q` 최신 결과 기록
- [ ] Docker Desktop 실행 및 `docker compose up --build` 성공
- [ ] `8000` 포트 충돌 없음
- [ ] `/health`, `/docs`, `/dashboard` 접속 확인
