# HuggingMask

AI 모델 공급망 보안을 위한 프록시 기반 검증 프로젝트입니다.

## 1. 프로젝트 개요
- 목표: 안전하지 않은 모델/코드를 사전에 탐지하고 차단할 수 있는 검증 파이프라인 구축
- 팀 표준: Python `3.13`, 공통 포트 `8000`, 실행 기준 `docker compose up --build`
- 작업 흐름: `feature/*`에서 개발 후 `dev`로 PR, 안정화 후 `main` 반영
- 현재 기준: 가중치, 코드, config, whitelist, 제한 런타임을 묶는 통합 검증 경로까지 구현했고 최종 데모/운영 안정화 단계

## 2. 폴더 구조
```text
HuggingMask/
├─ .github/
│  ├─ PULL_REQUEST_TEMPLATE.md
│  └─ CODEOWNERS
├─ proxy/
│  └─ app/
├─ analyzer/
│  ├─ README.md
│  ├─ classifier.py
│  ├─ orchestrator.py
│  ├─ schemas.py
│  ├─ service.py
│  └─ validators/
├─ whitelist/
├─ sandbox/
├─ tests/
├─ docs/
├─ evidence/
│  ├─ worklog/
│  ├─ meetings/
│  ├─ tests/
│  ├─ demo/
│  ├─ perf/
│  └─ budget/
├─ requirements.txt
├─ Dockerfile
├─ compose.yaml
├─ CONTRIBUTING.md
├─ SETUP_GUIDE.md
└─ TASK_GUIDE.md
```

## 3. 실행 명령
```bash
docker compose up --build
```

실행 후 확인:
- `http://127.0.0.1:8000/health`
- `http://127.0.0.1:8000/docs`
- `POST http://127.0.0.1:8000/internal/v1/validation/jobs`
  - 가중치 검증 중심 endpoint
- `POST http://127.0.0.1:8000/internal/v1/validation/full`
  - 가중치 + 코드 + config + whitelist + 제한 런타임 통합 검증 endpoint
- `http://127.0.0.1:8000/dashboard`
  - whitelist/pending/audit/feedback 운영 대시보드

## 4. 브랜치 규칙
- 기본 브랜치: `main`, `dev`
- 작업 브랜치: `feature/*`
- PR 방향: `feature/*` -> `dev`
- 금지: `main` 직접 수정/직접 push

## 5. 테스트 명령
```bash
python -m pytest -q
```

현재 기준 검증 결과:
- 2026-05-22 기준 `python -m pytest -q` -> `647 passed, 1 skipped`
- `/health` 응답 코드 `200`
- 통합 endpoint와 dashboard 관련 회귀 테스트 포함

## 6. 현재 역할 분배
- 박용담: 파일분류, `config.json`, `tokenizer_config.json`, 공통 JSON 스키마/계약, 최종 응답 조립 기준
- 정은미: 가중치검증경로, safetensors 검증, pickle Path A/Path B 검증
- 양유상: 코드검증경로, 검증1(`CODE_AST_SCAN`), 검증2(`CODE_RESTRICTED_RUNTIME`), 검증3(`CODE_SANDBOX_RUNTIME`)
- 김민우: 적응형 화이트리스트 엔진, allow/block/unknown/pending 판정, pending API 저장/갱신, 통합 검증 endpoint 연결

## 7. 담당 모듈 설명
- `proxy`: FastAPI 진입점. health, 가중치 검증, 통합 검증, whitelist 운영 API, dashboard 제공
- `analyzer`: 공통 schema, 파일 분류, 가중치 검증 service, 코드/config orchestrator의 중심 모듈
- `analyzer/validators`: safetensors/pickle, 코드 AST/API/context, 제한 런타임, 전처리 metadata semantic 검증 경로
- `whitelist`: adaptive whitelist, pending API 영속 저장, review, audit, feedback, 통합 검증 병합 로직
- `sandbox`: B-2/C 후보에 대한 격리 실행 증거 수집 경로. 현재 phase0/정책 게이트 중심 구현

## 8. 시작 전 읽을 문서
- [CONTRIBUTING.md](./CONTRIBUTING.md): Git/PR/리뷰/커밋 규칙
- [SETUP_GUIDE.md](./SETUP_GUIDE.md): 환경 설치 및 실행 절차
- [TASK_GUIDE.md](./TASK_GUIDE.md): 구현 착수 및 작업 운영 가이드
