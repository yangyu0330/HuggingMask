# HuggingMask

AI 모델 공급망 보안을 위한 프록시 기반 검증 프로젝트입니다.

## 1. 프로젝트 개요
- 목표: 안전하지 않은 모델 파일, 설정, 커스텀 코드를 실행 전에 탐지하고 차단할 수 있는 검증 파이프라인 구축
- 팀 표준: Python `3.12`, 공통 포트 `8000`, 실행 기준 `docker compose up --build`
- 작업 흐름: `feature/*`에서 개발 후 `dev`로 PR, 안정화 후 `main` 반영
- 현재 기준: `proxy` FastAPI 진입점에서 `analyzer`, `whitelist`, `dashboard`가 연결된 발표용 MVP 상태

## 2. 폴더 구조
```text
HuggingMask/
├─ .github/
│  ├─ PULL_REQUEST_TEMPLATE.md
│  └─ CODEOWNERS
├─ proxy/
│  ├─ README.md
│  └─ app/
├─ analyzer/
│  ├─ README.md
│  ├─ classifier.md
│  ├─ json_validator.md
│  ├─ orchestrator.md
│  ├─ schemas.md
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
- `http://127.0.0.1:8000/dashboard`

주요 API:
- `POST /internal/v1/validation/jobs`: 가중치 중심 검증
- `POST /internal/v1/validation/full`: 가중치 + 코드 + config + 전처리 메타데이터 + whitelist 통합 검증
- `POST /internal/v1/whitelist/check`: API allow/block/pending 판정
- `GET /internal/v1/pending`, `POST /internal/v1/review`, `GET /internal/v1/audit`: 운영/리뷰 증빙

## 4. 브랜치 규칙
- 기본 브랜치: `main`, `dev`
- 작업 브랜치: `feature/*`
- PR 방향: `feature/*` -> `dev`
- 금지: `main` 직접 수정/직접 push

## 5. 테스트 명령
```bash
python -m pytest -q
```

최소 성공 기준:
- `/health` 응답 코드 `200`
- `python -m pytest -q` 전체 회귀 테스트 통과

2026-06-08 발표 전 점검 기준:
- 로컬 Python: `3.12.10`
- Docker 이미지 빌드 성공
- 컨테이너 헬스체크 성공: `/health` `200`
- 전체 테스트: `700 passed, 1 skipped`

## 6. 현재 역할 분배
- 박용담: 파일분류, `config.json`, `tokenizer_config.json`, 공통 JSON 스키마/계약, 최종 응답 조립 기준
- 정은미: 가중치검증경로, safetensors 검증, pickle Path A/Path B 검증
- 양유상: 코드검증경로, 검증1(`CODE_AST_SCAN`), 검증2(`CODE_RESTRICTED_RUNTIME`), 검증3(`CODE_SANDBOX_RUNTIME`)
- 김민우: 적응형 화이트리스트 엔진, allow/block/unknown/pending 판정, pending API 저장/갱신

## 7. 담당 모듈 설명
- `proxy`: FastAPI 실행 진입점. health, Swagger, dashboard, validation API, whitelist 운영 API를 제공
- `analyzer`: 파일 분류, 공통 schema, 가중치/코드/config/전처리 검증 결과 조립
- `analyzer/validators`: safetensors, pickle, Python, config, preprocessing metadata 검증 경로
- `whitelist`: 적응형 화이트리스트, pending/review/feedback/audit 운영 API 관리
- `sandbox`: B-2 Docker/runsc 제한 실행 증빙 경로. 기본 검증에서는 opt-in으로 사용

## 8. 발표 범위와 한계
- 발표 범위: safetensors fast path, pickle 차단/변환 정책, config trigger 차단, Python AST/semantic 검증, whitelist review 흐름, dashboard
- 보안 원칙: raw pickle은 자동 release하지 않고, malicious opcode/YARA/modelscan 차단은 전체 `DENY`로 전파
- 현재 한계: 실제 Hub 저장소 전체를 production 수준으로 수집/운영하는 단계는 아니며, B-2 runsc 실환경 실행은 opt-in 증빙 경로로 분리
- 포트 주의: `8000`이 다른 프로세스에 점유되어 있으면 해당 프로세스를 종료하거나 compose 포트 매핑을 임시 변경

## 9. 시작 전 읽을 문서
- [CONTRIBUTING.md](./CONTRIBUTING.md): Git/PR/리뷰/커밋 규칙
- [SETUP_GUIDE.md](./SETUP_GUIDE.md): 환경 설치 및 실행 절차
- [TASK_GUIDE.md](./TASK_GUIDE.md): 구현 착수 및 작업 운영 가이드
- [docs/final_demo_script.md](./docs/final_demo_script.md): 최종 발표 데모 흐름
