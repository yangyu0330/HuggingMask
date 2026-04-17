# HuggingMask

AI 모델 공급망 보안을 위한 프록시 기반 검증 프로젝트입니다.

## 1. 프로젝트 개요
- 목표: 안전하지 않은 모델/코드를 사전에 탐지하고 차단할 수 있는 검증 파이프라인 구축
- 팀 표준: Python `3.13`, 공통 포트 `8000`, 실행 기준 `docker compose up --build`
- 작업 흐름: `feature/*`에서 개발 후 `dev`로 PR, 안정화 후 `main` 반영
- 현재 기준: 프록시는 후순위로 두고, `analyzer`와 `whitelist` 중심으로 검증 엔진 구현에 착수

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
- `python -m pytest` 최소 1건 통과

## 6. 현재 역할 분배
- 박용담: 파일분류, `config.json`, `tokenizer_config.json`, 공통 JSON 스키마/계약, 최종 응답 조립 기준
- 정은미: 가중치검증경로, safetensors 검증, pickle Path A/Path B 검증
- 양유상: 코드검증경로, 검증1(`CODE_AST_SCAN`), 검증2(`CODE_RESTRICTED_RUNTIME`), 검증3(`CODE_SANDBOX_RUNTIME`)
- 김민우: 적응형 화이트리스트 엔진, allow/block/unknown/pending 판정, pending API 저장/갱신

## 7. 담당 모듈 설명
- `proxy`: 현재는 FastAPI health 서버와 향후 `analyzer` orchestrator 호출 진입점
- `analyzer`: 박용담/정은미/양유상 담당 검증 흐름의 중심 모듈
- `analyzer/validators`: 정은미/양유상 담당 파일 유형별 검증 경로
- `whitelist`: 김민우 담당 적응형 화이트리스트와 pending API 관리
- `sandbox`: 정은미/양유상 검증에서 제한 실행이 필요할 때 연결할 후순위 모듈

## 8. 시작 전 읽을 문서
- [CONTRIBUTING.md](./CONTRIBUTING.md): Git/PR/리뷰/커밋 규칙
- [SETUP_GUIDE.md](./SETUP_GUIDE.md): 환경 설치 및 실행 절차
- [TASK_GUIDE.md](./TASK_GUIDE.md): 구현 착수 및 작업 운영 가이드
