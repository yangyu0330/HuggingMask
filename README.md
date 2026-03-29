# HuggingMask

AI 모델 공급망 보안을 위한 프록시 기반 검증 프로젝트입니다.

## 1. 프로젝트 개요
- 목표: 안전하지 않은 모델/코드를 사전에 탐지하고 차단할 수 있는 검증 파이프라인 구축
- 팀 표준: Python `3.13`, 공통 포트 `8000`, 실행 기준 `docker compose up --build`
- 작업 흐름: `feature/*`에서 개발 후 `dev`로 PR, 안정화 후 `main` 반영

## 2. 폴더 구조
```text
HuggingMask/
├─ .github/
│  ├─ PULL_REQUEST_TEMPLATE.md
│  └─ CODEOWNERS
├─ proxy/
│  └─ app/
├─ analyzer/
├─ whitelist/
├─ sandbox/
├─ tests/
├─ docs/
├─ evidence/
│  ├─ week01/ ~ week10/
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
pytest -q
```

최소 성공 기준:
- `/health` 응답 코드 `200`
- `pytest` 최소 1건 통과

## 6. 담당 모듈 설명
- `proxy`: FastAPI 프록시 엔트리포인트, 요청 라우팅, 인증/로깅, 외부 모델 요청 중계
- `analyzer`: pickle/코드/설정 파일 분석, 위험 패턴 탐지, 등급 분류 로직
- `whitelist`: 허용 API/정책 관리, Pending 목록 처리, 정책 데이터 관리
- `sandbox`: 격리 실행 환경, 실행 로그 수집, 고위험 코드 실행 제어

## 7. 시작 전 읽을 문서
- [CONTRIBUTING.md](./CONTRIBUTING.md): Git/PR/리뷰/커밋 규칙
- [SETUP_GUIDE.md](./SETUP_GUIDE.md): 환경 설치 및 실행 절차
- [TASK_GUIDE.md](./TASK_GUIDE.md): 주차별/일일 작업 운영 가이드
