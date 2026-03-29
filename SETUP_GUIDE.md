# SETUP GUIDE

HuggingMask 프로젝트를 처음 실행하는 팀원을 위한 한글 설치/실행 가이드입니다.

## 1. 사전 설치 항목
- Git
- Python 3.13
- Docker Desktop (Compose 포함)

## 2. 설치 확인 명령
아래 4개 명령 결과를 팀 채널(디스코드/노션)에 캡처로 공유합니다.

```bash
git --version
python --version
docker --version
docker compose version
```

## 3. 가상환경 생성/활성화
생성:
```bash
python -m venv .venv
```

활성화(Windows PowerShell):
```powershell
.venv\Scripts\activate
```

활성화(macOS/Linux):
```bash
source .venv/bin/activate
```

pip 업그레이드:
```bash
python -m pip install --upgrade pip
```

## 4. 패키지 설치
```bash
pip install -r requirements.txt
```

## 5. Docker 실행
```bash
docker compose up --build
```

## 6. /health 확인
브라우저로 아래 경로를 확인합니다.
- `http://127.0.0.1:8000/health`
- `http://127.0.0.1:8000/docs`

정상 기준:
- `/health` 응답: `200`, 본문 `{"status":"ok"}`
- `/docs` 페이지 로드 성공

## 7. 테스트 실행
```bash
pytest -q
```

최소 기준:
- 테스트 최소 1건 이상 통과

## 8. 흔한 에러 3개와 해결법
1. Docker 엔진 연결 오류
   - 증상: `open //./pipe/dockerDesktopLinuxEngine ...`
   - 원인: Docker Desktop 미실행 또는 엔진 초기화 전
   - 해결: Docker Desktop 실행 후 엔진 상태가 Running인지 확인하고 재시도

2. 모듈 import 오류
   - 증상: `ModuleNotFoundError`
   - 원인: 가상환경 미활성화 또는 패키지 미설치
   - 해결: `.venv` 활성화 후 `pip install -r requirements.txt` 재실행

3. 포트 충돌 오류
   - 증상: `port 8000 is already allocated`
   - 원인: 기존 프로세스/컨테이너가 8000 사용 중
   - 해결: 기존 프로세스 종료 후 재실행 또는 `compose.yaml` 포트 변경

## 9. 팀 표준 요약
- Python: `3.13`
- 포트: `8000`
- 실행: `docker compose up --build`
- 브랜치: `feature/*` -> `dev` -> `main`
