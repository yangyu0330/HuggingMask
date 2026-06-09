#!/usr/bin/env bash
# HuggingMask — 대시보드 서버를 '실 sandbox 모드'로 (재)시작 (WSL2 turnkey)
#
#   bash scripts/run_dashboard_wsl2.sh
#
# 기존 서버를 확실히 종료하고, 모든 env 토글을 켜서 새 코드로 백그라운드 기동한다.
# 매번 손으로 export/uvicorn 칠 필요 없음. 멱등(여러 번 실행해도 안전).

set -uo pipefail
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

VENV="${HM_VENV:-$HOME/hm-venv}"
PORT="${HM_PORT:-8000}"
LOG="/tmp/hm-dashboard.log"

echo "==> [1/4] 기존 uvicorn 종료 (stale 서버가 포트를 잡고 있으면 새 코드가 안 뜸)"
pkill -f "uvicorn proxy.app.main" 2>/dev/null && echo "    기존 프로세스 종료" || echo "    기존 프로세스 없음"
fuser -k "${PORT}/tcp" 2>/dev/null || true
sleep 1

echo "==> [2/4] venv 활성화: $VENV"
if [ ! -f "$VENV/bin/activate" ]; then
  echo "    ✗ venv 없음 ($VENV). 먼저 만드세요:"
  echo "      python3 -m venv $VENV && source $VENV/bin/activate && pip install -r requirements.txt"
  exit 1
fi
# shellcheck disable=SC1091
source "$VENV/bin/activate"

echo "==> [3/4] 실 sandbox 토글 설정 (runsc-strace + Linux evidence)"
# 루프 방지: 서버 프로세스는 항상 실제 huggingface.co 로 직접 나가야 한다.
# (이 셸에서 export HF_ENDPOINT/HTTP(S)_PROXY 했다면 게이트의 검사 다운로드가
#  자기 자신(프록시)을 거쳐 깨진 내용을 받아 config.json 이 'JSON 아님'으로 BLOCK 됨.)
unset HF_ENDPOINT HTTP_PROXY HTTPS_PROXY http_proxy https_proxy 2>/dev/null || true
export HUGGINGMASK_ENABLE_REAL_SANDBOX=1
export HUGGINGMASK_ENABLE_PATH_B=1
export HUGGINGMASK_B2_IMAGE="${HUGGINGMASK_B2_IMAGE:-huggingmask-b2-sandbox:local}"
export HUGGINGMASK_B2_RUNTIME="${HUGGINGMASK_B2_RUNTIME:-runsc-strace}"
export HUGGINGMASK_B2_STRACE_LOG_DIR="${HUGGINGMASK_B2_STRACE_LOG_DIR:-/tmp/runsc-strace}"
export HUGGINGMASK_SANDBOX_EVIDENCE_DIR="${HUGGINGMASK_SANDBOX_EVIDENCE_DIR:-$HOME/hm-evidence}"
export HUGGINGMASK_PATH_B_TIMEOUT="${HUGGINGMASK_PATH_B_TIMEOUT:-120}"  # runsc+torch cold start 여유
# 전처리 자동화 B: baseline 없어도 구조적으로 안전(커스텀코드/인젝션/네트워크경로 0)하면
# 자동 통과 — 검토대기 부담 감소. (A=레지스트리 해시 매칭은 항상 동작, 악성은 항상 차단)
export HUGGINGMASK_PREPROCESSING_INVARIANTS="${HUGGINGMASK_PREPROCESSING_INVARIANTS:-1}"

echo "==> [4/4] uvicorn 백그라운드 기동 (port $PORT, 로그=$LOG)"
nohup uvicorn proxy.app.main:app --port "$PORT" > "$LOG" 2>&1 &
PID=$!
echo "    PID=$PID"

for i in $(seq 1 25); do
  if curl -s "http://127.0.0.1:$PORT/health" >/dev/null 2>&1; then
    echo "    ✓ 서버 준비됨"
    break
  fi
  if ! kill -0 "$PID" 2>/dev/null; then
    echo "    ✗ 서버가 죽음 — 로그:"; tail -20 "$LOG"; exit 1
  fi
  sleep 1
done

echo "────────────────────────────────────────────"
echo "대시보드:  http://localhost:$PORT/dashboard"
echo "검증:      bash scripts/verify_b2_dashboard.sh"
echo "서버 로그: tail -f $LOG"
echo "서버 종료: pkill -f 'uvicorn proxy.app.main'"
