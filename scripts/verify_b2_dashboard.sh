#!/usr/bin/env bash
# HuggingMask — 대시보드 B-2 gVisor 샌드박스 실제 실행 자동 검증 (WSL2)
#
#   bash scripts/verify_b2_dashboard.sh
#
# 브라우저 클릭/복붙 없이, 내장 B-2 데모를 inspect 엔드포인트로 호출해 runsc
# 실제 실행 결과를 출력한다. (서버는 run_dashboard_wsl2.sh 로 먼저 띄울 것)

set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORT="${HM_PORT:-8000}"

if ! curl -s "http://127.0.0.1:$PORT/health" >/dev/null 2>&1; then
  echo "✗ 서버 미응답 (port $PORT). 먼저: bash scripts/run_dashboard_wsl2.sh"
  exit 1
fi

echo "==> B-2 샌드박스 데모 검사 (runsc 실제 실행 — 첫 실행 20~30초)..."
curl -s -X POST "http://127.0.0.1:$PORT/internal/v1/validation/inspect" \
  -H "Content-Type: application/json" \
  -d '{"repo_id":"demo:b2-sandbox"}' --max-time 180 | python3 "$HERE/_verify_b2_print.py"
