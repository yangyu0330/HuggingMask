#!/usr/bin/env bash
# HuggingMask — 브라우저/OS HTTPS 다운로드 가로채기 (mitmproxy + 게이트 애드온)
#
#   1) 게이트 제공 서버 먼저:  bash scripts/run_dashboard_wsl2.sh   (다른 셸, :8000)
#   2) 이 MITM 프록시 기동:     bash scripts/run_hf_mitm.sh          (:8080)
#
# 브라우저의 huggingface.co '다운로드' 버튼까지 가로채려면 TLS MITM 이 필요하다.
# mitmproxy 는 의존성이 빡빡하므로 **전용 venv**($HOME/hm-mitm-venv)에 격리 설치한다
# (프로젝트 venv 와 충돌 0 — 애드온은 stdlib 만 쓰고 게이트는 HTTP 로 호출).
#
# ── 클라이언트(브라우저/OS) 설정 ──────────────────────────────
#  1) HTTP(S) 프록시 = 127.0.0.1:8080
#       (WSL2 면 Windows 프록시 설정에 127.0.0.1:8080 — localhost 포워딩됨.
#        안 되면 `hostname -I` 의 WSL2 IP 사용)
#  2) mitmproxy CA 인증서를 '신뢰된 루트 인증 기관'에 설치:
#       프록시 켠 채 브라우저로  http://mitm.it  접속 → OS용 인증서 받아 설치
#       (또는 ~/.mitmproxy/mitmproxy-ca-cert.cer 를 Windows 신뢰 저장소로 import)
#  ※ 데모엔 Firefox 권장 — 자체 프록시/인증서 저장소라 시스템 전체를 안 건드림.
# ──────────────────────────────────────────────────────────────
#
# 주의: 게이트 서버(:8000) 셸에는 HTTPS_PROXY 를 설정하지 말 것 — 게이트 내부
# 검사 다운로드가 실제 huggingface.co 로 직접 나가야 한다(자기 자신 경유 루프 방지).

set -uo pipefail
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

PORT="${MITM_PORT:-8080}"
MITM_VENV="${MITM_VENV:-$HOME/hm-mitm-venv}"
GATE_URL="${HM_GATE_URL:-http://localhost:8000/internal/v1/proxy/acquire}"

# 루프 방지: 이 셸의 프록시 env 제거
unset HTTP_PROXY HTTPS_PROXY http_proxy https_proxy HF_ENDPOINT 2>/dev/null || true

# 게이트 서버 살아있는지 확인(애드온이 HTTP 로 호출함)
if ! curl -s -o /dev/null "http://localhost:8000/health"; then
  echo "✗ 게이트 서버(:8000)가 안 떠 있습니다. 먼저: bash scripts/run_dashboard_wsl2.sh"
  exit 1
fi

# mitmproxy 전용 venv (격리 설치)
if [ ! -x "$MITM_VENV/bin/mitmdump" ]; then
  echo "==> mitmproxy 전용 venv 생성·설치: $MITM_VENV (최초 1회, 수십 초)"
  python3 -m venv "$MITM_VENV" || { echo "✗ venv 생성 실패"; exit 1; }
  "$MITM_VENV/bin/pip" install -q --upgrade pip
  "$MITM_VENV/bin/pip" install -q mitmproxy || { echo "✗ mitmproxy 설치 실패"; exit 1; }
fi

export HM_GATE_URL="$GATE_URL"

echo "════════════════════════════════════════════════════════════"
echo " HF 다운로드 MITM 가로채기  (listen :$PORT, gate=$GATE_URL)"
echo "────────────────────────────────────────────────────────────"
echo " 클라이언트 프록시 = 127.0.0.1:$PORT  /  CA 설치: http://mitm.it"
echo " 테스트(브라우저): huggingface.co/THUDM/chatglm3-6b 파일 다운로드 → 차단"
echo "                   huggingface.co/hf-internal-testing/tiny-random-bert → 통과"
echo "════════════════════════════════════════════════════════════"

exec "$MITM_VENV/bin/mitmdump" -s proxy/mitm/hf_gate_addon.py --listen-port "$PORT"
