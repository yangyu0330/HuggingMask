#!/usr/bin/env bash
# HuggingMask — HF 다운로드 transparent 가로채기 데모 (클라이언트 측)
#
#   1) 먼저 서버 기동:   bash scripts/run_dashboard_wsl2.sh
#   2) *다른 셸*에서:    bash scripts/demo_hf_proxy_intercept.sh
#
# HF_ENDPOINT 를 프록시로 지정하면 huggingface_hub 의 모든 다운로드가 프록시로
# 들어온다. 프록시가 게이트 검사 후 허용/차단한다. 실제 다운로드 호출은 CLI 버전
# 차이를 피하려고 python snapshot_download 를 직접 쓰는 클라이언트로 위임한다.
# (서버 셸에는 HF_ENDPOINT 를 설정하지 말 것 — 게이트 내부 다운로드가 실 HF 로 나가야 함.)

set -uo pipefail
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

export HF_ENDPOINT="${HF_ENDPOINT:-http://localhost:8000}"

echo "==> 프록시 라이브/판정 sanity (curl):"
curl -s -o /dev/null -w "    정상 tiny-bert api/models -> %{http_code} (기대 200)\n" \
  "$HF_ENDPOINT/api/models/hf-internal-testing/tiny-random-bert/revision/main"
curl -s -o /dev/null -w "    악성 chatglm3  api/models -> %{http_code} (기대 403)\n" \
  "$HF_ENDPOINT/api/models/THUDM/chatglm3-6b/revision/main"

echo
echo "==> 실 다운로드 데모 (python snapshot_download — 가로채기 실증):"
python scripts/demo_hf_proxy_client.py
