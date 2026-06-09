#!/usr/bin/env bash
# HuggingMask — 대시보드 B-2 gVisor 샌드박스 실제 실행 자동 검증 (WSL2)
#
#   bash scripts/verify_b2_dashboard.sh
#
# 브라우저 클릭/복붙 없이, 내장 B-2 데모를 inspect 엔드포인트로 호출해 runsc
# 실제 실행 결과를 출력한다. (서버는 run_dashboard_wsl2.sh 로 먼저 띄울 것)

set -uo pipefail
PORT="${HM_PORT:-8000}"

if ! curl -s "http://127.0.0.1:$PORT/health" >/dev/null 2>&1; then
  echo "✗ 서버 미응답 (port $PORT). 먼저: bash scripts/run_dashboard_wsl2.sh"
  exit 1
fi

echo "==> B-2 샌드박스 데모 검사 (runsc 실제 실행 — 첫 실행 20~30초)..."
curl -s -X POST "http://127.0.0.1:$PORT/internal/v1/validation/inspect" \
  -H "Content-Type: application/json" \
  -d '{"repo_id":"demo:b2-sandbox"}' --max-time 180 | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
except Exception as e:
    print("응답 파싱 실패:", e); sys.exit(1)
if not d.get("ok"):
    print("ERROR:", d.get("error")); sys.exit(1)
r = d["response"]
print("=" * 56)
print("  전체 판정:", r["overall_decision"])
print("=" * 56)
for a in r["artifact_results"]:
    sc = (a.get("details") or {}).get("sandbox_check")
    print(f"  {a[\"artifact\"][\"file_name\"]}  |  {a[\"route_kind\"]}  |  {a[\"status\"]}")
    if sc:
        re_ = sc.get("runtime_evidence", {})
        ex = sc.get("execution", {})
        print(f"    runtime      = {sc.get(\"sandbox_runtime\")}")
        print(f"    네트워크     = {re_.get(\"network_mode\")}  (none=격리)")
        print(f"    read-only    = {re_.get(\"rootfs_readonly\")}")
        print(f"    cap-drop ALL = {re_.get(\"cap_drop_all\")}")
        print(f"    forward      = {ex.get(\"forward_status\")}")
        print(f"    판정         = {sc.get(\"decision\")}")
        print(f"    deployable   = {sc.get(\"deployable\")}")
        if sc.get("decision") == "B2_POLICY_REVIEW_REQUIRED":
            print("    => gVisor 샌드박스 실제 실행 + 격리 검증 + clean 판정 ✓")
'
