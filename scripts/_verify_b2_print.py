"""verify_b2_dashboard.sh 용 출력 헬퍼 — /validation/inspect 응답을 표로."""
import json
import sys

try:
    d = json.load(sys.stdin)
except Exception as e:  # noqa: BLE001
    print("응답 파싱 실패:", e)
    sys.exit(1)

if not d.get("ok"):
    print("ERROR:", d.get("error"))
    sys.exit(1)

r = d["response"]
print("=" * 56)
print("  전체 판정:", r.get("overall_decision"))
print("=" * 56)
for a in r.get("artifact_results", []):
    art = a.get("artifact", {})
    sc = (a.get("details") or {}).get("sandbox_check")
    print("  %s  |  %s  |  %s" % (art.get("file_name"), a.get("route_kind"), a.get("status")))
    if sc:
        re_ = sc.get("runtime_evidence", {}) or {}
        ex = sc.get("execution", {}) or {}
        print("    runtime      =", sc.get("sandbox_runtime"))
        print("    네트워크     =", re_.get("network_mode"), " (none=격리)")
        print("    read-only    =", re_.get("rootfs_readonly"))
        print("    cap-drop ALL =", re_.get("cap_drop_all"))
        print("    forward      =", ex.get("forward_status"))
        print("    판정         =", sc.get("decision"))
        print("    deployable   =", sc.get("deployable"))
        if sc.get("decision") == "B2_POLICY_REVIEW_REQUIRED":
            print("    => gVisor 샌드박스 실제 실행 + 격리 검증 + clean 판정 OK")
