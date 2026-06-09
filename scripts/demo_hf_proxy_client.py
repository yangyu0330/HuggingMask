"""HuggingMask — HF 다운로드 가로채기 데모 (클라이언트, 버전-안전).

서버 기동 후(run_dashboard_wsl2.sh) *다른 셸*에서:

    python scripts/demo_hf_proxy_client.py

HF_ENDPOINT 를 프록시로 지정하고 huggingface_hub.snapshot_download 를 직접 호출한다
(huggingface-cli / hf CLI 버전 차이에 영향받지 않음). 실제 파이프라인이 모델을
받는 방식 그대로다.
"""

from __future__ import annotations

import os

os.environ.setdefault("HF_ENDPOINT", "http://localhost:8000")
os.environ.setdefault("HF_HUB_DISABLE_PROGRESS_BARS", "1")

from huggingface_hub import snapshot_download  # noqa: E402

try:
    from huggingface_hub.utils import HfHubHTTPError  # noqa: E402
except Exception:  # pragma: no cover
    HfHubHTTPError = Exception  # type: ignore

CLEAN = os.getenv("CLEAN_REPO", "hf-internal-testing/tiny-random-bert")
EVIL = os.getenv("EVIL_REPO", "THUDM/chatglm3-6b")

print("HF_ENDPOINT =", os.environ["HF_ENDPOINT"], "(모든 다운로드가 프록시 경유)")


def _attempt(repo: str, **kwargs):
    try:
        return ("OK", snapshot_download(repo, **kwargs))
    except Exception as e:  # noqa: BLE001
        # huggingface_hub 은 게이트 403 을 HfHubHTTPError 또는 그걸 감싼
        # LocalEntryNotFoundError 로 던진다. 둘 다 차단으로 분류한다.
        msg = str(e)
        code = getattr(getattr(e, "response", None), "status_code", None)
        if code == 403 or "403 Forbidden" in msg or "blocked by security gate" in msg:
            return ("BLOCKED", msg)
        return ("ERR", type(e).__name__, msg)


print(f"\n===== ① 악성/위험 모델: {EVIL} (게이트가 받기 전 차단해야 함) =====")
res = _attempt(EVIL, allow_patterns=["*.json", "*.py"])
if res[0] == "BLOCKED":
    print("   ✅ 게이트 차단됨 (403) — 프록시가 받기 전에 격리(QUARANTINED)")
    reason = res[1].split("blocked by security gate", 1)
    if len(reason) > 1:
        print("      사유:", "blocked by security gate" + reason[1].splitlines()[0])
elif res[0] == "OK":
    print("   ⚠ 통과됨(예상과 다름):", res[1])
else:
    print("   ?? 기타 결과:", res)

print(f"\n===== ② 정상 모델: {CLEAN} (게이트 통과 → 실제 다운로드) =====")
res = _attempt(CLEAN)
if res[0] == "OK":
    path = res[1]
    print("   ✅ 다운로드 성공 (게이트 통과 ACQUIRED) →", path)
    for f in sorted(os.listdir(path)):
        print("      -", f)
else:
    print("   ⚠ 실패:", res)

print("\n대시보드 🛡️ 다운로드 게이트 탭: http://localhost:8000/dashboard (Nexus 기록 확인)")
