"""mitmproxy 애드온 — 브라우저 등 임의 클라이언트의 huggingface.co HTTPS 다운로드를
MITM(TLS 복호화)으로 가로채 다운로드 게이트를 적용한다.

이 경로는 huggingface_hub(HF_ENDPOINT)로는 못 잡는 **브라우저 다운로드 버튼**까지
가로챈다. 클라이언트가 huggingface.co/{repo}/resolve/... 로 파일을 받으려 하면:

  * 게이트 판정 QUARANTINED(DENY) → 403 으로 응답을 가로채 다운로드를 막는다.
  * 그 외(ACQUIRED/PENDING/검사불가/게이트오류) → 그대로 통과시켜 실제 파일이 내려간다.

게이트 판정은 whitelist 스택을 직접 import 하지 않고 **이미 떠 있는 게이트 API**
(``HM_GATE_URL``, 기본 http://localhost:8000/internal/v1/proxy/acquire)를 HTTP 로
호출해 받는다 — 그래야 mitmproxy 를 별도 venv 에 깔아도 의존성 충돌이 없다.

실행:
    1) 게이트 제공 서버 기동:  bash scripts/run_dashboard_wsl2.sh
    2) MITM 프록시 기동:        bash scripts/run_hf_mitm.sh
       (또는 직접: mitmdump -s proxy/mitm/hf_gate_addon.py --listen-port 8080)

클라이언트(브라우저/OS): 프록시 = <host>:8080 + mitmproxy CA 인증서 신뢰 설치(http://mitm.it).

주의: 게이트 서버(:8000) 프로세스 환경에는 HTTPS_PROXY 를 설정하지 말 것 —
게이트 내부 검사 다운로드가 실제 huggingface.co 로 직접 나가야 한다(자기 자신 경유 루프 방지).
"""

from __future__ import annotations

import json
import os
import urllib.request

from mitmproxy import http

_HF_HOSTS = {"huggingface.co", "www.huggingface.co"}
_GATE_URL = os.getenv("HM_GATE_URL", "http://localhost:8000/internal/v1/proxy/acquire")

# (repo) -> 게이트 판정 결과. 같은 repo 는 파일마다 재검사하지 않는다.
_gate_cache: dict[str, dict] = {}


def _repo_from_path(path: str) -> str | None:
    """huggingface.co 경로에서 검사 대상 repo_id 추출. 다운로드/메타 경로만 대상."""
    p = path.split("?", 1)[0].lstrip("/")
    if p.startswith("api/models/"):
        return p[len("api/models/"):].split("/revision/", 1)[0].rstrip("/") or None
    if "/resolve/" in p:
        return p.split("/resolve/", 1)[0] or None
    return None


def _decide(repo: str) -> dict:
    """게이트 API 를 HTTP 로 호출해 판정(캐시). 오류 시 fail-open(통과)."""
    cached = _gate_cache.get(repo)
    if cached is None:
        payload = json.dumps({"repo_id": repo}).encode("utf-8")
        req = urllib.request.Request(
            _GATE_URL,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=180) as resp:
                cached = json.loads(resp.read().decode("utf-8"))
        except Exception as e:  # noqa: BLE001 — 게이트 불가 시 fail-open
            cached = {"status": "GATE_UNAVAILABLE", "reason": str(e)}
        _gate_cache[repo] = cached
    return cached


def request(flow: http.HTTPFlow) -> None:
    """huggingface.co 다운로드/메타 요청을 게이트 판정으로 가로채 차단 또는 통과."""
    if flow.request.pretty_host not in _HF_HOSTS:
        return  # HF 외 트래픽은 그대로 통과

    repo = _repo_from_path(flow.request.path)
    if not repo:
        return  # 모델 페이지 브라우징 등 — 다운로드 아님, 통과

    decision = _decide(repo)
    if decision.get("status") != "QUARANTINED":
        return  # ACQUIRED/PENDING/검사불가/게이트오류 → 실제 huggingface.co 로 통과

    body = json.dumps(
        {
            "error": "HuggingMask proxy: download blocked by security gate",
            "repo_id": repo,
            "status": decision.get("status"),
            "decision": decision.get("decision"),
            "reason": decision.get("reason"),
        },
        ensure_ascii=False,
    )
    flow.response = http.Response.make(
        403,
        body.encode("utf-8"),
        {"Content-Type": "application/json; charset=utf-8"},
    )
