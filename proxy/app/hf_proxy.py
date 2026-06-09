"""HuggingFace 다운로드 transparent 가로채기 (HF_ENDPOINT 리버스 프록시).

클라이언트가 ``export HF_ENDPOINT=http://localhost:8000`` 후
``huggingface-cli download`` / ``AutoModel.from_pretrained`` 를 실행하면
huggingface_hub 의 모든 API/파일 요청이 이 프록시로 들어온다. 프록시는:

  * ``/api/models/{repo}`` (모델 메타) 요청에서 **다운로드 게이트를 먼저 실행**한다.
      - QUARANTINED(DENY) → 403 으로 막아 다운로드를 **받기 전에 차단**한다.
      - 그 외(ACQUIRED/PENDING/검사불가) → 실제 huggingface.co 로 포워딩.
  * ``/{repo}/resolve/{rev}/{file}`` (파일) 요청도 같은 게이트 결정으로 막거나 포워딩.

설계 원칙
  * 업스트림은 항상 실제 huggingface.co (env 로 덮어쓰기 가능). 프록시 서버 프로세스에는
    HF_ENDPOINT 를 설정하지 않아야 게이트의 내부 snapshot_download 가 실 HF 로 나간다(루프 방지).
  * 가중치 바이트는 HF 가 CDN 302 redirect 로 돌려주므로 프록시를 거치지 않는다(효율).
    게이트는 redirect 전에 이미 허용/차단을 결정한다.
  * 게이트 결정은 repo 단위로 in-process 캐시 — 파일마다 재검사하지 않는다.
  * 라우트는 async + threadpool(게이트는 동기 IO) — 최신 huggingface_hub 의 POST
    (paths-info 등)·body 요청까지 그대로 포워딩한다.
"""

from __future__ import annotations

import json
import os

import httpx
from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from whitelist.acquisition import gate_model
from whitelist.database import get_db

router = APIRouter()

# 업스트림은 항상 실제 HF (env 로만 덮어쓰기 — 테스트용). 절대 프록시 자신을 가리키면 안 됨.
HF_UPSTREAM = os.getenv("HUGGINGMASK_HF_UPSTREAM", "https://huggingface.co").rstrip("/")

# 포워딩 시 그대로 넘기면 안 되는 hop-by-hop / 재계산 대상 헤더.
_DROP_HEADERS = {
    "host",
    "content-length",
    "content-encoding",
    "transfer-encoding",
    "connection",
    "accept-encoding",
    "keep-alive",
}

_FORWARD_METHODS = ["GET", "HEAD", "POST"]

# (repo) -> gate_model 결과. 같은 repo 는 파일마다 재검사하지 않는다.
_gate_cache: dict[str, dict] = {}


async def _decide(repo: str, revision: str, db: Session) -> dict:
    """repo 단위 게이트 결정(캐시). 최초 1회만 실검사(동기 IO→threadpool) 후 재사용."""
    cached = _gate_cache.get(repo)
    if cached is None:
        cached = await run_in_threadpool(gate_model, repo, db=db, revision=revision)
        _gate_cache[repo] = cached
    return cached


def _blocked_response(repo: str, decision: dict) -> Response:
    """다운로드 차단 응답 — 클라이언트(huggingface_hub)는 이 4xx 로 다운로드 실패 처리."""
    body = json.dumps(
        {
            "error": "HuggingMask proxy: download blocked by security gate",
            "repo_id": repo,
            "status": decision.get("status"),
            "decision": decision.get("decision"),
            "reason": decision.get("reason"),
        },
        ensure_ascii=False,
    ).encode("utf-8")
    return Response(content=body, status_code=403, media_type="application/json")


async def _forward(request: Request, url: str) -> Response:
    """요청을 실제 HF 로 그대로 포워딩하고 응답을 반환(redirect 따라가지 않음)."""
    fwd_headers = {
        k: v for k, v in request.headers.items() if k.lower() not in _DROP_HEADERS
    }
    body = await request.body()
    async with httpx.AsyncClient(follow_redirects=False, timeout=60.0) as client:
        upstream = await client.request(
            request.method,
            url,
            headers=fwd_headers,
            params=dict(request.query_params),
            content=body or None,
        )
    resp_headers = {
        k: v for k, v in upstream.headers.items() if k.lower() not in _DROP_HEADERS
    }
    return Response(
        content=upstream.content,
        status_code=upstream.status_code,
        headers=resp_headers,
    )


def _split_repo_revision(repo_path: str) -> tuple[str, str]:
    """``org/name`` 또는 ``org/name/revision/{rev}`` → (repo, revision)."""
    if "/revision/" in repo_path:
        repo, rev = repo_path.split("/revision/", 1)
        return repo, (rev.split("/", 1)[0] or "main")
    return repo_path, "main"


@router.api_route("/api/models/{repo_path:path}", methods=_FORWARD_METHODS)
async def hf_api_models(repo_path: str, request: Request, db: Session = Depends(get_db)):
    """모델 메타 요청 — 다운로드 게이트를 먼저 돌리고, 통과 시 실 HF 메타 포워딩."""
    repo, revision = _split_repo_revision(repo_path)
    decision = await _decide(repo, revision, db)
    if decision.get("status") == "QUARANTINED":
        return _blocked_response(repo, decision)
    return await _forward(request, f"{HF_UPSTREAM}/api/models/{repo_path}")


@router.api_route("/{full_path:path}", methods=_FORWARD_METHODS)
async def hf_passthrough(full_path: str, request: Request, db: Session = Depends(get_db)):
    """파일(resolve) 및 기타 HF API 포워딩. resolve 는 게이트 결정으로 차단/허용."""
    if "/resolve/" in full_path:
        repo, rest = full_path.split("/resolve/", 1)
        revision = rest.split("/", 1)[0] or "main"
        decision = await _decide(repo, revision, db)
        if decision.get("status") == "QUARANTINED":
            return _blocked_response(repo, decision)
        return await _forward(request, f"{HF_UPSTREAM}/{full_path}")

    # 그 외 HF API(whoami, tree, paths-info 등)는 게이트 없이 포워딩. HF 리소스가 아니면 404.
    if full_path.startswith("api/"):
        return await _forward(request, f"{HF_UPSTREAM}/{full_path}")

    return Response(
        content=json.dumps({"error": "not a proxied HuggingFace resource", "path": full_path}),
        status_code=404,
        media_type="application/json",
    )
