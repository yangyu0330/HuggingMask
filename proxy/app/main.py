"""HuggingMask 프록시 부트스트랩.

현재는 다음만 활성화되어 있다:
  - 헬스 체크 (/, /health)
  - 화이트리스트 엔진 (/internal/v1/whitelist/*, /pending/*, /review, /feedback, /audit/*)
  - 운영 대시보드 (/dashboard) — 보안 담당자용 4탭 UI

analyzer/sandbox 라우터는 각 모듈 구현 완료 후 추가 예정.
"""

import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from analyzer.schemas import ValidationJobRequest
from analyzer.service import validate_job
from proxy.auth import require_internal_token
from whitelist.database import get_db
from whitelist.full_pipeline import run_full_validation
from whitelist.model_inspector import inspect_model_repo

app = FastAPI(title="HuggingMask Proxy Bootstrap")
from whitelist.bootstrap import init_whitelist
from whitelist.router import router as whitelist_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_whitelist()
    yield


app = FastAPI(title="HuggingMask Proxy Bootstrap", lifespan=lifespan)


@app.get("/")
def root() -> dict[str, str]:
    return {"message": "HuggingMask bootstrap running"}


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


def _path_b_enabled_by_operator() -> bool:
    """배포 단위 Path B(gVisor) 활성 토글.

    스키마 기본값(enable_path_b=False)은 그대로 두되, b2 샌드박스가 실제로
    프로비저닝된 프로덕션에서는 env ``HUGGINGMASK_ENABLE_PATH_B=1``로 코드 변경
    없이 켤 수 있다. 미프로비저닝 환경(dev/CI/데모)에서는 설정하지 않으므로
    pickle이 정적 opcode 게이트(Path A)만 거쳐 기존 동작을 보존한다.
    """
    return os.getenv("HUGGINGMASK_ENABLE_PATH_B", "").strip().lower() in {"1", "true", "yes", "on"}


def _apply_operator_path_b(payload: ValidationJobRequest) -> ValidationJobRequest:
    if not payload.enable_path_b and _path_b_enabled_by_operator():
        payload.enable_path_b = True
    return payload


@app.post(
    "/internal/v1/validation/jobs",
    dependencies=[Depends(require_internal_token)],
)
def validation_jobs(payload: ValidationJobRequest):
    return validate_job(_apply_operator_path_b(payload))


@app.post(
    "/internal/v1/validation/full",
    dependencies=[Depends(require_internal_token)],
)
def validation_full(payload: ValidationJobRequest, db: Session = Depends(get_db)):
    """통합 검증 — 가중치 + 코드 + config + 화이트리스트 + 제한 런타임을
    한 요청에서 모두 거쳐 단일 판정으로 응답.

    ``/jobs``(가중치 전용)와 달리 PYTHON/CONFIG_JSON/TOKENIZER_CONFIG_JSON도
    실제 검증 경로(양유상 orchestrator + 본인 화이트리스트/제한 런타임)로 보낸다.
    """
    return run_full_validation(_apply_operator_path_b(payload), db=db)


class InspectModelRequest(BaseModel):
    """대시보드 '모델 검사' 입력 — repo_id만 받아 서버측에서 다운로드/검증."""

    repo_id: str
    revision: str = "main"
    skip_weights: bool = True
    enable_path_b: bool = False


@app.post(
    "/internal/v1/validation/inspect",
    dependencies=[Depends(require_internal_token)],
)
def validation_inspect(payload: InspectModelRequest, db: Session = Depends(get_db)):
    """repo_id를 받아 서버에서 텍스트 아티팩트를 내려받아 통합 검증 실행.

    대시보드 '모델 검사' 탭의 가시화용. 브라우저가 HF 모델을 직접 받을 수
    없으므로 서버가 다운로드까지 대행한다. ``/validation/full``과 동일한
    응답 + 다운로드/분류 메타를 묶어 반환(실패도 200 + ``ok:false``).

    실 검증 파이프라인을 돌리므로 ``/full``과 동일하게 내부 토큰 인증
    적용(미설정 시 no-op — 데모/dev 경로 보존).
    """
    return inspect_model_repo(
        payload.repo_id,
        db=db,
        revision=payload.revision,
        skip_weights=payload.skip_weights,
        enable_path_b=payload.enable_path_b,
    )


class ProxyGateRequest(BaseModel):
    """프록시 다운로드 게이트 입력."""

    repo_id: str
    revision: str = "main"


@app.post(
    "/internal/v1/proxy/acquire",
    dependencies=[Depends(require_internal_token)],
)
def proxy_acquire(payload: ProxyGateRequest, db: Session = Depends(get_db)):
    """다운로드 게이트 — 받기 전에 검사하고 안전하면 통과·저장, 아니면 차단.

    HuggingMask 제품 thesis 를 다운로드 경로에 적용: 코드/config 를 먼저 검사
    (가중치 제외)해 DENY 면 격리(다운로드 차단), 안전하면 acquire + 저장소 기록.
    """
    from whitelist.acquisition import gate_model

    return gate_model(payload.repo_id, db=db, revision=payload.revision)


@app.get(
    "/internal/v1/proxy/acquired",
    dependencies=[Depends(require_internal_token)],
)
def proxy_acquired(db: Session = Depends(get_db)):
    """게이트 저장소(Nexus 역할) 목록 — ACQUIRED/QUARANTINED/PENDING."""
    from whitelist.acquisition import list_acquired

    return {"items": list_acquired(db)}


@app.get(
    "/internal/v1/proxy/nexus",
    dependencies=[Depends(require_internal_token)],
)
def proxy_nexus():
    """Nexus 사내 저장소에 실제 보관된 모델 파일 목록(매니페스트 기반)."""
    from whitelist.acquisition import list_nexus

    return {"items": list_nexus()}


@app.get(
    "/internal/v1/proxy/nexus/file",
    dependencies=[Depends(require_internal_token)],
)
def proxy_nexus_file(repo: str, path: str, revision: str = "main"):
    """Nexus 에 보관된 개별 파일 다운로드(저장 디렉터리 밖 접근 차단)."""
    from fastapi.responses import FileResponse, JSONResponse

    from whitelist.acquisition import nexus_file_path

    target = nexus_file_path(repo, revision, path)
    if target is None:
        return JSONResponse(
            {"error": "file not found in nexus store", "repo": repo, "path": path},
            status_code=404,
        )
    return FileResponse(str(target), filename=path.split("/")[-1])


@app.get(
    "/internal/v1/proxy/nexus/zip",
    dependencies=[Depends(require_internal_token)],
)
def proxy_nexus_zip(repo: str, revision: str = "main"):
    """Nexus 에 보관된 모델 '전체'를 ZIP 1개로 다운로드(브라우저 일괄 받기)."""
    from fastapi.responses import JSONResponse, Response

    from whitelist.acquisition import build_nexus_zip

    data = build_nexus_zip(repo, revision)
    if data is None:
        return JSONResponse(
            {"error": "model not stored in nexus", "repo": repo}, status_code=404
        )
    fname = repo.replace("/", "__") + ".zip"
    return Response(
        content=data,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


# ─────────────────────────────────────────────
# 운영 대시보드 (보안 담당자 UI)
# ─────────────────────────────────────────────

_DASHBOARD_HTML = (
    Path(__file__).resolve().parent.parent.parent
    / "whitelist" / "static" / "dashboard.html"
)


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard() -> HTMLResponse:
    """승인된 API / Pending / Audit / Feedback 4탭 운영 UI.

    백엔드는 ``/internal/v1/*``에 그대로 살아있고, 이 엔드포인트는 정적
    HTML을 서빙. JS 안에서 ``window.location.origin + '/internal/v1'``을
    호출.
    """
    if not _DASHBOARD_HTML.exists():
        return HTMLResponse(
            content="<h1>dashboard.html not found</h1>",
            status_code=404,
        )
    return HTMLResponse(content=_DASHBOARD_HTML.read_text(encoding="utf-8"))


app.include_router(
    whitelist_router,
    dependencies=[Depends(require_internal_token)],
)

# HuggingFace 다운로드 transparent 가로채기(HF_ENDPOINT 리버스 프록시).
# catch-all 라우트('/{full_path:path}')를 포함하므로 반드시 맨 마지막에 등록해
# /dashboard·/health·/internal/v1/* 등 명시 라우트를 가리지 않게 한다.
from proxy.app.hf_proxy import router as hf_proxy_router

app.include_router(hf_proxy_router)
