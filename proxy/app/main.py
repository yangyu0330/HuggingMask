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
from sqlalchemy.orm import Session

from analyzer.schemas import ValidationJobRequest
from analyzer.service import validate_job
from proxy.auth import require_internal_token
from whitelist.database import get_db
from whitelist.full_pipeline import run_full_validation

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
