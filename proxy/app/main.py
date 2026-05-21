"""HuggingMask 프록시 부트스트랩.

현재는 다음만 활성화되어 있다:
  - 헬스 체크 (/, /health)
  - 화이트리스트 엔진 (/internal/v1/whitelist/*, /pending/*, /review, /feedback, /audit/*)
  - 운영 대시보드 (/dashboard) — 보안 담당자용 4탭 UI

analyzer/sandbox 라우터는 각 모듈 구현 완료 후 추가 예정.
"""

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse

from analyzer.schemas import ValidationJobRequest
from analyzer.service import validate_job

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


@app.post("/internal/v1/validation/jobs")
def validation_jobs(payload: ValidationJobRequest):
    return validate_job(payload)


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


app.include_router(whitelist_router)
