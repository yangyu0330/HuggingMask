"""HuggingMask 프록시 부트스트랩.

현재는 다음만 활성화되어 있다:
  - 헬스 체크 (/, /health)
  - 화이트리스트 엔진 (/internal/v1/whitelist/*, /pending/*, /review, /feedback, /audit/*)
  - 운영 대시보드 (/dashboard) — 보안 담당자용 4탭 UI

analyzer/sandbox 라우터는 각 모듈 구현 완료 후 추가 예정.
"""

from contextlib import asynccontextmanager
import json
from pathlib import Path
from typing import Any

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
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_B2_SANDBOX_HTML = _REPO_ROOT / "whitelist" / "static" / "b2_sandbox_demo.html"
_B2_EVIDENCE_ROOT = _REPO_ROOT / "evidence" / "sandbox"


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


@app.get("/sandbox/b2", response_class=HTMLResponse)
def b2_sandbox_demo() -> HTMLResponse:
    """Classroom-friendly B-2 runsc evidence screen."""

    if not _B2_SANDBOX_HTML.exists():
        return HTMLResponse(
            content="<h1>b2_sandbox_demo.html not found</h1>",
            status_code=404,
        )
    return HTMLResponse(content=_B2_SANDBOX_HTML.read_text(encoding="utf-8"))


@app.get("/internal/v1/sandbox/b2/latest")
def latest_b2_sandbox_evidence() -> dict[str, Any]:
    """Return selected fields from the latest local B-2 sandbox evidence."""

    evidence_dir = _latest_b2_evidence_dir(_B2_EVIDENCE_ROOT)
    if evidence_dir is None:
        return {
            "available": False,
            "evidence_dir": None,
            "summary": {},
            "runtime_evidence": {},
            "docker_inspect": {},
            "runner_result": {},
            "files": {},
        }
    return _b2_evidence_payload(evidence_dir)


def _latest_b2_evidence_dir(root: Path) -> Path | None:
    if not root.is_dir():
        return None
    candidates = [
        path
        for path in root.iterdir()
        if path.is_dir() and (path / "summary.json").is_file()
    ]
    if not candidates:
        return None
    return max(candidates, key=lambda path: path.stat().st_mtime)


def _b2_evidence_payload(evidence_dir: Path) -> dict[str, Any]:
    summary = _read_json_object(evidence_dir / "summary.json")
    sandbox_check = _read_json_object(evidence_dir / "sandbox_check.json")
    runner_result = _read_json_object(evidence_dir / "runner_result.json")
    docker_inspect = _read_json_value(evidence_dir / "docker_inspect.json")

    return {
        "available": True,
        "evidence_dir": _display_path(evidence_dir),
        "summary": _select(
            summary,
            "repo_path",
            "grade",
            "route",
            "status",
            "docker_runtime",
            "runtime_verified",
            "runner_diagnostics_status",
            "manifest_verified",
            "import_status",
            "instantiate_status",
            "forward_status",
            "decision",
            "reason_code",
            "deployable",
        ),
        "runtime_evidence": _select(
            _mapping(sandbox_check.get("runtime_evidence")),
            "runtime",
            "network_mode",
            "rootfs_readonly",
            "cap_drop_all",
            "no_new_privileges",
            "mounts_ok",
            "non_root_user",
            "env_allowlist_ok",
            "pids_limit",
            "memory_limit",
            "cpu_limit",
        ),
        "docker_inspect": _docker_inspect_summary(docker_inspect),
        "runner_result": _select(
            runner_result,
            "manifest_verified",
            "import_status",
            "instantiate_status",
            "forward_status",
            "exception_class",
            "exception_message",
        ),
        "files": {
            "summary": _display_path(evidence_dir / "summary.json"),
            "sandbox_check": _display_path(evidence_dir / "sandbox_check.json"),
            "docker_inspect": _display_path(evidence_dir / "docker_inspect.json"),
            "runner_result": _display_path(evidence_dir / "runner_result.json"),
        },
    }


def _docker_inspect_summary(value: Any) -> dict[str, Any]:
    item = value[0] if isinstance(value, list) and value else value
    if not isinstance(item, dict):
        return {}
    host_config = _mapping(item.get("HostConfig"))
    config = _mapping(item.get("Config"))
    mounts = item.get("Mounts")
    return {
        "runtime": host_config.get("Runtime"),
        "network_mode": host_config.get("NetworkMode"),
        "rootfs_readonly": host_config.get("ReadonlyRootfs"),
        "cap_drop": list(host_config.get("CapDrop") or []),
        "security_opt": list(host_config.get("SecurityOpt") or []),
        "user": config.get("User"),
        "mounts": [
            {
                "destination": mount.get("Destination"),
                "mode": mount.get("Mode"),
                "rw": mount.get("RW"),
            }
            for mount in mounts
            if isinstance(mount, dict)
        ]
        if isinstance(mounts, list)
        else [],
    }


def _read_json_object(path: Path) -> dict[str, Any]:
    value = _read_json_value(path)
    return value if isinstance(value, dict) else {}


def _read_json_value(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _select(source: dict[str, Any], *keys: str) -> dict[str, Any]:
    return {key: source.get(key) for key in keys if key in source}


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _display_path(path: Path) -> str:
    try:
        return path.relative_to(_REPO_ROOT).as_posix()
    except ValueError:
        return str(path)


app.include_router(whitelist_router)
