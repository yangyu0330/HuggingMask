"""Static serving helpers for the built React frontend."""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles


REPO_ROOT = Path(__file__).resolve().parents[2]
FRONTEND_DIST = REPO_ROOT / "frontend" / "dist"
LEGACY_DASHBOARD_HTML = REPO_ROOT / "whitelist" / "static" / "dashboard.html"


def mount_frontend(app: FastAPI) -> None:
    assets_dir = FRONTEND_DIST / "assets"
    app.mount(
        "/assets",
        StaticFiles(directory=str(assets_dir), check_dir=False),
        name="frontend-assets",
    )


def frontend_dashboard() -> HTMLResponse:
    index = FRONTEND_DIST / "index.html"
    if not index.exists():
        return HTMLResponse(
            content=(
                "<!doctype html><title>HuggingMask</title>"
                "<div id=\"root\">Frontend build not found. Run "
                "<code>npm --prefix frontend run build</code>.</div>"
            ),
            status_code=503,
        )
    return HTMLResponse(content=index.read_text(encoding="utf-8"))


def legacy_dashboard() -> HTMLResponse:
    if not LEGACY_DASHBOARD_HTML.exists():
        return HTMLResponse(content="<h1>dashboard.html not found</h1>", status_code=404)
    return HTMLResponse(content=LEGACY_DASHBOARD_HTML.read_text(encoding="utf-8"))
