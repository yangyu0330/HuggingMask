import importlib
import os
import re
import subprocess
import tempfile
import textwrap
from pathlib import Path

import pytest
from fastapi.testclient import TestClient


REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def client(monkeypatch):
    tmpdir = tempfile.mkdtemp()
    db_path = Path(tmpdir) / "whitelist.db"
    monkeypatch.setenv("HUGGINGMASK_DB_URL", f"sqlite:///{db_path}")

    from whitelist import database as db_mod
    importlib.reload(db_mod)
    from whitelist import tables as t_mod
    importlib.reload(t_mod)
    from whitelist import bootstrap as bs_mod
    importlib.reload(bs_mod)
    from whitelist import router as r_mod
    importlib.reload(r_mod)
    from proxy.app import static_frontend as sf_mod
    importlib.reload(sf_mod)
    from proxy.app import main as m_mod
    importlib.reload(m_mod)

    with TestClient(m_mod.app) as test_client:
        yield test_client

    try:
        db_mod.engine.dispose()
    except Exception:
        pass
    try:
        if db_path.exists():
            db_path.unlink()
        os.rmdir(tmpdir)
    except (PermissionError, OSError):
        pass


def test_dashboard_returns_built_react_app(client):
    response = client.get("/dashboard")

    assert response.status_code == 200
    assert "text/html" in response.headers.get("content-type", "")
    assert '<div id="root">' in response.text
    assert "/assets/" in response.text
    assert "Frontend build not found" not in response.text


def test_dashboard_deep_link_uses_react_fallback(client):
    response = client.get("/dashboard/demo")

    assert response.status_code == 200
    assert '<div id="root">' in response.text


def test_built_frontend_asset_is_served(client):
    html = client.get("/dashboard").text
    match = re.search(r'src="(/assets/[^"]+\.js)"', html)
    assert match, html

    asset = client.get(match.group(1))
    assert asset.status_code == 200
    assert "javascript" in asset.headers.get("content-type", "")


def test_legacy_dashboard_route_is_available(client):
    response = client.get("/legacy-dashboard")

    assert response.status_code == 200
    assert "/internal/v1" in response.text


def test_frontend_api_base_is_internal_v1():
    client_source = (REPO_ROOT / "frontend" / "src" / "api" / "client.ts").read_text(
        encoding="utf-8"
    )

    assert "API_BASE = '/internal/v1'" in client_source
    assert "'/api/v1'" not in client_source


def test_frontend_api_client_rejects_applied_false_response():
    script = textwrap.dedent(
        """
        const fs = require('fs');
        const ts = require('./frontend/node_modules/typescript');
        const vm = require('vm');

        const source = fs.readFileSync('frontend/src/api/client.ts', 'utf8');
        const compiled = ts.transpileModule(source, {
          compilerOptions: {
            module: ts.ModuleKind.CommonJS,
            target: ts.ScriptTarget.ES2020,
          },
        }).outputText;

        let requestedUrl = null;
        const sandbox = {
          module: { exports: {} },
          exports: {},
          require,
          Headers,
          FormData,
          Blob,
          ArrayBuffer,
          URLSearchParams,
          fetch: async (url) => {
            requestedUrl = url;
            return {
              ok: true,
              status: 200,
              headers: new Headers({ 'content-type': 'application/json' }),
              json: async () => ({ applied: false, message: 'not applied' }),
              text: async () => '',
            };
          },
        };
        sandbox.exports = sandbox.module.exports;
        vm.runInNewContext(compiled, sandbox, { filename: 'client.js' });

        (async () => {
          try {
            await sandbox.module.exports.fetchJson('/review');
            throw new Error('fetchJson resolved instead of rejecting applied:false');
          } catch (error) {
            if (error.name !== 'ApiError') {
              throw error;
            }
            if (error.status !== 200) {
              throw new Error(`expected status 200, got ${error.status}`);
            }
            if (!error.body || error.body.applied !== false) {
              throw new Error(`expected applied:false body, got ${JSON.stringify(error.body)}`);
            }
            if (requestedUrl !== '/internal/v1/review') {
              throw new Error(`expected /internal/v1/review, got ${requestedUrl}`);
            }
          }
        })().catch((error) => {
          console.error(error);
          process.exit(1);
        });
        """
    )

    result = subprocess.run(
        ["node", "-e", script],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr


def test_overview_binds_required_readiness_endpoints():
    api_source = (REPO_ROOT / "frontend" / "src" / "api" / "overview.ts").read_text(
        encoding="utf-8"
    )
    overview_source = (
        REPO_ROOT / "frontend" / "src" / "features" / "overview" / "OverviewPage.tsx"
    ).read_text(encoding="utf-8")

    assert "fetch('/health'" in api_source
    assert "apiGet<WhitelistStats>('/stats')" in api_source
    assert "apiGet<DemoReadiness>('/demo/readiness')" in api_source
    assert "readiness.evidence.missing" in overview_source
    assert "readiness.warnings" in overview_source
    assert "pipelineStages" in overview_source
    assert "ErrorPanel" in overview_source
    assert "aria-busy" in overview_source


def test_demo_console_binds_scenarios_and_validation_detail():
    api_source = (REPO_ROOT / "frontend" / "src" / "api" / "demo.ts").read_text(
        encoding="utf-8"
    )
    routes_source = (REPO_ROOT / "frontend" / "src" / "app" / "routes.tsx").read_text(
        encoding="utf-8"
    )
    demo_source = (
        REPO_ROOT / "frontend" / "src" / "features" / "demo" / "DemoConsolePage.tsx"
    ).read_text(encoding="utf-8")
    validation_source = (
        REPO_ROOT
        / "frontend"
        / "src"
        / "features"
        / "validation"
        / "ValidationDetailPage.tsx"
    ).read_text(encoding="utf-8")

    assert "apiGet<DemoScenarioListResponse>('/demo/scenarios')" in api_source
    assert "/demo/scenarios/${encodeURIComponent(scenarioId)}/run" in api_source
    assert "repeat_cache_check: false" in api_source
    assert "enable_path_b: false" in api_source
    assert "window.localStorage" in api_source

    assert 'path="/demo"' in routes_source
    assert 'path="/validation"' in routes_source
    assert "scenario-list" in demo_source
    assert "matched_expectation" in demo_source
    assert "Expectation Match" in demo_source
    assert "Job Decision" in demo_source
    assert "Artifact Status" in demo_source
    assert "generated_artifacts" in demo_source
    assert "safetensors" in demo_source
    assert "validation_response" in demo_source
    assert "Raw JSON" in demo_source
    assert "Decision Hierarchy" in validation_source
    assert "Route Explanation" in validation_source
    assert "coverage_summary" in validation_source
    assert "innerHTML" not in demo_source
    assert "innerHTML" not in validation_source


def test_operations_binds_required_endpoints_and_safe_rendering():
    api_source = (REPO_ROOT / "frontend" / "src" / "api" / "ops.ts").read_text(
        encoding="utf-8"
    )
    routes_source = (REPO_ROOT / "frontend" / "src" / "app" / "routes.tsx").read_text(
        encoding="utf-8"
    )
    ops_source = (
        REPO_ROOT
        / "frontend"
        / "src"
        / "features"
        / "operations"
        / "OperationsPage.tsx"
    ).read_text(encoding="utf-8")

    assert "apiPost<WhitelistCheckResult[], WhitelistCheckRequest>(" in api_source
    assert "'/whitelist/check'" in api_source
    assert "apiGet<PendingListResponse>(appendParams('/pending'" in api_source
    assert "apiPost<ReviewDecisionResult, ReviewDecisionRequest>('/review'" in api_source
    assert "apiGet<ApprovedListResponse>(appendParams('/approved'" in api_source
    assert "include_blocked: params.include_blocked ?? true" in api_source
    assert "apiPost<FeedbackReportResponse, FeedbackReportRequest>('/feedback'" in api_source
    assert "apiGet<FeedbackListResponse>(appendParams('/feedback'" in api_source
    assert "apiGet<AuditListResponse>(appendParams('/audit'" in api_source
    assert "apiGet<AuditVerifyResponse>('/audit/verify')" in api_source

    assert 'path="/operations"' in routes_source
    assert "OperationsPage" in routes_source
    assert "Whitelist Check" in ops_source
    assert "Pending Review Queue" in ops_source
    assert "AUTO_APPROVE is a recommendation" in ops_source
    assert "Approved and Blocked Policies" in ops_source
    assert "Submit feedback" in ops_source
    assert "Verify chain" in ops_source
    assert "reviewDecisions" in ops_source
    assert 'ErrorPanel title="Review decision failed"' in ops_source
    assert "error={reviewMutation.error}" in ops_source
    assert "reviewMutation.reset()" in ops_source
    assert "'approve'" in ops_source
    assert "'reject'" in ops_source
    assert "'defer'" in ops_source
    assert "risk_keywords" in ops_source
    assert "ALLOWED" in ops_source
    assert "BLOCKED" in ops_source
    assert "PENDING" in ops_source
    assert "innerHTML" not in ops_source


def test_evidence_route_binds_evidence_api_and_limitations():
    api_source = (REPO_ROOT / "frontend" / "src" / "api" / "demo.ts").read_text(
        encoding="utf-8"
    )
    routes_source = (REPO_ROOT / "frontend" / "src" / "app" / "routes.tsx").read_text(
        encoding="utf-8"
    )
    evidence_source = (
        REPO_ROOT
        / "frontend"
        / "src"
        / "features"
        / "evidence"
        / "EvidencePage.tsx"
    ).read_text(encoding="utf-8")

    assert "apiGet<DemoEvidenceResponse>('/demo/evidence')" in api_source
    assert 'path="/evidence"' in routes_source
    assert "EvidencePage" in routes_source
    assert "Evidence Matrix" in evidence_source
    assert "Missing Evidence" in evidence_source
    assert "Demo Documents" in evidence_source
    assert "Known Limitations" in evidence_source
    assert "B-2/gVisor" in evidence_source
    assert "opt-in evidence" in evidence_source
    assert "Live Hugging Face" in evidence_source
    assert "not a production crawler claim" in evidence_source
    assert "focused build and pytest checks" in evidence_source
    assert "README.md" in evidence_source
    assert "SETUP_GUIDE.md" in evidence_source
    assert "docs/final_demo_script.md" in evidence_source
    assert "innerHTML" not in evidence_source
