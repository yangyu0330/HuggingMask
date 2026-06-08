import importlib
import os
import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import analyzer.validators.weight.cache as cache_mod


@pytest.fixture
def client(monkeypatch, tmp_path: Path):
    tmpdir = tempfile.mkdtemp()
    db_path = Path(tmpdir) / "whitelist.db"
    monkeypatch.setenv("HUGGINGMASK_DB_URL", f"sqlite:///{db_path}")
    monkeypatch.setattr(cache_mod, "CACHE_FILE", tmp_path / "cache_store.json")

    from whitelist import database as db_mod
    importlib.reload(db_mod)
    from whitelist import tables as t_mod
    importlib.reload(t_mod)
    from whitelist import audit as a_mod
    importlib.reload(a_mod)
    from whitelist import pending_store as ps_mod
    importlib.reload(ps_mod)
    from whitelist import engine as e_mod
    importlib.reload(e_mod)
    from whitelist import feedback as fb_mod
    importlib.reload(fb_mod)
    from whitelist import bootstrap as bs_mod
    importlib.reload(bs_mod)
    from whitelist import router as r_mod
    importlib.reload(r_mod)
    from proxy.app import demo as d_mod
    importlib.reload(d_mod)
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


def test_list_scenarios_returns_all_mock_hf_fixtures(client):
    response = client.get("/internal/v1/demo/scenarios")

    assert response.status_code == 200
    items = response.json()["items"]
    assert [item["scenario_id"] for item in items] == [
        "hm-01-safe-st",
        "hm-02-safe-pkl",
        "hm-03-bad-pkl-reduce",
        "hm-04-bad-py-import",
        "hm-05-bad-config-automap",
    ]
    assert all(item["fixture_path"].startswith("mock_hf/") for item in items)


def test_scenario_detail_contains_expected_fixture_metadata(client):
    response = client.get("/internal/v1/demo/scenarios/hm-02-safe-pkl")

    assert response.status_code == 200
    body = response.json()
    assert body["scenario_id"] == "hm-02-safe-pkl"
    assert "pytorch_model.bin" in body["required_repo_files"]
    assert body["expected"]["expected_overall_decision"] == "APPROVE_WITH_TRANSFORM"
    assert any(item["repo_path"] == "config.json" for item in body["source_files"])


def test_scenario_path_traversal_is_rejected(client):
    response = client.get("/internal/v1/demo/scenarios/..%2F..%2FREADME.md")

    assert response.status_code in {404, 405}


def test_run_safe_pickle_shows_generated_safetensors_and_match(client):
    response = client.post(
        "/internal/v1/demo/scenarios/hm-02-safe-pkl/run",
        json={"requested_by": "pytest", "repeat_cache_check": True},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["matched_expectation"] is True
    assert body["actual"]["overall_decision"] == "APPROVE_WITH_TRANSFORM"
    assert body["actual"]["overall_status"] == "PASS"
    assert any(item.endswith(".safetensors") for item in body["actual"]["generated_artifacts"])
    assert body["validation_response"]["overall_status"] == "PASS"
    assert body["cache_check_response"] is not None


@pytest.mark.parametrize(
    ("scenario_id", "expected_status"),
    [
        ("hm-01-safe-st", "PASS"),
        ("hm-02-safe-pkl", "PASS"),
        ("hm-03-bad-pkl-reduce", "BLOCK"),
        ("hm-04-bad-py-import", "BLOCK"),
        ("hm-05-bad-config-automap", "BLOCK"),
    ],
)
def test_run_each_fixture_returns_validation_summary(client, scenario_id, expected_status):
    response = client.post(
        f"/internal/v1/demo/scenarios/{scenario_id}/run",
        json={"requested_by": "pytest"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["scenario_id"] == scenario_id
    assert body["validation_response"]["artifact_results"]
    assert body["expected"]["overall_status"] == expected_status
    assert body["matched_expectation"] is True, body["expectation_mismatches"]
    assert "overall_status" in body["actual"]
    assert "reason_codes" in body["actual"]


def test_strict_default_config_demo_enforcement_keeps_response_consistent(client):
    response = client.post(
        "/internal/v1/demo/scenarios/hm-05-bad-config-automap/run",
        json={"requested_by": "pytest"},
    )

    assert response.status_code == 200
    body = response.json()
    validation = body["validation_response"]
    config_result = next(
        item
        for item in validation["artifact_results"]
        if item["artifact"]["repo_path"] == "config.json"
    )
    config_artifact_id = config_result["artifact"]["artifact_id"]

    assert body["matched_expectation"] is True
    assert validation["overall_decision"] == "DENY"
    assert validation["overall_status"] == "BLOCK"
    assert validation["release_action"] == "DENY"
    assert config_result["status"] == "BLOCK"
    assert config_result["details"]["effective_status"] == "BLOCK"
    assert config_result["details"]["demo_policy_enforcement"]["policy_profile"] == "strict_default"
    assert validation["coverage_summary"]["blocked"] >= 1
    assert config_artifact_id in validation["blocked_artifact_ids"]
    assert config_artifact_id not in validation["pending_artifact_ids"]
    assert config_artifact_id not in validation["approved_artifact_ids"]


def test_demo_evidence_and_readiness(client):
    evidence = client.get("/internal/v1/demo/evidence")
    readiness = client.get("/internal/v1/demo/readiness")

    assert evidence.status_code == 200
    assert readiness.status_code == 200
    evidence_items = evidence.json()["items"]
    assert any(item["path"] == "docs/final_demo_script.md" for item in evidence_items)
    body = readiness.json()
    assert body["health"]["ok"] is True
    assert "approved_active" in body["stats"]
    assert "missing" in body["evidence"]


def test_live_model_run_reports_download_classify_lanes_and_final(client, monkeypatch, tmp_path):
    snapshot = tmp_path / "hf_snapshot"
    snapshot.mkdir()
    (snapshot / "config.json").write_text(
        '{"model_type":"demo","architectures":["DemoModel"]}',
        encoding="utf-8",
    )
    (snapshot / "modeling_demo.py").write_text(
        "import torch\\nclass DemoModel:\\n    def forward(self, x):\\n        return torch.special.expit(x)\\n",
        encoding="utf-8",
    )
    (snapshot / "model.safetensors").write_bytes(b"not-used-in-fast-mode")

    from proxy.app import demo as d_mod

    monkeypatch.setattr(d_mod, "_download_hf_snapshot", lambda request: snapshot)

    response = client.post(
        "/internal/v1/demo/live-model/run",
        json={"repo_id": "org/demo-model", "skip_weights": True, "enable_path_b": True},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["repo_id"] == "org/demo-model"
    assert body["fast_mode"] is True
    assert body["file_summary"]["python"] >= 1
    assert body["file_summary"]["config"] >= 1
    assert "model.safetensors" in body["skipped"]["weights_fast_mode"]
    step_titles = [step["title"] for step in body["steps"]]
    assert "Hugging Face 모델 다운로드" in step_titles
    assert "파일 분류" in step_titles
    assert "파일별 검증 실행" in step_titles
    assert "샌드박스 실행 근거" in step_titles
    assert "최종 릴리스 판정" in step_titles
    lanes = {lane["lane"]: lane for lane in body["lane_results"]}
    assert "python" in lanes
    assert "config" in lanes
    sandbox_summary = body["sandbox_summary"]
    python_results = [
        {
            "repo_path": item["artifact"]["repo_path"],
            "status": item["status"],
            "grade": item["grade"],
            "route_kind": item["route_kind"],
            "review_action": item["review_action"],
            "has_sandbox_check": "sandbox_check" in item["details"],
            "detail_keys": sorted(item["details"].keys()),
        }
        for item in body["validation_response"]["artifact_results"]
        if item["artifact"]["file_kind"] == "PYTHON"
    ]
    assert sandbox_summary["requested"] is True
    assert sandbox_summary["eligible_count"] >= 1
    assert sandbox_summary["check_count"] >= 1, python_results
    assert sandbox_summary["checks"][0]["decision"] == "NOT_RUN"
    assert sandbox_summary["checks"][0]["reason_code"] in {
        "SANDBOX_NOT_CONFIGURED",
        "SANDBOX_CHECK_NOT_ATTACHED",
    }
    assert "validation_response" in body


def test_strict_default_config_trigger_response_is_consistent(client):
    response = client.post(
        "/internal/v1/demo/scenarios/hm-05-bad-config-automap/run",
        json={"requested_by": "pytest"},
    )

    assert response.status_code == 200
    body = response.json()
    validation = body["validation_response"]
    assert validation["overall_status"] == "BLOCK"
    assert validation["overall_decision"] == "DENY"
    config_result = next(
        item for item in validation["artifact_results"]
        if item["artifact"]["repo_path"] == "config.json"
    )
    assert config_result["status"] == "BLOCK"
    assert config_result["details"]["effective_status"] == "BLOCK"
    assert config_result["details"]["demo_policy_enforcement"]["policy_profile"] == "strict_default"
    assert validation["coverage_summary"]["blocked"] >= 1
    assert config_result["artifact"]["artifact_id"] in validation["blocked_artifact_ids"]
