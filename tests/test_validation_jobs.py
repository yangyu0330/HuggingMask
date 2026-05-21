import json
from pathlib import Path

from fastapi.testclient import TestClient
import pytest
from safetensors.torch import save_file
import torch

from proxy.app.main import app
from analyzer.validators.weight.hashing import sha256_file
import analyzer.validators.weight.cache as cache_mod

client = TestClient(app)


@pytest.fixture(autouse=True)
def isolate_weight_cache(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(cache_mod, "CACHE_FILE", tmp_path / "cache_store.json")


def _payload_for(
    file_path: Path,
    file_kind: str,
    ext: str,
    *,
    temp_local_path: str | None = None,
) -> dict:
    sha256 = sha256_file(str(file_path))

    return {
        "request_id": "test-request",
        "job_id": "test-job",
        "policy_fingerprint": "policy-2026.04.22",
        "artifacts": [
            {
                "artifact_id": f"sha256:{sha256}",
                "repo_path": file_path.name,
                "file_name": file_path.name,
                "file_kind": file_kind,
                "detected_extension": ext,
                "size_bytes": file_path.stat().st_size,
                "sha256": sha256,
                "source_url": "local",
                "temp_local_path": temp_local_path or str(file_path),
                "referenced_by": [],
                "is_generated": False,
            }
        ],
    }


def test_validation_jobs_safetensors(tmp_path: Path):
    path = tmp_path / "model.safetensors"
    save_file(
        {"linear.weight": torch.ones((2, 2), dtype=torch.float32)},
        str(path),
    )

    response = client.post(
        "/internal/v1/validation/jobs",
        json=_payload_for(path, "SAFETENSORS", ".safetensors"),
    )

    assert response.status_code == 200
    body = response.json()
    assert body["overall_status"] == "PASS"
    assert body["artifact_results"][0]["status"] == "PASS"


def test_validation_jobs_other_is_skipped(tmp_path: Path):
    path = tmp_path / "README.md"
    path.write_text("hello", encoding="utf-8")

    response = client.post(
        "/internal/v1/validation/jobs",
        json=_payload_for(path, "OTHER", ".md"),
    )

    assert response.status_code == 200
    body = response.json()
    assert body["artifact_results"][0]["status"] == "SKIPPED"
    assert body["pending_artifact_ids"] == []


def test_validation_jobs_python_without_model_uses_orchestrator_defaults(tmp_path: Path):
    path = tmp_path / "tokenization_demo.py"
    path.write_text(
        "class DemoTokenizer:\n"
        "    def tokenize(self, text):\n"
        "        return text.split()\n",
        encoding="utf-8",
    )

    response = client.post(
        "/internal/v1/validation/jobs",
        json=_payload_for(path, "PYTHON", ".py"),
    )

    assert response.status_code == 200
    body = response.json()
    assert body["overall_status"] == "PENDING_REVIEW"
    assert body["overall_decision"] == "REVIEW_REQUIRED"
    assert body["release_action"] != "APPROVE"
    assert body["artifact_results"][0]["status"] == "PENDING_REVIEW"
    reason_codes = {
        entry["code"]
        for result in body["artifact_results"]
        for entry in result["reason_entries"]
    }
    assert "ORCHESTRATOR_ERROR" not in reason_codes


def test_validation_jobs_config_without_model_does_not_orchestrator_error(tmp_path: Path):
    path = tmp_path / "config.json"
    path.write_text(
        json.dumps({"auto_map": {"AutoModel": "modeling_missing.DemoModel"}}),
        encoding="utf-8",
    )

    response = client.post(
        "/internal/v1/validation/jobs",
        json=_payload_for(path, "CONFIG_JSON", ".json"),
    )

    assert response.status_code == 200
    body = response.json()
    assert body["overall_status"] == "PENDING_REVIEW"
    assert body["overall_decision"] == "REVIEW_REQUIRED"
    assert body["release_action"] != "APPROVE"
    reason_codes = {
        entry["code"]
        for result in body["artifact_results"]
        for entry in result["reason_entries"]
    }
    assert "ORCHESTRATOR_ERROR" not in reason_codes


def test_validation_jobs_preprocessing_metadata_routes_to_semantic_scan(tmp_path: Path):
    path = tmp_path / "processor_config.json"
    path.write_text(
        json.dumps(
            {
                "processor_class": "DemoProcessor",
                "chat_template": "{{ messages }}",
            }
        ),
        encoding="utf-8",
    )

    response = client.post(
        "/internal/v1/validation/jobs",
        json=_payload_for(path, "PROCESSOR_CONFIG_JSON", ".json"),
    )

    assert response.status_code == 200
    body = response.json()
    result = body["artifact_results"][0]
    assert body["overall_status"] == "PENDING_REVIEW"
    assert body["overall_decision"] == "REVIEW_REQUIRED"
    assert body["release_action"] != "APPROVE"
    assert result["route_kind"] == "PREPROCESSING_SEMANTIC_SCAN"
    assert result["status"] == "PENDING_REVIEW"
    assert result["details"]["semantic_check"]["status"] == "BASELINE_MISSING"


def test_validation_jobs_orchestrator_error_preserves_error_status(tmp_path: Path):
    path = tmp_path / "modeling_missing.py"
    path.write_text("def f():\n    return 1\n", encoding="utf-8")

    response = client.post(
        "/internal/v1/validation/jobs",
        json=_payload_for(
            path,
            "PYTHON",
            ".py",
            temp_local_path=str(tmp_path / "does-not-exist.py"),
        ),
    )

    assert response.status_code == 200
    body = response.json()
    assert body["overall_status"] == "ERROR"
    assert body["overall_decision"] == "ERROR"
    assert body["release_action"] == "ERROR"
    assert body["artifact_results"][0]["status"] == "ERROR"
    assert body["artifact_results"][0]["artifact"]["artifact_id"] in body["pending_artifact_ids"]
    assert body["blocked_artifact_ids"] == []
