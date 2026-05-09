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


def _payload_for(file_path: Path, file_kind: str, ext: str) -> dict:
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
                "temp_local_path": str(file_path),
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
