from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import pickle

import torch
from fastapi.testclient import TestClient
from safetensors.torch import save_file

from proxy.app.main import app
from analyzer.validators.weight.hashing import sha256_file


client = TestClient(app)


def _payload(
    path: Path,
    file_kind: str,
    ext: str,
    sha256: str,
    policy: str,
    enable_path_b: bool = False,
):
    return {
        "request_id": f"req-{policy}",
        "job_id": f"job-{policy}",
        "policy_fingerprint": policy,
        "enable_path_b": enable_path_b,
        "artifacts": [
            {
                "artifact_id": f"sha256:{sha256}",
                "repo_path": path.name,
                "file_name": path.name,
                "file_kind": file_kind,
                "detected_extension": ext,
                "size_bytes": path.stat().st_size,
                "sha256": sha256,
                "source_url": "local",
                "temp_local_path": str(path),
                "referenced_by": [],
                "is_generated": False,
            }
        ],
    }


def test_safetensors_pass(tmp_path: Path):
    path = tmp_path / "model.safetensors"
    save_file(
        {"linear.weight": torch.ones((2, 2), dtype=torch.float32)},
        str(path),
    )

    digest = sha256_file(str(path))

    response = client.post(
        "/internal/v1/validation/jobs",
        json=_payload(path, "SAFETENSORS", ".safetensors", digest, "test-safe-pass"),
    )

    assert response.status_code == 200
    body = response.json()

    assert body["overall_status"] == "PASS"
    assert body["artifact_results"][0]["status"] == "PASS"
    assert body["artifact_results"][0]["reason_entries"][0]["code"] == "SAFE_TENSORS_HASH_OK"


def test_safetensors_hash_mismatch_blocks(tmp_path: Path):
    path = tmp_path / "model.safetensors"
    save_file(
        {"linear.weight": torch.ones((2, 2), dtype=torch.float32)},
        str(path),
    )

    response = client.post(
        "/internal/v1/validation/jobs",
        json=_payload(path, "SAFETENSORS", ".safetensors", "dummy", "test-safe-block"),
    )

    assert response.status_code == 200
    body = response.json()

    assert body["overall_status"] == "BLOCK"
    assert body["artifact_results"][0]["status"] == "BLOCK"
    assert body["artifact_results"][0]["reason_entries"][0]["code"] == "SAFE_TENSORS_HASH_MISMATCH"


def test_malicious_pickle_blocks(tmp_path: Path):
    class Exploit:
        def __reduce__(self):
            import os
            return (os.system, ("echo hacked",))

    path = tmp_path / "malicious.pkl"

    with open(path, "wb") as f:
        pickle.dump(Exploit(), f, protocol=4)

    response = client.post(
        "/internal/v1/validation/jobs",
        json=_payload(path, "PICKLE", ".pkl", "dummy", "test-pickle-block"),
    )

    assert response.status_code == 200
    body = response.json()

    assert body["overall_status"] == "BLOCK"
    assert body["artifact_results"][0]["status"] == "BLOCK"
    assert body["artifact_results"][0]["reason_entries"][0]["code"] == "PICKLE_OPCODE_BLOCKED"


def test_safe_schema_pickle_passes_and_converts(tmp_path: Path):
    path = tmp_path / "safe_model.pkl"

    safe_schema = {
        "__tensor_dict__": {
            "linear.weight": {
                "dtype": "float32",
                "shape": [2, 2],
                "data": [1.0, 1.0, 1.0, 1.0],
            },
            "linear.bias": {
                "dtype": "float32",
                "shape": [2],
                "data": [0.5, 0.5],
            },
        }
    }

    with open(path, "wb") as f:
        pickle.dump(safe_schema, f, protocol=4)

    response = client.post(
        "/internal/v1/validation/jobs",
        json=_payload(path, "PICKLE", ".pkl", "dummy", "test-pickle-pass"),
    )

    assert response.status_code == 200
    body = response.json()

    result = body["artifact_results"][0]

    assert body["overall_status"] == "PASS"
    assert result["status"] == "PASS"
    assert result["reason_entries"][0]["code"] == "PICKLE_OPCODE_ALLOWED_ONLY"
    assert result["detail"]["converted"]["status"] == "PASS"
    assert result["generated_artifact"] is not None
    assert result["generated_artifact"]["file_kind"] == "SAFETENSORS"