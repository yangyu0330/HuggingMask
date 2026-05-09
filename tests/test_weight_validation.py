from pathlib import Path
import json
import pickle
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import pytest
import torch
from fastapi.testclient import TestClient
from safetensors.torch import save_file

from proxy.app.main import app
from analyzer.validators.weight.hashing import sha256_file
from analyzer.validators.weight.pipeline import validate
import analyzer.validators.weight.cache as cache_mod
import analyzer.validators.weight.pipeline as pipeline_mod


client = TestClient(app)


@pytest.fixture(autouse=True)
def isolate_weight_cache(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(cache_mod, "CACHE_FILE", tmp_path / "cache_store.json")


def _wrong_sha256_for(path: Path) -> str:
    real = sha256_file(str(path))
    wrong = "0" * 64
    return wrong if wrong != real else "1" * 64


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


def _payload_with_real_hash(
    path: Path,
    file_kind: str,
    ext: str,
    policy: str,
    enable_path_b: bool = False,
):
    digest = sha256_file(str(path))
    return _payload(
        path=path,
        file_kind=file_kind,
        ext=ext,
        sha256=digest,
        policy=policy,
        enable_path_b=enable_path_b,
    )


def test_safetensors_pass(tmp_path: Path):
    path = tmp_path / "model.safetensors"
    save_file(
        {"linear.weight": torch.ones((2, 2), dtype=torch.float32)},
        str(path),
    )

    response = client.post(
        "/internal/v1/validation/jobs",
        json=_payload_with_real_hash(
            path,
            "SAFETENSORS",
            ".safetensors",
            "test-safe-pass",
        ),
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
        json=_payload(
            path,
            "SAFETENSORS",
            ".safetensors",
            _wrong_sha256_for(path),
            "test-safe-block",
        ),
    )

    assert response.status_code == 200
    body = response.json()

    assert body["overall_status"] == "BLOCK"
    assert body["artifact_results"][0]["status"] == "BLOCK"
    assert body["artifact_results"][0]["reason_entries"][0]["code"] == "ARTIFACT_HASH_MISMATCH"


def test_pickle_hash_mismatch_blocks(tmp_path: Path):
    path = tmp_path / "safe_model.pkl"
    safe_schema = {
        "__tensor_dict__": {
            "linear.weight": {
                "dtype": "float32",
                "shape": [2, 2],
                "data": [1.0, 1.0, 1.0, 1.0],
            }
        }
    }

    with open(path, "wb") as f:
        pickle.dump(safe_schema, f, protocol=4)

    response = client.post(
        "/internal/v1/validation/jobs",
        json=_payload(
            path,
            "PICKLE",
            ".pkl",
            _wrong_sha256_for(path),
            "test-pickle-hash-block",
        ),
    )

    assert response.status_code == 200
    body = response.json()

    assert body["overall_status"] == "BLOCK"
    assert body["artifact_results"][0]["status"] == "BLOCK"
    assert body["artifact_results"][0]["reason_entries"][0]["code"] == "ARTIFACT_HASH_MISMATCH"


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
        json=_payload_with_real_hash(
            path,
            "PICKLE",
            ".pkl",
            "test-pickle-block",
        ),
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
        json=_payload_with_real_hash(
            path,
            "PICKLE",
            ".pkl",
            "test-pickle-pass",
        ),
    )

    assert response.status_code == 200
    body = response.json()

    result = body["artifact_results"][0]

    assert body["overall_status"] == "PASS"
    assert result["status"] == "PASS"
    assert result["reason_entries"][0]["code"] == "PICKLE_OPCODE_ALLOWED_ONLY"
    assert result["details"]["converted"]["status"] == "PASS"
    assert result["generated_artifact"] is not None
    assert result["generated_artifact"]["file_kind"] == "SAFETENSORS"


def test_pickle_path_b_request_ignores_path_a_only_cache(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    path = tmp_path / "safe_model.pkl"
    safe_schema = {
        "__tensor_dict__": {
            "linear.weight": {
                "dtype": "float32",
                "shape": [2, 2],
                "data": [1.0, 1.0, 1.0, 1.0],
            }
        }
    }

    with open(path, "wb") as f:
        pickle.dump(safe_schema, f, protocol=4)

    policy = "test-path-b-cache-bypass"
    first = validate(
        str(path),
        policy_fingerprint=policy,
        file_kind="PICKLE",
        enable_path_b=False,
    )
    assert first["status"] == "PASS"
    assert "path_b" not in first

    calls = []

    def fake_run_in_docker(**kwargs):
        calls.append(kwargs)
        return {
            "status": "PASS",
            "reason_code": "PICKLE_PATH_B_LOAD_OK",
            "reason": "pickle loaded in sandbox",
            "tensors": first["path_a"]["tensors"],
        }

    monkeypatch.setattr(pipeline_mod, "run_in_docker", fake_run_in_docker)

    second = validate(
        str(path),
        policy_fingerprint=policy,
        file_kind="PICKLE",
        enable_path_b=True,
    )

    assert calls
    assert second.get("cached") is not True
    assert second["status"] == "PASS"
    assert "path_b" in second


def test_weight_cli_outputs_json(tmp_path: Path):
    path = tmp_path / "model.safetensors"
    save_file(
        {"linear.weight": torch.ones((2, 2), dtype=torch.float32)},
        str(path),
    )

    root_cache_file = ROOT / "cache_store.json"
    root_cache_file.unlink(missing_ok=True)
    try:
        response = subprocess.run(
            [
                sys.executable,
                "-m",
                "analyzer.validators.weight.cli",
                str(path),
                "--policy-fingerprint",
                "test-cli",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
    finally:
        root_cache_file.unlink(missing_ok=True)

    assert response.returncode == 0, response.stderr
    body = json.loads(response.stdout)
    assert body["status"] == "PASS"
