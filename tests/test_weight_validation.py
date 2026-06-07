from pathlib import Path
from types import SimpleNamespace
import ast
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
from analyzer.validators.weight import cache as cache_mod
from analyzer.validators.weight import cli as weight_cli
from analyzer.validators.weight import pipeline as pipeline_mod
from analyzer.validators.weight.dtypes import DTYPE_MAP
from analyzer.validators.weight.hashing import sha256_file
from analyzer.validators.weight.pipeline import validate
from analyzer.validators.weight.reporting import make_tensor_entry
from analyzer.validators.weight.sandbox import docker_runner, load_and_extract
from analyzer.validators.weight.validators import modelscan_wrapper
from analyzer.validators.weight.validators import yara_scanner


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


def _artifact_entry(
    path: Path,
    file_kind: str,
    ext: str,
    repo_path: str | None = None,
) -> dict:
    digest = sha256_file(str(path))
    resolved_repo_path = repo_path or path.name
    return {
        "artifact_id": f"sha256:{digest}",
        "repo_path": resolved_repo_path,
        "file_name": Path(resolved_repo_path).name,
        "file_kind": file_kind,
        "detected_extension": ext,
        "size_bytes": path.stat().st_size,
        "sha256": digest,
        "source_url": "local",
        "temp_local_path": str(path),
        "referenced_by": [],
        "is_generated": False,
    }


def _job_payload(policy: str, artifacts: list[dict], enable_path_b: bool = False) -> dict:
    return {
        "request_id": f"req-{policy}",
        "job_id": f"job-{policy}",
        "policy_fingerprint": policy,
        "enable_path_b": enable_path_b,
        "artifacts": artifacts,
    }


def _scanner_pass(path: str) -> dict:
    return {
        "status": "PASS",
        "reason_code": "TEST_SCANNER_PASS",
        "reason": "scanner bypassed in unit test",
    }


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
    assert body["artifact_results"][0]["reason_entries"][0]["code"] in {
        "PICKLE_OPCODE_BLOCKED",
        "PICKLE_YARA_BLOCKED",
    }


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


def test_path_b_block_cache_does_not_poison_default_pickle_validation(
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

    def fake_run_in_docker(*args, **kwargs):
        return {
            "status": "BLOCK",
            "reason_code": "PICKLE_PATH_B_NOT_AVAILABLE",
            "reason": "Path B is not available in this environment",
        }

    monkeypatch.setattr(pipeline_mod, "run_in_docker", fake_run_in_docker)

    policy = "test-path-b-cache-isolated"
    path_b_result = validate(
        str(path),
        policy_fingerprint=policy,
        file_kind="PICKLE",
        enable_path_b=True,
    )

    default_result = validate(
        str(path),
        policy_fingerprint=policy,
        file_kind="PICKLE",
        enable_path_b=False,
    )

    assert path_b_result["status"] == "BLOCK"
    assert path_b_result["stage"] == "PATH_B"
    assert "PICKLE_PATH_B" in path_b_result["cache_key"]
    assert default_result["status"] == "PASS"
    assert "path_b" not in default_result
    assert "PICKLE_PATH_B" not in default_result["cache_key"]


def test_weight_cli_outputs_json(tmp_path: Path):
    path = tmp_path / "model.safetensors"
    save_file(
        {"linear.weight": torch.ones((2, 2), dtype=torch.float32)},
        str(path),
    )

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

    assert response.returncode == 0, response.stderr
    body = json.loads(response.stdout)
    assert body["status"] == "PASS"


def test_path_ab_mismatch_blocks(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
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

    def fake_run_in_docker(*args, **kwargs):
        return {
            "status": "PASS",
            "reason_code": "PICKLE_PATH_B_LOAD_OK",
            "reason": "pickle loaded in sandbox",
            "tensors": {
                "linear.weight": {
                    "hash": "bad-hash",
                    "shape": [2, 2],
                    "dtype": "torch.float32",
                }
            },
        }

    monkeypatch.setattr(pipeline_mod, "run_in_docker", fake_run_in_docker)

    result = validate(
        str(path),
        policy_fingerprint="test-ab-mismatch",
        file_kind="PICKLE",
        enable_path_b=True,
    )

    assert result["status"] == "BLOCK"
    assert result["stage"] == "DIFF"
    assert result["reason_code"] == "PICKLE_PATH_AB_MISMATCH"
    assert result["diff"]["status"] == "MISMATCH"


def test_path_b_extra_tensor_blocks(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
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

    first = validate(
        str(path),
        policy_fingerprint="test-extra-tensor-baseline",
        file_kind="PICKLE",
        enable_path_b=False,
    )

    def fake_run_in_docker(*args, **kwargs):
        tensors = dict(first["path_a"]["tensors"])
        tensors["unexpected.bias"] = {
            "hash": "extra",
            "shape": [1],
            "dtype": "torch.float32",
        }

        return {
            "status": "PASS",
            "reason_code": "PICKLE_PATH_B_LOAD_OK",
            "reason": "pickle loaded in sandbox",
            "tensors": tensors,
        }

    monkeypatch.setattr(pipeline_mod, "run_in_docker", fake_run_in_docker)

    result = validate(
        str(path),
        policy_fingerprint="test-extra-tensor",
        file_kind="PICKLE",
        enable_path_b=True,
    )

    assert result["status"] == "BLOCK"
    assert result["reason_code"] == "PICKLE_PATH_AB_MISMATCH"
    assert any(
        item["reason"] == "MISSING_IN_A"
        for item in result["diff"]["details"]
    )


def test_path_ab_shape_dtype_mismatch_blocks(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
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

    def fake_run_in_docker(*args, **kwargs):
        return {
            "status": "PASS",
            "reason_code": "PICKLE_PATH_B_LOAD_OK",
            "reason": "pickle loaded in sandbox",
            "tensors": {
                "linear.weight": {
                    "hash": "same-hash-is-not-enough",
                    "shape": [4],
                    "dtype": "torch.float64",
                }
            },
        }

    monkeypatch.setattr(pipeline_mod, "run_in_docker", fake_run_in_docker)

    result = validate(
        str(path),
        policy_fingerprint="test-shape-dtype-mismatch",
        file_kind="PICKLE",
        enable_path_b=True,
    )

    assert result["status"] == "BLOCK"
    assert result["stage"] == "DIFF"
    assert result["reason_code"] == "PICKLE_PATH_AB_MISMATCH"

    reasons = {item["reason"] for item in result["diff"]["details"]}
    assert "SHAPE_MISMATCH" in reasons or "DTYPE_MISMATCH" in reasons


def test_pickle_pass_release_targets_converted_safetensors_not_original(tmp_path: Path):
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
        json=_payload_with_real_hash(
            path,
            "PICKLE",
            ".pkl",
            "test-release-converted",
        ),
    )

    assert response.status_code == 200
    body = response.json()

    original_id = f"sha256:{sha256_file(str(path))}"
    generated = body["artifact_results"][0]["generated_artifact"]

    assert body["overall_status"] == "PASS"
    assert generated is not None
    assert generated["file_kind"] == "SAFETENSORS"
    assert body["approved_artifact_ids"] == [generated["artifact_id"]]
    assert original_id not in body["approved_artifact_ids"]


def test_safetensors_release_is_not_denied_by_auxiliary_training_pickle(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
):
    monkeypatch.setattr(pipeline_mod, "scan_with_yara", _scanner_pass)
    monkeypatch.setattr(pipeline_mod, "scan_with_modelscan", _scanner_pass)

    safetensors_path = tmp_path / "model.safetensors"
    training_args_path = tmp_path / "training_args.bin"
    save_file(
        {"linear.weight": torch.ones((2, 2), dtype=torch.float32)},
        str(safetensors_path),
    )
    with open(training_args_path, "wb") as f:
        pickle.dump({"learning_rate": 1e-4, "num_train_epochs": 1}, f, protocol=4)

    response = client.post(
        "/internal/v1/validation/jobs",
        json=_job_payload(
            "test-auxiliary-training-neutral",
            [
                _artifact_entry(safetensors_path, "SAFETENSORS", ".safetensors"),
                _artifact_entry(training_args_path, "PICKLE", ".bin"),
            ],
        ),
    )

    assert response.status_code == 200
    body = response.json()
    results = {
        result["artifact"]["file_name"]: result
        for result in body["artifact_results"]
    }
    safetensors_result = results["model.safetensors"]
    auxiliary_result = results["training_args.bin"]

    assert body["overall_status"] == "PASS"
    assert body["overall_decision"] == "APPROVE"
    assert body["release_action"] == "APPROVE"
    assert body["approved_artifact_ids"] == [
        safetensors_result["artifact"]["artifact_id"]
    ]
    assert body["blocked_artifact_ids"] == []
    assert body["pending_artifact_ids"] == []
    assert auxiliary_result["status"] == "SKIPPED"
    assert auxiliary_result["reason_entries"][0]["code"] == (
        "PICKLE_AUXILIARY_NOT_RELEASE_ARTIFACT"
    )
    assert auxiliary_result["details"]["pickle_role"] == "AUXILIARY_TRAINING"
    assert auxiliary_result["details"]["release_eligible"] is False
    assert auxiliary_result["details"]["release_target"] is None


def test_deployable_raw_pickle_requires_review_without_release_approval(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
):
    monkeypatch.setattr(pipeline_mod, "scan_with_yara", _scanner_pass)
    monkeypatch.setattr(pipeline_mod, "scan_with_modelscan", _scanner_pass)

    path = tmp_path / "pytorch_model.bin"
    torch.save(
        {"linear.weight": torch.ones((2, 2), dtype=torch.float32)},
        path,
    )

    response = client.post(
        "/internal/v1/validation/jobs",
        json=_payload_with_real_hash(
            path,
            "PICKLE",
            ".bin",
            "test-deployable-raw-pickle-review",
        ),
    )

    assert response.status_code == 200
    body = response.json()
    result = body["artifact_results"][0]

    assert body["overall_status"] == "PENDING_REVIEW"
    assert body["overall_decision"] == "REVIEW_REQUIRED"
    assert body["release_action"] == "DENY"
    assert body["approved_artifact_ids"] == []
    assert body["blocked_artifact_ids"] == []
    assert body["pending_artifact_ids"] == [result["artifact"]["artifact_id"]]
    assert result["status"] == "PENDING_REVIEW"
    assert result["reason_entries"][0]["code"] == (
        "PICKLE_WEIGHT_REQUIRES_REVIEW_OR_CONVERSION"
    )
    assert result["details"]["pickle_role"] == "DEPLOYABLE_WEIGHT"
    assert result["details"]["release_eligible"] is False
    assert result["details"]["release_target"] is None


def test_path_a_parse_failure_preserves_path_b_review_evidence(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
):
    monkeypatch.setattr(pipeline_mod, "scan_with_yara", _scanner_pass)
    monkeypatch.setattr(pipeline_mod, "scan_with_modelscan", _scanner_pass)

    path = tmp_path / "pytorch_model.bin"
    torch.save(
        {"linear.weight": torch.ones((2, 2), dtype=torch.float32)},
        path,
    )

    calls = []

    def fake_run_in_docker(**kwargs):
        calls.append(kwargs)
        return {
            "status": "PASS",
            "reason_code": "PICKLE_PATH_B_LOAD_OK",
            "reason": "pickle loaded in sandbox for review evidence",
            "tensors": {
                "linear.weight": {
                    "hash": "sandbox-hash",
                    "shape": [2, 2],
                    "dtype": "torch.float32",
                }
            },
        }

    monkeypatch.setattr(pipeline_mod, "run_in_docker", fake_run_in_docker)

    result = validate(
        str(path),
        policy_fingerprint="test-path-b-review-evidence",
        file_kind="PICKLE",
        enable_path_b=True,
        repo_path="pytorch_model.bin",
    )

    assert len(calls) == 1
    assert result["status"] == "BLOCK"
    assert result["stage"] == "PATH_A"
    assert result["path_a"]["reason_code"] == "PICKLE_PARSE_ERROR"
    assert result["path_b"]["reason_code"] == "PICKLE_PATH_B_LOAD_OK"
    assert result["diff"]["reason"] == "PATH_A_BLOCKED_BEFORE_TENSOR_REPORT"
    assert result["pickle_role"] == "DEPLOYABLE_WEIGHT"
    assert result["release_eligible"] is False
    assert result["release_target"] is None


def test_path_b_success_does_not_approve_raw_pickle_release(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
):
    monkeypatch.setattr(pipeline_mod, "scan_with_yara", _scanner_pass)
    monkeypatch.setattr(pipeline_mod, "scan_with_modelscan", _scanner_pass)

    path = tmp_path / "pytorch_model.bin"
    torch.save(
        {"linear.weight": torch.ones((2, 2), dtype=torch.float32)},
        path,
    )

    def fake_run_in_docker(**kwargs):
        return {
            "status": "PASS",
            "reason_code": "PICKLE_PATH_B_LOAD_OK",
            "reason": "pickle loaded in sandbox for review evidence",
        }

    monkeypatch.setattr(pipeline_mod, "run_in_docker", fake_run_in_docker)

    response = client.post(
        "/internal/v1/validation/jobs",
        json=_payload_with_real_hash(
            path,
            "PICKLE",
            ".bin",
            "test-path-b-success-no-raw-release",
            enable_path_b=True,
        ),
    )

    assert response.status_code == 200
    body = response.json()
    result = body["artifact_results"][0]

    assert body["overall_status"] == "PENDING_REVIEW"
    assert body["overall_decision"] == "REVIEW_REQUIRED"
    assert body["approved_artifact_ids"] == []
    assert body["blocked_artifact_ids"] == []
    assert body["pending_artifact_ids"] == [result["artifact"]["artifact_id"]]
    assert result["status"] == "PENDING_REVIEW"
    assert result["details"]["path_b"]["reason_code"] == "PICKLE_PATH_B_LOAD_OK"
    assert result["details"]["pickle_role"] == "DEPLOYABLE_WEIGHT"
    assert result["details"]["release_eligible"] is False
    assert result["details"]["release_target"] is None


def test_path_b_unavailable_evidence_requires_review_without_raw_release(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
):
    monkeypatch.setattr(pipeline_mod, "scan_with_yara", _scanner_pass)
    monkeypatch.setattr(pipeline_mod, "scan_with_modelscan", _scanner_pass)

    path = tmp_path / "pytorch_model.bin"
    torch.save(
        {"linear.weight": torch.ones((2, 2), dtype=torch.float32)},
        path,
    )

    def fake_run_in_docker(**kwargs):
        return {
            "status": "BLOCK",
            "reason_code": "PICKLE_PATH_B_NOT_AVAILABLE",
            "reason": "Path B is not available in this environment",
        }

    monkeypatch.setattr(pipeline_mod, "run_in_docker", fake_run_in_docker)

    response = client.post(
        "/internal/v1/validation/jobs",
        json=_payload_with_real_hash(
            path,
            "PICKLE",
            ".bin",
            "test-path-b-unavailable-review",
            enable_path_b=True,
        ),
    )

    assert response.status_code == 200
    body = response.json()
    result = body["artifact_results"][0]

    assert body["overall_status"] == "PENDING_REVIEW"
    assert body["overall_decision"] == "REVIEW_REQUIRED"
    assert body["approved_artifact_ids"] == []
    assert body["blocked_artifact_ids"] == []
    assert body["pending_artifact_ids"] == [result["artifact"]["artifact_id"]]
    assert result["status"] == "PENDING_REVIEW"
    assert result["details"]["stage"] == "PATH_B"
    assert result["details"]["path_b"]["reason_code"] == "PICKLE_PATH_B_NOT_AVAILABLE"
    assert result["details"]["release_eligible"] is False
    assert result["details"]["release_target"] is None


def test_actual_torch_state_dict_pickle_is_explicitly_blocked_by_path_a(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
):
    monkeypatch.setattr(pipeline_mod, "scan_with_yara", _scanner_pass)
    monkeypatch.setattr(pipeline_mod, "scan_with_modelscan", _scanner_pass)

    path = tmp_path / "pytorch_model.bin"

    torch.save(
        {"linear.weight": torch.ones((2, 2), dtype=torch.float32)},
        path,
    )

    result = validate(
        str(path),
        policy_fingerprint="test-real-torch-state-dict",
        file_kind="PICKLE",
    )

    assert result["status"] == "BLOCK"
    assert result["stage"] == "PATH_A"
    assert result["path_a"]["reason_code"] in {
        "PICKLE_OPCODE_BLOCKED",
        "UNSUPPORTED_PICKLE_FORMAT",
        "PICKLE_PARSE_ERROR",
    }


def test_path_a_failure_denies_release(tmp_path: Path):
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
            "test-path-a-fail-deny",
        ),
    )

    assert response.status_code == 200
    body = response.json()

    assert body["overall_status"] == "BLOCK"
    assert body["release_action"] == "DENY"
    assert body["approved_artifact_ids"] == []
    assert body["blocked_artifact_ids"] != []


def test_malicious_pickle_opcode_still_blocks_with_role_detail(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
):
    monkeypatch.setattr(pipeline_mod, "scan_with_yara", _scanner_pass)
    monkeypatch.setattr(pipeline_mod, "scan_with_modelscan", _scanner_pass)

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
            "test-malicious-role-detail",
        ),
    )

    assert response.status_code == 200
    body = response.json()
    result = body["artifact_results"][0]

    assert body["overall_status"] == "BLOCK"
    assert body["overall_decision"] == "DENY"
    assert body["approved_artifact_ids"] == []
    assert body["pending_artifact_ids"] == []
    assert body["blocked_artifact_ids"] == [result["artifact"]["artifact_id"]]
    assert result["status"] == "BLOCK"
    assert result["reason_entries"][0]["code"] == "PICKLE_OPCODE_BLOCKED"
    assert result["details"]["pickle_role"] == "GENERIC_PICKLE"
    assert result["details"]["release_eligible"] is False
    assert result["details"]["release_target"] is None


def test_malicious_auxiliary_training_pickle_still_blocks(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
):
    monkeypatch.setattr(pipeline_mod, "scan_with_yara", _scanner_pass)
    monkeypatch.setattr(pipeline_mod, "scan_with_modelscan", _scanner_pass)

    class Exploit:
        def __reduce__(self):
            import os

            return (os.system, ("echo hacked",))

    path = tmp_path / "training_args.bin"
    with open(path, "wb") as f:
        pickle.dump(Exploit(), f, protocol=4)

    response = client.post(
        "/internal/v1/validation/jobs",
        json=_payload_with_real_hash(
            path,
            "PICKLE",
            ".bin",
            "test-malicious-auxiliary-training",
        ),
    )

    assert response.status_code == 200
    body = response.json()
    result = body["artifact_results"][0]

    assert body["overall_status"] == "BLOCK"
    assert body["overall_decision"] == "DENY"
    assert body["approved_artifact_ids"] == []
    assert body["pending_artifact_ids"] == []
    assert body["blocked_artifact_ids"] == [result["artifact"]["artifact_id"]]
    assert result["status"] == "BLOCK"
    assert result["reason_entries"][0]["code"] == "PICKLE_OPCODE_BLOCKED"
    assert result["details"]["pickle_role"] == "AUXILIARY_TRAINING"
    assert result["details"]["release_eligible"] is False
    assert result["details"]["release_target"] is None


def test_malicious_opcode_block_skips_path_b_evidence(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
):
    monkeypatch.setattr(pipeline_mod, "scan_with_yara", _scanner_pass)
    monkeypatch.setattr(pipeline_mod, "scan_with_modelscan", _scanner_pass)

    class Exploit:
        def __reduce__(self):
            import os

            return (os.system, ("echo hacked",))

    path = tmp_path / "malicious.pkl"
    with open(path, "wb") as f:
        pickle.dump(Exploit(), f, protocol=4)

    calls = []

    def fake_run_in_docker(**kwargs):
        calls.append(kwargs)
        return {
            "status": "PASS",
            "reason_code": "PICKLE_PATH_B_LOAD_OK",
            "reason": "should not be called for malicious opcode",
        }

    monkeypatch.setattr(pipeline_mod, "run_in_docker", fake_run_in_docker)

    result = validate(
        str(path),
        policy_fingerprint="test-malicious-skips-path-b",
        file_kind="PICKLE",
        enable_path_b=True,
        repo_path="malicious.pkl",
    )

    assert calls == []
    assert result["status"] == "BLOCK"
    assert result["stage"] == "PATH_A"
    assert result["path_a"]["reason_code"] == "PICKLE_OPCODE_BLOCKED"
    assert "path_b" not in result
    assert result["pickle_role"] == "GENERIC_PICKLE"


def test_path_b_block_blocks_pipeline(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
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

    def fake_run_in_docker(*args, **kwargs):
        return {
            "status": "BLOCK",
            "reason_code": "PICKLE_PATH_B_BLOCKED",
            "reason": "sandbox execution failed or detected unsafe behavior",
        }

    monkeypatch.setattr(pipeline_mod, "run_in_docker", fake_run_in_docker)

    result = validate(
        str(path),
        policy_fingerprint="test-path-b-block",
        file_kind="PICKLE",
        enable_path_b=True,
    )

    assert result["status"] == "BLOCK"
    assert result["stage"] == "PATH_B"
    assert result["reason_code"] == "PICKLE_PATH_B_BLOCKED"


def test_load_and_extract_does_not_use_unsafe_pickle_loading():
    source = Path(load_and_extract.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)

    saw_weights_only_true = False

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name != "pickle"

        if isinstance(node, ast.ImportFrom):
            assert node.module != "pickle"

        if not isinstance(node, ast.Call):
            continue

        if isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                module_name = node.func.value.id
            else:
                module_name = ""

            if module_name == "pickle" and node.func.attr == "load":
                pytest.fail("pickle.load must not be used in sandbox loader")

            if module_name == "torch" and node.func.attr == "load":
                for keyword in node.keywords:
                    if keyword.arg != "weights_only":
                        continue

                    if isinstance(keyword.value, ast.Constant):
                        assert keyword.value.value is not False

                        if keyword.value.value is True:
                            saw_weights_only_true = True

    assert saw_weights_only_true


def test_docker_runner_defaults_to_runsc_and_rejects_unprefixed_json(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
):
    model_path = tmp_path / "model.pkl"
    model_path.write_bytes(b"dummy")

    captured = {}

    def fake_run(cmd, capture_output, text, timeout):
        captured["cmd"] = cmd

        return SimpleNamespace(
            returncode=0,
            stdout=json.dumps(
                {
                    "status": "PASS",
                    "reason_code": "FAKE_PASS",
                    "tensors": {},
                }
            ),
            stderr="",
        )

    monkeypatch.setattr(docker_runner.subprocess, "run", fake_run)

    result = docker_runner.run_in_docker(
        file_path=str(model_path),
        image_name="weight-sandbox-test",
    )

    cmd = captured["cmd"]
    runtime_index = cmd.index("--runtime")

    assert cmd[runtime_index + 1] == "runsc"
    assert result["status"] == "BLOCK"
    assert result["reason_code"] == "PICKLE_PATH_B_EXECUTION_FAILED"
    assert "INVALID_SANDBOX_JSON" in result["reason"]


def test_docker_runner_accepts_only_nonce_prefixed_result(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
):
    model_path = tmp_path / "model.pkl"
    model_path.write_bytes(b"dummy")

    def fake_run(cmd, capture_output, text, timeout):
        env_index = cmd.index("-e")
        env_value = cmd[env_index + 1]
        nonce = env_value.split("=", 1)[1]

        payload = {
            "status": "PASS",
            "reason_code": "PICKLE_PATH_B_LOAD_OK",
            "reason": "ok",
            "tensors": {},
        }

        return SimpleNamespace(
            returncode=0,
            stdout=(
                "attacker noise\n"
                f"{docker_runner.RESULT_PREFIX}:{nonce}:{json.dumps(payload)}\n"
            ),
            stderr="",
        )

    monkeypatch.setattr(docker_runner.subprocess, "run", fake_run)

    result = docker_runner.run_in_docker(
        file_path=str(model_path),
        image_name="weight-sandbox-test",
    )

    assert result["status"] == "PASS"
    assert result["reason_code"] == "PICKLE_PATH_B_LOAD_OK"
    assert result["runtime"] == "runsc"


def test_yara_rule_path_is_absolute_and_points_to_assets():
    assert yara_scanner.RULE_PATH.is_absolute()
    assert yara_scanner.RULE_PATH.name == "malicious_pickle.yar"
    assert "analyzer" in yara_scanner.RULE_PATH.parts
    assert "assets" in yara_scanner.RULE_PATH.parts


def test_yara_rule_uses_hex_opcode_patterns_not_plain_opcode_words():
    content = yara_scanner.RULE_PATH.read_text(encoding="utf-8")

    assert '"REDUCE"' not in content
    assert '"GLOBAL"' not in content
    assert '"STACK_GLOBAL"' not in content

    assert "{ 52 }" in content
    assert "{ 63 }" in content
    assert "{ 93 }" in content


def test_make_tensor_entry_handles_bfloat16():
    tensor = torch.ones((2, 2), dtype=torch.bfloat16)

    entry = make_tensor_entry(tensor)

    assert entry["shape"] == [2, 2]
    assert entry["dtype"] == "torch.bfloat16"
    assert isinstance(entry["hash"], str)
    assert len(entry["hash"]) == 64


def test_weight_cache_rejects_tampered_entry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    cache_file = tmp_path / "weight_cache.json"
    monkeypatch.setattr(cache_mod, "CACHE_FILE", cache_file)
    monkeypatch.setenv("WEIGHT_CACHE_HMAC_KEY", "test-cache-secret")

    cache_mod.set_cache(
        "cache-key-1",
        {
            "status": "BLOCK",
            "reason": "original",
        },
    )

    assert cache_mod.get_cache("cache-key-1") == {
        "status": "BLOCK",
        "reason": "original",
    }

    data = json.loads(cache_file.read_text(encoding="utf-8"))
    data["entries"]["cache-key-1"]["result"]["status"] = "PASS"
    data["entries"]["cache-key-1"]["result"]["reason"] = "tampered"
    cache_file.write_text(json.dumps(data), encoding="utf-8")

    assert cache_mod.get_cache("cache-key-1") is None


def test_weight_cache_file_path_is_absolute():
    assert cache_mod.CACHE_FILE.is_absolute()


def test_dtype_map_is_shared_for_weight_modules():
    assert DTYPE_MAP["float32"] is torch.float32
    assert DTYPE_MAP["torch.bfloat16"] is torch.bfloat16


def test_cli_requires_policy_fingerprint(tmp_path: Path):
    path = tmp_path / "model.pkl"
    path.write_bytes(b"dummy")

    with pytest.raises(SystemExit) as exc:
        weight_cli.main([str(path)])

    assert exc.value.code == 2


def test_modelscan_wrapper_normalizes_issue_shapes(monkeypatch: pytest.MonkeyPatch):
    class FakeScanner:
        def scan(self, path: str):
            return {
                "issues": [
                    {
                        "severity": "HIGH",
                        "category": "pickle",
                        "message": "dangerous pickle content",
                    }
                ]
            }

    class FakeModelScanModule:
        ModelScan = FakeScanner

    import_calls = []

    def fake_import_module(name: str):
        import_calls.append(name)
        assert name == "modelscan.modelscan"
        return FakeModelScanModule

    monkeypatch.setattr(modelscan_wrapper, "import_module", fake_import_module)

    result = modelscan_wrapper.scan_with_modelscan("dummy.pkl")

    assert import_calls == ["modelscan.modelscan"]
    assert result["status"] == "BLOCK"
    assert result["reason_code"] == "PICKLE_MODELSCAN_BLOCKED"
    assert result["severities"] == ["HIGH"]
    assert result["issues"][0]["category"] == "pickle"


def test_modelscan_wrapper_falls_back_to_legacy_top_level_import(
    monkeypatch: pytest.MonkeyPatch,
):
    class FakeScanner:
        def scan(self, path: str):
            return {"issues": []}

    class FakeModelScanModule:
        ModelScan = FakeScanner

    import_calls = []

    def fake_import_module(name: str):
        import_calls.append(name)
        if name == "modelscan.modelscan":
            raise ImportError("no submodule")
        if name == "modelscan":
            return FakeModelScanModule

        raise AssertionError(f"unexpected module import: {name}")

    monkeypatch.setattr(modelscan_wrapper, "import_module", fake_import_module)

    result = modelscan_wrapper.scan_with_modelscan("dummy.pkl")

    assert import_calls == ["modelscan.modelscan", "modelscan"]
    assert result["status"] == "PASS"
    assert result["reason_code"] == "MODELSCAN_NO_ISSUE"
