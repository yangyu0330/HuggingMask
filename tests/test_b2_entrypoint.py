from __future__ import annotations

import json
import sys
from pathlib import Path, PurePosixPath

from sandbox.b2 import entrypoint


def _write(input_root: Path, repo_path: str, source: str) -> dict:
    data = source.encode("utf-8")
    path = input_root.joinpath(*PurePosixPath(repo_path).parts)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return {
        "path": repo_path,
        "sha256": __import__("hashlib").sha256(data).hexdigest(),
        "size_bytes": len(data),
        "role": "MODELING",
        "ast_grade": "B-2",
        "content_kind": "PYTHON",
        "import_allowed": True,
        "target_allowed": True,
        "is_primary": True,
        "validation_status": "PENDING_REVIEW",
        "unknown_apis": [],
        "risk_flags": [],
    }


def _write_manifest(
    input_root: Path,
    *,
    module_name: str,
    target_class: str | None,
    file_entries: list[dict],
    request_id: str = "req-entrypoint",
) -> Path:
    payload = {
        "schema_version": "1.0",
        "request_id": request_id,
        "job_id": "job-entrypoint",
        "primary_artifact_id": "sha256:" + "1" * 64,
        "primary_repo_path": file_entries[0]["path"],
        "revision": "rev-entrypoint",
        "policy_version": "policy-2026.05.20",
        "grade": "B-2",
        "target": {
            "source": "direct_python",
            "target_module": module_name,
            "target_class": target_class,
            "auto_map_key": None,
            "primary_repo_path": file_entries[0]["path"],
            "import_root": "/sandbox/input",
        },
        "manifest_sha256": "",
        "files": file_entries,
    }
    payload["manifest_sha256"] = entrypoint.compute_manifest_sha256(payload)
    manifest_path = input_root / "b2_input_manifest.json"
    manifest_path.write_text(json.dumps(payload, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    return manifest_path


def _run(manifest_path: Path, output_path: Path, *, expected_sha256: str | None = None) -> dict:
    argv = [
        "--manifest",
        str(manifest_path),
        "--nonce",
        "nonce-entrypoint",
        "--output",
        str(output_path),
        "--request-id",
        "req-entrypoint",
    ]
    if expected_sha256 is not None:
        argv.extend(["--manifest-sha256", expected_sha256])
    assert entrypoint.main(argv) == 0
    return json.loads(output_path.read_text(encoding="utf-8"))


def test_valid_manifest_imports_and_instantiates_target_class(tmp_path: Path) -> None:
    input_root = tmp_path / "input"
    module_name = "phase10_safe_model"
    file_entry = _write(
        input_root,
        f"{module_name}.py",
        "class SafeModel:\n"
        "    def __init__(self):\n"
        "        self.ready = True\n",
    )
    manifest_path = _write_manifest(
        input_root,
        module_name=module_name,
        target_class="SafeModel",
        file_entries=[file_entry],
    )

    result = _run(manifest_path, tmp_path / "runner_result.json")

    assert result["schema_version"] == "1.0"
    assert result["request_id"] == "req-entrypoint"
    assert result["nonce"] == "nonce-entrypoint"
    assert result["manifest_verified"] is True
    assert result["import_status"] == "success"
    assert result["instantiate_status"] == "success"
    assert result["forward_status"] == "skipped_schema_unknown"
    assert result["exception_class"] is None
    assert result["exception_message"] is None


def test_manifest_hash_mismatch_skips_import_and_preserves_result(tmp_path: Path) -> None:
    input_root = tmp_path / "input"
    marker = tmp_path / "imported.txt"
    module_name = "phase10_manifest_mismatch"
    file_entry = _write(
        input_root,
        f"{module_name}.py",
        f"from pathlib import Path\nPath({str(marker)!r}).write_text('imported')\nclass SafeModel:\n    pass\n",
    )
    manifest_path = _write_manifest(
        input_root,
        module_name=module_name,
        target_class="SafeModel",
        file_entries=[file_entry],
    )
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    payload["manifest_sha256"] = "0" * 64
    manifest_path.write_text(json.dumps(payload, sort_keys=True, separators=(",", ":")), encoding="utf-8")

    result = _run(manifest_path, tmp_path / "runner_result.json")

    assert result["manifest_verified"] is False
    assert result["import_status"] == "skipped"
    assert result["instantiate_status"] == "skipped"
    assert result["forward_status"] == "skipped"
    assert result["exception_class"] == "ManifestVerificationError"
    assert marker.exists() is False


def test_file_hash_mismatch_skips_import_and_does_not_add_input_to_syspath(tmp_path: Path) -> None:
    input_root = tmp_path / "input"
    marker = tmp_path / "hash_imported.txt"
    module_name = "phase10_file_mismatch"
    file_entry = _write(input_root, f"{module_name}.py", "class SafeModel:\n    pass\n")
    manifest_path = _write_manifest(
        input_root,
        module_name=module_name,
        target_class="SafeModel",
        file_entries=[file_entry],
    )
    input_root.joinpath(f"{module_name}.py").write_text(
        f"from pathlib import Path\nPath({str(marker)!r}).write_text('imported')\nclass SafeModel:\n    pass\n",
        encoding="utf-8",
    )

    before = list(sys.path)
    result = _run(manifest_path, tmp_path / "runner_result.json")

    assert result["manifest_verified"] is False
    assert result["import_status"] == "skipped"
    assert result["exception_class"] == "ManifestVerificationError"
    assert marker.exists() is False
    assert str(input_root.resolve(strict=False)) not in sys.path
    assert sys.path == before


def test_import_failure_is_recorded_after_manifest_verification(tmp_path: Path) -> None:
    input_root = tmp_path / "input"
    module_name = "phase10_import_failure"
    file_entry = _write(input_root, f"{module_name}.py", "import missing_dependency\nclass MissingModel:\n    pass\n")
    manifest_path = _write_manifest(
        input_root,
        module_name=module_name,
        target_class="MissingModel",
        file_entries=[file_entry],
    )

    result = _run(manifest_path, tmp_path / "runner_result.json")

    assert result["manifest_verified"] is True
    assert result["import_status"] == "failed"
    assert result["instantiate_status"] == "skipped"
    assert result["forward_status"] == "skipped"
    assert result["exception_class"] == "ModuleNotFoundError"


def test_unmanifested_input_file_fails_before_import(tmp_path: Path) -> None:
    input_root = tmp_path / "input"
    marker = tmp_path / "unmanifested_imported.txt"
    module_name = "phase10_unmanifested_extra"
    file_entry = _write(
        input_root,
        f"{module_name}.py",
        "import evil_extra\nclass SafeModel:\n    pass\n",
    )
    input_root.joinpath("evil_extra.py").write_text(
        f"from pathlib import Path\nPath({str(marker)!r}).write_text('imported')\n",
        encoding="utf-8",
    )
    manifest_path = _write_manifest(
        input_root,
        module_name=module_name,
        target_class="SafeModel",
        file_entries=[file_entry],
    )

    result = _run(manifest_path, tmp_path / "runner_result.json")

    assert result["manifest_verified"] is False
    assert result["import_status"] == "skipped"
    assert result["exception_class"] == "ManifestVerificationError"
    assert marker.exists() is False


def test_target_module_must_be_target_allowed_python_manifest_file(tmp_path: Path) -> None:
    input_root = tmp_path / "input"
    module_name = "phase10_dependency_not_target"
    file_entry = _write(input_root, f"{module_name}.py", "class SafeModel:\n    pass\n")
    file_entry["target_allowed"] = False
    manifest_path = _write_manifest(
        input_root,
        module_name=module_name,
        target_class="SafeModel",
        file_entries=[file_entry],
    )

    result = _run(manifest_path, tmp_path / "runner_result.json")

    assert result["manifest_verified"] is False
    assert result["import_status"] == "skipped"
    assert result["exception_class"] == "ManifestVerificationError"
    assert "target_allowed" in result["exception_message"]


def test_missing_target_class_does_not_use_filename_or_class_heuristics(tmp_path: Path) -> None:
    input_root = tmp_path / "input"
    marker = tmp_path / "instantiated.txt"
    module_name = "phase10_no_target_class"
    file_entry = _write(
        input_root,
        f"{module_name}.py",
        f"from pathlib import Path\nclass HeuristicModel:\n    def __init__(self):\n        Path({str(marker)!r}).write_text('instantiated')\n",
    )
    manifest_path = _write_manifest(
        input_root,
        module_name=module_name,
        target_class=None,
        file_entries=[file_entry],
    )

    result = _run(manifest_path, tmp_path / "runner_result.json")

    assert result["manifest_verified"] is True
    assert result["import_status"] == "success"
    assert result["instantiate_status"] == "failed"
    assert result["forward_status"] == "skipped"
    assert result["exception_class"] == "TargetClassMissing"
    assert marker.exists() is False


def test_nonexistent_target_class_is_recorded(tmp_path: Path) -> None:
    input_root = tmp_path / "input"
    module_name = "phase10_missing_class"
    file_entry = _write(input_root, f"{module_name}.py", "class ExistingModel:\n    pass\n")
    manifest_path = _write_manifest(
        input_root,
        module_name=module_name,
        target_class="MissingModel",
        file_entries=[file_entry],
    )

    result = _run(manifest_path, tmp_path / "runner_result.json")

    assert result["manifest_verified"] is True
    assert result["import_status"] == "success"
    assert result["instantiate_status"] == "failed"
    assert result["exception_class"] == "AttributeError"
    assert "MissingModel" in result["exception_message"]


def test_instantiate_exception_is_recorded(tmp_path: Path) -> None:
    input_root = tmp_path / "input"
    module_name = "phase10_instantiate_error"
    file_entry = _write(
        input_root,
        f"{module_name}.py",
        "class BrokenModel:\n"
        "    def __init__(self):\n"
        "        raise RuntimeError('boom')\n",
    )
    manifest_path = _write_manifest(
        input_root,
        module_name=module_name,
        target_class="BrokenModel",
        file_entries=[file_entry],
    )

    result = _run(manifest_path, tmp_path / "runner_result.json")

    assert result["manifest_verified"] is True
    assert result["import_status"] == "success"
    assert result["instantiate_status"] == "failed"
    assert result["forward_status"] == "skipped"
    assert result["exception_class"] == "RuntimeError"
    assert result["exception_message"] == "boom"
