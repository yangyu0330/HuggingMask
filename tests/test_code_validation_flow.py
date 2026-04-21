import hashlib
import json
from pathlib import Path, PurePosixPath
from typing import Any

import pytest

from analyzer.schemas import ArtifactRef, FileKind, PolicyInfo, ValidationStatus
from analyzer.validators.code_validator import validate_python_artifact
from analyzer.validators.config_validator import validate_config_artifact


FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "code_validation"


def _make_policy() -> PolicyInfo:
    return PolicyInfo(
        policy_version="policy-2026.04.20",
        whitelist_version="wl-2026.04.20",
        opcode_policy_version="opcode-2026.04.20",
        config_schema_version="cfg-2026.04.20",
        runtime_profile_version="rt-2026.04.20",
    )


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _read_json(path: Path) -> Any:
    return json.loads(_read_text(path))


def _build_artifact(repo_path: str, file_kind: FileKind, source_text: str) -> ArtifactRef:
    digest = hashlib.sha256(f"{repo_path}:{source_text}".encode("utf-8")).hexdigest()
    file_name = PurePosixPath(repo_path).name
    ext = PurePosixPath(repo_path).suffix or (".json" if file_kind in {FileKind.CONFIG_JSON, FileKind.TOKENIZER_CONFIG_JSON} else ".py")
    media_type = "application/json" if file_kind in {FileKind.CONFIG_JSON, FileKind.TOKENIZER_CONFIG_JSON} else None
    return ArtifactRef(
        artifact_id=f"sha256:{digest}",
        repo_path=repo_path,
        file_name=file_name,
        file_kind=file_kind,
        detected_extension=ext,
        media_type=media_type,
        size_bytes=len(source_text.encode("utf-8")),
        sha256=digest,
        source_url=f"https://huggingface.co/org/demo/resolve/main/{repo_path}",
        temp_local_path=f"/tmp/{file_name}",
        referenced_by=[],
        is_generated=False,
    )


def _build_source_loader(case_dir: Path, files: list[str] | None) -> dict[str, str] | None:
    if files is None:
        return None
    return {name: _read_text(case_dir / name) for name in files}


def _run_case(manifest_path: Path):
    case_dir = manifest_path.parent
    manifest = _read_json(manifest_path)
    artifact_spec = manifest["artifact"]
    file_kind = FileKind(artifact_spec["file_kind"])
    repo_path = artifact_spec["repo_path"]
    source_text = _read_text(case_dir / manifest["source_file"])
    artifact = _build_artifact(repo_path, file_kind, source_text)

    if manifest["validator"] == "code":
        runtime_check = None
        if manifest.get("runtime_check_file"):
            runtime_check = _read_json(case_dir / manifest["runtime_check_file"])
        ast_call_metadata = None
        if manifest.get("ast_call_metadata_file"):
            ast_call_metadata = _read_json(case_dir / manifest["ast_call_metadata_file"])
        result = validate_python_artifact(
            artifact=artifact,
            source=source_text,
            policy=_make_policy(),
            runtime_check=runtime_check,
            ast_call_metadata=ast_call_metadata,
        )
        return manifest, result

    if manifest["validator"] == "config":
        source_loader = _build_source_loader(case_dir, manifest.get("source_loader_files"))
        runtime_check_loader = None
        if manifest.get("runtime_check_loader_file"):
            runtime_check_loader = _read_json(case_dir / manifest["runtime_check_loader_file"])
        result = validate_config_artifact(
            artifact=artifact,
            source=source_text,
            policy=_make_policy(),
            source_loader=source_loader,
            runtime_check_loader=runtime_check_loader,
        )
        return manifest, result

    raise AssertionError(f"Unsupported validator type: {manifest['validator']}")


def _assert_expected(manifest: dict[str, Any], result) -> None:
    expected = manifest["expected"]

    if "status" in expected:
        assert result.status.value == expected["status"]
    if "grade" in expected:
        assert result.grade.value == expected["grade"]
    if "review_action" in expected:
        assert result.review_action.value == expected["review_action"]
    if "route_kind" in expected:
        assert result.route_kind.value == expected["route_kind"]

    if expected.get("not_pass"):
        assert result.status is not ValidationStatus.PASS
    if "allowed_statuses" in expected:
        assert result.status.value in expected["allowed_statuses"]

    if "pending_api_refs_contains" in expected:
        pending_api_refs = result.details.get("pending_api_refs", [])
        for api in expected["pending_api_refs_contains"]:
            assert api in pending_api_refs

    if "context_summary_decision" in expected:
        assert result.details["context_api_scan"]["summary_decision"] == expected["context_summary_decision"]

    if "effective_status" in expected:
        assert result.details["effective_status"] == expected["effective_status"]
    if "trigger_fields_contains" in expected:
        trigger_fields = result.details.get("trigger_fields", [])
        for field_name in expected["trigger_fields_contains"]:
            assert field_name in trigger_fields
    if "referenced_files_contains" in expected:
        referenced = result.details["config_scan"]["referenced_python_files"]
        for file_name in expected["referenced_files_contains"]:
            assert file_name in referenced
    if "linked_code_statuses_contains" in expected:
        statuses = result.details.get("linked_code_statuses", [])
        for status in expected["linked_code_statuses_contains"]:
            assert status in statuses


@pytest.mark.parametrize(
    "manifest_path",
    sorted(FIXTURE_ROOT.glob("*/fixture_manifest.json")),
    ids=lambda path: path.parent.name,
)
def test_code_validation_flow_regression_from_fixtures(manifest_path: Path) -> None:
    manifest, result = _run_case(manifest_path)
    _assert_expected(manifest, result)
