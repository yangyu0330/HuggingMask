import hashlib
import json
import os
from pathlib import Path, PurePosixPath

import pytest

from analyzer.schemas import ArtifactRef, ArtifactValidationResult, FileKind, PolicyInfo
from analyzer.snapshot_resolver import SnapshotSourceResolver
from analyzer.validators.code_validator import validate_python_artifact
from sandbox.b2.repo_manifest import (
    B2ManifestError,
    build_b2_input_manifest,
    compute_manifest_sha256,
    prepare_job_input_dir,
    verify_manifest_files,
)
from sandbox.b2.schemas import B2_INPUT_MANIFEST_FILENAME, B2ManifestFile


def _make_policy() -> PolicyInfo:
    return PolicyInfo(
        policy_version="policy-2026.05.20",
        whitelist_version="wl-2026.05.20",
        opcode_policy_version="opcode-2026.05.20",
        config_schema_version="cfg-2026.05.20",
        runtime_profile_version="rt-2026.05.20",
    )


def _write(root: Path, repo_path: str, source: str | bytes) -> str:
    data = source.encode("utf-8") if isinstance(source, str) else source
    path = root.joinpath(*PurePosixPath(repo_path).parts)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return hashlib.sha256(data).hexdigest()


def _artifact(repo_path: str, source: str | bytes, file_kind: FileKind = FileKind.PYTHON) -> ArtifactRef:
    data = source.encode("utf-8") if isinstance(source, str) else source
    digest = hashlib.sha256(data).hexdigest()
    file_name = PurePosixPath(repo_path).name
    return ArtifactRef(
        artifact_id=f"sha256:{digest}",
        repo_path=repo_path,
        file_name=file_name,
        file_kind=file_kind,
        detected_extension=PurePosixPath(repo_path).suffix,
        media_type=None,
        size_bytes=len(data),
        sha256=digest,
        source_url=f"https://huggingface.co/org/demo/resolve/main/{repo_path}",
        temp_local_path=f"/tmp/{file_name}",
        referenced_by=[],
        is_generated=False,
    )


def _validate(repo_path: str, source: str, *, ast_call_metadata: list[dict] | None = None) -> ArtifactValidationResult:
    return validate_python_artifact(
        _artifact(repo_path, source),
        source,
        _make_policy(),
        runtime_check={"status": "SKIPPED", "runtime_mode": "RESTRICTED_RUNTIME"},
        ast_call_metadata=ast_call_metadata,
    )


def _primary_source(import_line: str = "") -> str:
    return (
        f"{import_line}"
        "import torch\n"
        "class DemoModel:\n"
        "    def forward(self, x):\n"
        "        return torch.special.expit(x)\n"
    )


def _build_manifest(
    root: Path,
    primary_source: str,
    candidate_results: list[ArtifactValidationResult] | None = None,
):
    resolver = SnapshotSourceResolver(model_snapshot_root=root)
    primary_result = _validate("modeling_demo.py", primary_source)
    return build_b2_input_manifest(
        request_id="req-b2",
        job_id="job-b2",
        source_resolver=resolver,
        revision="abc123",
        policy_version=_make_policy().policy_version,
        primary_result=primary_result,
        candidate_results=candidate_results or [],
    )


def test_primary_b2_artifact_manifest_includes_support_json(tmp_path: Path) -> None:
    root = tmp_path / "snapshot"
    primary = _primary_source()
    _write(root, "modeling_demo.py", primary)
    _write(root, "config.json", b'{"model_type":"demo"}\n')

    manifest = _build_manifest(root, primary)

    files = {item.path: item for item in manifest.files}
    assert manifest.primary_repo_path == "modeling_demo.py"
    assert manifest.grade == "B-2"
    assert manifest.target.source == "direct_python"
    assert manifest.target.target_module == "modeling_demo"
    assert files["modeling_demo.py"].target_allowed is True
    assert files["modeling_demo.py"].import_allowed is True
    assert files["modeling_demo.py"].is_primary is True
    assert files["config.json"].content_kind == "JSON_SUPPORT"
    assert files["config.json"].role == "SUPPORT"
    assert len(manifest.manifest_sha256) == 64
    assert verify_manifest_files(manifest, SnapshotSourceResolver(model_snapshot_root=root)) == []


def test_local_import_closure_includes_package_init_and_helper(tmp_path: Path) -> None:
    root = tmp_path / "snapshot"
    primary = _primary_source("from layers import helper\n")
    init_source = "from .helper import helper\n"
    helper_source = "def helper(x):\n    return x\n"
    _write(root, "modeling_demo.py", primary)
    _write(root, "layers/__init__.py", init_source)
    _write(root, "layers/helper.py", helper_source)

    manifest = _build_manifest(
        root,
        primary,
        candidate_results=[
            _validate("layers/helper.py", helper_source),
            _validate("layers/__init__.py", init_source),
        ],
    )

    files = {item.path: item for item in manifest.files}
    assert set(files) == {"layers/__init__.py", "layers/helper.py", "modeling_demo.py"}
    assert files["layers/__init__.py"].import_allowed is True
    assert files["layers/__init__.py"].target_allowed is False
    assert files["layers/helper.py"].import_allowed is True
    assert files["layers/helper.py"].target_allowed is False


def test_symlink_escape_fails_manifest_build(tmp_path: Path) -> None:
    root = tmp_path / "snapshot"
    outside_source = _primary_source()
    outside = tmp_path / "outside_modeling.py"
    outside.write_text(outside_source, encoding="utf-8")
    root.mkdir()
    link = root / "modeling_demo.py"
    try:
        os.symlink(outside, link)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")

    primary_result = _validate("modeling_demo.py", outside_source)
    with pytest.raises(B2ManifestError) as exc_info:
        build_b2_input_manifest(
            request_id="req-b2",
            job_id="job-b2",
            source_resolver=SnapshotSourceResolver(model_snapshot_root=root),
            revision="abc123",
            policy_version=_make_policy().policy_version,
            primary_result=primary_result,
            candidate_results=[],
        )

    assert exc_info.value.reason_code == "PATH_ESCAPE"


def test_inventory_hash_mismatch_fails_manifest_build(tmp_path: Path) -> None:
    trusted = tmp_path / "trusted"
    source = _primary_source()
    path = trusted / "modeling_demo.py"
    path.parent.mkdir(parents=True)
    path.write_bytes(source.encode("utf-8"))
    resolver = SnapshotSourceResolver(
        model_snapshot_inventory=[
            {
                "repo_path": "modeling_demo.py",
                "temp_local_path": str(path),
                "sha256": "0" * 64,
                "size_bytes": len(source.encode("utf-8")),
                "file_kind": "PYTHON",
            }
        ],
        trusted_temp_bases=[trusted],
    )

    with pytest.raises(B2ManifestError) as exc_info:
        build_b2_input_manifest(
            request_id="req-b2",
            job_id="job-b2",
            source_resolver=resolver,
            revision="abc123",
            policy_version=_make_policy().policy_version,
            primary_result=_validate("modeling_demo.py", source),
            candidate_results=[],
        )

    assert exc_info.value.reason_code == "HASH_MISMATCH"


def test_unresolved_dependency_fails_closed(tmp_path: Path) -> None:
    root = tmp_path / "snapshot"
    primary = _primary_source("import missing_local\n")
    _write(root, "modeling_demo.py", primary)

    with pytest.raises(B2ManifestError) as exc_info:
        _build_manifest(root, primary)

    assert exc_info.value.reason_code == "UNRESOLVED_DEPENDENCY"
    assert exc_info.value.dependency == "missing_local"


def test_dependency_without_validation_result_fails_closed(tmp_path: Path) -> None:
    root = tmp_path / "snapshot"
    primary = _primary_source("import helper\n")
    helper_source = "def helper(x):\n    return x\n"
    _write(root, "modeling_demo.py", primary)
    _write(root, "helper.py", helper_source)

    with pytest.raises(B2ManifestError) as exc_info:
        _build_manifest(root, primary)

    assert exc_info.value.reason_code == "DEPENDENCY_NOT_VALIDATED"
    assert exc_info.value.dependency == "helper.py"


@pytest.mark.parametrize(
    ("helper_source", "metadata"),
    [
        ("import subprocess\n", None),
        ("def helper(module, name):\n    return getattr(module, name)\n", None),
        (
            "def helper(user_path):\n    return open(user_path, 'w')\n",
            [
                {
                    "api": "open",
                    "args": [
                        {"kind": "name", "value": "user_path", "source": "user_input", "is_user_input": True},
                        {"kind": "constant_str", "value": "w"},
                    ],
                }
            ],
        ),
    ],
)
def test_dependency_static_risk_fails_manifest_build(
    tmp_path: Path,
    helper_source: str,
    metadata: list[dict] | None,
) -> None:
    root = tmp_path / "snapshot"
    primary = _primary_source("import helper\n")
    _write(root, "modeling_demo.py", primary)
    _write(root, "helper.py", helper_source)

    with pytest.raises(B2ManifestError) as exc_info:
        _build_manifest(
            root,
            primary,
            candidate_results=[_validate("helper.py", helper_source, ast_call_metadata=metadata)],
        )

    assert exc_info.value.reason_code == "DEPENDENCY_STATIC_RISK"


def test_manifest_hash_is_stable_sorted_and_excludes_hash_field(tmp_path: Path) -> None:
    root = tmp_path / "snapshot"
    primary = _primary_source("from layers import helper\n")
    init_source = "from .helper import helper\n"
    helper_source = "def helper(x):\n    return x\n"
    _write(root, "modeling_demo.py", primary)
    _write(root, "layers/__init__.py", init_source)
    _write(root, "layers/helper.py", helper_source)

    results = [_validate("layers/helper.py", helper_source), _validate("layers/__init__.py", init_source)]
    manifest_a = _build_manifest(root, primary, candidate_results=results)
    manifest_b = _build_manifest(root, primary, candidate_results=list(reversed(results)))

    assert [item.path for item in manifest_a.files] == sorted(item.path for item in manifest_a.files)
    assert manifest_a.manifest_sha256 == manifest_b.manifest_sha256
    original_hash = compute_manifest_sha256(manifest_a)
    manifest_a.manifest_sha256 = "f" * 64
    assert compute_manifest_sha256(manifest_a) == original_hash


def test_staging_directory_copies_only_verified_manifest_files(tmp_path: Path) -> None:
    root = tmp_path / "snapshot"
    primary = _primary_source("import helper\n")
    helper_source = "def helper(x):\n    return x\n"
    _write(root, "modeling_demo.py", primary)
    _write(root, "helper.py", helper_source)
    _write(root, "secret.py", "SHOULD_NOT_BE_STAGED = True\n")
    _write(root, "config.json", b'{"model_type":"demo"}\n')
    resolver = SnapshotSourceResolver(model_snapshot_root=root)
    manifest = _build_manifest(root, primary, candidate_results=[_validate("helper.py", helper_source)])

    input_dir = prepare_job_input_dir(source_resolver=resolver, manifest=manifest, output_dir=tmp_path / "out")

    staged_files = sorted(
        path.relative_to(input_dir).as_posix()
        for path in input_dir.rglob("*")
        if path.is_file()
    )
    assert staged_files == sorted(["modeling_demo.py", "helper.py", "config.json", B2_INPUT_MANIFEST_FILENAME])
    assert (input_dir / "secret.py").exists() is False
    payload = json.loads((input_dir / B2_INPUT_MANIFEST_FILENAME).read_text(encoding="utf-8"))
    assert payload["manifest_sha256"] == manifest.manifest_sha256


def test_staging_blocks_duplicate_path_hash_mismatch(tmp_path: Path) -> None:
    root = tmp_path / "snapshot"
    primary = _primary_source()
    _write(root, "modeling_demo.py", primary)
    resolver = SnapshotSourceResolver(model_snapshot_root=root)
    manifest = _build_manifest(root, primary)
    original = manifest.files[0]
    manifest.files.append(
        B2ManifestFile(
            path=original.path,
            sha256="0" * 64,
            size_bytes=original.size_bytes,
            role=original.role,
            ast_grade=original.ast_grade,
            content_kind=original.content_kind,
        )
    )

    with pytest.raises(B2ManifestError) as exc_info:
        prepare_job_input_dir(source_resolver=resolver, manifest=manifest, output_dir=tmp_path / "out")

    assert exc_info.value.reason_code == "HASH_MISMATCH"


def test_staging_refuses_symlinked_input_dir(tmp_path: Path) -> None:
    root = tmp_path / "snapshot"
    primary = _primary_source()
    _write(root, "modeling_demo.py", primary)
    resolver = SnapshotSourceResolver(model_snapshot_root=root)
    manifest = _build_manifest(root, primary)
    output_dir = tmp_path / "out"
    outside = tmp_path / "outside"
    output_dir.mkdir()
    outside.mkdir()
    (outside / "keep.txt").write_text("keep", encoding="utf-8")
    try:
        os.symlink(outside, output_dir / "input", target_is_directory=True)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")

    with pytest.raises(B2ManifestError) as exc_info:
        prepare_job_input_dir(source_resolver=resolver, manifest=manifest, output_dir=output_dir)

    assert exc_info.value.reason_code == "PATH_ESCAPE"
    assert (outside / "keep.txt").read_text(encoding="utf-8") == "keep"
