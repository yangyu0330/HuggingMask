import hashlib
import os
from pathlib import Path

import pytest

from analyzer.schemas import FileKind, SnapshotFileRef
from analyzer.snapshot_resolver import (
    ResolvedSnapshotFile,
    SnapshotResolveError,
    SnapshotSourceResolver,
    build_source_loader,
)


def _write(path: Path, content: bytes) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return hashlib.sha256(content).hexdigest()


def test_resolves_repo_relative_file_from_snapshot_root(tmp_path: Path) -> None:
    root = tmp_path / "snapshot"
    digest = _write(root / "sub" / "modeling_demo.py", b"class Demo:\n    pass\n")

    resolver = SnapshotSourceResolver(model_snapshot_root=root)
    result = resolver.resolve("sub/modeling_demo.py")

    assert isinstance(result, ResolvedSnapshotFile)
    assert result.repo_path == "sub/modeling_demo.py"
    assert result.local_path == (root / "sub" / "modeling_demo.py").resolve()
    assert result.sha256 == digest
    assert result.size_bytes == len(b"class Demo:\n    pass\n")
    assert result.source_kind == "root"


@pytest.mark.parametrize(
    "repo_path",
    [
        "/abs/modeling.py",
        "C:/abs/modeling.py",
        "sub/../modeling.py",
        "sub\\modeling.py",
        "modeling.py\x00suffix",
        ".",
    ],
)
def test_rejects_non_repo_relative_paths(tmp_path: Path, repo_path: str) -> None:
    resolver = SnapshotSourceResolver(model_snapshot_root=tmp_path / "snapshot")

    assert resolver.resolve(repo_path) is SnapshotResolveError.INVALID_REPO_PATH


def test_resolves_inventory_file_only_under_trusted_base(tmp_path: Path) -> None:
    trusted_base = tmp_path / "trusted-temp"
    source_path = trusted_base / "inputs" / "modeling_demo.py"
    content = b"import torch\n"
    digest = _write(source_path, content)
    ref = SnapshotFileRef(
        repo_path="modeling_demo.py",
        temp_local_path=str(source_path),
        sha256=digest,
        size_bytes=len(content),
        file_kind=FileKind.PYTHON,
    )

    resolver = SnapshotSourceResolver(
        model_snapshot_inventory=[ref],
        trusted_temp_bases=[trusted_base],
    )
    result = resolver.resolve("modeling_demo.py")

    assert isinstance(result, ResolvedSnapshotFile)
    assert result.local_path == source_path.resolve()
    assert result.sha256 == digest
    assert result.size_bytes == len(content)
    assert result.file_kind is FileKind.PYTHON
    assert result.source_kind == "inventory"


def test_rejects_inventory_file_outside_trusted_base(tmp_path: Path) -> None:
    trusted_base = tmp_path / "trusted-temp"
    outside = tmp_path / "outside" / "modeling_demo.py"
    content = b"print('outside')\n"
    digest = _write(outside, content)
    ref = SnapshotFileRef(
        repo_path="modeling_demo.py",
        temp_local_path=str(outside),
        sha256=digest,
        size_bytes=len(content),
        file_kind=FileKind.PYTHON,
    )

    resolver = SnapshotSourceResolver(
        model_snapshot_inventory=[ref],
        trusted_temp_bases=[trusted_base],
    )

    assert resolver.resolve("modeling_demo.py") is SnapshotResolveError.UNTRUSTED_LOCAL_PATH


def test_distinguishes_size_and_hash_mismatch(tmp_path: Path) -> None:
    trusted_base = tmp_path / "trusted-temp"
    source_path = trusted_base / "modeling_demo.py"
    content = b"abc"
    digest = _write(source_path, content)

    size_bad = SnapshotFileRef(
        repo_path="modeling_size_bad.py",
        temp_local_path=str(source_path),
        sha256=digest,
        size_bytes=len(content) + 1,
        file_kind=FileKind.PYTHON,
    )
    hash_bad = SnapshotFileRef(
        repo_path="modeling_hash_bad.py",
        temp_local_path=str(source_path),
        sha256="0" * 64,
        size_bytes=len(content),
        file_kind=FileKind.PYTHON,
    )
    resolver = SnapshotSourceResolver(
        model_snapshot_inventory=[size_bad, hash_bad],
        trusted_temp_bases=[trusted_base],
    )

    assert resolver.resolve("modeling_size_bad.py") is SnapshotResolveError.SIZE_MISMATCH
    assert resolver.resolve("modeling_hash_bad.py") is SnapshotResolveError.HASH_MISMATCH


def test_symlink_escape_is_blocked_for_snapshot_root(tmp_path: Path) -> None:
    root = tmp_path / "snapshot"
    outside = tmp_path / "outside.py"
    _write(outside, b"print('outside')\n")
    root.mkdir()
    link = root / "modeling_link.py"
    try:
        os.symlink(outside, link)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")

    resolver = SnapshotSourceResolver(model_snapshot_root=root)

    assert resolver.resolve("modeling_link.py") is SnapshotResolveError.PATH_ESCAPE


def test_source_loader_returns_bytes_for_verified_files_and_none_for_errors(tmp_path: Path) -> None:
    root = tmp_path / "snapshot"
    content = b'{"auto_map": {}}\n'
    _write(root / "config.json", content)
    loader = build_source_loader(SnapshotSourceResolver(model_snapshot_root=root))

    assert loader("config.json") == content
    assert loader("missing.py") is None
