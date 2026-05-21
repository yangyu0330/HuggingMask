"""Verified snapshot source resolution for code-validation inputs.

The resolver deliberately accepts only repo-relative paths and verified files
under trusted snapshot/temp bases. It is a source-reading helper, not a
sandbox manifest or dependency-closure builder.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Callable, Iterable

from analyzer.schemas import FileKind, SnapshotFileRef, StringEnum, ValidationJobRequest


class SnapshotResolveError(StringEnum):
    MISSING_SOURCE = "MISSING_SOURCE"
    PATH_ESCAPE = "PATH_ESCAPE"
    HASH_MISMATCH = "HASH_MISMATCH"
    SIZE_MISMATCH = "SIZE_MISMATCH"
    UNTRUSTED_LOCAL_PATH = "UNTRUSTED_LOCAL_PATH"
    INVALID_REPO_PATH = "INVALID_REPO_PATH"


@dataclass(frozen=True)
class ResolvedSnapshotFile:
    repo_path: str
    local_path: Path
    sha256: str
    size_bytes: int
    file_kind: FileKind
    source_kind: str


class SnapshotSourceResolver:
    def __init__(
        self,
        *,
        model_snapshot_root: str | Path | None = None,
        model_snapshot_inventory: Iterable[SnapshotFileRef | dict] | None = None,
        trusted_temp_bases: Iterable[str | Path] | None = None,
    ) -> None:
        self._snapshot_root = _resolve_base(model_snapshot_root) if model_snapshot_root else None
        bases = list(trusted_temp_bases or [])
        if self._snapshot_root is not None:
            bases.append(self._snapshot_root)
        self._trusted_bases = [_resolve_base(base) for base in bases]
        self._inventory: dict[str, SnapshotFileRef] = {}
        for item in model_snapshot_inventory or []:
            ref = item if isinstance(item, SnapshotFileRef) else SnapshotFileRef.from_dict(item)
            normalized = _normalize_repo_path(ref.repo_path)
            if isinstance(normalized, SnapshotResolveError):
                continue
            self._inventory[normalized] = ref

    @classmethod
    def from_request(
        cls,
        request: ValidationJobRequest,
        *,
        trusted_temp_bases: Iterable[str | Path] | None = None,
    ) -> "SnapshotSourceResolver":
        return cls(
            model_snapshot_root=request.model_snapshot_root,
            model_snapshot_inventory=request.model_snapshot_inventory,
            trusted_temp_bases=trusted_temp_bases,
        )

    def resolve(self, repo_path: str) -> ResolvedSnapshotFile | SnapshotResolveError:
        normalized = _normalize_repo_path(repo_path)
        if isinstance(normalized, SnapshotResolveError):
            return normalized

        if normalized in self._inventory:
            return self._resolve_inventory_ref(self._inventory[normalized], normalized)

        if self._snapshot_root is None:
            return SnapshotResolveError.MISSING_SOURCE
        return self._resolve_from_root(normalized)

    def read_bytes(self, repo_path: str) -> bytes | SnapshotResolveError:
        resolved = self.resolve(repo_path)
        if isinstance(resolved, SnapshotResolveError):
            return resolved
        try:
            return resolved.local_path.read_bytes()
        except OSError:
            return SnapshotResolveError.MISSING_SOURCE

    def _resolve_inventory_ref(
        self,
        ref: SnapshotFileRef,
        normalized_repo_path: str,
    ) -> ResolvedSnapshotFile | SnapshotResolveError:
        local_path = Path(ref.temp_local_path)
        if not local_path.is_absolute():
            return SnapshotResolveError.UNTRUSTED_LOCAL_PATH
        if not self._trusted_bases:
            return SnapshotResolveError.UNTRUSTED_LOCAL_PATH

        lexical_path = Path(local_path.absolute())
        if not _is_under_any(lexical_path, self._trusted_bases):
            return SnapshotResolveError.UNTRUSTED_LOCAL_PATH

        resolved_path = local_path.resolve(strict=False)
        if not _is_under_any(resolved_path, self._trusted_bases):
            return SnapshotResolveError.PATH_ESCAPE

        verified = _verify_file(resolved_path, expected_size=ref.size_bytes, expected_sha256=ref.sha256)
        if isinstance(verified, SnapshotResolveError):
            return verified

        return ResolvedSnapshotFile(
            repo_path=normalized_repo_path,
            local_path=resolved_path,
            sha256=verified["sha256"],
            size_bytes=verified["size_bytes"],
            file_kind=ref.file_kind,
            source_kind="inventory",
        )

    def _resolve_from_root(self, normalized_repo_path: str) -> ResolvedSnapshotFile | SnapshotResolveError:
        assert self._snapshot_root is not None
        candidate = self._snapshot_root.joinpath(*PurePosixPath(normalized_repo_path).parts)
        resolved_path = candidate.resolve(strict=False)
        if not _is_relative_to(resolved_path, self._snapshot_root):
            return SnapshotResolveError.PATH_ESCAPE

        verified = _verify_file(resolved_path, expected_size=None, expected_sha256=None)
        if isinstance(verified, SnapshotResolveError):
            return verified

        return ResolvedSnapshotFile(
            repo_path=normalized_repo_path,
            local_path=resolved_path,
            sha256=verified["sha256"],
            size_bytes=verified["size_bytes"],
            file_kind=FileKind.OTHER,
            source_kind="root",
        )


SourceLoader = Callable[[str], str | bytes | None]


def build_source_loader(resolver: SnapshotSourceResolver) -> SourceLoader:
    def _loader(repo_path: str) -> bytes | None:
        value = resolver.read_bytes(repo_path)
        if isinstance(value, SnapshotResolveError):
            return None
        return value

    return _loader


def _normalize_repo_path(repo_path: str) -> str | SnapshotResolveError:
    text = str(repo_path)
    if not text or text == "." or "\x00" in text or "\\" in text:
        return SnapshotResolveError.INVALID_REPO_PATH
    if len(text) >= 2 and text[1] == ":" and text[0].isalpha():
        return SnapshotResolveError.INVALID_REPO_PATH

    path = PurePosixPath(text)
    if path.is_absolute():
        return SnapshotResolveError.INVALID_REPO_PATH
    if any(part in {"", ".", ".."} for part in path.parts):
        return SnapshotResolveError.INVALID_REPO_PATH
    return path.as_posix()


def _resolve_base(path: str | Path) -> Path:
    return Path(path).resolve(strict=False)


def _verify_file(
    path: Path,
    *,
    expected_size: int | None,
    expected_sha256: str | None,
) -> dict[str, int | str] | SnapshotResolveError:
    if not path.is_file():
        return SnapshotResolveError.MISSING_SOURCE
    try:
        data = path.read_bytes()
    except OSError:
        return SnapshotResolveError.MISSING_SOURCE

    actual_size = len(data)
    if expected_size is not None and actual_size != expected_size:
        return SnapshotResolveError.SIZE_MISMATCH

    actual_sha256 = hashlib.sha256(data).hexdigest()
    if expected_sha256 is not None and actual_sha256 != expected_sha256:
        return SnapshotResolveError.HASH_MISMATCH

    return {"sha256": actual_sha256, "size_bytes": actual_size}


def _is_under_any(path: Path, bases: list[Path]) -> bool:
    return any(_is_relative_to(path, base) for base in bases)


def _is_relative_to(path: Path, base: Path) -> bool:
    try:
        path.relative_to(base)
        return True
    except ValueError:
        return False
