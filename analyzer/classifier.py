"""Minimal file classifier for early code-validation tests.

This helper only classifies repository files and builds ArtifactRef metadata.
It does not execute or import model code and does not implement final Analyzer
Core dispatch policy.
"""

from __future__ import annotations

import hashlib
from pathlib import Path, PurePosixPath

from analyzer.schemas import ArtifactRef, FileKind

PICKLE_EXTENSIONS = {".pkl", ".pt", ".bin"}


def normalize_repo_path(path: str | Path) -> str:
    normalized = str(path).replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    while "//" in normalized:
        normalized = normalized.replace("//", "/")
    return normalized


def classify_file_kind(repo_path: str | Path) -> FileKind:
    normalized = normalize_repo_path(repo_path)
    name = PurePosixPath(normalized).name.lower()
    suffix = PurePosixPath(normalized).suffix.lower()

    if name == "config.json":
        return FileKind.CONFIG_JSON
    if name == "tokenizer_config.json":
        return FileKind.TOKENIZER_CONFIG_JSON
    if name == "tokenizer.json":
        return FileKind.TOKENIZER_JSON
    if name == "special_tokens_map.json":
        return FileKind.SPECIAL_TOKENS_MAP_JSON
    if name == "added_tokens.json":
        return FileKind.ADDED_TOKENS_JSON
    if name == "vocab.json":
        return FileKind.VOCAB_JSON
    if name == "merges.txt":
        return FileKind.MERGES_TXT
    if name == "preprocessor_config.json":
        return FileKind.PREPROCESSOR_CONFIG_JSON
    if name == "processor_config.json":
        return FileKind.PROCESSOR_CONFIG_JSON
    if name == "chat_template.jinja":
        return FileKind.CHAT_TEMPLATE_JINJA
    if suffix == ".safetensors":
        return FileKind.SAFETENSORS
    if suffix in PICKLE_EXTENSIONS:
        return FileKind.PICKLE
    if suffix == ".py":
        return FileKind.PYTHON
    return FileKind.OTHER


def sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def build_artifact_ref(
    repo_path: str | Path,
    content: bytes | str | None = None,
    *,
    local_path: str | Path | None = None,
    source_url: str = "",
    media_type: str | None = None,
    referenced_by: list[str] | None = None,
    is_generated: bool = False,
) -> ArtifactRef:
    if content is None:
        if local_path is None:
            raise ValueError("content or local_path is required")
        raw_content = Path(local_path).read_bytes()
    elif isinstance(content, str):
        raw_content = content.encode("utf-8")
    else:
        raw_content = content

    normalized_repo_path = normalize_repo_path(repo_path)
    posix_path = PurePosixPath(normalized_repo_path)
    digest = sha256_bytes(raw_content)

    return ArtifactRef(
        artifact_id=f"sha256:{digest}",
        repo_path=normalized_repo_path,
        file_name=posix_path.name,
        file_kind=classify_file_kind(normalized_repo_path),
        detected_extension=posix_path.suffix.lower(),
        media_type=media_type,
        size_bytes=len(raw_content),
        sha256=digest,
        source_url=source_url,
        temp_local_path=str(local_path) if local_path is not None else normalized_repo_path,
        referenced_by=list(referenced_by or []),
        is_generated=is_generated,
    )


def build_artifact_ref_from_file(
    local_path: str | Path,
    *,
    repo_path: str | Path | None = None,
    source_url: str = "",
    media_type: str | None = None,
    referenced_by: list[str] | None = None,
    is_generated: bool = False,
) -> ArtifactRef:
    resolved_repo_path = repo_path if repo_path is not None else Path(local_path).name
    return build_artifact_ref(
        resolved_repo_path,
        local_path=local_path,
        source_url=source_url,
        media_type=media_type,
        referenced_by=referenced_by,
        is_generated=is_generated,
    )
