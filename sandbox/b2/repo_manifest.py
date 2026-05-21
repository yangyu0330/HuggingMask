"""Build verified B-2 sandbox input manifests.

This module fixes the set of files that may enter a future B-2 sandbox run. It
uses only ``SnapshotSourceResolver.resolve()`` verified paths for hashing and
staging. It does not import or execute repository Python code.
"""

from __future__ import annotations

import ast
import hashlib
import json
import shutil
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

from analyzer.schemas import (
    ArtifactValidationResult,
    CodeGrade,
    FileKind,
    ValidationStatus,
    to_jsonable,
)
from analyzer.snapshot_resolver import ResolvedSnapshotFile, SnapshotResolveError, SnapshotSourceResolver
from sandbox.b2.schemas import (
    B2_INPUT_MANIFEST_FILENAME,
    B2_MANIFEST_SCHEMA_VERSION,
    B2InputManifest,
    B2ManifestContentKind,
    B2ManifestErrorCode,
    B2ManifestFile,
    B2Target,
)

_KNOWN_EXTERNAL_IMPORT_ROOTS = {
    "__future__",
    "abc",
    "aiohttp",
    "collections",
    "contextlib",
    "copy",
    "ctypes",
    "dataclasses",
    "enum",
    "functools",
    "httpx",
    "importlib",
    "inspect",
    "itertools",
    "json",
    "logging",
    "math",
    "numpy",
    "os",
    "pathlib",
    "pickle",
    "re",
    "requests",
    "socket",
    "subprocess",
    "sys",
    "torch",
    "transformers",
    "typing",
    "typing_extensions",
    "urllib",
    "warnings",
}
_SUPPORT_REPO_PATHS = (
    "config.json",
    "generation_config.json",
    "tokenizer_config.json",
    "preprocessor_config.json",
    "processor_config.json",
    "special_tokens_map.json",
    "added_tokens.json",
)


class B2ManifestError(Exception):
    """Structured manifest/staging failure."""

    def __init__(
        self,
        reason_code: B2ManifestErrorCode | SnapshotResolveError | str,
        message: str,
        *,
        repo_path: str | None = None,
        dependency: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        self.reason_code = _reason_value(reason_code)
        self.repo_path = repo_path
        self.dependency = dependency
        self.details = dict(details or {})
        super().__init__(message)

    def to_dict(self) -> dict[str, Any]:
        return {
            "reason_code": self.reason_code,
            "message": str(self),
            "repo_path": self.repo_path,
            "dependency": self.dependency,
            "details": dict(self.details),
        }


@dataclass(frozen=True)
class _ResolvedImport:
    repo_path: str
    requested: str


def build_b2_input_manifest(
    *,
    request_id: str,
    job_id: str,
    source_resolver: SnapshotSourceResolver,
    revision: str,
    policy_version: str,
    primary_result: ArtifactValidationResult,
    candidate_results: list[ArtifactValidationResult],
) -> B2InputManifest:
    primary_repo_path = _normalize_repo_path_or_raise(primary_result.artifact.repo_path)
    if primary_result.artifact.file_kind is not FileKind.PYTHON:
        raise B2ManifestError(
            B2ManifestErrorCode.DEPENDENCY_NOT_VALIDATED,
            "primary B-2 target must be a Python artifact",
            repo_path=primary_repo_path,
        )

    results_by_path = _build_result_index([primary_result, *candidate_results])
    primary_resolved = _resolve_required(source_resolver, primary_repo_path)
    _verify_result_matches_resolved(primary_result, primary_resolved)
    _validate_python_result_static(primary_result)

    python_paths = _collect_python_import_closure(
        primary_repo_path=primary_repo_path,
        source_resolver=source_resolver,
    )
    support_paths = _collect_support_files(source_resolver)

    files_by_path: dict[str, B2ManifestFile] = {}
    for repo_path in python_paths:
        result = results_by_path.get(repo_path)
        if result is None:
            raise B2ManifestError(
                B2ManifestErrorCode.DEPENDENCY_NOT_VALIDATED,
                "manifest Python dependency has no ArtifactValidationResult",
                repo_path=repo_path,
                dependency=repo_path,
            )
        resolved = _resolve_required(source_resolver, repo_path)
        _verify_result_matches_resolved(result, resolved)
        _validate_python_result_static(result)
        _add_manifest_file(
            files_by_path,
            _python_manifest_file(
                result=result,
                resolved=resolved,
                is_primary=repo_path == primary_repo_path,
            ),
        )

    for repo_path in support_paths:
        resolved = _resolve_required(source_resolver, repo_path)
        _add_manifest_file(files_by_path, _support_manifest_file(resolved))

    manifest = B2InputManifest(
        schema_version=B2_MANIFEST_SCHEMA_VERSION,
        request_id=request_id,
        job_id=job_id,
        primary_artifact_id=primary_result.artifact.artifact_id,
        primary_repo_path=primary_repo_path,
        revision=revision,
        policy_version=policy_version,
        grade=primary_result.grade.value,
        target=_target_from_result(primary_result, primary_repo_path),
        manifest_sha256="",
        files=_sort_manifest_files(files_by_path.values()),
    )
    refresh_manifest_hash(manifest)
    return manifest


def refresh_manifest_hash(manifest: B2InputManifest) -> B2InputManifest:
    manifest.files = _sort_manifest_files(manifest.files)
    manifest.manifest_sha256 = compute_manifest_sha256(manifest)
    return manifest


def compute_manifest_sha256(manifest: B2InputManifest) -> str:
    payload = _canonical_json_bytes(_manifest_payload(manifest, include_hash=False))
    return hashlib.sha256(payload).hexdigest()


def write_manifest(manifest: B2InputManifest, output_path: Path) -> None:
    refresh_manifest_hash(manifest)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(_canonical_json_bytes(_manifest_payload(manifest, include_hash=True)))


def verify_manifest_files(manifest: B2InputManifest, source_resolver: SnapshotSourceResolver) -> list[str]:
    errors: list[str] = []
    seen: dict[str, str] = {}
    for item in _sort_manifest_files(manifest.files):
        try:
            repo_path = _normalize_repo_path_or_raise(item.path)
            previous_sha = seen.get(repo_path)
            if previous_sha is not None and previous_sha != item.sha256:
                raise B2ManifestError(
                    B2ManifestErrorCode.HASH_MISMATCH,
                    "duplicate manifest path has conflicting hashes",
                    repo_path=repo_path,
                )
            seen[repo_path] = item.sha256
            resolved = _resolve_required(source_resolver, repo_path)
            _verify_manifest_file_matches_resolved(item, resolved)
        except B2ManifestError as exc:
            errors.append(f"{exc.reason_code}:{exc.repo_path or item.path}")
    return errors


def prepare_job_input_dir(
    *,
    source_resolver: SnapshotSourceResolver,
    manifest: B2InputManifest,
    output_dir: Path,
) -> Path:
    input_dir = _prepare_clean_input_dir(output_dir)

    seen: dict[str, str] = {}
    for item in _sort_manifest_files(manifest.files):
        repo_path = _normalize_repo_path_or_raise(item.path)
        previous_sha = seen.get(repo_path)
        if previous_sha is not None:
            reason = B2ManifestErrorCode.HASH_MISMATCH if previous_sha != item.sha256 else B2ManifestErrorCode.DUPLICATE_PATH
            raise B2ManifestError(reason, "duplicate manifest path", repo_path=repo_path)
        seen[repo_path] = item.sha256

        resolved = _resolve_required(source_resolver, repo_path)
        _verify_manifest_file_matches_resolved(item, resolved)
        destination = input_dir.joinpath(*PurePosixPath(repo_path).parts)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(resolved.local_path, destination)

    write_manifest(manifest, input_dir / B2_INPUT_MANIFEST_FILENAME)
    return input_dir


def _prepare_clean_input_dir(output_dir: Path) -> Path:
    output_root = Path(output_dir).resolve(strict=False)
    if output_root.parent == output_root:
        raise B2ManifestError(
            B2ManifestErrorCode.PATH_ESCAPE,
            "refusing to stage B-2 input under filesystem root",
            details={"output_dir": str(output_root)},
        )

    input_dir = output_root / "input"
    if input_dir.is_symlink():
        raise B2ManifestError(
            B2ManifestErrorCode.PATH_ESCAPE,
            "refusing to remove symlinked B-2 input directory",
            details={"input_dir": str(input_dir)},
        )

    resolved_input = input_dir.resolve(strict=False)
    if resolved_input == output_root or not resolved_input.is_relative_to(output_root):
        raise B2ManifestError(
            B2ManifestErrorCode.PATH_ESCAPE,
            "B-2 input directory escapes output directory",
            details={"output_dir": str(output_root), "input_dir": str(resolved_input)},
        )

    if resolved_input.exists():
        if not resolved_input.is_dir():
            raise B2ManifestError(
                B2ManifestErrorCode.PATH_ESCAPE,
                "B-2 input path is not a directory",
                details={"input_dir": str(resolved_input)},
            )
        shutil.rmtree(resolved_input)
    resolved_input.mkdir(parents=True)
    return resolved_input


def _collect_python_import_closure(
    *,
    primary_repo_path: str,
    source_resolver: SnapshotSourceResolver,
) -> list[str]:
    start_paths = [*_existing_package_inits(primary_repo_path, source_resolver), primary_repo_path]
    seen: set[str] = set(start_paths)
    ordered: list[str] = list(start_paths)
    queue: list[str] = list(start_paths)

    while queue:
        repo_path = queue.pop(0)
        resolved = _resolve_required(source_resolver, repo_path)
        source = resolved.local_path.read_bytes()
        try:
            tree = ast.parse(source.decode("utf-8", errors="replace"))
        except SyntaxError as exc:
            raise B2ManifestError(
                B2ManifestErrorCode.DEPENDENCY_STATIC_RISK,
                "manifest Python dependency has a syntax error",
                repo_path=repo_path,
                details={"parse_error": str(exc)},
            ) from exc

        for dependency in _collect_local_imports(repo_path, tree, source_resolver):
            if dependency.repo_path in seen:
                continue
            seen.add(dependency.repo_path)
            ordered.append(dependency.repo_path)
            queue.append(dependency.repo_path)

    return sorted(ordered)


def _collect_local_imports(
    current_repo_path: str,
    tree: ast.Module,
    source_resolver: SnapshotSourceResolver,
) -> list[_ResolvedImport]:
    dependencies: list[_ResolvedImport] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                dependencies.extend(
                    _resolve_absolute_import(
                        alias.name,
                        source_resolver=source_resolver,
                        current_repo_path=current_repo_path,
                    )
                )
        elif isinstance(node, ast.ImportFrom):
            if node.module == "__future__":
                continue
            aliases = [alias.name for alias in node.names if alias.name != "*"]
            if node.level:
                dependencies.extend(
                    _resolve_relative_import(
                        current_repo_path=current_repo_path,
                        level=node.level,
                        module=node.module,
                        aliases=aliases,
                        source_resolver=source_resolver,
                    )
                )
            elif node.module:
                dependencies.extend(
                    _resolve_absolute_from_import(
                        node.module,
                        aliases,
                        source_resolver=source_resolver,
                        current_repo_path=current_repo_path,
                    )
                )
    return _dedupe_imports(dependencies)


def _resolve_absolute_import(
    module_name: str,
    *,
    source_resolver: SnapshotSourceResolver,
    current_repo_path: str,
) -> list[_ResolvedImport]:
    matches = _resolve_module_reference(module_name.split("."), module_name, source_resolver)
    if matches:
        return matches
    if _is_known_external(module_name):
        return []
    raise B2ManifestError(
        B2ManifestErrorCode.UNRESOLVED_DEPENDENCY,
        "absolute import could not be resolved as a repo-local dependency",
        repo_path=current_repo_path,
        dependency=module_name,
    )


def _resolve_absolute_from_import(
    module_name: str,
    aliases: list[str],
    *,
    source_resolver: SnapshotSourceResolver,
    current_repo_path: str,
) -> list[_ResolvedImport]:
    dependencies = _resolve_module_reference(module_name.split("."), module_name, source_resolver)
    for alias in aliases:
        dependencies.extend(
            _resolve_module_reference([*module_name.split("."), alias], f"{module_name}.{alias}", source_resolver)
        )
    if dependencies:
        return _dedupe_imports(dependencies)
    if _is_known_external(module_name):
        return []
    raise B2ManifestError(
        B2ManifestErrorCode.UNRESOLVED_DEPENDENCY,
        "from-import could not be resolved as a repo-local dependency",
        repo_path=current_repo_path,
        dependency=module_name,
    )


def _resolve_relative_import(
    *,
    current_repo_path: str,
    level: int,
    module: str | None,
    aliases: list[str],
    source_resolver: SnapshotSourceResolver,
) -> list[_ResolvedImport]:
    base_parts = _relative_import_base_parts(current_repo_path, level)
    if base_parts is None:
        raise B2ManifestError(
            B2ManifestErrorCode.UNRESOLVED_DEPENDENCY,
            "relative import escapes the repository package root",
            repo_path=current_repo_path,
            dependency=f"{'.' * level}{module or ''}",
        )

    module_parts = [*base_parts, *(module.split(".") if module else [])]
    dependencies: list[_ResolvedImport] = []

    if module:
        dependencies.extend(_resolve_module_reference(module_parts, "." * level + module, source_resolver))
        for alias in aliases:
            dependencies.extend(
                _resolve_module_reference([*module_parts, alias], "." * level + module + "." + alias, source_resolver)
            )
        if dependencies:
            return _dedupe_imports(dependencies)
        raise B2ManifestError(
            B2ManifestErrorCode.UNRESOLVED_DEPENDENCY,
            "relative from-import dependency could not be resolved",
            repo_path=current_repo_path,
            dependency=f"{'.' * level}{module}",
        )

    for alias in aliases:
        matches = _resolve_module_reference([*module_parts, alias], "." * level + alias, source_resolver)
        if not matches:
            raise B2ManifestError(
                B2ManifestErrorCode.UNRESOLVED_DEPENDENCY,
                "relative import dependency could not be resolved",
                repo_path=current_repo_path,
                dependency=f"{'.' * level}{alias}",
            )
        dependencies.extend(matches)
    return _dedupe_imports(dependencies)


def _resolve_module_reference(
    module_parts: list[str],
    requested: str,
    source_resolver: SnapshotSourceResolver,
) -> list[_ResolvedImport]:
    if not module_parts or any(not part or part == "*" for part in module_parts):
        return []
    module_path = "/".join(module_parts)
    candidate_paths = [f"{module_path}.py", f"{module_path}/__init__.py"]
    resolved: list[_ResolvedImport] = []
    for candidate_path in candidate_paths:
        candidate = _probe_repo_path(candidate_path, source_resolver)
        if candidate is None:
            continue
        for package_init in _existing_package_inits(candidate, source_resolver):
            resolved.append(_ResolvedImport(package_init, requested))
        resolved.append(_ResolvedImport(candidate, requested))
    return _dedupe_imports(resolved)


def _probe_repo_path(repo_path: str, source_resolver: SnapshotSourceResolver) -> str | None:
    normalized = _normalize_repo_path_or_raise(repo_path)
    resolved = source_resolver.resolve(normalized)
    if isinstance(resolved, ResolvedSnapshotFile):
        return normalized
    if resolved is SnapshotResolveError.MISSING_SOURCE:
        return None
    raise B2ManifestError(resolved, "dependency candidate failed snapshot resolution", repo_path=normalized)


def _existing_package_inits(repo_path: str, source_resolver: SnapshotSourceResolver) -> list[str]:
    path = PurePosixPath(repo_path)
    parent_parts = list(path.parts[:-1])
    if path.name == "__init__.py":
        parent_parts = parent_parts[:-1]
    package_inits: list[str] = []
    for index in range(1, len(parent_parts) + 1):
        init_path = PurePosixPath(*parent_parts[:index], "__init__.py").as_posix()
        if init_path == repo_path:
            continue
        candidate = _probe_repo_path(init_path, source_resolver)
        if candidate is not None:
            package_inits.append(candidate)
    return package_inits


def _relative_import_base_parts(current_repo_path: str, level: int) -> list[str] | None:
    current = PurePosixPath(current_repo_path)
    package_parts = list(current.parts[:-1])
    if current.name == "__init__.py":
        package_parts = list(current.parts[:-1])
    keep_count = len(package_parts) - level + 1
    if keep_count < 0:
        return None
    return package_parts[:keep_count]


def _collect_support_files(source_resolver: SnapshotSourceResolver) -> list[str]:
    support_paths: list[str] = []
    for repo_path in _SUPPORT_REPO_PATHS:
        resolved = source_resolver.resolve(repo_path)
        if isinstance(resolved, ResolvedSnapshotFile):
            support_paths.append(repo_path)
        elif resolved is not SnapshotResolveError.MISSING_SOURCE:
            raise B2ManifestError(resolved, "support file failed snapshot resolution", repo_path=repo_path)
    return sorted(support_paths)


def _python_manifest_file(
    *,
    result: ArtifactValidationResult,
    resolved: ResolvedSnapshotFile,
    is_primary: bool,
) -> B2ManifestFile:
    return B2ManifestFile(
        path=resolved.repo_path,
        sha256=resolved.sha256,
        size_bytes=resolved.size_bytes,
        role=_role_from_result(result),
        ast_grade=result.grade.value,
        content_kind=B2ManifestContentKind.PYTHON.value,
        import_allowed=True,
        target_allowed=is_primary,
        is_primary=is_primary,
        validation_status=result.status.value,
        unknown_apis=_unknown_apis_from_result(result),
        risk_flags=_manifest_risk_flags(result),
    )


def _support_manifest_file(resolved: ResolvedSnapshotFile) -> B2ManifestFile:
    content_kind = B2ManifestContentKind.JSON_SUPPORT.value
    if PurePosixPath(resolved.repo_path).suffix.lower() != ".json":
        content_kind = B2ManifestContentKind.TEXT_SUPPORT.value
    return B2ManifestFile(
        path=resolved.repo_path,
        sha256=resolved.sha256,
        size_bytes=resolved.size_bytes,
        role="SUPPORT",
        ast_grade=CodeGrade.NA.value,
        content_kind=content_kind,
        import_allowed=False,
        target_allowed=False,
        is_primary=False,
        validation_status="SUPPORT_ONLY",
        unknown_apis=[],
        risk_flags=[],
    )


def _target_from_result(result: ArtifactValidationResult, primary_repo_path: str) -> B2Target:
    details = result.details or {}
    target_module = details.get("target_module") or _module_name_from_repo_path(primary_repo_path)
    target_class = details.get("target_class") or _single_forward_class_from_ast(details)
    return B2Target(
        source="auto_map" if details.get("linked_from_config") else "direct_python",
        target_module=str(target_module),
        target_class=target_class,
        auto_map_key=details.get("auto_map_key"),
        primary_repo_path=primary_repo_path,
    )


def _single_forward_class_from_ast(details: dict[str, Any]) -> str | None:
    ast_scan = details.get("ast_scan") or {}
    classes = ast_scan.get("classes") or []
    if not isinstance(classes, list) or len(classes) != 1:
        return None
    class_name = classes[0]
    if not isinstance(class_name, str):
        return None
    methods = ast_scan.get("methods") or []
    if f"{class_name}.forward" not in methods:
        return None
    return class_name


def _build_result_index(results: Iterable[ArtifactValidationResult]) -> dict[str, ArtifactValidationResult]:
    indexed: dict[str, ArtifactValidationResult] = {}
    for result in results:
        repo_path = _normalize_repo_path_or_raise(result.artifact.repo_path)
        previous = indexed.get(repo_path)
        if previous is not None:
            if previous.artifact.sha256 != result.artifact.sha256:
                raise B2ManifestError(
                    B2ManifestErrorCode.HASH_MISMATCH,
                    "candidate results contain duplicate paths with conflicting hashes",
                    repo_path=repo_path,
                )
            continue
        indexed[repo_path] = result
    return indexed


def _verify_result_matches_resolved(result: ArtifactValidationResult, resolved: ResolvedSnapshotFile) -> None:
    if result.artifact.sha256 != resolved.sha256:
        raise B2ManifestError(
            B2ManifestErrorCode.HASH_MISMATCH,
            "artifact result hash does not match verified snapshot file",
            repo_path=resolved.repo_path,
            details={"artifact_sha256": result.artifact.sha256, "resolved_sha256": resolved.sha256},
        )
    if result.artifact.size_bytes != resolved.size_bytes:
        raise B2ManifestError(
            B2ManifestErrorCode.SIZE_MISMATCH,
            "artifact result size does not match verified snapshot file",
            repo_path=resolved.repo_path,
            details={"artifact_size_bytes": result.artifact.size_bytes, "resolved_size_bytes": resolved.size_bytes},
        )


def _verify_manifest_file_matches_resolved(item: B2ManifestFile, resolved: ResolvedSnapshotFile) -> None:
    if item.sha256 != resolved.sha256:
        raise B2ManifestError(
            B2ManifestErrorCode.HASH_MISMATCH,
            "manifest file hash does not match verified snapshot file",
            repo_path=item.path,
            details={"manifest_sha256": item.sha256, "resolved_sha256": resolved.sha256},
        )
    if item.size_bytes != resolved.size_bytes:
        raise B2ManifestError(
            B2ManifestErrorCode.SIZE_MISMATCH,
            "manifest file size does not match verified snapshot file",
            repo_path=item.path,
            details={"manifest_size_bytes": item.size_bytes, "resolved_size_bytes": resolved.size_bytes},
        )


def _validate_python_result_static(result: ArtifactValidationResult) -> None:
    risk_flags = _static_risk_flags(result)
    if risk_flags:
        raise B2ManifestError(
            B2ManifestErrorCode.DEPENDENCY_STATIC_RISK,
            "manifest Python file has static risk and cannot be staged for B-2",
            repo_path=result.artifact.repo_path,
            dependency=result.artifact.repo_path,
            details={"risk_flags": risk_flags},
        )


def _static_risk_flags(result: ArtifactValidationResult) -> list[str]:
    details = result.details or {}
    ast_scan = details.get("ast_scan") or {}
    api_scan = details.get("api_scan") or {}
    context_scan = details.get("context_api_scan") or {}
    flags: list[str] = []
    if ast_scan.get("parse_error"):
        flags.append("PARSE_ERROR")
    for key, flag in (
        ("dangerous_imports", "DANGEROUS_IMPORT"),
        ("dangerous_calls", "DANGEROUS_CALL"),
        ("dynamic_patterns", "DYNAMIC_PATTERN"),
        ("obfuscation_patterns", "OBFUSCATION_PATTERN"),
    ):
        if ast_scan.get(key):
            flags.append(flag)
    if api_scan.get("blocked_apis"):
        flags.append("DANGEROUS_API")
    if context_scan.get("summary_decision") == "block":
        flags.append("CONTEXT_API_BLOCKED")
    if result.status is ValidationStatus.BLOCK:
        flags.append("VALIDATION_BLOCK")
    return _dedupe(flags)


def _manifest_risk_flags(result: ArtifactValidationResult) -> list[str]:
    details = result.details or {}
    context_scan = details.get("context_api_scan") or {}
    flags: list[str] = []
    if _unknown_apis_from_result(result):
        flags.append("UNREGISTERED_API")
    if context_scan.get("summary_decision") == "review":
        flags.append("CONTEXT_API_REVIEW")
    return flags


def _unknown_apis_from_result(result: ArtifactValidationResult) -> list[str]:
    details = result.details or {}
    api_scan = details.get("api_scan") or {}
    return _dedupe(list(details.get("pending_api_refs") or []) + list(api_scan.get("unregistered_apis") or []))


def _role_from_result(result: ArtifactValidationResult) -> str:
    details = result.details or {}
    return str((details.get("role_classification") or {}).get("role") or "UNKNOWN")


def _module_name_from_repo_path(repo_path: str) -> str:
    path = PurePosixPath(repo_path)
    if path.name == "__init__.py":
        return ".".join(path.parts[:-1])
    return ".".join((*path.parts[:-1], path.stem))


def _add_manifest_file(files_by_path: dict[str, B2ManifestFile], item: B2ManifestFile) -> None:
    normalized = _normalize_repo_path_or_raise(item.path)
    previous = files_by_path.get(normalized)
    if previous is not None:
        if previous.sha256 != item.sha256:
            raise B2ManifestError(
                B2ManifestErrorCode.HASH_MISMATCH,
                "manifest contains duplicate path with conflicting hashes",
                repo_path=normalized,
            )
        return
    item.path = normalized
    files_by_path[normalized] = item


def _resolve_required(source_resolver: SnapshotSourceResolver, repo_path: str) -> ResolvedSnapshotFile:
    normalized = _normalize_repo_path_or_raise(repo_path)
    resolved = source_resolver.resolve(normalized)
    if isinstance(resolved, ResolvedSnapshotFile):
        return resolved
    raise B2ManifestError(resolved, "snapshot source resolution failed", repo_path=normalized)


def _manifest_payload(manifest: B2InputManifest, *, include_hash: bool) -> dict[str, Any]:
    payload = to_jsonable(manifest)
    payload["files"] = [to_jsonable(item) for item in _sort_manifest_files(manifest.files)]
    if not include_hash:
        payload.pop("manifest_sha256", None)
    return payload


def _canonical_json_bytes(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sort_manifest_files(files: Iterable[B2ManifestFile]) -> list[B2ManifestFile]:
    return sorted(files, key=lambda item: (item.path, item.content_kind))


def _normalize_repo_path_or_raise(repo_path: str) -> str:
    text = str(repo_path)
    if not text or text == "." or "\x00" in text or "\\" in text:
        raise B2ManifestError(B2ManifestErrorCode.INVALID_REPO_PATH, "invalid repo path", repo_path=text)
    if len(text) >= 2 and text[1] == ":" and text[0].isalpha():
        raise B2ManifestError(B2ManifestErrorCode.INVALID_REPO_PATH, "invalid repo path", repo_path=text)
    path = PurePosixPath(text)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise B2ManifestError(B2ManifestErrorCode.INVALID_REPO_PATH, "invalid repo path", repo_path=text)
    return path.as_posix()


def _is_known_external(module_name: str) -> bool:
    root = module_name.split(".", 1)[0]
    return root in _KNOWN_EXTERNAL_IMPORT_ROOTS


def _dedupe_imports(items: Iterable[_ResolvedImport]) -> list[_ResolvedImport]:
    seen: set[str] = set()
    ordered: list[_ResolvedImport] = []
    for item in items:
        if item.repo_path in seen:
            continue
        seen.add(item.repo_path)
        ordered.append(item)
    return ordered


def _dedupe(items: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        ordered.append(item)
    return ordered


def _reason_value(reason_code: B2ManifestErrorCode | SnapshotResolveError | str) -> str:
    if hasattr(reason_code, "value"):
        return str(reason_code.value)
    return str(reason_code)
