"""Trusted in-container B-2 runner entrypoint contract.

This module is designed to be unit-tested as ``main(argv)``. It validates the
already-staged B-2 input manifest before adding the staged input directory to
``sys.path`` or importing any target module.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import inspect
import importlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

B2_SCHEMA_VERSION = "1.0"


class EntrypointError(Exception):
    pass


class ManifestVerificationError(EntrypointError):
    pass


class TargetClassMissing(EntrypointError):
    pass


@dataclass(frozen=True)
class VerifiedManifest:
    payload: dict[str, Any]
    input_root: Path
    manifest_sha256: str
    target_module: str
    target_class: str | None

    @property
    def request_id(self) -> str:
        return str(self.payload.get("request_id") or "")


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    result = _base_result(request_id=args.request_id or "", nonce=args.nonce)

    try:
        verified = verify_manifest(
            Path(args.manifest),
            expected_manifest_sha256=args.manifest_sha256,
        )
        result["request_id"] = args.request_id or verified.request_id
        result["manifest_verified"] = True
    except Exception as exc:
        result.update(
            {
                "manifest_verified": False,
                "import_status": "skipped",
                "instantiate_status": "skipped",
                "forward_status": "skipped",
                "exception_class": type(exc).__name__,
                "exception_message": str(exc),
            }
        )
        _write_runner_result(Path(args.output), result)
        _emit_runner_log(result)
        return 0

    original_sys_path = list(sys.path)
    original_dont_write_bytecode = sys.dont_write_bytecode
    previous_modules = _remove_target_modules(verified.target_module)
    try:
        sys.dont_write_bytecode = True
        _add_input_root_to_syspath(verified.input_root)
        importlib.invalidate_caches()
        module = importlib.import_module(verified.target_module)
        result["import_status"] = "success"

        if not verified.target_class:
            raise TargetClassMissing("manifest target_class is required; filename heuristics are forbidden")
        try:
            target = getattr(module, verified.target_class)
        except AttributeError as exc:
            raise AttributeError(f"target_class not found: {verified.target_class}") from exc

        instance = target()
        result["instantiate_status"] = "success"
        try:
            result["forward_status"] = _run_deterministic_forward(instance)
        except Exception as exc:
            result["forward_status"] = "failed"
            result["exception_class"] = type(exc).__name__
            result["exception_message"] = str(exc)
    except Exception as exc:
        if result["import_status"] != "success":
            result["import_status"] = "failed"
            result["instantiate_status"] = "skipped"
        else:
            result["instantiate_status"] = "failed"
        result["forward_status"] = "skipped"
        result["exception_class"] = type(exc).__name__
        result["exception_message"] = str(exc)
    finally:
        sys.path[:] = original_sys_path
        sys.dont_write_bytecode = original_dont_write_bytecode
        _remove_modules_loaded_from_input(verified.input_root)
        sys.modules.update(previous_modules)

    _write_runner_result(Path(args.output), result)
    _emit_runner_log(result)
    return 0


def verify_manifest(
    manifest_path: Path,
    *,
    expected_manifest_sha256: str | None = None,
) -> VerifiedManifest:
    payload = _read_manifest_payload(manifest_path)
    embedded_sha256 = payload.get("manifest_sha256")
    if not isinstance(embedded_sha256, str) or len(embedded_sha256) != 64:
        raise ManifestVerificationError("manifest_sha256 is missing or invalid")

    actual_manifest_sha256 = compute_manifest_sha256(payload)
    if embedded_sha256 != actual_manifest_sha256:
        raise ManifestVerificationError("manifest_sha256 mismatch")
    if expected_manifest_sha256 is not None and expected_manifest_sha256 != embedded_sha256:
        raise ManifestVerificationError("expected manifest_sha256 mismatch")

    target = payload.get("target")
    if not isinstance(target, dict):
        raise ManifestVerificationError("manifest target is missing or invalid")
    target_module = target.get("target_module")
    target_class = target.get("target_class")
    if not isinstance(target_module, str) or not _is_valid_module_name(target_module):
        raise ManifestVerificationError("target_module is missing or invalid")
    if target_class is not None and not isinstance(target_class, str):
        raise ManifestVerificationError("target_class is invalid")

    input_root = manifest_path.parent.resolve(strict=False)
    manifest_files = _verify_manifest_files(payload, input_root=input_root)
    _verify_target_module_is_manifest_target(
        manifest_files,
        target_module=target_module,
    )
    _verify_no_unexpected_input_files(input_root=input_root, manifest_files=set(manifest_files))

    return VerifiedManifest(
        payload=payload,
        input_root=input_root,
        manifest_sha256=embedded_sha256,
        target_module=target_module,
        target_class=target_class,
    )


def compute_manifest_sha256(payload: dict[str, Any]) -> str:
    canonical = copy.deepcopy(payload)
    canonical.pop("manifest_sha256", None)
    files = canonical.get("files")
    if isinstance(files, list):
        canonical["files"] = sorted(
            files,
            key=lambda item: (
                str(item.get("path", "")) if isinstance(item, dict) else "",
                str(item.get("content_kind", "")) if isinstance(item, dict) else "",
            ),
        )
    data = json.dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="b2-entrypoint")
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--nonce", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--request-id")
    parser.add_argument("--job-id")
    parser.add_argument("--manifest-sha256")
    return parser.parse_args(argv)


def _run_deterministic_forward(instance: Any) -> str:
    forward = getattr(instance, "forward", None)
    if not callable(forward):
        return "skipped_schema_unknown"
    args = _deterministic_forward_args(forward)
    if args is None:
        return "skipped_schema_unknown"
    forward(*args)
    return "success"


def _deterministic_forward_args(forward: Any) -> list[Any] | None:
    try:
        signature = inspect.signature(forward)
    except (TypeError, ValueError):
        return None

    required_positional = []
    for parameter in signature.parameters.values():
        if parameter.kind in {inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD}:
            continue
        if parameter.default is not inspect.Parameter.empty:
            continue
        if parameter.kind in {inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD}:
            required_positional.append(parameter)
            continue
        if parameter.kind is inspect.Parameter.KEYWORD_ONLY:
            return None

    if not required_positional:
        return []
    if len(required_positional) == 1:
        return [None]
    return None


def _read_manifest_payload(manifest_path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ManifestVerificationError(f"manifest read failed: {exc}") from exc
    if not isinstance(payload, dict):
        raise ManifestVerificationError("manifest root must be an object")
    return payload


def _verify_manifest_files(payload: dict[str, Any], *, input_root: Path) -> dict[str, dict[str, Any]]:
    files = payload.get("files")
    if not isinstance(files, list) or not files:
        raise ManifestVerificationError("manifest files are missing")
    manifest_files: dict[str, dict[str, Any]] = {}
    for item in files:
        if not isinstance(item, dict):
            raise ManifestVerificationError("manifest file entry must be an object")
        repo_path = _normalize_repo_path(item.get("path"))
        expected_sha256 = item.get("sha256")
        expected_size = item.get("size_bytes")
        if not isinstance(expected_sha256, str) or len(expected_sha256) != 64:
            raise ManifestVerificationError(f"invalid sha256 for {repo_path}")
        if not isinstance(expected_size, int):
            raise ManifestVerificationError(f"invalid size_bytes for {repo_path}")

        local_path = input_root.joinpath(*PurePosixPath(repo_path).parts)
        resolved = local_path.resolve(strict=False)
        if not _is_relative_to(resolved, input_root):
            raise ManifestVerificationError(f"manifest file escapes input root: {repo_path}")
        if not resolved.is_file():
            raise ManifestVerificationError(f"manifest file missing: {repo_path}")
        data = resolved.read_bytes()
        if len(data) != expected_size:
            raise ManifestVerificationError(f"manifest file size mismatch: {repo_path}")
        actual_sha256 = hashlib.sha256(data).hexdigest()
        if actual_sha256 != expected_sha256:
            raise ManifestVerificationError(f"manifest file sha256 mismatch: {repo_path}")
        manifest_files[repo_path] = item
    return manifest_files


def _verify_target_module_is_manifest_target(
    manifest_files: dict[str, dict[str, Any]],
    *,
    target_module: str,
) -> None:
    candidate_paths = _module_candidate_paths(target_module)
    for repo_path in candidate_paths:
        item = manifest_files.get(repo_path)
        if item is None:
            continue
        if item.get("content_kind") != "PYTHON":
            raise ManifestVerificationError("target_module must refer to a Python manifest file")
        if item.get("target_allowed") is not True:
            raise ManifestVerificationError("target_module is not marked target_allowed")
        return
    raise ManifestVerificationError("target_module is not present in manifest files")


def _verify_no_unexpected_input_files(*, input_root: Path, manifest_files: set[str]) -> None:
    allowed = {PurePosixPath("b2_input_manifest.json").as_posix(), *manifest_files}
    for path in input_root.rglob("*"):
        if not path.is_file():
            continue
        resolved = path.resolve(strict=False)
        if not _is_relative_to(resolved, input_root):
            raise ManifestVerificationError("input root contains escaping file")
        repo_path = resolved.relative_to(input_root).as_posix()
        if repo_path not in allowed:
            raise ManifestVerificationError(f"unexpected input file not listed in manifest: {repo_path}")


def _module_candidate_paths(module_name: str) -> list[str]:
    module_path = PurePosixPath(*module_name.split("."))
    return [
        f"{module_path.as_posix()}.py",
        module_path.joinpath("__init__.py").as_posix(),
    ]


def _normalize_repo_path(value: Any) -> str:
    if not isinstance(value, str) or not value or value == "." or "\x00" in value or "\\" in value:
        raise ManifestVerificationError("invalid manifest repo path")
    if len(value) >= 2 and value[1] == ":" and value[0].isalpha():
        raise ManifestVerificationError("invalid manifest repo path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ManifestVerificationError("invalid manifest repo path")
    return path.as_posix()


def _is_valid_module_name(value: str) -> bool:
    return all(part.isidentifier() for part in value.split(".")) and not value.startswith(".")


def _add_input_root_to_syspath(input_root: Path) -> None:
    text = str(input_root)
    if text not in sys.path:
        sys.path.insert(0, text)


def _base_result(*, request_id: str, nonce: str) -> dict[str, Any]:
    return {
        "schema_version": B2_SCHEMA_VERSION,
        "request_id": request_id,
        "nonce": nonce,
        "manifest_verified": False,
        "import_status": "skipped",
        "instantiate_status": "skipped",
        "forward_status": "skipped",
        "exception_class": None,
        "exception_message": None,
    }


def _write_runner_result(output_path: Path, result: dict[str, Any]) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=False),
        encoding="utf-8",
    )


def _emit_runner_log(result: dict[str, Any]) -> None:
    print(
        "B2_RUNNER_COMPLETE "
        f"manifest_verified={result.get('manifest_verified')} "
        f"import_status={result.get('import_status')} "
        f"instantiate_status={result.get('instantiate_status')} "
        f"forward_status={result.get('forward_status')}",
        flush=True,
    )


def _remove_target_modules(target_module: str) -> dict[str, Any]:
    names = {
        ".".join(target_module.split(".")[:index])
        for index in range(1, len(target_module.split(".")) + 1)
    }
    removed: dict[str, Any] = {}
    for name in names:
        if name in sys.modules:
            removed[name] = sys.modules.pop(name)
    return removed


def _remove_modules_loaded_from_input(input_root: Path) -> None:
    for name, module in list(sys.modules.items()):
        module_file = getattr(module, "__file__", None)
        if not module_file:
            continue
        try:
            resolved = Path(module_file).resolve(strict=False)
        except OSError:
            continue
        if _is_relative_to(resolved, input_root):
            sys.modules.pop(name, None)


def _is_relative_to(path: Path, base: Path) -> bool:
    try:
        path.relative_to(base)
        return True
    except ValueError:
        return False


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
