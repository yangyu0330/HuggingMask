"""Pure Docker inspect evidence validation for B-2 sandbox runs.

The functions in this module consume already-collected ``docker inspect`` JSON
fixtures. They do not invoke Docker, run subprocesses, or inspect the host.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from pathlib import PurePosixPath
from typing import Any

from sandbox.b2.host_runner import B2_FORBIDDEN_ENV_KEYS, B2_OUTPUT_CONTAINER_DIR
from sandbox.b2.schemas import B2_DEFAULT_IMPORT_ROOT, RuntimeEvidence

DEFAULT_ENV_ALLOWLIST_KEYS = frozenset(
    {
        "PATH",
        "PYTHONNOUSERSITE",
        "PYTHONDONTWRITEBYTECODE",
        "TRANSFORMERS_OFFLINE",
        "HF_HUB_OFFLINE",
        "HOME",
        "HF_HOME",
        "TORCH_HOME",
        "XDG_CACHE_HOME",
        "PIP_DISABLE_PIP_VERSION_CHECK",
        "OMP_NUM_THREADS",
        "MKL_NUM_THREADS",
        "TORCH_NUM_THREADS",
        "HUGGINGMASK_REQUEST_ID",
        "HUGGINGMASK_JOB_ID",
        "HUGGINGMASK_NONCE",
        "HUGGINGMASK_OUTPUT_DIR",
        "HUGGINGMASK_MANIFEST_SHA256",
    }
)


def validate_docker_inspect(
    inspect_payload: Mapping[str, Any] | Sequence[Mapping[str, Any]],
    *,
    expected_docker_runtime: str,
    expected_image_ref: str | None = None,
    expected_entrypoint: str = "/usr/bin/env",
    expected_python_executable: str = "/usr/local/bin/python",
    expected_runner_entrypoint: str = "/app/huggingmask_runner/b2_entrypoint.py",
    expected_input_container_dir: str = B2_DEFAULT_IMPORT_ROOT,
    expected_output_container_dir: str = B2_OUTPUT_CONTAINER_DIR,
    expected_input_source: str | None = None,
    expected_output_source: str | None = None,
    expected_pids_limit: int | None = None,
    expected_memory_limit: str | int | None = None,
    expected_cpu_limit: str | int | float | None = None,
    allowed_env_keys: Iterable[str] | None = None,
) -> tuple[bool, RuntimeEvidence, list[str]]:
    """Validate a Docker inspect fixture and return decision-builder evidence."""

    errors: list[str] = []
    item = _coerce_inspect_item(inspect_payload)
    if item is None:
        return False, RuntimeEvidence(), ["INSPECT_PAYLOAD_INVALID"]

    host_config = _mapping(item.get("HostConfig"))
    config = _mapping(item.get("Config"))
    mounts = [mount for mount in item.get("Mounts") or [] if isinstance(mount, Mapping)]
    args = [str(arg) for arg in item.get("Args") or []]
    security_opt = [str(value) for value in host_config.get("SecurityOpt") or []]
    cap_add = [str(value).upper() for value in host_config.get("CapAdd") or []]
    cap_drop = [str(value).upper() for value in host_config.get("CapDrop") or []]
    env_allowlist = set(allowed_env_keys or DEFAULT_ENV_ALLOWLIST_KEYS)

    runtime = _string_or_none(host_config.get("Runtime"))
    image_ref = _string_or_none(config.get("Image")) or _string_or_none(item.get("Image"))
    network_mode = _string_or_none(host_config.get("NetworkMode"))
    rootfs_readonly = host_config.get("ReadonlyRootfs") is True
    cap_drop_all = not cap_add and "ALL" in cap_drop
    no_new_privileges = any(value == "no-new-privileges" or value.startswith("no-new-privileges:") for value in security_opt)
    user = _string_or_none(config.get("User")) or ""
    non_root_user = _is_non_root_user(user)
    pids_limit = _int_or_none(host_config.get("PidsLimit"))
    memory_limit = _int_or_none(host_config.get("Memory"))
    cpu_limit = _actual_nano_cpus(host_config)

    if runtime != expected_docker_runtime:
        errors.append("RUNTIME_MISMATCH")
    if expected_image_ref is not None and expected_image_ref not in {config.get("Image"), item.get("Image")}:
        errors.append("IMAGE_MISMATCH")
    if network_mode != "none":
        errors.append("NETWORK_NOT_NONE")
    if not rootfs_readonly:
        errors.append("ROOTFS_NOT_READ_ONLY")
    if host_config.get("Privileged") is True:
        errors.append("PRIVILEGED_ENABLED")
    if cap_add:
        errors.append("CAP_ADD_PRESENT")
    if "ALL" not in cap_drop:
        errors.append("CAP_DROP_ALL_MISSING")
    if not no_new_privileges:
        errors.append("NO_NEW_PRIVILEGES_MISSING")
    if not non_root_user:
        errors.append("ROOT_USER")
    if expected_pids_limit is not None and pids_limit != expected_pids_limit:
        errors.append("PIDS_LIMIT_MISMATCH")
    if expected_memory_limit is not None and memory_limit != parse_bytes(expected_memory_limit):
        errors.append("MEMORY_LIMIT_MISMATCH")
    if expected_cpu_limit is not None and cpu_limit != parse_cpus(expected_cpu_limit):
        errors.append("CPU_LIMIT_MISMATCH")

    mount_errors = _validate_mounts(
        mounts,
        expected_input_container_dir=expected_input_container_dir,
        expected_output_container_dir=expected_output_container_dir,
        expected_input_source=expected_input_source,
        expected_output_source=expected_output_source,
    )
    errors.extend(mount_errors)
    mounts_ok = not mount_errors

    env_errors = _validate_env(config.get("Env") or [], args=args, allowed_env_keys=env_allowlist)
    errors.extend(env_errors)
    env_allowlist_ok = not env_errors

    errors.extend(
        _validate_entrypoint_args(
            path=_string_or_none(item.get("Path")),
            args=args,
            expected_entrypoint=expected_entrypoint,
            expected_python_executable=expected_python_executable,
            expected_runner_entrypoint=expected_runner_entrypoint,
        )
    )

    evidence = RuntimeEvidence(
        runtime=runtime,
        image_ref=image_ref,
        network_mode=network_mode,
        rootfs_readonly=rootfs_readonly,
        cap_drop_all=cap_drop_all,
        no_new_privileges=no_new_privileges,
        non_root_user=non_root_user,
        pids_limit=pids_limit,
        memory_limit=memory_limit,
        cpu_limit=cpu_limit,
        env_allowlist_ok=env_allowlist_ok,
        mounts_ok=mounts_ok,
    )
    return not errors, evidence, _dedupe(errors)


def parse_bytes(value: str | int) -> int:
    if isinstance(value, int):
        return value
    text = str(value).strip().lower()
    if not text:
        raise ValueError("empty byte value")
    suffixes = {
        "k": 1024,
        "kb": 1024,
        "m": 1024**2,
        "mb": 1024**2,
        "g": 1024**3,
        "gb": 1024**3,
        "t": 1024**4,
        "tb": 1024**4,
    }
    for suffix, multiplier in sorted(suffixes.items(), key=lambda item: len(item[0]), reverse=True):
        if text.endswith(suffix):
            return int(float(text[: -len(suffix)]) * multiplier)
    return int(text)


def parse_cpus(value: str | int | float) -> int:
    return int(float(value) * 1_000_000_000)


def _coerce_inspect_item(
    payload: Mapping[str, Any] | Sequence[Mapping[str, Any]],
) -> Mapping[str, Any] | None:
    if isinstance(payload, Mapping):
        return payload
    if isinstance(payload, Sequence) and payload and isinstance(payload[0], Mapping):
        return payload[0]
    return None


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _validate_mounts(
    mounts: list[Mapping[str, Any]],
    *,
    expected_input_container_dir: str,
    expected_output_container_dir: str,
    expected_input_source: str | None,
    expected_output_source: str | None,
) -> list[str]:
    errors: list[str] = []
    input_mount = _mount_by_destination(mounts, expected_input_container_dir)
    output_mount = _mount_by_destination(mounts, expected_output_container_dir)
    if input_mount is None:
        errors.append("INPUT_MOUNT_MISSING")
    elif _mount_is_writable(input_mount):
        errors.append("INPUT_MOUNT_NOT_READ_ONLY")
    elif expected_input_source is not None and not _same_host_path(
        _string_or_none(input_mount.get("Source")),
        expected_input_source,
    ):
        errors.append("INPUT_MOUNT_SOURCE_MISMATCH")
    if output_mount is None:
        errors.append("OUTPUT_MOUNT_MISSING")
    elif not _mount_is_writable(output_mount):
        errors.append("OUTPUT_MOUNT_NOT_WRITABLE")
    elif expected_output_source is not None and not _same_host_path(
        _string_or_none(output_mount.get("Source")),
        expected_output_source,
    ):
        errors.append("OUTPUT_MOUNT_SOURCE_MISMATCH")

    for mount in mounts:
        destination = _string_or_none(mount.get("Destination"))
        mount_type = _string_or_none(mount.get("Type"))
        if mount_type == "bind" and destination not in {expected_input_container_dir, expected_output_container_dir}:
            errors.append("UNEXPECTED_BIND_MOUNT")

    if input_mount is not None and output_mount is not None:
        if _paths_overlap(_string_or_none(input_mount.get("Destination")), _string_or_none(output_mount.get("Destination"))):
            errors.append("INPUT_OUTPUT_MOUNT_OVERLAP")
        if _paths_overlap(_string_or_none(input_mount.get("Source")), _string_or_none(output_mount.get("Source"))):
            errors.append("INPUT_OUTPUT_MOUNT_OVERLAP")
    return _dedupe(errors)


def _validate_env(
    config_env: Iterable[Any],
    *,
    args: list[str],
    allowed_env_keys: set[str],
) -> list[str]:
    errors: list[str] = []
    for token in config_env:
        key = _env_key(str(token))
        if key in B2_FORBIDDEN_ENV_KEYS:
            errors.append("FORBIDDEN_ENV")

    for token in _runner_env_assignments(args):
        key = _env_key(token)
        if key in B2_FORBIDDEN_ENV_KEYS:
            errors.append("FORBIDDEN_ENV")
        elif key not in allowed_env_keys:
            errors.append("ENV_NOT_ALLOWLISTED")
    return _dedupe(errors)


def _validate_entrypoint_args(
    *,
    path: str | None,
    args: list[str],
    expected_entrypoint: str,
    expected_python_executable: str,
    expected_runner_entrypoint: str,
) -> list[str]:
    errors: list[str] = []
    if path != expected_entrypoint:
        errors.append("ENTRYPOINT_MISMATCH")
    if not args or args[0] != "-i":
        errors.append("ENV_I_MISSING")
        return errors
    try:
        python_index = args.index(expected_python_executable)
    except ValueError:
        errors.append("PYTHON_EXECUTABLE_MISSING")
        return errors
    python_args = args[python_index + 1 :]
    if "-I" not in python_args:
        errors.append("PYTHON_ISOLATED_MODE_MISSING")
    if "-S" not in python_args:
        errors.append("PYTHON_NO_SITE_MISSING")
    if expected_runner_entrypoint not in python_args:
        errors.append("RUNNER_ENTRYPOINT_MISMATCH")
    else:
        runner_index = python_args.index(expected_runner_entrypoint)
        for token in python_args[:runner_index]:
            if token not in {"-I", "-S"}:
                errors.append("UNEXPECTED_PRE_RUNNER_ARG")
                break
    return _dedupe(errors)


def _mount_by_destination(mounts: list[Mapping[str, Any]], destination: str) -> Mapping[str, Any] | None:
    for mount in mounts:
        if mount.get("Destination") == destination:
            return mount
    return None


def _mount_is_writable(mount: Mapping[str, Any]) -> bool:
    if "RW" in mount:
        return mount.get("RW") is True
    mode = str(mount.get("Mode") or "").lower()
    return "rw" in mode and "ro" not in mode.split(",")


def _actual_nano_cpus(host_config: Mapping[str, Any]) -> int | None:
    nano_cpus = _int_or_none(host_config.get("NanoCpus"))
    if nano_cpus:
        return nano_cpus
    quota = _int_or_none(host_config.get("CpuQuota"))
    period = _int_or_none(host_config.get("CpuPeriod"))
    if quota and period:
        return int((quota / period) * 1_000_000_000)
    return None


def _runner_env_assignments(args: list[str]) -> list[str]:
    if not args or args[0] != "-i":
        return []
    output: list[str] = []
    for token in args[1:]:
        if "=" not in token or token.startswith("-"):
            break
        output.append(token)
    return output


def _env_key(token: str) -> str:
    return token.split("=", 1)[0]


def _is_non_root_user(user: str) -> bool:
    if not user:
        return False
    first = user.split(":", 1)[0]
    return first not in {"", "0", "root"}


def _paths_overlap(first: str | None, second: str | None) -> bool:
    if not first or not second:
        return False
    first_path = PurePosixPath(first.replace("\\", "/"))
    second_path = PurePosixPath(second.replace("\\", "/"))
    return first_path == second_path or _is_relative_to(first_path, second_path) or _is_relative_to(second_path, first_path)


def _same_host_path(actual: str | None, expected: str) -> bool:
    if not actual:
        return False
    return _normalize_host_path(actual) == _normalize_host_path(expected)


def _normalize_host_path(value: str) -> str:
    return str(value).replace("\\", "/").rstrip("/")


def _is_relative_to(path: PurePosixPath, base: PurePosixPath) -> bool:
    try:
        path.relative_to(base)
        return True
    except ValueError:
        return False


def _string_or_none(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def _int_or_none(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    return None


def _dedupe(items: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    output: list[str] = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        output.append(item)
    return output
