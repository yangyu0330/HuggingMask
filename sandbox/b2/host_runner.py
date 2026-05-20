"""Host-side Docker/runsc command planning for B-2 sandbox runs.

This module only builds command argv lists and lifecycle plans. It does not
execute subprocesses, create containers, inspect Docker state, or parse logs.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping

from sandbox.b2.schemas import B2_DEFAULT_IMPORT_ROOT, B2_INPUT_MANIFEST_FILENAME

B2_OUTPUT_CONTAINER_DIR = "/tmp/huggingmask"
B2_RUNNER_RESULT_FILENAME = "runner_result.json"

B2_FORBIDDEN_ENV_KEYS = frozenset(
    {
        "HF_TOKEN",
        "HUGGINGFACE_HUB_TOKEN",
        "GITHUB_TOKEN",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "PIP_INDEX_URL",
        "PIP_EXTRA_INDEX_URL",
        "PYTHONSTARTUP",
        "PYTHONHOME",
        "PYTHONPATH",
        "LD_LIBRARY_PATH",
        "LD_PRELOAD",
        "CUDA_VISIBLE_DEVICES",
    }
)

_DEFAULT_ENV_ALLOWLIST: tuple[tuple[str, str], ...] = (
    ("PATH", "/usr/local/bin:/usr/bin:/bin"),
    ("PYTHONNOUSERSITE", "1"),
    ("PYTHONDONTWRITEBYTECODE", "1"),
    ("TRANSFORMERS_OFFLINE", "1"),
    ("HF_HUB_OFFLINE", "1"),
    ("HOME", "/tmp"),
    ("HF_HOME", "/tmp/hf"),
    ("TORCH_HOME", "/tmp/torch"),
    ("XDG_CACHE_HOME", "/tmp/cache"),
    ("PIP_DISABLE_PIP_VERSION_CHECK", "1"),
    ("OMP_NUM_THREADS", "4"),
    ("MKL_NUM_THREADS", "4"),
    ("TORCH_NUM_THREADS", "4"),
)


@dataclass(frozen=True)
class B2DockerRuntimeConfig:
    image_ref: str
    docker_runtime: str
    docker_binary: str = "docker"
    env_entrypoint: str = "/usr/bin/env"
    python_executable: str = "/usr/local/bin/python"
    runner_entrypoint: str = "/app/huggingmask_runner/b2_entrypoint.py"
    input_container_dir: str = B2_DEFAULT_IMPORT_ROOT
    output_container_dir: str = B2_OUTPUT_CONTAINER_DIR
    pids_limit: int = 128
    memory_limit: str = "4g"
    cpus: str = "2"
    user: str = "1000:1000"
    tmpfs_mounts: tuple[str, ...] = (
        "/tmp:rw,noexec,nosuid,nodev,size=512m",
        "/run:rw,noexec,nosuid,nodev,size=64m",
    )
    env_allowlist: Mapping[str, str] = field(default_factory=lambda: dict(_DEFAULT_ENV_ALLOWLIST))

    def __post_init__(self) -> None:
        if not self.image_ref:
            raise ValueError("image_ref is required")
        if not self.docker_runtime:
            raise ValueError("docker_runtime is required")
        for path_value in (
            self.env_entrypoint,
            self.python_executable,
            self.runner_entrypoint,
            self.input_container_dir,
            self.output_container_dir,
        ):
            _validate_container_absolute_path(path_value)
        _validate_env_allowlist(self.env_allowlist)

    @property
    def manifest_container_path(self) -> str:
        return f"{self.input_container_dir.rstrip('/')}/{B2_INPUT_MANIFEST_FILENAME}"

    @property
    def runner_result_container_path(self) -> str:
        return f"{self.output_container_dir.rstrip('/')}/{B2_RUNNER_RESULT_FILENAME}"


@dataclass(frozen=True)
class B2SandboxJob:
    request_id: str
    job_id: str
    input_dir: Path
    output_dir: Path
    nonce: str
    config: B2DockerRuntimeConfig
    container_name: str | None = None
    manifest_sha256: str | None = None
    repo_root: Path | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "input_dir", Path(self.input_dir))
        object.__setattr__(self, "output_dir", Path(self.output_dir))
        if self.repo_root is not None:
            object.__setattr__(self, "repo_root", Path(self.repo_root))
        if not self.request_id:
            raise ValueError("request_id is required")
        if not self.job_id:
            raise ValueError("job_id is required")
        if not self.nonce:
            raise ValueError("nonce is required")

    @property
    def effective_container_name(self) -> str:
        return self.container_name or f"huggingmask-b2-{_safe_docker_name(self.request_id)}-{_safe_docker_name(self.job_id)}"


@dataclass(frozen=True)
class B2LifecycleStep:
    name: str
    command: list[str]


@dataclass(frozen=True)
class B2LifecyclePlan:
    job: B2SandboxJob
    steps: tuple[B2LifecycleStep, ...]

    @property
    def step_names(self) -> list[str]:
        return [step.name for step in self.steps]


def build_sandbox_job_from_context(
    context,
    *,
    config: B2DockerRuntimeConfig,
    output_dir: str | Path,
    repo_root: str | Path | None = None,
    container_name: str | None = None,
) -> B2SandboxJob:
    """Build a future-connectable host runner job from a pipeline context."""

    return B2SandboxJob(
        request_id=context.request_id,
        job_id=context.job_id,
        input_dir=context.input_dir,
        output_dir=Path(output_dir),
        nonce=context.nonce,
        config=config,
        container_name=container_name,
        manifest_sha256=getattr(context.manifest, "manifest_sha256", None),
        repo_root=Path(repo_root) if repo_root is not None else None,
    )


def build_docker_create_command(
    job: B2SandboxJob,
    *,
    manifest_container_path: str | None = None,
) -> list[str]:
    """Return a Docker create argv list without executing it."""

    _validate_job_mounts(job)
    config = job.config
    manifest_path = manifest_container_path or config.manifest_container_path
    _validate_container_absolute_path(manifest_path)

    command: list[str] = [
        config.docker_binary,
        "create",
        "--name",
        job.effective_container_name,
        f"--runtime={config.docker_runtime}",
        "--entrypoint",
        config.env_entrypoint,
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        f"--pids-limit={config.pids_limit}",
        f"--memory={config.memory_limit}",
        f"--cpus={config.cpus}",
        f"--user={config.user}",
        "--pull=never",
    ]
    for tmpfs in config.tmpfs_mounts:
        command.extend(["--tmpfs", tmpfs])
    command.extend(
        [
            "-v",
            _bind_mount_arg(job.input_dir, config.input_container_dir, "ro"),
            "-v",
            _bind_mount_arg(job.output_dir, config.output_container_dir, "rw"),
            config.image_ref,
            "-i",
        ]
    )
    command.extend(_env_tokens(job))
    command.extend(
        [
            config.python_executable,
            "-I",
            "-S",
            config.runner_entrypoint,
            "--manifest",
            manifest_path,
            "--nonce",
            job.nonce,
            "--output",
            config.runner_result_container_path,
            "--request-id",
            job.request_id,
            "--job-id",
            job.job_id,
        ]
    )
    if job.manifest_sha256:
        command.extend(["--manifest-sha256", job.manifest_sha256])
    return command


def build_docker_lifecycle_plan(job: B2SandboxJob) -> B2LifecyclePlan:
    """Return the planned Docker lifecycle commands without executing them."""

    container = job.effective_container_name
    docker = job.config.docker_binary
    local_runner_result = job.output_dir / B2_RUNNER_RESULT_FILENAME
    steps = (
        B2LifecycleStep("create", build_docker_create_command(job)),
        B2LifecycleStep("start", [docker, "start", container]),
        B2LifecycleStep("wait", [docker, "wait", container]),
        B2LifecycleStep("inspect", [docker, "inspect", container]),
        B2LifecycleStep("logs", [docker, "logs", container]),
        B2LifecycleStep("cp", [docker, "cp", f"{container}:{job.config.runner_result_container_path}", str(local_runner_result)]),
        B2LifecycleStep("rm", [docker, "rm", "-f", container]),
    )
    return B2LifecyclePlan(job=job, steps=steps)


def _env_tokens(job: B2SandboxJob) -> list[str]:
    env = dict(job.config.env_allowlist)
    env.update(
        {
            "HUGGINGMASK_REQUEST_ID": job.request_id,
            "HUGGINGMASK_JOB_ID": job.job_id,
            "HUGGINGMASK_NONCE": job.nonce,
            "HUGGINGMASK_OUTPUT_DIR": job.config.output_container_dir,
        }
    )
    if job.manifest_sha256:
        env["HUGGINGMASK_MANIFEST_SHA256"] = job.manifest_sha256
    _validate_env_allowlist(env)
    return [f"{key}={value}" for key, value in env.items()]


def _validate_env_allowlist(env: Mapping[str, str]) -> None:
    for key, value in env.items():
        if not key or "=" in key or "\x00" in key:
            raise ValueError(f"invalid env key: {key!r}")
        if key in B2_FORBIDDEN_ENV_KEYS:
            raise ValueError(f"forbidden env key: {key}")
        if "\x00" in str(value):
            raise ValueError(f"invalid env value for {key}")


def _validate_job_mounts(job: B2SandboxJob) -> None:
    input_dir = job.input_dir.resolve(strict=False)
    output_dir = job.output_dir.resolve(strict=False)
    if _paths_overlap(input_dir, output_dir):
        raise ValueError("B-2 host runner requires separate input and output mounts")
    if job.repo_root is None:
        return
    repo_root = job.repo_root.resolve(strict=False)
    if input_dir == repo_root or output_dir == repo_root:
        raise ValueError("B-2 host runner refuses to mount the whole repository root")


def _bind_mount_arg(host_path: Path, container_path: str, mode: str) -> str:
    _validate_container_absolute_path(container_path)
    if mode not in {"ro", "rw"}:
        raise ValueError("mount mode must be ro or rw")
    return f"{Path(host_path)}:{container_path}:{mode}"


def _paths_overlap(first: Path, second: Path) -> bool:
    return first == second or first.is_relative_to(second) or second.is_relative_to(first)


def _validate_container_absolute_path(path_value: str) -> None:
    if not path_value or "\x00" in path_value or not path_value.startswith("/"):
        raise ValueError(f"container path must be absolute POSIX path: {path_value!r}")


def _safe_docker_name(value: str) -> str:
    cleaned = "".join(ch if ch.isalnum() or ch in {"-", "_", "."} else "-" for ch in value.lower())
    return cleaned.strip("-._") or "job"
