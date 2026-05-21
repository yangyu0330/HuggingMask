from pathlib import Path

import pytest

from sandbox.b2.host_runner import (
    B2DockerRuntimeConfig,
    B2SandboxJob,
    build_docker_create_command,
    build_docker_lifecycle_plan,
    build_sandbox_job_from_context,
)


def _config(**overrides) -> B2DockerRuntimeConfig:
    payload = {
        "image_ref": "huggingmask/b2-runner@sha256:" + "1" * 64,
        "docker_runtime": "runsc-b2-debug",
        "memory_limit": "2g",
        "cpus": "1.5",
    }
    payload.update(overrides)
    return B2DockerRuntimeConfig(**payload)


def _job(tmp_path: Path, **overrides) -> B2SandboxJob:
    input_dir = tmp_path / "staging" / "input"
    output_dir = tmp_path / "evidence"
    repo_root = tmp_path / "repo"
    input_dir.mkdir(parents=True)
    output_dir.mkdir()
    repo_root.mkdir()
    payload = {
        "request_id": "req-123",
        "job_id": "job-456",
        "input_dir": input_dir,
        "output_dir": output_dir,
        "nonce": "nonce-abc",
        "manifest_sha256": "2" * 64,
        "config": _config(),
        "repo_root": repo_root,
    }
    payload.update(overrides)
    return B2SandboxJob(**payload)


def _mount_args(command: list[str]) -> list[str]:
    return [command[index + 1] for index, token in enumerate(command) if token == "-v"]


def _env_tokens(command: list[str], config: B2DockerRuntimeConfig) -> list[str]:
    start = command.index("-i") + 1
    end = command.index(config.python_executable)
    return command[start:end]


def test_docker_create_command_is_argv_create_not_run_or_rm(tmp_path: Path) -> None:
    job = _job(tmp_path)
    command = build_docker_create_command(job)

    assert isinstance(command, list)
    assert all(isinstance(item, str) for item in command)
    assert command[:2] == ["docker", "create"]
    assert command[1] != "run"
    assert "--rm" not in command


def test_runtime_and_security_options_come_from_config(tmp_path: Path) -> None:
    job = _job(tmp_path, config=_config(docker_runtime="runsc-custom", user="2000:2000", pids_limit=64))
    command = build_docker_create_command(job)

    assert "--runtime=runsc-custom" in command
    assert "--network=none" in command
    assert "--read-only" in command
    assert "--cap-drop=ALL" in command
    assert "--security-opt=no-new-privileges" in command
    assert "--pids-limit=64" in command
    assert "--memory=2g" in command
    assert "--cpus=1.5" in command
    assert "--user=2000:2000" in command
    assert "--pull=never" in command
    assert "--entrypoint" in command
    assert command[command.index("--entrypoint") + 1] == "/usr/bin/env"
    assert "--tmpfs" in command


def test_input_mount_is_read_only_and_output_mount_is_separate_writable(tmp_path: Path) -> None:
    job = _job(tmp_path)
    command = build_docker_create_command(job)
    mounts = _mount_args(command)

    assert f"{job.input_dir}:{job.config.input_container_dir}:ro" in mounts
    assert f"{job.output_dir}:{job.config.output_container_dir}:rw" in mounts
    assert all(not mount.startswith(f"{job.repo_root}:") for mount in mounts)
    assert not any(mount.startswith(f"{job.input_dir}:") and not mount.endswith(":ro") for mount in mounts)


def test_whole_repo_root_mount_is_rejected(tmp_path: Path) -> None:
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    job = B2SandboxJob(
        request_id="req",
        job_id="job",
        input_dir=repo_root,
        output_dir=tmp_path / "evidence",
        nonce="nonce",
        config=_config(),
        repo_root=repo_root,
    )

    with pytest.raises(ValueError, match="whole repository root"):
        build_docker_create_command(job)


def test_overlapping_input_and_output_mounts_are_rejected(tmp_path: Path) -> None:
    base_job = _job(tmp_path)
    job = B2SandboxJob(
        request_id=base_job.request_id,
        job_id=base_job.job_id,
        input_dir=base_job.input_dir,
        output_dir=base_job.input_dir,
        nonce=base_job.nonce,
        manifest_sha256=base_job.manifest_sha256,
        config=base_job.config,
        repo_root=base_job.repo_root,
    )

    with pytest.raises(ValueError, match="separate input and output mounts"):
        build_docker_create_command(job)


def test_overlapping_input_and_output_mounts_are_rejected_without_repo_root(tmp_path: Path) -> None:
    shared_dir = tmp_path / "shared"
    shared_dir.mkdir()
    job = B2SandboxJob(
        request_id="req",
        job_id="job",
        input_dir=shared_dir,
        output_dir=shared_dir,
        nonce="nonce",
        config=_config(),
        repo_root=None,
    )

    with pytest.raises(ValueError, match="separate input and output mounts"):
        build_docker_create_command(job)


def test_env_uses_explicit_allowlist_without_pythonpath_or_host_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HF_TOKEN", "host-secret")
    monkeypatch.setenv("PYTHONPATH", "/host/repo")
    job = _job(tmp_path)
    command = build_docker_create_command(job)
    env_tokens = _env_tokens(command, job.config)
    env_keys = {token.split("=", 1)[0] for token in env_tokens}

    assert "-e" not in command
    assert "--env" not in command
    assert "HF_TOKEN" not in env_keys
    assert "PYTHONPATH" not in env_keys
    assert "HUGGINGMASK_REQUEST_ID" in env_keys
    assert "HUGGINGMASK_JOB_ID" in env_keys
    assert "HUGGINGMASK_NONCE" in env_keys
    assert "PATH" in env_keys
    assert "HUGGINGMASK_NONCE=nonce-abc" in env_tokens


def test_forbidden_env_allowlist_entry_is_rejected() -> None:
    with pytest.raises(ValueError, match="forbidden env key"):
        B2DockerRuntimeConfig(
            image_ref="huggingmask/b2-runner@sha256:" + "1" * 64,
            docker_runtime="runsc-b2-debug",
            env_allowlist={"PYTHONPATH": "/sandbox/input"},
        )


def test_runner_entrypoint_manifest_nonce_and_output_are_explicit(tmp_path: Path) -> None:
    job = _job(tmp_path)
    command = build_docker_create_command(job)

    assert job.config.image_ref in command
    python_index = command.index(job.config.python_executable)
    assert command[python_index : python_index + 4] == [
        "/usr/local/bin/python",
        "-I",
        "-S",
        "/app/huggingmask_runner/b2_entrypoint.py",
    ]
    assert command[command.index("--manifest") + 1] == "/sandbox/input/b2_input_manifest.json"
    assert command[command.index("--nonce") + 1] == "nonce-abc"
    assert command[command.index("--output") + 1] == "/tmp/huggingmask/runner_result.json"
    assert command[command.index("--request-id") + 1] == "req-123"
    assert command[command.index("--job-id") + 1] == "job-456"


def test_lifecycle_plan_order_uses_create_start_wait_inspect_logs_cp_rm(tmp_path: Path) -> None:
    job = _job(tmp_path)
    plan = build_docker_lifecycle_plan(job)

    assert plan.step_names == ["create", "start", "wait", "inspect", "logs", "cp", "rm"]
    assert plan.steps[0].command[:2] == ["docker", "create"]
    assert plan.steps[1].command == ["docker", "start", job.effective_container_name]
    assert plan.steps[2].command == ["docker", "wait", job.effective_container_name]
    assert plan.steps[3].command == ["docker", "inspect", job.effective_container_name]
    assert plan.steps[4].command == ["docker", "logs", job.effective_container_name]
    assert plan.steps[5].command == [
        "docker",
        "cp",
        f"{job.effective_container_name}:/tmp/huggingmask/runner_result.json",
        str(job.output_dir / "runner_result.json"),
    ]
    assert plan.steps[6].command == ["docker", "rm", "-f", job.effective_container_name]


def test_job_can_be_built_from_pipeline_context_shape(tmp_path: Path) -> None:
    class _Manifest:
        manifest_sha256 = "3" * 64

    class _Context:
        request_id = "req-context"
        job_id = "job-context"
        input_dir = tmp_path / "input"
        nonce = "nonce-context"
        manifest = _Manifest()

    job = build_sandbox_job_from_context(
        _Context(),
        config=_config(docker_runtime="runtime-from-config"),
        output_dir=tmp_path / "evidence",
        repo_root=tmp_path / "repo",
    )
    command = build_docker_create_command(job)

    assert job.request_id == "req-context"
    assert job.manifest_sha256 == "3" * 64
    assert "--runtime=runtime-from-config" in command
