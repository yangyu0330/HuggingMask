import json
from pathlib import Path, PurePosixPath
from typing import Any

from analyzer.classifier import build_artifact_ref
from analyzer.orchestrator import build_minimal_request, run_validation_job
from analyzer.schemas import ArtifactRef, PolicyInfo
from analyzer.snapshot_resolver import SnapshotSourceResolver, build_source_loader
from sandbox.b2.host_runner import B2DockerRuntimeConfig
from sandbox.b2.host_runner_executor import B2HostRunner, CommandResult


IMAGE_REF = "huggingmask/b2-runner@sha256:" + "1" * 64


class FixtureCommandRunner:
    def __init__(
        self,
        *,
        pre_inspect_overrides: dict[str, Any] | None = None,
        post_inspect_overrides: dict[str, Any] | None = None,
        runsc_logs: str | None = None,
        runner_result_mode: str = "clean",
        mutate_input_on_create: bool = False,
    ) -> None:
        self.pre_inspect_overrides = pre_inspect_overrides or {}
        self.post_inspect_overrides = post_inspect_overrides or {}
        self.runsc_logs = runsc_logs if runsc_logs is not None else _clean_log()
        self.runner_result_mode = runner_result_mode
        self.mutate_input_on_create = mutate_input_on_create
        self.calls: list[tuple[str, list[str]]] = []
        self._nonce_by_container: dict[str, str] = {}
        self._mount_sources_by_container: dict[str, tuple[str, str]] = {}

    def __call__(self, step_name: str, argv: list[str]) -> CommandResult:
        self.calls.append((step_name, argv))
        if step_name == "create":
            container_name = argv[argv.index("--name") + 1]
            nonce = argv[argv.index("--nonce") + 1]
            self._nonce_by_container[container_name] = nonce
            self._mount_sources_by_container[container_name] = _mount_sources_from_create_command(argv)
            if self.mutate_input_on_create:
                _mutate_primary_input(_input_mount_from_create_command(argv))
            return CommandResult(
                fixtures={
                    "pre_start_inspect": _inspect_fixture(
                        *self._mount_sources_by_container[container_name],
                        **self.pre_inspect_overrides,
                    )
                }
            )
        if step_name == "inspect":
            container_name = argv[-1]
            sources = self._mount_sources_by_container[container_name]
            return CommandResult(fixtures={"post_start_inspect": _inspect_fixture(*sources, **self.post_inspect_overrides)})
        if step_name == "logs":
            return CommandResult(fixtures={"runsc_logs": self.runsc_logs})
        if step_name == "cp":
            if self.runner_result_mode == "missing":
                return CommandResult()
            container_name = argv[2].split(":", 1)[0]
            nonce = self._nonce_by_container[container_name]
            if self.runner_result_mode == "malformed":
                return CommandResult(fixtures={"runner_result": {"schema_version": "1.0"}})
            return CommandResult(fixtures={"runner_result": _runner_result(nonce=nonce)})
        return CommandResult()


def _policy() -> PolicyInfo:
    return PolicyInfo(
        policy_version="policy-2026.05.20",
        whitelist_version="wl-2026.05.20",
        opcode_policy_version="opcode-2026.05.20",
        config_schema_version="cfg-2026.05.20",
        runtime_profile_version="rt-2026.05.20",
    )


def _config() -> B2DockerRuntimeConfig:
    return B2DockerRuntimeConfig(
        image_ref=IMAGE_REF,
        docker_runtime="runsc-b2-debug",
        memory_limit="2g",
        cpus="1.5",
    )


def _b2_source(class_name: str = "DemoModel") -> str:
    return (
        "import torch\n"
        f"class {class_name}:\n"
        "    def forward(self, x):\n"
        "        return torch.special.expit(x)\n"
    )


def _write_snapshot(root: Path, repo_path: str, source: str | bytes) -> None:
    data = source.encode("utf-8") if isinstance(source, str) else source
    path = root.joinpath(*PurePosixPath(repo_path).parts)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def _artifact(repo_path: str, source: str | bytes) -> ArtifactRef:
    return build_artifact_ref(repo_path, content=source, source_url=f"https://huggingface.co/org/demo/{repo_path}")


def _run_request(
    tmp_path: Path,
    *,
    artifacts: list[ArtifactRef],
    snapshot_sources: dict[str, str | bytes],
    command_runner: FixtureCommandRunner,
    request_id: str = "req-full-fixture",
    job_id: str = "job-full-fixture",
):
    snapshot_root = tmp_path / "snapshot"
    for repo_path, source in snapshot_sources.items():
        _write_snapshot(snapshot_root, repo_path, source)
    request = build_minimal_request(
        request_id=request_id,
        job_id=job_id,
        policy=_policy(),
        artifacts=artifacts,
    )
    request.model_snapshot_root = str(snapshot_root)
    resolver = SnapshotSourceResolver.from_request(request)
    host_runner = B2HostRunner(
        config=_config(),
        output_dir=tmp_path / "host-runner",
        command_runner=command_runner,
        repo_root=tmp_path / "repo-root",
    )
    return run_validation_job(
        request,
        source_loader=build_source_loader(resolver),
        source_resolver=resolver,
        b2_runner=host_runner,
        b2_output_dir=tmp_path / "pipeline-staging",
    )


def _inspect_fixture(input_source: str = "/job/input", output_source: str = "/job/out", **host_overrides: Any) -> dict:
    host_config = {
        "Runtime": "runsc-b2-debug",
        "NetworkMode": "none",
        "ReadonlyRootfs": True,
        "Privileged": False,
        "CapAdd": [],
        "CapDrop": ["ALL"],
        "SecurityOpt": ["no-new-privileges"],
        "PidsLimit": 128,
        "Memory": 2 * 1024 * 1024 * 1024,
        "NanoCpus": 1_500_000_000,
    }
    host_config.update(host_overrides)
    return {
        "Path": "/usr/bin/env",
        "Args": [
            "-i",
            "PATH=/usr/local/bin:/usr/bin:/bin",
            "PYTHONNOUSERSITE=1",
            "PYTHONDONTWRITEBYTECODE=1",
            "HUGGINGMASK_REQUEST_ID=req-full-fixture",
            "HUGGINGMASK_JOB_ID=job-full-fixture",
            "HUGGINGMASK_NONCE=nonce-placeholder",
            "/usr/local/bin/python",
            "-I",
            "-S",
            "/app/huggingmask_runner/b2_entrypoint.py",
            "--manifest",
            "/sandbox/input/b2_input_manifest.json",
        ],
        "Config": {
            "Image": IMAGE_REF,
            "User": "1000:1000",
            "Env": ["PATH=/usr/local/bin:/usr/bin:/bin"],
        },
        "HostConfig": host_config,
        "Mounts": [
            {"Type": "bind", "Source": input_source, "Destination": "/sandbox/input", "Mode": "ro", "RW": False},
            {"Type": "bind", "Source": output_source, "Destination": "/tmp/huggingmask", "Mode": "rw", "RW": True},
        ],
    }


def _runner_result(*, nonce: str) -> dict:
    return {
        "schema_version": "1.0",
        "request_id": "req-full-fixture",
        "nonce": nonce,
        "manifest_verified": True,
        "import_status": "success",
        "instantiate_status": "success",
        "forward_status": "success",
    }


def _clean_log() -> str:
    return '1 openat(AT_FDCWD, "/sandbox/input/modeling_demo.py", O_RDONLY|O_CLOEXEC) = 3'


def _security_log() -> str:
    return """
1 execve("/bin/sh", ["sh"], 0x7ffd) = 0
2 socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) = 3
3 openat(AT_FDCWD, "/sandbox/input/modeling_demo.py", O_WRONLY|O_CREAT, 0644) = -1 EROFS
"""


def _input_mount_from_create_command(argv: list[str]) -> Path:
    return Path(_mount_sources_from_create_command(argv)[0])


def _mount_sources_from_create_command(argv: list[str]) -> tuple[str, str]:
    input_source = ""
    output_source = ""
    mounts = [argv[index + 1] for index, token in enumerate(argv) if token == "-v"]
    for mount in mounts:
        host_path, container_path, mode = mount.rsplit(":", 2)
        if container_path == "/sandbox/input" and mode == "ro":
            input_source = host_path
        elif container_path == "/tmp/huggingmask" and mode == "rw":
            output_source = host_path
    if not input_source or not output_source:
        raise AssertionError("expected mounts not found")
    return input_source, output_source


def _mutate_primary_input(input_root: Path) -> None:
    manifest = json.loads((input_root / "b2_input_manifest.json").read_text(encoding="utf-8"))
    primary_path = manifest["primary_repo_path"]
    target = input_root.joinpath(*PurePosixPath(primary_path).parts)
    data = bytearray(target.read_bytes())
    data[-2] = ord("#") if data[-2] != ord("#") else ord(" ")
    target.write_bytes(data)


def test_direct_python_b2_clean_fixture_flow_is_policy_review_not_deployable(tmp_path: Path) -> None:
    source = _b2_source("DirectModel")
    runner = FixtureCommandRunner()
    response = _run_request(
        tmp_path,
        artifacts=[_artifact("modeling_direct.py", source)],
        snapshot_sources={"modeling_direct.py": source},
        command_runner=runner,
    )

    result = response.artifact_results[0]
    sandbox_check = result.details["sandbox_check"]
    assert sandbox_check["decision"] == "B2_POLICY_REVIEW_REQUIRED"
    assert sandbox_check["deployable"] is False
    assert sandbox_check["policy_gate"]["reason_code"] == "SANDBOX_POLICY_GATE_REQUIRED"
    assert [name for name, _ in runner.calls] == ["create", "start", "wait", "inspect", "logs", "cp", "rm"]


def test_config_auto_map_sibling_uses_host_runner_and_parent_summary_refreshes(tmp_path: Path) -> None:
    config_source = json.dumps({"auto_map": {"AutoModel": "modeling_linked.LinkedModel"}})
    linked_source = _b2_source("LinkedModel")
    runner = FixtureCommandRunner()
    response = _run_request(
        tmp_path,
        artifacts=[_artifact("config.json", config_source)],
        snapshot_sources={"config.json": config_source, "modeling_linked.py": linked_source},
        command_runner=runner,
    )

    by_path = {item.artifact.repo_path: item for item in response.artifact_results}
    linked_check = by_path["modeling_linked.py"].details["sandbox_check"]
    cfg_result = by_path["config.json"]
    assert linked_check["decision"] == "B2_POLICY_REVIEW_REQUIRED"
    assert cfg_result.details["linked_code_results"][0]["details"]["sandbox_check"]["decision"] == (
        "B2_POLICY_REVIEW_REQUIRED"
    )
    assert cfg_result.details["linked_code_edges"][0]["sandbox_decision"] == "B2_POLICY_REVIEW_REQUIRED"


def test_runsc_security_fixture_blocks_artifact_sandbox_check(tmp_path: Path) -> None:
    source = _b2_source("SecurityEventModel")
    response = _run_request(
        tmp_path,
        artifacts=[_artifact("modeling_security.py", source)],
        snapshot_sources={"modeling_security.py": source},
        command_runner=FixtureCommandRunner(runsc_logs=_security_log()),
    )

    sandbox_check = response.artifact_results[0].details["sandbox_check"]
    assert sandbox_check["decision"] == "BLOCKED_SECURITY_EVENT"
    assert sandbox_check["policy_gate"]["reason_code"] == "SANDBOX_SECURITY_EVENT"
    assert sandbox_check["security_events"]["unexpected_execve"]
    assert sandbox_check["security_events"]["network_events"]
    assert sandbox_check["security_events"]["blocked_writes"]


def test_pre_start_inspect_drift_maps_to_sandbox_infra_error(tmp_path: Path) -> None:
    source = _b2_source("PreDriftModel")
    response = _run_request(
        tmp_path,
        artifacts=[_artifact("modeling_pre_drift.py", source)],
        snapshot_sources={"modeling_pre_drift.py": source},
        command_runner=FixtureCommandRunner(pre_inspect_overrides={"Runtime": "runc"}),
    )

    sandbox_check = response.artifact_results[0].details["sandbox_check"]
    assert sandbox_check["decision"] == "SANDBOX_INFRA_ERROR"
    assert sandbox_check["policy_gate"]["reason_code"] == "SANDBOX_INFRA_NOT_STARTED"
    assert "PRE_START_INSPECT:RUNTIME_MISMATCH" in sandbox_check["policy_gate"]["runtime_setup_errors"]


def test_post_start_inspect_drift_maps_to_runtime_invalid(tmp_path: Path) -> None:
    source = _b2_source("PostDriftModel")
    response = _run_request(
        tmp_path,
        artifacts=[_artifact("modeling_post_drift.py", source)],
        snapshot_sources={"modeling_post_drift.py": source},
        command_runner=FixtureCommandRunner(post_inspect_overrides={"NetworkMode": "bridge"}),
    )

    sandbox_check = response.artifact_results[0].details["sandbox_check"]
    assert sandbox_check["decision"] == "BLOCKED_RUNTIME_INVALID"
    assert sandbox_check["policy_gate"]["reason_code"] == "SANDBOX_RUNTIME_DRIFT_AFTER_START"
    assert "POST_START_INSPECT:NETWORK_NOT_NONE" in sandbox_check["policy_gate"]["post_start_runtime_errors"]


def test_missing_and_malformed_runner_result_map_to_functional_review(tmp_path: Path) -> None:
    source = _b2_source("RunnerDiagModel")
    missing = _run_request(
        tmp_path / "missing",
        artifacts=[_artifact("modeling_missing_runner.py", source)],
        snapshot_sources={"modeling_missing_runner.py": source},
        command_runner=FixtureCommandRunner(runner_result_mode="missing"),
        request_id="req-full-fixture",
        job_id="job-full-fixture",
    ).artifact_results[0].details["sandbox_check"]
    malformed = _run_request(
        tmp_path / "malformed",
        artifacts=[_artifact("modeling_malformed_runner.py", source)],
        snapshot_sources={"modeling_malformed_runner.py": source},
        command_runner=FixtureCommandRunner(runner_result_mode="malformed"),
        request_id="req-full-fixture",
        job_id="job-full-fixture",
    ).artifact_results[0].details["sandbox_check"]

    assert missing["decision"] == "FUNCTIONAL_REVIEW_REQUIRED"
    assert missing["policy_gate"]["reason_code"] == "RUNNER_DIAGNOSTICS_MISSING"
    assert malformed["decision"] == "FUNCTIONAL_REVIEW_REQUIRED"
    assert malformed["policy_gate"]["reason_code"] == "RUNNER_DIAGNOSTICS_MALFORMED"


def test_manifest_input_hash_mismatch_maps_to_input_integrity_violation(tmp_path: Path) -> None:
    source = _b2_source("InputMismatchModel")
    response = _run_request(
        tmp_path,
        artifacts=[_artifact("modeling_input_mismatch.py", source)],
        snapshot_sources={"modeling_input_mismatch.py": source},
        command_runner=FixtureCommandRunner(mutate_input_on_create=True),
    )

    sandbox_check = response.artifact_results[0].details["sandbox_check"]
    assert sandbox_check["decision"] == "BLOCKED_SECURITY_EVENT"
    assert sandbox_check["policy_gate"]["reason_code"] == "SANDBOX_INPUT_INTEGRITY_VIOLATION"
    assert sandbox_check["manifest_evidence"]["input_hash_errors"] == ["HASH_MISMATCH:modeling_input_mismatch.py"]


def test_same_job_direct_and_sibling_b2_do_not_share_output_or_container_name(tmp_path: Path) -> None:
    config_source = json.dumps({"auto_map": {"AutoModel": "modeling_linked.LinkedModel"}})
    linked_source = _b2_source("LinkedModel")
    direct_source = _b2_source("DirectModel")
    runner = FixtureCommandRunner()
    response = _run_request(
        tmp_path,
        artifacts=[_artifact("config.json", config_source), _artifact("modeling_direct.py", direct_source)],
        snapshot_sources={
            "config.json": config_source,
            "modeling_linked.py": linked_source,
            "modeling_direct.py": direct_source,
        },
        command_runner=runner,
    )

    assert {item.artifact.repo_path for item in response.artifact_results} >= {
        "config.json",
        "modeling_linked.py",
        "modeling_direct.py",
    }
    create_commands = [argv for name, argv in runner.calls if name == "create"]
    cp_commands = [argv for name, argv in runner.calls if name == "cp"]
    container_names = [argv[argv.index("--name") + 1] for argv in create_commands]
    cp_outputs = [argv[-1] for argv in cp_commands]

    assert len(create_commands) == 2
    assert len(set(container_names)) == 2
    assert len(set(cp_outputs)) == 2
    assert any("modeling_linked.py" in name for name in container_names)
    assert any("modeling_direct.py" in name for name in container_names)
    assert any("modeling_linked.py" in output for output in cp_outputs)
    assert any("modeling_direct.py" in output for output in cp_outputs)
