import hashlib
import json
from pathlib import Path

from sandbox.b2.decision_builder import build_sandbox_check_from_runner_result
from sandbox.b2.entrypoint import compute_manifest_sha256
from sandbox.b2.host_runner import B2DockerRuntimeConfig
from sandbox.b2.host_runner_executor import B2HostRunner, CommandResult
from sandbox.b2.pipeline import B2RunnerContext, B2RunnerOutput
from sandbox.b2.schemas import B2InputManifest, B2ManifestFile, B2Target


IMAGE_REF = "huggingmask/b2-runner@sha256:" + "1" * 64


class FakeCommandRunner:
    def __init__(self, fixtures_by_step: dict[str, dict] | None = None, raise_on: str | None = None) -> None:
        self.fixtures_by_step = fixtures_by_step or {}
        self.raise_on = raise_on
        self.calls: list[tuple[str, list[str]]] = []
        self._mount_sources_by_container: dict[str, tuple[str, str]] = {}

    def __call__(self, step_name: str, argv: list[str]) -> CommandResult:
        self.calls.append((step_name, argv))
        if step_name == self.raise_on:
            raise RuntimeError(f"boom:{step_name}")
        fixture = self.fixtures_by_step.get(step_name, {})
        if step_name == "create":
            container = argv[argv.index("--name") + 1]
            self._mount_sources_by_container[container] = _mount_sources_from_create_command(argv)
            fixture = _with_inspect_sources(fixture, self._mount_sources_by_container[container])
        elif step_name == "inspect":
            sources = self._mount_sources_by_container.get(argv[-1])
            if sources is not None:
                fixture = _with_inspect_sources(fixture, sources)
        return CommandResult(
            exit_code=fixture.get("exit_code", 0),
            stdout=fixture.get("stdout", ""),
            stderr=fixture.get("stderr", ""),
            fixtures={key: value for key, value in fixture.items() if key not in {"exit_code", "stdout", "stderr"}},
        )


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
    return input_source, output_source


def _with_inspect_sources(fixture: dict, sources: tuple[str, str]) -> dict:
    updated = dict(fixture)
    for key in ("pre_start_inspect", "post_start_inspect"):
        if key in updated:
            inspect_payload = json.loads(json.dumps(updated[key]))
            _set_mount_sources(inspect_payload, sources)
            updated[key] = inspect_payload
    return updated


def _set_mount_sources(inspect_payload: dict, sources: tuple[str, str]) -> None:
    input_source, output_source = sources
    for mount in inspect_payload.get("Mounts", []):
        if mount.get("Destination") == "/sandbox/input":
            mount["Source"] = input_source
        elif mount.get("Destination") == "/tmp/huggingmask":
            mount["Source"] = output_source


def _config(**overrides) -> B2DockerRuntimeConfig:
    payload = {
        "image_ref": IMAGE_REF,
        "docker_runtime": "runsc-b2-debug",
        "memory_limit": "2g",
        "cpus": "1.5",
    }
    payload.update(overrides)
    return B2DockerRuntimeConfig(**payload)


def _context(tmp_path: Path, *, repo_path: str = "modeling_demo.py") -> B2RunnerContext:
    module_name = repo_path[:-3] if repo_path.endswith(".py") else repo_path
    input_dir = tmp_path / f"input-{module_name}"
    input_dir.mkdir()
    source = b"class DemoModel:\n    pass\n"
    source_path = input_dir / repo_path
    source_path.parent.mkdir(parents=True, exist_ok=True)
    source_path.write_bytes(source)
    file_entry = B2ManifestFile(
        path=repo_path,
        sha256=hashlib.sha256(source).hexdigest(),
        size_bytes=len(source),
        role="MODELING",
        ast_grade="B-2",
        import_allowed=True,
        target_allowed=True,
        is_primary=True,
        validation_status="PENDING_REVIEW",
    )
    manifest = B2InputManifest(
        schema_version="1.0",
        request_id="req-b2",
        job_id="job-b2",
        primary_artifact_id="sha256:" + "a" * 64,
        primary_repo_path=repo_path,
        revision="rev",
        policy_version="policy-2026.05.20",
        grade="B-2",
        target=B2Target(source="direct_python", target_module=module_name, target_class="DemoModel"),
        manifest_sha256="",
        files=[file_entry],
    )
    payload = manifest.to_dict()
    manifest.manifest_sha256 = compute_manifest_sha256(payload)
    payload["manifest_sha256"] = manifest.manifest_sha256
    (input_dir / "b2_input_manifest.json").write_text(
        json.dumps(payload, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    return B2RunnerContext(
        request_id="req-b2",
        job_id="job-b2",
        revision="rev",
        policy_version="policy-2026.05.20",
        primary_result=None,  # type: ignore[arg-type]
        candidate_results=[],
        manifest=manifest,
        input_dir=input_dir,
        nonce="nonce-123",
    )


def _inspect_fixture(**host_overrides) -> dict:
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
            "HUGGINGMASK_REQUEST_ID=req-b2",
            "HUGGINGMASK_JOB_ID=job-b2",
            "HUGGINGMASK_NONCE=nonce-123",
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
            {"Type": "bind", "Source": "/job/input", "Destination": "/sandbox/input", "Mode": "ro", "RW": False},
            {"Type": "bind", "Source": "/job/out", "Destination": "/tmp/huggingmask", "Mode": "rw", "RW": True},
        ],
    }


def _runner_result(**overrides) -> dict:
    payload = {
        "schema_version": "1.0",
        "request_id": "req-b2",
        "nonce": "nonce-123",
        "manifest_verified": True,
        "import_status": "success",
        "instantiate_status": "success",
        "forward_status": "success",
    }
    payload.update(overrides)
    return payload


def _clean_log() -> str:
    return '1 openat(AT_FDCWD, "/sandbox/input/modeling_demo.py", O_RDONLY|O_CLOEXEC) = 3'


def _runner(
    tmp_path: Path,
    fixtures: dict[str, dict] | None = None,
    *,
    fake: FakeCommandRunner | None = None,
) -> tuple[B2HostRunner, FakeCommandRunner]:
    command_runner = fake or FakeCommandRunner(fixtures)
    return (
        B2HostRunner(
            config=_config(),
            output_dir=tmp_path / "host-output",
            command_runner=command_runner,
            repo_root=tmp_path / "repo",
        ),
        command_runner,
    )


def _default_fixtures() -> dict[str, dict]:
    return {
        "create": {"pre_start_inspect": _inspect_fixture()},
        "inspect": {"post_start_inspect": _inspect_fixture()},
        "logs": {"runsc_logs": _clean_log()},
        "cp": {"runner_result": _runner_result()},
    }


def _sandbox_check(output: B2RunnerOutput) -> dict:
    return build_sandbox_check_from_runner_result(
        request_id="req-b2",
        job_id="job-b2",
        artifact_id="sha256:" + "a" * 64,
        repo_path="modeling_demo.py",
        runner_result=output.runner_result,
        expected_nonce="nonce-123",
        runtime_evidence=output.runtime_evidence,
        security_events=output.security_events,
        manifest_evidence=output.manifest_evidence,
        runtime_setup_errors=output.runtime_setup_errors,
        post_start_runtime_errors=output.post_start_runtime_errors,
        log_complete=output.log_complete if output.log_complete is not None else True,
    )


def test_host_runner_lifecycle_order_and_clean_runner_output(tmp_path: Path) -> None:
    context = _context(tmp_path)
    runner, fake = _runner(tmp_path, _default_fixtures())

    output = runner(context)

    assert [name for name, _ in fake.calls] == ["create", "start", "wait", "inspect", "logs", "cp", "rm"]
    assert isinstance(output, B2RunnerOutput)
    assert output.runner_result == _runner_result()
    assert output.runtime_setup_errors == []
    assert output.post_start_runtime_errors == []
    assert output.log_complete is True
    assert output.manifest_evidence.host_manifest_sha256 == context.manifest.manifest_sha256
    assert output.manifest_evidence.manifest_errors == []
    assert output.manifest_evidence.input_hash_errors == []


def test_pre_start_inspect_drift_becomes_runtime_setup_error(tmp_path: Path) -> None:
    context = _context(tmp_path)
    fixtures = _default_fixtures()
    fixtures["create"] = {"pre_start_inspect": _inspect_fixture(Runtime="runc")}
    runner, _ = _runner(tmp_path, fixtures)

    output = runner(context)
    check = _sandbox_check(output)

    assert "PRE_START_INSPECT:RUNTIME_MISMATCH" in output.runtime_setup_errors
    assert check["decision"] == "SANDBOX_INFRA_ERROR"
    assert check["policy_gate"]["reason_code"] == "SANDBOX_INFRA_NOT_STARTED"


def test_post_start_inspect_drift_becomes_runtime_invalid_error(tmp_path: Path) -> None:
    context = _context(tmp_path)
    fixtures = _default_fixtures()
    fixtures["inspect"] = {"post_start_inspect": _inspect_fixture(NetworkMode="bridge")}
    runner, _ = _runner(tmp_path, fixtures)

    output = runner(context)
    check = _sandbox_check(output)

    assert "POST_START_INSPECT:NETWORK_NOT_NONE" in output.post_start_runtime_errors
    assert check["decision"] == "BLOCKED_RUNTIME_INVALID"
    assert check["policy_gate"]["reason_code"] == "SANDBOX_RUNTIME_DRIFT_AFTER_START"


def test_runsc_security_events_are_passed_through(tmp_path: Path) -> None:
    context = _context(tmp_path)
    fixtures = _default_fixtures()
    fixtures["logs"] = {
        "runsc_logs": """
1 execve("/bin/sh", ["sh"], 0x7ffd) = 0
2 socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) = 3
3 openat(AT_FDCWD, "/sandbox/input/modeling_demo.py", O_WRONLY|O_CREAT, 0644) = -1 EROFS
"""
    }
    runner, _ = _runner(tmp_path, fixtures)

    output = runner(context)
    check = _sandbox_check(output)

    assert output.security_events.unexpected_execve
    assert output.security_events.network_events
    assert output.security_events.blocked_writes
    assert check["decision"] == "BLOCKED_SECURITY_EVENT"
    assert check["policy_gate"]["reason_code"] == "SANDBOX_SECURITY_EVENT"


def test_missing_runner_result_fails_closed_via_decision_builder(tmp_path: Path) -> None:
    context = _context(tmp_path)
    fixtures = _default_fixtures()
    fixtures["cp"] = {}
    runner, _ = _runner(tmp_path, fixtures)

    output = runner(context)
    check = _sandbox_check(output)

    assert output.runner_result is None
    assert check["decision"] == "FUNCTIONAL_REVIEW_REQUIRED"
    assert check["policy_gate"]["reason_code"] == "RUNNER_DIAGNOSTICS_MISSING"


def test_malformed_runner_result_fails_closed_via_decision_builder(tmp_path: Path) -> None:
    context = _context(tmp_path)
    fixtures = _default_fixtures()
    fixtures["cp"] = {"runner_result": {"schema_version": "1.0"}}
    runner, _ = _runner(tmp_path, fixtures)

    output = runner(context)
    check = _sandbox_check(output)

    assert check["decision"] == "FUNCTIONAL_REVIEW_REQUIRED"
    assert check["policy_gate"]["reason_code"] == "RUNNER_DIAGNOSTICS_MALFORMED"


def test_manifest_input_hash_revalidation_is_preserved(tmp_path: Path) -> None:
    context = _context(tmp_path)
    source_path = context.input_dir / "modeling_demo.py"
    data = bytearray(source_path.read_bytes())
    data[-2] = ord("#")
    source_path.write_bytes(data)
    runner, _ = _runner(tmp_path, _default_fixtures())

    output = runner(context)
    check = _sandbox_check(output)

    assert output.manifest_evidence.input_hash_errors == ["HASH_MISMATCH:modeling_demo.py"]
    assert check["decision"] == "BLOCKED_SECURITY_EVENT"
    assert check["policy_gate"]["reason_code"] == "SANDBOX_INPUT_INTEGRITY_VIOLATION"


def test_command_runner_exception_still_calls_rm_cleanup(tmp_path: Path) -> None:
    context = _context(tmp_path)
    fake = FakeCommandRunner(_default_fixtures(), raise_on="start")
    runner, _ = _runner(tmp_path, fake=fake)

    output = runner(context)

    assert [name for name, _ in fake.calls] == ["create", "start", "rm"]
    assert output.runner_result is None
    assert output.runtime_setup_errors == ["COMMAND_RUNNER_EXCEPTION:start:RuntimeError"]


def test_command_failure_stops_lifecycle_and_still_cleans_up(tmp_path: Path) -> None:
    context = _context(tmp_path)
    fixtures = _default_fixtures()
    fixtures["create"] = {"exit_code": 125, "stderr": "create failed"}
    fake = FakeCommandRunner(fixtures)
    runner, _ = _runner(tmp_path, fake=fake)

    output = runner(context)

    assert [name for name, _ in fake.calls] == ["create", "rm"]
    assert output.runner_result is None
    assert output.runtime_setup_errors == ["COMMAND_FAILED:create:125:create failed"]


def test_same_job_multiple_artifacts_get_distinct_output_dirs_and_container_names(tmp_path: Path) -> None:
    context_a = _context(tmp_path, repo_path="modeling_a.py")
    context_b = _context(tmp_path, repo_path="modeling_b.py")
    fake = FakeCommandRunner(_default_fixtures())
    runner, _ = _runner(tmp_path, fake=fake)

    runner(context_a)
    runner(context_b)

    create_commands = [argv for step_name, argv in fake.calls if step_name == "create"]
    cp_commands = [argv for step_name, argv in fake.calls if step_name == "cp"]
    container_names = [argv[argv.index("--name") + 1] for argv in create_commands]

    assert len(create_commands) == 2
    assert container_names[0] != container_names[1]
    assert "modeling_a.py" in container_names[0]
    assert "modeling_b.py" in container_names[1]
    assert cp_commands[0][-1] != cp_commands[1][-1]
    assert "modeling_a.py" in cp_commands[0][-1]
    assert "modeling_b.py" in cp_commands[1][-1]
