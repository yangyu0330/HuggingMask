import json
import subprocess
import sys
from pathlib import Path

from analyzer.orchestrator import run_validation_job
from analyzer.schemas import ValidationStatus
from analyzer.snapshot_resolver import SnapshotSourceResolver, build_source_loader
from sandbox.b2.host_runner_executor import CommandResult
from scripts import demo_b2_run

IMAGE_REF = "huggingmask-b2-sandbox:local"


def test_demo_script_can_be_invoked_by_documented_path() -> None:
    completed = subprocess.run(
        [sys.executable, "scripts/demo_b2_run.py", "--help"],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )

    assert completed.returncode == 0
    assert "--image-ref" in completed.stdout


class FakeDockerLifecycleRunner:
    def __init__(self, *, image_ref: str = IMAGE_REF, runtime: str = "runsc") -> None:
        self.image_ref = image_ref
        self.runtime = runtime
        self.calls: list[tuple[str, list[str]]] = []
        self.create_argv: list[str] | None = None

    def __call__(self, step_name: str, argv: list[str]) -> CommandResult:
        self.calls.append((step_name, argv))
        if step_name == "create":
            self.create_argv = list(argv)
            return CommandResult(stdout="container-id\n")
        if step_name == "start":
            return CommandResult(stdout="container-id\n")
        if step_name == "wait":
            return CommandResult(stdout="0\n", fixtures={"container_exit_code": 0})
        if step_name == "inspect":
            return CommandResult(fixtures={"post_start_inspect": self._inspect_payload()})
        if step_name == "logs":
            # 신뢰 가능한 runsc strace 소스로 모델링(runsc_logs). generic "logs"/
            # stdout은 strace 단독 근거가 아니다(양유상 PR #55) — 실제 runsc는
            # debug-log를 호스트 경로로 내보내며 이를 runsc_logs로 받는다.
            return CommandResult(
                stdout='1 openat(AT_FDCWD, "/sandbox/input/modeling_b2_demo.py", O_RDONLY|O_CLOEXEC) = 3\n',
                fixtures={"runsc_logs": '1 openat(AT_FDCWD, "/sandbox/input/modeling_b2_demo.py", O_RDONLY|O_CLOEXEC) = 3\n'},
            )
        if step_name == "cp":
            runner_result = self._runner_result()
            target = Path(argv[-1])
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(json.dumps(runner_result), encoding="utf-8")
            return CommandResult(fixtures={"runner_result": runner_result})
        if step_name == "rm":
            return CommandResult()
        raise AssertionError(f"unexpected step: {step_name}")

    def _runner_result(self) -> dict:
        assert self.create_argv is not None
        return {
            "schema_version": "1.0",
            "request_id": _value_after(self.create_argv, "--request-id"),
            "nonce": _value_after(self.create_argv, "--nonce"),
            "manifest_verified": True,
            "import_status": "success",
            "instantiate_status": "success",
            "forward_status": "success",
            "exception_class": None,
            "exception_message": None,
        }

    def _inspect_payload(self) -> dict:
        assert self.create_argv is not None
        input_source, output_source = _mount_sources(self.create_argv)
        image_index = self.create_argv.index(self.image_ref)
        return {
            "Path": "/usr/bin/env",
            "Args": self.create_argv[image_index + 1 :],
            "Config": {
                "Image": self.image_ref,
                "User": "1000:1000",
                "Env": ["PATH=/usr/local/bin:/usr/bin:/bin"],
            },
            "HostConfig": {
                "Runtime": self.runtime,
                "NetworkMode": "none",
                "ReadonlyRootfs": True,
                "Privileged": False,
                "CapAdd": [],
                "CapDrop": ["ALL"],
                "SecurityOpt": ["no-new-privileges"],
                "PidsLimit": 128,
                "Memory": 4 * 1024 * 1024 * 1024,
                "NanoCpus": 2_000_000_000,
            },
            "Mounts": [
                {"Type": "bind", "Source": input_source, "Destination": "/sandbox/input", "Mode": "ro", "RW": False},
                {"Type": "bind", "Source": output_source, "Destination": "/tmp/huggingmask", "Mode": "rw", "RW": True},
            ],
        }


def _value_after(argv: list[str], token: str) -> str:
    return argv[argv.index(token) + 1]


def _mount_sources(argv: list[str]) -> tuple[str, str]:
    input_source = ""
    output_source = ""
    mounts = [argv[index + 1] for index, token in enumerate(argv) if token == "-v"]
    for mount in mounts:
        host_path, container_path, mode = mount.rsplit(":", 2)
        if container_path == "/sandbox/input" and mode == "ro":
            input_source = host_path
        if container_path == "/tmp/huggingmask" and mode == "rw":
            output_source = host_path
    return input_source, output_source


def test_demo_snapshot_is_static_b2_sandbox_candidate(tmp_path: Path) -> None:
    request = demo_b2_run.build_demo_request(
        snapshot_root=tmp_path / "snapshot",
        request_id="req-demo-contract",
        job_id="job-demo-contract",
    )
    resolver = SnapshotSourceResolver.from_request(request)

    response = run_validation_job(
        request,
        source_loader=build_source_loader(resolver),
        source_resolver=resolver,
    )

    result = response.artifact_results[0]
    sandbox_check = result.details["sandbox_check"]
    assert result.status is ValidationStatus.PENDING_REVIEW
    assert result.grade.value == "B-2"
    assert result.route_kind.value == "CODE_SANDBOX_RUNTIME"
    assert result.details["pending_api_refs"] == ["self.custom_activation"]
    assert sandbox_check["decision"] == "NOT_RUN"
    assert sandbox_check["deployable"] is False


def test_run_demo_writes_review_evidence_with_injected_lifecycle_runner(tmp_path: Path) -> None:
    fake_runner = FakeDockerLifecycleRunner()

    result = demo_b2_run.run_demo(
        image_ref=IMAGE_REF,
        docker_runtime="runsc",
        evidence_dir=tmp_path,
        request_id="req-demo",
        job_id="job-demo",
        revision="rev-demo",
        run_id="fixed-run",
        command_runner=fake_runner,
    )

    assert [name for name, _ in fake_runner.calls] == ["create", "start", "wait", "inspect", "logs", "cp", "rm"]
    assert result.summary["decision"] == "B2_POLICY_REVIEW_REQUIRED"
    assert result.summary["runtime_verified"] is True
    assert result.summary["deployable"] is False
    assert (result.evidence_dir / "summary.json").is_file()
    assert (result.evidence_dir / "sandbox_check.json").is_file()
    assert (result.evidence_dir / "host_runner_output.json").is_file()
    assert (result.evidence_dir / "demo_snapshot_manifest.json").is_file()
    assert (result.evidence_dir / "b2_input_manifest.json").is_file()
    assert (result.evidence_dir / "runner_result.json").is_file()
