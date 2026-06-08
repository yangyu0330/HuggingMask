"""Run the local B-2 Docker/runsc demo and write review evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from analyzer.orchestrator import build_minimal_request, run_validation_job
from analyzer.schemas import ArtifactRef, FileKind, PolicyInfo, ValidationJobResponse, to_jsonable
from analyzer.snapshot_resolver import SnapshotSourceResolver, build_source_loader
from sandbox.b2.host_runner import B2_RUNNER_RESULT_FILENAME, B2DockerRuntimeConfig
from sandbox.b2.host_runner_executor import B2HostRunner, CommandRunner
from sandbox.b2.real_command_runner import RealDockerCommandRunner, redact_evidence_value
from sandbox.b2.schemas import B2_INPUT_MANIFEST_FILENAME

DEMO_REPO_PATH = "modeling_b2_demo.py"
DEMO_CLASS_NAME = "DemoModel"
DEMO_SOURCE = """class DemoModel:
    def custom_activation(self, x):
        return x

    def forward(self, x):
        return self.custom_activation(x)
"""


@dataclass(frozen=True)
class DemoRunResult:
    response: ValidationJobResponse
    artifact_result: Any
    sandbox_check: dict[str, Any]
    evidence_dir: Path
    snapshot_root: Path
    summary: dict[str, Any]


def run_demo(
    *,
    image_ref: str,
    docker_runtime: str,
    evidence_dir: Path,
    request_id: str = "req-b2-demo",
    job_id: str = "job-b2-demo",
    revision: str = "demo-local",
    docker_binary: str = "docker",
    runsc_strace_log_dir: Path | None = None,
    run_id: str | None = None,
    command_runner: CommandRunner | None = None,
) -> DemoRunResult:
    run_dir = _run_dir(evidence_dir, request_id=request_id, run_id=run_id)
    snapshot_root = run_dir / "demo_snapshot"
    request = build_demo_request(snapshot_root=snapshot_root, request_id=request_id, job_id=job_id)
    resolver = SnapshotSourceResolver.from_request(request)
    staging_output_dir = run_dir / "staging"
    runner_output_dir = run_dir / "runner"
    docker_config = B2DockerRuntimeConfig(
        image_ref=image_ref,
        docker_runtime=docker_runtime,
        docker_binary=docker_binary,
    )
    lifecycle_runner = command_runner or RealDockerCommandRunner(
        evidence_dir=run_dir,
        runsc_strace_log_dir=runsc_strace_log_dir,
    )
    b2_runner = B2HostRunner(
        config=docker_config,
        output_dir=runner_output_dir,
        command_runner=lifecycle_runner,
        repo_root=Path.cwd(),
    )

    response = run_validation_job(
        request,
        source_loader=build_source_loader(resolver),
        source_resolver=resolver,
        b2_runner=b2_runner,
        b2_output_dir=staging_output_dir,
        revision=revision,
    )
    artifact_result = _demo_artifact_result(response)
    sandbox_check = artifact_result.details.get("sandbox_check")
    if not isinstance(sandbox_check, dict):
        raise RuntimeError("B-2 demo artifact did not produce sandbox_check")

    summary = _build_summary(
        artifact_result=artifact_result,
        sandbox_check=sandbox_check,
        docker_runtime=docker_runtime,
        evidence_dir=run_dir,
    )
    _write_demo_evidence(
        run_dir=run_dir,
        response=response,
        sandbox_check=sandbox_check,
        summary=summary,
        snapshot_root=snapshot_root,
        staging_output_dir=staging_output_dir,
        runner_output_dir=runner_output_dir,
    )
    return DemoRunResult(
        response=response,
        artifact_result=artifact_result,
        sandbox_check=sandbox_check,
        evidence_dir=run_dir,
        snapshot_root=snapshot_root,
        summary=summary,
    )


def build_demo_request(*, snapshot_root: Path, request_id: str, job_id: str):
    artifact = write_demo_snapshot(snapshot_root)
    request = build_minimal_request(
        request_id=request_id,
        job_id=job_id,
        policy=build_demo_policy(),
        artifacts=[artifact],
    )
    request.model_snapshot_root = str(snapshot_root)
    return request


def write_demo_snapshot(snapshot_root: Path) -> ArtifactRef:
    snapshot_root.mkdir(parents=True, exist_ok=True)
    target_path = snapshot_root.joinpath(*PurePosixPath(DEMO_REPO_PATH).parts)
    target_path.parent.mkdir(parents=True, exist_ok=True)
    data = DEMO_SOURCE.encode("utf-8")
    target_path.write_bytes(data)
    return _artifact_for(DEMO_REPO_PATH, data)


def build_demo_policy() -> PolicyInfo:
    return PolicyInfo(
        policy_version="policy-2026.05.20",
        whitelist_version="wl-2026.05.20",
        opcode_policy_version="opcode-2026.05.20",
        config_schema_version="cfg-2026.05.20",
        runtime_profile_version="rt-2026.05.20",
    )


def _artifact_for(repo_path: str, data: bytes) -> ArtifactRef:
    digest = hashlib.sha256(data).hexdigest()
    file_name = PurePosixPath(repo_path).name
    return ArtifactRef(
        artifact_id=f"sha256:{digest}",
        repo_path=repo_path,
        file_name=file_name,
        file_kind=FileKind.PYTHON,
        detected_extension=".py",
        media_type=None,
        size_bytes=len(data),
        sha256=digest,
        source_url=f"local://demo/{repo_path}",
        temp_local_path=f"/tmp/{file_name}",
        referenced_by=[],
        is_generated=False,
    )


def _demo_artifact_result(response: ValidationJobResponse) -> Any:
    for result in response.artifact_results:
        if result.artifact.repo_path == DEMO_REPO_PATH:
            return result
    raise RuntimeError(f"demo artifact result missing: {DEMO_REPO_PATH}")


def _build_summary(
    *,
    artifact_result: Any,
    sandbox_check: dict[str, Any],
    docker_runtime: str,
    evidence_dir: Path,
) -> dict[str, Any]:
    policy_gate = _mapping(sandbox_check.get("policy_gate"))
    runtime_evidence = _mapping(sandbox_check.get("runtime_evidence"))
    execution = _mapping(sandbox_check.get("execution"))
    return {
        "repo_path": artifact_result.artifact.repo_path,
        "grade": artifact_result.grade.value,
        "route": artifact_result.route_kind.value,
        "status": artifact_result.status.value,
        "review_action": artifact_result.review_action.value,
        "docker_runtime": docker_runtime,
        "runtime_verified": _runtime_verified(runtime_evidence, expected_runtime=docker_runtime),
        "runner_diagnostics_status": policy_gate.get("runner_diagnostics_status"),
        "manifest_verified": execution.get("manifest_verified"),
        "import_status": execution.get("import_status"),
        "instantiate_status": execution.get("instantiate_status"),
        "forward_status": execution.get("forward_status"),
        "decision": sandbox_check.get("decision"),
        "reason_code": policy_gate.get("reason_code"),
        "deployable": sandbox_check.get("deployable"),
        "evidence_dir": str(evidence_dir),
    }


def _runtime_verified(runtime_evidence: dict[str, Any], *, expected_runtime: str) -> bool:
    return (
        runtime_evidence.get("runtime") == expected_runtime
        and runtime_evidence.get("network_mode") == "none"
        and runtime_evidence.get("rootfs_readonly") is True
        and runtime_evidence.get("cap_drop_all") is True
        and runtime_evidence.get("no_new_privileges") is True
        and runtime_evidence.get("non_root_user") is True
        and runtime_evidence.get("env_allowlist_ok") is True
        and runtime_evidence.get("mounts_ok") is True
    )


def _write_demo_evidence(
    *,
    run_dir: Path,
    response: ValidationJobResponse,
    sandbox_check: dict[str, Any],
    summary: dict[str, Any],
    snapshot_root: Path,
    staging_output_dir: Path,
    runner_output_dir: Path,
) -> None:
    run_dir.mkdir(parents=True, exist_ok=True)
    _write_json(run_dir / "summary.json", summary)
    _write_json(run_dir / "sandbox_check.json", sandbox_check)
    _write_json(run_dir / "host_runner_output.json", response.to_dict())
    _write_json(run_dir / "demo_snapshot_manifest.json", _snapshot_manifest(snapshot_root))
    _copy_first(staging_output_dir, B2_INPUT_MANIFEST_FILENAME, run_dir / B2_INPUT_MANIFEST_FILENAME)
    _copy_first(runner_output_dir, B2_RUNNER_RESULT_FILENAME, run_dir / B2_RUNNER_RESULT_FILENAME)


def _snapshot_manifest(snapshot_root: Path) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for path in sorted(snapshot_root.rglob("*")):
        if not path.is_file():
            continue
        data = path.read_bytes()
        items.append(
            {
                "repo_path": path.relative_to(snapshot_root).as_posix(),
                "sha256": hashlib.sha256(data).hexdigest(),
                "size_bytes": len(data),
            }
        )
    return items


def _copy_first(root: Path, filename: str, target: Path) -> None:
    candidates = sorted(path for path in root.rglob(filename) if path.is_file())
    if not candidates:
        return
    shutil.copyfile(candidates[0], target)


def _write_json(path: Path, payload: Any) -> None:
    path.write_text(
        json.dumps(redact_evidence_value(to_jsonable(payload)), sort_keys=True, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def _run_dir(evidence_dir: Path, *, request_id: str, run_id: str | None) -> Path:
    segment = run_id or f"{_utc_stamp()}_{_safe_segment(request_id)}"
    return Path(evidence_dir) / segment


def _utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")


def _safe_segment(value: str) -> str:
    cleaned = "".join(ch if ch.isalnum() or ch in {"-", "_", "."} else "_" for ch in str(value))
    return cleaned.strip("._") or "run"


def _mapping(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}


def _print_summary(summary: dict[str, Any]) -> None:
    print("HuggingMask B-2 runsc demo")
    for key in (
        "repo_path",
        "grade",
        "route",
        "status",
        "docker_runtime",
        "runtime_verified",
        "runner_diagnostics_status",
        "decision",
        "reason_code",
        "deployable",
        "evidence_dir",
    ):
        print(f"{key}: {summary.get(key)}")


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="demo_b2_run")
    parser.add_argument("--image-ref", default="huggingmask-b2-sandbox:local")
    parser.add_argument("--docker-runtime", default="runsc")
    parser.add_argument("--docker-binary", default="docker")
    parser.add_argument("--runsc-strace-log-dir", type=Path, default=None)
    parser.add_argument("--evidence-dir", type=Path, default=Path("evidence/sandbox"))
    parser.add_argument("--request-id", default="req-b2-demo")
    parser.add_argument("--job-id", default="job-b2-demo")
    parser.add_argument("--revision", default="demo-local")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    result = run_demo(
        image_ref=args.image_ref,
        docker_runtime=args.docker_runtime,
        docker_binary=args.docker_binary,
        runsc_strace_log_dir=args.runsc_strace_log_dir,
        evidence_dir=args.evidence_dir,
        request_id=args.request_id,
        job_id=args.job_id,
        revision=args.revision,
    )
    _print_summary(result.summary)
    return 0 if result.summary["runtime_verified"] and result.summary["runner_diagnostics_status"] == "present_valid" else 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
