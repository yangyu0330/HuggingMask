"""Injectable host-side lifecycle coordinator for B-2 sandbox runs.

This module composes the planned Docker lifecycle with fixture-oriented command
results. It never invokes Docker/runsc directly and never calls subprocesses.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Protocol

from sandbox.b2.entrypoint import compute_manifest_sha256
from sandbox.b2.host_runner import (
    B2DockerRuntimeConfig,
    B2LifecycleStep,
    B2_RUNNER_RESULT_FILENAME,
    B2SandboxJob,
    build_docker_lifecycle_plan,
    build_sandbox_job_from_context,
)
from sandbox.b2.inspect_validator import validate_docker_inspect
from sandbox.b2.pipeline import B2RunnerOutput
from sandbox.b2.runsc_log_parser import parse_runsc_logs
from sandbox.b2.schemas import B2_INPUT_MANIFEST_FILENAME, ManifestEvidence, RuntimeEvidence


@dataclass(frozen=True)
class CommandResult:
    exit_code: int = 0
    stdout: str = ""
    stderr: str = ""
    fixtures: dict[str, Any] = field(default_factory=dict)


class CommandRunner(Protocol):
    def __call__(self, step_name: str, argv: list[str]) -> CommandResult | Mapping[str, Any]:
        ...


@dataclass
class B2HostRunner:
    config: B2DockerRuntimeConfig
    output_dir: Path
    command_runner: CommandRunner
    repo_root: Path | None = None
    container_name: str | None = None

    def __call__(self, context) -> B2RunnerOutput:
        artifact_segment = _context_artifact_segment(context)
        job = build_sandbox_job_from_context(
            context,
            config=self.config,
            output_dir=self.output_dir / _safe_segment(context.job_id) / artifact_segment,
            repo_root=self.repo_root,
            container_name=self.container_name
            or f"huggingmask-b2-{_safe_segment(context.request_id)}-{_safe_segment(context.job_id)}-{artifact_segment}",
        )
        plan = build_docker_lifecycle_plan(job)
        results: dict[str, CommandResult] = {}
        runtime_setup_errors: list[str] = []
        post_start_runtime_errors: list[str] = []

        try:
            for step in plan.steps:
                if step.name == "rm":
                    continue
                try:
                    result = _coerce_command_result(self.command_runner(step.name, list(step.command)))
                except Exception as exc:
                    _append_command_exception(
                        step.name,
                        exc,
                        runtime_setup_errors=runtime_setup_errors,
                        post_start_runtime_errors=post_start_runtime_errors,
                    )
                    break
                results[step.name] = result
                if result.exit_code != 0:
                    _append_command_failure(
                        step.name,
                        result,
                        runtime_setup_errors=runtime_setup_errors,
                        post_start_runtime_errors=post_start_runtime_errors,
                    )
                    break
        finally:
            rm_step = _step_by_name(plan, "rm")
            if rm_step is not None:
                try:
                    results["rm"] = _coerce_command_result(self.command_runner(rm_step.name, list(rm_step.command)))
                except Exception as exc:  # pragma: no cover - defensive cleanup guard
                    runtime_setup_errors.append(f"COMMAND_RUNNER_EXCEPTION:rm:{type(exc).__name__}")

        manifest_evidence = verify_staged_manifest_evidence(context)
        pre_inspect = _find_fixture(results, "pre_start_inspect", "pre_inspect")
        post_inspect = _find_fixture(results, "post_start_inspect", "inspect")
        runtime_evidence = RuntimeEvidence()

        if pre_inspect is not None:
            _, evidence, errors = _validate_inspect(pre_inspect, job)
            runtime_evidence = evidence
            runtime_setup_errors.extend(f"PRE_START_INSPECT:{error}" for error in errors)

        if post_inspect is not None:
            _, evidence, errors = _validate_inspect(post_inspect, job)
            runtime_evidence = evidence
            post_start_runtime_errors.extend(f"POST_START_INSPECT:{error}" for error in errors)

        log_parse = parse_runsc_logs(_runsc_log_inputs(results))
        runner_result = _runner_result_from_results(results, job)
        artifacts = {
            "host_lifecycle_steps": ",".join(plan.step_names),
            "runner_result": str(job.output_dir / B2_RUNNER_RESULT_FILENAME),
        }

        return B2RunnerOutput(
            runner_result=runner_result,
            runtime_evidence=runtime_evidence,
            security_events=log_parse.security_events,
            manifest_evidence=manifest_evidence,
            artifacts=artifacts,
            runtime_setup_errors=_dedupe(runtime_setup_errors),
            post_start_runtime_errors=_dedupe(post_start_runtime_errors),
            log_complete=log_parse.log_complete,
            strace_observed=log_parse.strace_observed,
        )


def verify_staged_manifest_evidence(context) -> ManifestEvidence:
    manifest = context.manifest
    host_manifest_sha256 = getattr(manifest, "manifest_sha256", None)
    evidence = ManifestEvidence(host_manifest_sha256=host_manifest_sha256)
    manifest_path = Path(context.input_dir) / B2_INPUT_MANIFEST_FILENAME

    if not manifest_path.is_file():
        evidence.manifest_errors.append(f"MISSING_MANIFEST:{B2_INPUT_MANIFEST_FILENAME}")
    else:
        try:
            payload = json.loads(manifest_path.read_text(encoding="utf-8"))
            if not isinstance(payload, dict):
                raise ValueError("manifest root must be object")
            embedded = payload.get("manifest_sha256")
            if embedded != host_manifest_sha256:
                evidence.manifest_errors.append("MANIFEST_HASH_MISMATCH:b2_input_manifest.json")
            if isinstance(embedded, str) and compute_manifest_sha256(payload) != embedded:
                evidence.manifest_errors.append("MANIFEST_CANONICAL_HASH_MISMATCH:b2_input_manifest.json")
        except Exception as exc:
            evidence.manifest_errors.append(f"MANIFEST_READ_ERROR:{type(exc).__name__}")

    for item in getattr(manifest, "files", []):
        repo_path = str(getattr(item, "path", ""))
        expected_sha256 = str(getattr(item, "sha256", ""))
        expected_size = getattr(item, "size_bytes", None)
        local_path = Path(context.input_dir).joinpath(*PurePosixPath(repo_path).parts)
        resolved = local_path.resolve(strict=False)
        input_root = Path(context.input_dir).resolve(strict=False)
        if not _is_relative_to(resolved, input_root):
            evidence.input_hash_errors.append(f"INPUT_PATH_ESCAPE:{repo_path}")
            continue
        if not resolved.is_file():
            evidence.input_hash_errors.append(f"MISSING_INPUT:{repo_path}")
            continue
        data = resolved.read_bytes()
        if isinstance(expected_size, int) and len(data) != expected_size:
            evidence.input_hash_errors.append(f"SIZE_MISMATCH:{repo_path}")
            continue
        actual_sha256 = hashlib.sha256(data).hexdigest()
        if actual_sha256 != expected_sha256:
            evidence.input_hash_errors.append(f"HASH_MISMATCH:{repo_path}")
    return evidence


def _validate_inspect(payload: Any, job: B2SandboxJob) -> tuple[bool, RuntimeEvidence, list[str]]:
    return validate_docker_inspect(
        payload,
        expected_docker_runtime=job.config.docker_runtime,
        expected_image_ref=job.config.image_ref,
        expected_entrypoint=job.config.env_entrypoint,
        expected_python_executable=job.config.python_executable,
        expected_runner_entrypoint=job.config.runner_entrypoint,
        expected_input_container_dir=job.config.input_container_dir,
        expected_output_container_dir=job.config.output_container_dir,
        expected_input_source=str(job.input_dir),
        expected_output_source=str(job.output_dir),
        expected_pids_limit=job.config.pids_limit,
        expected_memory_limit=job.config.memory_limit,
        expected_cpu_limit=job.config.cpus,
    )


def _runsc_log_inputs(results: dict[str, CommandResult]) -> str | list[str | None] | None:
    logs = results.get("logs")
    if logs is None:
        return None
    fixture_logs = _fixture_value(logs, "runsc_logs", "runsc_log", "logs")
    if fixture_logs is not None:
        return fixture_logs
    return logs.stdout or None


def _runner_result_from_results(results: dict[str, CommandResult], job: B2SandboxJob) -> Mapping[str, Any] | None:
    for result in reversed(list(results.values())):
        value = _fixture_value(result, "runner_result")
        if isinstance(value, Mapping):
            return dict(value)
        json_value = _fixture_value(result, "runner_result_json")
        if isinstance(json_value, str):
            try:
                parsed = json.loads(json_value)
            except json.JSONDecodeError:
                return {"schema_version": "malformed"}
            return parsed if isinstance(parsed, Mapping) else {"schema_version": "malformed"}

    runner_result_path = job.output_dir / B2_RUNNER_RESULT_FILENAME
    if not runner_result_path.is_file():
        return None
    try:
        parsed = json.loads(runner_result_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {"schema_version": "malformed"}
    return parsed if isinstance(parsed, Mapping) else {"schema_version": "malformed"}


def _find_fixture(results: dict[str, CommandResult], *keys: str) -> Any:
    for result in results.values():
        value = _fixture_value(result, *keys)
        if value is not None:
            return value
    return None


def _fixture_value(result: CommandResult, *keys: str) -> Any:
    for key in keys:
        if key in result.fixtures:
            return result.fixtures[key]
    return None


def _coerce_command_result(value: CommandResult | Mapping[str, Any]) -> CommandResult:
    if isinstance(value, CommandResult):
        return value
    data = dict(value)
    fixtures = data.get("fixtures")
    fixture_map = dict(fixtures) if isinstance(fixtures, Mapping) else {}
    for key, item in data.items():
        if key not in {"exit_code", "stdout", "stderr", "fixtures"}:
            fixture_map[key] = item
    return CommandResult(
        exit_code=int(data.get("exit_code", 0)),
        stdout=str(data.get("stdout", "")),
        stderr=str(data.get("stderr", "")),
        fixtures=fixture_map,
    )


def _append_command_exception(
    step_name: str,
    exc: Exception,
    *,
    runtime_setup_errors: list[str],
    post_start_runtime_errors: list[str],
) -> None:
    error = f"COMMAND_RUNNER_EXCEPTION:{step_name}:{type(exc).__name__}"
    if step_name in {"create", "start"}:
        runtime_setup_errors.append(error)
    else:
        post_start_runtime_errors.append(error)


def _append_command_failure(
    step_name: str,
    result: CommandResult,
    *,
    runtime_setup_errors: list[str],
    post_start_runtime_errors: list[str],
) -> None:
    error = f"COMMAND_FAILED:{step_name}:{result.exit_code}"
    if result.stderr:
        error = f"{error}:{result.stderr[:120]}"
    if step_name in {"create", "start"}:
        runtime_setup_errors.append(error)
    else:
        post_start_runtime_errors.append(error)


def _step_by_name(plan, name: str) -> B2LifecycleStep | None:
    for step in plan.steps:
        if step.name == name:
            return step
    return None


def _safe_segment(value: str) -> str:
    cleaned = "".join(ch if ch.isalnum() or ch in {"-", "_", "."} else "_" for ch in str(value))
    return cleaned.strip("._") or "job"


def _context_artifact_segment(context) -> str:
    primary_result = getattr(context, "primary_result", None)
    artifact = getattr(primary_result, "artifact", None)
    for value in (
        getattr(artifact, "repo_path", None),
        getattr(artifact, "artifact_id", None),
        getattr(getattr(context, "manifest", None), "primary_repo_path", None),
        getattr(getattr(context, "manifest", None), "primary_artifact_id", None),
        getattr(context, "nonce", None),
    ):
        if value:
            return _safe_segment(str(value))
    return "artifact"


def _is_relative_to(path: Path, base: Path) -> bool:
    try:
        path.relative_to(base)
        return True
    except ValueError:
        return False


def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    output: list[str] = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        output.append(item)
    return output
