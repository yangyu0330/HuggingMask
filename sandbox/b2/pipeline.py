"""Host-side B-2 sandbox coordination contract.

This module wires the already-implemented host-side steps:

1. build a verified B-2 input manifest,
2. prepare a verified-only staging directory,
3. call an injected runner callable,
4. convert runner output into a standard ``sandbox_check`` dict.

It deliberately does not create containers, call Docker/runsc, build images, or
inspect runtime configuration. Tests provide fake runners.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Protocol

from analyzer.schemas import ArtifactValidationResult
from analyzer.snapshot_resolver import SnapshotSourceResolver
from sandbox.b2.decision_builder import build_sandbox_check_from_runner_result
from sandbox.b2.repo_manifest import B2ManifestError, build_b2_input_manifest, prepare_job_input_dir
from sandbox.b2.schemas import (
    B2_INPUT_MANIFEST_FILENAME,
    B2Decision,
    B2InputManifest,
    B2RunnerResult,
    B2RuntimePolicy,
    B2SandboxCheck,
    B2_SCHEMA_VERSION,
    ExecutionEvidence,
    ManifestEvidence,
    RuntimeEvidence,
    SecurityEvents,
)


@dataclass(frozen=True)
class B2RunnerContext:
    request_id: str
    job_id: str
    revision: str
    policy_version: str
    primary_result: ArtifactValidationResult
    candidate_results: list[ArtifactValidationResult]
    manifest: B2InputManifest
    input_dir: Path
    nonce: str


@dataclass(frozen=True)
class B2RunnerOutput:
    runner_result: B2RunnerResult | Mapping[str, Any] | None
    runtime_evidence: RuntimeEvidence | Mapping[str, Any] | None = None
    security_events: SecurityEvents | Mapping[str, Any] | None = None
    manifest_evidence: ManifestEvidence | Mapping[str, Any] | None = None
    artifacts: dict[str, str] = field(default_factory=dict)
    runtime_setup_errors: list[str] = field(default_factory=list)
    post_start_runtime_errors: list[str] = field(default_factory=list)
    log_complete: bool | None = None


class B2Runner(Protocol):
    def __call__(
        self,
        context: B2RunnerContext,
    ) -> B2RunnerOutput | B2RunnerResult | Mapping[str, Any] | None:
        ...


def run_b2_sandbox_pipeline(
    *,
    request_id: str,
    job_id: str,
    revision: str,
    policy_version: str,
    source_resolver: SnapshotSourceResolver,
    output_dir: Path,
    primary_result: ArtifactValidationResult,
    candidate_results: list[ArtifactValidationResult],
    runner: B2Runner,
    nonce: str | None = None,
    created_at: str | None = None,
    runtime_policy: B2RuntimePolicy | Mapping[str, Any] | None = None,
    sandbox_runtime: str | None = "gvisor",
    profile: str = "B2_STANDARD",
    log_complete: bool = True,
) -> dict[str, Any]:
    effective_nonce = nonce or secrets.token_urlsafe(24)

    try:
        manifest = build_b2_input_manifest(
            request_id=request_id,
            job_id=job_id,
            source_resolver=source_resolver,
            revision=revision,
            policy_version=policy_version,
            primary_result=primary_result,
            candidate_results=candidate_results,
        )
    except B2ManifestError as exc:
        return _pre_runner_failure_check(
            request_id=request_id,
            job_id=job_id,
            primary_result=primary_result,
            sandbox_runtime=sandbox_runtime,
            profile=profile,
            created_at=created_at,
            stage="manifest_build",
            error=exc,
        )

    try:
        input_dir = prepare_job_input_dir(
            source_resolver=source_resolver,
            manifest=manifest,
            output_dir=output_dir,
        )
    except B2ManifestError as exc:
        return _pre_runner_failure_check(
            request_id=request_id,
            job_id=job_id,
            primary_result=primary_result,
            sandbox_runtime=sandbox_runtime,
            profile=profile,
            created_at=created_at,
            stage="staging",
            error=exc,
            manifest_sha256=manifest.manifest_sha256,
        )

    context = B2RunnerContext(
        request_id=request_id,
        job_id=job_id,
        revision=revision,
        policy_version=policy_version,
        primary_result=primary_result,
        candidate_results=list(candidate_results),
        manifest=manifest,
        input_dir=input_dir,
        nonce=effective_nonce,
    )

    try:
        runner_output = _coerce_runner_output(runner(context))
    except Exception as exc:  # pragma: no cover - defensive contract guard
        return build_sandbox_check_from_runner_result(
            request_id=request_id,
            job_id=job_id,
            artifact_id=primary_result.artifact.artifact_id,
            repo_path=primary_result.artifact.repo_path,
            runner_result=None,
            expected_nonce=effective_nonce,
            grade=primary_result.grade.value,
            sandbox_runtime=sandbox_runtime,
            profile=profile,
            created_at=created_at,
            runtime_setup_errors=[f"RUNNER_CALL_FAILED:{type(exc).__name__}"],
            pending_api_refs=_pending_api_refs(primary_result),
            runtime_policy=runtime_policy,
            manifest_evidence=ManifestEvidence(host_manifest_sha256=manifest.manifest_sha256),
            artifacts=_artifacts(manifest),
            log_complete=log_complete,
        )

    manifest_evidence = _merge_manifest_evidence(runner_output.manifest_evidence, manifest)
    artifacts = {**_artifacts(manifest), **runner_output.artifacts}

    return build_sandbox_check_from_runner_result(
        request_id=request_id,
        job_id=job_id,
        artifact_id=primary_result.artifact.artifact_id,
        repo_path=primary_result.artifact.repo_path,
        runner_result=runner_output.runner_result,
        expected_nonce=effective_nonce,
        grade=primary_result.grade.value,
        sandbox_runtime=sandbox_runtime,
        profile=profile,
        created_at=created_at,
        runtime_evidence=runner_output.runtime_evidence,
        security_events=runner_output.security_events,
        pending_api_refs=_pending_api_refs(primary_result),
        runtime_policy=runtime_policy,
        manifest_evidence=manifest_evidence,
        artifacts=artifacts,
        runtime_setup_errors=runner_output.runtime_setup_errors,
        post_start_runtime_errors=runner_output.post_start_runtime_errors,
        log_complete=runner_output.log_complete if runner_output.log_complete is not None else log_complete,
    )


def _pre_runner_failure_check(
    *,
    request_id: str,
    job_id: str,
    primary_result: ArtifactValidationResult,
    sandbox_runtime: str | None,
    profile: str,
    created_at: str | None,
    stage: str,
    error: B2ManifestError,
    manifest_sha256: str | None = None,
) -> dict[str, Any]:
    error_payload = error.to_dict()
    reason_code = str(error.reason_code)
    check = B2SandboxCheck(
        schema_version=B2_SCHEMA_VERSION,
        request_id=request_id,
        job_id=job_id,
        artifact_id=primary_result.artifact.artifact_id,
        repo_path=primary_result.artifact.repo_path,
        grade=primary_result.grade.value,
        sandbox_runtime=sandbox_runtime,
        profile=profile,
        decision=B2Decision.BLOCKED_SECURITY_EVENT,
        deployable=False,
        runtime_evidence=RuntimeEvidence(),
        execution=ExecutionEvidence(),
        security_events=SecurityEvents(),
        manifest_evidence=ManifestEvidence(
            host_manifest_sha256=manifest_sha256,
            manifest_errors=[f"{reason_code}:{error.repo_path or primary_result.artifact.repo_path}"],
            input_hash_errors=[],
        ),
        artifacts={},
        policy_gate={
            "reason_code": reason_code,
            "decision": B2Decision.BLOCKED_SECURITY_EVENT.value,
            "stage": stage,
            "error": error_payload,
        },
        created_at=created_at or _utc_now(),
        reason=f"B-2 sandbox input preparation failed during {stage}",
    )
    return check.to_dict()


def _coerce_runner_output(
    value: B2RunnerOutput | B2RunnerResult | Mapping[str, Any] | None,
) -> B2RunnerOutput:
    if isinstance(value, B2RunnerOutput):
        return value
    if isinstance(value, Mapping) and _looks_like_runner_output_envelope(value):
        return B2RunnerOutput(
            runner_result=value.get("runner_result"),
            runtime_evidence=value.get("runtime_evidence"),
            security_events=value.get("security_events"),
            manifest_evidence=value.get("manifest_evidence"),
            artifacts=dict(value.get("artifacts") or {}),
            runtime_setup_errors=list(value.get("runtime_setup_errors") or []),
            post_start_runtime_errors=list(value.get("post_start_runtime_errors") or []),
            log_complete=value.get("log_complete"),
        )
    return B2RunnerOutput(runner_result=value)


def _looks_like_runner_output_envelope(value: Mapping[str, Any]) -> bool:
    envelope_keys = {
        "runner_result",
        "runtime_evidence",
        "security_events",
        "manifest_evidence",
        "artifacts",
        "runtime_setup_errors",
        "post_start_runtime_errors",
        "log_complete",
    }
    return any(key in value for key in envelope_keys)


def _merge_manifest_evidence(
    value: ManifestEvidence | Mapping[str, Any] | None,
    manifest: B2InputManifest,
) -> ManifestEvidence:
    if isinstance(value, ManifestEvidence):
        return ManifestEvidence(
            host_manifest_sha256=value.host_manifest_sha256 or manifest.manifest_sha256,
            manifest_errors=list(value.manifest_errors),
            input_hash_errors=list(value.input_hash_errors),
        )
    data = dict(value or {})
    data["host_manifest_sha256"] = data.get("host_manifest_sha256") or manifest.manifest_sha256
    return ManifestEvidence(**data)


def _pending_api_refs(result: ArtifactValidationResult) -> list[str]:
    details = result.details or {}
    return list(details.get("pending_api_refs") or [])


def _artifacts(manifest: B2InputManifest) -> dict[str, str]:
    return {
        "input_manifest": f"input/{B2_INPUT_MANIFEST_FILENAME}",
        "host_manifest_sha256": manifest.manifest_sha256,
    }


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
