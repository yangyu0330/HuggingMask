from datetime import UTC, datetime
from pathlib import Path

from analyzer.schemas import (
    ArtifactRef,
    ArtifactValidationResult,
    CodeGrade,
    OverallDecision,
    ReasonEntry,
    ReviewAction,
    RouteKind,
    ValidationJobRequest,
    ValidationJobResponse,
    ValidationStatus,
)
from analyzer.validators.weight.pipeline import validate


WEIGHT_FILE_KINDS = {"SAFETENSORS", "PICKLE"}


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _json_safe(obj):
    if isinstance(obj, dict):
        cleaned = {}
        for key, value in obj.items():
            if key == "tensor_dict":
                continue
            cleaned[key] = _json_safe(value)
        return cleaned

    if isinstance(obj, list):
        return [_json_safe(item) for item in obj]

    if isinstance(obj, tuple):
        return [_json_safe(item) for item in obj]

    if obj.__class__.__module__.startswith("torch"):
        return str(obj)

    return obj


def _extract_reason(core_result: dict):
    reason_code = core_result.get("reason_code")
    reason_message = core_result.get("reason")

    for key in ("path_a", "path_b", "diff", "converted", "yara", "modelscan"):
        if reason_code:
            break
        sub = core_result.get(key)
        if isinstance(sub, dict):
            reason_code = sub.get("reason_code")
            reason_message = sub.get("reason")

    return reason_code or "UNKNOWN", reason_message or "no message"


def _route_kind_for(artifact) -> RouteKind:
    if artifact.file_kind == "SAFETENSORS":
        return RouteKind.SAFETENSORS_FAST_PATH
    if artifact.file_kind == "PICKLE":
        return RouteKind.PICKLE_PATH_A
    return RouteKind.CONFIG_SCHEMA_VALIDATION


def _build_generated_artifact(artifact, core_result: dict):
    converted = core_result.get("converted")
    if not isinstance(converted, dict):
        return None

    if converted.get("status") != "PASS":
        return None

    output_path = converted.get("output_path")
    output_sha256 = converted.get("sha256")

    if not output_path or not output_sha256:
        return None

    out = Path(output_path)

    return ArtifactRef(
        artifact_id=f"sha256:{output_sha256}",
        repo_path=out.as_posix(),
        file_name=out.name,
        file_kind="SAFETENSORS",
        detected_extension=".safetensors",
        size_bytes=out.stat().st_size if out.exists() else 0,
        sha256=output_sha256,
        source_url=artifact.source_url,
        temp_local_path=out.as_posix(),
        referenced_by=[artifact.file_name],
        is_generated=True,
    )


def _build_result(
    artifact,
    status: str,
    reason_code: str,
    reason_message: str,
    details: dict,
    generated_artifact=None,
) -> ArtifactValidationResult:
    safe_details = _json_safe(details)

    return ArtifactValidationResult(
        artifact=artifact,
        route_kind=_route_kind_for(artifact),
        status=ValidationStatus(status),
        grade=CodeGrade.NA,
        review_action=ReviewAction.NONE,
        cache_key=safe_details.get("cache_key", ""),
        cache_hit=bool(safe_details.get("cached", False)),
        reason_entries=[
            ReasonEntry(
                code=reason_code,
                message=reason_message,
            )
        ],
        started_at=_now(),
        finished_at=_now(),
        details=safe_details,
        generated_artifact=generated_artifact,
    )


def _map_result(artifact, core_result, policy_fingerprint):
    status = "PASS" if core_result.get("status") == "PASS" else "BLOCK"

    reason_code, reason_message = _extract_reason(core_result)

    return _build_result(
        artifact=artifact,
        status=status,
        reason_code=reason_code,
        reason_message=reason_message,
        details=core_result,
        generated_artifact=_build_generated_artifact(artifact, core_result),
    )


def validate_job(job: ValidationJobRequest) -> ValidationJobResponse:
    results = []
    generated_artifacts = []
    approved_artifact_ids = []
    blocked_artifact_ids = []
    pending_artifact_ids = []
    overall_status = "PASS"

    policy_fingerprint = job.policy_fingerprint or "default-policy"

    for artifact in job.artifacts:
        if artifact.file_kind not in WEIGHT_FILE_KINDS:
            mapped = _build_result(
                artifact=artifact,
                status="SKIPPED",
                reason_code="NOT_WEIGHT_ARTIFACT",
                reason_message="artifact skipped because it is not a weight artifact",
                details={
                    "status": "SKIPPED",
                    "reason_code": "NOT_WEIGHT_ARTIFACT",
                    "reason": "artifact skipped because it is not a weight artifact",
                },
            )

            results.append(mapped)
            continue

        core = validate(
            path=artifact.temp_local_path,
            policy_fingerprint=policy_fingerprint,
            expected_sha256=artifact.sha256,
            file_kind=artifact.file_kind,
            enable_path_b=getattr(job, "enable_path_b", False),
        )

        mapped = _map_result(artifact, core, policy_fingerprint)
        results.append(mapped)

        if mapped.generated_artifact is not None:
            generated_artifacts.append(mapped.generated_artifact)

        if mapped.status == ValidationStatus.BLOCK:
            overall_status = "BLOCK"
            blocked_artifact_ids.append(artifact.artifact_id)
        elif mapped.status == ValidationStatus.PASS:
            approved_artifact_ids.append(artifact.artifact_id)
        else:
            pending_artifact_ids.append(artifact.artifact_id)

    decision = (
        OverallDecision.DENY
        if overall_status == "BLOCK"
        else OverallDecision.APPROVE
    )

    return ValidationJobResponse(
        request_id=job.request_id,
        job_id=job.job_id,
        overall_decision=decision,
        overall_status=ValidationStatus(overall_status),
        release_action="DENY" if overall_status == "BLOCK" else "APPROVE",
        artifact_results=results,
        approved_artifact_ids=approved_artifact_ids,
        blocked_artifact_ids=blocked_artifact_ids,
        pending_artifact_ids=pending_artifact_ids,
        generated_artifacts=generated_artifacts,
        report_id=f"report-{job.job_id}",
        report_path="",
        reason_entries=[],
        created_at=_now(),
    )
