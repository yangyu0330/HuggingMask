from pathlib import Path

from analyzer.schemas import (
    ArtifactRef,
    ArtifactValidationResult,
    ValidationJobRequest,
    ValidationJobResponse,
    ReasonEntry,
)
from analyzer.validators.weight.pipeline import validate

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


def _map_result(artifact, core_result, policy_fingerprint):
    status = "PASS" if core_result.get("status") == "PASS" else "BLOCK"

    reason_code, reason_message = _extract_reason(core_result)

    return ArtifactValidationResult(
        artifact=artifact,
        status=status,
        reason_entries=[
            ReasonEntry(
                code=reason_code,
                message=reason_message,
            )
        ],
        detail=_json_safe(core_result),
        generated_artifact=_build_generated_artifact(artifact, core_result),
    )


def validate_job(job: ValidationJobRequest) -> ValidationJobResponse:
    results = []
    overall_status = "PASS"

    for artifact in job.artifacts:
        expected_sha256 = None

        if artifact.file_kind == "SAFETENSORS":
            expected_sha256 = artifact.sha256

        core = validate(
            path=artifact.temp_local_path,
            policy_fingerprint=job.policy_fingerprint,
            expected_sha256=expected_sha256,
            enable_path_b=getattr(job, "enable_path_b", False),
        )

        mapped = _map_result(artifact, core, job.policy_fingerprint)
        results.append(mapped)

        if mapped.status == "BLOCK":
            overall_status = "BLOCK"

    return ValidationJobResponse(
        request_id=job.request_id,
        job_id=job.job_id,
        overall_status=overall_status,
        artifact_results=results,
    )