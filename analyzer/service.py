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
CONFIG_FILE_KINDS = {"CONFIG_JSON", "TOKENIZER_CONFIG_JSON"}
PYTHON_FILE_KINDS = {"PYTHON"}


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
    if str(artifact.file_kind) in CONFIG_FILE_KINDS:
        return RouteKind.CONFIG_SCHEMA_VALIDATION
    if str(artifact.file_kind) in PYTHON_FILE_KINDS:
        return RouteKind.CODE_AST_SCAN
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


def _read_artifact_source(artifact) -> bytes | None:
    """artifact의 temp_local_path 에서 파일 읽기."""
    path = Path(artifact.temp_local_path)
    if not path.exists():
        return None
    try:
        return path.read_bytes()
    except Exception:
        return None


def _validate_config_artifact(artifact) -> ArtifactValidationResult:
    """config.json / tokenizer_config.json 검증."""
    from analyzer.validators.config_validator import validate_config_artifact

    source = _read_artifact_source(artifact)
    if source is None:
        return _build_result(
            artifact=artifact,
            status="BLOCK",
            reason_code="SOURCE_READ_ERROR",
            reason_message="config 파일을 읽을 수 없음",
            details={"status": "BLOCK", "reason_code": "SOURCE_READ_ERROR"},
        )

    try:
        return validate_config_artifact(
            artifact=artifact,
            source=source,
        )
    except Exception as e:
        return _build_result(
            artifact=artifact,
            status="BLOCK",
            reason_code="VALIDATOR_ERROR",
            reason_message=f"config 검증 중 오류: {e}",
            details={"status": "BLOCK", "reason_code": "VALIDATOR_ERROR", "error": str(e)},
        )


def _validate_python_artifact(artifact) -> ArtifactValidationResult:
    """preprocessing .py 파일 검증."""
    from analyzer.validators.preprocessing_validator import validate_preprocessing_artifact

    source = _read_artifact_source(artifact)
    if source is None:
        return _build_result(
            artifact=artifact,
            status="BLOCK",
            reason_code="SOURCE_READ_ERROR",
            reason_message="python 파일을 읽을 수 없음",
            details={"status": "BLOCK", "reason_code": "SOURCE_READ_ERROR"},
        )

    try:
        return validate_preprocessing_artifact(
            filename=artifact.file_name,
            source=source,
            artifact=artifact,
        )
    except Exception as e:
        return _build_result(
            artifact=artifact,
            status="BLOCK",
            reason_code="VALIDATOR_ERROR",
            reason_message=f"python 검증 중 오류: {e}",
            details={"status": "BLOCK", "reason_code": "VALIDATOR_ERROR", "error": str(e)},
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

        # ── config.json / tokenizer_config.json ──────────────────────────────
        if str(artifact.file_kind) in CONFIG_FILE_KINDS:
            mapped = _validate_config_artifact(artifact)

        # ── preprocessing .py 파일 ────────────────────────────────────────────
        elif str(artifact.file_kind) in PYTHON_FILE_KINDS:
            mapped = _validate_python_artifact(artifact)

        # ── 가중치 파일 (SAFETENSORS / PICKLE) ───────────────────────────────
        elif str(artifact.file_kind) in WEIGHT_FILE_KINDS:
            core = validate(
                path=artifact.temp_local_path,
                policy_fingerprint=policy_fingerprint,
                expected_sha256=artifact.sha256,
                file_kind=artifact.file_kind,
                enable_path_b=getattr(job, "enable_path_b", False),
            )
            mapped = _map_result(artifact, core, policy_fingerprint)

        # ── 그 외 ─────────────────────────────────────────────────────────────
        else:
            mapped = _build_result(
                artifact=artifact,
                status="SKIPPED",
                reason_code="UNSUPPORTED_FILE_KIND",
                reason_message=f"지원하지 않는 파일 종류: {artifact.file_kind}",
                details={
                    "status": "SKIPPED",
                    "reason_code": "UNSUPPORTED_FILE_KIND",
                },
            )

        results.append(mapped)

        if mapped.generated_artifact is not None:
            generated_artifacts.append(mapped.generated_artifact)

        if mapped.status == ValidationStatus.BLOCK:
            overall_status = "BLOCK"
            blocked_artifact_ids.append(artifact.artifact_id)

        elif mapped.status == ValidationStatus.PASS:
            if str(artifact.file_kind) == "PICKLE":
                # 보안 정책:
                # 원본 pickle은 release 대상이 아님.
                # Path A에서 변환된 safetensors artifact만 release 승인.
                if mapped.generated_artifact is None:
                    overall_status = "BLOCK"
                    blocked_artifact_ids.append(artifact.artifact_id)
                    mapped.status = ValidationStatus.BLOCK
                    mapped.reason_entries.append(
                        ReasonEntry(
                            code="PICKLE_RELEASE_REQUIRES_CONVERTED_SAFETENSORS",
                            message=(
                                "pickle passed validation but no converted "
                                "safetensors artifact is available for release"
                            ),
                        )
                    )
                else:
                    approved_artifact_ids.append(mapped.generated_artifact.artifact_id)
            else:
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
