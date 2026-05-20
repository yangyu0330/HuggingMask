from datetime import UTC, datetime
from pathlib import Path
from typing import Any

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


def _make_source_loader(artifacts: list) -> dict[str, bytes]:
    """artifact 목록에서 temp_local_path 기반 source_loader 딕셔너리 생성."""
    loader: dict[str, bytes] = {}
    for artifact in artifacts:
        path = Path(artifact.temp_local_path)
        if path.exists():
            try:
                loader[artifact.repo_path] = path.read_bytes()
            except Exception:
                pass
    return loader


def validate_job(job: ValidationJobRequest) -> ValidationJobResponse:
    from analyzer.orchestrator import run_validation_job

    # 파일 종류별로 분리
    weight_artifacts = [
        a for a in job.artifacts
        if str(a.file_kind) in WEIGHT_FILE_KINDS
    ]
    non_weight_artifacts = [
        a for a in job.artifacts
        if str(a.file_kind) not in WEIGHT_FILE_KINDS
    ]

    results = []
    generated_artifacts = []
    approved_artifact_ids = []
    blocked_artifact_ids = []
    pending_artifact_ids = []
    overall_status = "PASS"

    policy_fingerprint = job.policy_fingerprint or "default-policy"

    # ── 가중치 파일: 기존 weight validator 사용 ──────────────────────────────
    for artifact in weight_artifacts:
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
            if str(artifact.file_kind) == "PICKLE":
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
        elif mapped.status == ValidationStatus.SKIPPED:
            pass
        else:
            pending_artifact_ids.append(artifact.artifact_id)

    # ── 비가중치 파일: orchestrator에 위임 ──────────────────────────────────
    # orchestrator가 처리하는 파일 종류
    ORCHESTRATOR_FILE_KINDS = {"PYTHON", "CONFIG_JSON", "TOKENIZER_CONFIG_JSON"}

    orchestrator_artifacts = [
        a for a in non_weight_artifacts
        if str(a.file_kind) in ORCHESTRATOR_FILE_KINDS
    ]
    skipped_artifacts = [
        a for a in non_weight_artifacts
        if str(a.file_kind) not in ORCHESTRATOR_FILE_KINDS
    ]

    # 지원하지 않는 파일 종류 → SKIPPED
    for artifact in skipped_artifacts:
        skipped = _build_result(
            artifact=artifact,
            status="SKIPPED",
            reason_code="UNSUPPORTED_FILE_KIND",
            reason_message=f"지원하지 않는 파일 종류: {artifact.file_kind}",
            details={"status": "SKIPPED", "reason_code": "UNSUPPORTED_FILE_KIND"},
        )
        results.append(skipped)

    if orchestrator_artifacts:
        source_loader = _make_source_loader(orchestrator_artifacts)

        # job 복사본에 orchestrator 대상 artifacts만 담아서 호출
        import dataclasses
        sub_job = dataclasses.replace(job, artifacts=orchestrator_artifacts)

        try:
            orch_response = run_validation_job(
                sub_job,
                source_loader=source_loader,
            )

            for item in orch_response.artifact_results:
                results.append(item)

            approved_artifact_ids.extend(orch_response.approved_artifact_ids)
            blocked_artifact_ids.extend(orch_response.blocked_artifact_ids)
            pending_artifact_ids.extend(orch_response.pending_artifact_ids)

            # overall_status 집계: BLOCK > PENDING_REVIEW > PASS
            if str(orch_response.overall_status) == "BLOCK":
                overall_status = "BLOCK"
            elif str(orch_response.overall_status) in {"PENDING_REVIEW", "ERROR"}:
                if overall_status == "PASS":
                    overall_status = "PENDING_REVIEW"

        except Exception as e:
            # orchestrator 실패 시 전부 ERROR 처리
            for artifact in orchestrator_artifacts:
                err_result = _build_result(
                    artifact=artifact,
                    status="ERROR",
                    reason_code="ORCHESTRATOR_ERROR",
                    reason_message=f"orchestrator 호출 실패: {e}",
                    details={"status": "ERROR", "error": str(e)},
                )
                results.append(err_result)
                overall_status = "BLOCK"
                blocked_artifact_ids.append(artifact.artifact_id)

    decision = (
        OverallDecision.DENY
        if overall_status == "BLOCK"
        else OverallDecision.APPROVE
        if overall_status == "PASS"
        else OverallDecision.REVIEW_REQUIRED
    )

    return ValidationJobResponse(
        request_id=job.request_id,
        job_id=job.job_id,
        overall_decision=decision,
        overall_status=ValidationStatus(overall_status),
        release_action="DENY" if overall_status in {"BLOCK", "PENDING_REVIEW"} else "APPROVE",
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
