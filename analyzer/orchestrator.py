"""Minimal orchestrator adapter for validator integration.

This adapter dispatches artifacts to existing validators and computes minimal
job-level status/decision. It is intentionally limited and does not replace the
final Analyzer Core response policy.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Callable, Mapping

from analyzer.schemas import (
    ArtifactRef,
    ArtifactValidationResult,
    CodeGrade,
    OverallDecision,
    PolicyInfo,
    ReasonEntry,
    ReviewAction,
    RouteKind,
    RuntimeContext,
    ValidationJobRequest,
    ValidationJobResponse,
    ValidationStatus,
)
from analyzer.validators.code_api_policy import WhitelistLookup
from analyzer.validators.code_semantic import (
    is_preprocessing_metadata_kind,
    validate_preprocessing_metadata_artifact,
)
from analyzer.validators.code_validator import validate_python_artifact
from analyzer.validators.config_validator import validate_config_artifact

SourceLoader = Callable[[str], str | bytes | None] | Mapping[str, str | bytes]
RuntimeCheckLoader = Callable[[str], dict[str, Any] | None] | Mapping[str, dict[str, Any]]
AstCallMetadataLoader = Callable[[str], list[dict[str, Any]] | None] | Mapping[str, list[dict[str, Any]]]


def run_validation_job(
    request: ValidationJobRequest | dict[str, Any],
    *,
    source_loader: SourceLoader,
    whitelist_lookup: WhitelistLookup | None = None,
    runtime_check_loader: RuntimeCheckLoader | None = None,
    ast_call_metadata_loader: AstCallMetadataLoader | None = None,
) -> ValidationJobResponse:
    """Dispatch one validation job and return a minimal ValidationJobResponse."""

    normalized = request if isinstance(request, ValidationJobRequest) else ValidationJobRequest.from_dict(request)
    artifact_results = dispatch_artifacts(
        artifacts=normalized.artifacts,
        policy=normalized.policy,
        stop_on_first_block=normalized.stop_on_first_block,
        source_loader=source_loader,
        whitelist_lookup=whitelist_lookup,
        runtime_check_loader=runtime_check_loader,
        ast_call_metadata_loader=ast_call_metadata_loader,
    )

    overall_status = _compute_overall_status(artifact_results)
    overall_decision = _overall_decision_from_status(overall_status)
    release_action = _release_action_from_status(overall_status)

    approved_artifact_ids = [item.artifact.artifact_id for item in artifact_results if item.status is ValidationStatus.PASS]
    blocked_artifact_ids = [item.artifact.artifact_id for item in artifact_results if item.status is ValidationStatus.BLOCK]
    pending_artifact_ids = [
        item.artifact.artifact_id
        for item in artifact_results
        if item.status in {ValidationStatus.PENDING_REVIEW, ValidationStatus.ERROR}
    ]

    summary_reason_entries = _build_summary_reason_entries(overall_status, artifact_results)

    response = ValidationJobResponse(
        request_id=normalized.request_id,
        job_id=normalized.job_id,
        overall_decision=overall_decision,
        overall_status=overall_status,
        release_action=release_action,
        artifact_results=artifact_results,
        approved_artifact_ids=approved_artifact_ids,
        blocked_artifact_ids=blocked_artifact_ids,
        pending_artifact_ids=pending_artifact_ids,
        generated_artifacts=[],
        report_id=f"report-{normalized.job_id}",
        report_path=f"/tmp/reports/{normalized.job_id}.json",
        reason_entries=summary_reason_entries,
        created_at=_utc_now(),
    )
    return response


def dispatch_artifacts(
    artifacts: list[ArtifactRef],
    *,
    policy: PolicyInfo,
    source_loader: SourceLoader,
    stop_on_first_block: bool = False,
    whitelist_lookup: WhitelistLookup | None = None,
    runtime_check_loader: RuntimeCheckLoader | None = None,
    ast_call_metadata_loader: AstCallMetadataLoader | None = None,
) -> list[ArtifactValidationResult]:
    """Dispatch artifact list directly to validators."""

    results: list[ArtifactValidationResult] = []
    for artifact in artifacts:
        source_loaded = _load_from_loader(source_loader, artifact.repo_path)
        if source_loaded["ok"] is not True:
            error_result = _build_loader_error_result(artifact, policy=policy, error=str(source_loaded["error"]))
            results.append(error_result)
            continue

        source = source_loaded["value"]
        try:
            if artifact.file_kind.value == "PYTHON":
                runtime_check = _load_optional(runtime_check_loader, artifact.repo_path)
                ast_call_metadata = _load_optional(ast_call_metadata_loader, artifact.repo_path) or []
                result = validate_python_artifact(
                    artifact=artifact,
                    source=source,
                    policy=policy,
                    whitelist_lookup=whitelist_lookup,
                    runtime_check=runtime_check,
                    ast_call_metadata=ast_call_metadata,
                )
            elif artifact.file_kind.value in {"CONFIG_JSON", "TOKENIZER_CONFIG_JSON"}:
                result = validate_config_artifact(
                    artifact=artifact,
                    source=source,
                    policy=policy,
                    whitelist_lookup=whitelist_lookup,
                    source_loader=source_loader,
                    runtime_check_loader=runtime_check_loader,
                    ast_call_metadata_loader=ast_call_metadata_loader,
                )
            elif is_preprocessing_metadata_kind(artifact.file_kind):
                result = validate_preprocessing_metadata_artifact(
                    artifact=artifact,
                    source=source,
                    policy=policy,
                )
            else:
                result = _build_skipped_result(
                    artifact,
                    policy=policy,
                    reason_code="UNKNOWN_FILE_TYPE",
                    message="unsupported artifact for minimal orchestrator adapter",
                )
        except Exception as exc:  # pragma: no cover - defensive
            result = _build_error_result(
                artifact,
                policy=policy,
                reason_code="VALIDATOR_INFRA_ERROR",
                message=f"validator dispatch error: {exc}",
            )

        results.append(result)
        if stop_on_first_block and result.status is ValidationStatus.BLOCK:
            break

    return results


def _compute_overall_status(artifact_results: list[ArtifactValidationResult]) -> ValidationStatus:
    if any(item.status is ValidationStatus.BLOCK for item in artifact_results):
        return ValidationStatus.BLOCK
    if any(item.status is ValidationStatus.ERROR for item in artifact_results):
        return ValidationStatus.ERROR
    if any(item.status is ValidationStatus.PENDING_REVIEW for item in artifact_results):
        return ValidationStatus.PENDING_REVIEW
    if artifact_results and all(item.status is ValidationStatus.PASS for item in artifact_results):
        return ValidationStatus.PASS
    return ValidationStatus.ERROR


def _overall_decision_from_status(status: ValidationStatus) -> OverallDecision:
    if status is ValidationStatus.BLOCK:
        return OverallDecision.DENY
    if status is ValidationStatus.ERROR:
        return OverallDecision.ERROR
    if status is ValidationStatus.PENDING_REVIEW:
        return OverallDecision.REVIEW_REQUIRED
    return OverallDecision.APPROVE


def _release_action_from_status(status: ValidationStatus) -> str:
    if status is ValidationStatus.BLOCK:
        return "DENY"
    if status is ValidationStatus.ERROR:
        return "ERROR"
    if status is ValidationStatus.PENDING_REVIEW:
        return "REVIEW_QUEUE"
    return "APPROVE_AND_STORE"


def _build_summary_reason_entries(
    overall_status: ValidationStatus,
    artifact_results: list[ArtifactValidationResult],
) -> list[ReasonEntry]:
    if overall_status is ValidationStatus.BLOCK:
        code = "CONTEXT_API_BLOCKED" if _has_context_block(artifact_results) else "DANGEROUS_API"
        return [
            ReasonEntry(
                code=code,
                severity="HIGH",
                message="at least one artifact is blocked",
                evidence=[item.artifact.repo_path for item in artifact_results if item.status is ValidationStatus.BLOCK],
                review_required=False,
            )
        ]
    if overall_status is ValidationStatus.PENDING_REVIEW:
        return [
            ReasonEntry(
                code="GRADE_B2_GATE_REQUIRED",
                severity="MEDIUM",
                message="at least one artifact requires review",
                evidence=[item.artifact.repo_path for item in artifact_results if item.status is ValidationStatus.PENDING_REVIEW],
                review_required=True,
            )
        ]
    if overall_status is ValidationStatus.ERROR:
        return [
            ReasonEntry(
                code="VALIDATOR_INFRA_ERROR",
                severity="HIGH",
                message="orchestrator observed infrastructure or loader errors",
                evidence=[item.artifact.repo_path for item in artifact_results if item.status is ValidationStatus.ERROR],
                review_required=True,
            )
        ]
    return []


def _has_context_block(artifact_results: list[ArtifactValidationResult]) -> bool:
    for item in artifact_results:
        if item.status is not ValidationStatus.BLOCK:
            continue
        context_scan = item.details.get("context_api_scan", {})
        if isinstance(context_scan, dict) and context_scan.get("summary_decision") == "block":
            return True
    return False


def _load_from_loader(loader: SourceLoader, key: str) -> dict[str, Any]:
    try:
        if callable(loader):
            value = loader(key)
        else:
            value = loader.get(key)
    except Exception as exc:  # pragma: no cover - defensive
        return {"ok": False, "error": f"loader_error:{exc}"}
    if value is None:
        return {"ok": False, "error": "source_not_found"}
    if not isinstance(value, (str, bytes)):
        return {"ok": False, "error": "invalid_source_type"}
    return {"ok": True, "value": value}


def _load_optional(loader: RuntimeCheckLoader | AstCallMetadataLoader | None, key: str) -> Any:
    if loader is None:
        return None
    if callable(loader):
        return loader(key)
    return loader.get(key)


def _build_loader_error_result(artifact: ArtifactRef, *, policy: PolicyInfo, error: str) -> ArtifactValidationResult:
    return _build_error_like_result(
        artifact=artifact,
        policy=policy,
        status=ValidationStatus.ERROR,
        review_action=ReviewAction.MANUAL_REVIEW_REQUIRED,
        reason_code="VALIDATOR_INFRA_ERROR",
        message=f"source loader failure: {error}",
    )


def _build_error_result(
    artifact: ArtifactRef,
    *,
    policy: PolicyInfo,
    reason_code: str,
    message: str,
) -> ArtifactValidationResult:
    return _build_error_like_result(
        artifact=artifact,
        policy=policy,
        status=ValidationStatus.ERROR,
        review_action=ReviewAction.MANUAL_REVIEW_REQUIRED,
        reason_code=reason_code,
        message=message,
    )


def _build_skipped_result(
    artifact: ArtifactRef,
    *,
    policy: PolicyInfo,
    reason_code: str,
    message: str,
) -> ArtifactValidationResult:
    return _build_error_like_result(
        artifact=artifact,
        policy=policy,
        status=ValidationStatus.SKIPPED,
        review_action=ReviewAction.NONE,
        reason_code=reason_code,
        message=message,
    )


def _build_error_like_result(
    artifact: ArtifactRef,
    *,
    policy: PolicyInfo,
    status: ValidationStatus,
    review_action: ReviewAction,
    reason_code: str,
    message: str,
) -> ArtifactValidationResult:
    started_at = _utc_now()
    route_kind = _default_route_kind(artifact)
    return ArtifactValidationResult(
        artifact=artifact,
        route_kind=route_kind,
        status=status,
        grade=CodeGrade.NA,
        review_action=review_action,
        cache_key=f"{artifact.sha256}:{artifact.file_kind.value}:{policy.policy_fingerprint}",
        cache_hit=False,
        reason_entries=[
            ReasonEntry(
                code=reason_code,
                severity="HIGH" if status in {ValidationStatus.ERROR, ValidationStatus.BLOCK} else "LOW",
                message=message,
                evidence=[artifact.repo_path],
                review_required=status in {ValidationStatus.ERROR, ValidationStatus.PENDING_REVIEW},
            )
        ],
        details={
            "error": message,
            "effective_status": status.value,
        },
        started_at=started_at,
        finished_at=_utc_now(),
    )


def _default_route_kind(artifact: ArtifactRef) -> RouteKind:
    if artifact.file_kind.value in {"CONFIG_JSON", "TOKENIZER_CONFIG_JSON"}:
        return RouteKind.CONFIG_SCHEMA_VALIDATION
    if is_preprocessing_metadata_kind(artifact.file_kind):
        return RouteKind.PREPROCESSING_SEMANTIC_SCAN
    return RouteKind.CODE_AST_SCAN


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def build_minimal_request(
    *,
    request_id: str,
    job_id: str,
    policy: PolicyInfo,
    artifacts: list[ArtifactRef],
    stop_on_first_block: bool = False,
) -> ValidationJobRequest:
    """Helper for tests that want artifact-list style entry."""

    return ValidationJobRequest(
        request_id=request_id,
        job_id=job_id,
        model={
            "repo_id": "local/test-model",
            "revision": "main",
            "source_host": "local",
            "source_url": "local://fixture",
            "requested_at": _utc_now(),
            "endpoint_mode": "HF_ENDPOINT_PROXY",
            "requested_by": "test",
        },
        policy=policy,
        runtime_context=RuntimeContext(
            sandbox_runtime="gvisor",
            network_disabled=True,
            read_only_fs=True,
            compare_mode="TORCH_ALLCLOSE_THEN_SHA256",
            allow_cache_lookup=False,
            generate_mlbom=False,
            write_audit_log=False,
        ),
        artifacts=artifacts,
        requested_routes=[],
        stop_on_first_block=stop_on_first_block,
    )
