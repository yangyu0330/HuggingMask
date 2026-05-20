"""Minimal orchestrator adapter for validator integration.

This adapter dispatches artifacts to existing validators and computes minimal
job-level status/decision. It is intentionally limited and does not replace the
final Analyzer Core response policy.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from tempfile import gettempdir
from typing import Any, Callable, Mapping

from analyzer.schemas import (
    ArtifactRef,
    ArtifactValidationResult,
    CodeGrade,
    FileKind,
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
from sandbox.b2.decision_builder import build_sandbox_check_from_runner_result
from sandbox.b2.pipeline import run_b2_sandbox_pipeline

SourceLoader = Callable[[str], str | bytes | None] | Mapping[str, str | bytes]
RuntimeCheckLoader = Callable[[str], dict[str, Any] | None] | Mapping[str, dict[str, Any]]
AstCallMetadataLoader = Callable[[str], list[dict[str, Any]] | None] | Mapping[str, list[dict[str, Any]]]
SandboxCheckLoader = (
    Callable[[ArtifactValidationResult], dict[str, Any] | None]
    | Mapping[str, dict[str, Any]]
)


def run_validation_job(
    request: ValidationJobRequest | dict[str, Any],
    *,
    source_loader: SourceLoader,
    whitelist_lookup: WhitelistLookup | None = None,
    runtime_check_loader: RuntimeCheckLoader | None = None,
    ast_call_metadata_loader: AstCallMetadataLoader | None = None,
    source_resolver: Any | None = None,
    sandbox_check_loader: SandboxCheckLoader | None = None,
    b2_runner: Any | None = None,
    b2_output_dir: str | Path | None = None,
    revision: str | None = None,
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
        source_resolver=source_resolver,
        sandbox_check_loader=sandbox_check_loader,
        b2_runner=b2_runner,
        b2_output_dir=b2_output_dir,
        revision=revision or normalized.model.revision,
        request_id=normalized.request_id,
        job_id=normalized.job_id,
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
    source_resolver: Any | None = None,
    sandbox_check_loader: SandboxCheckLoader | None = None,
    b2_runner: Any | None = None,
    b2_output_dir: str | Path | None = None,
    revision: str | None = None,
    request_id: str | None = None,
    job_id: str | None = None,
) -> list[ArtifactValidationResult]:
    """Dispatch artifact list directly to validators."""

    results: list[ArtifactValidationResult] = []
    sibling_results_by_key: dict[str, ArtifactValidationResult] = {}
    parent_linked_results: list[tuple[ArtifactValidationResult, list[ArtifactValidationResult]]] = []
    for artifact in artifacts:
        source_loaded = _load_from_loader(source_loader, artifact.repo_path)
        if source_loaded["ok"] is not True:
            error_result = _build_loader_error_result(artifact, policy=policy, error=str(source_loaded["error"]))
            results.append(error_result)
            continue

        source = source_loaded["value"]
        linked_code_results_for_parent: list[ArtifactValidationResult] = []

        def _collect_linked_code_result(result: ArtifactValidationResult) -> None:
            linked_code_results_for_parent.append(result)

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
                    source_resolver=source_resolver,
                    linked_code_result_collector=_collect_linked_code_result,
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

        sibling_results_for_parent: list[ArtifactValidationResult] = []
        new_sibling_results: list[ArtifactValidationResult] = []
        for linked_result in linked_code_results_for_parent:
            key = _sibling_result_key(linked_result)
            sibling_result = sibling_results_by_key.get(key)
            if sibling_result is None:
                sibling_result = linked_result
                sibling_results_by_key[key] = sibling_result
                new_sibling_results.append(sibling_result)
            sibling_results_for_parent.append(sibling_result)
        if sibling_results_for_parent:
            parent_linked_results.append((result, sibling_results_for_parent))

        results.append(result)
        results.extend(new_sibling_results)
        if stop_on_first_block and result.status is ValidationStatus.BLOCK:
            break

    candidate_results = list(results)
    for index, result in enumerate(results):
        results[index] = _attach_b2_sandbox_check(
            result,
            source_resolver=source_resolver,
            sandbox_check_loader=sandbox_check_loader,
            b2_runner=b2_runner,
            b2_output_dir=b2_output_dir,
            revision=revision,
            policy=policy,
            candidate_results=candidate_results,
            request_id=request_id,
            job_id=job_id,
        )
    for parent, linked_results in parent_linked_results:
        _refresh_config_linked_results(parent, linked_results)

    return results


def _requires_b2_sandbox(result: ArtifactValidationResult) -> bool:
    details = result.details or {}
    role = (details.get("role_classification") or {}).get("role")
    ast_scan = details.get("ast_scan") or {}
    api_scan = details.get("api_scan") or {}
    context_scan = details.get("context_api_scan") or {}
    grade_result = details.get("grade_result") or {}

    has_b2_reason = (
        bool(details.get("pending_api_refs"))
        or context_scan.get("summary_decision") == "review"
        or (
            grade_result.get("requires_runtime_gate") is True
            and grade_result.get("status") == ValidationStatus.PENDING_REVIEW.value
        )
    )

    return (
        result.artifact.file_kind == FileKind.PYTHON
        and result.route_kind == RouteKind.CODE_SANDBOX_RUNTIME
        and result.grade == CodeGrade.B2
        and result.status == ValidationStatus.PENDING_REVIEW
        and result.review_action == ReviewAction.SECURITY_OWNER_GATE
        and role == "MODELING"
        and context_scan.get("summary_decision") != "block"
        and not ast_scan.get("dangerous_imports")
        and not ast_scan.get("dangerous_calls")
        and not ast_scan.get("dynamic_patterns")
        and not ast_scan.get("obfuscation_patterns")
        and not api_scan.get("blocked_apis")
        and has_b2_reason
    )


def _attach_b2_sandbox_check(
    result: ArtifactValidationResult,
    *,
    source_resolver: Any | None,
    sandbox_check_loader: SandboxCheckLoader | None,
    b2_runner: Any | None,
    b2_output_dir: str | Path | None,
    revision: str | None,
    policy: PolicyInfo,
    candidate_results: list[ArtifactValidationResult] | None,
    request_id: str | None,
    job_id: str | None,
) -> ArtifactValidationResult:
    if not _requires_b2_sandbox(result):
        return result

    sandbox_check = None
    if sandbox_check_loader is not None and source_resolver is not None:
        sandbox_check = _load_sandbox_check(sandbox_check_loader, result)

    if (
        sandbox_check is None
        and sandbox_check_loader is None
        and b2_runner is not None
        and _is_source_resolver(source_resolver)
    ):
        sandbox_check = _run_b2_pipeline_check(
            result,
            source_resolver=source_resolver,
            b2_runner=b2_runner,
            b2_output_dir=b2_output_dir,
            revision=revision,
            policy=policy,
            candidate_results=candidate_results or [],
            request_id=request_id,
            job_id=job_id,
        )

    if sandbox_check is None:
        sandbox_check = _build_sandbox_not_configured_check(
            result,
            request_id=request_id,
            job_id=job_id,
        )

    result.details = dict(result.details)
    result.details["sandbox_check"] = sandbox_check
    return result


def _run_b2_pipeline_check(
    result: ArtifactValidationResult,
    *,
    source_resolver: Any,
    b2_runner: Any,
    b2_output_dir: str | Path | None,
    revision: str | None,
    policy: PolicyInfo,
    candidate_results: list[ArtifactValidationResult],
    request_id: str | None,
    job_id: str | None,
) -> dict[str, Any]:
    try:
        return run_b2_sandbox_pipeline(
            request_id=request_id or "",
            job_id=job_id or "",
            revision=revision or "unknown",
            policy_version=policy.policy_version,
            source_resolver=source_resolver,
            output_dir=_b2_output_dir_for_result(b2_output_dir, result, job_id=job_id),
            primary_result=result,
            candidate_results=candidate_results,
            runner=b2_runner,
        )
    except Exception as exc:  # pragma: no cover - defensive integration guard
        check = build_sandbox_check_from_runner_result(
            request_id=request_id,
            job_id=job_id,
            artifact_id=result.artifact.artifact_id,
            repo_path=result.artifact.repo_path,
            runner_result=None,
            expected_nonce="",
            grade=result.grade.value,
            sandbox_runtime="gvisor",
            profile="B2_STANDARD",
            runtime_setup_errors=[f"B2_PIPELINE_FAILED:{type(exc).__name__}"],
            pending_api_refs=list((result.details or {}).get("pending_api_refs") or []),
        )
        check["policy_gate"]["pipeline_error"] = str(exc)
        return check


def _is_source_resolver(value: Any | None) -> bool:
    return value is not None and callable(getattr(value, "resolve", None))


def _b2_output_dir_for_result(
    base_dir: str | Path | None,
    result: ArtifactValidationResult,
    *,
    job_id: str | None,
) -> Path:
    base = Path(base_dir) if base_dir is not None else Path(gettempdir()) / "huggingmask-b2"
    job_segment = _safe_path_segment(job_id or "job")
    artifact_segment = _safe_path_segment(result.artifact.repo_path) or _safe_path_segment(
        result.artifact.artifact_id
    )
    return base / job_segment / artifact_segment


def _safe_path_segment(value: str) -> str:
    cleaned = "".join(ch if ch.isalnum() or ch in {"-", "_", "."} else "_" for ch in str(value))
    return cleaned.strip("._") or "item"


def _load_sandbox_check(
    loader: SandboxCheckLoader | None,
    result: ArtifactValidationResult,
) -> dict[str, Any] | None:
    if loader is None:
        return None
    if callable(loader):
        return loader(result)
    return loader.get(result.artifact.repo_path)


def _build_sandbox_not_configured_check(
    result: ArtifactValidationResult,
    *,
    request_id: str | None,
    job_id: str | None,
) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "request_id": request_id,
        "job_id": job_id,
        "artifact_id": result.artifact.artifact_id,
        "repo_path": result.artifact.repo_path,
        "grade": CodeGrade.B2.value,
        "sandbox_runtime": None,
        "profile": "B2_STANDARD",
        "decision": "NOT_RUN",
        "deployable": False,
        "runtime_evidence": {},
        "execution": {
            "import_status": "not_run",
            "instantiate_status": "not_run",
            "forward_status": "not_run",
        },
        "security_events": {
            "network_events": [],
            "unexpected_execve": [],
            "blocked_writes": [],
            "secret_path_access": [],
            "blocked_reads": [],
            "review_events": [],
        },
        "manifest_evidence": {
            "host_manifest_sha256": None,
            "manifest_errors": [],
            "input_hash_errors": [],
        },
        "artifacts": {},
        "policy_gate": {
            "reason_code": "SANDBOX_NOT_CONFIGURED",
        },
        "created_at": _utc_now(),
        "reason": "B-2 sandbox runner/resolver is not configured",
    }


def _sibling_result_key(result: ArtifactValidationResult) -> str:
    artifact_id = getattr(result.artifact, "artifact_id", "")
    if artifact_id:
        return artifact_id
    return result.artifact.repo_path


def _refresh_config_linked_results(
    parent: ArtifactValidationResult,
    linked_results: list[ArtifactValidationResult],
) -> ArtifactValidationResult:
    if parent.route_kind != RouteKind.CONFIG_SCHEMA_VALIDATION:
        return parent

    details = dict(parent.details)
    summaries_by_repo: dict[str, dict[str, Any]] = {}
    ordered_repos: list[str] = []
    for summary in details.get("linked_code_results", []):
        if not isinstance(summary, dict):
            continue
        repo_path = summary.get("repo_path")
        if not isinstance(repo_path, str):
            continue
        summaries_by_repo[repo_path] = dict(summary)
        ordered_repos.append(repo_path)

    child_by_repo = {child.artifact.repo_path: child for child in linked_results}
    child_by_artifact_id = {child.artifact.artifact_id: child for child in linked_results}
    for child in linked_results:
        if child.artifact.repo_path not in ordered_repos:
            ordered_repos.append(child.artifact.repo_path)
        summaries_by_repo[child.artifact.repo_path] = _linked_result_summary(child)

    ordered_unique_repos = _dedupe(ordered_repos)
    refreshed_summaries = [summaries_by_repo[repo_path] for repo_path in ordered_unique_repos if repo_path in summaries_by_repo]
    statuses = [str(summary.get("status")) for summary in refreshed_summaries if summary.get("status") is not None]

    details["linked_code_results"] = refreshed_summaries
    details["linked_code_statuses"] = statuses
    details["linked_code_artifact_ids"] = [
        str(summary["artifact_id"])
        for summary in refreshed_summaries
        if summary.get("artifact_id")
    ]
    details["linked_code_edges"] = [
        _refresh_linked_code_edge(
            edge,
            child_by_repo=child_by_repo,
            child_by_artifact_id=child_by_artifact_id,
        )
        for edge in details.get("linked_code_edges", [])
        if isinstance(edge, dict)
    ]

    effective_status = _config_status_from_linked_statuses(parent, statuses)
    parent.status = effective_status
    parent.review_action = _config_review_action_for_status(effective_status)
    details["effective_status"] = effective_status.value
    parent.details = details
    return parent


def _linked_result_summary(result: ArtifactValidationResult) -> dict[str, Any]:
    return {
        "repo_path": result.artifact.repo_path,
        "artifact_id": result.artifact.artifact_id,
        "status": result.status.value,
        "grade": result.grade.value,
        "review_action": result.review_action.value,
        "details": {
            "pending_api_refs": result.details.get("pending_api_refs", []),
            "grade_result": result.details.get("grade_result", {}),
            "sandbox_check": result.details.get("sandbox_check"),
            "linked_from_config": result.details.get("linked_from_config"),
            "auto_map_key": result.details.get("auto_map_key"),
            "auto_map_keys": result.details.get("auto_map_keys", []),
            "target_module": result.details.get("target_module"),
            "target_class": result.details.get("target_class"),
            "target_repo_path": result.details.get("target_repo_path"),
        },
    }


def _refresh_linked_code_edge(
    edge: dict[str, Any],
    *,
    child_by_repo: dict[str, ArtifactValidationResult],
    child_by_artifact_id: dict[str, ArtifactValidationResult],
) -> dict[str, Any]:
    refreshed = dict(edge)
    child = None
    artifact_id = refreshed.get("artifact_id")
    if isinstance(artifact_id, str):
        child = child_by_artifact_id.get(artifact_id)
    if child is None:
        repo_path = refreshed.get("repo_path") or refreshed.get("target_repo_path")
        if isinstance(repo_path, str):
            child = child_by_repo.get(repo_path)
    if child is None:
        return refreshed

    refreshed["artifact_id"] = child.artifact.artifact_id
    refreshed["post_sandbox_status"] = child.status.value
    refreshed["sandbox_decision"] = _sandbox_decision(child)
    return refreshed


def _config_status_from_linked_statuses(
    parent: ArtifactValidationResult,
    linked_statuses: list[str],
) -> ValidationStatus:
    if not linked_statuses:
        return parent.status
    normalized = {status.upper() for status in linked_statuses}
    if "BLOCK" in normalized:
        return ValidationStatus.BLOCK
    if "ERROR" in normalized:
        return ValidationStatus.ERROR
    if "PENDING_REVIEW" in normalized or "MISSING" in normalized:
        return ValidationStatus.PENDING_REVIEW
    if normalized == {"PASS"}:
        return ValidationStatus.PASS
    return ValidationStatus.PENDING_REVIEW


def _config_review_action_for_status(status: ValidationStatus) -> ReviewAction:
    if status is ValidationStatus.BLOCK:
        return ReviewAction.BLOCK_IMMEDIATELY
    if status is ValidationStatus.ERROR:
        return ReviewAction.MANUAL_REVIEW_REQUIRED
    if status is ValidationStatus.PENDING_REVIEW:
        return ReviewAction.SECURITY_OWNER_GATE
    return ReviewAction.NONE


def _sandbox_decision(result: ArtifactValidationResult) -> str | None:
    sandbox_check = result.details.get("sandbox_check")
    if isinstance(sandbox_check, dict):
        decision = sandbox_check.get("decision")
        return str(decision) if decision is not None else None
    return None


def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    output: list[str] = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        output.append(item)
    return output


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
