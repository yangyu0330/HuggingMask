"""통합 검증 파이프라인 — 한 ValidationJobRequest를 가중치 + 코드 + config +
화이트리스트 + 제한 런타임까지 모두 거쳐 단일 ValidationJobResponse로 합친다.

책임 경계:
    이 모듈은 기존 검증기를 **공개 인터페이스로 호출만** 한다 (타 영역 production
    코드 무수정).
    - 가중치(SAFETENSORS/PICKLE) → ``analyzer.service.validate_job`` (정은미)
    - 코드(PYTHON) + config(CONFIG_JSON/TOKENIZER_CONFIG_JSON)
      → ``whitelist.integration.run_validation_job_with_whitelist_engine``
        (양유상 orchestrator + 본인 화이트리스트 어댑터 + 본인 제한 런타임 loader)
    두 결과를 병합해 job-level 판정을 재계산한다.

검증3(B-2 gVisor / CODE_SANDBOX_RUNTIME)은 양유상 ``sandbox/b2`` 영역이며,
runsc/Docker가 없으면 하위 검증기가 graceful degrade 한다
(``PICKLE_PATH_B_NOT_AVAILABLE`` 등).

주의:
    ``run_validation_job_with_whitelist_engine``이 module-level monkey-patch
    (``default_api_policy``)를 쓰므로 동시 호출 시 한 번에 한 흐름만 안전.
    단일 사용자 데모/운영 콘솔 기준.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy.orm import Session

from analyzer.schemas import (
    ArtifactValidationResult,
    CodeGrade,
    ModelRef,
    OverallDecision,
    PolicyInfo,
    ReasonEntry,
    ReviewAction,
    RouteKind,
    ValidationJobRequest,
    ValidationJobResponse,
    ValidationStatus,
)
from analyzer.service import validate_job as _validate_weight_job

WEIGHT_KINDS = {"SAFETENSORS", "PICKLE"}
CODE_CONFIG_KINDS = {"PYTHON", "CONFIG_JSON", "TOKENIZER_CONFIG_JSON"}


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _default_policy() -> PolicyInfo:
    from whitelist.rules import WHITELIST_VERSION

    return PolicyInfo(
        policy_version="unified-pipeline",
        whitelist_version=str(WHITELIST_VERSION),
        opcode_policy_version="opcode-unified",
        config_schema_version="config-unified",
        runtime_profile_version="runtime-unified",
    )


def _default_model() -> ModelRef:
    # orchestrator(run_validation_job)가 model.revision 등을 요구하므로
    # 호출자가 model을 안 보낸 경우 최소 ModelRef를 채운다.
    # (이것은 analyzer.schemas.ModelRef — orchestrator 전용)
    return ModelRef(
        repo_id="local/unified-demo",
        revision="main",
        source_host="local",
        source_url="local://unified",
        requested_at=_now(),
        endpoint_mode="HF_ENDPOINT_PROXY",
        requested_by="unified-pipeline",
    )


def _whitelist_model(analyzer_model: ModelRef):
    """화이트리스트 어댑터(WhitelistEngineLookup)는 pydantic
    ``whitelist.models.ModelRef``를 요구한다. orchestrator용
    ``analyzer.schemas.ModelRef`` 필드를 그대로 옮겨 변환한다.
    """
    from whitelist.models import EndpointMode as WLEndpointMode
    from whitelist.models import ModelRef as WLModelRef

    endpoint = analyzer_model.endpoint_mode
    try:
        endpoint = WLEndpointMode(endpoint)
    except ValueError:
        endpoint = WLEndpointMode.HF_ENDPOINT_PROXY

    return WLModelRef(
        repo_id=analyzer_model.repo_id,
        revision=analyzer_model.revision,
        source_host=analyzer_model.source_host,
        source_url=analyzer_model.source_url,
        requested_by=analyzer_model.requested_by or "unified-pipeline",
        requested_at=analyzer_model.requested_at,
        endpoint_mode=endpoint,
    )


def _subset_request(
    request: ValidationJobRequest,
    artifacts: list,
    policy: PolicyInfo | None = None,
    model: ModelRef | None = None,
) -> ValidationJobRequest:
    return ValidationJobRequest(
        request_id=request.request_id,
        job_id=request.job_id,
        model=model if model is not None else request.model,
        policy=policy if policy is not None else request.policy,
        runtime_context=request.runtime_context,
        artifacts=artifacts,
        requested_routes=request.requested_routes,
        stop_on_first_block=request.stop_on_first_block,
        enable_path_b=request.enable_path_b,
        policy_fingerprint=request.policy_fingerprint,
        notes=request.notes,
        model_snapshot_root=request.model_snapshot_root,
        model_snapshot_inventory=request.model_snapshot_inventory,
    )


def _combine_status(results: list) -> ValidationStatus:
    statuses = {r.status for r in results}
    if ValidationStatus.BLOCK in statuses:
        return ValidationStatus.BLOCK
    if ValidationStatus.ERROR in statuses:
        return ValidationStatus.ERROR
    if ValidationStatus.PENDING_REVIEW in statuses:
        return ValidationStatus.PENDING_REVIEW
    if ValidationStatus.PASS in statuses:
        return ValidationStatus.PASS
    # 전부 SKIPPED 거나 빈 경우
    return ValidationStatus.SKIPPED if results else ValidationStatus.PASS


def _decision(status: ValidationStatus) -> OverallDecision:
    if status is ValidationStatus.BLOCK:
        return OverallDecision.DENY
    if status is ValidationStatus.ERROR:
        return OverallDecision.ERROR
    if status is ValidationStatus.PENDING_REVIEW:
        return OverallDecision.REVIEW_REQUIRED
    return OverallDecision.APPROVE


def _release(status: ValidationStatus) -> str:
    if status is ValidationStatus.BLOCK:
        return "DENY"
    if status is ValidationStatus.ERROR:
        return "ERROR"
    if status is ValidationStatus.PENDING_REVIEW:
        return "REVIEW_QUEUE"
    return "APPROVE_AND_STORE"


def _code_config_route_kind(artifact) -> RouteKind:
    if artifact.file_kind.value in {"CONFIG_JSON", "TOKENIZER_CONFIG_JSON"}:
        return RouteKind.CONFIG_SCHEMA_VALIDATION
    return RouteKind.CODE_AST_SCAN


def _source_error_result(
    artifact,
    *,
    reason_code: str,
    message: str,
    details: dict,
) -> ArtifactValidationResult:
    started_at = _now()
    return ArtifactValidationResult(
        artifact=artifact,
        route_kind=_code_config_route_kind(artifact),
        status=ValidationStatus.ERROR,
        grade=CodeGrade.NA,
        review_action=ReviewAction.MANUAL_REVIEW_REQUIRED,
        cache_key=f"{artifact.sha256}:{artifact.file_kind.value}:source-integrity",
        cache_hit=False,
        reason_entries=[
            ReasonEntry(
                code=reason_code,
                message=message,
                severity="HIGH",
                evidence=[artifact.repo_path],
                review_required=True,
            )
        ],
        started_at=started_at,
        finished_at=_now(),
        details=details,
    )


def _verified_text_source(artifact) -> tuple[str | None, ArtifactValidationResult | None]:
    try:
        raw = Path(artifact.temp_local_path).read_bytes()
    except OSError as exc:
        return None, _source_error_result(
            artifact,
            reason_code="SOURCE_READ_ERROR",
            message=f"source file could not be read: {exc}",
            details={
                "error": str(exc),
                "repo_path": artifact.repo_path,
                "temp_local_path": artifact.temp_local_path,
            },
        )

    actual_size = len(raw)
    if actual_size != artifact.size_bytes:
        return None, _source_error_result(
            artifact,
            reason_code="SOURCE_SIZE_MISMATCH",
            message="source file size does not match artifact metadata",
            details={
                "repo_path": artifact.repo_path,
                "temp_local_path": artifact.temp_local_path,
                "expected_size_bytes": artifact.size_bytes,
                "actual_size_bytes": actual_size,
            },
        )

    actual_sha256 = hashlib.sha256(raw).hexdigest()
    if actual_sha256 != artifact.sha256:
        return None, _source_error_result(
            artifact,
            reason_code="SOURCE_SHA256_MISMATCH",
            message="source file sha256 does not match artifact metadata",
            details={
                "repo_path": artifact.repo_path,
                "temp_local_path": artifact.temp_local_path,
                "expected_sha256": artifact.sha256,
                "actual_sha256": actual_sha256,
            },
        )

    return raw.decode("utf-8", errors="replace"), None


def _extend_unique(target: list[str], values: list[str]) -> None:
    for value in values:
        if value not in target:
            target.append(value)


def run_full_validation(
    request: ValidationJobRequest | dict,
    *,
    db: Session,
    engine=None,
    model=None,
) -> ValidationJobResponse:
    """가중치 + 코드 + config + 화이트리스트 + 제한 런타임 통합 검증."""
    if not isinstance(request, ValidationJobRequest):
        request = ValidationJobRequest.from_dict(request)

    weight_arts = [a for a in request.artifacts if a.file_kind.value in WEIGHT_KINDS]
    codecfg_arts = [
        a for a in request.artifacts if a.file_kind.value in CODE_CONFIG_KINDS
    ]

    results: list = []
    generated: list = []
    approved_artifact_ids: list[str] = []
    blocked_artifact_ids: list[str] = []
    pending_artifact_ids: list[str] = []

    # 1) 가중치 경로 (정은미)
    if weight_arts:
        wresp = _validate_weight_job(_subset_request(request, weight_arts))
        results.extend(wresp.artifact_results)
        generated.extend(wresp.generated_artifacts)
        _extend_unique(approved_artifact_ids, wresp.approved_artifact_ids)
        _extend_unique(blocked_artifact_ids, wresp.blocked_artifact_ids)
        _extend_unique(pending_artifact_ids, wresp.pending_artifact_ids)

    # 2) 코드 + config 경로 (양유상 orchestrator + 본인 화이트리스트/제한런타임)
    if codecfg_arts:
        from analyzer.validators.code_restricted_runtime import (
            make_restricted_runtime_loader,
        )
        from whitelist.integration import run_validation_job_with_whitelist_engine

        sources: dict[str, str] = {}
        verified_codecfg_arts = []
        for a in codecfg_arts:
            if a.repo_path in sources:
                source_error = _source_error_result(
                    a,
                    reason_code="DUPLICATE_REPO_PATH",
                    message="duplicate repo_path cannot be safely mapped to one source",
                    details={
                        "repo_path": a.repo_path,
                        "temp_local_path": a.temp_local_path,
                    },
                )
                results.append(source_error)
                _extend_unique(pending_artifact_ids, [a.artifact_id])
                continue

            source, source_error = _verified_text_source(a)
            if source_error is not None:
                results.append(source_error)
                _extend_unique(pending_artifact_ids, [a.artifact_id])
                continue
            sources[a.repo_path] = source or ""
            verified_codecfg_arts.append(a)

        if verified_codecfg_arts:
            runtime_loader = make_restricted_runtime_loader(sources)
            policy = request.policy or _default_policy()
            # orchestrator용 analyzer ModelRef (request에 채워 forward)
            analyzer_model = request.model or _default_model()
            cc_request = _subset_request(
                request, verified_codecfg_arts, policy=policy, model=analyzer_model
            )
            # WhitelistEngineLookup용 pydantic ModelRef (model= 인자는 별도 타입)
            wl_model = model if model is not None else _whitelist_model(analyzer_model)

            cresp = run_validation_job_with_whitelist_engine(
                cc_request,
                db=db,
                engine=engine,
                model=wl_model,
                source_loader=sources,
                runtime_check_loader=runtime_loader,
            )
            results.extend(cresp.artifact_results)
            _extend_unique(approved_artifact_ids, cresp.approved_artifact_ids)
            _extend_unique(blocked_artifact_ids, cresp.blocked_artifact_ids)
            _extend_unique(pending_artifact_ids, cresp.pending_artifact_ids)

    overall = _combine_status(results)

    return ValidationJobResponse(
        request_id=request.request_id,
        job_id=request.job_id,
        overall_decision=_decision(overall),
        overall_status=overall,
        release_action=_release(overall),
        artifact_results=results,
        approved_artifact_ids=approved_artifact_ids,
        blocked_artifact_ids=blocked_artifact_ids,
        pending_artifact_ids=pending_artifact_ids,
        generated_artifacts=generated,
        report_id=f"report-{request.job_id}",
        report_path="",
        reason_entries=[],
        created_at=_now(),
    )


__all__ = ["run_full_validation"]
