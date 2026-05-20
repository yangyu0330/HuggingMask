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

from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy.orm import Session

from analyzer.schemas import (
    ModelRef,
    OverallDecision,
    PolicyInfo,
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

    # 1) 가중치 경로 (정은미)
    if weight_arts:
        wresp = _validate_weight_job(_subset_request(request, weight_arts))
        results.extend(wresp.artifact_results)
        generated.extend(wresp.generated_artifacts)

    # 2) 코드 + config 경로 (양유상 orchestrator + 본인 화이트리스트/제한런타임)
    if codecfg_arts:
        from analyzer.validators.code_restricted_runtime import (
            make_restricted_runtime_loader,
        )
        from whitelist.integration import run_validation_job_with_whitelist_engine

        sources: dict[str, str] = {}
        for a in codecfg_arts:
            try:
                sources[a.repo_path] = Path(a.temp_local_path).read_text(
                    encoding="utf-8", errors="replace"
                )
            except OSError:
                sources[a.repo_path] = ""

        runtime_loader = make_restricted_runtime_loader(sources)
        policy = request.policy or _default_policy()
        # orchestrator용 analyzer ModelRef (request에 채워 forward)
        analyzer_model = request.model or _default_model()
        cc_request = _subset_request(
            request, codecfg_arts, policy=policy, model=analyzer_model
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

    overall = _combine_status(results)

    return ValidationJobResponse(
        request_id=request.request_id,
        job_id=request.job_id,
        overall_decision=_decision(overall),
        overall_status=overall,
        release_action=_release(overall),
        artifact_results=results,
        approved_artifact_ids=[
            r.artifact.artifact_id for r in results
            if r.status is ValidationStatus.PASS
        ],
        blocked_artifact_ids=[
            r.artifact.artifact_id for r in results
            if r.status is ValidationStatus.BLOCK
        ],
        pending_artifact_ids=[
            r.artifact.artifact_id for r in results
            if r.status in {ValidationStatus.PENDING_REVIEW, ValidationStatus.ERROR}
        ],
        generated_artifacts=generated,
        report_id=f"report-{request.job_id}",
        report_path="",
        reason_entries=[],
        created_at=_now(),
    )


__all__ = ["run_full_validation"]
