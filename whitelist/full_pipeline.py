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
from pathlib import Path, PurePosixPath

from sqlalchemy.orm import Session

from analyzer.schemas import (
    ArtifactRef,
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
from analyzer.validators.code_context import build_ast_call_metadata
from analyzer.validators.code_semantic import is_preprocessing_metadata_kind

WEIGHT_KINDS = {"SAFETENSORS", "PICKLE"}
CODE_CONFIG_KINDS = {"PYTHON", "CONFIG_JSON", "TOKENIZER_CONFIG_JSON"}
PREPROCESSING_METADATA_KINDS = {
    "TOKENIZER_JSON",
    "SPECIAL_TOKENS_MAP_JSON",
    "ADDED_TOKENS_JSON",
    "VOCAB_JSON",
    "MERGES_TXT",
    "PREPROCESSOR_CONFIG_JSON",
    "PROCESSOR_CONFIG_JSON",
    "CHAT_TEMPLATE_JINJA",
}
UNVALIDATED_REASON_CODES = {
    "ARTIFACT_RESULT_MISSING",
    "UNROUTED_ARTIFACT_KIND",
}


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
    if ValidationStatus.SKIPPED in statuses:
        return ValidationStatus.PENDING_REVIEW
    if ValidationStatus.PASS in statuses:
        return ValidationStatus.PASS
    # 검증 대상이 0건(빈 아티팩트 리스트 / 전부 드롭)이면 "아무것도 검증하지
    # 않은" 상태다. 이를 PASS로 두면 빈 job이 APPROVE로 새는 fail-open이 된다
    # (적대검증 2026-06-08 CRITICAL). 자동 승인하지 않고 검토 큐로 보낸다.
    return ValidationStatus.PENDING_REVIEW


def _decision(status: ValidationStatus) -> OverallDecision:
    if status is ValidationStatus.BLOCK:
        return OverallDecision.DENY
    if status is ValidationStatus.ERROR:
        return OverallDecision.ERROR
    if status in {ValidationStatus.PENDING_REVIEW, ValidationStatus.SKIPPED}:
        return OverallDecision.REVIEW_REQUIRED
    return OverallDecision.APPROVE


def _release(status: ValidationStatus) -> str:
    if status is ValidationStatus.BLOCK:
        return "DENY"
    if status is ValidationStatus.ERROR:
        return "ERROR"
    if status in {ValidationStatus.PENDING_REVIEW, ValidationStatus.SKIPPED}:
        return "REVIEW_QUEUE"
    return "APPROVE_AND_STORE"


def _code_config_route_kind(artifact) -> RouteKind:
    if artifact.file_kind.value in {"CONFIG_JSON", "TOKENIZER_CONFIG_JSON"}:
        return RouteKind.CONFIG_SCHEMA_VALIDATION
    if is_preprocessing_metadata_kind(artifact.file_kind):
        return RouteKind.PREPROCESSING_SEMANTIC_SCAN
    return RouteKind.CODE_AST_SCAN


def _routes_through_orchestrator(artifact) -> bool:
    kind = artifact.file_kind.value
    if kind in CODE_CONFIG_KINDS:
        return True
    return is_preprocessing_metadata_kind(artifact.file_kind)


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


def _unvalidated_route_kind(artifact) -> RouteKind:
    file_kind = artifact.file_kind.value
    if file_kind == "SAFETENSORS":
        return RouteKind.SAFETENSORS_FAST_PATH
    if file_kind == "PICKLE":
        return RouteKind.PICKLE_PATH_A
    if file_kind in {"CONFIG_JSON", "TOKENIZER_CONFIG_JSON"}:
        return RouteKind.CONFIG_SCHEMA_VALIDATION
    if file_kind in PREPROCESSING_METADATA_KINDS:
        return RouteKind.PREPROCESSING_SEMANTIC_SCAN
    return RouteKind.CODE_AST_SCAN


def _unvalidated_result(
    artifact,
    *,
    reason_code: str,
    message: str,
    details: dict,
) -> ArtifactValidationResult:
    started_at = _now()
    return ArtifactValidationResult(
        artifact=artifact,
        route_kind=_unvalidated_route_kind(artifact),
        status=ValidationStatus.SKIPPED,
        grade=CodeGrade.NA,
        review_action=ReviewAction.MANUAL_REVIEW_REQUIRED,
        cache_key=f"{artifact.sha256}:{artifact.file_kind.value}:unvalidated",
        cache_hit=False,
        reason_entries=[
            ReasonEntry(
                code=reason_code,
                message=message,
                severity="MEDIUM",
                evidence=[artifact.repo_path],
                review_required=True,
            )
        ],
        started_at=started_at,
        finished_at=_now(),
        details={
            "validation_coverage": "unvalidated",
            "reason_code": reason_code,
            "file_kind": artifact.file_kind.value,
            "repo_path": artifact.repo_path,
            "requires_manual_review": True,
            **details,
        },
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


def _artifact_key(artifact) -> tuple[str, str]:
    return artifact.artifact_id, artifact.repo_path


def _missing_submitted_artifacts(
    submitted_artifacts: list,
    results: list,
) -> list:
    submitted_keys = {_artifact_key(artifact) for artifact in submitted_artifacts}
    result_keys = {
        _artifact_key(result.artifact)
        for result in results
        if _artifact_key(result.artifact) in submitted_keys
    }
    return [
        artifact
        for artifact in submitted_artifacts
        if _artifact_key(artifact) not in result_keys
    ]


def _is_unvalidated_result(result) -> bool:
    if result.details.get("validation_coverage") == "unvalidated":
        return True
    return any(
        entry.code in UNVALIDATED_REASON_CODES
        for entry in result.reason_entries
    )


def _coverage_summary(
    submitted_artifacts: list,
    results: list,
    pending_artifact_ids: list[str],
) -> dict[str, int]:
    submitted_keys = {_artifact_key(artifact) for artifact in submitted_artifacts}
    pending_ids = set(pending_artifact_ids)
    submitted_results = [
        result
        for result in results
        if _artifact_key(result.artifact) in submitted_keys
    ]
    result_keys = {_artifact_key(result.artifact) for result in submitted_results}

    return {
        "submitted": len(submitted_artifacts),
        "result_count": len(submitted_results),
        "validated": sum(
            1
            for result in submitted_results
            if result.status is not ValidationStatus.SKIPPED
            and not _is_unvalidated_result(result)
        ),
        "approved": sum(
            1
            for result in submitted_results
            if result.status is ValidationStatus.PASS
        ),
        "pending": sum(
            1
            for result in submitted_results
            if result.status in {
                ValidationStatus.PENDING_REVIEW,
                ValidationStatus.ERROR,
                ValidationStatus.SKIPPED,
            }
            or result.artifact.artifact_id in pending_ids
        ),
        "blocked": sum(
            1
            for result in submitted_results
            if result.status is ValidationStatus.BLOCK
        ),
        "skipped": sum(
            1
            for result in submitted_results
            if result.status is ValidationStatus.SKIPPED
        ),
        "unsupported": sum(
            1
            for result in submitted_results
            if _is_unvalidated_result(result)
        ),
        "error": sum(
            1
            for result in submitted_results
            if result.status is ValidationStatus.ERROR
        ),
        "missing": max(0, len(submitted_keys) - len(result_keys)),
        "extra_results": max(0, len(results) - len(submitted_results)),
    }


# 저장소에 존재하면 모델 로드 시 실행/적재될 수 있는 위험 확장자.
# (file_kind PYTHON/PICKLE은 별도로 본다)
_EXECUTABLE_RISK_EXTENSIONS = {
    ".so", ".dll", ".dylib", ".pyd", ".pyc", ".pyo",
    ".sh", ".bash", ".zsh", ".exe", ".bat", ".cmd", ".ps1", ".scr",
}


def _make_ast_call_metadata_loader(sources: dict[str, str]):
    """소스 맵에서 repo_path별 ast_call_metadata를 생성하는 loader.

    컨텍스트 분석기가 open()의 mode/path 등 인자 의존 위험을 보게 한다
    (적대검증 2026-06-08 CRITICAL — 프로덕션에서 metadata가 항상 []였던 갭).
    """
    def _loader(repo_path: str):
        source = sources.get(repo_path)
        if source is None:
            return None
        return build_ast_call_metadata(source, repo_path)

    return _loader


def _is_executable_risk_snapshot_file(file_kind_value: str, repo_path: str) -> bool:
    if file_kind_value in {"PYTHON", "PICKLE"}:
        return True
    return PurePosixPath(repo_path).suffix.lower() in _EXECUTABLE_RISK_EXTENSIONS


def _snapshot_unvalidated_result(inv) -> ArtifactValidationResult:
    """스냅샷 인벤토리에는 있으나 검증 제출에서 누락된 실행 파일을 게이트하는 결과."""
    started_at = _now()
    file_kind_value = inv.file_kind.value if hasattr(inv.file_kind, "value") else str(inv.file_kind)
    posix = PurePosixPath(inv.repo_path)
    artifact = ArtifactRef(
        artifact_id=f"sha256:{inv.sha256}",
        repo_path=inv.repo_path,
        file_name=posix.name,
        file_kind=inv.file_kind,
        detected_extension=posix.suffix.lower(),
        size_bytes=inv.size_bytes,
        sha256=inv.sha256,
        source_url="",
        temp_local_path=inv.temp_local_path,
    )
    return ArtifactValidationResult(
        artifact=artifact,
        route_kind=_unvalidated_route_kind(artifact),
        status=ValidationStatus.PENDING_REVIEW,
        grade=CodeGrade.NA,
        review_action=ReviewAction.SECURITY_OWNER_GATE,
        cache_key=f"{inv.sha256}:{file_kind_value}:snapshot-unvalidated",
        cache_hit=False,
        reason_entries=[
            ReasonEntry(
                code="SNAPSHOT_UNVALIDATED_EXECUTABLE",
                message=(
                    "executable file is present in the model snapshot inventory but "
                    "was not submitted for validation (possible hidden code)"
                ),
                severity="HIGH",
                evidence=[inv.repo_path],
                review_required=True,
            )
        ],
        started_at=started_at,
        finished_at=_now(),
        details={
            "validation_coverage": "unvalidated",
            "reason_code": "SNAPSHOT_UNVALIDATED_EXECUTABLE",
            "file_kind": file_kind_value,
            "repo_path": inv.repo_path,
            "requires_manual_review": True,
            "snapshot_only": True,
        },
    )


def _snapshot_inventory_gate(
    request: ValidationJobRequest,
    results: list,
) -> list:
    """스냅샷 인벤토리 ↔ 검증된 아티팩트 대조.

    저장소(스냅샷)에 실재하나 검증 아티팩트 집합에 없는 실행 파일(.py/.so/.sh/
    pickle 등)은 "검증을 우회한 실행 코드"이므로 검토 게이트로 끌어올린다.
    인벤토리가 비어 있으면(호출자가 제공 안 함) no-op — 기존 동작 보존.
    (적대검증 2026-06-08 HIGH-2: coverage = 호출자 제출 목록 한계 보완)
    """
    inventory = getattr(request, "model_snapshot_inventory", None) or []
    if not inventory:
        return []
    covered = {a.repo_path for a in request.artifacts}
    covered |= {r.artifact.repo_path for r in results}
    gated: list = []
    seen: set[str] = set()
    for inv in inventory:
        repo_path = getattr(inv, "repo_path", None)
        if not isinstance(repo_path, str) or repo_path in covered or repo_path in seen:
            continue
        file_kind_value = inv.file_kind.value if hasattr(inv.file_kind, "value") else str(inv.file_kind)
        if _is_executable_risk_snapshot_file(file_kind_value, repo_path):
            gated.append(_snapshot_unvalidated_result(inv))
            seen.add(repo_path)
    return gated


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
    codecfg_arts = [a for a in request.artifacts if _routes_through_orchestrator(a)]
    routed_kinds = WEIGHT_KINDS | CODE_CONFIG_KINDS | PREPROCESSING_METADATA_KINDS
    unrouted_arts = [
        a for a in request.artifacts
        if a.file_kind.value not in WEIGHT_KINDS
        and not _routes_through_orchestrator(a)
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
            ast_call_metadata_loader = _make_ast_call_metadata_loader(sources)
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
                ast_call_metadata_loader=ast_call_metadata_loader,
            )
            results.extend(cresp.artifact_results)
            _extend_unique(approved_artifact_ids, cresp.approved_artifact_ids)
            _extend_unique(blocked_artifact_ids, cresp.blocked_artifact_ids)
            _extend_unique(pending_artifact_ids, cresp.pending_artifact_ids)

    for artifact in unrouted_arts:
        results.append(
            _unvalidated_result(
                artifact,
                reason_code="UNROUTED_ARTIFACT_KIND",
                message=(
                    "submitted artifact has no full-pipeline validation route "
                    f"for file_kind={artifact.file_kind.value}"
                ),
                details={
                    "supported_file_kinds": sorted(routed_kinds),
                },
            )
        )
        _extend_unique(pending_artifact_ids, [artifact.artifact_id])

    for artifact in _missing_submitted_artifacts(request.artifacts, results):
        results.append(
            _unvalidated_result(
                artifact,
                reason_code="ARTIFACT_RESULT_MISSING",
                message="submitted artifact did not produce a validation result",
                details={
                    "routed_file_kind": artifact.file_kind.value in routed_kinds,
                },
            )
        )
        _extend_unique(pending_artifact_ids, [artifact.artifact_id])

    # 스냅샷 인벤토리에 있으나 검증에서 누락된 실행 파일 게이트(코드 숨김 차단)
    for inventory_result in _snapshot_inventory_gate(request, results):
        results.append(inventory_result)
        _extend_unique(pending_artifact_ids, [inventory_result.artifact.artifact_id])

    gated_artifact_ids = set(blocked_artifact_ids) | set(pending_artifact_ids)
    approved_artifact_ids = [
        artifact_id
        for artifact_id in approved_artifact_ids
        if artifact_id not in gated_artifact_ids
    ]

    overall = _combine_status(results)
    coverage = _coverage_summary(request.artifacts, results, pending_artifact_ids)

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
        coverage_summary=coverage,
    )


__all__ = ["run_full_validation"]
