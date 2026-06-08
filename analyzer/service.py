from datetime import UTC, datetime
from dataclasses import replace
from pathlib import Path, PurePosixPath
from typing import Any

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
from analyzer.validators.weight.pipeline import validate
from analyzer.validators.weight.pickle_roles import PickleRole


WEIGHT_FILE_KINDS = {"SAFETENSORS", "PICKLE"}
ORCHESTRATOR_FILE_KINDS = {"PYTHON", "CONFIG_JSON", "TOKENIZER_CONFIG_JSON"}
PICKLE_HARD_BLOCK_REASON_CODES = {
    "ARTIFACT_HASH_MISMATCH",
    "PICKLE_OPCODE_BLOCKED",
    "PICKLE_YARA_BLOCKED",
    "PICKLE_MODELSCAN_BLOCKED",
    "PICKLE_PATH_B_BLOCKED",
    "PICKLE_PATH_B_RUNTIME_POLICY_VIOLATION",
    "PICKLE_PATH_B_SECURITY_EVENT",
    "PICKLE_PATH_AB_MISMATCH",
}
PICKLE_NON_AUXILIARY_HARD_BLOCK_REASON_CODES = {
    "PICKLE_PATH_B_EXECUTION_FAILED",
    "PICKLE_PATH_B_INVALID_ARGUMENT",
    "PICKLE_PATH_B_UNSUPPORTED_OBJECT",
}
PICKLE_HARD_BLOCK_STAGES = {"YARA", "MODELSCAN", "DIFF"}
STATUS_PRIORITY = {
    "PASS": 0,
    "PENDING_REVIEW": 1,
    "ERROR": 2,
    "BLOCK": 3,
}


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _status_value(status) -> str:
    return status.value if hasattr(status, "value") else str(status)


def _merge_overall_status(current: str, candidate) -> str:
    candidate_value = _status_value(candidate)
    return (
        candidate_value
        if STATUS_PRIORITY[candidate_value] > STATUS_PRIORITY[current]
        else current
    )


def _default_policy(policy_fingerprint: str) -> PolicyInfo:
    return PolicyInfo(
        policy_version="default-policy",
        whitelist_version="default-whitelist",
        opcode_policy_version="default-opcode-policy",
        config_schema_version="default-config-schema",
        runtime_profile_version="default-runtime-profile",
        policy_fingerprint=policy_fingerprint,
    )


def _default_model() -> ModelRef:
    return ModelRef(
        repo_id="unknown/unknown",
        revision="main",
        source_host="local",
        source_url="local",
        requested_at=_now(),
        endpoint_mode="INTERNAL_VALIDATION_JOB",
        requested_by=None,
    )


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


def _collect_reason_codes(core_result: dict) -> set[str]:
    codes = set()
    for key in ("reason_code",):
        value = core_result.get(key)
        if value:
            codes.add(str(value))

    for key in ("path_a", "path_b", "diff", "converted", "yara", "modelscan"):
        sub = core_result.get(key)
        if isinstance(sub, dict) and sub.get("reason_code"):
            codes.add(str(sub["reason_code"]))

    return codes


def _is_pickle_hard_block(core_result: dict) -> bool:
    if core_result.get("stage") in PICKLE_HARD_BLOCK_STAGES:
        return True

    codes = _collect_reason_codes(core_result)
    if codes & PICKLE_HARD_BLOCK_REASON_CODES:
        return True

    if _pickle_role_value(core_result) == PickleRole.AUXILIARY_TRAINING.value:
        return False

    return bool(codes & PICKLE_NON_AUXILIARY_HARD_BLOCK_REASON_CODES)


def _pickle_role_value(core_result: dict) -> str:
    return str(core_result.get("pickle_role") or PickleRole.GENERIC_PICKLE.value)


def _details_with_release_policy(
    core_result: dict,
    *,
    release_eligible: bool,
    release_target,
) -> dict:
    details = dict(core_result)
    details["release_eligible"] = release_eligible
    details["release_target"] = release_target
    return details


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
    review_action: ReviewAction | str = ReviewAction.NONE,
) -> ArtifactValidationResult:
    safe_details = _json_safe(details)
    return ArtifactValidationResult(
        artifact=artifact,
        route_kind=_route_kind_for(artifact),
        status=ValidationStatus(status),
        grade=CodeGrade.NA,
        review_action=ReviewAction(review_action),
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
    if str(artifact.file_kind) == "PICKLE":
        return _map_pickle_result(artifact, core_result)

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


def _map_pickle_result(artifact, core_result):
    role = _pickle_role_value(core_result)
    reason_code, reason_message = _extract_reason(core_result)
    generated_artifact = _build_generated_artifact(artifact, core_result)

    if _is_pickle_hard_block(core_result):
        return _build_result(
            artifact=artifact,
            status="BLOCK",
            reason_code=reason_code,
            reason_message=reason_message,
            details=_details_with_release_policy(
                core_result,
                release_eligible=False,
                release_target=None,
            ),
            generated_artifact=None,
            review_action=ReviewAction.BLOCK_IMMEDIATELY,
        )

    if role == PickleRole.AUXILIARY_TRAINING.value:
        return _build_result(
            artifact=artifact,
            status="SKIPPED",
            reason_code="PICKLE_AUXILIARY_NOT_RELEASE_ARTIFACT",
            reason_message="auxiliary training pickle is not a release artifact",
            details=_details_with_release_policy(
                core_result,
                release_eligible=False,
                release_target=None,
            ),
            generated_artifact=None,
        )

    if core_result.get("status") == "PASS" and generated_artifact is not None:
        return _build_result(
            artifact=artifact,
            status="PASS",
            reason_code=reason_code,
            reason_message=reason_message,
            details=_details_with_release_policy(
                core_result,
                release_eligible=True,
                release_target="GENERATED_SAFETENSORS",
            ),
            generated_artifact=generated_artifact,
            review_action=ReviewAction.AUTO_APPROVE_REGENERATED,
        )

    if role == PickleRole.UNSUPPORTED_CHECKPOINT.value:
        return _build_result(
            artifact=artifact,
            status="PENDING_REVIEW",
            reason_code="UNSUPPORTED_PICKLE_CHECKPOINT",
            reason_message="pickle checkpoint artifacts are unsupported in this policy scope",
            details=_details_with_release_policy(
                core_result,
                release_eligible=False,
                release_target=None,
            ),
            generated_artifact=None,
            review_action=ReviewAction.MANUAL_REVIEW_REQUIRED,
        )

    return _build_result(
        artifact=artifact,
        status="PENDING_REVIEW",
        reason_code="PICKLE_WEIGHT_REQUIRES_REVIEW_OR_CONVERSION",
        reason_message=(
            "raw pickle weight requires converted safetensors or explicit review"
        ),
        details=_details_with_release_policy(
            core_result,
            release_eligible=False,
            release_target=None,
        ),
        generated_artifact=None,
        review_action=ReviewAction.MANUAL_REVIEW_REQUIRED,
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
    from analyzer.validators.code_semantic import is_preprocessing_metadata_kind
    from analyzer.classifier import looks_like_executable_or_script

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
            repo_path=artifact.repo_path,
            file_name=artifact.file_name,
        )
        mapped = _map_result(artifact, core, policy_fingerprint)
        results.append(mapped)

        if mapped.status == ValidationStatus.BLOCK:
            overall_status = "BLOCK"
            blocked_artifact_ids.append(artifact.artifact_id)
        elif mapped.status == ValidationStatus.PASS:
            if str(artifact.file_kind) == "PICKLE":
                if mapped.generated_artifact is not None:
                    generated_artifacts.append(mapped.generated_artifact)
                    approved_artifact_ids.append(mapped.generated_artifact.artifact_id)
            else:
                approved_artifact_ids.append(artifact.artifact_id)
        elif mapped.status == ValidationStatus.SKIPPED:
            pass
        else:
            overall_status = _merge_overall_status(overall_status, mapped.status)
            pending_artifact_ids.append(artifact.artifact_id)

    # ── 비가중치 파일: orchestrator에 위임 ──────────────────────────────────
    orchestrator_artifacts = [
        a for a in non_weight_artifacts
        if (
            str(a.file_kind) in ORCHESTRATOR_FILE_KINDS
            or is_preprocessing_metadata_kind(a.file_kind)
        )
    ]
    skipped_artifacts = [
        a for a in non_weight_artifacts
        if not (
            str(a.file_kind) in ORCHESTRATOR_FILE_KINDS
            or is_preprocessing_metadata_kind(a.file_kind)
        )
    ]

    # 지원하지 않는 파일 종류 → SKIPPED.
    # 단, OTHER로 떨어졌지만 실제로는 실행 스크립트/바이너리(startup.sh,
    # payload.py.txt, ELF/PE 등)인 파일은 무해한 SKIPPED로 자동 통과시키지 않고
    # PENDING_REVIEW로 보낸다 (미검증 실행물 → 보안 검토 강제).
    for artifact in skipped_artifacts:
        content_head = None
        try:
            with open(artifact.temp_local_path, "rb") as _f:
                content_head = _f.read(256)
        except Exception:
            content_head = None

        # 메타데이터 조작 우회 방지: file_name만 신뢰하지 않고 repo_path / temp
        # basename도 함께 검사한다. (양유상 PR #53 리뷰: repo_path=payload.py.txt +
        # file_name=README.md로 OTHER 실행물 검토가 우회됨.) 또한 repo_path
        # basename과 file_name이 불일치하면 그 자체가 조작 신호이므로 fail-closed.
        candidate_names = [artifact.file_name, artifact.repo_path]
        try:
            candidate_names.append(Path(artifact.temp_local_path).name)
        except Exception:
            pass
        exec_like = any(
            looks_like_executable_or_script(name, content_head)
            for name in candidate_names
            if name
        )
        name_mismatch = PurePosixPath(artifact.repo_path).name != artifact.file_name

        if exec_like or name_mismatch:
            reason_code = (
                "UNVETTED_EXECUTABLE_FILE" if exec_like else "ARTIFACT_NAME_MISMATCH"
            )
            reason_message = (
                f"검증되지 않은 실행 가능 파일(OTHER): {artifact.repo_path}. "
                "스크립트/바이너리는 자동 통과시키지 않고 보안 검토로 보낸다."
                if exec_like
                else (
                    f"artifact 메타데이터 불일치: repo_path={artifact.repo_path} vs "
                    f"file_name={artifact.file_name} (조작 의심) — 보안 검토로 보낸다."
                )
            )
            review = _build_result(
                artifact=artifact,
                status="PENDING_REVIEW",
                reason_code=reason_code,
                reason_message=reason_message,
                details={"status": "PENDING_REVIEW", "reason_code": reason_code},
            )
            results.append(review)
            overall_status = _merge_overall_status(overall_status, "PENDING_REVIEW")
            pending_artifact_ids.append(artifact.artifact_id)
        else:
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
        sub_job = replace(
            job,
            artifacts=orchestrator_artifacts,
            model=job.model or _default_model(),
            policy=job.policy or _default_policy(policy_fingerprint),
        )

        try:
            orch_response = run_validation_job(
                sub_job,
                source_loader=source_loader,
                revision=sub_job.model.revision,
            )

            for item in orch_response.artifact_results:
                results.append(item)

            approved_artifact_ids.extend(orch_response.approved_artifact_ids)
            blocked_artifact_ids.extend(orch_response.blocked_artifact_ids)
            pending_artifact_ids.extend(orch_response.pending_artifact_ids)

            overall_status = _merge_overall_status(
                overall_status,
                orch_response.overall_status,
            )

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
                overall_status = _merge_overall_status(overall_status, "ERROR")
                pending_artifact_ids.append(artifact.artifact_id)

    # 검증 결과가 하나도 없으면(빈 아티팩트 집합 등) APPROVE로 fail-open하지
    # 않는다. orchestrator._compute_overall_status([])와 동일하게 fail-closed.
    if not results:
        overall_status = "ERROR"

    if overall_status == "BLOCK":
        decision = OverallDecision.DENY
        release_action = "DENY"
    elif overall_status == "ERROR":
        decision = OverallDecision.ERROR
        release_action = "ERROR"
    elif overall_status == "PENDING_REVIEW":
        decision = OverallDecision.REVIEW_REQUIRED
        release_action = "DENY"
    else:
        decision = OverallDecision.APPROVE
        release_action = "APPROVE"

    return ValidationJobResponse(
        request_id=job.request_id,
        job_id=job.job_id,
        overall_decision=decision,
        overall_status=ValidationStatus(overall_status),
        release_action=release_action,
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
