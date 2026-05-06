import json

import pytest

from analyzer.schemas import (
    ArtifactRef,
    ArtifactValidationResult,
    CodeGrade,
    FileKind,
    ModelRef,
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


SHA256_ZERO = "0" * 64


def make_artifact() -> ArtifactRef:
    return ArtifactRef(
        artifact_id=f"sha256:{SHA256_ZERO}",
        repo_path="modeling_demo.py",
        file_name="modeling_demo.py",
        file_kind=FileKind.PYTHON,
        detected_extension=".py",
        media_type=None,
        size_bytes=12,
        sha256=SHA256_ZERO,
        source_url="https://huggingface.co/org/model/resolve/main/modeling_demo.py",
        temp_local_path="/tmp/job/modeling_demo.py",
        referenced_by=[],
        is_generated=False,
    )


def test_interface_enum_values_are_stable() -> None:
    assert {item.value for item in FileKind} == {
        "SAFETENSORS",
        "PICKLE",
        "PYTHON",
        "CONFIG_JSON",
        "TOKENIZER_CONFIG_JSON",
        "OTHER",
    }
    assert {item.value for item in ValidationStatus} == {
        "PASS",
        "BLOCK",
        "PENDING_REVIEW",
        "ERROR",
        "SKIPPED",
    }
    assert "REVIEW_REQUIRED" not in {item.value for item in ValidationStatus}
    assert {item.value for item in ReviewAction} == {
        "NONE",
        "AUTO_APPROVE",
        "AUTO_APPROVE_REGENERATED",
        "SECURITY_OWNER_GATE",
        "MANUAL_REVIEW_REQUIRED",
        "BLOCK_IMMEDIATELY",
        "AUTO_LOG_REVIEW",
    }
    assert [CodeGrade.A.value, CodeGrade.B1.value, CodeGrade.B2.value, CodeGrade.C.value, CodeGrade.NA.value] == [
        "A",
        "B-1",
        "B-2",
        "C",
        "N/A",
    ]
    assert {item.value for item in RouteKind} == {
        "SAFETENSORS_FAST_PATH",
        "PICKLE_PATH_A",
        "PICKLE_PATH_B",
        "CODE_AST_SCAN",
        "CODE_RESTRICTED_RUNTIME",
        "CODE_SANDBOX_RUNTIME",
        "CONFIG_SCHEMA_VALIDATION",
    }
    assert {item.value for item in OverallDecision} == {
        "APPROVE",
        "APPROVE_WITH_TRANSFORM",
        "DENY",
        "REVIEW_REQUIRED",
        "ERROR",
    }


def test_policy_fingerprint_is_generated_from_versions() -> None:
    policy = PolicyInfo(
        policy_version="policy-2026.04.20",
        whitelist_version="wl-2026.04.20",
        opcode_policy_version="opcode-2026.04.20",
        config_schema_version="cfg-2026.04.20",
        runtime_profile_version="rt-2026.04.20",
    )

    assert policy.policy_fingerprint == (
        "policy-2026.04.20|wl-2026.04.20|opcode-2026.04.20|"
        "cfg-2026.04.20|rt-2026.04.20"
    )


def test_artifact_validation_result_serializes_details_and_enums() -> None:
    result = ArtifactValidationResult(
        artifact=make_artifact(),
        route_kind=RouteKind.CODE_AST_SCAN,
        status=ValidationStatus.PENDING_REVIEW,
        grade=CodeGrade.B2,
        review_action=ReviewAction.SECURITY_OWNER_GATE,
        cache_key="cache-key",
        cache_hit=False,
        reason_entries=[
            ReasonEntry(
                code="UNREGISTERED_API",
                severity="HIGH",
                message="unregistered API requires review",
                evidence=["torch.special.expit"],
                review_required=True,
            )
        ],
        details={
            "ast_scan": {"imports": ["torch"]},
            "api_scan": {"unregistered": ["torch.special.expit"]},
            "pending_api_refs": ["torch.special.expit"],
        },
        started_at="2026-04-20T09:00:00Z",
        finished_at="2026-04-20T09:00:01Z",
    )

    payload = result.to_dict()
    assert payload["artifact"]["file_kind"] == "PYTHON"
    assert payload["route_kind"] == "CODE_AST_SCAN"
    assert payload["status"] == "PENDING_REVIEW"
    assert payload["grade"] == "B-2"
    assert payload["review_action"] == "SECURITY_OWNER_GATE"
    assert payload["reason_entries"][0]["code"] == "UNREGISTERED_API"
    assert payload["details"]["pending_api_refs"] == ["torch.special.expit"]
    assert json.loads(json.dumps(payload)) == payload


def test_validation_job_request_and_response_roundtrip() -> None:
    artifact = make_artifact()
    request = ValidationJobRequest(
        request_id="0c7d3f5a-0f86-4f8d-a9df-8c0c315e7284",
        job_id="9a7675b3-c726-45c8-9dae-98e5a6df7da2",
        model=ModelRef(
            repo_id="org/demo-model",
            revision="main",
            source_host="huggingface.co",
            source_url="https://huggingface.co/org/demo-model",
            requested_by="developer-a",
            requested_at="2026-04-20T09:00:00Z",
            endpoint_mode="HF_ENDPOINT_PROXY",
        ),
        policy=PolicyInfo(
            policy_version="policy-2026.04.20",
            whitelist_version="wl-2026.04.20",
            opcode_policy_version="opcode-2026.04.20",
            config_schema_version="cfg-2026.04.20",
            runtime_profile_version="rt-2026.04.20",
        ),
        runtime_context=RuntimeContext(
            sandbox_runtime="gvisor",
            network_disabled=True,
            read_only_fs=True,
            compare_mode="TORCH_ALLCLOSE_THEN_SHA256",
            allow_cache_lookup=True,
            generate_mlbom=True,
            write_audit_log=True,
        ),
        artifacts=[artifact],
        requested_routes=[RouteKind.CODE_AST_SCAN],
        stop_on_first_block=False,
        notes=None,
    )

    request_payload = request.to_dict()
    restored_request = ValidationJobRequest.from_dict(request_payload)
    assert restored_request.artifacts[0].file_kind is FileKind.PYTHON
    assert restored_request.requested_routes == [RouteKind.CODE_AST_SCAN]
    assert restored_request.to_dict() == request_payload

    result = ArtifactValidationResult(
        artifact=artifact,
        route_kind=RouteKind.CODE_AST_SCAN,
        status=ValidationStatus.PASS,
        grade=CodeGrade.A,
        review_action=ReviewAction.AUTO_APPROVE_REGENERATED,
        cache_key="cache-key",
        cache_hit=False,
        reason_entries=[],
        details={"grade_result": {"grade": "A"}},
        started_at="2026-04-20T09:00:00Z",
        finished_at="2026-04-20T09:00:01Z",
    )
    response = ValidationJobResponse(
        request_id=request.request_id,
        job_id=request.job_id,
        overall_decision=OverallDecision.APPROVE,
        overall_status=ValidationStatus.PASS,
        release_action="APPROVE_AND_STORE",
        artifact_results=[result],
        approved_artifact_ids=[artifact.artifact_id],
        blocked_artifact_ids=[],
        pending_artifact_ids=[],
        generated_artifacts=[],
        report_id="vr_2026_04_20_001",
        report_path="/tmp/report.json",
        reason_entries=[],
        created_at="2026-04-20T09:00:02Z",
    )

    response_payload = response.to_dict()
    restored_response = ValidationJobResponse.from_dict(response_payload)
    assert restored_response.overall_status is ValidationStatus.PASS
    assert restored_response.artifact_results[0].grade is CodeGrade.A
    assert restored_response.to_dict() == response_payload


def test_artifact_ref_rejects_invalid_artifact_id() -> None:
    with pytest.raises(ValueError):
        ArtifactRef(
            artifact_id="sha256:not-the-same",
            repo_path="model.py",
            file_name="model.py",
            file_kind=FileKind.PYTHON,
            detected_extension=".py",
            media_type=None,
            size_bytes=1,
            sha256=SHA256_ZERO,
            source_url="",
            temp_local_path="/tmp/model.py",
            referenced_by=[],
            is_generated=False,
        )

