from sandbox.b2.schemas import (
    B2InputManifest,
    B2ManifestFile,
    B2RunnerResult,
    B2SandboxCheck,
    B2Target,
    ExecutionEvidence,
    ManifestEvidence,
    RuntimeEvidence,
    SecurityEvents,
)


def test_b2_input_manifest_round_trips_nested_dataclasses() -> None:
    manifest = B2InputManifest(
        schema_version="1.0",
        request_id="req-b2",
        job_id="job-b2",
        primary_artifact_id="sha256:" + "a" * 64,
        primary_repo_path="modeling_demo.py",
        revision="rev",
        policy_version="policy-2026.05.20",
        grade="B-2",
        target=B2Target(source="direct_python", target_module="modeling_demo", target_class="DemoModel"),
        manifest_sha256="b" * 64,
        files=[
            B2ManifestFile(
                path="modeling_demo.py",
                sha256="c" * 64,
                size_bytes=12,
                role="MODELING",
                ast_grade="B-2",
                import_allowed=True,
                target_allowed=True,
                is_primary=True,
                validation_status="PENDING_REVIEW",
            )
        ],
    )

    payload = manifest.to_dict()
    restored = B2InputManifest(**payload)

    assert isinstance(restored.target, B2Target)
    assert isinstance(restored.files[0], B2ManifestFile)
    assert restored.to_dict() == payload


def test_b2_runner_result_round_trips_from_dict() -> None:
    payload = {
        "schema_version": "1.0",
        "request_id": "req-b2",
        "nonce": "nonce",
        "manifest_verified": True,
        "import_status": "success",
        "instantiate_status": "success",
        "forward_status": "skipped_schema_unknown",
        "exception_class": None,
        "exception_message": None,
    }

    restored = B2RunnerResult.from_dict(payload)

    assert restored.to_dict() == payload


def test_b2_sandbox_check_round_trips_nested_evidence_dicts() -> None:
    check = B2SandboxCheck(
        schema_version="1.0",
        request_id="req-b2",
        job_id="job-b2",
        artifact_id="sha256:" + "a" * 64,
        repo_path="modeling_demo.py",
        grade="B-2",
        sandbox_runtime="gvisor",
        profile="B2_STANDARD",
        decision="B2_POLICY_REVIEW_REQUIRED",
        deployable=False,
        runtime_evidence=RuntimeEvidence(runtime="runsc-b2-debug", network_mode="none"),
        execution=ExecutionEvidence(manifest_verified=True, import_status="success"),
        security_events=SecurityEvents(review_events=[{"event_type": "clone"}]),
        manifest_evidence=ManifestEvidence(host_manifest_sha256="b" * 64),
        artifacts={"runner_result": "runner/result.json"},
        policy_gate={"reason_code": "SANDBOX_POLICY_GATE_REQUIRED"},
        created_at="2026-05-20T00:00:00Z",
    )

    payload = check.to_dict()
    restored = B2SandboxCheck(**payload)

    assert isinstance(restored.runtime_evidence, RuntimeEvidence)
    assert isinstance(restored.execution, ExecutionEvidence)
    assert isinstance(restored.security_events, SecurityEvents)
    assert isinstance(restored.manifest_evidence, ManifestEvidence)
    assert restored.to_dict() == payload
