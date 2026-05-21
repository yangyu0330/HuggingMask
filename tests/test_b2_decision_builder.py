import hashlib
from pathlib import PurePosixPath

from analyzer.orchestrator import _requires_b2_sandbox, build_minimal_request, run_validation_job
from analyzer.schemas import ArtifactRef, FileKind, PolicyInfo, RouteKind, ValidationStatus
from sandbox.b2.decision_builder import build_sandbox_check_from_runner_result
from sandbox.b2.schemas import B2RuntimePolicy


def _make_policy() -> PolicyInfo:
    return PolicyInfo(
        policy_version="policy-2026.05.20",
        whitelist_version="wl-2026.05.20",
        opcode_policy_version="opcode-2026.05.20",
        config_schema_version="cfg-2026.05.20",
        runtime_profile_version="rt-2026.05.20",
    )


def _make_artifact(repo_path: str, source_text: str) -> ArtifactRef:
    digest = hashlib.sha256(f"{repo_path}:{source_text}".encode("utf-8")).hexdigest()
    file_name = PurePosixPath(repo_path).name
    return ArtifactRef(
        artifact_id=f"sha256:{digest}",
        repo_path=repo_path,
        file_name=file_name,
        file_kind=FileKind.PYTHON,
        detected_extension=".py",
        media_type=None,
        size_bytes=len(source_text.encode("utf-8")),
        sha256=digest,
        source_url=f"https://huggingface.co/org/demo/resolve/main/{repo_path}",
        temp_local_path=f"/tmp/{file_name}",
        referenced_by=[],
        is_generated=False,
    )


def _runner_result(**overrides):
    payload = {
        "schema_version": "1.0",
        "request_id": "req-b2",
        "nonce": "nonce-123",
        "manifest_verified": True,
        "import_status": "success",
        "instantiate_status": "success",
        "forward_status": "success",
        "exception_class": None,
        "exception_message": None,
    }
    payload.update(overrides)
    return payload


def _sandbox_check(**kwargs):
    payload = {
        "request_id": "req-b2",
        "job_id": "job-b2",
        "artifact_id": "sha256:" + "a" * 64,
        "repo_path": "modeling_demo.py",
        "runner_result": _runner_result(),
        "expected_nonce": "nonce-123",
        "pending_api_refs": ["torch.special.expit"],
        "created_at": "2026-05-20T00:00:00Z",
    }
    payload.update(kwargs)
    return build_sandbox_check_from_runner_result(**payload)


def test_clean_runner_result_stays_policy_review_and_not_deployable() -> None:
    check = _sandbox_check()

    assert check["decision"] == "B2_POLICY_REVIEW_REQUIRED"
    assert check["deployable"] is False
    assert check["policy_gate"]["reason_code"] == "SANDBOX_POLICY_GATE_REQUIRED"
    assert check["policy_gate"]["pending_api_refs"] == ["torch.special.expit"]
    assert check["execution"]["manifest_verified"] is True
    assert check["execution"]["import_status"] == "success"
    assert check["execution"]["instantiate_status"] == "success"
    assert check["execution"]["forward_status"] == "success"


def test_security_event_maps_to_blocked_security_event() -> None:
    check = _sandbox_check(
        security_events={
            "network_events": [{"event_type": "connect", "family": "AF_INET"}],
            "unexpected_execve": [],
            "blocked_writes": [],
            "secret_path_access": [],
            "blocked_reads": [],
            "review_events": [],
        }
    )

    assert check["decision"] == "BLOCKED_SECURITY_EVENT"
    assert check["deployable"] is False
    assert check["policy_gate"]["reason_code"] == "SANDBOX_SECURITY_EVENT"


def test_timeout_and_memory_resource_flags_are_functional_review() -> None:
    from sandbox.b2.decision_builder import build_b2_decision
    from sandbox.b2.schemas import ExecutionEvidence, ManifestEvidence, RuntimeEvidence, SecurityEvents

    timeout_check = build_b2_decision(
        request_id="req-b2",
        job_id="job-b2",
        artifact_id="sha256:" + "a" * 64,
        repo_path="modeling_demo.py",
        grade="B-2",
        sandbox_runtime="gvisor",
        profile="B2_STANDARD",
        created_at="2026-05-20T00:00:00Z",
        runtime_evidence=RuntimeEvidence(),
        execution=ExecutionEvidence(import_status="success", instantiate_status="success", forward_status="success", timeout=True),
        security_events=SecurityEvents(),
        manifest_evidence=ManifestEvidence(),
        artifacts={},
        pending_api_refs=[],
        runtime_policy=B2RuntimePolicy(),
        runtime_setup_errors=[],
        post_start_runtime_errors=[],
        runner_diagnostics_status="present_valid",
        log_complete=True,
    ).to_dict()
    memory_check = build_b2_decision(
        request_id="req-b2",
        job_id="job-b2",
        artifact_id="sha256:" + "a" * 64,
        repo_path="modeling_demo.py",
        grade="B-2",
        sandbox_runtime="gvisor",
        profile="B2_STANDARD",
        created_at="2026-05-20T00:00:00Z",
        runtime_evidence=RuntimeEvidence(),
        execution=ExecutionEvidence(import_status="success", instantiate_status="success", forward_status="success", oom_killed=True),
        security_events=SecurityEvents(),
        manifest_evidence=ManifestEvidence(),
        artifacts={},
        pending_api_refs=[],
        runtime_policy=B2RuntimePolicy(),
        runtime_setup_errors=[],
        post_start_runtime_errors=[],
        runner_diagnostics_status="present_valid",
        log_complete=True,
    ).to_dict()

    assert timeout_check["decision"] == "FUNCTIONAL_REVIEW_REQUIRED"
    assert timeout_check["policy_gate"]["reason_code"] == "SANDBOX_FUNCTIONAL_REVIEW"
    assert memory_check["decision"] == "FUNCTIONAL_REVIEW_REQUIRED"
    assert memory_check["policy_gate"]["reason_code"] == "SANDBOX_RESOURCE_REVIEW"


def test_log_incomplete_review_and_block_policy_are_fail_closed() -> None:
    review_check = _sandbox_check(log_complete=False, runtime_policy=B2RuntimePolicy(log_incomplete_action="review"))
    block_check = _sandbox_check(log_complete=False, runtime_policy=B2RuntimePolicy(log_incomplete_action="block"))

    assert review_check["decision"] == "LOG_INCOMPLETE"
    assert review_check["policy_gate"]["reason_code"] == "SANDBOX_LOG_INCOMPLETE"
    assert review_check["deployable"] is False
    assert block_check["decision"] == "BLOCKED_SECURITY_EVENT"
    assert block_check["policy_gate"]["reason_code"] == "SANDBOX_LOG_INCOMPLETE"


def test_infra_malformed_and_nonce_mismatch_are_fail_closed() -> None:
    infra = _sandbox_check(runtime_setup_errors=["docker runtime missing"])
    malformed = _sandbox_check(runner_result={"schema_version": "1.0"})
    nonce_mismatch = _sandbox_check(runner_result=_runner_result(nonce="wrong"))

    assert infra["decision"] == "SANDBOX_INFRA_ERROR"
    assert infra["policy_gate"]["reason_code"] == "SANDBOX_INFRA_NOT_STARTED"
    assert malformed["decision"] == "FUNCTIONAL_REVIEW_REQUIRED"
    assert malformed["policy_gate"]["reason_code"] == "RUNNER_DIAGNOSTICS_MALFORMED"
    assert nonce_mismatch["decision"] == "FUNCTIONAL_REVIEW_REQUIRED"
    assert nonce_mismatch["policy_gate"]["reason_code"] == "RUNNER_DIAGNOSTICS_NONCE_MISMATCH"


def test_manifest_hash_errors_precede_runner_diagnostics() -> None:
    check = _sandbox_check(
        runner_result={"schema_version": "1.0"},
        manifest_evidence={
            "host_manifest_sha256": "0" * 64,
            "manifest_errors": ["HASH_MISMATCH:modeling_demo.py"],
            "input_hash_errors": [],
        },
    )

    assert check["decision"] == "BLOCKED_SECURITY_EVENT"
    assert check["policy_gate"]["reason_code"] == "SANDBOX_INPUT_INTEGRITY_VIOLATION"


def test_runner_manifest_not_verified_blocks_input_integrity() -> None:
    check = _sandbox_check(runner_result=_runner_result(manifest_verified=False))

    assert check["decision"] == "BLOCKED_SECURITY_EVENT"
    assert check["policy_gate"]["reason_code"] == "SANDBOX_INPUT_MANIFEST_NOT_VERIFIED"
    assert check["deployable"] is False


def test_runner_result_with_invalid_core_field_type_is_malformed() -> None:
    check = _sandbox_check(runner_result=_runner_result(manifest_verified="true"))

    assert check["decision"] == "FUNCTIONAL_REVIEW_REQUIRED"
    assert check["policy_gate"]["reason_code"] == "RUNNER_DIAGNOSTICS_MALFORMED"


def test_b2_non_target_does_not_call_decision_builder() -> None:
    source = (
        "class DemoModel:\n"
        "    def forward(self, module, name):\n"
        "        fn = getattr(module, name)\n"
        "        return fn()\n"
    )
    artifact = _make_artifact("modeling_dynamic.py", source)
    request = build_minimal_request(
        request_id="req-boundary",
        job_id="job-boundary",
        policy=_make_policy(),
        artifacts=[artifact],
    )
    calls: list[str] = []

    def sandbox_loader(result):
        calls.append(result.artifact.repo_path)
        return _sandbox_check(repo_path=result.artifact.repo_path)

    response = run_validation_job(
        request,
        source_loader={artifact.repo_path: source},
        source_resolver=object(),
        sandbox_check_loader=sandbox_loader,
    )

    result = response.artifact_results[0]
    assert calls == []
    assert result.route_kind is RouteKind.CODE_SANDBOX_RUNTIME
    assert _requires_b2_sandbox(result) is False
    assert result.status is ValidationStatus.PENDING_REVIEW
    assert "sandbox_check" not in result.details
