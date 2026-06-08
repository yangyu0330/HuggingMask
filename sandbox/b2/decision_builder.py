"""Build host-side B-2 sandbox decisions from runner evidence.

This module consumes already-collected fake/host runner output and evidence. It
does not create containers, call Docker/runsc, parse inspect output, or stage
files.
"""

from __future__ import annotations

from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from typing import Any, Mapping

from analyzer.schemas import CodeGrade
from sandbox.b2.schemas import (
    B2Decision,
    B2RunnerResult,
    B2RuntimePolicy,
    B2SandboxCheck,
    B2_SCHEMA_VERSION,
    ExecutionEvidence,
    ManifestEvidence,
    RunnerDiagnosticsStatus,
    RuntimeEvidence,
    SecurityEvents,
)

_RUNNER_STATUS_VALUES = {"success", "failed", "skipped", "skipped_schema_unknown"}


def build_sandbox_check_from_runner_result(
    *,
    request_id: str | None,
    job_id: str | None,
    artifact_id: str,
    repo_path: str,
    runner_result: B2RunnerResult | Mapping[str, Any] | None,
    expected_nonce: str | None = None,
    grade: str = CodeGrade.B2.value,
    sandbox_runtime: str | None = "gvisor",
    profile: str = "B2_STANDARD",
    created_at: str | None = None,
    runtime_evidence: RuntimeEvidence | Mapping[str, Any] | None = None,
    security_events: SecurityEvents | Mapping[str, Any] | None = None,
    manifest_evidence: ManifestEvidence | Mapping[str, Any] | None = None,
    artifacts: dict[str, str] | None = None,
    pending_api_refs: list[str] | None = None,
    runtime_policy: B2RuntimePolicy | Mapping[str, Any] | None = None,
    runtime_setup_errors: list[str] | None = None,
    post_start_runtime_errors: list[str] | None = None,
    log_complete: bool = True,
    strace_observed: bool = True,
) -> dict[str, Any]:
    """Return a standard ``sandbox_check`` dict for orchestrator details."""

    runner, diagnostics_status = normalize_runner_result(
        runner_result,
        expected_nonce=expected_nonce,
        expected_request_id=request_id,
    )
    execution = _execution_from_runner(runner)
    check = build_b2_decision(
        request_id=request_id,
        job_id=job_id,
        artifact_id=artifact_id,
        repo_path=repo_path,
        grade=grade,
        sandbox_runtime=sandbox_runtime,
        profile=profile,
        created_at=created_at or _utc_now(),
        runtime_evidence=_coerce_runtime_evidence(runtime_evidence),
        execution=execution,
        security_events=_coerce_security_events(security_events),
        manifest_evidence=_coerce_manifest_evidence(manifest_evidence),
        artifacts=artifacts or {},
        pending_api_refs=pending_api_refs or [],
        runtime_policy=_coerce_runtime_policy(runtime_policy),
        runtime_setup_errors=runtime_setup_errors or [],
        post_start_runtime_errors=post_start_runtime_errors or [],
        runner_diagnostics_status=diagnostics_status,
        log_complete=log_complete,
        strace_observed=strace_observed,
    )
    return check.to_dict()


def normalize_runner_result(
    runner_result: B2RunnerResult | Mapping[str, Any] | None,
    *,
    expected_nonce: str | None = None,
    expected_request_id: str | None = None,
) -> tuple[B2RunnerResult | None, RunnerDiagnosticsStatus]:
    if runner_result is None:
        return None, RunnerDiagnosticsStatus.MISSING

    if isinstance(runner_result, B2RunnerResult):
        data = runner_result.to_dict()
    elif isinstance(runner_result, Mapping):
        data = dict(runner_result)
    elif is_dataclass(runner_result):
        data = asdict(runner_result)
    else:
        return None, RunnerDiagnosticsStatus.MALFORMED

    required = {
        "schema_version",
        "request_id",
        "nonce",
        "manifest_verified",
        "import_status",
        "instantiate_status",
        "forward_status",
    }
    if not required.issubset(data):
        return None, RunnerDiagnosticsStatus.MALFORMED
    if data.get("schema_version") != B2_SCHEMA_VERSION:
        return None, RunnerDiagnosticsStatus.MALFORMED
    if not isinstance(data.get("request_id"), str):
        return None, RunnerDiagnosticsStatus.MALFORMED
    if not isinstance(data.get("nonce"), str):
        return None, RunnerDiagnosticsStatus.MALFORMED
    if not isinstance(data.get("manifest_verified"), bool):
        return None, RunnerDiagnosticsStatus.MALFORMED
    for status_key in ("import_status", "instantiate_status", "forward_status"):
        status = data.get(status_key)
        if not isinstance(status, str) or status not in _RUNNER_STATUS_VALUES:
            return None, RunnerDiagnosticsStatus.MALFORMED
    if expected_request_id is not None and data.get("request_id") != expected_request_id:
        return None, RunnerDiagnosticsStatus.NONCE_MISMATCH
    if expected_nonce is not None and data.get("nonce") != expected_nonce:
        return None, RunnerDiagnosticsStatus.NONCE_MISMATCH

    try:
        return B2RunnerResult.from_dict(data), RunnerDiagnosticsStatus.PRESENT_VALID
    except TypeError:
        return None, RunnerDiagnosticsStatus.MALFORMED


def build_b2_decision(
    *,
    request_id: str | None,
    job_id: str | None,
    artifact_id: str,
    repo_path: str,
    grade: str,
    sandbox_runtime: str | None,
    profile: str,
    created_at: str,
    runtime_evidence: RuntimeEvidence,
    execution: ExecutionEvidence,
    security_events: SecurityEvents,
    manifest_evidence: ManifestEvidence,
    artifacts: dict[str, str],
    pending_api_refs: list[str],
    runtime_policy: B2RuntimePolicy,
    runtime_setup_errors: list[str],
    post_start_runtime_errors: list[str],
    runner_diagnostics_status: RunnerDiagnosticsStatus,
    log_complete: bool,
    strace_observed: bool = True,
) -> B2SandboxCheck:
    runner_diagnostics_status = RunnerDiagnosticsStatus(runner_diagnostics_status)
    decision, reason_code, reason = _select_decision(
        execution=execution,
        security_events=security_events,
        manifest_evidence=manifest_evidence,
        pending_api_refs=pending_api_refs,
        runtime_policy=runtime_policy,
        runtime_setup_errors=runtime_setup_errors,
        post_start_runtime_errors=post_start_runtime_errors,
        runner_diagnostics_status=runner_diagnostics_status,
        log_complete=log_complete,
        strace_observed=strace_observed,
    )

    policy_gate: dict[str, Any] = {
        "reason_code": reason_code,
        "decision": decision.value,
        "runner_diagnostics_status": runner_diagnostics_status.value,
    }
    if pending_api_refs:
        policy_gate["pending_api_refs"] = list(pending_api_refs)
    if runtime_setup_errors:
        policy_gate["runtime_setup_errors"] = list(runtime_setup_errors)
    if post_start_runtime_errors:
        policy_gate["post_start_runtime_errors"] = list(post_start_runtime_errors)

    return B2SandboxCheck(
        schema_version=B2_SCHEMA_VERSION,
        request_id=request_id,
        job_id=job_id,
        artifact_id=artifact_id,
        repo_path=repo_path,
        grade=grade,
        sandbox_runtime=sandbox_runtime,
        profile=profile,
        decision=decision,
        deployable=False,
        runtime_evidence=runtime_evidence,
        execution=execution,
        security_events=security_events,
        manifest_evidence=manifest_evidence,
        artifacts=dict(artifacts),
        policy_gate=policy_gate,
        created_at=created_at,
        reason=reason,
    )


def _select_decision(
    *,
    execution: ExecutionEvidence,
    security_events: SecurityEvents,
    manifest_evidence: ManifestEvidence,
    pending_api_refs: list[str],
    runtime_policy: B2RuntimePolicy,
    runtime_setup_errors: list[str],
    post_start_runtime_errors: list[str],
    runner_diagnostics_status: RunnerDiagnosticsStatus,
    log_complete: bool,
    strace_observed: bool = True,
) -> tuple[B2Decision, str, str]:
    if runtime_setup_errors:
        return (
            B2Decision.SANDBOX_INFRA_ERROR,
            "SANDBOX_INFRA_NOT_STARTED",
            "B-2 sandbox infrastructure did not start cleanly",
        )
    if post_start_runtime_errors:
        return (
            B2Decision.BLOCKED_RUNTIME_INVALID,
            "SANDBOX_RUNTIME_DRIFT_AFTER_START",
            "B-2 sandbox runtime policy drift was observed after start",
        )
    if manifest_evidence.manifest_errors or manifest_evidence.input_hash_errors:
        return (
            B2Decision.BLOCKED_SECURITY_EVENT,
            "SANDBOX_INPUT_INTEGRITY_VIOLATION",
            "host-side manifest or input hash verification failed",
        )
    if execution.manifest_verified is False:
        return (
            B2Decision.BLOCKED_SECURITY_EVENT,
            "SANDBOX_INPUT_MANIFEST_NOT_VERIFIED",
            "runner did not verify the B-2 input manifest",
        )
    if _has_hard_security_event(security_events):
        return (
            B2Decision.BLOCKED_SECURITY_EVENT,
            "SANDBOX_SECURITY_EVENT",
            "B-2 sandbox observed a hard security event",
        )
    if not log_complete:
        if runtime_policy.log_incomplete_action == "block":
            return (
                B2Decision.BLOCKED_SECURITY_EVENT,
                "SANDBOX_LOG_INCOMPLETE",
                "required B-2 sandbox log evidence is incomplete",
            )
        return (
            B2Decision.LOG_INCOMPLETE,
            "SANDBOX_LOG_INCOMPLETE",
            "required B-2 sandbox log evidence is incomplete",
        )
    if runner_diagnostics_status is not RunnerDiagnosticsStatus.PRESENT_VALID:
        return (
            B2Decision.FUNCTIONAL_REVIEW_REQUIRED,
            _runner_diagnostics_reason_code(runner_diagnostics_status),
            "B-2 runner diagnostics are missing, malformed, or nonce mismatched",
        )
    if execution.timeout:
        return (
            B2Decision.FUNCTIONAL_REVIEW_REQUIRED,
            "SANDBOX_FUNCTIONAL_REVIEW",
            "B-2 sandbox timed out without a hard security event",
        )
    if execution.oom_killed or execution.pids_limit_hit:
        return (
            B2Decision.FUNCTIONAL_REVIEW_REQUIRED,
            "SANDBOX_RESOURCE_REVIEW",
            "B-2 sandbox hit a resource limit without a hard security event",
        )
    if execution.import_status == "failed" or execution.instantiate_status == "failed":
        return (
            B2Decision.FUNCTIONAL_REVIEW_REQUIRED,
            "SANDBOX_FUNCTIONAL_REVIEW",
            "B-2 import or instantiate failed",
        )
    if execution.forward_status in {"failed", "skipped", "skipped_schema_unknown"}:
        return (
            B2Decision.FORWARD_SKIPPED_REVIEW,
            "SANDBOX_FORWARD_REVIEW",
            "B-2 forward execution did not produce a clean supported result",
        )
    if _has_high_risk_review_event(security_events):
        return (
            B2Decision.HIGH_RISK_REVIEW,
            "SANDBOX_HIGH_RISK_REVIEW",
            "B-2 sandbox observed a high-risk review event",
        )

    # require_runsc_strace 강제: 정책이 strace를 요구하는데 실제 strace 관측이
    # 없었다면(strace_observed=False) "관측된 적 없음"을 clean으로 인증하지
    # 않는다. (이전엔 이 정책 필드가 어디서도 안 읽혀, container stdout만 있고
    # syscall trace가 없어도 아래 clean 분기로 빠졌다.) syscall trace 없이는
    # network/exec/write 이벤트 부재가 "안전"이 아니라 "관측 불가"이기 때문.
    if runtime_policy.require_runsc_strace and not strace_observed:
        if runtime_policy.log_incomplete_action == "block":
            return (
                B2Decision.BLOCKED_SECURITY_EVENT,
                "SANDBOX_STRACE_NOT_OBSERVED",
                "required runsc strace evidence was not observed; cannot certify clean",
            )
        return (
            B2Decision.LOG_INCOMPLETE,
            "SANDBOX_STRACE_NOT_OBSERVED",
            "required runsc strace evidence was not observed; cannot certify clean",
        )

    return (
        B2Decision.B2_POLICY_REVIEW_REQUIRED,
        "SANDBOX_POLICY_GATE_REQUIRED",
        "B-2 sandbox observation is clean but still requires security owner review",
    )


def _execution_from_runner(runner: B2RunnerResult | None) -> ExecutionEvidence:
    if runner is None:
        return ExecutionEvidence()
    return ExecutionEvidence(
        manifest_verified=runner.manifest_verified,
        import_status=runner.import_status,
        instantiate_status=runner.instantiate_status,
        forward_status=runner.forward_status,
        timeout=False,
        oom_killed=False,
        pids_limit_hit=False,
    )


def _has_hard_security_event(security_events: SecurityEvents) -> bool:
    return any(
        [
            security_events.network_events,
            security_events.unexpected_execve,
            security_events.blocked_writes,
            security_events.secret_path_access,
            security_events.blocked_reads,
        ]
    )


def _has_high_risk_review_event(security_events: SecurityEvents) -> bool:
    for event in security_events.review_events:
        severity = str(event.get("severity", "")).upper()
        event_type = str(event.get("event_type", "")).lower()
        if severity == "HIGH" or event_type == "high_risk_namespace":
            return True
    return False


def _runner_diagnostics_reason_code(status: RunnerDiagnosticsStatus) -> str:
    return {
        RunnerDiagnosticsStatus.MISSING: "RUNNER_DIAGNOSTICS_MISSING",
        RunnerDiagnosticsStatus.MALFORMED: "RUNNER_DIAGNOSTICS_MALFORMED",
        RunnerDiagnosticsStatus.NONCE_MISMATCH: "RUNNER_DIAGNOSTICS_NONCE_MISMATCH",
    }.get(status, "SANDBOX_FUNCTIONAL_REVIEW")


def _coerce_runtime_policy(value: B2RuntimePolicy | Mapping[str, Any] | None) -> B2RuntimePolicy:
    if value is None:
        return B2RuntimePolicy()
    if isinstance(value, B2RuntimePolicy):
        return value
    return B2RuntimePolicy(**dict(value))


def _coerce_runtime_evidence(value: RuntimeEvidence | Mapping[str, Any] | None) -> RuntimeEvidence:
    if value is None:
        return RuntimeEvidence()
    if isinstance(value, RuntimeEvidence):
        return value
    return RuntimeEvidence(**dict(value))


def _coerce_security_events(value: SecurityEvents | Mapping[str, Any] | None) -> SecurityEvents:
    if value is None:
        return SecurityEvents()
    if isinstance(value, SecurityEvents):
        return value
    return SecurityEvents(**dict(value))


def _coerce_manifest_evidence(value: ManifestEvidence | Mapping[str, Any] | None) -> ManifestEvidence:
    if value is None:
        return ManifestEvidence()
    if isinstance(value, ManifestEvidence):
        return value
    return ManifestEvidence(**dict(value))


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
