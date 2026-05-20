"""Stage-7 integrated code validator and grade decision engine.

This module combines role classification, AST scan, API policy scan, context
analysis, and externally-injected runtime gate results to produce a single
ArtifactValidationResult for a Python artifact.

It does not import or execute untrusted model source code.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from analyzer.schemas import (
    ArtifactRef,
    ArtifactValidationResult,
    CodeGrade,
    FileKind,
    PolicyInfo,
    ReasonEntry,
    ReviewAction,
    RouteKind,
    ValidationStatus,
)
from analyzer.validators.code_api import ApiScanResult, scan_api_policy
from analyzer.validators.code_api_policy import ApiPolicy, WhitelistLookup, default_api_policy
from analyzer.validators.code_ast import AstScanResult, extract_ast_candidates
from analyzer.validators.code_context import ContextApiScanResult, analyze_contextual_api_calls
from analyzer.validators.code_roles import PythonFileRole, RoleClassification, classify_python_role

_UNRESOLVED_DYNAMIC_REASON = "UNRESOLVED_WITH_DYNAMIC_OR_OBFUSCATION"
_RUNTIME_MODE_REGENERATE = "REGENERATE"
_RUNTIME_MODE_RESTRICTED = "RESTRICTED_RUNTIME"
_RUNTIME_MODE_SANDBOX = "SANDBOX"
_RUNTIME_MODE_NONE = "NONE"
_RUNTIME_STATUS_PASS = "PASS"
_RUNTIME_STATUS_SKIPPED = "SKIPPED"
_RUNTIME_STATUS_ERROR = "ERROR"
_RUNTIME_STATUS_FAIL = "FAIL"
_RUNTIME_STATUS_TIMEOUT = "TIMEOUT"
_RUNTIME_STATUS_MEMORY_LIMIT = "MEMORY_LIMIT"
_RUNTIME_FAILURE_REASON_CODES = {
    "RUNTIME_GATE_SKIPPED",
    "RUNTIME_GATE_ERROR",
    "RUNTIME_GATE_FAIL",
    "RUNTIME_GATE_TIMEOUT",
    "RUNTIME_GATE_MEMORY_LIMIT",
    "RUNTIME_GATE_UNKNOWN_STATUS",
    "RUNTIME_SECURITY_EVENT",
    "RUNTIME_FUNCTIONAL_REVIEW",
    "RUNTIME_RESOURCE_REVIEW",
    "RUNTIME_RESOURCE_SECURITY_EVENT",
}


@dataclass
class _GradeDecision:
    grade: CodeGrade
    status: ValidationStatus
    review_action: ReviewAction
    runtime_mode: str
    reason_codes: list[str]
    grade_reasons: list[str]
    requires_runtime_gate: bool = False
    requires_security_review: bool = False


def validate_python_artifact(
    artifact: ArtifactRef,
    source: str | bytes,
    policy: PolicyInfo | ApiPolicy | None = None,
    whitelist_lookup: WhitelistLookup | None = None,
    runtime_check: dict[str, Any] | None = None,
    *,
    ast_call_metadata: list[dict[str, Any]] | None = None,
) -> ArtifactValidationResult:
    """Validate one Python artifact without importing/executing source code."""

    started_at = _utc_now()
    source_text = source.decode("utf-8", errors="replace") if isinstance(source, bytes) else source
    runtime_detail = _normalize_runtime_check(runtime_check)

    if artifact.file_kind is not FileKind.PYTHON:
        decision = _GradeDecision(
            grade=CodeGrade.NA,
            status=ValidationStatus.SKIPPED,
            review_action=ReviewAction.NONE,
            runtime_mode=_RUNTIME_MODE_NONE,
            reason_codes=["UNKNOWN_FILE_TYPE"],
            grade_reasons=["python_artifact_required"],
            requires_runtime_gate=False,
            requires_security_review=False,
        )
        details = {
            "role_classification": {},
            "ast_scan": {},
            "configuration_metadata": {},
            "api_scan": {},
            "context_api_scan": {"summary_decision": "safe"},
            "grade_result": _grade_result_to_dict(decision),
            "runtime_check": runtime_detail,
            "pending_api_refs": [],
            "review_queue_entry_id": None,
            "effective_output_artifact_id": None,
        }
        result = ArtifactValidationResult(
            artifact=artifact,
            route_kind=RouteKind.CODE_AST_SCAN,
            status=decision.status,
            grade=decision.grade,
            review_action=decision.review_action,
            cache_key=_build_cache_key(artifact, policy),
            cache_hit=False,
            reason_entries=_build_reason_entries(
                reason_codes=decision.reason_codes,
                ast_scan=None,
                api_scan=None,
                context_scan=None,
                runtime_check=runtime_detail,
                status=decision.status,
            ),
            details=details,
            started_at=started_at,
            finished_at=_utc_now(),
        )
        return result

    role = classify_python_role(artifact.repo_path, source_text)
    ast_scan = extract_ast_candidates(artifact.repo_path, source_text)

    api_policy = _resolve_api_policy(policy)
    api_scan = scan_api_policy(
        ast_scan,
        policy=api_policy,
        whitelist_lookup=whitelist_lookup,
    )

    context_scan = analyze_contextual_api_calls(
        api_scan.contextual_apis,
        ast_call_metadata or [],
        file_role=role.role.value,
    )

    decision = _decide_grade(
        role=role,
        ast_scan=ast_scan,
        api_scan=api_scan,
        context_scan=context_scan,
        runtime_check=runtime_detail,
    )

    details = {
        "role_classification": role.to_dict(),
        "ast_scan": ast_scan.to_dict(),
        "configuration_metadata": _configuration_metadata(ast_scan),
        "api_scan": api_scan.to_dict(),
        "context_api_scan": context_scan.to_dict(),
        "grade_result": _grade_result_to_dict(decision),
        "runtime_check": runtime_detail,
        "pending_api_refs": list(api_scan.pending_api_refs),
        "review_queue_entry_id": None,
        "effective_output_artifact_id": None,
    }

    result = ArtifactValidationResult(
        artifact=artifact,
        route_kind=_route_kind_from_runtime_mode(decision.runtime_mode),
        status=decision.status,
        grade=decision.grade,
        review_action=decision.review_action,
        cache_key=_build_cache_key(artifact, policy),
        cache_hit=False,
        reason_entries=_build_reason_entries(
            reason_codes=decision.reason_codes,
            ast_scan=ast_scan,
            api_scan=api_scan,
            context_scan=context_scan,
            runtime_check=runtime_detail,
            status=decision.status,
        ),
        details=details,
        started_at=started_at,
        finished_at=_utc_now(),
    )
    return result


def _decide_grade(
    *,
    role: RoleClassification,
    ast_scan: AstScanResult,
    api_scan: ApiScanResult,
    context_scan: ContextApiScanResult,
    runtime_check: dict[str, Any],
) -> _GradeDecision:
    dangerous_api_candidates = _dangerous_api_blocked_list(api_scan)

    # 1. 위험 import/call/API -> C/BLOCK/BLOCK_IMMEDIATELY
    if ast_scan.dangerous_imports or ast_scan.dangerous_calls or dangerous_api_candidates:
        reason_codes: list[str] = []
        if ast_scan.dangerous_imports:
            reason_codes.append("DANGEROUS_IMPORT")
        if ast_scan.dangerous_calls:
            reason_codes.append("DANGEROUS_CALL")
        if dangerous_api_candidates:
            reason_codes.append("DANGEROUS_API")
        return _GradeDecision(
            grade=CodeGrade.C,
            status=ValidationStatus.BLOCK,
            review_action=ReviewAction.BLOCK_IMMEDIATELY,
            runtime_mode=_RUNTIME_MODE_NONE,
            reason_codes=_dedupe(reason_codes),
            grade_reasons=["dangerous_import_call_or_api"],
        )

    # 2. context analyzer decision=block -> C/BLOCK/BLOCK_IMMEDIATELY
    if context_scan.summary_decision == "block":
        return _GradeDecision(
            grade=CodeGrade.C,
            status=ValidationStatus.BLOCK,
            review_action=ReviewAction.BLOCK_IMMEDIATELY,
            runtime_mode=_RUNTIME_MODE_NONE,
            reason_codes=["CONTEXT_API_BLOCKED"],
            grade_reasons=["contextual_api_block_decision"],
        )

    # 3. 동적/난독화 패턴 -> C/PENDING_REVIEW/MANUAL_REVIEW_REQUIRED
    if ast_scan.dynamic_patterns or ast_scan.obfuscation_patterns:
        reason_codes: list[str] = []
        if ast_scan.dynamic_patterns:
            reason_codes.append("DYNAMIC_PATTERN")
        if ast_scan.obfuscation_patterns:
            reason_codes.append("OBFUSCATION_PATTERN")
        reason_codes.append("GRADE_C_MANUAL_REVIEW")
        return _GradeDecision(
            grade=CodeGrade.C,
            status=ValidationStatus.PENDING_REVIEW,
            review_action=ReviewAction.MANUAL_REVIEW_REQUIRED,
            runtime_mode=_RUNTIME_MODE_SANDBOX,
            reason_codes=_dedupe(reason_codes),
            grade_reasons=["dynamic_or_obfuscation_detected"],
            requires_security_review=True,
        )

    # 4. context analyzer decision=review -> B-2/PENDING_REVIEW/SECURITY_OWNER_GATE
    if context_scan.summary_decision == "review":
        return _GradeDecision(
            grade=CodeGrade.B2,
            status=ValidationStatus.PENDING_REVIEW,
            review_action=ReviewAction.SECURITY_OWNER_GATE,
            runtime_mode=_RUNTIME_MODE_SANDBOX,
            reason_codes=["CONTEXT_API_REVIEW", "GRADE_B2_GATE_REQUIRED"],
            grade_reasons=["contextual_api_review_required"],
            requires_security_review=True,
        )

    # 5. unregistered API 존재 -> B-2/PENDING_REVIEW/SECURITY_OWNER_GATE
    if api_scan.unregistered_apis:
        return _GradeDecision(
            grade=CodeGrade.B2,
            status=ValidationStatus.PENDING_REVIEW,
            review_action=ReviewAction.SECURITY_OWNER_GATE,
            runtime_mode=_RUNTIME_MODE_SANDBOX,
            reason_codes=["UNREGISTERED_API", "GRADE_B2_GATE_REQUIRED"],
            grade_reasons=["unregistered_api_detected"],
            requires_security_review=True,
        )

    # 6. 단순 config + 재생성 가능 조건 -> A/PASS/AUTO_APPROVE_REGENERATED
    if _is_grade_a_candidate(role, ast_scan, api_scan, context_scan):
        return _GradeDecision(
            grade=CodeGrade.A,
            status=ValidationStatus.PASS,
            review_action=ReviewAction.AUTO_APPROVE_REGENERATED,
            runtime_mode=_RUNTIME_MODE_REGENERATE,
            reason_codes=["GRADE_A_REGENERATED"],
            grade_reasons=["configuration_static_shape_regenerable"],
        )

    # 7. 정형 modeling + allowed API + context safe + runtime_check passed -> B-1/PASS/AUTO_APPROVE
    if role.role is PythonFileRole.CONFIGURATION:
        return _GradeDecision(
            grade=CodeGrade.B2,
            status=ValidationStatus.PENDING_REVIEW,
            review_action=ReviewAction.SECURITY_OWNER_GATE,
            runtime_mode=_RUNTIME_MODE_SANDBOX,
            reason_codes=["GRADE_B2_GATE_REQUIRED"],
            grade_reasons=["configuration_not_regenerable_requires_review"],
            requires_security_review=True,
        )

    if _is_b1_candidate(role, ast_scan, api_scan, context_scan):
        return _decide_b1_runtime_gate(runtime_check)

    # 8. 그 외 -> B-2 또는 C/PENDING_REVIEW
    normalized_role = role.role.value
    if normalized_role == PythonFileRole.UNKNOWN.value:
        return _GradeDecision(
            grade=CodeGrade.C,
            status=ValidationStatus.PENDING_REVIEW,
            review_action=ReviewAction.MANUAL_REVIEW_REQUIRED,
            runtime_mode=_RUNTIME_MODE_SANDBOX,
            reason_codes=["GRADE_C_MANUAL_REVIEW"],
            grade_reasons=["unknown_role_manual_review"],
            requires_security_review=True,
        )

    return _GradeDecision(
        grade=CodeGrade.B2,
        status=ValidationStatus.PENDING_REVIEW,
        review_action=ReviewAction.SECURITY_OWNER_GATE,
        runtime_mode=_RUNTIME_MODE_SANDBOX,
        reason_codes=["GRADE_B2_GATE_REQUIRED"],
        grade_reasons=["out_of_scope_or_non_auto_approval_role"],
        requires_security_review=True,
    )


def _is_grade_a_candidate(
    role: RoleClassification,
    ast_scan: AstScanResult,
    api_scan: ApiScanResult,
    context_scan: ContextApiScanResult,
) -> bool:
    if role.role is not PythonFileRole.CONFIGURATION:
        return False
    config_meta = _configuration_metadata(ast_scan)
    if not bool(config_meta.get("config_regenerable", False)):
        return False
    if ast_scan.parse_error is not None:
        return False
    if not ast_scan.classes:
        return False
    if ast_scan.method_flags.get("has_forward") or ast_scan.method_flags.get("has_generate") or ast_scan.method_flags.get(
        "has_call"
    ):
        return False
    if ast_scan.dangerous_imports or ast_scan.dangerous_calls:
        return False
    if ast_scan.dynamic_patterns or ast_scan.obfuscation_patterns:
        return False
    if api_scan.blocked_apis or api_scan.unregistered_apis:
        return False
    if context_scan.summary_decision != "safe":
        return False
    return True


def _is_b1_candidate(
    role: RoleClassification,
    ast_scan: AstScanResult,
    api_scan: ApiScanResult,
    context_scan: ContextApiScanResult,
) -> bool:
    if role.role is not PythonFileRole.MODELING:
        return False
    if ast_scan.parse_error is not None:
        return False
    if ast_scan.dangerous_imports or ast_scan.dangerous_calls:
        return False
    if ast_scan.dynamic_patterns or ast_scan.obfuscation_patterns:
        return False
    if api_scan.blocked_apis or api_scan.unregistered_apis:
        return False
    if context_scan.summary_decision != "safe":
        return False
    if not api_scan.allowed_apis:
        return False

    used = set(api_scan.used_apis)
    allowed_or_contextual = set(api_scan.allowed_apis) | set(api_scan.contextual_apis)
    return used.issubset(allowed_or_contextual)


def _runtime_gate_passed(runtime_check: dict[str, Any]) -> bool:
    return _runtime_status(runtime_check) == _RUNTIME_STATUS_PASS


def _decide_b1_runtime_gate(runtime_check: dict[str, Any]) -> _GradeDecision:
    status = _runtime_status(runtime_check)
    runtime_reason_codes = _runtime_detail_reason_codes(runtime_check)

    if status == _RUNTIME_STATUS_PASS:
        return _GradeDecision(
            grade=CodeGrade.B1,
            status=ValidationStatus.PASS,
            review_action=ReviewAction.AUTO_APPROVE,
            runtime_mode=_RUNTIME_MODE_RESTRICTED,
            reason_codes=["GRADE_B1_RUNTIME_OK"],
            grade_reasons=["structured_modeling_runtime_gate_passed"],
            requires_runtime_gate=True,
        )

    if status in {"", _RUNTIME_STATUS_SKIPPED}:
        return _GradeDecision(
            grade=CodeGrade.B2,
            status=ValidationStatus.PENDING_REVIEW,
            review_action=ReviewAction.SECURITY_OWNER_GATE,
            runtime_mode=_RUNTIME_MODE_SANDBOX,
            reason_codes=_dedupe(["RUNTIME_GATE_SKIPPED", "GRADE_B2_GATE_REQUIRED"] + runtime_reason_codes),
            grade_reasons=["runtime_gate_missing_or_skipped"],
            requires_runtime_gate=True,
            requires_security_review=True,
        )

    if status == _RUNTIME_STATUS_ERROR:
        return _GradeDecision(
            grade=CodeGrade.C,
            status=ValidationStatus.ERROR,
            review_action=ReviewAction.MANUAL_REVIEW_REQUIRED,
            runtime_mode=_RUNTIME_MODE_NONE,
            reason_codes=_dedupe(["RUNTIME_GATE_ERROR"] + runtime_reason_codes),
            grade_reasons=["runtime_gate_infra_or_unknown_error"],
            requires_runtime_gate=True,
        )

    if status == _RUNTIME_STATUS_FAIL:
        if _has_runtime_security_event(runtime_check):
            return _GradeDecision(
                grade=CodeGrade.C,
                status=ValidationStatus.BLOCK,
                review_action=ReviewAction.BLOCK_IMMEDIATELY,
                runtime_mode=_RUNTIME_MODE_NONE,
                reason_codes=_dedupe(["RUNTIME_GATE_FAIL", "RUNTIME_SECURITY_EVENT"] + runtime_reason_codes),
                grade_reasons=["runtime_gate_fail_security_event"],
                requires_runtime_gate=True,
            )
        return _GradeDecision(
            grade=CodeGrade.C,
            status=ValidationStatus.PENDING_REVIEW,
            review_action=ReviewAction.MANUAL_REVIEW_REQUIRED,
            runtime_mode=_RUNTIME_MODE_NONE,
            reason_codes=_dedupe(["RUNTIME_GATE_FAIL", "RUNTIME_FUNCTIONAL_REVIEW"] + runtime_reason_codes),
            grade_reasons=["runtime_gate_fail_functional_review"],
            requires_runtime_gate=True,
        )

    if status == _RUNTIME_STATUS_TIMEOUT:
        if _has_runtime_security_event(runtime_check):
            return _GradeDecision(
                grade=CodeGrade.C,
                status=ValidationStatus.BLOCK,
                review_action=ReviewAction.BLOCK_IMMEDIATELY,
                runtime_mode=_RUNTIME_MODE_NONE,
                reason_codes=_dedupe(["RUNTIME_GATE_TIMEOUT", "RUNTIME_SECURITY_EVENT"] + runtime_reason_codes),
                grade_reasons=["runtime_gate_timeout_security_event"],
                requires_runtime_gate=True,
            )
        return _GradeDecision(
            grade=CodeGrade.C,
            status=ValidationStatus.PENDING_REVIEW,
            review_action=ReviewAction.MANUAL_REVIEW_REQUIRED,
            runtime_mode=_RUNTIME_MODE_NONE,
            reason_codes=_dedupe(["RUNTIME_GATE_TIMEOUT", "RUNTIME_FUNCTIONAL_REVIEW"] + runtime_reason_codes),
            grade_reasons=["runtime_gate_timeout_functional_review"],
            requires_runtime_gate=True,
        )

    if status == _RUNTIME_STATUS_MEMORY_LIMIT:
        if _has_runtime_resource_security_event(runtime_check):
            return _GradeDecision(
                grade=CodeGrade.C,
                status=ValidationStatus.BLOCK,
                review_action=ReviewAction.BLOCK_IMMEDIATELY,
                runtime_mode=_RUNTIME_MODE_NONE,
                reason_codes=_dedupe(
                    ["RUNTIME_GATE_MEMORY_LIMIT", "RUNTIME_RESOURCE_SECURITY_EVENT"] + runtime_reason_codes
                ),
                grade_reasons=["runtime_gate_memory_limit_runaway_or_fork_evidence"],
                requires_runtime_gate=True,
            )
        return _GradeDecision(
            grade=CodeGrade.C,
            status=ValidationStatus.PENDING_REVIEW,
            review_action=ReviewAction.MANUAL_REVIEW_REQUIRED,
            runtime_mode=_RUNTIME_MODE_NONE,
            reason_codes=_dedupe(["RUNTIME_GATE_MEMORY_LIMIT", "RUNTIME_RESOURCE_REVIEW"] + runtime_reason_codes),
            grade_reasons=["runtime_gate_memory_limit_resource_review"],
            requires_runtime_gate=True,
        )

    return _GradeDecision(
        grade=CodeGrade.C,
        status=ValidationStatus.PENDING_REVIEW,
        review_action=ReviewAction.MANUAL_REVIEW_REQUIRED,
        runtime_mode=_RUNTIME_MODE_NONE,
        reason_codes=_dedupe(["RUNTIME_GATE_UNKNOWN_STATUS"] + runtime_reason_codes),
        grade_reasons=["runtime_gate_unknown_status_manual_review"],
        requires_runtime_gate=True,
    )


def _runtime_status(runtime_check: dict[str, Any]) -> str:
    return str(runtime_check.get("status", "")).upper()


def _dangerous_api_blocked_list(api_scan: ApiScanResult) -> list[str]:
    dangerous: list[str] = []
    for api in api_scan.blocked_apis:
        reason = api_scan.blocked_reason_by_api.get(api)
        if reason == _UNRESOLVED_DYNAMIC_REASON:
            continue
        dangerous.append(api)
    return dangerous


def _resolve_api_policy(policy: PolicyInfo | ApiPolicy | None) -> ApiPolicy:
    if isinstance(policy, ApiPolicy):
        return policy
    if isinstance(policy, PolicyInfo):
        return default_api_policy(policy_version=policy.policy_version)
    if policy is not None and hasattr(policy, "policy_version"):
        return default_api_policy(policy_version=str(getattr(policy, "policy_version")))
    return default_api_policy()


def _normalize_runtime_check(runtime_check: dict[str, Any] | None) -> dict[str, Any]:
    normalized = {
        "runtime_mode": _RUNTIME_MODE_NONE,
        "builtins_removed": [],
        "import_allowlist_applied": False,
        "dummy_forward_executed": False,
        "sandbox_runtime": None,
        "syscall_anomaly_detected": None,
        "logs_ref": None,
        "status": "SKIPPED",
    }
    if runtime_check:
        normalized.update(runtime_check)
    return normalized


def _runtime_detail_reason_codes(runtime_check: dict[str, Any]) -> list[str]:
    codes: list[str] = []
    for key in ("reason_code", "error_code"):
        code = _normalize_reason_code(runtime_check.get(key))
        if code:
            codes.append(code)
    for key in ("reason_codes", "error_codes"):
        value = runtime_check.get(key)
        if isinstance(value, (list, tuple, set)):
            for item in value:
                code = _normalize_reason_code(item)
                if code:
                    codes.append(code)
        else:
            code = _normalize_reason_code(value)
            if code:
                codes.append(code)
    return _dedupe(codes)


def _normalize_reason_code(value: Any) -> str | None:
    if value is None:
        return None
    raw = str(value).strip().upper()
    if not raw:
        return None
    normalized = "".join(char if char.isalnum() else "_" for char in raw).strip("_")
    return normalized or None


def _has_runtime_security_event(runtime_check: dict[str, Any]) -> bool:
    security_keys = {
        "security_event",
        "security_events",
        "security_event_detected",
        "blocked_import",
        "blocked_imports",
        "denied_import",
        "denied_imports",
        "blocked_audit_event",
        "blocked_audit_events",
        "audit_security_event",
        "audit_security_events",
        "audit_events",
        "policy_violation",
        "policy_violations",
        "syscall_anomaly_detected",
    }
    if any(_runtime_value_has_signal(runtime_check.get(key)) for key in security_keys):
        return True

    traceback = str(runtime_check.get("traceback") or "")
    return any(token in traceback.lower() for token in ("blocked", "denylist", "security", "audit"))


def _has_runtime_resource_security_event(runtime_check: dict[str, Any]) -> bool:
    resource_keys = {
        "runaway_detected",
        "runaway_process",
        "runaway_processes",
        "fork_detected",
        "fork_events",
        "thread_detected",
        "thread_events",
        "thread_runaway_detected",
        "resource_security_event",
        "resource_security_events",
    }
    if any(_runtime_value_has_signal(runtime_check.get(key)) for key in resource_keys):
        return True

    haystack = " ".join(
        _runtime_evidence_value(runtime_check.get(key))
        for key in ("audit_events", "security_events", "traceback", "message", "reason", "reason_code")
    ).lower()
    return any(token in haystack for token in ("fork", "thread", "runaway"))


def _runtime_value_has_signal(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() not in {"", "false", "0", "none", "null", "no"}
    if isinstance(value, dict):
        return any(_runtime_value_has_signal(item) for item in value.values())
    if isinstance(value, (list, tuple, set)):
        return any(_runtime_value_has_signal(item) for item in value)
    return bool(value)


def _build_reason_entries(
    *,
    reason_codes: list[str],
    ast_scan: AstScanResult | None,
    api_scan: ApiScanResult | None,
    context_scan: ContextApiScanResult | None,
    runtime_check: dict[str, Any] | None,
    status: ValidationStatus,
) -> list[ReasonEntry]:
    entries: list[ReasonEntry] = []
    for code in _dedupe(reason_codes):
        evidence = _reason_evidence(
            code,
            ast_scan=ast_scan,
            api_scan=api_scan,
            context_scan=context_scan,
            runtime_check=runtime_check,
        )
        severity, review_required = _severity_and_review_flag(code, status)
        entries.append(
            ReasonEntry(
                code=code,
                severity=severity,
                message=_reason_message(code),
                evidence=evidence,
                review_required=review_required,
            )
        )
    return entries


def _reason_evidence(
    code: str,
    *,
    ast_scan: AstScanResult | None,
    api_scan: ApiScanResult | None,
    context_scan: ContextApiScanResult | None,
    runtime_check: dict[str, Any] | None,
) -> list[str]:
    if code == "DANGEROUS_IMPORT" and ast_scan is not None:
        return list(ast_scan.dangerous_imports)
    if code == "DANGEROUS_CALL" and ast_scan is not None:
        return list(ast_scan.dangerous_calls)
    if code == "DANGEROUS_API" and api_scan is not None:
        return _dangerous_api_blocked_list(api_scan)
    if code == "DYNAMIC_PATTERN" and ast_scan is not None:
        return list(ast_scan.dynamic_patterns)
    if code == "OBFUSCATION_PATTERN" and ast_scan is not None:
        return list(ast_scan.obfuscation_patterns)
    if code == "UNREGISTERED_API" and api_scan is not None:
        return list(api_scan.unregistered_apis)
    if code in {"CONTEXT_API_REVIEW", "CONTEXT_API_BLOCKED"} and context_scan is not None:
        target = "review" if code == "CONTEXT_API_REVIEW" else "block"
        return _context_apis_by_decision(context_scan, target)
    if runtime_check is not None and (
        code in _RUNTIME_FAILURE_REASON_CODES or code in _runtime_detail_reason_codes(runtime_check)
    ):
        return _runtime_reason_evidence(runtime_check)
    return []


def _runtime_reason_evidence(runtime_check: dict[str, Any]) -> list[str]:
    evidence: list[str] = []
    for key in (
        "status",
        "reason_code",
        "reason_codes",
        "error_code",
        "error_codes",
        "message",
        "exception_class",
        "blocked_imports",
        "audit_events",
        "security_events",
        "resource_security_events",
        "syscall_anomaly_detected",
        "logs_ref",
    ):
        if key not in runtime_check:
            continue
        value = runtime_check.get(key)
        if not _runtime_value_has_signal(value):
            continue
        evidence.append(f"{key}={_runtime_evidence_value(value)}")
    return evidence


def _runtime_evidence_value(value: Any) -> str:
    if isinstance(value, dict):
        return ",".join(f"{key}:{_runtime_evidence_value(item)}" for key, item in sorted(value.items()))
    if isinstance(value, (list, tuple, set)):
        return ",".join(_runtime_evidence_value(item) for item in value)
    return str(value)


def _context_apis_by_decision(context_scan: ContextApiScanResult, decision: str) -> list[str]:
    findings = (
        context_scan.open_calls
        + context_scan.os_calls
        + context_scan.path_helper_calls
        + context_scan.env_access_calls
        + context_scan.file_mutation_calls
        + context_scan.network_calls
        + context_scan.command_exec_calls
    )
    return sorted({item.api for item in findings if item.decision == decision})


def _severity_and_review_flag(code: str, status: ValidationStatus) -> tuple[str, bool]:
    if status is ValidationStatus.BLOCK:
        return "HIGH", False
    if status is ValidationStatus.ERROR:
        return "HIGH", True
    if status is ValidationStatus.PENDING_REVIEW:
        if code in {
            "DYNAMIC_PATTERN",
            "OBFUSCATION_PATTERN",
            "GRADE_C_MANUAL_REVIEW",
            "RUNTIME_GATE_FAIL",
            "RUNTIME_GATE_TIMEOUT",
            "RUNTIME_GATE_MEMORY_LIMIT",
            "RUNTIME_GATE_UNKNOWN_STATUS",
        }:
            return "HIGH", True
        return "MEDIUM", True
    return "LOW", False


def _reason_message(code: str) -> str:
    return {
        "UNKNOWN_FILE_TYPE": "unsupported file kind for code validator",
        "DANGEROUS_IMPORT": "dangerous import detected",
        "DANGEROUS_CALL": "dangerous call detected",
        "DANGEROUS_API": "dangerous API blocked by policy",
        "DYNAMIC_PATTERN": "dynamic pattern detected",
        "OBFUSCATION_PATTERN": "obfuscation pattern detected",
        "UNREGISTERED_API": "unregistered API requires security review",
        "CONTEXT_API_REVIEW": "context-dependent API requires review",
        "CONTEXT_API_BLOCKED": "context-dependent API blocked",
        "GRADE_A_REGENERATED": "configuration qualifies for regenerated grade A path",
        "GRADE_B1_RUNTIME_OK": "restricted runtime gate passed for B-1",
        "GRADE_B2_GATE_REQUIRED": "B-2 security owner gate required",
        "GRADE_C_MANUAL_REVIEW": "manual review required for C-grade candidate",
        "RUNTIME_GATE_SKIPPED": "restricted runtime gate was skipped or not provided",
        "RUNTIME_GATE_ERROR": "restricted runtime gate returned an infrastructure or unknown error",
        "RUNTIME_GATE_FAIL": "restricted runtime gate failed",
        "RUNTIME_GATE_TIMEOUT": "restricted runtime gate timed out",
        "RUNTIME_GATE_MEMORY_LIMIT": "restricted runtime gate hit a memory limit",
        "RUNTIME_GATE_UNKNOWN_STATUS": "restricted runtime gate returned an unknown status",
        "RUNTIME_SECURITY_EVENT": "restricted runtime failure included security evidence",
        "RUNTIME_FUNCTIONAL_REVIEW": "restricted runtime failure requires functional review",
        "RUNTIME_RESOURCE_REVIEW": "restricted runtime memory failure requires resource review",
        "RUNTIME_RESOURCE_SECURITY_EVENT": "restricted runtime memory failure included runaway or fork/thread evidence",
    }.get(code, "policy decision")


def _configuration_metadata(ast_scan: AstScanResult) -> dict[str, Any]:
    raw = getattr(ast_scan, "configuration_metadata", None)
    if not isinstance(raw, dict):
        return {}
    return dict(raw)


def _grade_result_to_dict(decision: _GradeDecision) -> dict[str, Any]:
    grade_reason = "; ".join(decision.grade_reasons) if decision.grade_reasons else "policy decision"
    return {
        "grade": decision.grade.value,
        "grade_reason": grade_reason,
        "status": decision.status.value,
        "review_action": decision.review_action.value,
        "runtime_mode": decision.runtime_mode,
        "grade_reasons": list(decision.grade_reasons),
        "reason_codes": list(decision.reason_codes),
        "is_auto_approval_candidate": decision.status is ValidationStatus.PASS,
        "requires_runtime_gate": decision.requires_runtime_gate,
        "requires_security_review": decision.requires_security_review,
    }


def _route_kind_from_runtime_mode(runtime_mode: str) -> RouteKind:
    if runtime_mode == _RUNTIME_MODE_RESTRICTED:
        return RouteKind.CODE_RESTRICTED_RUNTIME
    if runtime_mode == _RUNTIME_MODE_SANDBOX:
        return RouteKind.CODE_SANDBOX_RUNTIME
    return RouteKind.CODE_AST_SCAN


def _build_cache_key(artifact: ArtifactRef, policy: PolicyInfo | ApiPolicy | None) -> str:
    file_kind = artifact.file_kind.value if hasattr(artifact.file_kind, "value") else str(artifact.file_kind)
    fingerprint = getattr(policy, "policy_fingerprint", None)
    if not fingerprint:
        fingerprint = getattr(policy, "policy_version", "policy-unknown")
    return f"{artifact.sha256}:{file_kind}:{fingerprint}"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        ordered.append(item)
    return ordered
