"""Stage-8 config routing validator.

This module parses config JSON artifacts, detects code trigger fields, resolves
referenced Python modules, and routes those references to the existing code
validator. It never imports or executes model config/code directly.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Mapping

from analyzer.classifier import build_artifact_ref
from analyzer.schemas import (
    ArtifactRef,
    ArtifactValidationResult,
    CodeGrade,
    PolicyInfo,
    ReasonEntry,
    ReviewAction,
    RouteKind,
    ValidationStatus,
)
from analyzer.validators.code_api_policy import WhitelistLookup
from analyzer.validators.code_validator import validate_python_artifact

SourceLoader = Callable[[str], str | bytes | None] | Mapping[str, str | bytes]
RuntimeCheckLoader = Callable[[str], dict[str, Any] | None] | Mapping[str, dict[str, Any]]
AstCallMetadataLoader = Callable[[str], list[dict[str, Any]] | None] | Mapping[str, list[dict[str, Any]]]

_TRIGGER_AUTO_MAP = "auto_map"
_TRIGGER_CUSTOM_PIPELINES = "custom_pipelines"
_TRIGGER_TRUST_REMOTE_CODE = "trust_remote_code"

_TOKENIZER_CLASS_KEYS = {
    "tokenizer_class",
    "processor_class",
    "image_processor_class",
    "video_processor_class",
    "feature_extractor_class",
}


@dataclass
class ConfigScanResult:
    schema_valid: bool
    parse_error: str | None = None
    trigger_fields: list[str] = field(default_factory=list)
    referenced_python_files: list[str] = field(default_factory=list)
    trust_remote_code: bool = False
    unknown_fields: list[str] = field(default_factory=list)
    rerouted_to_code_validation: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "route_kind": RouteKind.CONFIG_SCHEMA_VALIDATION.value,
            "schema_valid": self.schema_valid,
            "parse_error": self.parse_error,
            "trigger_fields_detected": list(self.trigger_fields),
            "unknown_fields": list(self.unknown_fields),
            "referenced_python_files": list(self.referenced_python_files),
            "trust_remote_code": self.trust_remote_code,
            "rerouted_to_code_validation": self.rerouted_to_code_validation,
        }


def validate_config_artifact(
    artifact: ArtifactRef,
    source: str | bytes,
    policy: PolicyInfo | None = None,
    whitelist_lookup: WhitelistLookup | None = None,
    *,
    source_loader: SourceLoader | None = None,
    runtime_check_loader: RuntimeCheckLoader | None = None,
    ast_call_metadata_loader: AstCallMetadataLoader | None = None,
) -> ArtifactValidationResult:
    """Validate config/tokenizer_config and route referenced Python code."""

    started_at = _utc_now()
    source_text = source.decode("utf-8", errors="replace") if isinstance(source, bytes) else source

    scan_result, config_payload = scan_config_for_routing(artifact, source_text)
    referenced_code: list[dict[str, Any]] = []
    linked_code_results: list[dict[str, Any]] = []
    linked_statuses: list[str] = []
    linked_artifact_ids: list[str] = []

    if scan_result.schema_valid and scan_result.referenced_python_files:
        scan_result.rerouted_to_code_validation = True
        for repo_path in scan_result.referenced_python_files:
            ref_entry: dict[str, Any] = {
                "repo_path": repo_path,
                "triggered_by": list(scan_result.trigger_fields),
                "load_status": "PENDING",
            }
            referenced_code.append(ref_entry)

            loaded = _load_referenced_source(source_loader, repo_path)
            if loaded["ok"] is not True:
                ref_entry["load_status"] = "MISSING"
                ref_entry["load_error"] = loaded["error"]
                linked_code_results.append(
                    {
                        "repo_path": repo_path,
                        "status": "MISSING",
                        "grade": CodeGrade.NA.value,
                        "review_action": ReviewAction.SECURITY_OWNER_GATE.value,
                        "error": loaded["error"],
                    }
                )
                linked_statuses.append("MISSING")
                continue

            ref_entry["load_status"] = "LOADED"
            code_source = loaded["source"]
            code_artifact = build_artifact_ref(
                repo_path,
                content=code_source,
                source_url=artifact.source_url,
                referenced_by=[artifact.repo_path],
            )
            runtime_check = _load_runtime_check(runtime_check_loader, repo_path)
            ast_call_metadata = _load_ast_call_metadata(ast_call_metadata_loader, repo_path) or []
            code_result = validate_python_artifact(
                artifact=code_artifact,
                source=code_source,
                policy=policy,
                whitelist_lookup=whitelist_lookup,
                runtime_check=runtime_check,
                ast_call_metadata=ast_call_metadata,
            )
            linked_artifact_ids.append(code_result.artifact.artifact_id)
            linked_statuses.append(code_result.status.value)
            linked_code_results.append(
                {
                    "repo_path": repo_path,
                    "artifact_id": code_result.artifact.artifact_id,
                    "status": code_result.status.value,
                    "grade": code_result.grade.value,
                    "review_action": code_result.review_action.value,
                    "details": {
                        "pending_api_refs": code_result.details.get("pending_api_refs", []),
                        "grade_result": code_result.details.get("grade_result", {}),
                    },
                }
            )

    effective_status = _compute_effective_status(scan_result, linked_statuses)

    details = {
        "config_scan": scan_result.to_dict(),
        "trigger_fields": list(scan_result.trigger_fields),
        "referenced_code": referenced_code,
        "linked_code_results": linked_code_results,
        "linked_code_artifact_ids": linked_artifact_ids,
        "linked_code_statuses": linked_statuses,
        "effective_status": effective_status.value,
    }
    if isinstance(config_payload, dict):
        details["config_field_count"] = len(config_payload)

    reason_entries = _build_reason_entries(
        trigger_fields=scan_result.trigger_fields,
        rerouted=scan_result.rerouted_to_code_validation,
        effective_status=effective_status,
    )

    result = ArtifactValidationResult(
        artifact=artifact,
        route_kind=RouteKind.CONFIG_SCHEMA_VALIDATION,
        status=effective_status,
        grade=CodeGrade.NA,
        review_action=_review_action_for_status(effective_status),
        cache_key=_build_cache_key(artifact, policy),
        cache_hit=False,
        reason_entries=reason_entries,
        details=details,
        started_at=started_at,
        finished_at=_utc_now(),
    )
    return result


def scan_config_for_routing(artifact: ArtifactRef, source_text: str) -> tuple[ConfigScanResult, dict[str, Any] | None]:
    try:
        payload = json.loads(source_text)
    except json.JSONDecodeError as exc:
        return ConfigScanResult(schema_valid=False, parse_error=str(exc)), None

    if not isinstance(payload, dict):
        return ConfigScanResult(schema_valid=False, parse_error="config root must be object"), None

    trigger_fields: list[str] = []
    referenced_files: set[str] = set()

    if payload.get("auto_map"):
        trigger_fields.append(_TRIGGER_AUTO_MAP)
        referenced_files.update(_extract_refs_from_auto_map(payload.get("auto_map")))

    if payload.get("custom_pipelines"):
        trigger_fields.append(_TRIGGER_CUSTOM_PIPELINES)
        referenced_files.update(_extract_refs_from_custom_pipelines(payload.get("custom_pipelines")))

    trust_remote_code = bool(payload.get("trust_remote_code") is True)
    if trust_remote_code:
        trigger_fields.append(_TRIGGER_TRUST_REMOTE_CODE)

    if artifact.file_name == "tokenizer_config.json":
        referenced_files.update(_extract_refs_from_tokenizer_custom_fields(payload))

    result = ConfigScanResult(
        schema_valid=True,
        parse_error=None,
        trigger_fields=sorted(set(trigger_fields)),
        referenced_python_files=sorted(referenced_files),
        trust_remote_code=trust_remote_code,
        unknown_fields=[],
    )
    return result, payload


def _extract_refs_from_auto_map(auto_map: Any) -> set[str]:
    refs: set[str] = set()
    for raw in _collect_strings(auto_map):
        resolved = _module_ref_to_repo_path(raw)
        if resolved:
            refs.add(resolved)
    return refs


def _extract_refs_from_custom_pipelines(custom_pipelines: Any) -> set[str]:
    refs: set[str] = set()
    for raw in _collect_strings(custom_pipelines):
        resolved = _module_ref_to_repo_path(raw)
        if resolved:
            refs.add(resolved)
    return refs


def _extract_refs_from_tokenizer_custom_fields(payload: dict[str, Any]) -> set[str]:
    refs: set[str] = set()
    for key, value in payload.items():
        if key in _TOKENIZER_CLASS_KEYS:
            resolved = _module_ref_to_repo_path(str(value)) if isinstance(value, str) else None
            if resolved:
                refs.add(resolved)
    return refs


def _collect_strings(value: Any) -> list[str]:
    output: list[str] = []
    if isinstance(value, str):
        output.append(value)
        return output
    if isinstance(value, list):
        for item in value:
            output.extend(_collect_strings(item))
        return output
    if isinstance(value, dict):
        for item in value.values():
            output.extend(_collect_strings(item))
        return output
    return output


def _module_ref_to_repo_path(raw: str) -> str | None:
    text = raw.strip()
    if not text:
        return None
    if text.startswith(("http://", "https://")):
        return None

    if "--" in text:
        text = text.rsplit("--", 1)[-1]
    if ":" in text:
        text = text.split(":", 1)[0]
    if "@" in text and ".py" not in text:
        text = text.split("@", 1)[0]

    normalized = text.replace("\\", "/").strip()

    if normalized.endswith(".py"):
        return normalized.lstrip("/")

    if "." in normalized:
        module_part = normalized.rsplit(".", 1)[0]
        if not module_part:
            return None
        if any(ch.isspace() for ch in module_part):
            return None
        return f"{module_part.replace('.', '/')}.py"

    return None


def _load_referenced_source(loader: SourceLoader | None, repo_path: str) -> dict[str, Any]:
    if loader is None:
        return {"ok": False, "error": "source_loader_not_provided"}
    try:
        if callable(loader):
            value = loader(repo_path)
        else:
            value = loader.get(repo_path)
    except Exception as exc:  # pragma: no cover - defensive
        return {"ok": False, "error": f"loader_error:{exc}"}

    if value is None:
        return {"ok": False, "error": "referenced_source_not_found"}
    if isinstance(value, (str, bytes)):
        return {"ok": True, "source": value}
    return {"ok": False, "error": "invalid_loader_source_type"}


def _load_runtime_check(loader: RuntimeCheckLoader | None, repo_path: str) -> dict[str, Any] | None:
    if loader is None:
        return None
    if callable(loader):
        return loader(repo_path)
    return loader.get(repo_path)


def _load_ast_call_metadata(loader: AstCallMetadataLoader | None, repo_path: str) -> list[dict[str, Any]] | None:
    if loader is None:
        return None
    if callable(loader):
        return loader(repo_path)
    return loader.get(repo_path)


def _compute_effective_status(scan_result: ConfigScanResult, linked_statuses: list[str]) -> ValidationStatus:
    if not scan_result.schema_valid:
        return ValidationStatus.BLOCK

    if scan_result.referenced_python_files:
        if not linked_statuses:
            return ValidationStatus.PENDING_REVIEW

        normalized = {item.upper() for item in linked_statuses}
        if "BLOCK" in normalized:
            return ValidationStatus.BLOCK
        if "PENDING_REVIEW" in normalized or "ERROR" in normalized or "MISSING" in normalized:
            return ValidationStatus.PENDING_REVIEW
        if normalized == {"PASS"}:
            return ValidationStatus.PASS
        return ValidationStatus.PENDING_REVIEW

    if scan_result.trigger_fields:
        return ValidationStatus.PENDING_REVIEW

    return ValidationStatus.PASS


def _build_reason_entries(
    *,
    trigger_fields: list[str],
    rerouted: bool,
    effective_status: ValidationStatus,
) -> list[ReasonEntry]:
    codes: list[str] = []
    if trigger_fields:
        codes.append("CONFIG_TRIGGER_FIELD_FOUND")
    if rerouted:
        codes.append("CONFIG_REFERENCED_CODE_ROUTED")
    if effective_status is ValidationStatus.PENDING_REVIEW:
        codes.append("GRADE_B2_GATE_REQUIRED")
    entries: list[ReasonEntry] = []
    for code in codes:
        entries.append(
            ReasonEntry(
                code=code,
                severity=_severity_for_status(effective_status),
                message=_reason_message(code),
                evidence=list(trigger_fields),
                review_required=effective_status is ValidationStatus.PENDING_REVIEW,
            )
        )
    return entries


def _severity_for_status(status: ValidationStatus) -> str:
    if status is ValidationStatus.BLOCK:
        return "HIGH"
    if status is ValidationStatus.PENDING_REVIEW:
        return "MEDIUM"
    return "LOW"


def _reason_message(code: str) -> str:
    return {
        "CONFIG_TRIGGER_FIELD_FOUND": "config trigger fields detected",
        "CONFIG_REFERENCED_CODE_ROUTED": "referenced code routed to code validator",
        "GRADE_B2_GATE_REQUIRED": "config requires review gate because linked code is not fully PASS",
    }.get(code, "config routing decision")


def _review_action_for_status(status: ValidationStatus) -> ReviewAction:
    if status is ValidationStatus.BLOCK:
        return ReviewAction.BLOCK_IMMEDIATELY
    if status is ValidationStatus.PENDING_REVIEW:
        return ReviewAction.SECURITY_OWNER_GATE
    return ReviewAction.NONE


def _build_cache_key(artifact: ArtifactRef, policy: PolicyInfo | None) -> str:
    fingerprint = policy.policy_fingerprint if policy is not None else "policy-unknown"
    file_kind = artifact.file_kind.value if hasattr(artifact.file_kind, "value") else str(artifact.file_kind)
    return f"{artifact.sha256}:{file_kind}:{fingerprint}"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
