"""Stage-8 config routing validator.

This module parses config JSON artifacts, detects code trigger fields, resolves
referenced Python modules, and routes those references to the existing code
validator. It never imports or executes model config/code directly.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import PurePosixPath
from typing import Any, Callable, Mapping

from analyzer.classifier import build_artifact_ref
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
from analyzer.snapshot_resolver import SnapshotResolveError
from analyzer.validators.code_api_policy import WhitelistLookup
from analyzer.validators.code_semantic import validate_preprocessing_metadata_artifact
from analyzer.validators.code_validator import validate_python_artifact

SourceLoader = Callable[[str], str | bytes | None] | Mapping[str, str | bytes]
RuntimeCheckLoader = Callable[[str], dict[str, Any] | None] | Mapping[str, dict[str, Any]]
AstCallMetadataLoader = Callable[[str], list[dict[str, Any]] | None] | Mapping[str, list[dict[str, Any]]]
LinkedCodeResultCollector = Callable[[ArtifactValidationResult], None]

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
class CodeReferenceTarget:
    repo_path: str
    trigger_field: str
    auto_map_key: str | None = None
    target_module: str | None = None
    target_class: str | None = None
    target_repo_path: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "repo_path": self.repo_path,
            "trigger_field": self.trigger_field,
            "auto_map_key": self.auto_map_key,
            "target_module": self.target_module,
            "target_class": self.target_class,
            "target_repo_path": self.target_repo_path or self.repo_path,
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
    referenced_code_targets: list[CodeReferenceTarget] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "route_kind": RouteKind.CONFIG_SCHEMA_VALIDATION.value,
            "schema_valid": self.schema_valid,
            "parse_error": self.parse_error,
            "trigger_fields_detected": list(self.trigger_fields),
            "unknown_fields": list(self.unknown_fields),
            "referenced_python_files": list(self.referenced_python_files),
            "referenced_code_targets": [target.to_dict() for target in self.referenced_code_targets],
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
    source_resolver: Any | None = None,
    linked_code_result_collector: LinkedCodeResultCollector | None = None,
) -> ArtifactValidationResult:
    """Validate config/tokenizer_config and route referenced Python code."""

    started_at = _utc_now()
    source_text = source.decode("utf-8", errors="replace") if isinstance(source, bytes) else source

    scan_result, config_payload = scan_config_for_routing(artifact, source_text)
    referenced_code: list[dict[str, Any]] = []
    linked_code_results: list[dict[str, Any]] = []
    linked_code_edges: list[dict[str, Any]] = []
    linked_statuses: list[str] = []
    linked_artifact_ids: list[str] = []
    semantic_result: ArtifactValidationResult | None = None

    if artifact.file_kind is FileKind.TOKENIZER_CONFIG_JSON:
        semantic_result = validate_preprocessing_metadata_artifact(
            artifact=artifact,
            source=source,
            policy=policy,
        )

    if scan_result.schema_valid and scan_result.referenced_python_files:
        scan_result.rerouted_to_code_validation = True
        targets_by_repo = _targets_by_repo(scan_result.referenced_code_targets)
        for repo_path in scan_result.referenced_python_files:
            targets = targets_by_repo.get(repo_path, [])
            ref_entry: dict[str, Any] = {
                "repo_path": repo_path,
                "triggered_by": list(scan_result.trigger_fields),
                "load_status": "PENDING",
            }
            referenced_code.append(ref_entry)

            loaded = _load_referenced_source(source_loader, repo_path, source_resolver=source_resolver)
            if loaded["ok"] is not True:
                linked_status = _linked_status_for_load_error(str(loaded["error"]))
                ref_entry["load_status"] = "MISSING"
                ref_entry["load_error"] = loaded["error"]
                if loaded.get("resolver_error"):
                    ref_entry["resolver_error"] = loaded["resolver_error"]
                linked_code_results.append(
                    {
                        "repo_path": repo_path,
                        "status": linked_status,
                        "grade": CodeGrade.NA.value,
                        "review_action": ReviewAction.SECURITY_OWNER_GATE.value,
                        "error": loaded["error"],
                        "details": _load_error_details(loaded),
                    }
                )
                linked_statuses.append(linked_status)
                linked_code_edges.extend(
                    _edge_for_load_error(target, linked_status=linked_status, error=str(loaded["error"]))
                    for target in targets
                )
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
            code_result.details = _with_linked_code_details(
                code_result.details,
                parent_repo_path=artifact.repo_path,
                targets=targets,
                repo_path=repo_path,
            )
            linked_artifact_ids.append(code_result.artifact.artifact_id)
            linked_statuses.append(code_result.status.value)
            if linked_code_result_collector is not None:
                linked_code_result_collector(code_result)
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
            linked_code_edges.extend(_edges_for_code_result(targets=targets, code_result=code_result))

    effective_status = _combine_with_semantic_status(
        _compute_effective_status(scan_result, linked_statuses),
        semantic_result,
    )

    details = {
        "config_scan": scan_result.to_dict(),
        "trigger_fields": list(scan_result.trigger_fields),
        "referenced_code": referenced_code,
        "linked_code_results": linked_code_results,
        "linked_code_edges": linked_code_edges,
        "linked_code_artifact_ids": linked_artifact_ids,
        "linked_code_statuses": linked_statuses,
        "semantic_findings": [],
        "semantic_finding_codes": [],
        "effective_status": effective_status.value,
    }
    if semantic_result is not None:
        details.update(_semantic_details_for_config(semantic_result))
    if isinstance(config_payload, dict):
        details["config_field_count"] = len(config_payload)

    reason_entries = _build_reason_entries(
        trigger_fields=scan_result.trigger_fields,
        rerouted=scan_result.rerouted_to_code_validation,
        effective_status=effective_status,
    )
    reason_entries.extend(_semantic_reason_entries_for_config(semantic_result, effective_status))

    result = ArtifactValidationResult(
        artifact=artifact,
        route_kind=RouteKind.CONFIG_SCHEMA_VALIDATION,
        status=effective_status,
        grade=_grade_for_config_result(effective_status, semantic_result),
        review_action=_review_action_for_config_result(effective_status, semantic_result),
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
        auto_map_targets = _extract_targets_from_auto_map(payload.get("auto_map"))
        referenced_files.update(target.repo_path for target in auto_map_targets)
    else:
        auto_map_targets = []

    if payload.get("custom_pipelines"):
        trigger_fields.append(_TRIGGER_CUSTOM_PIPELINES)
        custom_pipeline_targets = _extract_targets_from_custom_pipelines(payload.get("custom_pipelines"))
        referenced_files.update(target.repo_path for target in custom_pipeline_targets)
    else:
        custom_pipeline_targets = []

    trust_remote_code = bool(payload.get("trust_remote_code") is True)
    if trust_remote_code:
        trigger_fields.append(_TRIGGER_TRUST_REMOTE_CODE)

    if artifact.file_name == "tokenizer_config.json":
        tokenizer_targets = _extract_targets_from_tokenizer_custom_fields(payload)
        referenced_files.update(target.repo_path for target in tokenizer_targets)
    else:
        tokenizer_targets = []

    result = ConfigScanResult(
        schema_valid=True,
        parse_error=None,
        trigger_fields=sorted(set(trigger_fields)),
        referenced_python_files=sorted(referenced_files),
        trust_remote_code=trust_remote_code,
        unknown_fields=[],
        referenced_code_targets=sorted(
            auto_map_targets + custom_pipeline_targets + tokenizer_targets,
            key=lambda target: (
                target.repo_path,
                target.auto_map_key or "",
                target.target_class or "",
                target.trigger_field,
            ),
        ),
    )
    return result, payload


def _extract_targets_from_auto_map(auto_map: Any) -> list[CodeReferenceTarget]:
    targets: list[CodeReferenceTarget] = []
    if isinstance(auto_map, dict):
        for key, value in auto_map.items():
            for raw in _collect_strings(value):
                target = _module_ref_to_target(raw, trigger_field=_TRIGGER_AUTO_MAP, auto_map_key=str(key))
                if target is not None:
                    targets.append(target)
        return targets

    for raw in _collect_strings(auto_map):
        target = _module_ref_to_target(raw, trigger_field=_TRIGGER_AUTO_MAP)
        if target is not None:
            targets.append(target)
    return targets


def _extract_targets_from_custom_pipelines(custom_pipelines: Any) -> list[CodeReferenceTarget]:
    targets: list[CodeReferenceTarget] = []
    for raw in _collect_strings(custom_pipelines):
        target = _module_ref_to_target(raw, trigger_field=_TRIGGER_CUSTOM_PIPELINES)
        if target is not None:
            targets.append(target)
    return targets


def _extract_targets_from_tokenizer_custom_fields(payload: dict[str, Any]) -> list[CodeReferenceTarget]:
    targets: list[CodeReferenceTarget] = []
    for key, value in payload.items():
        if key in _TOKENIZER_CLASS_KEYS:
            target = (
                _module_ref_to_target(str(value), trigger_field=key)
                if isinstance(value, str)
                else None
            )
            if target is not None:
                targets.append(target)
    return targets


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
    target = _module_ref_to_target(raw, trigger_field="")
    return target.repo_path if target is not None else None


def _module_ref_to_target(
    raw: str,
    *,
    trigger_field: str,
    auto_map_key: str | None = None,
) -> CodeReferenceTarget | None:
    text = raw.strip()
    if not text:
        return None
    if "\x00" in text or "\\" in text or text.startswith("/"):
        return None
    if len(text) >= 2 and text[1] == ":" and text[0].isalpha():
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
        repo_path = normalized
        if not _is_safe_repo_py_path(repo_path):
            return None
        module = repo_path[:-3].replace("/", ".") if repo_path.endswith(".py") else None
        return CodeReferenceTarget(
            repo_path=repo_path,
            trigger_field=trigger_field,
            auto_map_key=auto_map_key,
            target_module=module,
            target_class=None,
            target_repo_path=repo_path,
        )

    if "." in normalized:
        module_part = normalized.rsplit(".", 1)[0]
        target_class = normalized.rsplit(".", 1)[1]
        if not module_part:
            return None
        if any(ch.isspace() for ch in module_part):
            return None
        if "/" in module_part or "\\" in module_part or "\x00" in module_part:
            return None
        if not target_class or any(ch.isspace() for ch in target_class):
            return None
        repo_path = f"{module_part.replace('.', '/')}.py"
        if not _is_safe_repo_py_path(repo_path):
            return None
        return CodeReferenceTarget(
            repo_path=repo_path,
            trigger_field=trigger_field,
            auto_map_key=auto_map_key,
            target_module=module_part,
            target_class=target_class,
            target_repo_path=repo_path,
        )

    return None


def _is_safe_repo_py_path(repo_path: str) -> bool:
    if not repo_path.endswith(".py"):
        return False
    if not repo_path or "\x00" in repo_path or "\\" in repo_path:
        return False
    if repo_path.startswith("/"):
        return False
    if len(repo_path) >= 2 and repo_path[1] == ":" and repo_path[0].isalpha():
        return False
    path = PurePosixPath(repo_path)
    if path.is_absolute():
        return False
    if any(part in {"", ".", ".."} for part in path.parts):
        return False
    return True


def _load_referenced_source(
    loader: SourceLoader | None,
    repo_path: str,
    *,
    source_resolver: Any | None = None,
) -> dict[str, Any]:
    if source_resolver is not None and hasattr(source_resolver, "read_bytes"):
        value = source_resolver.read_bytes(repo_path)
        if isinstance(value, SnapshotResolveError):
            return {
                "ok": False,
                "error": value.value,
                "resolver_error": value.value,
            }
        if isinstance(value, bytes):
            return {"ok": True, "source": value}
        return {"ok": False, "error": "invalid_resolver_source_type"}

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
        if "ERROR" in normalized:
            return ValidationStatus.ERROR
        if "PENDING_REVIEW" in normalized or "MISSING" in normalized:
            return ValidationStatus.PENDING_REVIEW
        if normalized == {"PASS"}:
            return ValidationStatus.PASS
        return ValidationStatus.PENDING_REVIEW

    if scan_result.trigger_fields:
        return ValidationStatus.PENDING_REVIEW

    return ValidationStatus.PASS


def _combine_with_semantic_status(
    config_status: ValidationStatus,
    semantic_result: ArtifactValidationResult | None,
) -> ValidationStatus:
    if config_status is ValidationStatus.BLOCK:
        return ValidationStatus.BLOCK
    if semantic_result is None:
        return config_status
    if semantic_result.status is ValidationStatus.BLOCK:
        return ValidationStatus.BLOCK
    if _semantic_check_requires_review(semantic_result):
        return ValidationStatus.PENDING_REVIEW
    if semantic_result.status in {ValidationStatus.ERROR, ValidationStatus.PENDING_REVIEW}:
        return ValidationStatus.PENDING_REVIEW
    return config_status


def _semantic_details_for_config(semantic_result: ArtifactValidationResult) -> dict[str, Any]:
    semantic_details = semantic_result.details
    semantic_findings = semantic_details.get("semantic_findings", [])
    return {
        "semantic_check": semantic_details.get("semantic_check", {}),
        "semantic_inventory": semantic_details.get("semantic_inventory", {}),
        "semantic_findings": semantic_findings,
        "semantic_finding_codes": _semantic_finding_codes(semantic_findings),
        "semantic_route_kind": semantic_result.route_kind.value,
        "semantic_status": semantic_result.status.value,
        "semantic_grade": semantic_result.grade.value,
        "semantic_review_action": semantic_result.review_action.value,
    }


def _semantic_reason_entries_for_config(
    semantic_result: ArtifactValidationResult | None,
    effective_status: ValidationStatus,
) -> list[ReasonEntry]:
    if semantic_result is None:
        return []
    if semantic_result.status is ValidationStatus.PASS and not _semantic_check_requires_review(semantic_result):
        return []

    entries: list[ReasonEntry] = []
    seen: set[tuple[str, tuple[str, ...]]] = set()
    for entry in semantic_result.reason_entries:
        key = (entry.code, tuple(entry.evidence))
        seen.add(key)
        entries.append(
            ReasonEntry(
                code=entry.code,
                severity=entry.severity,
                message=entry.message,
                evidence=list(entry.evidence),
                review_required=effective_status is ValidationStatus.PENDING_REVIEW,
            )
        )
    for finding in semantic_result.details.get("semantic_findings", []):
        if not isinstance(finding, dict):
            continue
        code = str(finding.get("code") or "SEMANTIC_FINDING")
        evidence = [str(item) for item in finding.get("evidence", [])]
        key = (code, tuple(evidence))
        if key in seen:
            continue
        seen.add(key)
        entries.append(
            ReasonEntry(
                code=code,
                severity=str(finding.get("severity") or "MEDIUM"),
                message=f"preprocessing semantic finding: {code}",
                evidence=evidence,
                review_required=effective_status is ValidationStatus.PENDING_REVIEW,
            )
        )
    return entries


def _semantic_check_requires_review(semantic_result: ArtifactValidationResult) -> bool:
    semantic_check = semantic_result.details.get("semantic_check", {})
    if not isinstance(semantic_check, dict):
        return False
    return semantic_check.get("status") in {"REVIEW", "FAILED", "ERROR", "BASELINE_MISSING"}


def _semantic_finding_codes(semantic_findings: Any) -> list[str]:
    if not isinstance(semantic_findings, list):
        return []
    codes: list[str] = []
    for finding in semantic_findings:
        if not isinstance(finding, dict):
            continue
        code = finding.get("code")
        if isinstance(code, str) and code not in codes:
            codes.append(code)
    return codes


def _grade_for_config_result(
    effective_status: ValidationStatus,
    semantic_result: ArtifactValidationResult | None,
) -> CodeGrade:
    if effective_status is ValidationStatus.BLOCK:
        return CodeGrade.NA
    if semantic_result is not None and semantic_result.grade is CodeGrade.C:
        return CodeGrade.C
    return CodeGrade.NA


def _review_action_for_config_result(
    effective_status: ValidationStatus,
    semantic_result: ArtifactValidationResult | None,
) -> ReviewAction:
    if effective_status is ValidationStatus.BLOCK:
        return ReviewAction.BLOCK_IMMEDIATELY
    if semantic_result is not None and semantic_result.review_action is ReviewAction.MANUAL_REVIEW_REQUIRED:
        return ReviewAction.MANUAL_REVIEW_REQUIRED
    return _review_action_for_status(effective_status)


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
    if effective_status is ValidationStatus.ERROR:
        codes.append("VALIDATOR_INFRA_ERROR")
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
        "VALIDATOR_INFRA_ERROR": "config linked code source resolution failed integrity checks",
    }.get(code, "config routing decision")


def _review_action_for_status(status: ValidationStatus) -> ReviewAction:
    if status is ValidationStatus.BLOCK:
        return ReviewAction.BLOCK_IMMEDIATELY
    if status is ValidationStatus.PENDING_REVIEW:
        return ReviewAction.SECURITY_OWNER_GATE
    if status is ValidationStatus.ERROR:
        return ReviewAction.MANUAL_REVIEW_REQUIRED
    return ReviewAction.NONE


def _targets_by_repo(targets: list[CodeReferenceTarget]) -> dict[str, list[CodeReferenceTarget]]:
    output: dict[str, list[CodeReferenceTarget]] = {}
    for target in targets:
        output.setdefault(target.repo_path, []).append(target)
    return output


def _with_linked_code_details(
    details: dict[str, Any],
    *,
    parent_repo_path: str,
    targets: list[CodeReferenceTarget],
    repo_path: str,
) -> dict[str, Any]:
    updated = dict(details)
    first = targets[0] if targets else None
    updated["linked_from_config"] = parent_repo_path
    updated["auto_map_key"] = first.auto_map_key if first is not None else None
    updated["auto_map_keys"] = sorted({target.auto_map_key for target in targets if target.auto_map_key})
    updated["target_module"] = first.target_module if first is not None else None
    updated["target_class"] = first.target_class if first is not None else None
    updated["target_repo_path"] = repo_path
    updated["linked_code_targets"] = [target.to_dict() for target in targets]
    return updated


def _edges_for_code_result(
    *,
    targets: list[CodeReferenceTarget],
    code_result: ArtifactValidationResult,
) -> list[dict[str, Any]]:
    return [
        {
            **target.to_dict(),
            "artifact_id": code_result.artifact.artifact_id,
            "post_sandbox_status": code_result.status.value,
            "sandbox_decision": _sandbox_decision(code_result),
        }
        for target in targets
    ]


def _edge_for_load_error(
    target: CodeReferenceTarget,
    *,
    linked_status: str,
    error: str,
) -> dict[str, Any]:
    return {
        **target.to_dict(),
        "artifact_id": None,
        "post_sandbox_status": linked_status,
        "sandbox_decision": None,
        "error": error,
    }


def _load_error_details(loaded: dict[str, Any]) -> dict[str, Any]:
    details: dict[str, Any] = {
        "source_resolution": {
            "status": "ERROR" if _linked_status_for_load_error(str(loaded["error"])) == "ERROR" else "MISSING",
            "error": loaded["error"],
        }
    }
    if loaded.get("resolver_error"):
        details["source_resolution"]["resolver_error"] = loaded["resolver_error"]
    return details


def _linked_status_for_load_error(error: str) -> str:
    if error in {"source_loader_not_provided", "referenced_source_not_found", "MISSING_SOURCE"}:
        return "MISSING"
    return "ERROR"


def _sandbox_decision(result: ArtifactValidationResult) -> str | None:
    sandbox_check = result.details.get("sandbox_check")
    if isinstance(sandbox_check, dict):
        decision = sandbox_check.get("decision")
        return str(decision) if decision is not None else None
    return None


def _build_cache_key(artifact: ArtifactRef, policy: PolicyInfo | None) -> str:
    fingerprint = policy.policy_fingerprint if policy is not None else "policy-unknown"
    file_kind = artifact.file_kind.value if hasattr(artifact.file_kind, "value") else str(artifact.file_kind)
    return f"{artifact.sha256}:{file_kind}:{fingerprint}"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
