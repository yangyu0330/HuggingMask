"""Stage-6 contextual API analyzer for validation step-2.

This module is a sub-analyzer of API_POLICY_SCAN. It consumes contextual API
paths and AST-derived call metadata, then emits safe/review/block decisions for
open/path/os/env/mutation/network-related calls.

It does not import or execute model code.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

SAFE = "safe"
REVIEW = "review"
BLOCK = "block"

_DECISION_PRIORITY = {SAFE: 0, REVIEW: 1, BLOCK: 2}

_RESOURCE_FILE_NAMES = {
    "vocab.json",
    "merges.txt",
    "tokenizer.json",
    "tokenizer_config.json",
    "special_tokens_map.json",
    "added_tokens.json",
    "processor_config.json",
    "preprocessor_config.json",
    "config.json",
}

_RESOURCE_HINT_KEYWORDS = (
    "vocab",
    "merge",
    "tokenizer",
    "processor",
    "special_tokens",
    "config",
)

_PATH_HELPER_APIS = {
    "os.path.join",
    "os.path.dirname",
    "os.path.basename",
    "os.path.exists",
}

_ENV_APIS = {"os.getenv", "os.environ.get"}

_OS_FILE_MUTATION_APIS = {
    "os.remove",
    "os.unlink",
    "os.rename",
    "os.replace",
    "os.rmdir",
    "shutil.rmtree",
}

_PATH_MUTATION_SUFFIXES = (
    ".write_text",
    ".write_bytes",
    ".unlink",
    ".rmdir",
    ".rename",
    ".replace",
    ".chmod",
    ".mkdir",
    ".touch",
)

_NETWORK_PREFIXES = ("requests.", "urllib.", "httpx.", "socket.")
_PROCESS_PREFIXES = ("subprocess.", "os.exec", "os.spawn")
_COMMAND_EXEC_APIS = {"os.system", "os.popen"}
_WRITE_MODE_FLAGS = {"w", "a", "x", "+"}


@dataclass
class ContextCallFinding:
    api: str
    category: str
    decision: str
    reason_code: str
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "api": self.api,
            "category": self.category,
            "decision": self.decision,
            "reason_code": self.reason_code,
            "evidence": list(self.evidence),
        }


@dataclass
class ContextApiScanResult:
    open_calls: list[ContextCallFinding] = field(default_factory=list)
    os_calls: list[ContextCallFinding] = field(default_factory=list)
    path_helper_calls: list[ContextCallFinding] = field(default_factory=list)
    env_access_calls: list[ContextCallFinding] = field(default_factory=list)
    file_mutation_calls: list[ContextCallFinding] = field(default_factory=list)
    network_calls: list[ContextCallFinding] = field(default_factory=list)
    command_exec_calls: list[ContextCallFinding] = field(default_factory=list)
    summary_decision: str = SAFE

    def to_dict(self) -> dict[str, Any]:
        return {
            "open_calls": [item.to_dict() for item in self.open_calls],
            "os_calls": [item.to_dict() for item in self.os_calls],
            "path_helper_calls": [item.to_dict() for item in self.path_helper_calls],
            "env_access_calls": [item.to_dict() for item in self.env_access_calls],
            "file_mutation_calls": [item.to_dict() for item in self.file_mutation_calls],
            "network_calls": [item.to_dict() for item in self.network_calls],
            "command_exec_calls": [item.to_dict() for item in self.command_exec_calls],
            "summary_decision": self.summary_decision,
        }


def analyze_open_call(
    api: str,
    call_meta: dict[str, Any] | None = None,
    *,
    file_role: str | None = None,
) -> ContextCallFinding:
    meta = call_meta or {}
    path_arg = _extract_path_arg(api, meta)
    mode_arg = _extract_mode_arg(api, meta)

    mode_text = mode_arg["value"] if mode_arg["is_constant"] else ""
    mode_is_write = _is_write_mode(mode_text) if mode_arg["is_constant"] else False

    evidence = [
        f"path={path_arg['display']}",
        f"path_constant={path_arg['is_constant']}",
        f"path_user_input={path_arg['is_user_input']}",
        f"mode={mode_arg['display']}",
        f"mode_constant={mode_arg['is_constant']}",
    ]

    if mode_is_write:
        return ContextCallFinding(
            api=api,
            category="open",
            decision=BLOCK,
            reason_code="OPEN_WRITE_MODE_BLOCK",
            evidence=evidence,
        )

    if mode_arg["is_constant"] and not mode_text:
        return ContextCallFinding(
            api=api,
            category="open",
            decision=REVIEW,
            reason_code="OPEN_EMPTY_MODE_REVIEW",
            evidence=evidence,
        )

    if not mode_arg["is_constant"]:
        return ContextCallFinding(
            api=api,
            category="open",
            decision=REVIEW,
            reason_code="OPEN_DYNAMIC_MODE_REVIEW",
            evidence=evidence,
        )

    if path_arg["is_user_input"]:
        return ContextCallFinding(
            api=api,
            category="open",
            decision=REVIEW,
            reason_code="OPEN_USER_INPUT_PATH_REVIEW",
            evidence=evidence,
        )

    if not path_arg["is_constant"]:
        return ContextCallFinding(
            api=api,
            category="open",
            decision=REVIEW,
            reason_code="OPEN_DYNAMIC_PATH_REVIEW",
            evidence=evidence,
        )

    path_value = path_arg["value"]
    if _is_suspicious_path(path_value):
        return ContextCallFinding(
            api=api,
            category="open",
            decision=REVIEW,
            reason_code="OPEN_SUSPICIOUS_PATH_REVIEW",
            evidence=evidence,
        )

    if _is_resource_path(path_value):
        if _is_preprocess_context(file_role=file_role, call_meta=meta):
            return ContextCallFinding(
                api=api,
                category="open",
                decision=SAFE,
                reason_code="OPEN_RESOURCE_READ_SAFE",
                evidence=evidence,
            )
        return ContextCallFinding(
            api=api,
            category="open",
            decision=REVIEW,
            reason_code="OPEN_RESOURCE_READ_REVIEW",
            evidence=evidence,
        )

    return ContextCallFinding(
        api=api,
        category="open",
        decision=REVIEW,
        reason_code="OPEN_NON_RESOURCE_READ_REVIEW",
        evidence=evidence,
    )


def analyze_path_call(
    api: str,
    call_meta: dict[str, Any] | None = None,
    *,
    file_role: str | None = None,
) -> ContextCallFinding:
    if _is_path_mutation_api(api):
        return analyze_file_mutation_call(api, call_meta, file_role=file_role)

    if api.endswith(".open"):
        return analyze_open_call(api, call_meta, file_role=file_role)

    if api in _PATH_HELPER_APIS:
        return _analyze_path_helper_call(api, call_meta, file_role=file_role)

    if api.endswith(".read_text") or api.endswith(".read_bytes"):
        return _analyze_path_read_call(api, call_meta, file_role=file_role)

    return ContextCallFinding(
        api=api,
        category="path_helper",
        decision=REVIEW,
        reason_code="PATH_CALL_REVIEW_UNKNOWN",
        evidence=["path_call_unclassified"],
    )


def analyze_os_call(
    api: str,
    call_meta: dict[str, Any] | None = None,
    *,
    file_role: str | None = None,
) -> ContextCallFinding:
    if api.startswith("os.path."):
        return analyze_path_call(api, call_meta, file_role=file_role)
    if api in _ENV_APIS:
        return analyze_env_call(api, call_meta, file_role=file_role)
    if api in _OS_FILE_MUTATION_APIS:
        return analyze_file_mutation_call(api, call_meta, file_role=file_role)
    if _is_command_exec_api(api):
        return ContextCallFinding(
            api=api,
            category="command_exec",
            decision=BLOCK,
            reason_code="COMMAND_EXEC_BLOCK",
            evidence=["os_command_exec"],
        )
    return ContextCallFinding(
        api=api,
        category="os",
        decision=REVIEW,
        reason_code="OS_CALL_REVIEW",
        evidence=["os_call_without_specific_policy"],
    )


def analyze_env_call(
    api: str,
    call_meta: dict[str, Any] | None = None,
    *,
    file_role: str | None = None,
) -> ContextCallFinding:
    del file_role
    meta = call_meta or {}
    arg0 = _extract_argument(meta, 0)
    usage_tags = _extract_usage_tags(meta)

    evidence = [
        f"env_key={arg0['display']}",
        f"env_key_constant={arg0['is_constant']}",
    ]
    if usage_tags:
        evidence.append(f"usage_tags={','.join(sorted(usage_tags))}")

    reason_code = "ENV_ACCESS_REVIEW"
    if {"path", "token", "network"} & usage_tags:
        reason_code = "ENV_ACCESS_SENSITIVE_FLOW_REVIEW"

    return ContextCallFinding(
        api=api,
        category="env_access",
        decision=REVIEW,
        reason_code=reason_code,
        evidence=evidence,
    )


def analyze_file_mutation_call(
    api: str,
    call_meta: dict[str, Any] | None = None,
    *,
    file_role: str | None = None,
) -> ContextCallFinding:
    del file_role
    meta = call_meta or {}
    path_arg = _extract_path_arg(api, meta)
    evidence = [
        f"path={path_arg['display']}",
        f"path_constant={path_arg['is_constant']}",
        f"path_user_input={path_arg['is_user_input']}",
        "file_mutation_or_create",
    ]
    return ContextCallFinding(
        api=api,
        category="file_mutation",
        decision=BLOCK,
        reason_code="FILE_MUTATION_BLOCK",
        evidence=evidence,
    )


def analyze_network_call(
    api: str,
    call_meta: dict[str, Any] | None = None,
    *,
    file_role: str | None = None,
) -> ContextCallFinding:
    del call_meta, file_role
    return ContextCallFinding(
        api=api,
        category="network",
        decision=BLOCK,
        reason_code="NETWORK_CALL_BLOCK",
        evidence=["network_api_in_model_code"],
    )


def analyze_contextual_api_calls(
    contextual_apis: list[str],
    ast_call_metadata: list[dict[str, Any]],
    *,
    file_role: str | None = None,
) -> ContextApiScanResult:
    result = ContextApiScanResult()
    by_api: dict[str, list[dict[str, Any]]] = {}
    for item in ast_call_metadata:
        api = _extract_api_name(item)
        if not api:
            continue
        by_api.setdefault(api, []).append(item)

    all_candidates = set(contextual_apis)
    all_candidates.update(by_api.keys())

    findings: list[ContextCallFinding] = []
    for api in sorted(all_candidates):
        metas = by_api.get(api, [{}])
        for meta in metas:
            finding = _dispatch_contextual_api(api, meta, file_role=file_role)
            findings.append(finding)
            _append_finding(result, finding)

    result.summary_decision = _summarize_decision([item.decision for item in findings])
    return result


def _dispatch_contextual_api(
    api: str,
    call_meta: dict[str, Any],
    *,
    file_role: str | None,
) -> ContextCallFinding:
    if _is_network_api(api):
        return analyze_network_call(api, call_meta, file_role=file_role)
    if _is_command_exec_api(api):
        return ContextCallFinding(
            api=api,
            category="command_exec",
            decision=BLOCK,
            reason_code="COMMAND_EXEC_BLOCK",
            evidence=["command_exec_api_should_not_be_contextual_safe"],
        )
    if _is_file_mutation_api(api):
        return analyze_file_mutation_call(api, call_meta, file_role=file_role)
    if api == "open" or api.endswith(".open") or api.endswith(".read_text") or api.endswith(".read_bytes"):
        return analyze_path_call(api, call_meta, file_role=file_role) if api != "open" else analyze_open_call(
            api, call_meta, file_role=file_role
        )
    if api.startswith("os."):
        return analyze_os_call(api, call_meta, file_role=file_role)
    if api.startswith("Path.") or api.startswith("pathlib.Path."):
        return analyze_path_call(api, call_meta, file_role=file_role)
    return ContextCallFinding(
        api=api,
        category="contextual",
        decision=REVIEW,
        reason_code="CONTEXTUAL_API_REVIEW_UNKNOWN",
        evidence=["contextual_api_without_specific_handler"],
    )


def _append_finding(result: ContextApiScanResult, finding: ContextCallFinding) -> None:
    if finding.category == "open":
        result.open_calls.append(finding)
    elif finding.category == "path_helper":
        result.path_helper_calls.append(finding)
    elif finding.category == "env_access":
        result.env_access_calls.append(finding)
    elif finding.category == "file_mutation":
        result.file_mutation_calls.append(finding)
    elif finding.category == "network":
        result.network_calls.append(finding)
    elif finding.category == "command_exec":
        result.command_exec_calls.append(finding)

    if finding.api.startswith("os."):
        result.os_calls.append(finding)


def _summarize_decision(decisions: list[str]) -> str:
    if not decisions:
        return SAFE
    return max(decisions, key=lambda item: _DECISION_PRIORITY.get(item, -1))


def _extract_api_name(meta: dict[str, Any]) -> str:
    if not isinstance(meta, dict):
        return ""
    for key in ("api", "resolved_api", "call_api"):
        value = meta.get(key)
        if isinstance(value, str) and value:
            return value
    return ""


def _extract_args(meta: dict[str, Any]) -> list[Any]:
    value = meta.get("args", [])
    if isinstance(value, list):
        return value
    return []


def _extract_kwargs(meta: dict[str, Any]) -> dict[str, Any]:
    value = meta.get("kwargs", {})
    if isinstance(value, dict):
        return value
    return {}


def _extract_argument(meta: dict[str, Any], index: int) -> dict[str, Any]:
    args = _extract_args(meta)
    if 0 <= index < len(args):
        return _normalize_arg(args[index])
    return _unknown_arg("missing")


def _extract_mode_arg(api: str, meta: dict[str, Any]) -> dict[str, Any]:
    kwargs = _extract_kwargs(meta)
    if "mode" in kwargs:
        return _normalize_arg(kwargs["mode"])

    mode_index = 1 if api == "open" else 0
    args = _extract_args(meta)
    if mode_index < len(args):
        return _normalize_arg(args[mode_index])

    return _normalize_arg({"kind": "constant_str", "value": "r"})


def _extract_path_arg(api: str, meta: dict[str, Any]) -> dict[str, Any]:
    if api.startswith("Path.") or api.startswith("pathlib.Path."):
        if "path_arg" in meta:
            return _normalize_arg(meta["path_arg"])
        if "receiver" in meta:
            return _normalize_arg(meta["receiver"])
    return _extract_argument(meta, 0)


def _normalize_arg(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        kind = str(value.get("kind", "")).strip().lower()
        raw_value = value.get("value")
        display = value.get("repr")
        if not isinstance(display, str):
            display = str(raw_value) if raw_value is not None else "unknown"
        source = str(value.get("source", "")).strip().lower()
        is_constant = bool(value.get("is_constant"))
        if not is_constant and kind in {"constant", "constant_str", "literal", "str"}:
            is_constant = isinstance(raw_value, str)
        is_user_input = bool(value.get("is_user_input")) or source in {
            "user_input",
            "request",
            "stdin",
            "cli",
            "external_input",
            "function_arg",
        }
        if raw_value is None and isinstance(value.get("literal"), str):
            raw_value = value["literal"]
            is_constant = True
            display = value["literal"]
        return {
            "value": raw_value if isinstance(raw_value, str) else "",
            "display": display,
            "is_constant": is_constant and isinstance(raw_value, str),
            "is_user_input": is_user_input,
            "source": source or "unknown",
        }

    if isinstance(value, str):
        return {
            "value": value,
            "display": value,
            "is_constant": True,
            "is_user_input": False,
            "source": "literal",
        }

    return _unknown_arg("unknown")


def _unknown_arg(source: str) -> dict[str, Any]:
    return {
        "value": "",
        "display": "unknown",
        "is_constant": False,
        "is_user_input": False,
        "source": source,
    }


def _is_write_mode(mode: str) -> bool:
    normalized = mode.lower().strip()
    return any(flag in normalized for flag in _WRITE_MODE_FLAGS)


def _is_resource_path(path_value: str) -> bool:
    normalized = path_value.replace("\\", "/").strip().lower()
    if not normalized:
        return False
    leaf = normalized.rsplit("/", 1)[-1]
    if leaf in _RESOURCE_FILE_NAMES:
        return True
    if leaf.endswith((".json", ".txt", ".model", ".vocab")):
        return any(keyword in leaf for keyword in _RESOURCE_HINT_KEYWORDS)
    return False


def _is_suspicious_path(path_value: str) -> bool:
    normalized = path_value.replace("\\", "/").strip().lower()
    if not normalized:
        return True
    if normalized.startswith(("/", "~/")):
        return True
    if len(normalized) > 1 and normalized[1] == ":":
        return True
    return ".." in normalized.split("/")


def _is_preprocess_context(file_role: str | None, call_meta: dict[str, Any]) -> bool:
    role = _normalize_role(file_role)
    if role == "PREPROCESSING":
        return True

    repo_path = str(call_meta.get("repo_path", "")).replace("\\", "/").lower()
    return repo_path.startswith("tokenization_") or repo_path.startswith("processing_") or repo_path.startswith(
        "image_processing_"
    ) or repo_path.startswith("video_processing_") or repo_path.startswith("feature_extraction_")


def _normalize_role(file_role: str | Any | None) -> str:
    if file_role is None:
        return ""
    if hasattr(file_role, "value"):
        return str(getattr(file_role, "value", "")).upper()
    return str(file_role).upper()


def _analyze_path_read_call(
    api: str,
    call_meta: dict[str, Any] | None,
    *,
    file_role: str | None,
) -> ContextCallFinding:
    meta = call_meta or {}
    path_arg = _extract_path_arg(api, meta)
    evidence = [
        f"path={path_arg['display']}",
        f"path_constant={path_arg['is_constant']}",
        f"path_user_input={path_arg['is_user_input']}",
        "path_read_call",
    ]

    if path_arg["is_user_input"]:
        return ContextCallFinding(
            api=api,
            category="open",
            decision=REVIEW,
            reason_code="PATH_READ_USER_INPUT_REVIEW",
            evidence=evidence,
        )

    if not path_arg["is_constant"]:
        return ContextCallFinding(
            api=api,
            category="open",
            decision=REVIEW,
            reason_code="PATH_READ_DYNAMIC_REVIEW",
            evidence=evidence,
        )

    path_value = path_arg["value"]
    if _is_suspicious_path(path_value):
        return ContextCallFinding(
            api=api,
            category="open",
            decision=REVIEW,
            reason_code="PATH_READ_SUSPICIOUS_PATH_REVIEW",
            evidence=evidence,
        )

    if _is_resource_path(path_value) and _is_preprocess_context(file_role=file_role, call_meta=meta):
        return ContextCallFinding(
            api=api,
            category="open",
            decision=SAFE,
            reason_code="PATH_READ_RESOURCE_SAFE",
            evidence=evidence,
        )

    return ContextCallFinding(
        api=api,
        category="open",
        decision=REVIEW,
        reason_code="PATH_READ_REVIEW",
        evidence=evidence,
    )


def _analyze_path_helper_call(
    api: str,
    call_meta: dict[str, Any] | None,
    *,
    file_role: str | None,
) -> ContextCallFinding:
    del file_role
    meta = call_meta or {}
    args = [_normalize_arg(item) for item in _extract_args(meta)]
    has_user_input = any(item["is_user_input"] for item in args)
    all_constant = bool(args) and all(item["is_constant"] for item in args)
    evidence = [
        f"arg_count={len(args)}",
        f"all_constant={all_constant}",
        f"has_user_input={has_user_input}",
    ]

    if has_user_input:
        return ContextCallFinding(
            api=api,
            category="path_helper",
            decision=REVIEW,
            reason_code="PATH_HELPER_USER_INPUT_REVIEW",
            evidence=evidence,
        )

    if all_constant:
        return ContextCallFinding(
            api=api,
            category="path_helper",
            decision=SAFE,
            reason_code="PATH_HELPER_CONSTANT_SAFE",
            evidence=evidence,
        )

    return ContextCallFinding(
        api=api,
        category="path_helper",
        decision=REVIEW,
        reason_code="PATH_HELPER_DYNAMIC_REVIEW",
        evidence=evidence,
    )


def _extract_usage_tags(meta: dict[str, Any]) -> set[str]:
    usage_tags: set[str] = set()
    raw_tags = meta.get("usage_tags", [])
    if isinstance(raw_tags, list):
        for item in raw_tags:
            if isinstance(item, str) and item:
                usage_tags.add(item.strip().lower())

    if meta.get("uses_as_path"):
        usage_tags.add("path")
    if meta.get("uses_as_token"):
        usage_tags.add("token")
    if meta.get("uses_as_network"):
        usage_tags.add("network")
    return usage_tags


def _is_network_api(api: str) -> bool:
    return api.startswith(_NETWORK_PREFIXES)


def _is_command_exec_api(api: str) -> bool:
    if api in _COMMAND_EXEC_APIS:
        return True
    return api.startswith(_PROCESS_PREFIXES)


def _is_path_mutation_api(api: str) -> bool:
    return api.endswith(_PATH_MUTATION_SUFFIXES)


def _is_file_mutation_api(api: str) -> bool:
    return api in _OS_FILE_MUTATION_APIS or _is_path_mutation_api(api)
