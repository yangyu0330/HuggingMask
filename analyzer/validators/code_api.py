"""Stage-5 API path resolution and policy classification.

This module consumes stage-4 AST scan output and classifies API calls into
allowed/blocked/contextual/unregistered groups using fixed policy order.
It does not import or execute model code and does not run context safe/review/
block decisions yet.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from analyzer.validators.code_api_policy import (
    ApiPolicy,
    WhitelistLookup,
    build_in_memory_whitelist_lookup,
    default_api_policy,
    is_blocked_by_policy,
    is_contextual_api,
    is_risk_category_api,
)

_BUILTIN_RESOLVED_CALLS = {
    "open",
    "eval",
    "exec",
    "compile",
    "__import__",
    "getattr",
    "setattr",
    "delattr",
    "globals",
    "locals",
    "type",
}


@dataclass
class ApiScanResult:
    used_apis: list[str] = field(default_factory=list)
    allowed_apis: list[str] = field(default_factory=list)
    blocked_apis: list[str] = field(default_factory=list)
    contextual_apis: list[str] = field(default_factory=list)
    unregistered_apis: list[str] = field(default_factory=list)
    alias_resolution: dict[str, str] = field(default_factory=dict)
    pending_api_refs: list[str] = field(default_factory=list)
    policy_version: str = ""
    whitelist_version: str = ""
    blocked_reason_by_api: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "used_apis": list(self.used_apis),
            "allowed_apis": list(self.allowed_apis),
            "blocked_apis": list(self.blocked_apis),
            "contextual_apis": list(self.contextual_apis),
            "unregistered_apis": list(self.unregistered_apis),
            "alias_resolution": dict(self.alias_resolution),
            "pending_api_refs": list(self.pending_api_refs),
            "policy_version": self.policy_version,
            "whitelist_version": self.whitelist_version,
            "blocked_reason_by_api": dict(self.blocked_reason_by_api),
        }


def scan_api_policy(
    ast_scan: Any,
    *,
    policy: ApiPolicy | None = None,
    whitelist_lookup: WhitelistLookup | None = None,
) -> ApiScanResult:
    """Resolve API paths from AST scan output and classify them by policy.

    Policy order is fixed:
    1) unresolved call target + dynamic/obfuscation pattern
    2) blocked exact/prefix
    3) risk category
    4) contextual exact/prefix
    5) allowed exact
    6) unregistered
    """

    policy = policy or default_api_policy()
    lookup = whitelist_lookup or build_in_memory_whitelist_lookup(
        allowed_exact=policy.allowed_exact,
    )

    imports = sorted(set(_list_field(ast_scan, "imports")))
    raw_api_calls = sorted(set(_list_field(ast_scan, "raw_api_calls")))
    contextual_candidates = sorted(set(_list_field(ast_scan, "contextual_api_candidates")))
    dynamic_patterns = _list_field(ast_scan, "dynamic_patterns")
    obfuscation_patterns = _list_field(ast_scan, "obfuscation_patterns")
    has_dynamic_or_obfuscated_pattern = bool(dynamic_patterns or obfuscation_patterns)

    alias_map = _build_alias_map(
        imports=imports,
        raw_api_calls=raw_api_calls,
        contextual_candidates=contextual_candidates,
    )

    alias_resolution: dict[str, str] = {}
    unresolved_apis: set[str] = set()
    used_apis: set[str] = set()
    for raw in raw_api_calls:
        resolved, resolved_ok = _resolve_api_call(raw, alias_map=alias_map, imports=imports)
        alias_resolution[raw] = resolved
        used_apis.add(resolved)
        if not resolved_ok:
            unresolved_apis.add(resolved)

    # Keep contextual candidates visible even if stage-4 extraction and raw calls
    # diverge in future revisions.
    for candidate in contextual_candidates:
        resolved, _ = _resolve_api_call(candidate, alias_map=alias_map, imports=imports)
        used_apis.add(resolved)

    allowed: set[str] = set()
    blocked: set[str] = set()
    contextual: set[str] = set()
    unregistered: set[str] = set()
    pending_api_refs: set[str] = set()
    blocked_reason_by_api: dict[str, str] = {}

    for api in sorted(used_apis):
        # 1) unresolved + dynamic/obfuscation
        if api in unresolved_apis and has_dynamic_or_obfuscated_pattern:
            blocked.add(api)
            blocked_reason_by_api.setdefault(api, "UNRESOLVED_WITH_DYNAMIC_OR_OBFUSCATION")
            continue

        # 2) blocked exact/prefix
        if is_blocked_by_policy(api, policy):
            blocked.add(api)
            blocked_reason_by_api.setdefault(api, "BLOCKED_BY_POLICY")
            continue

        # 3) risk category
        if is_risk_category_api(api, policy):
            blocked.add(api)
            blocked_reason_by_api.setdefault(api, "RISK_CATEGORY_BLOCK")
            continue

        # 4) contextual exact/prefix (no safe/review/block decision in stage-5)
        if is_contextual_api(api, policy):
            contextual.add(api)
            continue

        # 5) allowed exact
        if lookup.is_allowed_exact(api):
            allowed.add(api)
            continue

        # 6) unregistered
        unregistered.add(api)
        pending_api_refs.add(api)

    return ApiScanResult(
        used_apis=sorted(used_apis),
        allowed_apis=sorted(allowed),
        blocked_apis=sorted(blocked),
        contextual_apis=sorted(contextual),
        unregistered_apis=sorted(unregistered),
        alias_resolution=alias_resolution,
        pending_api_refs=sorted(pending_api_refs),
        policy_version=policy.policy_version,
        whitelist_version=lookup.whitelist_version,
        blocked_reason_by_api=blocked_reason_by_api,
    )


def _list_field(payload: Any, field_name: str) -> list[str]:
    if isinstance(payload, dict):
        value = payload.get(field_name, [])
    else:
        value = getattr(payload, field_name, [])
    if value is None:
        return []
    return [str(item) for item in value if item is not None]


def _build_alias_map(
    *,
    imports: list[str],
    raw_api_calls: list[str],
    contextual_candidates: list[str],
) -> dict[str, str]:
    alias_map: dict[str, str] = {}
    import_roots = {item.split(".", 1)[0] for item in imports}
    for root in sorted(import_roots):
        alias_map[root] = root

    imported = set(imports)
    if "numpy" in imported:
        alias_map.setdefault("np", "numpy")
    if "pickle" in imported:
        alias_map.setdefault("pkl", "pickle")
    if "pathlib" in imported:
        alias_map.setdefault("Path", "pathlib.Path")
    if "torch" in imported:
        alias_map.setdefault("nn", "torch.nn")
        alias_map.setdefault("F", "torch.nn.functional")

    for module_path in imports:
        leaf = module_path.rsplit(".", 1)[-1]
        if leaf == "functional":
            alias_map.setdefault("F", module_path)
        if leaf == "nn":
            alias_map.setdefault("nn", module_path)
        if module_path == "os":
            alias_map.setdefault("os", "os")

    for root in _all_roots(raw_api_calls + contextual_candidates):
        if root in alias_map:
            continue
        if root in import_roots:
            alias_map[root] = root
            continue

        # Heuristic: "F" -> "*functional", only when unambiguous.
        if root == "F":
            functional_matches = [item for item in imports if item.endswith(".functional")]
            if len(functional_matches) == 1:
                alias_map[root] = functional_matches[0]
                continue

        # Heuristic: one-letter alias uses a unique imported module with same
        # initial letter in its tail name.
        if len(root) == 1 and root.isalpha():
            initial_matches = [
                item
                for item in imports
                if item.rsplit(".", 1)[-1].lower().startswith(root.lower())
            ]
            if len(initial_matches) == 1:
                alias_map[root] = initial_matches[0]
                continue

        # Heuristic: exact tail match.
        tail_matches = [item for item in imports if item.rsplit(".", 1)[-1] == root]
        if len(tail_matches) == 1:
            alias_map[root] = tail_matches[0]

    return alias_map


def _all_roots(calls: list[str]) -> set[str]:
    roots: set[str] = set()
    for call in calls:
        call = call.strip()
        if not call:
            continue
        roots.add(call.split(".", 1)[0])
    return roots


def _resolve_api_call(
    call_name: str,
    *,
    alias_map: dict[str, str],
    imports: list[str],
) -> tuple[str, bool]:
    normalized = call_name.strip()
    if not normalized:
        return "", False

    if "." not in normalized:
        if normalized in alias_map:
            return alias_map[normalized], True
        if normalized in _BUILTIN_RESOLVED_CALLS:
            return normalized, True
        return normalized, False

    root, rest = normalized.split(".", 1)
    if root in alias_map:
        return f"{alias_map[root]}.{rest}", True

    import_roots = {item.split(".", 1)[0] for item in imports}
    if root in import_roots:
        return normalized, True

    return normalized, False
