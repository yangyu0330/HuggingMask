from __future__ import annotations

from importlib import import_module
from typing import Any


def _load_modelscan():
    try:
        module = import_module("modelscan")
    except ImportError:
        return None

    return getattr(module, "ModelScan", None)


def _get_value(obj: Any, name: str):
    if isinstance(obj, dict):
        return obj.get(name)

    return getattr(obj, name, None)


def _normalize_issue(issue: Any) -> dict:
    severity = _get_value(issue, "severity") or _get_value(issue, "level") or "UNKNOWN"
    category = _get_value(issue, "category") or _get_value(issue, "type") or "UNKNOWN"
    message = (
        _get_value(issue, "message")
        or _get_value(issue, "description")
        or _get_value(issue, "reason")
        or str(issue)
    )

    return {
        "severity": str(severity),
        "category": str(category),
        "message": str(message),
    }


def _extract_issues(results: Any) -> list[dict]:
    candidates = []

    if isinstance(results, dict):
        for key in ("issues", "findings", "alerts", "errors"):
            value = results.get(key)
            if value:
                candidates.extend(value)
    else:
        for key in ("issues", "findings", "alerts", "errors"):
            value = getattr(results, key, None)
            if value:
                candidates.extend(value)

    return [_normalize_issue(issue) for issue in candidates]


def scan_with_modelscan(path: str) -> dict:
    ModelScan = _load_modelscan()

    if ModelScan is None:
        return {
            "status": "SKIP",
            "reason_code": "MODELSCAN_UNAVAILABLE",
            "reason": "modelscan is not installed in this environment",
        }

    try:
        scanner = ModelScan()
        results = scanner.scan(path)
        issues = _extract_issues(results)

        if issues:
            severities = {
                issue.get("severity", "UNKNOWN").upper()
                for issue in issues
            }

            return {
                "status": "BLOCK",
                "reason_code": "PICKLE_MODELSCAN_BLOCKED",
                "reason": "modelscan detected suspicious content",
                "severities": sorted(severities),
                "issues": issues,
            }

        return {
            "status": "PASS",
            "reason_code": "MODELSCAN_NO_ISSUE",
            "reason": "modelscan found no issue",
        }

    except Exception as e:
        return {
            "status": "SKIP",
            "reason_code": "MODELSCAN_SCAN_ERROR",
            "reason": f"modelscan failed: {e}",
        }