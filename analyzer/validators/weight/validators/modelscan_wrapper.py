from __future__ import annotations

try:
    from modelscan import ModelScan
except Exception:
    ModelScan = None


def scan_with_modelscan(path: str) -> dict:
    if ModelScan is None:
        return {
            "status": "SKIP",
            "reason_code": "MODELSCAN_UNAVAILABLE",
            "reason": "modelscan is not installed in this environment",
        }

    try:
        scanner = ModelScan()
        results = scanner.scan(path)
        issues = getattr(results, "issues", None) or []

        if issues:
            return {
                "status": "BLOCK",
                "reason_code": "PICKLE_MODELSCAN_BLOCKED",
                "reason": "modelscan detected suspicious content",
                "issues": [str(x) for x in issues],
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