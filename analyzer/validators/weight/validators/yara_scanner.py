from __future__ import annotations

from pathlib import Path

try:
    import yara  # type: ignore[import-not-found]
except ImportError:
    yara = None


RULE_PATH = Path(__file__).resolve().parents[3] / "assets" / "malicious_pickle.yar"


def scan_with_yara(path: str) -> dict:
    if yara is None:
        return {
            "status": "SKIP",
            "reason_code": "YARA_UNAVAILABLE",
            "reason": "yara-python is not installed in this environment",
        }

    if not RULE_PATH.exists():
        return {
            "status": "SKIP",
            "reason_code": "YARA_RULE_MISSING",
            "reason": f"rule file not found: {RULE_PATH.as_posix()}",
        }

    try:
        rules = yara.compile(filepath=str(RULE_PATH))
        matches = rules.match(path)

        if matches:
            return {
                "status": "BLOCK",
                "reason_code": "PICKLE_YARA_BLOCKED",
                "reason": "matched yara rule",
                "matches": [m.rule for m in matches],
            }

        return {
            "status": "PASS",
            "reason_code": "YARA_NO_MATCH",
            "reason": "no yara rule matched",
        }

    except yara.Error as e:
        return {
            "status": "SKIP",
            "reason_code": "YARA_SCAN_ERROR",
            "reason": f"yara scan failed: {e}",
        }