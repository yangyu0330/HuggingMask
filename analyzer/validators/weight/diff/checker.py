from __future__ import annotations


def compare_tensor_reports(path_a_result: dict, path_b_result: dict) -> dict:
    mismatches = []

    for key in path_a_result:
        if key not in path_b_result:
            mismatches.append(
                {
                    "key": key,
                    "reason": "MISSING_IN_B",
                }
            )
            continue

        a = path_a_result[key]
        b = path_b_result[key]

        if a.get("hash") != b.get("hash"):
            mismatches.append(
                {
                    "key": key,
                    "reason": "HASH_MISMATCH",
                    "hash_a": a.get("hash"),
                    "hash_b": b.get("hash"),
                }
            )

    if mismatches:
        return {
            "status": "MISMATCH",
            "details": mismatches,
        }

    return {
        "status": "MATCH",
        "details": [],
    }