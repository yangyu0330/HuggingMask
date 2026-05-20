from __future__ import annotations


def compare_tensor_reports(path_a_result: dict, path_b_result: dict) -> dict:
    mismatches = []

    a_keys = set(path_a_result.keys())
    b_keys = set(path_b_result.keys())

    for key in sorted(a_keys - b_keys):
        mismatches.append(
            {
                "key": key,
                "reason": "MISSING_IN_B",
            }
        )

    for key in sorted(b_keys - a_keys):
        mismatches.append(
            {
                "key": key,
                "reason": "MISSING_IN_A",
            }
        )

    for key in sorted(a_keys & b_keys):
        a = path_a_result[key]
        b = path_b_result[key]

        if a.get("shape") != b.get("shape"):
            mismatches.append(
                {
                    "key": key,
                    "reason": "SHAPE_MISMATCH",
                    "shape_a": a.get("shape"),
                    "shape_b": b.get("shape"),
                }
            )
            continue

        if a.get("dtype") != b.get("dtype"):
            mismatches.append(
                {
                    "key": key,
                    "reason": "DTYPE_MISMATCH",
                    "dtype_a": a.get("dtype"),
                    "dtype_b": b.get("dtype"),
                }
            )
            continue

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
            "reason_code": "PICKLE_PATH_AB_MISMATCH",
            "reason": "Path A and Path B tensor reports do not match",
            "details": mismatches,
        }

    return {
        "status": "MATCH",
        "reason_code": "PICKLE_PATH_AB_MATCH",
        "reason": "Path A and Path B tensor reports match by key, shape, dtype, and hash",
        "details": [],
    }