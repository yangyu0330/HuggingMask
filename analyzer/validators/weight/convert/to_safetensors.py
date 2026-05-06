from __future__ import annotations

from pathlib import Path

from safetensors.torch import save_file

from analyzer.validators.weight.hashing import sha256_file


def convert_tensor_dict_to_safetensors(
    tensor_dict: dict,
    output_path: str,
    policy_version: str | None = None,
) -> dict:
    try:
        if not tensor_dict:
            return {
                "status": "BLOCK",
                "reason_code": "PICKLE_CONVERT_FAILED",
                "reason": "tensor_dict is empty",
            }

        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)

        save_file(tensor_dict, str(out))
        new_hash = sha256_file(str(out))

        return {
            "status": "PASS",
            "reason_code": "PICKLE_CONVERT_OK",
            "reason": "converted Path A tensor_dict to safetensors",
            "output_path": out.as_posix(),
            "sha256": new_hash,
            "policy_version": policy_version,
        }

    except Exception as e:
        return {
            "status": "BLOCK",
            "reason_code": "PICKLE_CONVERT_FAILED",
            "reason": f"CONVERSION_ERROR: {e}",
        }