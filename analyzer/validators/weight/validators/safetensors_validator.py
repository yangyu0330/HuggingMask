from __future__ import annotations

from safetensors import safe_open

from analyzer.validators.weight.hashing import sha256_file
from analyzer.validators.weight.reporting import make_tensor_entry

ALLOWED_DTYPES = {
    "torch.float16",
    "torch.float32",
    "torch.float64",
    "torch.bfloat16",
    "torch.int8",
    "torch.int16",
    "torch.int32",
    "torch.int64",
    "torch.uint8",
    "torch.bool",
}

MAX_RANK = 8
MAX_DIM_SIZE = 100000


def validate_safetensors(path: str, expected_sha256: str | None = None) -> dict:
    file_hash = sha256_file(path)

    if expected_sha256 and expected_sha256 != file_hash:
        return {
            "status": "BLOCK",
            "reason_code": "SAFE_TENSORS_HASH_MISMATCH",
            "reason": "downloaded file hash does not match expected source hash",
            "sha256": file_hash,
            "expected_sha256": expected_sha256,
        }

    try:
        tensor_info = {}
        metadata = {}

        with safe_open(path, framework="pt") as f:
            metadata = f.metadata() or {}
            keys = list(f.keys())

            if not keys:
                return {
                    "status": "BLOCK",
                    "reason_code": "SAFE_TENSORS_METADATA_INVALID",
                    "reason": "NO_TENSORS_FOUND",
                }

            for key in keys:
                if not isinstance(key, str) or not key.strip():
                    return {
                        "status": "BLOCK",
                        "reason_code": "SAFE_TENSORS_METADATA_INVALID",
                        "reason": "INVALID_TENSOR_NAME",
                        "tensor": str(key),
                    }

                tensor = f.get_tensor(key)
                shape = list(tensor.shape)
                dtype = str(tensor.dtype)

                if dtype not in ALLOWED_DTYPES:
                    return {
                        "status": "BLOCK",
                        "reason_code": "SAFE_TENSORS_METADATA_INVALID",
                        "reason": "INVALID_DTYPE",
                        "tensor": key,
                        "dtype": dtype,
                    }

                if len(shape) > MAX_RANK:
                    return {
                        "status": "BLOCK",
                        "reason_code": "SAFE_TENSORS_METADATA_INVALID",
                        "reason": "INVALID_RANK",
                        "tensor": key,
                        "shape": shape,
                    }

                for dim in shape:
                    if dim < 0:
                        return {
                            "status": "BLOCK",
                            "reason_code": "SAFE_TENSORS_METADATA_INVALID",
                            "reason": "NEGATIVE_DIMENSION",
                            "tensor": key,
                            "shape": shape,
                        }
                    if dim > MAX_DIM_SIZE:
                        return {
                            "status": "BLOCK",
                            "reason_code": "SAFE_TENSORS_METADATA_INVALID",
                            "reason": "DIMENSION_TOO_LARGE",
                            "tensor": key,
                            "shape": shape,
                        }

                tensor_info[key] = make_tensor_entry(tensor)

        return {
            "status": "PASS",
            "reason_code": "SAFE_TENSORS_HASH_OK",
            "reason": "SAFE_TENSORS_VALID",
            "sha256": file_hash,
            "metadata": metadata,
            "tensors": tensor_info,
        }

    except Exception as e:
        return {
            "status": "BLOCK",
            "reason_code": "SAFE_TENSORS_METADATA_INVALID",
            "reason": f"SAFE_TENSORS_PARSE_ERROR: {e}",
            "sha256": file_hash,
        }