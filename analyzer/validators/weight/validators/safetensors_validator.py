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
# 단일 텐서 총 원소수 상한. 각 차원이 MAX_DIM_SIZE 이하여도 곱(예:
# [100000, 100000] = 1e10)이 거대하면 get_tensor가 전체를 메모리에 올리며
# 검증 호스트를 OOM시킬 수 있다(적대검증 2026-06-08 MED). 실제 거대 모델의
# 단일 텐서도 ~5e9(예: lm_head [vocab, hidden]) 수준이라 1e10이면 정상은 통과,
# 악의적 헤더(1e10 초과)는 materialize 전에 차단한다.
MAX_TOTAL_ELEMENTS = 10**10


def _oversized_tensor_block(f, key: str) -> dict | None:
    """get_tensor(materialize) 전에 헤더 shape만으로 총 원소수를 확인한다.

    get_slice는 데이터를 로드하지 않고 shape만 읽으므로 DoS를 예방한다.
    get_slice를 지원하지 않는 환경에서는 None을 반환해 기존 경로로 진행한다
    (최선 노력 — 기존 동작보다 나빠지지 않는다)."""
    try:
        shape = list(f.get_slice(key).get_shape())
    except Exception:
        return None
    total = 1
    for dim in shape:
        if not isinstance(dim, int) or dim < 0:
            return None  # 음수/이상 차원은 기존 NEGATIVE_DIMENSION 체크가 처리
        total *= dim
    if total > MAX_TOTAL_ELEMENTS:
        return {
            "status": "BLOCK",
            "reason_code": "SAFE_TENSORS_METADATA_INVALID",
            "reason": "TENSOR_TOO_LARGE",
            "tensor": key,
            "shape": shape,
            "total_elements": total,
        }
    return None


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

                oversized = _oversized_tensor_block(f, key)
                if oversized is not None:
                    return oversized

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