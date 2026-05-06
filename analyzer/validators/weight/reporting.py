from __future__ import annotations

import hashlib


def make_tensor_entry(tensor) -> dict:
    tensor_bytes = tensor.numpy().tobytes()
    return {
        "hash": hashlib.sha256(tensor_bytes).hexdigest(),
        "shape": list(tensor.shape),
        "dtype": str(tensor.dtype),
    }