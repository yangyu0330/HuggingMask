from __future__ import annotations

import hashlib

import torch


def _tensor_raw_bytes(tensor) -> bytes:
    tensor = tensor.detach().cpu().contiguous()

    try:
        return tensor.numpy().tobytes()
    except (TypeError, RuntimeError):
        return tensor.view(torch.uint8).numpy().tobytes()


def make_tensor_entry(tensor) -> dict:
    tensor_bytes = _tensor_raw_bytes(tensor)

    return {
        "hash": hashlib.sha256(tensor_bytes).hexdigest(),
        "shape": list(tensor.shape),
        "dtype": str(tensor.dtype),
    }