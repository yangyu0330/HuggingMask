from __future__ import annotations

import hashlib
import json
import os
import sys

import torch

try:
    from dtypes import DTYPE_MAP
except ImportError:
    from analyzer.validators.weight.dtypes import DTYPE_MAP


RESULT_PREFIX = "HM_SANDBOX_RESULT"


def _tensor_raw_bytes(tensor) -> bytes:
    tensor = tensor.detach().cpu().contiguous()

    try:
        return tensor.numpy().tobytes()
    except (TypeError, RuntimeError):
        return tensor.view(torch.uint8).numpy().tobytes()


def tensor_entry(tensor) -> dict:
    tensor_bytes = _tensor_raw_bytes(tensor)

    return {
        "hash": hashlib.sha256(tensor_bytes).hexdigest(),
        "shape": list(tensor.shape),
        "dtype": str(tensor.dtype),
    }


def schema_to_tensor_dict(obj: dict) -> dict:
    raw = obj.get("__tensor_dict__")
    if not isinstance(raw, dict):
        raise ValueError("missing __tensor_dict__")

    tensor_dict = {}

    for name, spec in raw.items():
        dtype_name = spec["dtype"]
        shape = spec["shape"]
        data = spec["data"]

        if dtype_name not in DTYPE_MAP:
            raise ValueError(f"unsupported dtype: {dtype_name}")

        tensor = torch.tensor(data, dtype=DTYPE_MAP[dtype_name]).reshape(shape)
        tensor_dict[name] = tensor

    return tensor_dict


def load_torch_weights_only(path: str):
    # 보안 정책:
    # Path B sandbox 내부에서도 사용자 pickle reducer 실행을 허용하지 않는다.
    # weights_only=False와 pickle.load fallback은 RCE 가능성이 있으므로 사용하지 않는다.
    return torch.load(path, map_location="cpu", weights_only=True)


def emit_result(payload: dict) -> None:
    nonce = os.getenv("HM_SANDBOX_NONCE", "")
    text = json.dumps(payload, sort_keys=True)

    if nonce:
        print(f"{RESULT_PREFIX}:{nonce}:{text}", flush=True)
    else:
        print(text, flush=True)


def main() -> None:
    if len(sys.argv) != 2:
        emit_result(
            {
                "status": "BLOCK",
                "reason_code": "PICKLE_PATH_B_INVALID_ARGUMENT",
                "reason": "usage: load_and_extract.py <pickle_path>",
            }
        )
        return

    path = sys.argv[1]

    try:
        obj = load_torch_weights_only(path)

        if isinstance(obj, dict) and "__tensor_dict__" in obj:
            tensor_dict = schema_to_tensor_dict(obj)

        elif isinstance(obj, dict):
            tensor_dict = {
                k: v
                for k, v in obj.items()
                if isinstance(k, str) and torch.is_tensor(v)
            }

        else:
            emit_result(
                {
                    "status": "BLOCK",
                    "reason_code": "PICKLE_PATH_B_UNSUPPORTED_OBJECT",
                    "reason": f"unsupported object type: {type(obj).__name__}",
                }
            )
            return

        tensors = {
            name: tensor_entry(tensor)
            for name, tensor in tensor_dict.items()
        }

        emit_result(
            {
                "status": "PASS",
                "reason_code": "PICKLE_PATH_B_LOAD_OK",
                "reason": "sandbox loaded weights_only artifact and extracted tensor report",
                "tensors": tensors,
            }
        )

    except Exception as e:
        emit_result(
            {
                "status": "BLOCK",
                "reason_code": "PICKLE_PATH_B_EXECUTION_FAILED",
                "reason": str(e),
            }
        )


if __name__ == "__main__":
    main()