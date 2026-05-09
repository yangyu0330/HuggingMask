from __future__ import annotations

import hashlib
import json
import pickle
import sys

import torch


DTYPE_MAP = {
    "float16": torch.float16,
    "float32": torch.float32,
    "float64": torch.float64,
    "bfloat16": torch.bfloat16,
    "int8": torch.int8,
    "int16": torch.int16,
    "int32": torch.int32,
    "int64": torch.int64,
    "uint8": torch.uint8,
    "bool": torch.bool,
    "torch.float16": torch.float16,
    "torch.float32": torch.float32,
    "torch.float64": torch.float64,
    "torch.bfloat16": torch.bfloat16,
    "torch.int8": torch.int8,
    "torch.int16": torch.int16,
    "torch.int32": torch.int32,
    "torch.int64": torch.int64,
    "torch.uint8": torch.uint8,
    "torch.bool": torch.bool,
}


def tensor_entry(tensor) -> dict:
    tensor = tensor.detach().cpu()
    tensor_bytes = tensor.numpy().tobytes()
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


def load_pickle_or_torch(path: str):
    try:
        return torch.load(path, map_location="cpu", weights_only=False)
    except Exception:
        with open(path, "rb") as f:
            return pickle.load(f)


def main() -> None:
    if len(sys.argv) != 2:
        print(
            json.dumps(
                {
                    "status": "BLOCK",
                    "reason_code": "PICKLE_PATH_B_INVALID_ARGUMENT",
                    "reason": "usage: load_and_extract.py <pickle_path>",
                }
            )
        )
        return

    path = sys.argv[1]

    try:
        obj = load_pickle_or_torch(path)

        if isinstance(obj, dict) and "__tensor_dict__" in obj:
            tensor_dict = schema_to_tensor_dict(obj)
        elif isinstance(obj, dict):
            tensor_dict = {
                k: v
                for k, v in obj.items()
                if torch.is_tensor(v)
            }
        else:
            print(
                json.dumps(
                    {
                        "status": "BLOCK",
                        "reason_code": "PICKLE_PATH_B_UNSUPPORTED_OBJECT",
                        "reason": f"unsupported object type: {type(obj).__name__}",
                    }
                )
            )
            return

        tensors = {
            name: tensor_entry(tensor)
            for name, tensor in tensor_dict.items()
        }

        print(
            json.dumps(
                {
                    "status": "PASS",
                    "reason_code": "PICKLE_PATH_B_LOAD_OK",
                    "reason": "sandbox loaded pickle and extracted tensor report",
                    "tensors": tensors,
                }
            )
        )

    except Exception as e:
        print(
            json.dumps(
                {
                    "status": "BLOCK",
                    "reason_code": "PICKLE_PATH_B_EXECUTION_FAILED",
                    "reason": str(e),
                }
            )
        )


if __name__ == "__main__":
    main()