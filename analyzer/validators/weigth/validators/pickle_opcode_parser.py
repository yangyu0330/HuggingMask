from __future__ import annotations

import pickletools
from typing import Any

import torch

from analyzer.validators.weigth.reporting import make_tensor_entry


ALLOWED_OPCODES = {
    "PROTO",
    "FRAME",
    "STOP",
    "EMPTY_DICT",
    "DICT",
    "SETITEM",
    "SETITEMS",
    "EMPTY_LIST",
    "LIST",
    "APPEND",
    "APPENDS",
    "EMPTY_TUPLE",
    "TUPLE",
    "TUPLE1",
    "TUPLE2",
    "TUPLE3",
    "MARK",
    "POP",
    "POP_MARK",
    "DUP",
    "NONE",
    "NEWTRUE",
    "NEWFALSE",
    "BINUNICODE",
    "SHORT_BINUNICODE",
    "BINUNICODE8",
    "BININT",
    "BININT1",
    "BININT2",
    "BINFLOAT",
    "LONG1",
    "BINBYTES",
    "SHORT_BINBYTES",
    "BINBYTES8",
    "BINPUT",
    "LONG_BINPUT",
    "BINGET",
    "LONG_BINGET",
    "MEMOIZE",
}


BLOCKED_EXECUTION_OPCODES = {
    "GLOBAL",
    "STACK_GLOBAL",
    "REDUCE",
    "BUILD",
    "INST",
    "OBJ",
    "NEWOBJ",
    "NEWOBJ_EX",
    "EXT1",
    "EXT2",
    "EXT4",
    "PERSID",
    "BINPERSID",
}


_MARK = object()


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


def _find_mark(stack: list[Any]) -> int:
    for i in range(len(stack) - 1, -1, -1):
        if stack[i] is _MARK:
            return i
    raise ValueError("MARK not found")


def _product(shape: list[int]) -> int:
    result = 1
    for dim in shape:
        result *= dim
    return result


def _setitems(target: dict, items: list[Any]) -> None:
    if len(items) % 2 != 0:
        raise ValueError("SETITEMS requires key/value pairs")

    for i in range(0, len(items), 2):
        key = items[i]
        value = items[i + 1]
        target[key] = value


def _reconstruct_safe_object(path: str) -> dict:
    stack: list[Any] = []
    memo: dict[int, Any] = {}
    next_memo_index = 0

    with open(path, "rb") as f:
        for opcode, arg, pos in pickletools.genops(f):
            name = opcode.name

            if name not in ALLOWED_OPCODES:
                return {
                    "status": "BLOCK",
                    "reason_code": "PICKLE_OPCODE_BLOCKED",
                    "reason": "blocked opcode detected",
                    "opcode": name,
                    "position": pos,
                }

            if name in {"PROTO", "FRAME"}:
                continue

            if name == "STOP":
                if not stack:
                    return {
                        "status": "BLOCK",
                        "reason_code": "PICKLE_PARSE_ERROR",
                        "reason": "empty stack at STOP",
                    }
                return {
                    "status": "PASS",
                    "object": stack[-1],
                }

            if name == "MARK":
                stack.append(_MARK)

            elif name == "EMPTY_DICT":
                stack.append({})

            elif name == "EMPTY_LIST":
                stack.append([])

            elif name == "EMPTY_TUPLE":
                stack.append(())

            elif name in {"BINUNICODE", "SHORT_BINUNICODE", "BINUNICODE8"}:
                stack.append(arg)

            elif name in {"BININT", "BININT1", "BININT2"}:
                stack.append(arg)

            elif name == "BINFLOAT":
                stack.append(arg)

            elif name == "LONG1":
                stack.append(int(arg))

            elif name in {"BINBYTES", "SHORT_BINBYTES", "BINBYTES8"}:
                stack.append(arg)

            elif name == "NONE":
                stack.append(None)

            elif name == "NEWTRUE":
                stack.append(True)

            elif name == "NEWFALSE":
                stack.append(False)

            elif name == "SETITEM":
                value = stack.pop()
                key = stack.pop()
                target = stack[-1]
                if not isinstance(target, dict):
                    raise ValueError("SETITEM target is not dict")
                target[key] = value

            elif name == "SETITEMS":
                mark_index = _find_mark(stack)
                items = stack[mark_index + 1:]
                del stack[mark_index:]

                target = stack[-1]
                if not isinstance(target, dict):
                    raise ValueError("SETITEMS target is not dict")

                _setitems(target, items)

            elif name == "APPEND":
                value = stack.pop()
                target = stack[-1]
                if not isinstance(target, list):
                    raise ValueError("APPEND target is not list")
                target.append(value)

            elif name == "APPENDS":
                mark_index = _find_mark(stack)
                items = stack[mark_index + 1:]
                del stack[mark_index:]

                target = stack[-1]
                if not isinstance(target, list):
                    raise ValueError("APPENDS target is not list")
                target.extend(items)

            elif name == "LIST":
                mark_index = _find_mark(stack)
                items = stack[mark_index + 1:]
                del stack[mark_index:]
                stack.append(items)

            elif name == "DICT":
                mark_index = _find_mark(stack)
                items = stack[mark_index + 1:]
                del stack[mark_index:]

                target = {}
                _setitems(target, items)
                stack.append(target)

            elif name == "TUPLE":
                mark_index = _find_mark(stack)
                items = stack[mark_index + 1:]
                del stack[mark_index:]
                stack.append(tuple(items))

            elif name == "TUPLE1":
                a = stack.pop()
                stack.append((a,))

            elif name == "TUPLE2":
                b = stack.pop()
                a = stack.pop()
                stack.append((a, b))

            elif name == "TUPLE3":
                c = stack.pop()
                b = stack.pop()
                a = stack.pop()
                stack.append((a, b, c))

            elif name == "MEMOIZE":
                memo[next_memo_index] = stack[-1]
                next_memo_index += 1

            elif name in {"BINPUT", "LONG_BINPUT"}:
                memo[arg] = stack[-1]

            elif name in {"BINGET", "LONG_BINGET"}:
                stack.append(memo[arg])

            elif name == "POP":
                stack.pop()

            elif name == "POP_MARK":
                mark_index = _find_mark(stack)
                del stack[mark_index:]

            elif name == "DUP":
                stack.append(stack[-1])

    return {
        "status": "BLOCK",
        "reason_code": "PICKLE_PARSE_ERROR",
        "reason": "missing STOP opcode",
    }


def _schema_to_tensor_dict(obj: Any) -> dict:
    if not isinstance(obj, dict):
        raise ValueError("top-level object is not dict")

    if "__tensor_dict__" not in obj:
        raise ValueError("unsupported pickle format: missing __tensor_dict__")

    raw_tensor_dict = obj["__tensor_dict__"]
    if not isinstance(raw_tensor_dict, dict):
        raise ValueError("__tensor_dict__ must be dict")

    tensor_dict = {}

    for name, spec in raw_tensor_dict.items():
        if not isinstance(name, str) or not name.strip():
            raise ValueError("invalid tensor name")

        if not isinstance(spec, dict):
            raise ValueError(f"tensor spec for {name} must be dict")

        dtype_name = spec.get("dtype")
        shape = spec.get("shape")
        data = spec.get("data")

        if dtype_name not in DTYPE_MAP:
            raise ValueError(f"unsupported dtype for {name}: {dtype_name}")

        if not isinstance(shape, list) or not all(isinstance(x, int) for x in shape):
            raise ValueError(f"invalid shape for {name}")

        if not isinstance(data, list):
            raise ValueError(f"invalid data for {name}")

        expected = _product(shape)
        if len(data) != expected:
            raise ValueError(
                f"data length mismatch for {name}: expected {expected}, got {len(data)}"
            )

        tensor = torch.tensor(data, dtype=DTYPE_MAP[dtype_name]).reshape(shape)
        tensor_dict[name] = tensor

    return tensor_dict


def validate_pickle(path: str) -> dict:
    try:
        parsed = _reconstruct_safe_object(path)

        if parsed["status"] == "BLOCK":
            return parsed

        obj = parsed["object"]

        try:
            tensor_dict = _schema_to_tensor_dict(obj)
        except Exception as e:
            return {
                "status": "BLOCK",
                "reason_code": "UNSUPPORTED_PICKLE_FORMAT",
                "reason": str(e),
            }

        tensor_report = {
            name: make_tensor_entry(tensor)
            for name, tensor in tensor_dict.items()
        }

        return {
            "status": "PASS",
            "reason_code": "PICKLE_OPCODE_ALLOWED_ONLY",
            "reason": "pickle passed opcode whitelist and safe tensor schema validation",
            "tensors": tensor_report,
            "tensor_dict": tensor_dict,
        }

    except Exception as e:
        return {
            "status": "BLOCK",
            "reason_code": "PICKLE_PARSE_ERROR",
            "reason": f"PARSE_ERROR: {e}",
        }