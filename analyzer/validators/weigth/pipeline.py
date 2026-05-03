from __future__ import annotations

from pathlib import Path
from typing import Any

from analyzer.utils import build_cache_key
from analyzer.validators.weigth.hashing import sha256_file
from analyzer.validators.weigth.validators.pickle_opcode_parser import validate_pickle
from analyzer.validators.weigth.validators.safetensors_validator import validate_safetensors
from analyzer.validators.weigth.validators.yara_scanner import scan_with_yara
from analyzer.validators.weigth.validators.modelscan_wrapper import scan_with_modelscan
from analyzer.validators.weigth.cache import get_cache, set_cache
from analyzer.validators.weigth.sandbox.docker_runner import run_in_docker
from analyzer.validators.weigth.diff.checker import compare_tensor_reports
from analyzer.validators.weigth.convert.to_safetensors import convert_tensor_dict_to_safetensors


def _make_cacheable(obj: Any):
    if isinstance(obj, dict):
        cleaned = {}
        for k, v in obj.items():
            if k == "tensor_dict":
                continue
            cleaned[k] = _make_cacheable(v)
        return cleaned

    if isinstance(obj, list):
        return [_make_cacheable(x) for x in obj]

    return obj


def validate_pickle_pipeline(
    path: str,
    policy_fingerprint: str,
    sandbox_image: str = "weight-sandbox",
    enable_path_b: bool = False,
    runtime: str = "runc",
) -> dict:
    file_hash = sha256_file(path)
    cache_key = build_cache_key(file_hash, "PICKLE", policy_fingerprint)

    cached = get_cache(cache_key)
    if cached:
        cached["cached"] = True
        cached["cache_key"] = cache_key
        return cached

    yara_result = scan_with_yara(path)
    if yara_result["status"] == "BLOCK":
        result = {
            "status": "BLOCK",
            "stage": "YARA",
            "cache_key": cache_key,
            "file_sha256": file_hash,
            **yara_result,
        }
        set_cache(cache_key, _make_cacheable(result))
        return result

    modelscan_result = scan_with_modelscan(path)
    if modelscan_result["status"] == "BLOCK":
        result = {
            "status": "BLOCK",
            "stage": "MODELSCAN",
            "cache_key": cache_key,
            "file_sha256": file_hash,
            **modelscan_result,
        }
        set_cache(cache_key, _make_cacheable(result))
        return result

    path_a_result = validate_pickle(path)
    if path_a_result["status"] == "BLOCK":
        result = {
            "status": "BLOCK",
            "stage": "PATH_A",
            "cache_key": cache_key,
            "file_sha256": file_hash,
            "yara": yara_result,
            "modelscan": modelscan_result,
            "path_a": path_a_result,
        }
        set_cache(cache_key, _make_cacheable(result))
        return result

    result = {
        "status": "PASS",
        "stage": "PATH_A",
        "cache_key": cache_key,
        "file_sha256": file_hash,
        "yara": yara_result,
        "modelscan": modelscan_result,
        "path_a": path_a_result,
    }

    path_a_tensors = path_a_result.get("tensors")
    path_a_tensor_dict = path_a_result.get("tensor_dict")

    if enable_path_b:
        path_b_result = run_in_docker(
            file_path=path,
            image_name=sandbox_image,
            timeout_sec=10,
            runtime=runtime,
        )
        result["path_b"] = path_b_result

        if path_b_result.get("status") == "BLOCK":
            result["status"] = "BLOCK"
            result["stage"] = "PATH_B"
            set_cache(cache_key, _make_cacheable(result))
            return result

        path_b_tensors = path_b_result.get("tensors")

        if path_a_tensors is not None and path_b_tensors is not None:
            diff_result = compare_tensor_reports(path_a_tensors, path_b_tensors)
            result["diff"] = diff_result

            if diff_result["status"] != "MATCH":
                result["status"] = "BLOCK"
                result["stage"] = "DIFF"
                result["reason_code"] = "PICKLE_PATH_AB_MISMATCH"
                set_cache(cache_key, _make_cacheable(result))
                return result
        else:
            result["diff"] = {
                "status": "SKIP",
                "reason": "PATH_A_OR_PATH_B_TENSORS_MISSING",
            }

    if path_a_tensor_dict:
        output_path = str(Path("generated") / "weights" / f"{file_hash}.safetensors")

        convert_result = convert_tensor_dict_to_safetensors(
            tensor_dict=path_a_tensor_dict,
            output_path=output_path,
            policy_version=policy_fingerprint,
        )

        result["converted"] = convert_result

        if convert_result["status"] == "BLOCK":
            result["status"] = "BLOCK"
            result["stage"] = "CONVERT"
            set_cache(cache_key, _make_cacheable(result))
            return result
    else:
        result["converted"] = {
            "status": "SKIP",
            "reason": "NO_TENSOR_DICT_FROM_PATH_A",
        }

    set_cache(cache_key, _make_cacheable(result))
    return result


def validate(
    path: str,
    policy_fingerprint: str,
    expected_sha256: str | None = None,
    enable_path_b: bool = False,
):
    file_hash = sha256_file(path)

    if path.endswith(".safetensors"):
        cache_key = build_cache_key(file_hash, "SAFETENSORS", policy_fingerprint)
        cached = get_cache(cache_key)
        if cached:
            cached["cached"] = True
            cached["cache_key"] = cache_key
            return cached

        result = validate_safetensors(path, expected_sha256=expected_sha256)
        result["cache_key"] = cache_key
        set_cache(cache_key, _make_cacheable(result))
        return result

    return validate_pickle_pipeline(
        path=path,
        policy_fingerprint=policy_fingerprint,
        enable_path_b=enable_path_b,
    )