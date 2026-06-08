from __future__ import annotations

from pathlib import Path
from typing import Any

from analyzer.utils import build_cache_key
from analyzer.validators.weight.cache import get_cache, set_cache
from analyzer.validators.weight.convert.to_safetensors import (
    convert_tensor_dict_to_safetensors,
)
from analyzer.validators.weight.diff.checker import compare_tensor_reports
from analyzer.validators.weight.hashing import sha256_file
from analyzer.validators.weight.pickle_roles import PickleRole, classify_pickle_role
from analyzer.validators.weight.sandbox.docker_runner import run_in_docker
from analyzer.validators.weight.validators.modelscan_wrapper import scan_with_modelscan
from analyzer.validators.weight.validators.pickle_opcode_parser import validate_pickle
from analyzer.validators.weight.validators.safetensors_validator import (
    validate_safetensors,
)
from analyzer.validators.weight.validators.yara_scanner import scan_with_yara


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


def _cached_pickle_result_satisfies_request(cached: dict, enable_path_b: bool) -> bool:
    if enable_path_b:
        return True

    return "path_b" not in cached


def _pickle_cache_kind(enable_path_b: bool) -> str:
    if enable_path_b:
        return "PICKLE_PATH_B"

    return "PICKLE"


def _path_a_block_allows_path_b_evidence(path_a_result: dict) -> bool:
    return path_a_result.get("reason_code") in {
        "PICKLE_PARSE_ERROR",
        "UNSUPPORTED_PICKLE_FORMAT",
    }


def _hash_mismatch_result(
    file_hash: str,
    expected_sha256: str,
    file_kind: str,
    cache_key: str,
) -> dict:
    return {
        "status": "BLOCK",
        "reason_code": "ARTIFACT_HASH_MISMATCH",
        "reason": "artifact file hash does not match expected sha256",
        "sha256": file_hash,
        "expected_sha256": expected_sha256,
        "file_kind": file_kind,
        "cache_key": cache_key,
    }


def _annotate_pickle_result(result: dict, pickle_role: PickleRole | str) -> dict:
    role_value = (
        pickle_role.value
        if isinstance(pickle_role, PickleRole)
        else str(pickle_role)
    )
    result["pickle_role"] = role_value

    converted = result.get("converted")
    if isinstance(converted, dict) and converted.get("status") == "PASS":
        result["release_eligible"] = True
        result["release_target"] = "GENERATED_SAFETENSORS"
    else:
        result["release_eligible"] = False
        result["release_target"] = None

    return result


def _cache_pickle_result(
    cache_key: str,
    result: dict,
    pickle_role: PickleRole | str,
) -> dict:
    annotated = _annotate_pickle_result(result, pickle_role)
    set_cache(cache_key, _make_cacheable(annotated))
    return annotated


def validate_pickle_pipeline(
    path: str,
    policy_fingerprint: str,
    sandbox_image: str = "weight-sandbox",
    enable_path_b: bool = False,
    runtime: str = "runsc",
    file_hash: str | None = None,
    pickle_role: PickleRole | str = PickleRole.GENERIC_PICKLE,
) -> dict:
    file_hash = file_hash or sha256_file(path)
    cache_key = build_cache_key(
        file_hash,
        _pickle_cache_kind(enable_path_b),
        policy_fingerprint,
    )

    cached = get_cache(cache_key)
    if cached and _cached_pickle_result_satisfies_request(cached, enable_path_b):
        cached["cached"] = True
        cached["cache_key"] = cache_key
        return _annotate_pickle_result(cached, pickle_role)

    yara_result = scan_with_yara(path)
    if yara_result["status"] == "BLOCK":
        result = {
            "status": "BLOCK",
            "stage": "YARA",
            "cache_key": cache_key,
            "file_sha256": file_hash,
            **yara_result,
        }
        return _cache_pickle_result(cache_key, result, pickle_role)

    modelscan_result = scan_with_modelscan(path)
    if modelscan_result["status"] == "BLOCK":
        result = {
            "status": "BLOCK",
            "stage": "MODELSCAN",
            "cache_key": cache_key,
            "file_sha256": file_hash,
            **modelscan_result,
        }
        return _cache_pickle_result(cache_key, result, pickle_role)

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
        if enable_path_b and _path_a_block_allows_path_b_evidence(path_a_result):
            path_b_result = run_in_docker(
                file_path=path,
                image_name=sandbox_image,
                timeout_sec=10,
                runtime=runtime,
            )
            result["path_b"] = path_b_result

            if path_b_result.get("status") == "BLOCK":
                result["stage"] = "PATH_B"
                result["reason_code"] = path_b_result.get(
                    "reason_code",
                    "PICKLE_PATH_B_BLOCKED",
                )
                result["reason"] = path_b_result.get(
                    "reason",
                    "Path B sandbox validation blocked pickle",
                )
            else:
                result["diff"] = {
                    "status": "SKIPPED",
                    "reason_code": "PICKLE_PATH_AB_COMPARE_SKIPPED",
                    "reason": "PATH_A_BLOCKED_BEFORE_TENSOR_REPORT",
                }
        return _cache_pickle_result(cache_key, result, pickle_role)

    result = {
        "status": "PASS",
        "stage": "PATH_A",
        "cache_key": cache_key,
        "file_sha256": file_hash,
        "yara": yara_result,
        "modelscan": modelscan_result,
        "path_a": path_a_result,
        # 스캐너 적용 가시성: SKIP이면 해당 레이어가 실제로 돌지 않았다는 뜻.
        "scanner_coverage": {
            "yara": yara_result.get("status"),
            "modelscan": modelscan_result.get("status"),
        },
    }

    # opt-in fail-closed: 운영자가 HUGGINGMASK_REQUIRE_WEIGHT_SCANNERS로 스캐너
    # 필수를 선언했는데 yara/modelscan이 부재·오류(SKIP)면 Path A만으로 자동
    # PASS시키지 않고 BLOCK한다. 기본값(미설정)에서는 동작 변화 없음.
    import os as _os
    if _os.getenv("HUGGINGMASK_REQUIRE_WEIGHT_SCANNERS", "").strip().lower() in {"1", "true", "yes", "on"}:
        if (
            yara_result.get("status") not in {"PASS", "BLOCK"}
            or modelscan_result.get("status") not in {"PASS", "BLOCK"}
        ):
            # env 의존 결정이므로 캐시하지 않는다(토글 변경 시 stale 방지).
            return _annotate_pickle_result(
                {
                    **result,
                    "status": "BLOCK",
                    "stage": "SCANNER_COVERAGE",
                    "reason_code": "WEIGHT_SCANNER_REQUIRED",
                    "reason": "required malware scanner unavailable (HUGGINGMASK_REQUIRE_WEIGHT_SCANNERS)",
                },
                pickle_role,
            )

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
            result["reason_code"] = path_b_result.get(
                "reason_code",
                "PICKLE_PATH_B_BLOCKED",
            )
            result["reason"] = path_b_result.get(
                "reason",
                "Path B sandbox validation blocked pickle",
            )
            return _cache_pickle_result(cache_key, result, pickle_role)

        path_b_tensors = path_b_result.get("tensors")

        if path_a_tensors is not None and path_b_tensors is not None:
            diff_result = compare_tensor_reports(path_a_tensors, path_b_tensors)
            result["diff"] = diff_result

            if diff_result["status"] != "MATCH":
                result["status"] = "BLOCK"
                result["stage"] = "DIFF"
                result["reason_code"] = "PICKLE_PATH_AB_MISMATCH"
                result["reason"] = "Path A and Path B tensor reports do not match"
                return _cache_pickle_result(cache_key, result, pickle_role)
        else:
            result["diff"] = {
                "status": "SKIPPED",
                "reason_code": "PICKLE_PATH_AB_COMPARE_SKIPPED",
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
            result["reason_code"] = convert_result.get(
                "reason_code",
                "PICKLE_CONVERT_FAILED",
            )
            result["reason"] = convert_result.get(
                "reason",
                "pickle to safetensors conversion failed",
            )
            return _cache_pickle_result(cache_key, result, pickle_role)
    else:
        result["status"] = "BLOCK"
        result["stage"] = "CONVERT"
        result["reason_code"] = "PICKLE_PATH_A_NO_CONVERTIBLE_TENSOR_DICT"
        result["reason"] = (
            "Path A did not produce a convertible tensor_dict. "
            "Original pickle cannot be released."
        )
        result["converted"] = {
            "status": "BLOCK",
            "reason_code": "PICKLE_PATH_A_NO_CONVERTIBLE_TENSOR_DICT",
            "reason": "NO_TENSOR_DICT_FROM_PATH_A",
        }
        return _cache_pickle_result(cache_key, result, pickle_role)

    return _cache_pickle_result(cache_key, result, pickle_role)


def validate(
    path: str,
    policy_fingerprint: str,
    expected_sha256: str | None = None,
    file_kind: str | None = None,
    enable_path_b: bool = False,
    repo_path: str | None = None,
    file_name: str | None = None,
):
    file_hash = sha256_file(path)

    normalized_kind = file_kind or (
        "SAFETENSORS" if path.endswith(".safetensors") else "PICKLE"
    )
    pickle_role = (
        classify_pickle_role(repo_path or path, file_name=file_name)
        if normalized_kind == "PICKLE"
        else None
    )

    cache_key = build_cache_key(
        file_hash,
        (
            _pickle_cache_kind(enable_path_b)
            if normalized_kind == "PICKLE"
            else normalized_kind
        ),
        policy_fingerprint,
    )

    # expected_sha256 검증은 cache lookup보다 먼저 수행해야 함.
    # cached PASS가 잘못된 expected hash 요청을 우회하면 안 됨.
    if expected_sha256 and expected_sha256 != file_hash:
        result = _hash_mismatch_result(
            file_hash=file_hash,
            expected_sha256=expected_sha256,
            file_kind=normalized_kind,
            cache_key=cache_key,
        )
        if pickle_role is not None:
            return _annotate_pickle_result(result, pickle_role)
        return result

    if normalized_kind == "SAFETENSORS":
        cached = get_cache(cache_key)
        if cached:
            cached["cached"] = True
            cached["cache_key"] = cache_key
            return cached

        result = validate_safetensors(path, expected_sha256=expected_sha256)
        result["cache_key"] = cache_key
        set_cache(cache_key, _make_cacheable(result))
        return result

    if normalized_kind == "PICKLE":
        return validate_pickle_pipeline(
            path=path,
            policy_fingerprint=policy_fingerprint,
            enable_path_b=enable_path_b,
            file_hash=file_hash,
            pickle_role=pickle_role or PickleRole.GENERIC_PICKLE,
        )

    return {
        "status": "SKIPPED",
        "reason_code": "NOT_WEIGHT_ARTIFACT",
        "reason": f"unsupported weight validator file kind: {normalized_kind}",
        "file_sha256": file_hash,
        "cache_key": cache_key,
    }
