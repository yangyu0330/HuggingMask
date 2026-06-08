"""Fixture-backed demo API for the HuggingMask frontend console."""

from __future__ import annotations

import hashlib
import json
import pickle
import shutil
import uuid
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

import torch
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from safetensors.torch import save_file
from sqlalchemy.orm import Session

from analyzer.schemas import (
    ArtifactRef,
    ModelRef,
    OverallDecision,
    PolicyInfo,
    ReasonEntry,
    ReviewAction,
    RuntimeContext,
    ValidationJobResponse,
    ValidationStatus,
    ValidationJobRequest,
    to_jsonable,
)
from analyzer.validators.weight.hashing import sha256_file
from whitelist.audit import verify_audit_chain
from whitelist.database import get_db
from whitelist.full_pipeline import run_full_validation
from whitelist.router import whitelist_stats


router = APIRouter(prefix="/internal/v1/demo", tags=["demo"])

REPO_ROOT = Path(__file__).resolve().parents[2]
MOCK_HF_ROOT = REPO_ROOT / "mock_hf"
DEMO_SNAPSHOT_ROOT = REPO_ROOT / "demo_snapshots"

SCENARIO_ORDER = [
    "hm-01-safe-st",
    "hm-02-safe-pkl",
    "hm-03-bad-pkl-reduce",
    "hm-04-bad-py-import",
    "hm-05-bad-config-automap",
]

PREVIEW_LIMIT = 2400


class DemoRunRequest(BaseModel):
    repeat_cache_check: bool = False
    reset_demo_state: bool = False
    enable_path_b: bool = False
    requested_by: str = "demo_presenter"


class _DemoReducePayload:
    """Harmless payload whose pickle contains a REDUCE opcode."""

    def __reduce__(self):
        return (print, ("[DEMO] malicious pickle reduce reached",))


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _scenario_ids() -> list[str]:
    found = {
        item.name
        for item in MOCK_HF_ROOT.iterdir()
        if item.is_dir()
        and (item / "fixture_manifest.json").exists()
        and (item / "expected_result.json").exists()
    }
    ordered = [item for item in SCENARIO_ORDER if item in found]
    ordered.extend(sorted(found.difference(ordered)))
    return ordered


def _scenario_dir(scenario_id: str) -> Path:
    if scenario_id not in _scenario_ids():
        raise HTTPException(status_code=404, detail="Scenario not found")
    path = (MOCK_HF_ROOT / scenario_id).resolve()
    if not path.is_dir() or not _is_under(path, MOCK_HF_ROOT.resolve()):
        raise HTTPException(status_code=404, detail="Scenario not found")
    return path


def _is_under(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _safe_repo_path(raw_path: str) -> PurePosixPath:
    if not raw_path or "\x00" in raw_path or "\\" in raw_path:
        raise HTTPException(status_code=400, detail="Unsafe fixture path")
    path = PurePosixPath(raw_path)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise HTTPException(status_code=400, detail="Unsafe fixture path")
    return path


def _safe_fixture_file(scenario_root: Path, raw_path: str) -> Path:
    repo_path = _safe_repo_path(raw_path)
    path = (scenario_root / Path(*repo_path.parts)).resolve()
    if not _is_under(path, scenario_root.resolve()):
        raise HTTPException(status_code=400, detail="Unsafe fixture path")
    return path


def _summary_for(scenario_id: str) -> dict[str, Any]:
    root = _scenario_dir(scenario_id)
    manifest = _read_json(root / "fixture_manifest.json")
    expected = _read_json(root / "expected_result.json")
    policy_profile = _policy_profile(manifest, expected)
    return {
        "scenario_id": scenario_id,
        "title": expected.get("demo_title") or scenario_id,
        "category": _category_for(expected),
        "policy_profile": policy_profile,
        "expected_overall_decision": expected.get("expected_overall_decision"),
        "expected_overall_status": expected.get("expected_overall_status"),
        "expected_release_action": expected.get("expected_release_action"),
        "expected_reason_codes": expected.get("expected_reason_codes", []),
        "primary_stage": expected.get("expected_primary_stage"),
        "fixture_path": f"mock_hf/{scenario_id}",
        "stable": True,
        "notes": expected.get("notes", []),
    }


def _category_for(expected: dict[str, Any]) -> str:
    status = str(expected.get("expected_overall_status") or "").upper()
    decision = str(expected.get("expected_overall_decision") or "").upper()
    if status == "PASS" and decision == "APPROVE_WITH_TRANSFORM":
        return "transform"
    if status == "PASS":
        return "safe"
    if status == "BLOCK":
        return "blocked"
    return "review"


def _policy_profile(manifest: dict[str, Any], expected: dict[str, Any]) -> str:
    return (
        expected.get("demo_policy_profile")
        or manifest.get("demo_policy_profile")
        or "strict_default"
    )


def _detail_for(scenario_id: str) -> dict[str, Any]:
    root = _scenario_dir(scenario_id)
    manifest = _read_json(root / "fixture_manifest.json")
    expected = _read_json(root / "expected_result.json")
    source_files = _source_previews(root, manifest)
    return {
        **_summary_for(scenario_id),
        "required_repo_files": manifest.get("required_repo_files", []),
        "files_present_in_repo": manifest.get("files_present_in_repo", []),
        "artifacts_to_generate": manifest.get("artifacts_to_generate", []),
        "expected": expected,
        "manifest": manifest,
        "source_files": source_files,
        "presentation_notes": expected.get("notes", []),
        "limitations": [
            "Fixture scenarios are the default demo path.",
            "Live Hugging Face downloads remain optional evidence.",
            "Path B/gVisor evidence is opt-in via enable_path_b.",
        ],
    }


def _source_previews(
    scenario_root: Path,
    manifest: dict[str, Any],
) -> list[dict[str, Any]]:
    paths = list(manifest.get("files_present_in_repo", []))
    for extra in ("README.md", "expected_log.md"):
        if extra not in paths and (scenario_root / extra).exists():
            paths.append(extra)

    previews = []
    for raw_path in paths:
        path = _safe_fixture_file(scenario_root, raw_path)
        if not path.exists() or not path.is_file():
            previews.append({
                "repo_path": raw_path,
                "exists": False,
                "preview": "",
                "truncated": False,
            })
            continue

        raw = path.read_bytes()
        text = raw.decode("utf-8", errors="replace")
        previews.append({
            "repo_path": raw_path,
            "exists": True,
            "size_bytes": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "preview": text[:PREVIEW_LIMIT],
            "truncated": len(text) > PREVIEW_LIMIT,
        })
    return previews


def _snapshot_dir(scenario_id: str, run_id: str, reset: bool) -> Path:
    root = (DEMO_SNAPSHOT_ROOT / scenario_id).resolve()
    if not _is_under(root, DEMO_SNAPSHOT_ROOT.resolve()):
        raise HTTPException(status_code=400, detail="Unsafe snapshot path")
    if reset and root.exists():
        shutil.rmtree(root)
    path = root / run_id
    path.mkdir(parents=True, exist_ok=True)
    return path


def _materialize_snapshot(
    scenario_id: str,
    run_id: str,
    request: DemoRunRequest,
) -> tuple[Path, list[ArtifactRef]]:
    scenario_root = _scenario_dir(scenario_id)
    manifest = _read_json(scenario_root / "fixture_manifest.json")
    snapshot = _snapshot_dir(scenario_id, run_id, request.reset_demo_state)

    copied_paths: set[str] = set()
    artifacts: list[ArtifactRef] = []

    for raw_path in manifest.get("files_present_in_repo", []):
        repo_path = _safe_repo_path(raw_path)
        source = _safe_fixture_file(scenario_root, raw_path)
        if not source.exists() or not source.is_file():
            continue
        target = snapshot / Path(*repo_path.parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        copied_paths.add(repo_path.as_posix())
        artifact = _artifact_for_file(target, repo_path.as_posix(), is_generated=False)
        if artifact is not None:
            artifacts.append(artifact)

    for item in manifest.get("artifacts_to_generate", []):
        raw_path = str(item.get("path") or "")
        repo_path = _safe_repo_path(raw_path)
        target = snapshot / Path(*repo_path.parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        _generate_artifact_file(target, scenario_id, item, manifest)
        copied_paths.add(repo_path.as_posix())
        artifact = _artifact_for_file(target, repo_path.as_posix(), is_generated=False)
        if artifact is not None:
            artifacts.append(artifact)

    return snapshot, artifacts


def _artifact_for_file(
    path: Path,
    repo_path: str,
    *,
    is_generated: bool,
) -> ArtifactRef | None:
    kind = _file_kind(repo_path)
    if kind is None:
        return None
    digest = sha256_file(str(path))
    suffix = PurePosixPath(repo_path).suffix
    return ArtifactRef(
        artifact_id=f"sha256:{digest}",
        repo_path=repo_path,
        file_name=PurePosixPath(repo_path).name,
        file_kind=kind,
        detected_extension=suffix,
        size_bytes=path.stat().st_size,
        sha256=digest,
        source_url=f"mock_hf://{repo_path}",
        temp_local_path=str(path),
        media_type="application/json" if suffix == ".json" else None,
        referenced_by=[],
        is_generated=is_generated,
    )


def _file_kind(repo_path: str) -> str | None:
    name = PurePosixPath(repo_path).name
    suffix = PurePosixPath(repo_path).suffix.lower()
    if suffix == ".safetensors":
        return "SAFETENSORS"
    if suffix in {".bin", ".pkl", ".pickle", ".pt", ".pth"}:
        return "PICKLE"
    if suffix == ".py":
        return "PYTHON"
    if name == "tokenizer_config.json":
        return "TOKENIZER_CONFIG_JSON"
    if name == "config.json":
        return "CONFIG_JSON"
    if suffix == ".json":
        return "OTHER"
    return None


def _generate_artifact_file(
    target: Path,
    scenario_id: str,
    item: dict[str, Any],
    manifest: dict[str, Any],
) -> None:
    kind = str(item.get("kind") or _file_kind(target.name) or "")
    if kind == "SAFETENSORS":
        save_file(_tensor_dict_from_manifest(manifest), str(target))
        return
    if kind == "PICKLE":
        if "plus_reduce" in str(item.get("schema") or "") or scenario_id.endswith("bad-pkl-reduce"):
            with target.open("wb") as handle:
                pickle.dump(_DemoReducePayload(), handle, protocol=4)
            return
        with target.open("wb") as handle:
            pickle.dump(
                {"__tensor_dict__": _tensor_schema_from_manifest(manifest)},
                handle,
                protocol=4,
            )
        return
    raise HTTPException(status_code=400, detail=f"Unsupported generated artifact kind: {kind}")


def _tensor_dict_from_manifest(manifest: dict[str, Any]) -> dict[str, torch.Tensor]:
    source = _tensor_schema_from_manifest(manifest)
    tensors: dict[str, torch.Tensor] = {}
    for name, spec in source.items():
        dtype = _torch_dtype(str(spec.get("dtype", "float32")))
        data = spec.get("data", [])
        shape = spec.get("shape", [])
        tensors[name] = torch.tensor(data, dtype=dtype).reshape(shape)
    return tensors


def _tensor_schema_from_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    payload = manifest.get("payload_schema")
    if isinstance(payload, dict):
        return {
            key: value
            for key, value in payload.items()
            if isinstance(value, dict) and "data" in value
        }
    return _read_json(MOCK_HF_ROOT / "base_model_spec.json")["tensor_spec"]


def _torch_dtype(name: str):
    return {
        "float16": torch.float16,
        "float32": torch.float32,
        "float64": torch.float64,
        "int8": torch.int8,
        "int16": torch.int16,
        "int32": torch.int32,
        "int64": torch.int64,
        "uint8": torch.uint8,
        "bool": torch.bool,
    }.get(name, torch.float32)


def _validation_request(
    scenario_id: str,
    run_id: str,
    artifacts: list[ArtifactRef],
    snapshot: Path,
    request: DemoRunRequest,
) -> ValidationJobRequest:
    timestamp = _now()
    scenario_root = _scenario_dir(scenario_id)
    manifest = _read_json(scenario_root / "fixture_manifest.json")
    expected = _read_json(scenario_root / "expected_result.json")
    policy_profile = _policy_profile(manifest, expected)
    policy = PolicyInfo(
        policy_version=f"demo-{policy_profile}",
        whitelist_version="demo-whitelist",
        opcode_policy_version="demo-opcode",
        config_schema_version="demo-config",
        runtime_profile_version="demo-runtime",
    )
    return ValidationJobRequest(
        request_id=f"demo-{uuid.uuid4()}",
        job_id=run_id,
        model=ModelRef(
            repo_id=f"mock_hf/{scenario_id}",
            revision="fixture",
            source_host="mock_hf",
            source_url=f"mock_hf://{scenario_id}",
            requested_at=timestamp,
            endpoint_mode="HF_ENDPOINT_PROXY",
            requested_by=request.requested_by,
        ),
        policy=policy,
        runtime_context=RuntimeContext(
            sandbox_runtime="gVisor" if request.enable_path_b else "none",
            network_disabled=True,
            read_only_fs=True,
            compare_mode="path_b" if request.enable_path_b else "path_a",
            allow_cache_lookup=True,
            generate_mlbom=False,
            write_audit_log=True,
        ),
        artifacts=artifacts,
        requested_routes=_requested_routes_for_expected(expected),
        stop_on_first_block=False,
        enable_path_b=request.enable_path_b,
        policy_fingerprint=policy.policy_fingerprint,
        notes=f"frontend demo scenario {scenario_id}",
        model_snapshot_root=str(snapshot),
    )


def _requested_routes_for_expected(expected: dict[str, Any]) -> list[str]:
    stage = expected.get("expected_primary_stage")
    if stage == "VALIDATE_SAFETENSORS":
        return ["SAFETENSORS_FAST_PATH"]
    if stage == "VALIDATE_PICKLE_PATH_A":
        return ["PICKLE_PATH_A"]
    if stage == "VALIDATE_CODE_AST":
        return ["CODE_AST_SCAN"]
    if stage == "VALIDATE_CONFIG":
        return ["CONFIG_SCHEMA_VALIDATION"]
    return []


def _apply_demo_policy_response(
    scenario_id: str,
    response: ValidationJobResponse,
) -> ValidationJobResponse:
    """Apply fixture policy profile semantics to the demo response only."""
    scenario_root = _scenario_dir(scenario_id)
    manifest = _read_json(scenario_root / "fixture_manifest.json")
    expected = _read_json(scenario_root / "expected_result.json")
    policy_profile = _policy_profile(manifest, expected)

    if (
        policy_profile != "strict_default"
        or expected.get("expected_primary_stage") != "VALIDATE_CONFIG"
    ):
        return response

    updated_results = []
    blocked_ids = list(response.blocked_artifact_ids)
    pending_ids = [
        item for item in response.pending_artifact_ids
    ]
    approved_ids = [
        item for item in response.approved_artifact_ids
    ]
    changed = False

    for result in response.artifact_results:
        reason_codes = {entry.code for entry in result.reason_entries}
        is_config_trigger = (
            result.artifact.repo_path == "config.json"
            and "CONFIG_TRIGGER_FIELD_FOUND" in reason_codes
        )
        if not is_config_trigger:
            updated_results.append(result)
            continue

        details = dict(result.details)
        details["effective_status"] = ValidationStatus.BLOCK.value
        details["demo_policy_enforcement"] = {
            "policy_profile": policy_profile,
            "reason": "strict_default blocks custom-code config trigger fields",
            "source": "mock_hf expected_result.json",
        }
        reason_entries = list(result.reason_entries)
        if "CONFIG_TRIGGER_FIELD_FOUND" not in reason_codes:
            reason_entries.append(
                ReasonEntry(
                    code="CONFIG_TRIGGER_FIELD_FOUND",
                    message="config trigger fields detected",
                    severity="HIGH",
                    evidence=["auto_map", "custom_pipelines"],
                    review_required=False,
                )
            )
        updated_results.append(
            replace(
                result,
                status=ValidationStatus.BLOCK,
                review_action=ReviewAction.BLOCK_IMMEDIATELY,
                reason_entries=reason_entries,
                details=details,
            )
        )
        artifact_id = result.artifact.artifact_id
        if artifact_id not in blocked_ids:
            blocked_ids.append(artifact_id)
        pending_ids = [item for item in pending_ids if item != artifact_id]
        approved_ids = [item for item in approved_ids if item != artifact_id]
        changed = True

    if not changed:
        return response

    return replace(
        response,
        overall_decision=OverallDecision.DENY,
        overall_status=ValidationStatus.BLOCK,
        release_action="DENY",
        artifact_results=updated_results,
        approved_artifact_ids=approved_ids,
        blocked_artifact_ids=blocked_ids,
        pending_artifact_ids=pending_ids,
        coverage_summary=_coverage_summary_for_updated_response(
            response.coverage_summary,
            updated_results,
            pending_ids,
        ),
    )


def _coverage_summary_for_updated_response(
    original: dict[str, Any],
    results: list[Any],
    pending_artifact_ids: list[str],
) -> dict[str, int]:
    pending_ids = set(pending_artifact_ids)
    summary = dict(original or {})
    summary["result_count"] = len(results)
    summary["approved"] = sum(
        1 for result in results if result.status is ValidationStatus.PASS
    )
    summary["blocked"] = sum(
        1 for result in results if result.status is ValidationStatus.BLOCK
    )
    summary["pending"] = sum(
        1
        for result in results
        if result.status in {
            ValidationStatus.PENDING_REVIEW,
            ValidationStatus.ERROR,
            ValidationStatus.SKIPPED,
        }
        or result.artifact.artifact_id in pending_ids
    )
    summary["skipped"] = sum(
        1 for result in results if result.status is ValidationStatus.SKIPPED
    )
    summary["error"] = sum(
        1 for result in results if result.status is ValidationStatus.ERROR
    )
    summary["validated"] = sum(
        1
        for result in results
        if result.status is not ValidationStatus.SKIPPED
        and result.details.get("validation_coverage") != "unvalidated"
    )
    return summary


def _expected_for(scenario_id: str) -> dict[str, Any]:
    expected = _read_json(_scenario_dir(scenario_id) / "expected_result.json")
    return {
        "overall_decision": expected.get("expected_overall_decision"),
        "overall_status": expected.get("expected_overall_status"),
        "release_action": expected.get("expected_release_action"),
        "reason_codes": expected.get("expected_reason_codes", []),
        "generated_artifact": expected.get("expected_generated_artifact"),
    }


def _actual_summary(response: Any) -> dict[str, Any]:
    reason_codes = sorted({
        entry.code
        for result in response.artifact_results
        for entry in result.reason_entries
    })
    generated = [artifact.file_name for artifact in response.generated_artifacts]
    decision = response.overall_decision.value
    if response.overall_status.value == "PASS" and generated:
        decision = "APPROVE_WITH_TRANSFORM"
    return {
        "overall_decision": decision,
        "overall_status": response.overall_status.value,
        "release_action": response.release_action,
        "reason_codes": reason_codes,
        "generated_artifacts": generated,
    }


def _match_expectation(expected: dict[str, Any], actual: dict[str, Any]) -> dict[str, Any]:
    checks = {
        "overall_decision": expected.get("overall_decision") == actual.get("overall_decision"),
        "overall_status": expected.get("overall_status") == actual.get("overall_status"),
        "release_action": expected.get("release_action") == actual.get("release_action"),
        "reason_codes": set(expected.get("reason_codes") or []).issubset(
            set(actual.get("reason_codes") or [])
        ),
    }
    generated = expected.get("generated_artifact")
    if generated:
        actual_generated = set(actual.get("generated_artifacts") or [])
        checks["generated_artifact"] = (
            generated in actual_generated
            or (
                generated.endswith(".safetensors")
                and any(item.endswith(".safetensors") for item in actual_generated)
            )
        )
    return {
        "matched": all(checks.values()),
        "checks": checks,
        "mismatches": [
            key for key, ok in checks.items() if not ok
        ],
    }


def _evidence_specs() -> list[dict[str, str]]:
    return [
        {
            "kind": "demo",
            "title": "Final demo script",
            "path": "docs/final_demo_script.md",
            "summary": "Presenter-facing scenario order and talking points.",
        },
        {
            "kind": "design",
            "title": "Frontend console blueprint",
            "path": "docs/frontend_demo_console_blueprint.md",
            "summary": "Source plan for this console implementation.",
        },
        {
            "kind": "demo",
            "title": "Smoke validation summary",
            "path": "evidence/demo/20260401_smoke_validate_summary_CX_v1.md",
            "summary": "Archived smoke validation evidence.",
        },
        {
            "kind": "demo",
            "title": "HF real download summary",
            "path": "evidence/demo/20260401_hf_real_download_test_summary_CX_v1.md",
            "summary": "Archived live Hugging Face download evidence.",
        },
        {
            "kind": "demo",
            "title": "Live endpoints summary",
            "path": "evidence/demo/20260506_live_endpoints_summary_KMW_v1.md",
            "summary": "Archived live endpoint verification.",
        },
        {
            "kind": "worklog",
            "title": "Integration adapter worklog",
            "path": "evidence/worklog/20260506_yangyu_integration_adapter_KMW_v1.md",
            "summary": "Integration worklog evidence.",
        },
        {
            "kind": "worklog",
            "title": "Dashboard and ops worklog",
            "path": "evidence/worklog/20260508_dashboard_and_ops_KMW_v1.md",
            "summary": "Operations dashboard worklog evidence.",
        },
        {
            "kind": "worklog",
            "title": "Restricted runtime worklog",
            "path": "evidence/worklog/20260508_restricted_runtime_KMW_v1.md",
            "summary": "Restricted runtime evidence and limits.",
        },
        {
            "kind": "tests",
            "title": "Latest full pytest raw log",
            "path": "evidence/tests/20260520_pr17_full_pytest_raw_KMW_v1.txt",
            "summary": "Archived full pytest raw output.",
        },
    ]


def _evidence_items() -> list[dict[str, Any]]:
    items = []
    for spec in _evidence_specs():
        path = REPO_ROOT / spec["path"]
        exists = path.exists()
        items.append({
            **spec,
            "exists": exists,
            "last_modified": (
                datetime.fromtimestamp(path.stat().st_mtime, UTC).isoformat()
                if exists
                else None
            ),
        })
    return items


@router.get("/scenarios")
def list_scenarios() -> dict[str, Any]:
    return {"items": [_summary_for(scenario_id) for scenario_id in _scenario_ids()]}


@router.get("/evidence")
def demo_evidence() -> dict[str, Any]:
    return {"items": _evidence_items()}


@router.get("/readiness")
def demo_readiness(db: Session = Depends(get_db)) -> dict[str, Any]:
    evidence = _evidence_items()
    missing = [item["path"] for item in evidence if not item["exists"]]
    audit_valid, audit_errors = verify_audit_chain(db)
    stats = whitelist_stats(db=db)
    warnings = []
    if missing:
        warnings.append("Some archived evidence files are missing.")
    warnings.append("Path B/gVisor is opt-in evidence and is not the default validation route.")
    return {
        "health": {"ok": True},
        "openapi": {"ok": True},
        "dashboard": {"ok": True},
        "audit_chain": {
            "valid": audit_valid,
            "violation_count": len(audit_errors),
            "violations": audit_errors[:10],
        },
        "stats": stats,
        "evidence": {"missing": missing, "items": evidence},
        "warnings": warnings,
    }


@router.get("/scenarios/{scenario_id}")
def get_scenario(scenario_id: str) -> dict[str, Any]:
    return _detail_for(scenario_id)


@router.post("/scenarios/{scenario_id}/run")
def run_scenario(
    scenario_id: str,
    request: DemoRunRequest,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    _scenario_dir(scenario_id)
    run_id = f"demo_{datetime.now(UTC).strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"
    started_at = _now()
    snapshot, artifacts = _materialize_snapshot(scenario_id, run_id, request)
    job_request = _validation_request(scenario_id, run_id, artifacts, snapshot, request)
    response = _apply_demo_policy_response(
        scenario_id,
        run_full_validation(job_request, db=db),
    )

    cache_check_response = None
    if request.repeat_cache_check:
        second_run_id = f"{run_id}_cache"
        second_request = _validation_request(
            scenario_id,
            second_run_id,
            artifacts,
            snapshot,
            request,
        )
        cache_check_response = _apply_demo_policy_response(
            scenario_id,
            run_full_validation(second_request, db=db),
        )

    expected = _expected_for(scenario_id)
    actual = _actual_summary(response)
    comparison = _match_expectation(expected, actual)
    return {
        "scenario_id": scenario_id,
        "run_id": run_id,
        "started_at": started_at,
        "finished_at": _now(),
        "expected": expected,
        "actual": actual,
        "matched_expectation": comparison["matched"],
        "expectation_checks": comparison["checks"],
        "expectation_mismatches": comparison["mismatches"],
        "snapshot_root": str(snapshot),
        "validation_response": to_jsonable(response),
        "cache_check_response": (
            to_jsonable(cache_check_response)
            if cache_check_response is not None
            else None
        ),
    }
