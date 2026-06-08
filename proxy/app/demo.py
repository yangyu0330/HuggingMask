"""Fixture-backed demo API for the HuggingMask frontend console."""

from __future__ import annotations

import hashlib
import fnmatch
import json
import pickle
import shutil
import time
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

from analyzer.classifier import classify_file_kind as classify_core_file_kind
from analyzer.schemas import (
    ArtifactRef,
    FileKind,
    ModelRef,
    OverallDecision,
    PolicyInfo,
    ReasonEntry,
    ReviewAction,
    RuntimeContext,
    SnapshotFileRef,
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

SCENARIO_DISPLAY_TITLES = {
    "hm-01-safe-st": "정상 safetensors",
    "hm-02-safe-pkl": "정상 pickle 변환",
    "hm-03-bad-pkl-reduce": "위험 pickle opcode 차단",
    "hm-04-bad-py-import": "위험 Python 코드 차단",
    "hm-05-bad-config-automap": "위험 config 트리거 차단",
}

PREVIEW_LIMIT = 2400

FAST_LIVE_MODEL_ALLOW_PATTERNS = [
    "*.json",
    "*.py",
    "*.txt",
    "*.model",
    "*.jinja",
]

WEIGHT_FILE_KINDS = {FileKind.SAFETENSORS, FileKind.PICKLE}


class DemoRunRequest(BaseModel):
    repeat_cache_check: bool = False
    reset_demo_state: bool = False
    enable_path_b: bool = False
    requested_by: str = "demo_presenter"


class LiveModelRunRequest(BaseModel):
    repo_id: str
    revision: str = "main"
    skip_weights: bool = True
    enable_path_b: bool = False
    include_patterns: list[str] = []
    exclude_patterns: list[str] = []
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
        "title": SCENARIO_DISPLAY_TITLES.get(scenario_id)
        or expected.get("demo_title")
        or scenario_id,
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
            "fixture 시나리오가 기본 데모 경로입니다.",
            "실제 Hugging Face 다운로드는 선택 근거로만 남깁니다.",
            "Path B/gVisor 근거는 enable_path_b로 선택했을 때만 사용합니다.",
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


def _matches_any(value: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatchcase(value, pattern) for pattern in patterns)


def _download_allow_patterns(request: LiveModelRunRequest) -> list[str] | None:
    if request.include_patterns:
        return request.include_patterns
    if request.skip_weights:
        return FAST_LIVE_MODEL_ALLOW_PATTERNS
    return None


def _download_hf_snapshot(request: LiveModelRunRequest) -> Path:
    try:
        from huggingface_hub import snapshot_download
    except ImportError as exc:
        raise HTTPException(
            status_code=503,
            detail="huggingface_hub 패키지가 없어 실제 모델 다운로드를 실행할 수 없습니다.",
        ) from exc

    try:
        return Path(snapshot_download(
            repo_id=request.repo_id,
            revision=request.revision,
            allow_patterns=_download_allow_patterns(request),
            ignore_patterns=request.exclude_patterns or None,
        ))
    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Hugging Face 모델 다운로드 실패: {exc}",
        ) from exc


def _live_artifact_for_file(path: Path, repo_path: str, request: LiveModelRunRequest) -> ArtifactRef:
    kind = classify_core_file_kind(repo_path)
    digest = sha256_file(str(path))
    suffix = PurePosixPath(repo_path).suffix.lower()
    return ArtifactRef(
        artifact_id=f"sha256:{digest}",
        repo_path=repo_path,
        file_name=PurePosixPath(repo_path).name,
        file_kind=kind,
        detected_extension=suffix,
        size_bytes=path.stat().st_size,
        sha256=digest,
        source_url=f"https://huggingface.co/{request.repo_id}/blob/{request.revision}/{repo_path}",
        temp_local_path=str(path),
        media_type="application/json" if suffix == ".json" else None,
        referenced_by=[],
        is_generated=False,
    )


def _scan_live_model_snapshot(
    snapshot_root: Path,
    request: LiveModelRunRequest,
) -> tuple[list[ArtifactRef], list[SnapshotFileRef], dict[str, list[str]]]:
    artifacts: list[ArtifactRef] = []
    inventory: list[SnapshotFileRef] = []
    skipped = {
        "unsupported": [],
        "weights_fast_mode": [],
        "include_filter": [],
        "exclude_filter": [],
    }

    for path in sorted(snapshot_root.rglob("*")):
        if not path.is_file():
            continue
        repo_path = path.relative_to(snapshot_root).as_posix()
        if request.include_patterns and not _matches_any(repo_path, request.include_patterns):
            skipped["include_filter"].append(repo_path)
            continue
        if request.exclude_patterns and _matches_any(repo_path, request.exclude_patterns):
            skipped["exclude_filter"].append(repo_path)
            continue

        kind = classify_core_file_kind(repo_path)
        digest = sha256_file(str(path))
        inventory.append(SnapshotFileRef(
            repo_path=repo_path,
            temp_local_path=str(path),
            sha256=digest,
            size_bytes=path.stat().st_size,
            file_kind=kind,
        ))

        if kind is FileKind.OTHER:
            skipped["unsupported"].append(repo_path)
            continue
        if request.skip_weights and kind in WEIGHT_FILE_KINDS:
            skipped["weights_fast_mode"].append(repo_path)
            continue
        artifacts.append(_live_artifact_for_file(path, repo_path, request))

    return artifacts, inventory, skipped


def _live_policy() -> PolicyInfo:
    return PolicyInfo(
        policy_version="live-demo-policy",
        whitelist_version="live-demo-whitelist",
        opcode_policy_version="live-demo-opcode",
        config_schema_version="live-demo-config",
        runtime_profile_version="live-demo-runtime",
    )


def _live_validation_request(
    request: LiveModelRunRequest,
    run_id: str,
    snapshot_root: Path,
    artifacts: list[ArtifactRef],
    inventory: list[SnapshotFileRef],
) -> ValidationJobRequest:
    timestamp = _now()
    policy = _live_policy()
    return ValidationJobRequest(
        request_id=f"live-{uuid.uuid4()}",
        job_id=run_id,
        model=ModelRef(
            repo_id=request.repo_id,
            revision=request.revision,
            source_host="huggingface.co",
            source_url=f"https://huggingface.co/{request.repo_id}",
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
        stop_on_first_block=False,
        enable_path_b=request.enable_path_b,
        policy_fingerprint=policy.policy_fingerprint,
        notes=f"live model dashboard demo for {request.repo_id}",
        model_snapshot_root=str(snapshot_root),
        model_snapshot_inventory=inventory,
    )


def _lane_for_kind(kind: str) -> str:
    if kind in {"SAFETENSORS", "PICKLE"}:
        return "weights"
    if kind == "PYTHON":
        return "python"
    if kind in {
        "CONFIG_JSON",
        "TOKENIZER_CONFIG_JSON",
        "TOKENIZER_JSON",
        "SPECIAL_TOKENS_MAP_JSON",
        "ADDED_TOKENS_JSON",
        "VOCAB_JSON",
        "MERGES_TXT",
        "PREPROCESSOR_CONFIG_JSON",
        "PROCESSOR_CONFIG_JSON",
        "CHAT_TEMPLATE_JINJA",
    }:
        return "config"
    return "other"


def _lane_status(results: list[ArtifactValidationResult]) -> str:
    if not results:
        return "SKIPPED"
    statuses = {result.status.value for result in results}
    if "BLOCK" in statuses or "ERROR" in statuses:
        return "BLOCK"
    if "PENDING_REVIEW" in statuses or "SKIPPED" in statuses:
        return "PENDING_REVIEW"
    return "PASS"


def _live_lane_results(response: ValidationJobResponse) -> list[dict[str, Any]]:
    lane_meta = {
        "weights": {
            "title": "가중치 검사",
            "description": "safetensors와 pickle/bin 파일을 해시, 메타데이터, opcode 기준으로 확인합니다.",
        },
        "python": {
            "title": "Python 코드 검사",
            "description": "역할 분류, AST/API/context 검사 후 A/B-1/B-2/C 등급을 결정합니다.",
        },
        "config": {
            "title": "config 검사",
            "description": "schema, trigger 필드, auto_map 연결 Python 파일을 함께 확인합니다.",
        },
    }
    grouped: dict[str, list[ArtifactValidationResult]] = {key: [] for key in lane_meta}
    for result in response.artifact_results:
        lane = _lane_for_kind(result.artifact.file_kind.value)
        if lane in grouped:
            grouped[lane].append(result)

    return [
        {
            "lane": lane,
            "title": meta["title"],
            "description": meta["description"],
            "status": _lane_status(grouped[lane]),
            "count": len(grouped[lane]),
            "results": [to_jsonable(result) for result in grouped[lane]],
        }
        for lane, meta in lane_meta.items()
    ]


def _value_text(value: Any) -> str:
    return str(getattr(value, "value", value))


def _dict_value(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _sandbox_security_event_count(check: dict[str, Any]) -> int:
    events = _dict_value(check.get("security_events"))
    total = 0
    for value in events.values():
        if isinstance(value, list):
            total += len(value)
    return total


def _sandbox_execution_ran(check: dict[str, Any]) -> bool:
    execution = _dict_value(check.get("execution"))
    statuses = [
        str(execution.get("import_status") or "").lower(),
        str(execution.get("instantiate_status") or "").lower(),
        str(execution.get("forward_status") or "").lower(),
    ]
    return any(status not in {"", "not_run", "skipped"} for status in statuses)


def _live_sandbox_status(
    *,
    requested: bool,
    checks: list[dict[str, Any]],
    blocked_event_count: int,
) -> str:
    if not requested:
        return "SKIPPED"
    if not checks:
        return "SKIPPED"

    decisions = {str(check.get("decision") or "") for check in checks}
    if blocked_event_count > 0 or any(decision.startswith("BLOCKED") for decision in decisions):
        return "BLOCK"
    if "SANDBOX_INFRA_ERROR" in decisions or "ERROR" in decisions:
        return "ERROR"
    return "PENDING_REVIEW"


def _live_sandbox_message(
    *,
    requested: bool,
    eligible_count: int,
    check_count: int,
    ran_count: int,
    decisions: set[str],
) -> str:
    if not requested:
        return "Path B/gVisor 근거 요청이 꺼져 있어 샌드박스 실행 단계는 건너뛰었습니다."
    if eligible_count == 0:
        return "이번 모델에는 B-2 샌드박스 대상 Python 코드가 없어 실행하지 않았습니다."
    if check_count == 0:
        return "B-2 대상은 있었지만 sandbox_check 근거가 응답에 붙지 않았습니다. 보안 담당자 검토가 필요합니다."
    if ran_count > 0:
        return "gVisor/runsc 샌드박스 실행 근거를 수집했습니다. 이 근거는 자동 승인 대신 보안 검토 자료로 남습니다."
    if "NOT_RUN" in decisions:
        return "B-2 대상은 있었지만 현재 데모 API에는 runner/resolver가 연결되지 않아 실제 컨테이너 실행은 NOT_RUN으로 남았습니다."
    return "샌드박스 근거가 생성되었지만 최종 승인은 보안 담당자 검토 뒤에만 가능합니다."


def _live_sandbox_summary(
    request: LiveModelRunRequest,
    response: ValidationJobResponse,
) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    eligible_count = 0
    blocked_event_count = 0
    ran_count = 0

    for result in response.artifact_results:
        grade = _value_text(result.grade)
        file_kind = _value_text(result.artifact.file_kind)
        if file_kind == "PYTHON" and grade == "B-2":
            eligible_count += 1

        sandbox_check = _dict_value((result.details or {}).get("sandbox_check"))
        if not sandbox_check and request.enable_path_b and file_kind == "PYTHON" and grade == "B-2":
            sandbox_check = {
                "schema_version": "1.0",
                "request_id": response.request_id,
                "job_id": response.job_id,
                "artifact_id": result.artifact.artifact_id,
                "repo_path": result.artifact.repo_path,
                "grade": "B-2",
                "sandbox_runtime": None,
                "profile": "B2_STANDARD",
                "decision": "NOT_RUN",
                "deployable": False,
                "runtime_evidence": {},
                "execution": {
                    "import_status": "not_run",
                    "instantiate_status": "not_run",
                    "forward_status": "not_run",
                },
                "security_events": {
                    "network_events": [],
                    "unexpected_execve": [],
                    "blocked_writes": [],
                    "secret_path_access": [],
                    "blocked_reads": [],
                    "review_events": [],
                },
                "manifest_evidence": {
                    "host_manifest_sha256": None,
                    "manifest_errors": [],
                    "input_hash_errors": [],
                },
                "artifacts": {},
                "policy_gate": {"reason_code": "SANDBOX_CHECK_NOT_ATTACHED"},
                "created_at": _now(),
                "reason": "B-2 sandbox check was not attached by the validation pipeline",
            }
        if not sandbox_check:
            continue

        event_count = _sandbox_security_event_count(sandbox_check)
        did_run = _sandbox_execution_ran(sandbox_check)
        blocked_event_count += event_count
        ran_count += 1 if did_run else 0
        policy_gate = _dict_value(sandbox_check.get("policy_gate"))

        checks.append({
            "repo_path": result.artifact.repo_path,
            "artifact_id": result.artifact.artifact_id,
            "status": _value_text(result.status),
            "grade": grade,
            "route_kind": _value_text(result.route_kind),
            "decision": str(sandbox_check.get("decision") or "UNKNOWN"),
            "deployable": bool(sandbox_check.get("deployable")),
            "sandbox_runtime": sandbox_check.get("sandbox_runtime"),
            "reason_code": policy_gate.get("reason_code"),
            "reason": sandbox_check.get("reason"),
            "execution": to_jsonable(_dict_value(sandbox_check.get("execution"))),
            "runtime_evidence": to_jsonable(_dict_value(sandbox_check.get("runtime_evidence"))),
            "security_events": to_jsonable(_dict_value(sandbox_check.get("security_events"))),
            "manifest_evidence": to_jsonable(_dict_value(sandbox_check.get("manifest_evidence"))),
            "policy_gate": to_jsonable(policy_gate),
            "artifacts": to_jsonable(_dict_value(sandbox_check.get("artifacts"))),
        })

    decisions = {str(check.get("decision") or "") for check in checks}
    status = _live_sandbox_status(
        requested=request.enable_path_b,
        checks=checks,
        blocked_event_count=blocked_event_count,
    )
    message = _live_sandbox_message(
        requested=request.enable_path_b,
        eligible_count=eligible_count,
        check_count=len(checks),
        ran_count=ran_count,
        decisions=decisions,
    )
    return {
        "requested": request.enable_path_b,
        "eligible_count": eligible_count,
        "check_count": len(checks),
        "ran_count": ran_count,
        "skipped_count": max(0, eligible_count - ran_count),
        "blocked_event_count": blocked_event_count,
        "status": status,
        "message": message,
        "checks": checks,
    }


def _live_sandbox_step_items(summary: dict[str, Any]) -> list[str]:
    checks = summary.get("checks")
    if not isinstance(checks, list) or not checks:
        return [str(summary.get("message") or "샌드박스 실행 근거 없음")]
    items = []
    for check in checks[:12]:
        if not isinstance(check, dict):
            continue
        repo_path = check.get("repo_path") or "unknown"
        decision = check.get("decision") or "UNKNOWN"
        reason_code = check.get("reason_code") or "사유 없음"
        items.append(f"{repo_path} → {decision} / {reason_code}")
    return items


def _live_file_summary(artifacts: list[ArtifactRef], skipped: dict[str, list[str]]) -> dict[str, Any]:
    counts = {"weights": 0, "python": 0, "config": 0, "other": 0}
    for artifact in artifacts:
        counts[_lane_for_kind(artifact.file_kind.value)] += 1
    return {
        **counts,
        "total_supported": len(artifacts),
        "skipped_unsupported": len(skipped["unsupported"]),
        "skipped_weights_fast_mode": len(skipped["weights_fast_mode"]),
        "skipped_include_filter": len(skipped["include_filter"]),
        "skipped_exclude_filter": len(skipped["exclude_filter"]),
    }


def _live_step(
    step_id: str,
    title: str,
    status: str,
    detail: str,
    *,
    started: float | None = None,
    items: list[str] | None = None,
) -> dict[str, Any]:
    duration_ms = int((time.perf_counter() - started) * 1000) if started else None
    return {
        "id": step_id,
        "title": title,
        "status": status,
        "detail": detail,
        "duration_ms": duration_ms,
        "items": items or [],
    }


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
            "title": "최종 데모 스크립트",
            "path": "docs/final_demo_script.md",
            "summary": "발표용 시나리오 순서와 설명 포인트입니다.",
        },
        {
            "kind": "design",
            "title": "프론트엔드 콘솔 설계안",
            "path": "docs/frontend_demo_console_blueprint.md",
            "summary": "이 콘솔 구현의 원본 설계 계획입니다.",
        },
        {
            "kind": "demo",
            "title": "스모크 검증 요약",
            "path": "evidence/demo/20260401_smoke_validate_summary_CX_v1.md",
            "summary": "보관된 스모크 검증 근거입니다.",
        },
        {
            "kind": "demo",
            "title": "HF 실제 다운로드 요약",
            "path": "evidence/demo/20260401_hf_real_download_test_summary_CX_v1.md",
            "summary": "보관된 실제 Hugging Face 다운로드 근거입니다.",
        },
        {
            "kind": "demo",
            "title": "실제 엔드포인트 검증 요약",
            "path": "evidence/demo/20260506_live_endpoints_summary_KMW_v1.md",
            "summary": "보관된 실제 엔드포인트 검증 근거입니다.",
        },
        {
            "kind": "worklog",
            "title": "통합 어댑터 작업 기록",
            "path": "evidence/worklog/20260506_yangyu_integration_adapter_KMW_v1.md",
            "summary": "통합 작업 기록 근거입니다.",
        },
        {
            "kind": "worklog",
            "title": "대시보드/운영 작업 기록",
            "path": "evidence/worklog/20260508_dashboard_and_ops_KMW_v1.md",
            "summary": "운영 대시보드 작업 기록 근거입니다.",
        },
        {
            "kind": "worklog",
            "title": "제한 런타임 작업 기록",
            "path": "evidence/worklog/20260508_restricted_runtime_KMW_v1.md",
            "summary": "제한 런타임 근거와 한계입니다.",
        },
        {
            "kind": "tests",
            "title": "최신 전체 pytest 원본 로그",
            "path": "evidence/tests/20260520_pr17_full_pytest_raw_KMW_v1.txt",
            "summary": "보관된 전체 pytest 원본 출력입니다.",
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
        warnings.append("일부 보관 근거 파일이 누락되었습니다.")
    warnings.append("Path B/gVisor는 선택 근거이며 기본 검증 경로가 아닙니다.")
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


@router.post("/live-model/run")
def run_live_model(
    request: LiveModelRunRequest,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    repo_id = request.repo_id.strip()
    if not repo_id or "/" not in repo_id or ".." in repo_id:
        raise HTTPException(status_code=400, detail="Hugging Face repo_id는 owner/model 형식이어야 합니다.")
    request.repo_id = repo_id
    run_id = f"live-{uuid.uuid4()}"
    started_at = _now()
    steps: list[dict[str, Any]] = []

    started = time.perf_counter()
    snapshot_root = _download_hf_snapshot(request)
    steps.append(_live_step(
        "download",
        "Hugging Face 모델 다운로드",
        "PASS",
        f"{request.repo_id}@{request.revision} snapshot을 로컬 캐시에 받았습니다.",
        started=started,
        items=[str(snapshot_root)],
    ))

    started = time.perf_counter()
    artifacts, inventory, skipped = _scan_live_model_snapshot(snapshot_root, request)
    if not artifacts:
        steps.append(_live_step(
            "classify",
            "파일 분류",
            "ERROR",
            "검증 가능한 가중치, Python, config 파일을 찾지 못했습니다.",
            started=started,
        ))
        raise HTTPException(
            status_code=400,
            detail={
                "message": "검증 가능한 파일이 없습니다. include/exclude 또는 빠른 시연 옵션을 확인하세요.",
                "steps": steps,
                "skipped": skipped,
            },
        )
    summary = _live_file_summary(artifacts, skipped)
    steps.append(_live_step(
        "classify",
        "파일 분류",
        "PASS",
        (
            f"검증 대상 {summary['total_supported']}개를 찾았습니다. "
            f"가중치 {summary['weights']}개, Python {summary['python']}개, config {summary['config']}개입니다."
        ),
        started=started,
        items=[artifact.repo_path for artifact in artifacts[:20]],
    ))

    started = time.perf_counter()
    validation_request = _live_validation_request(request, run_id, snapshot_root, artifacts, inventory)
    validation_response = run_full_validation(validation_request, db=db)
    lane_results = _live_lane_results(validation_response)
    steps.append(_live_step(
        "validate",
        "파일별 검증 실행",
        validation_response.overall_status.value,
        "가중치, Python, config 검증기를 실행하고 artifact별 결과를 수집했습니다.",
        started=started,
    ))

    for lane in lane_results:
        steps.append(_live_step(
            f"lane-{lane['lane']}",
            lane["title"],
            lane["status"],
            lane["description"],
            items=[
                f"{result['artifact']['repo_path']} → {result['status']} / {result['grade']}"
                for result in lane["results"][:12]
            ],
        ))

    sandbox_summary = _live_sandbox_summary(request, validation_response)
    steps.append(_live_step(
        "sandbox",
        "샌드박스 실행 근거",
        sandbox_summary["status"],
        sandbox_summary["message"],
        items=_live_sandbox_step_items(sandbox_summary),
    ))

    steps.append(_live_step(
        "final",
        "최종 릴리스 판정",
        validation_response.overall_status.value,
        (
            f"Job decision={validation_response.overall_decision.value}, "
            f"release_action={validation_response.release_action}"
        ),
    ))

    return {
        "run_id": run_id,
        "repo_id": request.repo_id,
        "revision": request.revision,
        "started_at": started_at,
        "finished_at": _now(),
        "snapshot_root": str(snapshot_root),
        "fast_mode": request.skip_weights,
        "enable_path_b": request.enable_path_b,
        "file_summary": summary,
        "skipped": {key: value[:100] for key, value in skipped.items()},
        "steps": steps,
        "artifacts": [to_jsonable(artifact) for artifact in artifacts],
        "lane_results": lane_results,
        "sandbox_summary": sandbox_summary,
        "validation_response": to_jsonable(validation_response),
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
