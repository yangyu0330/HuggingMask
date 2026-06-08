import hashlib
import json
from pathlib import Path, PurePosixPath

from analyzer.orchestrator import _requires_b2_sandbox, build_minimal_request, run_validation_job
from analyzer.schemas import ArtifactRef, FileKind, PolicyInfo, RouteKind, ValidationStatus
from analyzer.snapshot_resolver import SnapshotSourceResolver, build_source_loader
from sandbox.b2.pipeline import B2RunnerContext


def _make_policy() -> PolicyInfo:
    return PolicyInfo(
        policy_version="policy-2026.05.20",
        whitelist_version="wl-2026.05.20",
        opcode_policy_version="opcode-2026.05.20",
        config_schema_version="cfg-2026.05.20",
        runtime_profile_version="rt-2026.05.20",
    )


def _write(root: Path, repo_path: str, source: str | bytes) -> str:
    data = source.encode("utf-8") if isinstance(source, str) else source
    path = root.joinpath(*PurePosixPath(repo_path).parts)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return hashlib.sha256(data).hexdigest()


def _make_artifact(repo_path: str, file_kind: FileKind, source: str | bytes) -> ArtifactRef:
    data = source.encode("utf-8") if isinstance(source, str) else source
    digest = hashlib.sha256(data).hexdigest()
    file_name = PurePosixPath(repo_path).name
    suffix = PurePosixPath(repo_path).suffix
    return ArtifactRef(
        artifact_id=f"sha256:{digest}",
        repo_path=repo_path,
        file_name=file_name,
        file_kind=file_kind,
        detected_extension=suffix or (".json" if file_kind is FileKind.CONFIG_JSON else ".py"),
        media_type="application/json" if file_kind is FileKind.CONFIG_JSON else None,
        size_bytes=len(data),
        sha256=digest,
        source_url=f"https://huggingface.co/org/demo/resolve/main/{repo_path}",
        temp_local_path=f"/tmp/{file_name}",
        referenced_by=[],
        is_generated=False,
    )


def _b2_source(class_name: str = "DemoModel") -> str:
    return (
        "import torch\n"
        f"class {class_name}:\n"
        "    def forward(self, x):\n"
        "        return torch.special.expit(x)\n"
    )


def _clean_runner_result(context: B2RunnerContext) -> dict:
    return {
        "schema_version": "1.0",
        "request_id": context.request_id,
        "nonce": context.nonce,
        "manifest_verified": True,
        "import_status": "success",
        "instantiate_status": "success",
        "forward_status": "success",
        "exception_class": None,
        "exception_message": None,
    }


def _clean_observed_result(context: B2RunnerContext) -> dict:
    """관측된 clean 런 모델링 — strace 관측 명시(fail-closed 기본). 실 러너는 명시 set."""
    return {"runner_result": _clean_runner_result(context), "strace_observed": True}


def test_direct_b2_uses_fake_pipeline_runner_and_attaches_sandbox_check(tmp_path: Path) -> None:
    snapshot_root = tmp_path / "snapshot"
    source = _b2_source("DirectModel")
    _write(snapshot_root, "modeling_direct.py", source)
    artifact = _make_artifact("modeling_direct.py", FileKind.PYTHON, source)
    request = build_minimal_request(
        request_id="req-direct-pipeline",
        job_id="job-direct-pipeline",
        policy=_make_policy(),
        artifacts=[artifact],
    )
    request.model_snapshot_root = str(snapshot_root)
    resolver = SnapshotSourceResolver.from_request(request)
    contexts: list[B2RunnerContext] = []

    def runner(context: B2RunnerContext) -> dict:
        contexts.append(context)
        return _clean_observed_result(context)

    response = run_validation_job(
        request,
        source_loader=build_source_loader(resolver),
        source_resolver=resolver,
        b2_runner=runner,
        b2_output_dir=tmp_path / "b2-out",
        revision="rev-phase7",
    )

    result = response.artifact_results[0]
    sandbox_check = result.details["sandbox_check"]
    assert contexts and contexts[0].primary_result.artifact.repo_path == "modeling_direct.py"
    assert contexts[0].manifest.revision == "rev-phase7"
    assert sandbox_check["decision"] == "B2_POLICY_REVIEW_REQUIRED"
    assert sandbox_check["deployable"] is False
    assert sandbox_check["policy_gate"]["reason_code"] == "SANDBOX_POLICY_GATE_REQUIRED"
    assert result.status is ValidationStatus.PENDING_REVIEW


def test_direct_b2_pipeline_uses_later_dependency_result(tmp_path: Path) -> None:
    snapshot_root = tmp_path / "snapshot"
    main_source = (
        "import helper\n"
        "import torch\n"
        "class DirectModel:\n"
        "    def forward(self, x):\n"
        "        return helper.apply(torch.special.expit(x))\n"
    )
    helper_source = "def apply(x):\n    return x\n"
    _write(snapshot_root, "modeling_direct.py", main_source)
    _write(snapshot_root, "helper.py", helper_source)
    main_artifact = _make_artifact("modeling_direct.py", FileKind.PYTHON, main_source)
    helper_artifact = _make_artifact("helper.py", FileKind.PYTHON, helper_source)
    request = build_minimal_request(
        request_id="req-direct-dependency",
        job_id="job-direct-dependency",
        policy=_make_policy(),
        artifacts=[main_artifact, helper_artifact],
    )
    request.model_snapshot_root = str(snapshot_root)
    resolver = SnapshotSourceResolver.from_request(request)
    contexts: list[B2RunnerContext] = []

    response = run_validation_job(
        request,
        source_loader=build_source_loader(resolver),
        source_resolver=resolver,
        b2_runner=lambda context: contexts.append(context) or _clean_observed_result(context),
        b2_output_dir=tmp_path / "b2-out",
    )

    by_path = {item.artifact.repo_path: item for item in response.artifact_results}
    assert [context.primary_result.artifact.repo_path for context in contexts] == ["modeling_direct.py"]
    assert {item.path for item in contexts[0].manifest.files} == {"helper.py", "modeling_direct.py"}
    assert by_path["modeling_direct.py"].details["sandbox_check"]["decision"] == "B2_POLICY_REVIEW_REQUIRED"


def test_auto_map_sibling_b2_uses_pipeline_and_parent_summary_refreshes(tmp_path: Path) -> None:
    snapshot_root = tmp_path / "snapshot"
    config_source = json.dumps({"auto_map": {"AutoModel": "modeling_linked.LinkedModel"}})
    linked_source = _b2_source("LinkedModel")
    _write(snapshot_root, "config.json", config_source)
    _write(snapshot_root, "modeling_linked.py", linked_source)
    config_artifact = _make_artifact("config.json", FileKind.CONFIG_JSON, config_source)
    request = build_minimal_request(
        request_id="req-sibling-pipeline",
        job_id="job-sibling-pipeline",
        policy=_make_policy(),
        artifacts=[config_artifact],
    )
    request.model_snapshot_root = str(snapshot_root)
    resolver = SnapshotSourceResolver.from_request(request)
    contexts: list[B2RunnerContext] = []

    def runner(context: B2RunnerContext) -> dict:
        contexts.append(context)
        return {
            "runner_result": _clean_runner_result(context),
            "security_events": {"blocked_reads": [{"path": "/etc/passwd"}]},
        }

    response = run_validation_job(
        request,
        source_loader=build_source_loader(resolver),
        source_resolver=resolver,
        b2_runner=runner,
        b2_output_dir=tmp_path / "b2-out",
    )

    by_path = {item.artifact.repo_path: item for item in response.artifact_results}
    cfg_result = by_path["config.json"]
    sibling_result = by_path["modeling_linked.py"]
    assert [context.primary_result.artifact.repo_path for context in contexts] == ["modeling_linked.py"]
    assert sibling_result.details["sandbox_check"]["decision"] == "BLOCKED_SECURITY_EVENT"
    assert sibling_result.details["sandbox_check"]["policy_gate"]["reason_code"] == "SANDBOX_SECURITY_EVENT"
    assert cfg_result.details["linked_code_results"][0]["details"]["sandbox_check"]["decision"] == "BLOCKED_SECURITY_EVENT"
    assert cfg_result.details["linked_code_edges"][0]["sandbox_decision"] == "BLOCKED_SECURITY_EVENT"


def test_non_b2_code_sandbox_runtime_does_not_call_pipeline_runner(tmp_path: Path) -> None:
    snapshot_root = tmp_path / "snapshot"
    source = (
        "class DemoModel:\n"
        "    def forward(self, module, name):\n"
        "        fn = getattr(module, name)\n"
        "        return fn()\n"
    )
    _write(snapshot_root, "modeling_dynamic.py", source)
    artifact = _make_artifact("modeling_dynamic.py", FileKind.PYTHON, source)
    request = build_minimal_request(
        request_id="req-non-b2",
        job_id="job-non-b2",
        policy=_make_policy(),
        artifacts=[artifact],
    )
    request.model_snapshot_root = str(snapshot_root)
    resolver = SnapshotSourceResolver.from_request(request)
    calls: list[B2RunnerContext] = []

    response = run_validation_job(
        request,
        source_loader=build_source_loader(resolver),
        source_resolver=resolver,
        b2_runner=lambda context: calls.append(context) or _clean_runner_result(context),
        b2_output_dir=tmp_path / "b2-out",
    )

    result = response.artifact_results[0]
    assert result.route_kind is RouteKind.CODE_SANDBOX_RUNTIME
    assert _requires_b2_sandbox(result) is False
    assert calls == []
    assert "sandbox_check" not in result.details


def test_missing_resolver_or_runner_keeps_not_run_fallback(tmp_path: Path) -> None:
    snapshot_root = tmp_path / "snapshot"
    source = _b2_source("NeedsSandbox")
    _write(snapshot_root, "modeling_needs_sandbox.py", source)
    artifact = _make_artifact("modeling_needs_sandbox.py", FileKind.PYTHON, source)
    request = build_minimal_request(
        request_id="req-not-configured",
        job_id="job-not-configured",
        policy=_make_policy(),
        artifacts=[artifact],
    )
    request.model_snapshot_root = str(snapshot_root)
    resolver = SnapshotSourceResolver.from_request(request)
    calls: list[B2RunnerContext] = []

    no_resolver_response = run_validation_job(
        request,
        source_loader={artifact.repo_path: source},
        b2_runner=lambda context: calls.append(context) or _clean_runner_result(context),
        b2_output_dir=tmp_path / "b2-out-no-resolver",
    )
    no_runner_response = run_validation_job(
        request,
        source_loader=build_source_loader(resolver),
        source_resolver=resolver,
        b2_output_dir=tmp_path / "b2-out-no-runner",
    )

    assert calls == []
    assert no_resolver_response.artifact_results[0].details["sandbox_check"]["decision"] == "NOT_RUN"
    assert no_resolver_response.artifact_results[0].details["sandbox_check"]["policy_gate"]["reason_code"] == (
        "SANDBOX_NOT_CONFIGURED"
    )
    assert no_runner_response.artifact_results[0].details["sandbox_check"]["decision"] == "NOT_RUN"
    assert no_runner_response.artifact_results[0].details["sandbox_check"]["policy_gate"]["reason_code"] == (
        "SANDBOX_NOT_CONFIGURED"
    )


def test_sandbox_check_loader_takes_priority_over_pipeline_runner(tmp_path: Path) -> None:
    snapshot_root = tmp_path / "snapshot"
    source = _b2_source("LegacyLoaderModel")
    _write(snapshot_root, "modeling_legacy.py", source)
    artifact = _make_artifact("modeling_legacy.py", FileKind.PYTHON, source)
    request = build_minimal_request(
        request_id="req-loader-priority",
        job_id="job-loader-priority",
        policy=_make_policy(),
        artifacts=[artifact],
    )
    request.model_snapshot_root = str(snapshot_root)
    resolver = SnapshotSourceResolver.from_request(request)
    pipeline_calls: list[B2RunnerContext] = []
    loader_calls: list[str] = []

    def sandbox_loader(result):
        loader_calls.append(result.artifact.repo_path)
        return {
            "decision": "B2_POLICY_REVIEW_REQUIRED",
            "deployable": False,
            "policy_gate": {"reason_code": "LEGACY_LOADER"},
        }

    response = run_validation_job(
        request,
        source_loader=build_source_loader(resolver),
        source_resolver=resolver,
        sandbox_check_loader=sandbox_loader,
        b2_runner=lambda context: pipeline_calls.append(context) or _clean_runner_result(context),
        b2_output_dir=tmp_path / "b2-out",
    )

    sandbox_check = response.artifact_results[0].details["sandbox_check"]
    assert loader_calls == ["modeling_legacy.py"]
    assert pipeline_calls == []
    assert sandbox_check["policy_gate"]["reason_code"] == "LEGACY_LOADER"


def test_pipeline_malformed_runner_result_is_preserved_in_sandbox_check(tmp_path: Path) -> None:
    snapshot_root = tmp_path / "snapshot"
    source = _b2_source("MalformedRunnerModel")
    _write(snapshot_root, "modeling_malformed_runner.py", source)
    artifact = _make_artifact("modeling_malformed_runner.py", FileKind.PYTHON, source)
    request = build_minimal_request(
        request_id="req-malformed-runner",
        job_id="job-malformed-runner",
        policy=_make_policy(),
        artifacts=[artifact],
    )
    request.model_snapshot_root = str(snapshot_root)
    resolver = SnapshotSourceResolver.from_request(request)

    response = run_validation_job(
        request,
        source_loader=build_source_loader(resolver),
        source_resolver=resolver,
        b2_runner=lambda context: {"schema_version": "1.0"},
        b2_output_dir=tmp_path / "b2-out",
    )

    sandbox_check = response.artifact_results[0].details["sandbox_check"]
    assert sandbox_check["decision"] == "FUNCTIONAL_REVIEW_REQUIRED"
    assert sandbox_check["deployable"] is False
    assert sandbox_check["policy_gate"]["reason_code"] == "RUNNER_DIAGNOSTICS_MALFORMED"
