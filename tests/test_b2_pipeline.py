import hashlib
import json
from pathlib import Path, PurePosixPath

from analyzer.orchestrator import build_minimal_request, run_validation_job
from analyzer.schemas import ArtifactRef, ArtifactValidationResult, FileKind, PolicyInfo
from analyzer.snapshot_resolver import SnapshotResolveError, SnapshotSourceResolver, build_source_loader
from analyzer.validators.code_validator import validate_python_artifact
from sandbox.b2.pipeline import B2RunnerContext, run_b2_sandbox_pipeline
from sandbox.b2.schemas import B2_INPUT_MANIFEST_FILENAME


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


def _artifact(repo_path: str, file_kind: FileKind, source: str | bytes) -> ArtifactRef:
    data = source.encode("utf-8") if isinstance(source, str) else source
    digest = hashlib.sha256(data).hexdigest()
    file_name = PurePosixPath(repo_path).name
    return ArtifactRef(
        artifact_id=f"sha256:{digest}",
        repo_path=repo_path,
        file_name=file_name,
        file_kind=file_kind,
        detected_extension=PurePosixPath(repo_path).suffix,
        media_type=None,
        size_bytes=len(data),
        sha256=digest,
        source_url=f"https://huggingface.co/org/demo/resolve/main/{repo_path}",
        temp_local_path=f"/tmp/{file_name}",
        referenced_by=[],
        is_generated=False,
    )


def _primary_source(import_line: str = "") -> str:
    return (
        f"{import_line}"
        "import torch\n"
        "class DemoModel:\n"
        "    def forward(self, x):\n"
        "        return torch.special.expit(x)\n"
    )


def _validate(repo_path: str, source: str) -> ArtifactValidationResult:
    return validate_python_artifact(
        _artifact(repo_path, FileKind.PYTHON, source),
        source,
        _make_policy(),
        runtime_check={"status": "SKIPPED", "runtime_mode": "RESTRICTED_RUNTIME"},
    )


def _clean_runner(context: B2RunnerContext) -> dict:
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


def _clean_observed(context: B2RunnerContext) -> dict:
    """관측된 clean 런 모델링 — strace 관측을 명시(fail-closed 기본).

    pipeline은 strace_observed 미보고(None)를 '관측 안 함'(fail-closed)으로 본다.
    실 B2HostRunner는 명시 set하므로, fake도 clean 경로를 보려면 명시해야 한다.
    """
    return {"runner_result": _clean_runner(context), "strace_observed": True}


def test_clean_fake_runner_remains_policy_review_and_not_deployable(tmp_path: Path) -> None:
    root = tmp_path / "snapshot"
    primary = _primary_source()
    _write(root, "modeling_demo.py", primary)
    _write(root, "config.json", b'{"model_type":"demo"}\n')
    resolver = SnapshotSourceResolver(model_snapshot_root=root)
    primary_result = _validate("modeling_demo.py", primary)
    contexts: list[B2RunnerContext] = []

    def runner(context: B2RunnerContext) -> dict:
        contexts.append(context)
        return _clean_observed(context)

    check = run_b2_sandbox_pipeline(
        request_id="req-b2",
        job_id="job-b2",
        revision="abc123",
        policy_version=_make_policy().policy_version,
        source_resolver=resolver,
        output_dir=tmp_path / "out",
        primary_result=primary_result,
        candidate_results=[],
        runner=runner,
        nonce="nonce-123",
        created_at="2026-05-20T00:00:00Z",
    )

    assert check["decision"] == "B2_POLICY_REVIEW_REQUIRED"
    assert check["deployable"] is False
    assert check["policy_gate"]["reason_code"] == "SANDBOX_POLICY_GATE_REQUIRED"
    assert len(contexts) == 1
    assert contexts[0].manifest.primary_repo_path == "modeling_demo.py"
    assert (contexts[0].input_dir / B2_INPUT_MANIFEST_FILENAME).is_file()
    assert (contexts[0].input_dir / "config.json").is_file()


def test_clean_runner_without_strace_report_is_fail_closed(tmp_path: Path) -> None:
    # pipeline.py fail-closed: 러너가 clean이어도 strace_observed를 보고하지 않으면
    # (bare runner_result) 관측 안 함으로 보고 require_runsc_strace 게이트가 발화한다.
    # (이전 else True 기본은 미보고를 '관측됨'으로 가정해 fail-open이었음.)
    root = tmp_path / "snapshot"
    primary = _primary_source()
    _write(root, "modeling_demo.py", primary)
    _write(root, "config.json", b'{"model_type":"demo"}\n')
    resolver = SnapshotSourceResolver(model_snapshot_root=root)
    primary_result = _validate("modeling_demo.py", primary)

    check = run_b2_sandbox_pipeline(
        request_id="req-b2",
        job_id="job-b2",
        revision="abc123",
        policy_version=_make_policy().policy_version,
        source_resolver=resolver,
        output_dir=tmp_path / "out",
        primary_result=primary_result,
        candidate_results=[],
        runner=_clean_runner,  # strace_observed 미보고(bare runner_result)
        nonce="nonce-123",
        created_at="2026-05-20T00:00:00Z",
    )

    assert check["decision"] == "LOG_INCOMPLETE"
    assert check["policy_gate"]["reason_code"] == "SANDBOX_STRACE_NOT_OBSERVED"
    assert check["deployable"] is False


def test_runner_output_envelope_forwards_security_events_and_runtime_evidence(tmp_path: Path) -> None:
    root = tmp_path / "snapshot"
    primary = _primary_source()
    _write(root, "modeling_demo.py", primary)
    resolver = SnapshotSourceResolver(model_snapshot_root=root)
    primary_result = _validate("modeling_demo.py", primary)

    def runner(context: B2RunnerContext) -> dict:
        return {
            "runner_result": _clean_runner(context),
            "runtime_evidence": {
                "runtime": "runsc",
                "network_mode": "none",
                "rootfs_readonly": True,
            },
            "security_events": {
                "blocked_writes": [{"path": "/sandbox/input/modeling_demo.py"}],
            },
            "artifacts": {"runner_log": "logs/b2-runner.log"},
        }

    check = run_b2_sandbox_pipeline(
        request_id="req-b2",
        job_id="job-b2",
        revision="abc123",
        policy_version=_make_policy().policy_version,
        source_resolver=resolver,
        output_dir=tmp_path / "out",
        primary_result=primary_result,
        candidate_results=[],
        runner=runner,
        nonce="nonce-123",
    )

    assert check["decision"] == "BLOCKED_SECURITY_EVENT"
    assert check["policy_gate"]["reason_code"] == "SANDBOX_SECURITY_EVENT"
    assert check["runtime_evidence"]["runtime"] == "runsc"
    assert check["runtime_evidence"]["rootfs_readonly"] is True
    assert check["security_events"]["blocked_writes"] == [{"path": "/sandbox/input/modeling_demo.py"}]
    assert check["artifacts"]["input_manifest"] == f"input/{B2_INPUT_MANIFEST_FILENAME}"
    assert check["artifacts"]["runner_log"] == "logs/b2-runner.log"


def test_manifest_build_failure_does_not_call_runner(tmp_path: Path) -> None:
    root = tmp_path / "snapshot"
    primary = _primary_source("import missing_local\n")
    _write(root, "modeling_demo.py", primary)
    calls: list[B2RunnerContext] = []

    check = run_b2_sandbox_pipeline(
        request_id="req-b2",
        job_id="job-b2",
        revision="abc123",
        policy_version=_make_policy().policy_version,
        source_resolver=SnapshotSourceResolver(model_snapshot_root=root),
        output_dir=tmp_path / "out",
        primary_result=_validate("modeling_demo.py", primary),
        candidate_results=[],
        runner=lambda context: calls.append(context) or _clean_runner(context),
        nonce="nonce-123",
    )

    assert calls == []
    assert check["decision"] == "BLOCKED_SECURITY_EVENT"
    assert check["deployable"] is False
    assert check["policy_gate"]["reason_code"] == "UNRESOLVED_DEPENDENCY"
    assert check["policy_gate"]["stage"] == "manifest_build"


class _StagingFailureResolver:
    def __init__(self, root: Path) -> None:
        self._resolver = SnapshotSourceResolver(model_snapshot_root=root)
        self._counts: dict[str, int] = {}

    def resolve(self, repo_path: str):
        self._counts[repo_path] = self._counts.get(repo_path, 0) + 1
        if repo_path == "modeling_demo.py" and self._counts[repo_path] >= 4:
            return SnapshotResolveError.HASH_MISMATCH
        return self._resolver.resolve(repo_path)


def test_staging_failure_does_not_call_runner(tmp_path: Path) -> None:
    root = tmp_path / "snapshot"
    primary = _primary_source()
    _write(root, "modeling_demo.py", primary)
    calls: list[B2RunnerContext] = []

    check = run_b2_sandbox_pipeline(
        request_id="req-b2",
        job_id="job-b2",
        revision="abc123",
        policy_version=_make_policy().policy_version,
        source_resolver=_StagingFailureResolver(root),  # type: ignore[arg-type]
        output_dir=tmp_path / "out",
        primary_result=_validate("modeling_demo.py", primary),
        candidate_results=[],
        runner=lambda context: calls.append(context) or _clean_runner(context),
        nonce="nonce-123",
    )

    assert calls == []
    assert check["decision"] == "BLOCKED_SECURITY_EVENT"
    assert check["policy_gate"]["reason_code"] == "HASH_MISMATCH"
    assert check["policy_gate"]["stage"] == "staging"


def test_runner_malformed_nonce_mismatch_and_manifest_unverified_fail_closed(tmp_path: Path) -> None:
    root = tmp_path / "snapshot"
    primary = _primary_source()
    _write(root, "modeling_demo.py", primary)
    resolver = SnapshotSourceResolver(model_snapshot_root=root)
    primary_result = _validate("modeling_demo.py", primary)

    def run_with(runner_result: dict) -> dict:
        return run_b2_sandbox_pipeline(
            request_id="req-b2",
            job_id="job-b2",
            revision="abc123",
            policy_version=_make_policy().policy_version,
            source_resolver=resolver,
            output_dir=tmp_path / hashlib.sha256(json.dumps(runner_result, sort_keys=True).encode()).hexdigest(),
            primary_result=primary_result,
            candidate_results=[],
            runner=lambda context: runner_result,
            nonce="nonce-123",
        )

    malformed = run_with({"schema_version": "1.0"})
    nonce_mismatch = run_with({**_clean_runner(B2RunnerContext("", "", "", "", primary_result, [], None, tmp_path, "wrong")), "request_id": "req-b2"})
    unverified = run_with(
        {
            "schema_version": "1.0",
            "request_id": "req-b2",
            "nonce": "nonce-123",
            "manifest_verified": False,
            "import_status": "success",
            "instantiate_status": "success",
            "forward_status": "success",
        }
    )

    assert malformed["decision"] == "FUNCTIONAL_REVIEW_REQUIRED"
    assert malformed["policy_gate"]["reason_code"] == "RUNNER_DIAGNOSTICS_MALFORMED"
    assert nonce_mismatch["decision"] == "FUNCTIONAL_REVIEW_REQUIRED"
    assert nonce_mismatch["policy_gate"]["reason_code"] == "RUNNER_DIAGNOSTICS_NONCE_MISMATCH"
    assert unverified["decision"] == "BLOCKED_SECURITY_EVENT"
    assert unverified["policy_gate"]["reason_code"] == "SANDBOX_INPUT_MANIFEST_NOT_VERIFIED"
    assert unverified["deployable"] is False


def test_direct_b2_and_auto_map_sibling_results_can_use_pipeline(tmp_path: Path) -> None:
    root = tmp_path / "snapshot"
    config_source = json.dumps({"auto_map": {"AutoModelForCausalLM": "modeling_linked.LinkedModel"}})
    linked_source = (
        "import torch\n"
        "class LinkedModel:\n"
        "    def forward(self, x):\n"
        "        return torch.special.expit(x)\n"
    )
    direct_source = _primary_source()
    _write(root, "config.json", config_source)
    _write(root, "modeling_linked.py", linked_source)
    _write(root, "modeling_demo.py", direct_source)

    request = build_minimal_request(
        request_id="req-flow",
        job_id="job-flow",
        policy=_make_policy(),
        artifacts=[
            _artifact("config.json", FileKind.CONFIG_JSON, config_source),
            _artifact("modeling_demo.py", FileKind.PYTHON, direct_source),
        ],
    )
    request.model_snapshot_root = str(root)
    resolver = SnapshotSourceResolver.from_request(request)
    response = run_validation_job(
        request,
        source_loader=build_source_loader(resolver),
        source_resolver=resolver,
    )
    by_path = {item.artifact.repo_path: item for item in response.artifact_results}
    linked_result = by_path["modeling_linked.py"]
    direct_result = by_path["modeling_demo.py"]

    linked_contexts: list[B2RunnerContext] = []
    direct_contexts: list[B2RunnerContext] = []

    linked_check = run_b2_sandbox_pipeline(
        request_id="req-flow",
        job_id="job-flow",
        revision="abc123",
        policy_version=_make_policy().policy_version,
        source_resolver=resolver,
        output_dir=tmp_path / "linked-out",
        primary_result=linked_result,
        candidate_results=response.artifact_results,
        runner=lambda context: linked_contexts.append(context) or _clean_observed(context),
        nonce="linked-nonce",
    )
    direct_check = run_b2_sandbox_pipeline(
        request_id="req-flow",
        job_id="job-flow",
        revision="abc123",
        policy_version=_make_policy().policy_version,
        source_resolver=resolver,
        output_dir=tmp_path / "direct-out",
        primary_result=direct_result,
        candidate_results=response.artifact_results,
        runner=lambda context: direct_contexts.append(context) or _clean_observed(context),
        nonce="direct-nonce",
    )

    assert linked_check["decision"] == "B2_POLICY_REVIEW_REQUIRED"
    assert direct_check["decision"] == "B2_POLICY_REVIEW_REQUIRED"
    assert linked_check["deployable"] is False
    assert direct_check["deployable"] is False
    assert linked_contexts[0].manifest.target.source == "auto_map"
    assert linked_contexts[0].manifest.target.target_class == "LinkedModel"
    assert linked_contexts[0].manifest.target.auto_map_key == "AutoModelForCausalLM"
    assert direct_contexts[0].manifest.target.source == "direct_python"
