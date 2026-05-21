import hashlib
from pathlib import PurePosixPath

from analyzer.orchestrator import _requires_b2_sandbox, build_minimal_request, run_validation_job
from analyzer.schemas import (
    ArtifactRef,
    ArtifactValidationResult,
    CodeGrade,
    FileKind,
    PolicyInfo,
    RouteKind,
    ValidationStatus,
)


def _make_policy() -> PolicyInfo:
    return PolicyInfo(
        policy_version="policy-2026.05.20",
        whitelist_version="wl-2026.05.20",
        opcode_policy_version="opcode-2026.05.20",
        config_schema_version="cfg-2026.05.20",
        runtime_profile_version="rt-2026.05.20",
    )


def _make_artifact(repo_path: str, source_text: str) -> ArtifactRef:
    digest = hashlib.sha256(f"{repo_path}:{source_text}".encode("utf-8")).hexdigest()
    file_name = PurePosixPath(repo_path).name
    return ArtifactRef(
        artifact_id=f"sha256:{digest}",
        repo_path=repo_path,
        file_name=file_name,
        file_kind=FileKind.PYTHON,
        detected_extension=".py",
        media_type=None,
        size_bytes=len(source_text.encode("utf-8")),
        sha256=digest,
        source_url=f"https://huggingface.co/org/demo/resolve/main/{repo_path}",
        temp_local_path=f"/tmp/{file_name}",
        referenced_by=[],
        is_generated=False,
    )


def _b1_modeling_source() -> str:
    return (
        "import torch.nn.functional as F\n"
        "from torch import nn\n"
        "class DemoModel:\n"
        "    def forward(self, x):\n"
        "        y = nn.Linear(4, 2)\n"
        "        return F.relu(y)\n"
    )


def test_route_kind_only_sandbox_results_do_not_call_sandbox_runner() -> None:
    policy = _make_policy()
    sources = {
        "modeling_dynamic.py": (
            "class DemoModel:\n"
            "    def forward(self, module, name):\n"
            "        fn = getattr(module, name)\n"
            "        return fn()\n"
        ),
        "configuration_incomplete.py": (
            "from transformers import PretrainedConfig\n"
            "class DemoConfig(PretrainedConfig):\n"
            "    def __init__(self, hidden_size=128, **kwargs):\n"
            "        super().__init__(**kwargs)\n"
            "        self.hidden_size = hidden_size\n"
        ),
        "random_script.py": "def helper(x):\n    return x\n",
        "tokenization_demo.py": "class DemoTokenizer:\n    pass\n",
    }
    request = build_minimal_request(
        request_id="req-route-only",
        job_id="job-route-only",
        policy=policy,
        artifacts=[_make_artifact(path, source) for path, source in sources.items()],
    )
    sandbox_calls: list[str] = []

    def sandbox_runner(result):
        sandbox_calls.append(result.artifact.repo_path)
        raise AssertionError("route-only result must not call sandbox runner")

    response = run_validation_job(
        request,
        source_loader=sources,
        sandbox_check_loader=sandbox_runner,
    )

    assert sandbox_calls == []
    assert {item.artifact.repo_path for item in response.artifact_results} == set(sources)
    for result in response.artifact_results:
        assert result.route_kind is RouteKind.CODE_SANDBOX_RUNTIME
        assert _requires_b2_sandbox(result) is False
        assert "sandbox_check" not in result.details

    roles = {
        item.artifact.repo_path: item.details["role_classification"]["role"]
        for item in response.artifact_results
    }
    assert roles["configuration_incomplete.py"] == "CONFIGURATION"
    assert roles["random_script.py"] == "UNKNOWN"
    assert roles["tokenization_demo.py"] == "PREPROCESSING"
    assert response.overall_status is ValidationStatus.PENDING_REVIEW


def test_b2_target_without_runner_or_resolver_keeps_not_run_sandbox_check() -> None:
    policy = _make_policy()
    source = (
        "import torch.nn.functional as F\n"
        "from torch import nn\n"
        "class DemoModel:\n"
        "    def forward(self, x):\n"
        "        y = nn.Linear(4, 2)\n"
        "        return F.relu(y)\n"
    )
    artifact = _make_artifact("modeling_runtime_missing.py", source)
    request = build_minimal_request(
        request_id="req-b2-not-configured",
        job_id="job-b2-not-configured",
        policy=policy,
        artifacts=[artifact],
    )

    response = run_validation_job(
        request,
        source_loader={artifact.repo_path: source},
    )

    result = response.artifact_results[0]
    assert _requires_b2_sandbox(result) is True
    assert result.status is ValidationStatus.PENDING_REVIEW
    assert response.overall_status is ValidationStatus.PENDING_REVIEW

    sandbox_check = result.details["sandbox_check"]
    assert sandbox_check["decision"] == "NOT_RUN"
    assert sandbox_check["deployable"] is False
    assert sandbox_check["policy_gate"]["reason_code"] == "SANDBOX_NOT_CONFIGURED"
    assert sandbox_check["execution"] == {
        "import_status": "not_run",
        "instantiate_status": "not_run",
        "forward_status": "not_run",
    }


def test_b2_target_with_runner_but_without_resolver_does_not_call_runner() -> None:
    policy = _make_policy()
    source = (
        "import torch.nn.functional as F\n"
        "from torch import nn\n"
        "class DemoModel:\n"
        "    def forward(self, x):\n"
        "        y = nn.Linear(4, 2)\n"
        "        return F.relu(y)\n"
    )
    artifact = _make_artifact("modeling_needs_resolver.py", source)
    request = build_minimal_request(
        request_id="req-b2-no-resolver",
        job_id="job-b2-no-resolver",
        policy=policy,
        artifacts=[artifact],
    )
    sandbox_calls: list[str] = []

    def sandbox_runner(result):
        sandbox_calls.append(result.artifact.repo_path)
        raise AssertionError("sandbox runner must not run without source_resolver")

    response = run_validation_job(
        request,
        source_loader={artifact.repo_path: source},
        sandbox_check_loader=sandbox_runner,
    )

    result = response.artifact_results[0]
    assert _requires_b2_sandbox(result) is True
    assert sandbox_calls == []
    assert result.status is ValidationStatus.PENDING_REVIEW
    assert result.details["sandbox_check"]["decision"] == "NOT_RUN"
    assert result.details["sandbox_check"]["policy_gate"]["reason_code"] == "SANDBOX_NOT_CONFIGURED"


def _run_runtime_failure_boundary(repo_path: str, runtime_check: dict) -> tuple[ArtifactValidationResult, list[str]]:
    policy = _make_policy()
    source = _b1_modeling_source()
    artifact = _make_artifact(repo_path, source)
    request = build_minimal_request(
        request_id=f"req-{repo_path}",
        job_id=f"job-{repo_path}",
        policy=policy,
        artifacts=[artifact],
    )
    sandbox_calls: list[str] = []

    def sandbox_runner(result):
        sandbox_calls.append(result.artifact.repo_path)
        raise AssertionError("runtime failure result must not call sandbox runner")

    response = run_validation_job(
        request,
        source_loader={artifact.repo_path: source},
        runtime_check_loader={artifact.repo_path: runtime_check},
        source_resolver=object(),
        sandbox_check_loader=sandbox_runner,
    )
    return response.artifact_results[0], sandbox_calls


def test_runtime_fail_security_event_does_not_call_b2_sandbox_runner() -> None:
    result, sandbox_calls = _run_runtime_failure_boundary(
        "modeling_runtime_fail.py",
        {
            "status": "FAIL",
            "runtime_mode": "RESTRICTED_RUNTIME",
            "blocked_imports": ["subprocess"],
        },
    )

    assert sandbox_calls == []
    assert _requires_b2_sandbox(result) is False
    assert result.grade is CodeGrade.C
    assert result.status is ValidationStatus.BLOCK
    assert result.route_kind is RouteKind.CODE_AST_SCAN
    assert "sandbox_check" not in result.details


def test_runtime_timeout_manual_review_does_not_call_b2_sandbox_runner() -> None:
    result, sandbox_calls = _run_runtime_failure_boundary(
        "modeling_runtime_timeout.py",
        {
            "status": "TIMEOUT",
            "runtime_mode": "RESTRICTED_RUNTIME",
            "exception_class": "TimeoutError",
        },
    )

    assert sandbox_calls == []
    assert _requires_b2_sandbox(result) is False
    assert result.grade is CodeGrade.C
    assert result.status is ValidationStatus.PENDING_REVIEW
    assert result.route_kind is RouteKind.CODE_AST_SCAN
    assert "sandbox_check" not in result.details


def test_runtime_memory_limit_manual_review_does_not_call_b2_sandbox_runner() -> None:
    result, sandbox_calls = _run_runtime_failure_boundary(
        "modeling_runtime_memory.py",
        {
            "status": "MEMORY_LIMIT",
            "runtime_mode": "RESTRICTED_RUNTIME",
            "exception_class": "MemoryError",
        },
    )

    assert sandbox_calls == []
    assert _requires_b2_sandbox(result) is False
    assert result.grade is CodeGrade.C
    assert result.status is ValidationStatus.PENDING_REVIEW
    assert result.route_kind is RouteKind.CODE_AST_SCAN
    assert "sandbox_check" not in result.details
