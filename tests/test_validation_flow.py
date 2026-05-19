import hashlib
import json
from pathlib import PurePosixPath

from analyzer.orchestrator import build_minimal_request, dispatch_artifacts, run_validation_job
from analyzer.schemas import ArtifactRef, FileKind, PolicyInfo, RouteKind, ValidationStatus


def _make_policy() -> PolicyInfo:
    return PolicyInfo(
        policy_version="policy-2026.04.20",
        whitelist_version="wl-2026.04.20",
        opcode_policy_version="opcode-2026.04.20",
        config_schema_version="cfg-2026.04.20",
        runtime_profile_version="rt-2026.04.20",
    )


def _make_artifact(repo_path: str, file_kind: FileKind, source_text: str) -> ArtifactRef:
    digest = hashlib.sha256(f"{repo_path}:{source_text}".encode("utf-8")).hexdigest()
    file_name = PurePosixPath(repo_path).name
    extension = PurePosixPath(repo_path).suffix or (".json" if file_kind in {FileKind.CONFIG_JSON, FileKind.TOKENIZER_CONFIG_JSON} else ".py")
    media_type = "application/json" if file_kind in {FileKind.CONFIG_JSON, FileKind.TOKENIZER_CONFIG_JSON} else None
    return ArtifactRef(
        artifact_id=f"sha256:{digest}",
        repo_path=repo_path,
        file_name=file_name,
        file_kind=file_kind,
        detected_extension=extension,
        media_type=media_type,
        size_bytes=len(source_text.encode("utf-8")),
        sha256=digest,
        source_url=f"https://huggingface.co/org/demo/resolve/main/{repo_path}",
        temp_local_path=f"/tmp/{file_name}",
        referenced_by=[],
        is_generated=False,
    )


def test_dispatch_artifacts_accepts_artifact_list_entrypoint() -> None:
    policy = _make_policy()
    source = (
        "import torch\n"
        "class DemoModel:\n"
        "    def forward(self, x):\n"
        "        return torch.special.expit(x)\n"
    )
    artifact = _make_artifact("modeling_unregistered.py", FileKind.PYTHON, source)
    results = dispatch_artifacts(
        artifacts=[artifact],
        policy=policy,
        source_loader={artifact.repo_path: source},
    )

    assert len(results) == 1
    assert results[0].status is ValidationStatus.PENDING_REVIEW
    assert "torch.special.expit" in results[0].details["pending_api_refs"]


def test_overall_pass_when_everything_passes() -> None:
    policy = _make_policy()
    config_source = json.dumps({"model_type": "demo"})
    model_source = (
        "import torch.nn.functional as F\n"
        "from torch import nn\n"
        "class DemoModel:\n"
        "    def forward(self, x):\n"
        "        return F.relu(nn.Linear(4, 2)(x))\n"
    )
    config_artifact = _make_artifact("config.json", FileKind.CONFIG_JSON, config_source)
    model_artifact = _make_artifact("modeling_safe.py", FileKind.PYTHON, model_source)
    request = build_minimal_request(
        request_id="req-pass",
        job_id="job-pass",
        policy=policy,
        artifacts=[config_artifact, model_artifact],
        stop_on_first_block=False,
    )

    response = run_validation_job(
        request,
        source_loader={
            "config.json": config_source,
            "modeling_safe.py": model_source,
        },
        runtime_check_loader={"modeling_safe.py": {"status": "PASS", "runtime_mode": "RESTRICTED_RUNTIME"}},
    )

    assert response.overall_status is ValidationStatus.PASS
    assert len(response.blocked_artifact_ids) == 0
    assert len(response.pending_artifact_ids) == 0
    assert set(response.approved_artifact_ids) == {config_artifact.artifact_id, model_artifact.artifact_id}


def test_overall_block_when_one_artifact_is_blocked() -> None:
    policy = _make_policy()
    bad_source = (
        "class DemoModel:\n"
        "    def forward(self, x):\n"
        "        return eval('1+1')\n"
    )
    ok_source = (
        "import torch.nn.functional as F\n"
        "from torch import nn\n"
        "class DemoModel:\n"
        "    def forward(self, x):\n"
        "        return F.relu(nn.Linear(4, 2)(x))\n"
    )
    bad_artifact = _make_artifact("modeling_bad.py", FileKind.PYTHON, bad_source)
    ok_artifact = _make_artifact("modeling_ok.py", FileKind.PYTHON, ok_source)
    request = build_minimal_request(
        request_id="req-block",
        job_id="job-block",
        policy=policy,
        artifacts=[bad_artifact, ok_artifact],
    )

    response = run_validation_job(
        request,
        source_loader={
            "modeling_bad.py": bad_source,
            "modeling_ok.py": ok_source,
        },
        runtime_check_loader={"modeling_ok.py": {"status": "PASS", "runtime_mode": "RESTRICTED_RUNTIME"}},
    )

    assert response.overall_status is ValidationStatus.BLOCK
    assert bad_artifact.artifact_id in response.blocked_artifact_ids
    assert ok_artifact.artifact_id in response.approved_artifact_ids


def test_overall_pending_review_when_no_block_but_pending_exists() -> None:
    policy = _make_policy()
    pending_source = (
        "import torch\n"
        "class DemoModel:\n"
        "    def forward(self, x):\n"
        "        return torch.special.expit(x)\n"
    )
    pending_artifact = _make_artifact("modeling_pending.py", FileKind.PYTHON, pending_source)
    request = build_minimal_request(
        request_id="req-pending",
        job_id="job-pending",
        policy=policy,
        artifacts=[pending_artifact],
    )

    response = run_validation_job(
        request,
        source_loader={"modeling_pending.py": pending_source},
    )

    assert response.overall_status is ValidationStatus.PENDING_REVIEW
    assert pending_artifact.artifact_id in response.pending_artifact_ids


def test_config_reroute_block_propagates_to_config_and_overall() -> None:
    policy = _make_policy()
    config_source = json.dumps({"auto_map": {"AutoModel": "modeling_evil.DemoModel"}})
    code_source = (
        "class DemoModel:\n"
        "    def forward(self, x):\n"
        "        return eval('1+1')\n"
    )
    artifact = _make_artifact("config.json", FileKind.CONFIG_JSON, config_source)
    request = build_minimal_request(
        request_id="req-cfg-block",
        job_id="job-cfg-block",
        policy=policy,
        artifacts=[artifact],
    )

    response = run_validation_job(
        request,
        source_loader={
            "config.json": config_source,
            "modeling_evil.py": code_source,
        },
    )

    assert response.overall_status is ValidationStatus.BLOCK
    cfg_result = response.artifact_results[0]
    assert cfg_result.status is ValidationStatus.BLOCK
    assert cfg_result.details["linked_code_statuses"] == ["BLOCK"]


def test_config_reroute_pending_propagates_to_config_and_overall() -> None:
    policy = _make_policy()
    config_source = json.dumps({"auto_map": {"AutoModel": "modeling_unknown.DemoModel"}})
    code_source = (
        "import torch\n"
        "class DemoModel:\n"
        "    def forward(self, x):\n"
        "        return torch.special.expit(x)\n"
    )
    artifact = _make_artifact("config.json", FileKind.CONFIG_JSON, config_source)
    request = build_minimal_request(
        request_id="req-cfg-pending",
        job_id="job-cfg-pending",
        policy=policy,
        artifacts=[artifact],
    )

    response = run_validation_job(
        request,
        source_loader={
            "config.json": config_source,
            "modeling_unknown.py": code_source,
        },
    )

    assert response.overall_status is ValidationStatus.PENDING_REVIEW
    cfg_result = response.artifact_results[0]
    assert cfg_result.status is ValidationStatus.PENDING_REVIEW
    assert cfg_result.details["linked_code_statuses"] == ["PENDING_REVIEW"]


def test_stop_on_first_block_stops_remaining_dispatch() -> None:
    policy = _make_policy()
    bad_source = (
        "class DemoModel:\n"
        "    def forward(self, x):\n"
        "        return eval('1+1')\n"
    )
    pending_source = (
        "import torch\n"
        "class DemoModel:\n"
        "    def forward(self, x):\n"
        "        return torch.special.expit(x)\n"
    )
    bad_artifact = _make_artifact("modeling_bad.py", FileKind.PYTHON, bad_source)
    pending_artifact = _make_artifact("modeling_pending.py", FileKind.PYTHON, pending_source)
    request = build_minimal_request(
        request_id="req-stop",
        job_id="job-stop",
        policy=policy,
        artifacts=[bad_artifact, pending_artifact],
        stop_on_first_block=True,
    )

    response = run_validation_job(
        request,
        source_loader={
            "modeling_bad.py": bad_source,
            "modeling_pending.py": pending_source,
        },
    )

    assert response.overall_status is ValidationStatus.BLOCK
    assert len(response.artifact_results) == 1
    assert response.artifact_results[0].artifact.artifact_id == bad_artifact.artifact_id


def test_context_review_and_context_block_are_reflected_in_overall_status() -> None:
    policy = _make_policy()
    review_source = (
        "class DemoModel:\n"
        "    def forward(self, user_path):\n"
        "        with open(user_path, 'r') as handle:\n"
        "            return handle.read()\n"
    )
    block_source = (
        "class DemoModel:\n"
        "    def forward(self, user_path):\n"
        "        with open(user_path, 'w') as handle:\n"
        "            handle.write('x')\n"
        "        return user_path\n"
    )
    review_artifact = _make_artifact("modeling_context_review.py", FileKind.PYTHON, review_source)
    block_artifact = _make_artifact("modeling_context_block.py", FileKind.PYTHON, block_source)

    review_request = build_minimal_request(
        request_id="req-context-review",
        job_id="job-context-review",
        policy=policy,
        artifacts=[review_artifact],
    )
    review_response = run_validation_job(
        review_request,
        source_loader={"modeling_context_review.py": review_source},
        ast_call_metadata_loader={
            "modeling_context_review.py": [
                {
                    "api": "open",
                    "args": [
                        {"kind": "name", "value": "user_path", "source": "user_input", "is_user_input": True},
                        {"kind": "constant_str", "value": "r"},
                    ],
                }
            ]
        },
    )
    assert review_response.overall_status is ValidationStatus.PENDING_REVIEW

    block_request = build_minimal_request(
        request_id="req-context-block",
        job_id="job-context-block",
        policy=policy,
        artifacts=[block_artifact],
    )
    block_response = run_validation_job(
        block_request,
        source_loader={"modeling_context_block.py": block_source},
        ast_call_metadata_loader={
            "modeling_context_block.py": [
                {
                    "api": "open",
                    "args": [
                        {"kind": "name", "value": "user_path", "source": "user_input", "is_user_input": True},
                        {"kind": "constant_str", "value": "w"},
                    ],
                }
            ]
        },
    )
    assert block_response.overall_status is ValidationStatus.BLOCK


def test_preprocessing_auxiliary_unknown_are_not_auto_passed_in_orchestrator() -> None:
    policy = _make_policy()
    preprocessing_source = "class DemoTokenizer:\n    pass\n"
    auxiliary_source = '"""pkg"""\nfrom .modeling_demo import DemoModel\n__all__ = ["DemoModel"]\n'
    unknown_source = "def helper(x):\n    return x\n"

    pre = _make_artifact("tokenization_demo.py", FileKind.PYTHON, preprocessing_source)
    aux = _make_artifact("__init__.py", FileKind.PYTHON, auxiliary_source)
    unk = _make_artifact("random_script.py", FileKind.PYTHON, unknown_source)
    request = build_minimal_request(
        request_id="req-roles",
        job_id="job-roles",
        policy=policy,
        artifacts=[pre, aux, unk],
    )

    response = run_validation_job(
        request,
        source_loader={
            "tokenization_demo.py": preprocessing_source,
            "__init__.py": auxiliary_source,
            "random_script.py": unknown_source,
        },
    )

    assert response.overall_status in {ValidationStatus.PENDING_REVIEW, ValidationStatus.ERROR}
    for item in response.artifact_results:
        assert item.status is not ValidationStatus.PASS


def test_preprocessing_metadata_routes_to_semantic_scan_and_stays_pending_without_baseline() -> None:
    policy = _make_policy()
    source = json.dumps({"processor_class": "DemoProcessor", "chat_template": "{{ messages }}"})
    artifact = _make_artifact("processor_config.json", FileKind.PROCESSOR_CONFIG_JSON, source)
    request = build_minimal_request(
        request_id="req-preprocessing-metadata",
        job_id="job-preprocessing-metadata",
        policy=policy,
        artifacts=[artifact],
    )

    response = run_validation_job(
        request,
        source_loader={"processor_config.json": source},
    )

    result = response.artifact_results[0]
    assert response.overall_status is ValidationStatus.PENDING_REVIEW
    assert result.route_kind is RouteKind.PREPROCESSING_SEMANTIC_SCAN
    assert result.status is ValidationStatus.PENDING_REVIEW
    assert result.details["semantic_check"]["status"] == "BASELINE_MISSING"


def test_tokenizer_config_dispatch_includes_semantic_inventory_and_stays_pending_without_baseline() -> None:
    policy = _make_policy()
    source = json.dumps(
        {
            "model_max_length": 2048,
            "padding_side": "left",
            "clean_up_tokenization_spaces": False,
        }
    )
    artifact = _make_artifact("tokenizer_config.json", FileKind.TOKENIZER_CONFIG_JSON, source)
    request = build_minimal_request(
        request_id="req-tokenizer-config-semantic",
        job_id="job-tokenizer-config-semantic",
        policy=policy,
        artifacts=[artifact],
    )

    response = run_validation_job(
        request,
        source_loader={"tokenizer_config.json": source},
    )

    result = response.artifact_results[0]
    assert response.overall_status is ValidationStatus.PENDING_REVIEW
    assert result.route_kind is RouteKind.CONFIG_SCHEMA_VALIDATION
    assert result.status is ValidationStatus.PENDING_REVIEW
    assert result.details["semantic_route_kind"] == "PREPROCESSING_SEMANTIC_SCAN"
    assert result.details["semantic_check"]["status"] == "BASELINE_MISSING"
    assert result.details["semantic_inventory"]["model_max_length"] == 2048
    assert result.details["semantic_inventory"]["padding_side"] == "left"
    assert result.details["semantic_inventory"]["clean_up_tokenization_spaces"] is False


def test_loader_error_is_reported_as_error_status() -> None:
    policy = _make_policy()
    source = "def f(x):\n    return x\n"
    artifact = _make_artifact("modeling_missing.py", FileKind.PYTHON, source)
    request = build_minimal_request(
        request_id="req-loader-error",
        job_id="job-loader-error",
        policy=policy,
        artifacts=[artifact],
    )

    response = run_validation_job(
        request,
        source_loader={},
    )

    assert response.overall_status is ValidationStatus.ERROR
    assert response.release_action == "ERROR"
    assert response.artifact_results[0].status is ValidationStatus.ERROR


def test_error_has_priority_over_pending_review_in_overall_status() -> None:
    policy = _make_policy()
    pending_source = (
        "import torch\n"
        "class DemoModel:\n"
        "    def forward(self, x):\n"
        "        return torch.special.expit(x)\n"
    )
    pending_artifact = _make_artifact("modeling_pending.py", FileKind.PYTHON, pending_source)
    missing_artifact = _make_artifact("modeling_missing.py", FileKind.PYTHON, "def f(x):\n    return x\n")
    request = build_minimal_request(
        request_id="req-mixed-error-pending",
        job_id="job-mixed-error-pending",
        policy=policy,
        artifacts=[pending_artifact, missing_artifact],
    )

    response = run_validation_job(
        request,
        source_loader={"modeling_pending.py": pending_source},
    )

    assert response.overall_status is ValidationStatus.ERROR
    assert response.release_action == "ERROR"
    statuses = {item.artifact.repo_path: item.status for item in response.artifact_results}
    assert statuses["modeling_pending.py"] is ValidationStatus.PENDING_REVIEW
    assert statuses["modeling_missing.py"] is ValidationStatus.ERROR
