import hashlib
import json
from pathlib import PurePosixPath

from analyzer.schemas import (
    ArtifactRef,
    CodeGrade,
    FileKind,
    PolicyInfo,
    ReviewAction,
    RouteKind,
    ValidationStatus,
)
from analyzer.validators.config_validator import validate_config_artifact


def _make_policy() -> PolicyInfo:
    return PolicyInfo(
        policy_version="policy-2026.04.20",
        whitelist_version="wl-2026.04.20",
        opcode_policy_version="opcode-2026.04.20",
        config_schema_version="cfg-2026.04.20",
        runtime_profile_version="rt-2026.04.20",
    )


def _make_artifact(repo_path: str, file_kind: FileKind) -> ArtifactRef:
    digest = hashlib.sha256(repo_path.encode("utf-8")).hexdigest()
    file_name = PurePosixPath(repo_path).name
    return ArtifactRef(
        artifact_id=f"sha256:{digest}",
        repo_path=repo_path,
        file_name=file_name,
        file_kind=file_kind,
        detected_extension=".json",
        media_type="application/json",
        size_bytes=1,
        sha256=digest,
        source_url=f"https://huggingface.co/org/demo/resolve/main/{repo_path}",
        temp_local_path=f"/tmp/{file_name}",
        referenced_by=[],
        is_generated=False,
    )


def test_trigger_absent_and_valid_json_is_pass() -> None:
    artifact = _make_artifact("config.json", FileKind.CONFIG_JSON)
    payload = {"model_type": "demo", "hidden_size": 128}
    result = validate_config_artifact(artifact, json.dumps(payload), _make_policy())

    assert result.route_kind is RouteKind.CONFIG_SCHEMA_VALIDATION
    assert result.grade is CodeGrade.NA
    assert result.status is ValidationStatus.PASS
    assert result.details["trigger_fields"] == []
    assert result.details["effective_status"] == "PASS"


def test_auto_map_extracts_referenced_python_and_links_passed_code() -> None:
    artifact = _make_artifact("config.json", FileKind.CONFIG_JSON)
    payload = {"auto_map": {"AutoModel": "modeling_demo.DemoModel"}}
    source_loader = {
        "modeling_demo.py": (
            "import torch.nn.functional as F\n"
            "from torch import nn\n"
            "class DemoModel:\n"
            "    def forward(self, x):\n"
            "        y = nn.Linear(4, 2)\n"
            "        return F.relu(y)\n"
        )
    }
    runtime_loader = {"modeling_demo.py": {"status": "PASS", "runtime_mode": "RESTRICTED_RUNTIME"}}

    result = validate_config_artifact(
        artifact,
        json.dumps(payload),
        _make_policy(),
        source_loader=source_loader,
        runtime_check_loader=runtime_loader,
    )

    assert result.status is ValidationStatus.PASS
    assert result.details["trigger_fields"] == ["auto_map"]
    assert result.details["config_scan"]["referenced_python_files"] == ["modeling_demo.py"]
    assert result.details["linked_code_statuses"] == ["PASS"]
    assert result.details["effective_status"] == "PASS"


def test_custom_pipelines_extracts_referenced_python() -> None:
    artifact = _make_artifact("config.json", FileKind.CONFIG_JSON)
    payload = {
        "custom_pipelines": {
            "my-task": {"impl": "pipelines.custom_pipeline.MyPipeline"},
        }
    }
    result = validate_config_artifact(
        artifact,
        json.dumps(payload),
        _make_policy(),
        source_loader={},
    )

    assert result.status is ValidationStatus.PENDING_REVIEW
    assert "custom_pipelines" in result.details["trigger_fields"]
    assert "pipelines/custom_pipeline.py" in result.details["config_scan"]["referenced_python_files"]
    assert result.details["linked_code_statuses"] == ["MISSING"]


def test_trust_remote_code_true_with_references_keeps_routing_evidence() -> None:
    artifact = _make_artifact("config.json", FileKind.CONFIG_JSON)
    payload = {
        "trust_remote_code": True,
        "auto_map": {"AutoModel": "modeling_remote.DemoModel"},
    }
    result = validate_config_artifact(
        artifact,
        json.dumps(payload),
        _make_policy(),
        source_loader={},
    )

    assert "trust_remote_code" in result.details["trigger_fields"]
    assert result.details["config_scan"]["trust_remote_code"] is True
    assert result.details["config_scan"]["rerouted_to_code_validation"] is True
    assert result.details["effective_status"] == "PENDING_REVIEW"


def test_linked_code_block_raises_config_block() -> None:
    artifact = _make_artifact("config.json", FileKind.CONFIG_JSON)
    payload = {"auto_map": {"AutoModel": "modeling_bad.DemoModel"}}
    source_loader = {
        "modeling_bad.py": (
            "class DemoModel:\n"
            "    def forward(self, x):\n"
            "        return eval('1+1')\n"
        )
    }
    result = validate_config_artifact(
        artifact,
        json.dumps(payload),
        _make_policy(),
        source_loader=source_loader,
    )

    assert result.status is ValidationStatus.BLOCK
    assert result.review_action is ReviewAction.BLOCK_IMMEDIATELY
    assert result.details["linked_code_statuses"] == ["BLOCK"]
    assert result.details["effective_status"] == "BLOCK"


def test_linked_code_pending_review_raises_config_pending_review() -> None:
    artifact = _make_artifact("config.json", FileKind.CONFIG_JSON)
    payload = {"auto_map": {"AutoModel": "modeling_unknown.DemoModel"}}
    source_loader = {
        "modeling_unknown.py": (
            "import torch\n"
            "class DemoModel:\n"
            "    def forward(self, x):\n"
            "        return torch.special.expit(x)\n"
        )
    }
    result = validate_config_artifact(
        artifact,
        json.dumps(payload),
        _make_policy(),
        source_loader=source_loader,
    )

    assert result.status is ValidationStatus.PENDING_REVIEW
    assert result.review_action is ReviewAction.SECURITY_OWNER_GATE
    assert result.details["linked_code_statuses"] == ["PENDING_REVIEW"]
    assert result.details["effective_status"] == "PENDING_REVIEW"


def test_missing_loader_or_reference_keeps_pending_review_with_details() -> None:
    artifact = _make_artifact("config.json", FileKind.CONFIG_JSON)
    payload = {"auto_map": {"AutoModel": "modeling_missing.DemoModel"}}
    result = validate_config_artifact(
        artifact,
        json.dumps(payload),
        _make_policy(),
        source_loader=None,
    )

    assert result.status is ValidationStatus.PENDING_REVIEW
    assert result.details["linked_code_results"][0]["status"] == "MISSING"
    assert result.details["linked_code_results"][0]["error"] in {
        "source_loader_not_provided",
        "referenced_source_not_found",
    }


def test_tokenizer_config_custom_class_reference_is_extracted() -> None:
    artifact = _make_artifact("tokenizer_config.json", FileKind.TOKENIZER_CONFIG_JSON)
    payload = {
        "tokenizer_class": "tokenization_demo.DemoTokenizer",
        "trust_remote_code": True,
    }
    result = validate_config_artifact(
        artifact,
        json.dumps(payload),
        _make_policy(),
        source_loader={},
    )

    assert result.status is ValidationStatus.PENDING_REVIEW
    assert "trust_remote_code" in result.details["trigger_fields"]
    assert "tokenization_demo.py" in result.details["config_scan"]["referenced_python_files"]


def test_invalid_json_blocks_config() -> None:
    artifact = _make_artifact("config.json", FileKind.CONFIG_JSON)
    result = validate_config_artifact(artifact, "{broken", _make_policy())

    assert result.status is ValidationStatus.BLOCK
    assert result.details["config_scan"]["schema_valid"] is False


def test_details_include_required_keys_and_json_serializable() -> None:
    artifact = _make_artifact("config.json", FileKind.CONFIG_JSON)
    payload = {"auto_map": {"AutoModel": "modeling_demo.DemoModel"}}
    result = validate_config_artifact(
        artifact,
        json.dumps(payload),
        _make_policy(),
        source_loader={},
    )
    details = result.details
    assert {"config_scan", "trigger_fields", "referenced_code", "linked_code_results", "effective_status"}.issubset(
        details.keys()
    )
    json.loads(json.dumps(result.to_dict()))
