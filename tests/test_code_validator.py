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
from analyzer.validators.code_validator import validate_python_artifact


def _make_policy() -> PolicyInfo:
    return PolicyInfo(
        policy_version="policy-2026.04.20",
        whitelist_version="wl-2026.04.20",
        opcode_policy_version="opcode-2026.04.20",
        config_schema_version="cfg-2026.04.20",
        runtime_profile_version="rt-2026.04.20",
    )


def _make_artifact(repo_path: str) -> ArtifactRef:
    digest = hashlib.sha256(repo_path.encode("utf-8")).hexdigest()
    file_name = PurePosixPath(repo_path).name
    return ArtifactRef(
        artifact_id=f"sha256:{digest}",
        repo_path=repo_path,
        file_name=file_name,
        file_kind=FileKind.PYTHON,
        detected_extension=".py",
        media_type=None,
        size_bytes=1,
        sha256=digest,
        source_url=f"https://huggingface.co/org/demo/resolve/main/{repo_path}",
        temp_local_path=f"/tmp/{file_name}",
        referenced_by=[],
        is_generated=False,
    )


def test_simple_configuration_is_grade_a_pass() -> None:
    artifact = _make_artifact("configuration_demo.py")
    source = (
        "from transformers import PretrainedConfig\n"
        "class DemoConfig(PretrainedConfig):\n"
        "    model_type = 'demo'\n"
        "    attribute_map = {'hidden_size': 'hidden_size'}\n"
        "    def __init__(self, hidden_size=128, **kwargs):\n"
        "        super().__init__(**kwargs)\n"
        "        self.hidden_size = hidden_size\n"
    )
    result = validate_python_artifact(artifact, source, _make_policy())

    assert result.grade is CodeGrade.A
    assert result.status is ValidationStatus.PASS
    assert result.review_action is ReviewAction.AUTO_APPROVE_REGENERATED
    assert result.details["grade_result"]["runtime_mode"] == "REGENERATE"
    assert result.details["role_classification"]["role"] == "CONFIGURATION"
    metadata = result.details["configuration_metadata"]
    assert metadata["class_name"] == "DemoConfig"
    assert metadata["model_type"] == "demo"
    assert metadata["init_parameters"] == ["hidden_size", "kwargs"]
    assert "hidden_size" in metadata["assigned_attributes"]
    assert metadata["attribute_map"] == {"hidden_size": "hidden_size"}
    assert metadata["config_regenerable"] is True
    assert metadata["config_regeneration_block_reasons"] == []


def test_configuration_with_execution_method_is_not_grade_a() -> None:
    artifact = _make_artifact("configuration_bad.py")
    source = (
        "from transformers import PretrainedConfig\n"
        "class BadConfig(PretrainedConfig):\n"
        "    model_type = 'demo'\n"
        "    def __init__(self, **kwargs):\n"
        "        super().__init__(**kwargs)\n"
        "        self.x = 1\n"
        "    def forward(self, x):\n"
        "        return x\n"
    )
    result = validate_python_artifact(artifact, source, _make_policy())

    assert result.grade is CodeGrade.B2
    assert result.status is ValidationStatus.PENDING_REVIEW
    assert result.review_action is ReviewAction.SECURITY_OWNER_GATE


def test_configuration_missing_model_type_is_b2_pending_review() -> None:
    artifact = _make_artifact("configuration_missing_model_type.py")
    source = (
        "from transformers import PretrainedConfig\n"
        "class MissingTypeConfig(PretrainedConfig):\n"
        "    def __init__(self, hidden_size=128, **kwargs):\n"
        "        super().__init__(**kwargs)\n"
        "        self.hidden_size = hidden_size\n"
    )
    result = validate_python_artifact(artifact, source, _make_policy())

    assert result.grade is CodeGrade.B2
    assert result.status is ValidationStatus.PENDING_REVIEW
    assert result.review_action is ReviewAction.SECURITY_OWNER_GATE
    metadata = result.details["configuration_metadata"]
    assert metadata["config_regenerable"] is False
    assert "missing_model_type_class_attribute" in metadata["config_regeneration_block_reasons"]


def test_configuration_without_pretrainedconfig_is_b2_pending_review() -> None:
    artifact = _make_artifact("configuration_no_base.py")
    source = (
        "class PlainConfig:\n"
        "    model_type = 'demo'\n"
        "    def __init__(self, hidden_size=128):\n"
        "        self.hidden_size = hidden_size\n"
    )
    result = validate_python_artifact(artifact, source, _make_policy())

    assert result.grade is CodeGrade.B2
    assert result.status is ValidationStatus.PENDING_REVIEW
    assert result.review_action is ReviewAction.SECURITY_OWNER_GATE
    metadata = result.details["configuration_metadata"]
    assert metadata["config_regenerable"] is False
    assert "class_not_inheriting_pretrained_config" in metadata["config_regeneration_block_reasons"]


def test_configuration_init_helper_call_is_b2_pending_review() -> None:
    artifact = _make_artifact("configuration_helper_call.py")
    source = (
        "from transformers import PretrainedConfig\n"
        "def _norm(v):\n"
        "    return v\n"
        "class HelperConfig(PretrainedConfig):\n"
        "    model_type = 'demo'\n"
        "    def __init__(self, hidden_size=128, **kwargs):\n"
        "        super().__init__(**kwargs)\n"
        "        self.hidden_size = _norm(hidden_size)\n"
    )
    result = validate_python_artifact(artifact, source, _make_policy())

    assert result.grade is CodeGrade.B2
    assert result.status is ValidationStatus.PENDING_REVIEW
    assert result.review_action is ReviewAction.SECURITY_OWNER_GATE


def test_configuration_init_eval_is_immediate_c_block() -> None:
    artifact = _make_artifact("configuration_eval.py")
    source = (
        "from transformers import PretrainedConfig\n"
        "class EvalConfig(PretrainedConfig):\n"
        "    model_type = 'demo'\n"
        "    def __init__(self, **kwargs):\n"
        "        super().__init__(**kwargs)\n"
        "        self.x = eval('1+1')\n"
    )
    result = validate_python_artifact(artifact, source, _make_policy())

    assert result.grade is CodeGrade.C
    assert result.status is ValidationStatus.BLOCK
    assert result.review_action is ReviewAction.BLOCK_IMMEDIATELY
    assert "DANGEROUS_CALL" in [entry.code for entry in result.reason_entries]


def test_configuration_top_level_function_call_is_b2_pending_review() -> None:
    artifact = _make_artifact("configuration_top_level_call.py")
    source = (
        "from transformers import PretrainedConfig\n"
        "def helper():\n"
        "    return 1\n"
        "BOOTSTRAP = helper()\n"
        "class TopLevelCallConfig(PretrainedConfig):\n"
        "    model_type = 'demo'\n"
        "    def __init__(self, **kwargs):\n"
        "        super().__init__(**kwargs)\n"
        "        self.ready = True\n"
    )
    result = validate_python_artifact(artifact, source, _make_policy())

    assert result.grade is CodeGrade.B2
    assert result.status is ValidationStatus.PENDING_REVIEW
    assert result.review_action is ReviewAction.SECURITY_OWNER_GATE


def test_configuration_top_level_dangerous_call_is_c_block() -> None:
    artifact = _make_artifact("configuration_top_level_eval.py")
    source = (
        "eval('1+1')\n"
        "from transformers import PretrainedConfig\n"
        "class TopLevelEvalConfig(PretrainedConfig):\n"
        "    model_type = 'demo'\n"
        "    def __init__(self, **kwargs):\n"
        "        super().__init__(**kwargs)\n"
    )
    result = validate_python_artifact(artifact, source, _make_policy())

    assert result.grade is CodeGrade.C
    assert result.status is ValidationStatus.BLOCK


def test_modeling_allowed_api_with_runtime_pass_is_b1_pass() -> None:
    artifact = _make_artifact("modeling_demo.py")
    source = (
        "import torch.nn.functional as F\n"
        "from torch import nn\n"
        "class DemoModel:\n"
        "    def forward(self, x):\n"
        "        y = nn.Linear(4, 2)\n"
        "        return F.relu(y)\n"
    )
    runtime_check = {"status": "PASS", "runtime_mode": "RESTRICTED_RUNTIME"}
    result = validate_python_artifact(artifact, source, _make_policy(), runtime_check=runtime_check)

    assert result.grade is CodeGrade.B1
    assert result.status is ValidationStatus.PASS
    assert result.review_action is ReviewAction.AUTO_APPROVE
    assert result.route_kind is RouteKind.CODE_RESTRICTED_RUNTIME


def test_modeling_runtime_missing_or_skipped_is_b2_pending_review() -> None:
    artifact = _make_artifact("modeling_demo.py")
    source = (
        "import torch.nn.functional as F\n"
        "from torch import nn\n"
        "class DemoModel:\n"
        "    def forward(self, x):\n"
        "        y = nn.Linear(4, 2)\n"
        "        return F.relu(y)\n"
    )
    runtime_check = {"status": "SKIPPED", "runtime_mode": "RESTRICTED_RUNTIME"}
    result = validate_python_artifact(artifact, source, _make_policy(), runtime_check=runtime_check)

    assert result.grade is CodeGrade.B2
    assert result.status is ValidationStatus.PENDING_REVIEW
    assert result.review_action is ReviewAction.SECURITY_OWNER_GATE


def test_unregistered_api_is_b2_pending_review() -> None:
    artifact = _make_artifact("modeling_unregistered.py")
    source = (
        "import torch\n"
        "class DemoModel:\n"
        "    def forward(self, x):\n"
        "        return torch.special.expit(x)\n"
    )
    result = validate_python_artifact(artifact, source, _make_policy())

    assert result.grade is CodeGrade.B2
    assert result.status is ValidationStatus.PENDING_REVIEW
    assert "UNREGISTERED_API" in [entry.code for entry in result.reason_entries]
    assert "torch.special.expit" in result.details["pending_api_refs"]


def test_dynamic_pattern_is_c_pending_review_not_block() -> None:
    artifact = _make_artifact("modeling_dynamic.py")
    source = (
        "class DemoModel:\n"
        "    def forward(self, module, name):\n"
        "        fn = getattr(module, name)\n"
        "        return fn()\n"
    )
    result = validate_python_artifact(artifact, source, _make_policy())

    assert result.grade is CodeGrade.C
    assert result.status is ValidationStatus.PENDING_REVIEW
    assert result.review_action is ReviewAction.MANUAL_REVIEW_REQUIRED
    assert "DYNAMIC_PATTERN" in [entry.code for entry in result.reason_entries]


def test_eval_is_immediate_c_block() -> None:
    artifact = _make_artifact("modeling_eval.py")
    source = (
        "class DemoModel:\n"
        "    def forward(self, x):\n"
        "        return eval('1+1')\n"
    )
    result = validate_python_artifact(artifact, source, _make_policy())

    assert result.grade is CodeGrade.C
    assert result.status is ValidationStatus.BLOCK
    assert result.review_action is ReviewAction.BLOCK_IMMEDIATELY
    assert "DANGEROUS_CALL" in [entry.code for entry in result.reason_entries]


def test_torch_load_is_immediate_c_block() -> None:
    artifact = _make_artifact("modeling_torch_load.py")
    source = (
        "import torch\n"
        "class DemoModel:\n"
        "    def forward(self, x):\n"
        "        return torch.load('weights.pt')\n"
    )
    result = validate_python_artifact(artifact, source, _make_policy())

    assert result.grade is CodeGrade.C
    assert result.status is ValidationStatus.BLOCK
    assert "DANGEROUS_API" in [entry.code for entry in result.reason_entries]


def test_os_remove_is_immediate_context_block() -> None:
    artifact = _make_artifact("modeling_os_remove.py")
    source = (
        "import os\n"
        "def run():\n"
        "    os.remove('config.json')\n"
    )
    result = validate_python_artifact(artifact, source, _make_policy())

    assert result.grade is CodeGrade.C
    assert result.status is ValidationStatus.BLOCK
    assert result.review_action is ReviewAction.BLOCK_IMMEDIATELY
    assert "CONTEXT_API_BLOCKED" in [entry.code for entry in result.reason_entries]


def test_shutil_rmtree_is_immediate_context_block() -> None:
    artifact = _make_artifact("modeling_shutil_rmtree.py")
    source = (
        "import shutil\n"
        "def run():\n"
        "    shutil.rmtree('cache')\n"
    )
    result = validate_python_artifact(artifact, source, _make_policy())

    assert result.grade is CodeGrade.C
    assert result.status is ValidationStatus.BLOCK
    assert result.review_action is ReviewAction.BLOCK_IMMEDIATELY
    assert "CONTEXT_API_BLOCKED" in [entry.code for entry in result.reason_entries]


def test_context_block_has_higher_priority_than_dynamic_review_paths() -> None:
    artifact = _make_artifact("modeling_context_block.py")
    source = (
        "def run(user_path):\n"
        "    return open(user_path, 'w')\n"
    )
    ast_call_metadata = [
        {
            "api": "open",
            "args": [
                {"kind": "name", "value": "user_path", "source": "user_input", "is_user_input": True},
                {"kind": "constant_str", "value": "w"},
            ],
        }
    ]
    result = validate_python_artifact(
        artifact,
        source,
        _make_policy(),
        ast_call_metadata=ast_call_metadata,
    )

    assert result.grade is CodeGrade.C
    assert result.status is ValidationStatus.BLOCK
    assert "CONTEXT_API_BLOCKED" in [entry.code for entry in result.reason_entries]


def test_preprocessing_and_auxiliary_roles_are_not_auto_passed() -> None:
    preprocessing = validate_python_artifact(
        _make_artifact("tokenization_demo.py"),
        "class DemoTokenizer:\n    pass\n",
        _make_policy(),
    )
    auxiliary = validate_python_artifact(
        _make_artifact("__init__.py"),
        '"""pkg"""\nfrom .modeling_demo import DemoModel\n__all__ = ["DemoModel"]\n',
        _make_policy(),
    )

    assert preprocessing.status is not ValidationStatus.PASS
    assert auxiliary.status is not ValidationStatus.PASS
    assert preprocessing.status in {ValidationStatus.PENDING_REVIEW, ValidationStatus.SKIPPED}
    assert auxiliary.status in {ValidationStatus.PENDING_REVIEW, ValidationStatus.SKIPPED}


def test_result_details_include_required_keys_and_are_json_serializable() -> None:
    artifact = _make_artifact("modeling_details.py")
    source = (
        "import torch\n"
        "class DemoModel:\n"
        "    def forward(self, x):\n"
        "        return torch.special.expit(x)\n"
    )
    result = validate_python_artifact(artifact, source, _make_policy())
    details = result.details

    assert {
        "role_classification",
        "ast_scan",
        "configuration_metadata",
        "api_scan",
        "context_api_scan",
        "grade_result",
        "runtime_check",
        "pending_api_refs",
        "review_queue_entry_id",
        "effective_output_artifact_id",
    }.issubset(details.keys())
    assert isinstance(details["grade_result"]["grade_reason"], str)
    json.loads(json.dumps(result.to_dict()))
