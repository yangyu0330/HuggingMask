from analyzer.validators.code_roles import (
    AuxiliaryKind,
    NON_AUTO_APPROVAL_REASON,
    PreprocessKind,
    PythonFileRole,
    RoleConfidence,
    classify_python_role,
)


def test_configuration_file_is_classified_by_filename() -> None:
    result = classify_python_role(
        "configuration_demo.py",
        "class DemoConfig:\n    pass\n",
    )
    assert result.role is PythonFileRole.CONFIGURATION
    assert result.preprocess_kind is PreprocessKind.NONE
    assert result.auto_approval_candidate is True
    assert result.auto_approval_block_reason is None


def test_generation_config_file_is_configuration_candidate() -> None:
    result = classify_python_role(
        "generation_config.py",
        "VALUE = 1\n",
    )
    assert result.role is PythonFileRole.CONFIGURATION
    assert result.auto_approval_candidate is True


def test_modeling_file_is_classified_by_filename() -> None:
    source = (
        "import torch.nn as nn\n"
        "class DemoModel(nn.Module):\n"
        "    def forward(self, x):\n"
        "        return x\n"
    )
    result = classify_python_role("modeling_demo.py", source)
    assert result.role is PythonFileRole.MODELING
    assert result.auto_approval_candidate is True


def test_tokenization_file_is_preprocessing_tokenizer() -> None:
    result = classify_python_role("tokenization_demo.py", "class DemoTokenizer:\n    pass\n")
    assert result.role is PythonFileRole.PREPROCESSING
    assert result.preprocess_kind is PreprocessKind.TOKENIZER
    assert result.auto_approval_candidate is False
    assert result.auto_approval_block_reason == NON_AUTO_APPROVAL_REASON
    assert NON_AUTO_APPROVAL_REASON in result.reasons


def test_processing_file_is_preprocessing_processor() -> None:
    result = classify_python_role("processing_demo.py", "class DemoProcessor:\n    pass\n")
    assert result.role is PythonFileRole.PREPROCESSING
    assert result.preprocess_kind is PreprocessKind.PROCESSOR
    assert result.auto_approval_candidate is False


def test_image_processing_file_is_preprocessing_image_processor() -> None:
    result = classify_python_role("image_processing_demo.py", "class DemoImageProcessor:\n    pass\n")
    assert result.role is PythonFileRole.PREPROCESSING
    assert result.preprocess_kind is PreprocessKind.IMAGE_PROCESSOR
    assert result.auto_approval_candidate is False


def test_convert_file_is_auxiliary_convert_script() -> None:
    result = classify_python_role("convert_demo.py", "print('convert only')\n")
    assert result.role is PythonFileRole.AUXILIARY
    assert result.auxiliary_kind is AuxiliaryKind.CONVERT_SCRIPT
    assert result.auto_approval_candidate is False
    assert result.auto_approval_block_reason == NON_AUTO_APPROVAL_REASON


def test_export_only_init_is_auxiliary_init_export_only() -> None:
    source = (
        '"""package init"""\n'
        "from .modeling_demo import DemoModel\n"
        "__all__ = ['DemoModel']\n"
        "__version__ = '0.1.0'\n"
    )
    result = classify_python_role("__init__.py", source)
    assert result.role is PythonFileRole.AUXILIARY
    assert result.auxiliary_kind is AuxiliaryKind.INIT_EXPORT_ONLY
    assert result.confidence is RoleConfidence.MEDIUM
    assert result.auto_approval_candidate is False


def test_dynamic_init_is_not_init_export_only() -> None:
    source = (
        "import importlib\n"
        "module = importlib.import_module('os')\n"
    )
    result = classify_python_role("__init__.py", source)
    assert result.role is PythonFileRole.UNKNOWN
    assert result.auxiliary_kind is None
    assert result.auto_approval_candidate is False
    assert result.auto_approval_block_reason == NON_AUTO_APPROVAL_REASON


def test_ast_shape_can_classify_configuration_when_name_is_ambiguous() -> None:
    source = (
        "from transformers import PretrainedConfig\n"
        "class CustomConfig(PretrainedConfig):\n"
        "    pass\n"
    )
    result = classify_python_role("custom_file.py", source)
    assert result.role is PythonFileRole.CONFIGURATION
    assert result.auto_approval_candidate is True
    assert "ROLE_AST_CONFIG_CLASS_SHAPE" in result.reasons


def test_ast_shape_can_classify_modeling_when_name_is_ambiguous() -> None:
    source = (
        "from transformers import PreTrainedModel\n"
        "class CustomModel(PreTrainedModel):\n"
        "    def forward(self, x):\n"
        "        return x\n"
    )
    result = classify_python_role("custom_module.py", source)
    assert result.role is PythonFileRole.MODELING
    assert result.auto_approval_candidate is True
    assert "ROLE_AST_MODEL_CLASS_SHAPE" in result.reasons


def test_unknown_file_remains_unknown_and_not_auto_approved() -> None:
    result = classify_python_role("random_script.py", "def helper():\n    return 1\n")
    assert result.role is PythonFileRole.UNKNOWN
    assert result.auto_approval_candidate is False
    assert result.auto_approval_block_reason == NON_AUTO_APPROVAL_REASON


def test_parse_error_returns_unknown_with_parse_reason() -> None:
    result = classify_python_role("broken.py", "def broken(:\n")
    assert result.role is PythonFileRole.UNKNOWN
    assert result.auto_approval_candidate is False
    assert "ROLE_AST_PARSE_ERROR" in result.reasons
    assert result.parse_error is not None


def test_classification_payload_is_json_ready() -> None:
    result = classify_python_role("tokenization_demo.py", "class DemoTokenizer:\n    pass\n")
    payload = result.to_dict()
    assert payload["role"] == "PREPROCESSING"
    assert payload["preprocess_kind"] == "TOKENIZER"
    assert payload["auto_approval_candidate"] is False
    assert payload["auto_approval_block_reason"] == NON_AUTO_APPROVAL_REASON

