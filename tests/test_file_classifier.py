import hashlib

import pytest

from analyzer.classifier import (
    build_artifact_ref,
    build_artifact_ref_from_file,
    classify_file_kind,
    normalize_repo_path,
    sha256_bytes,
)
from analyzer.schemas import FileKind
from analyzer.validators.weight.pickle_roles import PickleRole, classify_pickle_role


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("model.safetensors", FileKind.SAFETENSORS),
        ("weights.pkl", FileKind.PICKLE),
        ("pytorch_model.pt", FileKind.PICKLE),
        ("pytorch_model.bin", FileKind.PICKLE),
        ("modeling_demo.py", FileKind.PYTHON),
        ("config.json", FileKind.CONFIG_JSON),
        ("nested/config.json", FileKind.CONFIG_JSON),
        ("tokenizer_config.json", FileKind.TOKENIZER_CONFIG_JSON),
        ("nested/tokenizer_config.json", FileKind.TOKENIZER_CONFIG_JSON),
        ("tokenizer.json", FileKind.TOKENIZER_JSON),
        ("special_tokens_map.json", FileKind.SPECIAL_TOKENS_MAP_JSON),
        ("added_tokens.json", FileKind.ADDED_TOKENS_JSON),
        ("vocab.json", FileKind.VOCAB_JSON),
        ("merges.txt", FileKind.MERGES_TXT),
        ("preprocessor_config.json", FileKind.PREPROCESSOR_CONFIG_JSON),
        ("processor_config.json", FileKind.PROCESSOR_CONFIG_JSON),
        ("chat_template.jinja", FileKind.CHAT_TEMPLATE_JINJA),
        ("README.md", FileKind.OTHER),
        ("weights.json", FileKind.OTHER),
        ("weights.pth", FileKind.OTHER),
        ("checkpoint.ckpt", FileKind.OTHER),
    ],
)
def test_classify_file_kind(path: str, expected: FileKind) -> None:
    assert classify_file_kind(path) is expected


def test_public_file_kind_contract_does_not_expose_pickle_roles() -> None:
    internal_pickle_roles = {
        "DEPLOYABLE_WEIGHT",
        "AUXILIARY_TRAINING",
        "GENERIC_PICKLE",
        "UNSUPPORTED_CHECKPOINT",
    }

    assert FileKind.PICKLE.value == "PICKLE"
    assert internal_pickle_roles.isdisjoint({kind.value for kind in FileKind})


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("pytorch_model.bin", PickleRole.DEPLOYABLE_WEIGHT),
        ("pytorch_model-00001-of-00002.bin", PickleRole.DEPLOYABLE_WEIGHT),
        ("adapter_model.bin", PickleRole.DEPLOYABLE_WEIGHT),
        ("diffusion_pytorch_model.bin", PickleRole.DEPLOYABLE_WEIGHT),
        ("training_args.bin", PickleRole.AUXILIARY_TRAINING),
        ("checkpoint-12/optimizer.pt", PickleRole.AUXILIARY_TRAINING),
        ("rng_state_0.pt", PickleRole.AUXILIARY_TRAINING),
        ("weights.pkl", PickleRole.GENERIC_PICKLE),
        ("custom/model.pt", PickleRole.GENERIC_PICKLE),
        ("weights.pth", PickleRole.UNSUPPORTED_CHECKPOINT),
        ("checkpoint.ckpt", PickleRole.UNSUPPORTED_CHECKPOINT),
    ],
)
def test_classify_pickle_role_is_internal_and_deterministic(
    path: str,
    expected: PickleRole,
) -> None:
    assert classify_pickle_role(path) is expected


def test_config_names_take_priority_over_json_suffix() -> None:
    assert classify_file_kind("config.json") is FileKind.CONFIG_JSON
    assert classify_file_kind("tokenizer_config.json") is FileKind.TOKENIZER_CONFIG_JSON
    assert classify_file_kind("other_config.json") is FileKind.OTHER


def test_windows_repo_path_is_normalized_to_posix() -> None:
    assert normalize_repo_path(r"models\demo\modeling_demo.py") == "models/demo/modeling_demo.py"

    artifact = build_artifact_ref(r"models\demo\modeling_demo.py", b"print('x')\n")
    assert artifact.repo_path == "models/demo/modeling_demo.py"
    assert artifact.file_name == "modeling_demo.py"
    assert artifact.file_kind is FileKind.PYTHON


def test_artifact_ref_uses_bytes_for_sha256_and_size() -> None:
    content = b"abc"
    artifact = build_artifact_ref(
        "model.safetensors",
        content,
        source_url="https://huggingface.co/org/model/resolve/main/model.safetensors",
    )

    expected_sha = hashlib.sha256(content).hexdigest()
    assert sha256_bytes(content) == expected_sha
    assert artifact.sha256 == expected_sha
    assert artifact.artifact_id == f"sha256:{expected_sha}"
    assert artifact.size_bytes == len(content)
    assert artifact.detected_extension == ".safetensors"
    assert artifact.file_kind is FileKind.SAFETENSORS
    assert artifact.to_dict()["file_kind"] == "SAFETENSORS"


def test_artifact_ref_can_read_local_file_without_importing_code(tmp_path) -> None:
    local_file = tmp_path / "modeling_safe.py"
    local_file.write_text("class Demo: pass\n", encoding="utf-8")

    artifact = build_artifact_ref_from_file(
        local_file,
        repo_path=r"custom\modeling_safe.py",
        referenced_by=["config.json"],
    )

    assert artifact.repo_path == "custom/modeling_safe.py"
    assert artifact.temp_local_path == str(local_file)
    assert artifact.file_kind is FileKind.PYTHON
    assert artifact.referenced_by == ["config.json"]
    assert artifact.is_generated is False


def test_build_artifact_ref_requires_content_or_local_path() -> None:
    with pytest.raises(ValueError):
        build_artifact_ref("missing.py")
