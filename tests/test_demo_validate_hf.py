from analyzer.classifier import classify_file_kind as classify_core_file_kind
from analyzer.schemas import FileKind
from scripts.demo_validate_hf import build_artifacts


def _write_fixture(root, repo_path: str) -> None:
    path = root / repo_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(f"fixture:{repo_path}".encode("utf-8"))


def test_demo_artifacts_use_core_classifier_for_supported_files(tmp_path, capsys) -> None:
    repo_paths = [
        "model.safetensors",
        "weights.pkl",
        "modeling_demo.py",
        "config.json",
        "tokenizer_config.json",
        "tokenizer.json",
        "special_tokens_map.json",
        "preprocessor_config.json",
        "processor_config.json",
        "README.md",
        "weights.pth",
    ]
    for repo_path in repo_paths:
        _write_fixture(tmp_path, repo_path)

    artifacts = build_artifacts(tmp_path, "org/model", skip_weights=False)

    expected = {
        repo_path: classify_core_file_kind(repo_path).value
        for repo_path in repo_paths
        if classify_core_file_kind(repo_path) is not FileKind.OTHER
    }
    actual = {artifact["repo_path"]: artifact["file_kind"] for artifact in artifacts}
    assert actual == expected
    assert actual["preprocessor_config.json"] == FileKind.PREPROCESSOR_CONFIG_JSON.value
    assert actual["processor_config.json"] == FileKind.PROCESSOR_CONFIG_JSON.value

    output = capsys.readouterr().out
    assert "core FileKind=OTHER" in output
    assert "README.md" in output
    assert "weights.pth" in output


def test_demo_skip_weights_reports_explicitly_and_keeps_metadata(tmp_path, capsys) -> None:
    for repo_path in ["model.safetensors", "weights.pkl", "preprocessor_config.json"]:
        _write_fixture(tmp_path, repo_path)

    artifacts = build_artifacts(tmp_path, "org/model", skip_weights=True)

    assert [artifact["repo_path"] for artifact in artifacts] == ["preprocessor_config.json"]
    assert artifacts[0]["file_kind"] == FileKind.PREPROCESSOR_CONFIG_JSON.value

    output = capsys.readouterr().out
    assert "--skip-weights" in output
    assert "model.safetensors" in output
    assert "weights.pkl" in output
