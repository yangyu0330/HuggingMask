"""전처리 baseline 자동화 — A(레지스트리 매칭)·B(불변식 통과) 회귀.

A: 등록된 known-good 해시와 일치하면 자동 PASS(SEMANTIC_CHECK_PASSED).
B(opt-in): baseline 없어도 구조적으로 안전하면 PASS(INVARIANTS_OK). 악성은 항상 차단.
"""

import json

import pytest

from analyzer.classifier import build_artifact_ref
from analyzer.validators import baseline_registry as br
from analyzer.validators.code_semantic import validate_preprocessing_metadata_artifact

CLEAN = json.dumps({"version": "1.0", "model": {"type": "BPE", "vocab": {"<pad>": 0, "hi": 1}}})
EVIL = json.dumps({"auto_map": {"AutoTokenizer": "tok_mod.EvilTokenizer"}, "model": {"type": "BPE"}})


@pytest.fixture
def temp_registry(tmp_path, monkeypatch):
    reg = tmp_path / "baselines.json"
    monkeypatch.setenv("HUGGINGMASK_BASELINE_REGISTRY", str(reg))
    br.reload()
    yield reg
    br.reload()


def _validate(source):
    artifact = build_artifact_ref("tokenizer.json", source)
    return validate_preprocessing_metadata_artifact(artifact, source, None)


def test_A_registered_baseline_auto_passes(temp_registry, monkeypatch):
    monkeypatch.delenv("HUGGINGMASK_PREPROCESSING_INVARIANTS", raising=False)
    br.register_baseline(CLEAN, repo_id="seed/x", file_name="tokenizer.json")
    br.reload()
    result = _validate(CLEAN)
    assert result.status.value == "PASS"
    assert result.details["semantic_check"]["status"] == "PASSED"


def test_unregistered_clean_default_stays_review(temp_registry, monkeypatch):
    monkeypatch.delenv("HUGGINGMASK_PREPROCESSING_INVARIANTS", raising=False)
    result = _validate(CLEAN)
    assert result.status.value == "PENDING_REVIEW"
    assert result.details["semantic_check"]["status"] == "BASELINE_MISSING"


def test_B_invariants_optin_passes_clean(temp_registry, monkeypatch):
    monkeypatch.setenv("HUGGINGMASK_PREPROCESSING_INVARIANTS", "1")
    result = _validate(CLEAN)
    assert result.status.value == "PASS"
    assert result.details["semantic_check"]["status"] == "INVARIANTS_OK"


def test_B_invariants_optin_still_blocks_malicious(temp_registry, monkeypatch):
    monkeypatch.setenv("HUGGINGMASK_PREPROCESSING_INVARIANTS", "1")
    result = _validate(EVIL)
    assert result.status.value == "PENDING_REVIEW"
    assert result.details["semantic_check"]["status"] == "FAILED"
    assert "PREPROCESSING_CUSTOM_CODE_REF" in [f["code"] for f in result.details["semantic_findings"]]
