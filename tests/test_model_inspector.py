"""대시보드 '모델 검사' 서버측 글루(whitelist.model_inspector) 회귀.

브라우저 대신 서버가 다운로드/검증을 대행하는 경로를 검증한다. 네트워크 없는
fixture(tmp_path) 기반 — 다운로드 단계는 분리(:func:`inspect_artifacts`)되어 있어
HF 접근 없이 검증 로직과 가시화 메타를 모두 테스트한다.
"""
import hashlib
from pathlib import Path

from whitelist.model_inspector import (
    build_inspect_artifacts,
    inspect_artifacts,
    inspect_model_repo,
)

EVIL_PY = (
    "import os\n"
    "def hook(cmd):\n"
    "    return eval(cmd)\n"  # 명확한 위험 호출 → BLOCK
)
SAFE_PY = (
    "import torch.nn as nn\n"
    "class Net(nn.Module):\n"
    "    def forward(self, x):\n"
    "        return x\n"
)
CONFIG_JSON = '{"model_type": "roberta", "hidden_size": 768}\n'


def _artifact(path: Path, repo_path: str, file_kind: str) -> dict:
    data = path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    ext = "." + repo_path.rsplit(".", 1)[-1] if "." in repo_path else ""
    return {
        "artifact_id": f"sha256:{digest}",
        "repo_path": repo_path,
        "file_name": path.name,
        "file_kind": file_kind,
        "detected_extension": ext,
        "size_bytes": len(data),
        "sha256": digest,
        "source_url": f"https://huggingface.co/demo/{repo_path}",
        "temp_local_path": str(path),
    }


def test_inspect_artifacts_blocks_malicious_and_exposes_stage(db_session, tmp_path):
    evil = tmp_path / "modeling_evil.py"
    evil.write_text(EVIL_PY, encoding="utf-8")
    cfg = tmp_path / "config.json"
    cfg.write_text(CONFIG_JSON, encoding="utf-8")

    resp = inspect_artifacts(
        [
            _artifact(evil, "modeling_evil.py", "PYTHON"),
            _artifact(cfg, "config.json", "CONFIG_JSON"),
        ],
        db=db_session,
        repo_id="demo/evil",
    )

    # 전체 판정은 DENY
    assert resp.overall_decision.value == "DENY", resp.overall_decision

    # 각 결과에 가시화용 단계(route_kind)가 채워져 있어야 함
    by_path = {r.artifact.repo_path: r for r in resp.artifact_results}
    assert by_path["modeling_evil.py"].route_kind.value == "CODE_AST_SCAN"
    assert by_path["modeling_evil.py"].status.value == "BLOCK"
    # 사유(증거)가 가시화될 수 있게 reason_entries가 비어있지 않음
    assert by_path["modeling_evil.py"].reason_entries


def test_inspect_artifacts_safe_model_not_denied(db_session, tmp_path):
    safe = tmp_path / "modeling_safe.py"
    safe.write_text(SAFE_PY, encoding="utf-8")
    cfg = tmp_path / "config.json"
    cfg.write_text(CONFIG_JSON, encoding="utf-8")

    resp = inspect_artifacts(
        [
            _artifact(safe, "modeling_safe.py", "PYTHON"),
            _artifact(cfg, "config.json", "CONFIG_JSON"),
        ],
        db=db_session,
        repo_id="demo/safe",
    )
    assert resp.overall_decision.value != "DENY", resp.overall_decision


def test_build_inspect_artifacts_classifies_and_skips(tmp_path):
    (tmp_path / "modeling_x.py").write_text(SAFE_PY, encoding="utf-8")
    (tmp_path / "config.json").write_text(CONFIG_JSON, encoding="utf-8")
    (tmp_path / "README.bin").write_bytes(b"\x00\x01")  # OTHER 분류 → 제외
    (tmp_path / "model.safetensors").write_bytes(b"\x00" * 8)  # 가중치

    arts, skipped_other, skipped_weights = build_inspect_artifacts(
        tmp_path, "demo/x", skip_weights=True
    )
    repo_paths = {a["repo_path"] for a in arts}
    assert "modeling_x.py" in repo_paths
    assert "config.json" in repo_paths
    assert "model.safetensors" not in repo_paths  # skip_weights
    assert "model.safetensors" in skipped_weights
    # README.bin은 OTHER로 제외(검사 대상 아님)
    assert "model.safetensors" not in repo_paths


def test_inspect_model_repo_empty_repo_id_fails_gracefully(db_session):
    out = inspect_model_repo("  ", db=db_session)
    assert out["ok"] is False
    assert out["error_code"] == "EMPTY_REPO_ID"


def test_b2_demo_routes_to_sandbox(db_session):
    # 내장 B-2 데모가 CODE_SANDBOX_RUNTIME(gVisor 레인)으로 라우팅돼야 실
    # sandbox 실행(toggle ON, WSL2)이 트리거된다. 라우팅 자체는 OS 무관.
    out = inspect_model_repo("demo:b2-sandbox", db=db_session)
    assert out["ok"] is True
    by_path = {r.artifact.repo_path: r for r in out["response"].artifact_results}
    r = by_path["modeling_b2_demo.py"]
    assert r.route_kind.value == "CODE_SANDBOX_RUNTIME", r.route_kind.value
    assert r.grade.value == "B-2", r.grade.value
