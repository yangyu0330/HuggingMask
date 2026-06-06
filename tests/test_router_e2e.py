"""
라우터 E2E 테스트 — FastAPI TestClient로 실제 HTTP 흐름 검증.

이 테스트는 인메모리 DB가 아닌 실제 SQLite 파일을 사용하므로,
fixture에서 임시 디렉토리에 DB를 격리한다.
"""

import json
import os
import tempfile
import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(monkeypatch):
    """매 테스트마다 격리된 SQLite 파일 사용"""
    tmpdir = tempfile.mkdtemp()
    db_path = Path(tmpdir) / "whitelist.db"
    monkeypatch.setenv("HUGGINGMASK_DB_URL", f"sqlite:///{db_path}")

    # database 모듈을 새 URL로 재로드해야 함
    import importlib
    from whitelist import database as db_mod
    importlib.reload(db_mod)
    from whitelist import tables as t_mod
    importlib.reload(t_mod)
    from whitelist import audit as a_mod
    importlib.reload(a_mod)
    from whitelist import pending_store as ps_mod
    importlib.reload(ps_mod)
    from whitelist import engine as e_mod
    importlib.reload(e_mod)
    from whitelist import feedback as fb_mod
    importlib.reload(fb_mod)
    from whitelist import bootstrap as bs_mod
    importlib.reload(bs_mod)
    from whitelist import router as r_mod
    importlib.reload(r_mod)
    from proxy.app import main as m_mod
    importlib.reload(m_mod)

    with TestClient(m_mod.app) as c:
        yield c

    # SQLite 파일 락 해제를 위해 engine 명시적 dispose
    try:
        db_mod.engine.dispose()
    except Exception:
        pass
    # Windows에서는 가비지 컬렉션 후에도 파일 락이 늦게 해제될 수 있음 — 베스트 에포트로 정리
    try:
        if db_path.exists():
            db_path.unlink()
        os.rmdir(tmpdir)
    except (PermissionError, OSError):
        pass  # 임시 파일이므로 OS가 정리하도록 둠


def _model_payload() -> dict:
    return {
        "repo_id": "org/demo-model",
        "revision": "main",
        "source_host": "huggingface.co",
        "source_url": "https://huggingface.co/org/demo-model",
        "requested_by": "developer-a",
        "requested_at": "2026-04-20T09:00:00Z",
        "endpoint_mode": "HF_ENDPOINT_PROXY",
    }


class TestSpecExample:
    """인터페이스 정의서 14.1 예시 페이로드 → 14.2 예시 응답 형태"""

    def test_check_three_apis(self, client):
        payload = {
            "schema_version": "1.0",
            "request_id": str(uuid.uuid4()),
            "job_id": str(uuid.uuid4()),
            "model": _model_payload(),
            "apis": [
                "torch.nn.Linear",
                "torch.load",
                "torch.nn.functional.scaled_dot_product_attention",
            ],
        }
        r = client.post("/internal/v1/whitelist/check", json=payload)
        assert r.status_code == 200
        body = r.json()

        # 14.2절 — 응답은 배열 (wrapper 없음)
        assert isinstance(body, list)
        assert len(body) == 3
        # 각 항목에 whitelist_version 포함
        assert all(item["whitelist_version"].startswith("wl-") for item in body)

        results = {x["api_path"]: x for x in body}

        # 시드에 포함되어 있으니 ALLOWED
        assert results["torch.nn.Linear"]["status"] == "ALLOWED"
        # 영구 차단
        assert results["torch.load"]["status"] == "BLOCKED"
        # 시드 포함이지만 정확 매칭 시 ALLOWED, 아니면 PENDING — 시드에 있음
        assert results["torch.nn.functional.scaled_dot_product_attention"]["status"] == "ALLOWED"


class TestPendingFlow:

    def test_unknown_api_creates_pending_then_listed(self, client):
        payload = {
            "schema_version": "1.0",
            "request_id": str(uuid.uuid4()),
            "job_id": str(uuid.uuid4()),
            "model": _model_payload(),
            "apis": ["torch.nn.MyBrandNewLayer"],
        }
        r = client.post("/internal/v1/whitelist/check", json=payload)
        assert r.status_code == 200
        assert r.json()[0]["status"] == "PENDING"

        # GET /pending에서 보여야 함
        r2 = client.get("/internal/v1/pending")
        items = r2.json()["items"]
        assert any(i["api_path"] == "torch.nn.MyBrandNewLayer" for i in items)


class TestReviewFlow:

    def test_approve_changes_subsequent_check_to_allowed(self, client):
        # 1. 미등록 API 호출 → PENDING
        new_api = "torch.nn.functional.flexible_attention_v2"
        payload = {
            "schema_version": "1.0",
            "request_id": str(uuid.uuid4()),
            "job_id": str(uuid.uuid4()),
            "model": _model_payload(),
            "apis": [new_api],
        }
        client.post("/internal/v1/whitelist/check", json=payload)

        # 2. 보안 담당자 승인
        r = client.post("/internal/v1/review", json={
            "api_path": new_api,
            "decision": "approve",
            "reviewer_id": "admin_01",
            "review_note": "공식 PyTorch 2.5 신규 API",
        })
        assert r.status_code == 200
        assert r.json()["applied"] is True

        # 3. 다시 check → ALLOWED
        r2 = client.post("/internal/v1/whitelist/check", json={
            **payload, "request_id": str(uuid.uuid4()),
            "job_id": str(uuid.uuid4()),
        })
        assert r2.json()[0]["status"] == "ALLOWED"
        assert r2.json()[0]["source"] == "MANUAL_REVIEW"

    def test_canonical_reviews_decide_returns_audit_metadata(self, client):
        new_api = "torch.nn.functional.review_decide_layer"
        payload = {
            "schema_version": "1.0",
            "request_id": str(uuid.uuid4()),
            "job_id": str(uuid.uuid4()),
            "model": _model_payload(),
            "apis": [new_api],
        }
        client.post("/internal/v1/whitelist/check", json=payload)

        r = client.post("/internal/v1/reviews/decide", json={
            "api_path": new_api,
            "decision": "approve",
            "reviewer_id": "admin_01",
            "review_note": "canonical endpoint approval",
            "review_id": "rev-router-canonical-001",
            "source_evidence": ["test:e2e"],
        })
        assert r.status_code == 200
        body = r.json()
        assert body["applied"] is True
        assert body["review_id"] == "rev-router-canonical-001"
        assert body["final_review_status"] == "APPROVED"
        assert body["audit_event_id"] is not None
        assert body["audit_event_hash"]


class TestFeedbackFlow:

    def test_normal_feedback(self, client):
        r = client.post("/internal/v1/feedback", json={
            "blocked_api": "transformers.WhisperForConditionalGeneration",
            "model_id": "openai/whisper-large",
            "purpose": "음성 인식",
            "reporter_id": "dev_test",
        })
        assert r.status_code == 200
        body = r.json()
        assert body["report_id"].startswith("FB-")
        assert not body["auto_rejected"]

    def test_blocked_api_auto_rejected(self, client):
        r = client.post("/internal/v1/feedback", json={
            "blocked_api": "torch.load",
            "model_id": "evil/model",
            "purpose": "pickle 로드",
            "reporter_id": "dev_test",
        })
        body = r.json()
        assert body["auto_rejected"]
        assert body["estimated_response_hours"] == 0


class TestAuditChainEndpoint:

    def test_chain_starts_intact(self, client):
        # 시드 로드 + 몇 번 호출
        client.post("/internal/v1/whitelist/check", json={
            "schema_version": "1.0",
            "request_id": str(uuid.uuid4()),
            "job_id": str(uuid.uuid4()),
            "model": _model_payload(),
            "apis": ["torch.nn.NewSomething"],
        })
        r = client.get("/internal/v1/audit/verify")
        assert r.status_code == 200
        body = r.json()
        assert body["valid"] is True
        assert body["total_entries"] >= 1


class TestStats:

    def test_stats_endpoint(self, client):
        r = client.get("/internal/v1/stats")
        assert r.status_code == 200
        body = r.json()
        assert body["whitelist_version"].startswith("wl-")
        assert body["approved_active"] >= 145  # 시드 145개 이상


class TestHealth:
    """기존 test_health.py와 같은 동작 — main.py 변경 후에도 health 살아있는지"""

    def test_health(self, client):
        r = client.get("/health")
        assert r.status_code == 200
        assert r.json() == {"status": "ok"}

    def test_root(self, client):
        r = client.get("/")
        assert r.status_code == 200
