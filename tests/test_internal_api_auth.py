"""내부 API opt-in 인증(D8) 회귀 테스트.

HUGGINGMASK_INTERNAL_API_TOKEN 미설정 → 기존처럼 통과(무인증).
설정 → /internal/* 은 토큰 헤더 요구. /health·/dashboard 는 항상 개방.
"""
import pytest
from fastapi.testclient import TestClient

from proxy.app.main import app

client = TestClient(app)

_TOKEN = "secret-token-123"
_EMPTY_JOB = {
    "request_id": "t",
    "job_id": "t",
    "policy_fingerprint": "policy-2026.04.22",
    "artifacts": [],
}


@pytest.fixture(autouse=True)
def _clear_token(monkeypatch):
    monkeypatch.delenv("HUGGINGMASK_INTERNAL_API_TOKEN", raising=False)
    yield


def test_no_token_env_allows_request():
    # 인증 비활성(기본) → 통과 (빈입력은 ERROR지만 HTTP 200)
    r = client.post("/internal/v1/validation/jobs", json=_EMPTY_JOB)
    assert r.status_code == 200


def test_token_set_missing_header_rejected(monkeypatch):
    monkeypatch.setenv("HUGGINGMASK_INTERNAL_API_TOKEN", _TOKEN)
    r = client.post("/internal/v1/validation/jobs", json=_EMPTY_JOB)
    assert r.status_code == 401


def test_blank_token_is_fail_closed(monkeypatch):
    # 양유상 PR #54 P1: 설정됐는데 빈 문자열이면 무인증(fail-open) 아니라 fail-closed(503)
    monkeypatch.setenv("HUGGINGMASK_INTERNAL_API_TOKEN", "")
    r = client.post("/internal/v1/validation/jobs", json=_EMPTY_JOB)
    assert r.status_code == 503


def test_whitespace_token_is_fail_closed(monkeypatch):
    monkeypatch.setenv("HUGGINGMASK_INTERNAL_API_TOKEN", "   ")
    r = client.post("/internal/v1/validation/jobs", json=_EMPTY_JOB)
    assert r.status_code == 503


def test_token_set_wrong_header_rejected(monkeypatch):
    monkeypatch.setenv("HUGGINGMASK_INTERNAL_API_TOKEN", _TOKEN)
    r = client.post(
        "/internal/v1/validation/jobs",
        headers={"X-Internal-Token": "wrong"},
        json=_EMPTY_JOB,
    )
    assert r.status_code == 401


def test_token_set_correct_header_passes(monkeypatch):
    monkeypatch.setenv("HUGGINGMASK_INTERNAL_API_TOKEN", _TOKEN)
    r = client.post(
        "/internal/v1/validation/jobs",
        headers={"X-Internal-Token": _TOKEN},
        json=_EMPTY_JOB,
    )
    assert r.status_code == 200


def test_bearer_authorization_header_works(monkeypatch):
    monkeypatch.setenv("HUGGINGMASK_INTERNAL_API_TOKEN", _TOKEN)
    r = client.post(
        "/internal/v1/validation/jobs",
        headers={"Authorization": f"Bearer {_TOKEN}"},
        json=_EMPTY_JOB,
    )
    assert r.status_code == 200


def test_whitelist_router_protected(monkeypatch):
    # 화이트리스트 라우터(review/approve/audit 등)도 인증 대상인지 확인.
    # 토큰 없으면 핸들러/DB 도달 전 401로 차단. (토큰 통과 후 동작은
    # validation 엔드포인트 positive 테스트가 이미 커버.)
    monkeypatch.setenv("HUGGINGMASK_INTERNAL_API_TOKEN", _TOKEN)
    assert client.get("/internal/v1/pending").status_code == 401
    assert client.post("/internal/v1/review", json={}).status_code == 401


def test_health_and_dashboard_open_even_with_token(monkeypatch):
    monkeypatch.setenv("HUGGINGMASK_INTERNAL_API_TOKEN", _TOKEN)
    assert client.get("/health").status_code == 200
    # /dashboard 는 정적 UI — 인증 대상 아님 (200 또는 404 허용)
    assert client.get("/dashboard").status_code in (200, 404)
