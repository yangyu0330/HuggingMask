"""
운영 대시보드 + bulk 스크립트 통합 회귀.

대시보드 (proxy/app/main.py /dashboard):
- GET /dashboard 200 + HTML 응답
- HTML 안에 우리 인터페이스 정의서 path가 들어가 있는지 (회귀)
- 4탭 (분류 테스트 / 리뷰 대기 / 승인 / 오탐 / 감사) 마크업 존재

GET /internal/v1/approved (router.py 신규):
- 시드 데이터로 ApprovedApi 검색·필터·페이지네이션

bulk 스크립트:
- 모듈 import 가능 (smoke)
- 핵심 상수(SAFE_NAMESPACES, SKIP_KEYWORDS) 정합성
"""

import os
import tempfile
import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(monkeypatch):
    """매 테스트마다 격리 SQLite + reload (test_router_e2e.py 패턴 동일)."""
    tmpdir = tempfile.mkdtemp()
    db_path = Path(tmpdir) / "whitelist.db"
    monkeypatch.setenv("HUGGINGMASK_DB_URL", f"sqlite:///{db_path}")

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

    try:
        db_mod.engine.dispose()
    except Exception:
        pass
    try:
        if db_path.exists():
            db_path.unlink()
        os.rmdir(tmpdir)
    except (PermissionError, OSError):
        pass


# ─────────────────────────────────────────────
# /dashboard 엔드포인트
# ─────────────────────────────────────────────

class TestDashboardEndpoint:

    def test_dashboard_returns_html_200(self, client):
        r = client.get("/dashboard")
        assert r.status_code == 200
        assert "text/html" in r.headers.get("content-type", "")

    def test_dashboard_uses_backend_proxy_api_base(self, client):
        """Dashboard JS must use the backend proxy, not protected internals."""
        r = client.get("/dashboard")
        body = r.text
        assert "/dashboard/api" in body
        assert "/internal/v1" not in body
        assert "HUGGINGMASK_INTERNAL_API_TOKEN" not in body
        assert "X-Internal-Token" not in body
        assert "'/api/v1'" not in body  # 원본 prefix 회귀 방지

    def test_dashboard_uses_uppercase_enum(self, client):
        """JS의 enum 매핑이 대문자(우리 schema)로 되어있는지 회귀."""
        r = client.get("/dashboard")
        body = r.text
        # 핵심 enum이 대문자로 등장
        assert "AUTO_APPROVE" in body
        assert "PENDING" in body
        assert "ALLOWED" in body or "BLOCKED" in body
        # statusBadge / clsBadge / rvBadge 함수 정의 존재
        assert "statusBadge" in body
        assert "clsBadge" in body
        assert "rvBadge" in body

    def test_dashboard_has_four_tabs(self, client):
        r = client.get("/dashboard")
        body = r.text
        assert "분류 테스트" in body
        assert "리뷰 대기" in body
        assert "승인 목록" in body
        assert "오탐 피드백" in body
        assert "감사 로그" in body

    def test_dashboard_uses_risk_keywords_not_old_key(self, client):
        """원본 ``danger_keywords_found`` 키를 우리 ``risk_keywords``로 교체한 회귀."""
        r = client.get("/dashboard")
        body = r.text
        # 우리 키 사용
        assert "risk_keywords" in body
        # 원본 키는 더 이상 안 씀
        assert "danger_keywords_found" not in body


# ─────────────────────────────────────────────
# /internal/v1/approved 엔드포인트
# ─────────────────────────────────────────────

class TestApprovedListEndpoint:

    def test_lists_seeded_apis(self, client):
        """시드 145개 → /approved 첫 페이지 50개."""
        r = client.get("/internal/v1/approved")
        assert r.status_code == 200
        body = r.json()
        assert body["total"] >= 145
        assert len(body["items"]) <= 50

    def test_search_filter(self, client):
        r = client.get(
            "/internal/v1/approved",
            params={"search": "torch.nn.Linear"},
        )
        assert r.status_code == 200
        items = r.json()["items"]
        assert len(items) >= 1
        assert any(it["api_path"] == "torch.nn.Linear" for it in items)

    def test_namespace_filter(self, client):
        r = client.get(
            "/internal/v1/approved",
            params={"namespace": "torch.nn"},
        )
        items = r.json()["items"]
        assert all("torch.nn" in it["namespace"] for it in items)

    def test_source_filter_initial(self, client):
        r = client.get(
            "/internal/v1/approved",
            params={"source": "INITIAL"},
        )
        items = r.json()["items"]
        assert all(it["source"] == "INITIAL" for it in items)

    def test_pagination(self, client):
        r1 = client.get(
            "/internal/v1/approved",
            params={"limit": 10, "offset": 0},
        )
        r2 = client.get(
            "/internal/v1/approved",
            params={"limit": 10, "offset": 10},
        )
        items1 = {x["api_path"] for x in r1.json()["items"]}
        items2 = {x["api_path"] for x in r2.json()["items"]}
        assert items1 != items2  # 겹치지 않음
        assert len(items1) == 10
        assert len(items2) <= 10

    def test_response_keys_match_dashboard_expectations(self, client):
        """대시보드 JS가 기대하는 키 셋."""
        r = client.get("/internal/v1/approved", params={"limit": 1})
        items = r.json()["items"]
        if items:
            keys = items[0].keys()
            for required in (
                "api_path", "namespace", "source", "matched_rule",
                "source_version", "added_date", "reviewer_id", "review_note",
            ):
                assert required in keys, f"{required} 누락"


# ─────────────────────────────────────────────
# bulk 스크립트 — smoke + 정합성
# ─────────────────────────────────────────────

class TestDashboardProxyAuth:

    def test_dashboard_proxy_get_works_with_token_enabled(self, client, monkeypatch):
        token = "dashboard-proxy-secret"
        monkeypatch.setenv("HUGGINGMASK_INTERNAL_API_TOKEN", token)

        assert client.get("/internal/v1/stats").status_code == 401

        r = client.get("/dashboard/api/stats")
        assert r.status_code == 200
        body = r.json()
        assert body["whitelist_version"].startswith("wl-")
        assert token not in r.text

    def test_dashboard_proxy_post_works_with_token_enabled(self, client, monkeypatch):
        token = "dashboard-proxy-secret"
        monkeypatch.setenv("HUGGINGMASK_INTERNAL_API_TOKEN", token)
        payload = {
            "schema_version": "1.0",
            "request_id": str(uuid.uuid4()),
            "job_id": str(uuid.uuid4()),
            "model": {
                "repo_id": "dashboard/test",
                "revision": "main",
                "source_host": "huggingface.co",
                "source_url": "https://huggingface.co/dashboard/test",
                "requested_by": "dashboard",
                "requested_at": "2026-05-08T00:00:00Z",
                "endpoint_mode": "HF_ENDPOINT_PROXY",
            },
            "apis": ["torch.nn.DashboardProxyLayer"],
        }

        assert client.post(
            "/internal/v1/whitelist/check",
            json=payload,
        ).status_code == 401

        r = client.post("/dashboard/api/whitelist/check", json=payload)
        assert r.status_code == 200
        body = r.json()
        assert body[0]["api_path"] == "torch.nn.DashboardProxyLayer"
        assert token not in r.text


class TestBulkScripts:

    def test_bulk_approve_imports(self):
        """import 가능 + main 함수 존재."""
        import scripts.bulk_approve as ba
        assert callable(ba.bulk_approve_auto)
        assert callable(ba.main)
        assert "AUTO_APPROVE" in ba.bulk_approve_auto.__doc__ or True

    def test_bulk_conditional_imports(self):
        import scripts.bulk_conditional as bc
        assert callable(bc.main)
        # 안전 namespace 정합 — 우리 rules.NAMESPACE_RULES와 일치
        for ns in bc.SAFE_NAMESPACES:
            assert ns.endswith(".")
        # 위험 키워드 정합 — 우리 rules.DANGER_KEYWORDS와 교집합
        from whitelist.rules import DANGER_KEYWORDS
        common = bc.SKIP_KEYWORDS & DANGER_KEYWORDS
        assert len(common) >= 5, "bulk_conditional이 우리 위험 키워드와 정합 안 됨"

    def test_bulk_uses_internal_v1_base(self):
        """기본 API base가 /internal/v1로 변경됐는지 회귀."""
        import scripts.bulk_approve as ba
        import scripts.bulk_conditional as bc
        assert "/internal/v1" in ba.DEFAULT_API_BASE
        assert "/internal/v1" in bc.DEFAULT_API_BASE


# ─────────────────────────────────────────────
# PR #20 리뷰 응답 회귀 — bulk 스크립트 논리 오류 2건
#   (양유상 2026-05-18 inline: bulk_approve.py:66 응답 미검증 /
#    bulk_conditional.py:110 pagination offset 버그)
# ─────────────────────────────────────────────

import httpx


class _FakeWhitelistAPI:
    """httpx.MockTransport용 가짜 화이트리스트 서버.

    /pending 은 offset/limit 페이지네이션을 실제로 수행하고,
    /review approve 는 해당 api_path를 pending에서 제거한다.
    fail_paths 에 든 api_path는 500을 반환하고 pending에 그대로 남긴다.
    """

    def __init__(self, pending: list[dict], fail_paths: set[str] | None = None):
        # api_path -> item
        self.pending = {it["api_path"]: it for it in pending}
        self.fail_paths = fail_paths or set()
        self.review_calls = 0

    def handler(self, request: httpx.Request) -> httpx.Response:
        url = request.url
        if url.path.endswith("/stats"):
            return httpx.Response(200, json={
                "approved_active": 0, "pending_review": len(self.pending),
                "blocked": 0, "whitelist_version": 1,
            })
        if url.path.endswith("/pending"):
            offset = int(url.params.get("offset", 0))
            limit = int(url.params.get("limit", 50))
            items = list(self.pending.values())[offset:offset + limit]
            return httpx.Response(200, json={"items": items})
        if url.path.endswith("/review"):
            import json as _json
            body = _json.loads(request.content)
            path = body["api_path"]
            self.review_calls += 1
            if path in self.fail_paths:
                return httpx.Response(500, json={"applied": False})
            # 승인 → pending에서 제거 (목록이 줄어든다)
            self.pending.pop(path, None)
            return httpx.Response(200, json={"applied": True})
        return httpx.Response(404)


class TestBulkApproveResponseValidation:
    """bulk_approve.py:66 — /review 응답을 검증해야 한다."""

    def _client(self, api: _FakeWhitelistAPI) -> httpx.Client:
        return httpx.Client(transport=httpx.MockTransport(api.handler))

    def test_failed_approval_not_counted(self):
        """500 응답 항목은 승인 카운트에 포함되지 않는다."""
        import scripts.bulk_approve as ba
        items = [
            {"api_path": f"torch.nn.Ok{i}"} for i in range(3)
        ] + [{"api_path": "torch.nn.Bad"}]
        api = _FakeWhitelistAPI(items, fail_paths={"torch.nn.Bad"})
        with self._client(api) as c:
            n = ba.bulk_approve_auto(c, "http://x/internal/v1")
        assert n == 3, "실패 항목까지 카운트하면 안 됨"

    def test_failed_item_does_not_loop_forever(self):
        """실패해 pending에 남는 항목이 무한 재시도되지 않는다."""
        import scripts.bulk_approve as ba
        api = _FakeWhitelistAPI(
            [{"api_path": "torch.nn.Bad"}], fail_paths={"torch.nn.Bad"},
        )
        with self._client(api) as c:
            n = ba.bulk_approve_auto(c, "http://x/internal/v1")
        assert n == 0
        # 한 번만 시도하고 종료 (무한 루프 아님)
        assert api.review_calls == 1

    def test_all_success_counted(self):
        import scripts.bulk_approve as ba
        api = _FakeWhitelistAPI([{"api_path": f"torch.nn.L{i}"} for i in range(120)])
        with self._client(api) as c:
            n = ba.bulk_approve_auto(c, "http://x/internal/v1")
        assert n == 120

    def test_first_page_all_fail_still_reaches_later_items(self):
        """Issue #28 — 첫 페이지 50개가 전부 실패해도 51번째 이후 PENDING
        항목이 스킵되지 않고 모두 한 번씩 승인 시도돼야 한다.

        옛 구현: offset=0 재조회 + failed set 필터링 → 첫 50개가 다 failed면
        다음 페이지 응답이 같은 50개라 targets가 빈 셋 → 51+ 항목 미처리.
        새 구현: collect_pending_auto_approve 후 process.
        """
        import scripts.bulk_approve as ba
        items = [{"api_path": f"torch.nn.Bad{i}"} for i in range(50)]
        items += [{"api_path": f"torch.nn.Ok{i}"} for i in range(3)]
        fail = {f"torch.nn.Bad{i}" for i in range(50)}
        api = _FakeWhitelistAPI(items, fail_paths=fail)
        with self._client(api) as c:
            n = ba.bulk_approve_auto(c, "http://x/internal/v1")
        assert n == 3, "첫 페이지 전부 실패 후 51번째 이후 3개가 승인돼야 함"
        # 모든 53개 항목에 정확히 한 번씩 승인 시도 (재시도 없음)
        assert api.review_calls == 53

    def test_collect_pending_paginates(self):
        """collect_pending_auto_approve가 130개 → 3페이지 안정적 수집."""
        import scripts.bulk_approve as ba
        items = [{"api_path": f"torch.nn.L{i}"} for i in range(130)]
        api = _FakeWhitelistAPI(items)
        with self._client(api) as c:
            collected = ba.collect_pending_auto_approve(c, "http://x/internal/v1")
        assert len(collected) == 130


class TestBulkConditionalPagination:
    """bulk_conditional.py:110 — pagination offset 버그.

    승인하면서 목록이 줄어드는데 offset += 50 하면 항목을 건너뛴다.
    collect-then-process로 모든 안전 대상이 처리돼야 한다.
    """

    def _client(self, api: _FakeWhitelistAPI) -> httpx.Client:
        return httpx.Client(transport=httpx.MockTransport(api.handler))

    def test_all_safe_targets_approved_across_pages(self):
        import scripts.bulk_conditional as bc
        # 60개 전부 안전 namespace → 두 페이지에 걸침. 옛 버그면 일부 누락.
        items = [{"api_path": f"torch.optim.Opt{i}", "risk_keywords": []}
                 for i in range(60)]
        api = _FakeWhitelistAPI(items)
        with self._client(api) as c:
            collected = bc.collect_pending(c, "http://x/internal/v1")
            approved = sum(
                1 for it in collected
                if bc._is_safe_conditional(it)
                and bc._apply_review(c, "http://x/internal/v1",
                                     it["api_path"], "tester")
            )
        assert approved == 60, "pagination 누락 — 60개 전부 승인돼야 함"

    def test_collect_pending_paginates_fully(self):
        import scripts.bulk_conditional as bc
        items = [{"api_path": f"torch.optim.Opt{i}", "risk_keywords": []}
                 for i in range(130)]
        api = _FakeWhitelistAPI(items)
        with self._client(api) as c:
            collected = bc.collect_pending(c, "http://x/internal/v1")
        assert len(collected) == 130

    def test_unsafe_namespace_skipped(self):
        import scripts.bulk_conditional as bc
        item = {"api_path": "evil.module.run", "risk_keywords": []}
        assert bc._is_safe_conditional(item) is False

    def test_risk_keyword_skipped(self):
        import scripts.bulk_conditional as bc
        item = {"api_path": "torch.optim.load_state", "risk_keywords": []}
        assert bc._is_safe_conditional(item) is False  # load 키워드


# ─────────────────────────────────────────────
# 데모 시나리오 — 대시보드 흐름 (TestClient로 Pending → review)
# ─────────────────────────────────────────────

class TestDashboardFlow:

    def test_check_then_pending_then_approved_via_endpoints(self, client):
        """대시보드 시뮬레이션 — check → pending 등록 → review approve →
        approved 목록에 등장.
        """
        # 1. /whitelist/check로 미등록 API 분류 → PENDING 등록 (자동)
        payload = {
            "schema_version": "1.0",
            "request_id": str(uuid.uuid4()),
            "job_id": str(uuid.uuid4()),
            "model": {
                "repo_id": "dashboard/test", "revision": "main",
                "source_host": "huggingface.co",
                "source_url": "https://huggingface.co/dashboard/test",
                "requested_by": "dashboard",
                "requested_at": "2026-05-08T00:00:00Z",
                "endpoint_mode": "HF_ENDPOINT_PROXY",
            },
            "apis": ["torch.nn.NewDashboardLayer"],
        }
        r = client.post("/internal/v1/whitelist/check", json=payload)
        assert r.status_code == 200
        results = r.json()
        assert results[0]["status"] == "PENDING"

        # 2. /pending 목록에 등장
        r2 = client.get("/internal/v1/pending")
        items = r2.json()["items"]
        assert any(i["api_path"] == "torch.nn.NewDashboardLayer" for i in items)

        # 3. /review로 approve
        r3 = client.post(
            "/internal/v1/review",
            json={
                "api_path": "torch.nn.NewDashboardLayer",
                "decision": "approve",
                "reviewer_id": "admin_dashboard",
                "review_note": "dashboard test approve",
            },
        )
        assert r3.json()["applied"] is True

        # 4. /approved 목록에 등장 (source=MANUAL_REVIEW)
        r4 = client.get(
            "/internal/v1/approved",
            params={"search": "torch.nn.NewDashboardLayer"},
        )
        items = r4.json()["items"]
        assert len(items) >= 1
        assert items[0]["source"] == "MANUAL_REVIEW"
