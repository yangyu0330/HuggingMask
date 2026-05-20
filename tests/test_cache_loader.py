"""
cache_loader 단위 테스트.

- OrgCache 디스크 로드 / 빈 캐시 / 깨진 JSON degrade
- is_in_official_docs DB 조회 (INITIAL/AUTO_CRAWL만 True)
- apply_crawl_results_to_db (mod1 결과 → ApprovedApi)
- pending_store/feedback의 자동 채움 통합 검증
"""

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from whitelist.cache_loader import (
    OrgCache, apply_crawl_results_to_db, get_org_cache,
    is_in_official_docs, reset_org_cache,
)
from whitelist.mod1_doc_crawler import ExtractedApi
from whitelist.models import (
    PendingClassification, ReviewStatus, WhitelistSource,
)
from whitelist.tables import ApprovedApi


# ─────────────────────────────────────────────
# OrgCache 로드
# ─────────────────────────────────────────────

class TestOrgCacheLoad:

    def test_missing_file_returns_empty(self, tmp_path):
        cache = OrgCache(cache_path=tmp_path / "no_such.json")
        cache.reload()
        assert cache.size() == 0
        assert cache.lookup_verified_org_count("anything") == 0
        assert cache.lookup_org_list("anything") == []

    def test_broken_json_degrades_gracefully(self, tmp_path):
        path = tmp_path / "broken.json"
        path.write_text("not json {", encoding="utf-8")
        cache = OrgCache(cache_path=path)
        cache.reload()
        assert cache.size() == 0

    def test_load_with_unregistered_apis(self, tmp_path):
        path = tmp_path / "ok.json"
        path.write_text(json.dumps({
            "analyzed_at": "2026-04-07T00:00:00+00:00",
            "unregistered_apis": [
                {
                    "api_path": "transformers.NewModel",
                    "used_by_orgs": ["meta-llama", "google"],
                    "used_by_models": ["meta-llama/x", "google/y"],
                    "total_count": 10,
                },
            ],
        }), encoding="utf-8")
        cache = OrgCache(cache_path=path)
        cache.reload()
        assert cache.size() == 1
        assert cache.lookup_verified_org_count("transformers.NewModel") == 2
        assert set(cache.lookup_org_list("transformers.NewModel")) == {"meta-llama", "google"}
        assert cache.analyzed_at is not None


# ─────────────────────────────────────────────
# is_in_official_docs
# ─────────────────────────────────────────────

class TestIsInOfficialDocs:

    def test_initial_source_returns_true(self, db_session):
        db_session.add(ApprovedApi(
            api_path="torch.nn.Linear", namespace="torch.nn",
            source=WhitelistSource.INITIAL, is_blocked=False,
        ))
        db_session.commit()
        assert is_in_official_docs(db_session, "torch.nn.Linear") is True

    def test_auto_crawl_source_returns_true(self, db_session):
        db_session.add(ApprovedApi(
            api_path="torch.nn.NewLayer", namespace="torch.nn",
            source=WhitelistSource.AUTO_CRAWL, is_blocked=False,
        ))
        db_session.commit()
        assert is_in_official_docs(db_session, "torch.nn.NewLayer") is True

    def test_manual_review_source_returns_false(self, db_session):
        # 수동 승인은 "공식 문서 등록"으로 보지 않음 (mod1 실제 크롤만 인정)
        db_session.add(ApprovedApi(
            api_path="torch.nn.Custom", namespace="torch.nn",
            source=WhitelistSource.MANUAL_REVIEW, is_blocked=False,
        ))
        db_session.commit()
        assert is_in_official_docs(db_session, "torch.nn.Custom") is False

    def test_blocked_returns_false(self, db_session):
        db_session.add(ApprovedApi(
            api_path="torch.dangerous", namespace="torch",
            source=WhitelistSource.INITIAL, is_blocked=True,
        ))
        db_session.commit()
        assert is_in_official_docs(db_session, "torch.dangerous") is False

    def test_missing_returns_false(self, db_session):
        assert is_in_official_docs(db_session, "torch.does.not.exist") is False


# ─────────────────────────────────────────────
# apply_crawl_results_to_db
# ─────────────────────────────────────────────

class TestApplyCrawlResults:

    def _api(self, path: str) -> ExtractedApi:
        return ExtractedApi(
            full_path=path,
            namespace=path.rsplit(".", 1)[0],
            source_url="https://pytorch.org/docs/x",
        )

    def test_auto_approve_only_default(self, db_session):
        classified = {
            "AUTO_APPROVE": [self._api("torch.nn.NewA")],
            "CONDITIONAL":  [self._api("torch.optim.NewB")],
            "MANUAL":       [self._api("torch.utils.NewC")],
            "BLOCKED":      [self._api("torch.dangerous_z")],
        }
        counts = apply_crawl_results_to_db(classified, db_session)
        db_session.commit()
        assert counts["added"] == 1
        # AUTO_APPROVE만 등록됨
        from sqlalchemy import select
        rows = db_session.execute(select(ApprovedApi)).scalars().all()
        assert {r.api_path for r in rows} == {"torch.nn.NewA"}
        assert rows[0].source == WhitelistSource.AUTO_CRAWL

    def test_explicit_classifications(self, db_session):
        classified = {
            "AUTO_APPROVE": [self._api("torch.nn.A")],
            "CONDITIONAL":  [self._api("torch.optim.B")],
            "MANUAL":       [self._api("torch.utils.C")],
            "BLOCKED":      [self._api("torch.x_blocked")],
        }
        counts = apply_crawl_results_to_db(
            classified, db_session,
            allow_classifications=("AUTO_APPROVE", "CONDITIONAL"),
        )
        db_session.commit()
        assert counts["added"] == 2

    def test_existing_skipped(self, db_session):
        db_session.add(ApprovedApi(
            api_path="torch.nn.Existing", namespace="torch.nn",
            source=WhitelistSource.INITIAL, is_blocked=False,
        ))
        db_session.commit()
        classified = {"AUTO_APPROVE": [self._api("torch.nn.Existing")]}
        counts = apply_crawl_results_to_db(classified, db_session)
        assert counts["added"] == 0
        assert counts["skipped"] == 1

    def test_permanently_blocked_protected(self, db_session):
        # 영구 차단 API가 어떤 분류로 들어와도 자동 등록 거부
        classified = {"AUTO_APPROVE": [self._api("torch.load")]}
        counts = apply_crawl_results_to_db(classified, db_session)
        assert counts["added"] == 0
        assert counts["blocked_by_perm"] == 1

    def test_dry_run_does_not_persist(self, db_session):
        classified = {"AUTO_APPROVE": [self._api("torch.nn.DryA")]}
        counts = apply_crawl_results_to_db(classified, db_session, dry_run=True)
        assert counts["added"] == 1
        from sqlalchemy import select
        assert db_session.execute(
            select(ApprovedApi).where(ApprovedApi.api_path == "torch.nn.DryA")
        ).scalar_one_or_none() is None


# ─────────────────────────────────────────────
# pending_store / feedback 자동 채움 통합
# ─────────────────────────────────────────────

class TestPendingStoreAutoFill:

    def test_upsert_pending_auto_fills_from_org_cache(self, db_session, tmp_path):
        cache_file = tmp_path / "latest.json"
        cache_file.write_text(json.dumps({
            "analyzed_at": "2026-05-06T00:00:00+00:00",
            "unregistered_apis": [
                {
                    "api_path": "transformers.NewRare",
                    "used_by_orgs": ["meta-llama", "google", "mistralai"],
                    "used_by_models": ["meta-llama/x"],
                    "total_count": 7,
                },
            ],
        }), encoding="utf-8")
        reset_org_cache(cache_file)

        from whitelist.pending_store import upsert_pending
        p = upsert_pending(
            db_session,
            api_path="transformers.NewRare",
            auto_classification=PendingClassification.CONDITIONAL,
            job_id="auto-fill-1",
        )
        db_session.commit()
        # mod2 캐시에서 자동 채움
        assert p.verified_org_count == 3
        assert set(p.verified_org_list) == {"meta-llama", "google", "mistralai"}

    def test_upsert_pending_explicit_overrides_cache(self, db_session, tmp_path):
        cache_file = tmp_path / "latest.json"
        cache_file.write_text(json.dumps({
            "analyzed_at": "2026-05-06T00:00:00+00:00",
            "unregistered_apis": [
                {
                    "api_path": "transformers.X",
                    "used_by_orgs": ["org1"],
                    "used_by_models": [],
                    "total_count": 1,
                },
            ],
        }), encoding="utf-8")
        reset_org_cache(cache_file)

        from whitelist.pending_store import upsert_pending
        p = upsert_pending(
            db_session,
            api_path="transformers.X",
            auto_classification=PendingClassification.CONDITIONAL,
            job_id="explicit-1",
            verified_org_count=99,  # 명시 — 캐시 무시
            verified_org_list=["explicit-org"],
        )
        db_session.commit()
        assert p.verified_org_count == 99
        assert p.verified_org_list == ["explicit-org"]


@pytest.fixture(autouse=True)
def _reset_singleton_after_each_test():
    """매 테스트 후 OrgCache 싱글턴 초기화 (다른 테스트의 캐시 누수 방지)."""
    yield
    # tmp_path는 자동 정리되지만 module-level _cache는 명시 초기화
    from whitelist import cache_loader as cl
    cl._cache = None
