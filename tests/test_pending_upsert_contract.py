"""
PendingApiRecord ↔ /pending/upsert round-trip 계약 테스트

양유상 PR #9 리뷰 요청 (2026-04-21):
  - upsert가 record 전체를 손실 없이 보존하는지
  - model_list 2개 이상 유지
  - sample_callsites 2개 이상 유지
  - created_from_job_id가 record 기준으로 저장
  - review_status는 PENDING만 허용 (정책: 양유상 리뷰의 옵션 2 채택)
"""

from datetime import datetime, timezone

import pytest

from whitelist.models import (
    PendingApiRecord, PendingApiUpsertRequest, PendingClassification,
    ReviewStatus,
)
from whitelist.pending_store import (
    get_pending, to_record, upsert_pending_record,
)


def _make_record(**overrides) -> PendingApiRecord:
    """기본값을 다 채운 record 빌더"""
    base = dict(
        api_path="torch.nn.SomeNewLayer",
        first_seen_at=datetime(2026, 4, 1, 10, 0, 0, tzinfo=timezone.utc),
        last_seen_at=datetime(2026, 4, 20, 15, 30, 0, tzinfo=timezone.utc),
        seen_count=42,
        auto_classification=PendingClassification.AUTO_APPROVE,
        verified_org_count=3,
        verified_org_list=["Meta", "Google", "Mistral"],
        in_official_docs=True,
        review_status=ReviewStatus.PENDING,
        model_list=["org/model-a", "org/model-b", "org/model-c"],
        risk_keywords=["load", "save"],
        matched_namespace_rule="torch.nn.*",
        documentation_url="https://pytorch.org/docs/stable/generated/torch.nn.SomeNewLayer.html",
        sample_callsites=[
            "F.scaled_dot_product_attention(q, k, v)",
            "self.attn(x, x, x)",
            "model.forward(input_ids)",
        ],
        created_from_job_id="external-job-aaaa-bbbb-cccc",
    )
    base.update(overrides)
    return PendingApiRecord(**base)


# ─────────────────────────────────────────────
# 1. Round-trip 무결성
# ─────────────────────────────────────────────

class TestRoundTrip:

    def test_full_record_preserved(self, db_session):
        """upsert → DB → to_record() 결과가 원본 record와 동일해야 함"""
        record = _make_record()
        pending = upsert_pending_record(db_session, record)
        db_session.commit()

        roundtrip = to_record(pending)

        assert roundtrip.api_path == record.api_path
        assert roundtrip.first_seen_at == record.first_seen_at
        assert roundtrip.last_seen_at == record.last_seen_at
        assert roundtrip.seen_count == record.seen_count
        assert roundtrip.auto_classification == record.auto_classification
        assert roundtrip.verified_org_count == record.verified_org_count
        assert roundtrip.verified_org_list == record.verified_org_list
        assert roundtrip.in_official_docs == record.in_official_docs
        assert roundtrip.review_status == record.review_status
        assert roundtrip.model_list == record.model_list
        assert roundtrip.risk_keywords == record.risk_keywords
        assert roundtrip.matched_namespace_rule == record.matched_namespace_rule
        assert roundtrip.documentation_url == record.documentation_url
        assert roundtrip.sample_callsites == record.sample_callsites
        assert roundtrip.created_from_job_id == record.created_from_job_id


# ─────────────────────────────────────────────
# 2. 다중 원소 보존 (양유상 리뷰 명시)
# ─────────────────────────────────────────────

class TestMultiElementPreservation:

    def test_model_list_2_or_more_preserved(self, db_session):
        """3개 모델 모두 보존되어야 함 (이전 구현은 [0]만 저장했음)"""
        record = _make_record(model_list=["org/a", "org/b", "org/c"])
        pending = upsert_pending_record(db_session, record)
        db_session.commit()

        assert get_pending(db_session, record.api_path).model_list == [
            "org/a", "org/b", "org/c",
        ]

    def test_sample_callsites_2_or_more_preserved(self, db_session):
        """3개 콜사이트 모두 보존되어야 함 (이전 구현은 [0]만 저장)"""
        record = _make_record(sample_callsites=[
            "site_one()", "site_two()", "site_three()",
        ])
        pending = upsert_pending_record(db_session, record)
        db_session.commit()

        assert get_pending(db_session, record.api_path).sample_callsites == [
            "site_one()", "site_two()", "site_three()",
        ]

    def test_verified_org_list_full_preserved(self, db_session):
        record = _make_record(verified_org_list=["A", "B", "C", "D"])
        upsert_pending_record(db_session, record)
        db_session.commit()
        assert get_pending(db_session, record.api_path).verified_org_list == [
            "A", "B", "C", "D",
        ]

    def test_risk_keywords_preserved(self, db_session):
        record = _make_record(risk_keywords=["load", "save", "exec"])
        upsert_pending_record(db_session, record)
        db_session.commit()
        assert sorted(get_pending(db_session, record.api_path).risk_keywords) == [
            "exec", "load", "save",
        ]


# ─────────────────────────────────────────────
# 3. created_from_job_id가 record 기준으로 저장 (이전 구현은 req.job_id로 덮어씀)
# ─────────────────────────────────────────────

class TestCreatedFromJobId:

    def test_record_job_id_used_not_request_job_id(self, db_session):
        """record.created_from_job_id가 그대로 저장. req.job_id는 사용 안 함."""
        record = _make_record(created_from_job_id="job-from-record-123")
        upsert_pending_record(db_session, record)
        db_session.commit()
        assert get_pending(db_session, record.api_path).created_from_job_id == \
            "job-from-record-123"


# ─────────────────────────────────────────────
# 4. review_status 정책 (양유상 옵션 2 채택)
# ─────────────────────────────────────────────

class TestReviewStatusPolicy:
    """이 endpoint는 PENDING만 허용. 다른 상태로 만들려면 /review 사용."""

    @pytest.mark.parametrize("status", [
        ReviewStatus.UNDER_REVIEW,
        ReviewStatus.APPROVED,
        ReviewStatus.REJECTED,
        ReviewStatus.DEFERRED,
    ])
    def test_non_pending_status_raises(self, db_session, status):
        record = _make_record(review_status=status)
        with pytest.raises(ValueError, match="review_status=PENDING"):
            upsert_pending_record(db_session, record)

    def test_pending_status_succeeds(self, db_session):
        record = _make_record(review_status=ReviewStatus.PENDING)
        upsert_pending_record(db_session, record)
        db_session.commit()
        assert get_pending(db_session, record.api_path) is not None


# ─────────────────────────────────────────────
# 5. Update 시나리오 — 기존 record가 있으면 record 값으로 덮어씀
# ─────────────────────────────────────────────

class TestUpdateBehavior:

    def test_existing_record_overwritten_by_request(self, db_session):
        """동일 api_path 재호출 시 record 값으로 덮어쓴다 (외부 입력 우선)"""
        # 1차: seen_count=5, model_list=["m1"]
        rec1 = _make_record(seen_count=5, model_list=["m1"])
        upsert_pending_record(db_session, rec1)
        db_session.commit()

        # 2차: seen_count=10, model_list=["m1", "m2", "m3"]
        rec2 = _make_record(seen_count=10, model_list=["m1", "m2", "m3"])
        upsert_pending_record(db_session, rec2)
        db_session.commit()

        p = get_pending(db_session, rec1.api_path)
        assert p.seen_count == 10
        assert p.model_list == ["m1", "m2", "m3"]


# ─────────────────────────────────────────────
# 6. HTTP layer — 라우터를 통한 round-trip
# ─────────────────────────────────────────────

class TestRouterRoundTrip:
    """test_router_e2e.py의 fixture와 별개로 여기선 client fixture 직접 사용"""

    def test_post_pending_upsert_full_roundtrip(self, db_session):
        """라우터 핸들러를 직접 호출해서 응답 PendingApiRecord 검증"""
        from whitelist.router import upsert_pending_api

        req = PendingApiUpsertRequest(
            schema_version="1.0",
            request_id="req-xyz",
            job_id="ignored-job-id",  # 의도적으로 record와 다름
            record=_make_record(created_from_job_id="record-job-id"),
        )
        resp = upsert_pending_api(req, db_session)

        # router 응답이 record 그대로 (loss 없음)
        assert resp.api_path == req.record.api_path
        assert resp.model_list == req.record.model_list
        assert resp.sample_callsites == req.record.sample_callsites
        assert resp.created_from_job_id == "record-job-id"  # req.job_id 아님
        assert resp.first_seen_at == req.record.first_seen_at
        assert resp.last_seen_at == req.record.last_seen_at

    def test_post_pending_upsert_rejects_non_pending(self, db_session):
        """review_status≠PENDING은 400 (HTTPException)"""
        from fastapi import HTTPException
        from whitelist.router import upsert_pending_api

        req = PendingApiUpsertRequest(
            schema_version="1.0",
            request_id="req-xyz",
            job_id="job-1",
            record=_make_record(review_status=ReviewStatus.APPROVED),
        )
        with pytest.raises(HTTPException) as exc:
            upsert_pending_api(req, db_session)
        assert exc.value.status_code == 400
