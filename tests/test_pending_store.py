"""
Pending Store 테스트 — whitelist/pending_store.md 명세 구현
"""

from datetime import datetime, timezone

from whitelist.models import (
    EndpointMode, ModelRef, PendingApiRecord, PendingApiUpsertRequest,
    PendingClassification, ReviewStatus,
)
from whitelist.pending_store import (
    count_pending, get_pending, list_pending, to_record, upsert_pending,
)


def _upsert(db, api_path: str, **kwargs):
    defaults = dict(
        auto_classification=PendingClassification.MANUAL,
        job_id="test-job-1",
        model_repo_id="org/test-model",
    )
    defaults.update(kwargs)
    p = upsert_pending(db, api_path=api_path, **defaults)
    db.commit()
    return p


class TestUpsertBehavior:

    def test_first_insert_creates_record(self, db_session):
        p = _upsert(db_session, "torch.X")
        assert p.seen_count == 1
        assert p.review_status == ReviewStatus.PENDING

    def test_repeated_increments_seen_count(self, db_session):
        _upsert(db_session, "torch.X")
        _upsert(db_session, "torch.X")
        _upsert(db_session, "torch.X")
        p = get_pending(db_session, "torch.X")
        assert p.seen_count == 3

    def test_last_seen_at_updates(self, db_session):
        _upsert(db_session, "torch.X")
        first_p = get_pending(db_session, "torch.X")
        first_seen = first_p.last_seen_at

        # 약간의 시간 차 만들기 위한 두 번째 upsert
        import time
        time.sleep(0.01)
        _upsert(db_session, "torch.X")
        p = get_pending(db_session, "torch.X")
        assert p.last_seen_at >= first_seen

    def test_model_list_dedup(self, db_session):
        _upsert(db_session, "torch.X", model_repo_id="org/a")
        _upsert(db_session, "torch.X", model_repo_id="org/b")
        _upsert(db_session, "torch.X", model_repo_id="org/a")  # dup
        p = get_pending(db_session, "torch.X")
        assert set(p.model_list) == {"org/a", "org/b"}

    def test_sample_callsites_capped_at_20(self, db_session):
        for i in range(25):
            _upsert(db_session, "torch.X", sample_callsite=f"call-{i}")
        p = get_pending(db_session, "torch.X")
        assert len(p.sample_callsites) == 20
        # 가장 최근 20개만 유지
        assert "call-24" in p.sample_callsites
        assert "call-0" not in p.sample_callsites

    def test_risk_keywords_merge(self, db_session):
        _upsert(db_session, "torch.X", risk_keywords=["load"])
        _upsert(db_session, "torch.X", risk_keywords=["save", "exec"])
        p = get_pending(db_session, "torch.X")
        assert set(p.risk_keywords) == {"load", "save", "exec"}

    def test_review_status_always_pending_initially(self, db_session):
        """auto_classification이 AUTO_APPROVE여도 review_status는 PENDING"""
        p = _upsert(
            db_session, "torch.X",
            auto_classification=PendingClassification.AUTO_APPROVE,
        )
        assert p.review_status == ReviewStatus.PENDING


class TestRecordSerialization:

    def test_to_record_round_trips(self, db_session):
        p = _upsert(db_session, "torch.X")
        record = to_record(p)
        assert isinstance(record, PendingApiRecord)
        assert record.api_path == "torch.X"
        assert record.seen_count == 1


class TestListing:

    def test_count(self, db_session):
        _upsert(db_session, "torch.A")
        _upsert(db_session, "torch.B")
        _upsert(db_session, "torch.C")
        assert count_pending(db_session) == 3

    def test_filter_by_classification(self, db_session):
        _upsert(db_session, "torch.A", auto_classification=PendingClassification.MANUAL)
        _upsert(db_session, "torch.B", auto_classification=PendingClassification.AUTO_APPROVE)
        manual = list_pending(db_session, classification=PendingClassification.MANUAL)
        assert len(manual) == 1
        assert manual[0].api_path == "torch.A"
