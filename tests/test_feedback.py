"""오탐 피드백 루프 테스트 (모듈 5)"""

import pytest

from whitelist.feedback import submit_feedback
from whitelist.models import (
    PendingClassification, ReviewStatus, WhitelistSource,
)
from whitelist.pending_store import get_pending
from whitelist.tables import ApprovedApi, AuditLog, FeedbackReport


class TestNormalFeedback:

    def test_creates_pending_and_audit(self, db_session):
        resp = submit_feedback(
            db_session,
            blocked_api="torch.nn.functional.scaled_dot_product_attention",
            model_id="meta-llama/Llama-3",
            purpose="attention 연산 호출",
            reporter_id="dev_01",
        )

        assert not resp.auto_rejected
        assert resp.review_status == ReviewStatus.PENDING
        assert resp.report_id.startswith("FB-")
        # AUTO_APPROVE 분류 → SLA 4시간
        assert resp.estimated_response_hours == 4

        # pending_apis에도 등록됨
        p = get_pending(db_session, "torch.nn.functional.scaled_dot_product_attention")
        assert p is not None
        assert any("dev_01" in s for s in p.sample_callsites)

        # 감사 로그 기록
        log = db_session.query(AuditLog).filter_by(
            action="feedback_received",
        ).first()
        assert log is not None
        assert log.actor == "dev_01"


class TestAutoRejection:

    def test_permanently_blocked_api_auto_rejected(self, db_session):
        resp = submit_feedback(
            db_session,
            blocked_api="torch.load",
            model_id="some/model",
            purpose="모델 로드",
            reporter_id="dev_02",
        )
        assert resp.auto_rejected
        assert resp.review_status == ReviewStatus.REJECTED
        assert resp.estimated_response_hours == 0
        assert resp.auto_classification == PendingClassification.BLOCKED

        # 자동 거부 시 pending에는 등록 안 함
        assert get_pending(db_session, "torch.load") is None


class TestRejectionEdgeCases:

    def test_already_approved_raises(self, db_session):
        db_session.add(ApprovedApi(
            api_path="torch.nn.Linear", namespace="torch.nn",
            source=WhitelistSource.INITIAL, is_blocked=False,
        ))
        db_session.commit()

        with pytest.raises(ValueError, match="이미 화이트리스트"):
            submit_feedback(
                db_session, blocked_api="torch.nn.Linear",
                model_id="m", purpose="p", reporter_id="r",
            )

    def test_empty_api_raises(self, db_session):
        with pytest.raises(ValueError):
            submit_feedback(
                db_session, blocked_api="",
                model_id="m", purpose="p", reporter_id="r",
            )

    def test_unique_report_ids_for_same_api(self, db_session):
        r1 = submit_feedback(
            db_session, blocked_api="torch.X",
            model_id="m1", purpose="p", reporter_id="a",
        )
        r2 = submit_feedback(
            db_session, blocked_api="torch.X",
            model_id="m2", purpose="p", reporter_id="b",
        )
        assert r1.report_id != r2.report_id
        assert db_session.query(FeedbackReport).count() == 2
