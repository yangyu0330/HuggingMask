"""오탐 자동학습(#10) 회귀 테스트.

핵심 안전 불변식: 보고 행위 자체로는 위험 API가 승격되지 않는다. 위조 불가능한
외부 증거(verified org 다수 + AUTO_APPROVE 네임스페이스 + 위험키워드 0)가 모두
충족될 때만 사람 검토 없이 ALLOWED로 자동 승격된다.
"""
import pytest

from whitelist.feedback import submit_feedback
from whitelist.models import ReviewStatus, WhitelistSource
from whitelist.pending_store import get_pending
from whitelist.audit import verify_audit_chain
from whitelist.tables import ApprovedApi, AuditLog


class _FakeOrgCache:
    def __init__(self, n: int) -> None:
        self._n = n

    def lookup_verified_org_count(self, api_path: str) -> int:
        return self._n

    def lookup_org_list(self, api_path: str) -> list[str]:
        return [f"org{i}" for i in range(self._n)]


@pytest.fixture
def org_count(monkeypatch):
    """mod2 verified-org 카운트를 테스트에서 제어."""
    def _set(n: int):
        monkeypatch.setattr(
            "whitelist.cache_loader.get_org_cache", lambda *a, **k: _FakeOrgCache(n)
        )
    return _set


def _approved(db, api):
    return db.execute(
        ApprovedApi.__table__.select().where(ApprovedApi.api_path == api)
    ).first()


def test_eligible_api_auto_promoted(db_session, org_count):
    org_count(5)  # verified org 5개 → 임계(3) 충족
    api = "torch.nn.functional.scaled_dot_product_attention"  # AUTO_APPROVE 네임스페이스
    resp = submit_feedback(
        db_session, blocked_api=api, model_id="m1",
        purpose="정상 사용", reporter_id="dev1",
    )
    # 자동 승인
    assert resp.review_status is ReviewStatus.APPROVED
    row = db_session.query(ApprovedApi).filter_by(api_path=api).one()
    assert row.is_blocked is False
    assert row.source == WhitelistSource.AUTO_CRAWL
    assert row.reviewer_id == "auto-learn"
    # pending 큐에는 안 올라감(사람 검토 불필요)
    assert get_pending(db_session, api) is None
    # 전용 감사 액션 기록
    assert db_session.query(AuditLog).filter_by(
        api_path=api, action="feedback_auto_approved"
    ).count() == 1


def test_low_org_count_stays_pending(db_session, org_count):
    org_count(1)  # 임계 미만 → 사람 검토
    api = "torch.nn.functional.scaled_dot_product_attention"
    resp = submit_feedback(
        db_session, blocked_api=api, model_id="m1",
        purpose="정상 사용", reporter_id="dev1",
    )
    assert resp.review_status is ReviewStatus.PENDING
    assert db_session.query(ApprovedApi).filter_by(api_path=api).count() == 0
    assert get_pending(db_session, api) is not None


def test_permanently_blocked_never_auto_promoted_even_with_high_org_count(db_session, org_count):
    org_count(99)  # 외부 사용이 아무리 많아도
    resp = submit_feedback(
        db_session, blocked_api="torch.load", model_id="m1",
        purpose="가중치 로드", reporter_id="attacker",
    )
    assert resp.auto_rejected is True
    assert resp.review_status is ReviewStatus.REJECTED
    # ALLOWED(is_blocked=False)로 승격된 행이 없어야 함
    assert db_session.query(ApprovedApi).filter_by(
        api_path="torch.load", is_blocked=False
    ).count() == 0


def test_non_auto_approve_namespace_not_promoted(db_session, org_count):
    org_count(99)  # 사용 많아도 네임스페이스가 AUTO_APPROVE가 아니면 불가
    api = "torch.utils.data.DataLoader"  # MANUAL 네임스페이스
    resp = submit_feedback(
        db_session, blocked_api=api, model_id="m1",
        purpose="데이터 로딩", reporter_id="dev1",
    )
    assert resp.review_status is ReviewStatus.PENDING
    assert db_session.query(ApprovedApi).filter_by(api_path=api).count() == 0


def test_audit_chain_intact_after_auto_promote(db_session, org_count):
    org_count(5)
    submit_feedback(
        db_session, blocked_api="torch.nn.functional.gelu", model_id="m1",
        purpose="활성화 함수", reporter_id="dev1",
    )
    valid, errors = verify_audit_chain(db_session)
    assert valid, errors
