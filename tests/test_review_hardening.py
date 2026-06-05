import json

from sqlalchemy import select

from whitelist.engine import WhitelistEngine, apply_review_decision
from whitelist.models import (
    PendingClassification,
    PendingApiRecord,
    ReviewStatus,
    WhitelistStatus,
)
from whitelist.pending_store import get_pending, to_record, upsert_pending_record
from whitelist.rules import WHITELIST_VERSION
from whitelist.tables import ApprovedApi, AuditLog, ReviewDecisionLog


def _register_pending(db_session, check_request_factory, api_path: str):
    engine = WhitelistEngine(version=WHITELIST_VERSION)
    response = engine.check_batch(check_request_factory([api_path]), db_session)
    assert response[0].status is WhitelistStatus.PENDING
    pending = get_pending(db_session, api_path)
    assert pending is not None
    return engine, pending


def _audit_payload(db_session, audit_id: int) -> dict:
    audit = db_session.get(AuditLog, audit_id)
    assert audit is not None
    assert audit.entry_hash
    return json.loads(audit.detail)


def test_approve_creates_review_decision_and_structured_audit(
    db_session, check_request_factory,
):
    api_path = "torch.nn.ReviewApprovedLayer"
    _register_pending(db_session, check_request_factory, api_path)

    result = apply_review_decision(
        db_session,
        api_path=api_path,
        decision="approve",
        reviewer_id="security_admin",
        review_note="official docs and namespace evidence reviewed",
        review_id="rev-approve-001",
        source_evidence=["doc=https://pytorch.org/docs/stable/nn.html"],
    )
    db_session.commit()

    assert result.applied is True
    assert result.review_id == "rev-approve-001"
    assert result.final_review_status is ReviewStatus.APPROVED
    assert result.audit_event_id is not None
    assert result.audit_event_hash

    pending = get_pending(db_session, api_path)
    assert ReviewStatus(pending.review_status) is ReviewStatus.APPROVED

    approved = db_session.get(ApprovedApi, api_path)
    assert approved is not None
    assert approved.is_blocked is False
    assert approved.reviewer_id == "security_admin"

    decision = db_session.get(ReviewDecisionLog, "rev-approve-001")
    assert decision is not None
    assert decision.audit_log_id == result.audit_event_id
    assert decision.audit_entry_hash == result.audit_event_hash

    audit_detail = _audit_payload(db_session, result.audit_event_id)
    assert audit_detail["review_id"] == "rev-approve-001"
    assert audit_detail["decision"] == "approve"
    assert audit_detail["final_review_status"] == "APPROVED"
    assert any("created_from_job_id=" in item for item in audit_detail["source_evidence"])


def test_review_id_replay_is_idempotent_without_new_audit(
    db_session, check_request_factory,
):
    api_path = "torch.nn.IdempotentLayer"
    _register_pending(db_session, check_request_factory, api_path)

    first = apply_review_decision(
        db_session,
        api_path=api_path,
        decision="approve",
        reviewer_id="security_admin",
        review_note="same review request",
        review_id="rev-idempotent-001",
    )
    db_session.commit()
    audit_count = db_session.execute(select(AuditLog)).scalars().all()

    replay = apply_review_decision(
        db_session,
        api_path=api_path,
        decision="approve",
        reviewer_id="security_admin",
        review_note="same review request",
        review_id="rev-idempotent-001",
    )
    db_session.commit()

    assert replay.applied is True
    assert replay.audit_event_id == first.audit_event_id
    assert len(db_session.execute(select(AuditLog)).scalars().all()) == len(audit_count)


def test_review_id_reuse_with_different_payload_is_not_applied(
    db_session, check_request_factory,
):
    api_path = "torch.nn.ReviewConflictLayer"
    _register_pending(db_session, check_request_factory, api_path)

    first = apply_review_decision(
        db_session,
        api_path=api_path,
        decision="approve",
        reviewer_id="security_admin",
        review_note="original reason",
        review_id="rev-conflict-001",
    )
    db_session.commit()

    conflict = apply_review_decision(
        db_session,
        api_path=api_path,
        decision="reject",
        reviewer_id="security_admin",
        review_note="different reason",
        review_id="rev-conflict-001",
    )
    db_session.commit()

    assert first.applied is True
    assert conflict.applied is False
    assert "review_id already exists" in conflict.message


def test_reject_is_durable_and_future_checks_block(
    db_session, check_request_factory,
):
    api_path = "torch.nn.RejectedLayer"
    engine, _ = _register_pending(db_session, check_request_factory, api_path)

    result = apply_review_decision(
        db_session,
        api_path=api_path,
        decision="reject",
        reviewer_id="security_admin",
        review_note="unsafe API shape for production",
        review_id="rev-reject-001",
    )
    db_session.commit()

    assert result.applied is True
    assert result.final_review_status is ReviewStatus.REJECTED
    assert ReviewStatus(get_pending(db_session, api_path).review_status) is ReviewStatus.REJECTED

    rejected = db_session.get(ApprovedApi, api_path)
    assert rejected is not None
    assert rejected.is_blocked is True

    next_response = engine.check_batch(check_request_factory([api_path]), db_session)
    assert next_response[0].status is WhitelistStatus.BLOCKED
    assert next_response[0].source.value == "MANUAL_REVIEW"


def test_defer_records_audit_without_promoting_to_approved(
    db_session, check_request_factory,
):
    api_path = "torch.nn.DeferredLayer"
    _register_pending(db_session, check_request_factory, api_path)

    result = apply_review_decision(
        db_session,
        api_path=api_path,
        decision="defer",
        reviewer_id="security_admin",
        review_note="needs vendor confirmation",
        review_id="rev-defer-001",
    )
    db_session.commit()

    assert result.applied is True
    assert result.final_review_status is ReviewStatus.DEFERRED
    assert db_session.get(ApprovedApi, api_path) is None
    assert ReviewStatus(get_pending(db_session, api_path).review_status) is ReviewStatus.DEFERRED
    assert _audit_payload(db_session, result.audit_event_id)["decision"] == "defer"


def test_pending_upsert_cannot_downgrade_approved_review_status(
    db_session, check_request_factory,
):
    api_path = "torch.nn.NoDowngradeLayer"
    _register_pending(db_session, check_request_factory, api_path)
    apply_review_decision(
        db_session,
        api_path=api_path,
        decision="approve",
        reviewer_id="security_admin",
        review_note="approved once",
        review_id="rev-no-downgrade-001",
    )
    db_session.commit()

    record = to_record(get_pending(db_session, api_path))
    downgrade = PendingApiRecord(
        **{
            **record.model_dump(),
            "review_status": ReviewStatus.PENDING,
            "auto_classification": PendingClassification.AUTO_APPROVE,
        }
    )

    try:
        upsert_pending_record(db_session, downgrade)
    except ValueError as exc:
        assert "cannot downgrade finalized review_status APPROVED" in str(exc)
    else:
        raise AssertionError("expected finalized pending upsert downgrade to fail")

    assert ReviewStatus(get_pending(db_session, api_path).review_status) is ReviewStatus.APPROVED
