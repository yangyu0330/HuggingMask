"""
FastAPI 라우터 — HuggingMask 인터페이스 정의서 v1.0 정확 일치

엔드포인트:
  POST /internal/v1/whitelist/check    (14.1 → 14.2)
  POST /internal/v1/pending/upsert     (15.2)
  GET  /internal/v1/pending            (운영용 목록)
  POST /internal/v1/review             (보안 담당자 판정)
  POST /internal/v1/feedback           (모듈 5 — 오탐 피드백)
  GET  /internal/v1/feedback           (피드백 목록)
  GET  /internal/v1/audit              (감사 로그 조회)
  GET  /internal/v1/audit/verify       (해시 체인 무결성 검증)
"""

import logging

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select, func
from sqlalchemy.orm import Session

from proxy.auth import (
    InternalReviewerPrincipal,
    get_internal_reviewer_principal,
    resolve_reviewer_id_for_review,
)
from whitelist.audit import verify_audit_chain
from whitelist.database import get_db
from whitelist.engine import apply_review_decision, get_engine
from whitelist.feedback import (
    get_feedback_by_id, list_feedback, submit_feedback,
)
from whitelist.models import (
    FeedbackReportRequest, FeedbackReportResponse,
    PendingApiRecord, PendingApiUpsertRequest, ReviewStatus,
    ReviewDecisionRequest, ReviewDecisionResult,
    WhitelistCheckRequest, WhitelistCheckResponse,
)
from whitelist.pending_store import (
    count_pending, get_pending, list_pending, to_record,
    upsert_pending, upsert_pending_record,
)
from whitelist.rules import WHITELIST_VERSION
from whitelist.tables import ApprovedApi, AuditLog, FeedbackReport, PendingApi


logger = logging.getLogger(__name__)

router = APIRouter(prefix="/internal/v1", tags=["whitelist"])


# ─────────────────────────────────────────────
# 14. Whitelist check
# ─────────────────────────────────────────────

@router.post("/whitelist/check", response_model=list[WhitelistCheckResponse])
def check_whitelist(
    req: WhitelistCheckRequest, db: Session = Depends(get_db),
) -> list[WhitelistCheckResponse]:
    """코드 검증자(양유상)가 호출. per-API status 반환 + 미등록은 pending 등록.

    인터페이스 정의서 14.2 — 응답은 배열. wrapper 없음.
    """
    return get_engine().check_batch(req, db)


# ─────────────────────────────────────────────
# 15. Pending API
# ─────────────────────────────────────────────

@router.post("/pending/upsert", response_model=PendingApiRecord)
def upsert_pending_api(
    req: PendingApiUpsertRequest, db: Session = Depends(get_db),
) -> PendingApiRecord:
    """외부(analyzer 등)에서 PendingApiRecord 전체를 upsert.

    정책 (양유상 PR #9 리뷰):
      - record 전체를 손실 없이 반영 (first_seen_at, seen_count, model_list 등 전부)
      - created_from_job_id는 record 값 사용 (req.job_id는 감사/로깅용)
      - review_status는 PENDING만 허용 (보안 게이트 원칙) — 그 외 400
    """
    try:
        pending = upsert_pending_record(db, req.record)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    db.commit()
    return to_record(pending)


@router.get("/pending")
def list_pending_api(
    review_status: str | None = None,
    classification: str | None = None,
    limit: int = 50,
    offset: int = 0,
    db: Session = Depends(get_db),
):
    status = ReviewStatus(review_status) if review_status else None
    from whitelist.models import PendingClassification as PC
    cls = PC(classification) if classification else None
    items = list_pending(db, status, cls, limit, offset)
    return {
        "items": [to_record(p).model_dump(mode="json") for p in items],
        "count": len(items),
    }


@router.get("/pending/{api_path:path}", response_model=PendingApiRecord | None)
def get_pending_api(api_path: str, db: Session = Depends(get_db)):
    p = get_pending(db, api_path)
    if not p:
        raise HTTPException(status_code=404, detail="Pending not found")
    return to_record(p)


# ─────────────────────────────────────────────
# 16. 리뷰 (보안 담당자 판정)
# ─────────────────────────────────────────────

def _apply_review_request(
    req: ReviewDecisionRequest,
    db: Session,
    principal: InternalReviewerPrincipal | None,
) -> ReviewDecisionResult:
    reviewer_id = resolve_reviewer_id_for_review(req.reviewer_id, principal)
    result = apply_review_decision(
        db, api_path=req.api_path, decision=req.decision.value,
        reviewer_id=reviewer_id, review_note=req.review_note,
        condition=req.condition, review_id=req.review_id,
        source_evidence=req.source_evidence,
    )
    db.commit()
    return result


@router.post("/reviews/decide", response_model=ReviewDecisionResult)
def decide_review(
    req: ReviewDecisionRequest,
    db: Session = Depends(get_db),
    principal: InternalReviewerPrincipal | None = Depends(get_internal_reviewer_principal),
) -> ReviewDecisionResult:
    return _apply_review_request(req, db, principal)


@router.post("/review", response_model=ReviewDecisionResult)
def review_pending(
    req: ReviewDecisionRequest,
    db: Session = Depends(get_db),
    principal: InternalReviewerPrincipal | None = Depends(get_internal_reviewer_principal),
) -> ReviewDecisionResult:
    """Compatibility alias for older dashboard and bulk scripts."""
    return _apply_review_request(req, db, principal)


# ─────────────────────────────────────────────
# 모듈 5 — 오탐 피드백
# ─────────────────────────────────────────────

@router.post("/feedback", response_model=FeedbackReportResponse)
def post_feedback(
    req: FeedbackReportRequest, db: Session = Depends(get_db),
) -> FeedbackReportResponse:
    try:
        return submit_feedback(
            db,
            blocked_api=req.blocked_api,
            model_id=req.model_id,
            purpose=req.purpose,
            reporter_id=req.reporter_id,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/feedback")
def get_feedbacks(
    reporter_id: str = "",
    status: str | None = None,
    limit: int = 50,
    offset: int = 0,
    db: Session = Depends(get_db),
):
    review_status = ReviewStatus(status) if status else None
    items = list_feedback(
        db, reporter_id=reporter_id or None,
        review_status=review_status, limit=limit, offset=offset,
    )
    return {
        "items": [
            {
                "report_id": r.report_id,
                "blocked_api": r.blocked_api,
                "model_id": r.model_id,
                "purpose": r.purpose,
                "reporter_id": r.reporter_id,
                "submitted_at": r.submitted_at.isoformat() if r.submitted_at else "",
                "auto_classification": r.auto_classification,
                "in_official_docs": r.in_official_docs,
                "verified_org_count": r.verified_org_count,
                "estimated_response_hours": r.estimated_response_hours,
                "review_status": r.review_status,
                "auto_rejected": r.auto_rejected,
            }
            for r in items
        ],
        "count": len(items),
    }


@router.get("/feedback/{report_id}")
def get_feedback(report_id: str, db: Session = Depends(get_db)):
    r = get_feedback_by_id(db, report_id)
    if not r:
        raise HTTPException(status_code=404, detail="보고를 찾을 수 없습니다")
    return {
        "report_id": r.report_id,
        "blocked_api": r.blocked_api,
        "model_id": r.model_id,
        "purpose": r.purpose,
        "reporter_id": r.reporter_id,
        "submitted_at": r.submitted_at.isoformat() if r.submitted_at else "",
        "auto_classification": r.auto_classification,
        "in_official_docs": r.in_official_docs,
        "verified_org_count": r.verified_org_count,
        "estimated_response_hours": r.estimated_response_hours,
        "review_status": r.review_status,
        "auto_rejected": r.auto_rejected,
    }


# ─────────────────────────────────────────────
# 감사 로그
# ─────────────────────────────────────────────

@router.get("/audit")
def get_audit(
    api_path: str = "",
    action: str = "",
    actor: str = "",
    limit: int = 50,
    offset: int = 0,
    db: Session = Depends(get_db),
):
    stmt = select(AuditLog)
    if api_path:
        stmt = stmt.where(AuditLog.api_path.contains(api_path))
    if action:
        stmt = stmt.where(AuditLog.action == action)
    if actor:
        stmt = stmt.where(AuditLog.actor.contains(actor))

    total = db.execute(
        select(func.count()).select_from(stmt.subquery())
    ).scalar()
    items = db.execute(
        stmt.order_by(AuditLog.id.desc()).limit(limit).offset(offset)
    ).scalars().all()
    return {
        "items": [
            {
                "id": log.id,
                "timestamp": log.timestamp.isoformat() if log.timestamp else "",
                "action": log.action,
                "api_path": log.api_path,
                "actor": log.actor,
                "detail": log.detail or "",
                "prev_hash": log.prev_hash[:16] + "..." if log.prev_hash else "",
                "entry_hash": log.entry_hash[:16] + "..." if log.entry_hash else "",
            }
            for log in items
        ],
        "total": total,
        "count": len(items),
    }


@router.get("/audit/verify")
def verify_audit(db: Session = Depends(get_db)):
    """감사 로그 체인의 해시 무결성 검증"""
    is_valid, errors = verify_audit_chain(db)
    total = db.execute(select(func.count()).select_from(AuditLog)).scalar() or 0
    return {
        "valid": is_valid,
        "total_entries": total,
        "violation_count": len(errors),
        "violations": errors[:50],
    }


# ─────────────────────────────────────────────
# 승인된 API 목록 (운영 / 대시보드)
# ─────────────────────────────────────────────

@router.get("/approved")
def list_approved(
    search: str = "",
    namespace: str = "",
    source: str = "",
    include_blocked: bool = False,
    limit: int = 50,
    offset: int = 0,
    db: Session = Depends(get_db),
):
    """승인된 ApprovedApi 목록 — 검색/네임스페이스/source 필터.

    대시보드 ✅ 승인 목록 탭 + bulk 스크립트 운영용.
    is_blocked=True인 항목은 BLOCKED 응답 전용이므로 여기선 제외.
    """
    stmt = select(ApprovedApi)
    if not include_blocked:
        stmt = stmt.where(ApprovedApi.is_blocked == False)  # noqa: E712
    if search:
        stmt = stmt.where(ApprovedApi.api_path.contains(search))
    if namespace:
        stmt = stmt.where(ApprovedApi.namespace.contains(namespace))
    if source:
        stmt = stmt.where(ApprovedApi.source == source)

    total = db.execute(
        select(func.count()).select_from(stmt.subquery())
    ).scalar() or 0
    rows = db.execute(
        stmt.order_by(ApprovedApi.added_date.desc()).limit(limit).offset(offset)
    ).scalars().all()

    return {
        "items": [
            {
                "api_path": a.api_path,
                "namespace": a.namespace,
                "source": a.source,
                "matched_rule": a.matched_rule,
                "source_version": a.source_version or "",
                "added_date": a.added_date.isoformat() if a.added_date else "",
                "reviewer_id": a.reviewer_id or "",
                "review_note": a.review_note or "",
                "is_blocked": a.is_blocked,
            }
            for a in rows
        ],
        "total": total,
        "count": len(rows),
    }


# ─────────────────────────────────────────────
# 통계
# ─────────────────────────────────────────────

@router.get("/stats")
def whitelist_stats(db: Session = Depends(get_db)):
    approved_count = db.execute(
        select(func.count()).select_from(ApprovedApi)
        .where(ApprovedApi.is_blocked == False)  # noqa: E712
    ).scalar() or 0
    blocked_count = db.execute(
        select(func.count()).select_from(ApprovedApi)
        .where(ApprovedApi.is_blocked == True)  # noqa: E712
    ).scalar() or 0
    pending_count = count_pending(db)
    feedback_count = db.execute(
        select(func.count()).select_from(FeedbackReport)
    ).scalar() or 0
    return {
        "whitelist_version": WHITELIST_VERSION,
        "approved_active": approved_count,
        "blocked": blocked_count,
        "rejected": blocked_count,
        "pending_review": pending_count,
        "feedback_total": feedback_count,
    }
