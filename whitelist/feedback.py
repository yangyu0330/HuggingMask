"""
오탐 피드백 루프 (모듈 5 — 상세설계 7절)

개발자가 정상 사용임에도 차단된 API를 보고하면:
  1. 영구 차단 API → SLA 0시간으로 자동 거부
  2. 그 외 → 분류 권고 + 공식문서/Verified Org 사전 검토 후 PENDING 등록

원칙: 보고가 곧바로 화이트리스트 갱신으로 이어지지 않는다.
모든 보고는 보안 담당자 판정을 거쳐야 한다 (악의적 보고 / 계정 탈취 방어).
"""

import logging
import secrets
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from whitelist.audit import append_audit
from whitelist.engine import _Classifier
from whitelist.models import (
    FeedbackReportResponse, PendingClassification, ReviewStatus,
)
from whitelist.pending_store import upsert_pending
from whitelist.rules import (
    PERMANENTLY_BLOCKED_APIS, SLA_HOURS, documentation_url_for,
)
from whitelist.tables import ApprovedApi, FeedbackReport


logger = logging.getLogger(__name__)


def _generate_report_id() -> str:
    today = datetime.now(timezone.utc).strftime("%Y%m%d")
    return f"FB-{today}-{secrets.token_hex(3)}"


def submit_feedback(
    db: Session,
    blocked_api: str,
    model_id: str,
    purpose: str,
    reporter_id: str,
) -> FeedbackReportResponse:
    """피드백 보고 접수 + 자동 사전 검토.

    Raises:
        ValueError: blocked_api가 비었거나 이미 화이트리스트에 등록된 경우
    """
    api_path = blocked_api.strip()
    if not api_path:
        raise ValueError("blocked_api가 비어있습니다")

    # 이미 ALLOWED인 API에 대한 보고는 무의미
    approved = db.execute(
        select(ApprovedApi).where(ApprovedApi.api_path == api_path)
    ).scalar_one_or_none()
    if approved and not approved.is_blocked:
        raise ValueError(
            f"{api_path}는 이미 화이트리스트에 등록되어 있습니다. "
            f"차단 원인이 다른 검증 단계일 가능성"
        )

    # 자동 사전 검토 (상세설계 7.2절 3단계)
    classifier = _Classifier()
    base, matched = classifier.match_namespace(api_path)
    danger = classifier.find_risk_keywords(api_path)
    classification = classifier.escalate(base, danger)

    in_official = (approved is not None and not approved.is_blocked) or matched is not None
    auto_rejected = api_path in PERMANENTLY_BLOCKED_APIS

    if auto_rejected:
        sla = SLA_HOURS[PendingClassification.BLOCKED]
        review_status = ReviewStatus.REJECTED
        classification = PendingClassification.BLOCKED
    else:
        sla = SLA_HOURS.get(classification, 48)
        review_status = ReviewStatus.PENDING

    report = FeedbackReport(
        report_id=_generate_report_id(),
        blocked_api=api_path,
        model_id=model_id,
        purpose=purpose,
        reporter_id=reporter_id,
        auto_classification=classification,
        in_official_docs=in_official,
        verified_org_count=0,  # 모듈 2 결과 캐시 연동은 추후
        estimated_response_hours=sla,
        review_status=review_status,
        auto_rejected=auto_rejected,
    )
    db.add(report)

    if not auto_rejected:
        # 보안 담당자 큐에 들어가도록 pending에도 등록
        upsert_pending(
            db,
            api_path=api_path,
            auto_classification=classification,
            job_id=f"feedback:{report.report_id}",
            model_repo_id=model_id,
            risk_keywords=danger,
            matched_namespace_rule=matched,
            documentation_url=documentation_url_for(api_path),
            sample_callsite=f"reported by {reporter_id}: {purpose}",
        )

    append_audit(
        db,
        action="feedback_received",
        api_path=api_path,
        actor=reporter_id,
        detail=(
            f"report_id={report.report_id}, model={model_id}, "
            f"auto_rejected={auto_rejected}, sla={sla}h"
        ),
    )
    db.commit()

    if auto_rejected:
        message = (
            f"'{api_path}'는 영구 차단 목록에 등록된 API로, "
            f"자동 거부되었습니다. 다른 접근 방식을 사용하세요."
        )
    else:
        message = (
            f"보고 접수 완료. 자동 분류={classification.value}, "
            f"공식 문서 등록={'예' if in_official else '아니오'}. "
            f"예상 응답 {sla}시간 이내."
        )

    return FeedbackReportResponse(
        report_id=report.report_id,
        blocked_api=api_path,
        auto_classification=classification,
        in_official_docs=in_official,
        verified_org_count=report.verified_org_count,
        estimated_response_hours=sla,
        review_status=review_status,
        auto_rejected=auto_rejected,
        message=message,
    )


def list_feedback(
    db: Session,
    reporter_id: str | None = None,
    review_status: ReviewStatus | None = None,
    limit: int = 50,
    offset: int = 0,
) -> list[FeedbackReport]:
    stmt = select(FeedbackReport)
    if reporter_id:
        stmt = stmt.where(FeedbackReport.reporter_id == reporter_id)
    if review_status:
        stmt = stmt.where(FeedbackReport.review_status == review_status)
    stmt = stmt.order_by(FeedbackReport.submitted_at.desc()).limit(limit).offset(offset)
    return list(db.execute(stmt).scalars().all())


def get_feedback_by_id(db: Session, report_id: str) -> FeedbackReport | None:
    return db.execute(
        select(FeedbackReport).where(FeedbackReport.report_id == report_id)
    ).scalar_one_or_none()
