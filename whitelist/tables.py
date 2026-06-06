"""
DB 테이블 정의

- approved_apis : 승인된 API
- pending_apis  : 미등록 API (PendingApiRecord 매핑)
- audit_log     : append-only 감사 로그 (해시 체인)
- feedback_reports : 오탐 피드백 (모듈 5)
"""

from datetime import datetime, timezone

from sqlalchemy import (
    Boolean, DateTime, Enum, Integer, JSON, String, Text, Index,
)
from sqlalchemy.orm import Mapped, mapped_column

from whitelist.database import Base
from whitelist.models import PendingClassification, ReviewStatus, WhitelistSource


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ApprovedApi(Base):
    __tablename__ = "approved_apis"

    api_path: Mapped[str] = mapped_column(String(512), primary_key=True)
    namespace: Mapped[str] = mapped_column(String(256), nullable=False, index=True)
    source: Mapped[str] = mapped_column(
        Enum(WhitelistSource), nullable=False,
        comment="INITIAL / AUTO_CRAWL / MANUAL_REVIEW",
    )
    matched_rule: Mapped[str | None] = mapped_column(String(256), nullable=True)
    added_date: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    source_version: Mapped[str] = mapped_column(String(64), default="")
    reviewer_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    review_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_blocked: Mapped[bool] = mapped_column(
        Boolean, default=False,
        comment="True면 status=BLOCKED으로 응답 (수동 거부 결과 등)",
    )

    __table_args__ = (Index("ix_approved_namespace_blocked", "namespace", "is_blocked"),)

    def __repr__(self) -> str:
        return f"<ApprovedApi {self.api_path} blocked={self.is_blocked}>"


class PendingApi(Base):
    """PendingApiRecord (15.1절)와 1:1 대응되는 영속 모델"""
    __tablename__ = "pending_apis"

    api_path: Mapped[str] = mapped_column(String(512), primary_key=True)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    seen_count: Mapped[int] = mapped_column(Integer, default=1)
    auto_classification: Mapped[str] = mapped_column(
        Enum(PendingClassification), nullable=False,
    )
    verified_org_count: Mapped[int] = mapped_column(Integer, default=0)
    verified_org_list: Mapped[list] = mapped_column(JSON, default=list)
    in_official_docs: Mapped[bool] = mapped_column(Boolean, default=False)
    review_status: Mapped[str] = mapped_column(
        Enum(ReviewStatus), default=ReviewStatus.PENDING,
    )
    model_list: Mapped[list] = mapped_column(JSON, default=list)
    risk_keywords: Mapped[list] = mapped_column(JSON, default=list)
    matched_namespace_rule: Mapped[str | None] = mapped_column(String(256), nullable=True)
    documentation_url: Mapped[str | None] = mapped_column(String(512), nullable=True)
    sample_callsites: Mapped[list] = mapped_column(JSON, default=list)
    created_from_job_id: Mapped[str] = mapped_column(String(64), default="")

    __table_args__ = (
        Index("ix_pending_classification", "auto_classification"),
        Index("ix_pending_review_status", "review_status"),
    )

    def __repr__(self) -> str:
        return f"<PendingApi {self.api_path} [{self.review_status}]>"


class AuditLog(Base):
    """감사 로그 — append-only + SHA256 해시 체인 무결성

    체인 모델:
      prev_hash  = 직전 항목의 entry_hash (없으면 GENESIS)
      entry_hash = SHA256(prev_hash || action || api_path || actor || timestamp || detail)
    """
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, index=True)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    api_path: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    actor: Mapped[str] = mapped_column(String(128), nullable=False)
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    prev_hash: Mapped[str] = mapped_column(String(64), default="GENESIS")
    entry_hash: Mapped[str] = mapped_column(String(64), default="", index=True)

    def __repr__(self) -> str:
        return f"<AuditLog #{self.id} {self.action} {self.api_path}>"


class ReviewDecisionLog(Base):
    """Durable review decision record keyed by caller supplied review_id."""
    __tablename__ = "review_decisions"

    review_id: Mapped[str] = mapped_column(String(96), primary_key=True)
    api_path: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    decision: Mapped[str] = mapped_column(String(16), nullable=False)
    reviewer_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    review_note: Mapped[str] = mapped_column(Text, nullable=False)
    condition: Mapped[str | None] = mapped_column(Text, nullable=True)
    source_evidence: Mapped[list] = mapped_column(JSON, default=list)
    final_review_status: Mapped[str] = mapped_column(
        Enum(ReviewStatus), nullable=False, index=True,
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, index=True)
    audit_log_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    audit_entry_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)

    __table_args__ = (
        Index("ix_review_decisions_api_decision", "api_path", "decision"),
    )

    def __repr__(self) -> str:
        return f"<ReviewDecision {self.review_id} {self.api_path} {self.decision}>"


class FeedbackReport(Base):
    """오탐 피드백 보고 (모듈 5)"""
    __tablename__ = "feedback_reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    report_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    blocked_api: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    model_id: Mapped[str] = mapped_column(String(256), nullable=False)
    purpose: Mapped[str] = mapped_column(Text, nullable=False)
    reporter_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    submitted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, index=True)
    auto_classification: Mapped[str] = mapped_column(Enum(PendingClassification), nullable=False)
    in_official_docs: Mapped[bool] = mapped_column(Boolean, default=False)
    verified_org_count: Mapped[int] = mapped_column(Integer, default=0)
    estimated_response_hours: Mapped[int] = mapped_column(Integer, default=48)
    review_status: Mapped[str] = mapped_column(
        Enum(ReviewStatus), default=ReviewStatus.PENDING, index=True,
    )
    auto_rejected: Mapped[bool] = mapped_column(Boolean, default=False)

    def __repr__(self) -> str:
        return f"<FeedbackReport {self.report_id}>"
