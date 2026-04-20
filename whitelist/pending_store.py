"""
Pending API 저장소 — PendingApiRecord (15.1절) 영속화

설계 원칙 (whitelist/pending_store.md):
- 같은 API가 반복 등장하면 새 레코드를 만들지 않고 seen_count, last_seen_at 갱신
- review_status 기본값은 PENDING
- 자동 분류가 AUTO_APPROVE여도 실제 allow 규칙으로 즉시 승격하지 않는다
- sample_callsite와 risk_keyword를 저장해 리뷰 근거를 남긴다
"""

from datetime import datetime, timezone

from sqlalchemy import select, func
from sqlalchemy.orm import Session

from whitelist.audit import append_audit
from whitelist.models import (
    PendingApiRecord, PendingClassification, ReviewStatus,
)
from whitelist.tables import PendingApi


# ─────────────────────────────────────────────
# 조회
# ─────────────────────────────────────────────

def get_pending(db: Session, api_path: str) -> PendingApi | None:
    return db.execute(
        select(PendingApi).where(PendingApi.api_path == api_path)
    ).scalar_one_or_none()


def list_pending(
    db: Session,
    review_status: ReviewStatus | None = None,
    classification: PendingClassification | None = None,
    limit: int = 50,
    offset: int = 0,
) -> list[PendingApi]:
    stmt = select(PendingApi)
    if review_status:
        stmt = stmt.where(PendingApi.review_status == review_status)
    if classification:
        stmt = stmt.where(PendingApi.auto_classification == classification)
    stmt = stmt.order_by(PendingApi.last_seen_at.desc()).limit(limit).offset(offset)
    return list(db.execute(stmt).scalars().all())


def count_pending(db: Session) -> int:
    return db.execute(
        select(func.count()).select_from(PendingApi)
        .where(PendingApi.review_status == ReviewStatus.PENDING)
    ).scalar() or 0


# ─────────────────────────────────────────────
# Upsert (코어 — pending_store.md:21 원칙)
# ─────────────────────────────────────────────

def upsert_pending(
    db: Session,
    api_path: str,
    auto_classification: PendingClassification,
    job_id: str,
    model_repo_id: str = "",
    risk_keywords: list[str] | None = None,
    matched_namespace_rule: str | None = None,
    documentation_url: str | None = None,
    sample_callsite: str | None = None,
    verified_org_count: int = 0,
    verified_org_list: list[str] | None = None,
    in_official_docs: bool = False,
) -> PendingApi:
    """
    같은 api_path가 이미 있으면 seen_count, last_seen_at, model_list,
    sample_callsites 갱신. 없으면 신규 레코드 생성.

    review_status는 항상 PENDING으로 시작 (자동 승인 권고도 사람 게이트 거쳐야 함).
    """
    now = datetime.now(timezone.utc)
    existing = get_pending(db, api_path)

    if existing:
        existing.seen_count += 1
        existing.last_seen_at = now
        # 모델 목록 누적 (중복 없이)
        if model_repo_id and model_repo_id not in (existing.model_list or []):
            existing.model_list = list(existing.model_list or []) + [model_repo_id]
        # 콜사이트 누적 (최근 20개로 제한)
        if sample_callsite:
            sites = list(existing.sample_callsites or [])
            if sample_callsite not in sites:
                sites.append(sample_callsite)
                existing.sample_callsites = sites[-20:]
        # 신규 정보가 들어오면 보강
        if verified_org_count > existing.verified_org_count:
            existing.verified_org_count = verified_org_count
            existing.verified_org_list = verified_org_list or existing.verified_org_list
        if in_official_docs and not existing.in_official_docs:
            existing.in_official_docs = True
        if risk_keywords:
            merged = set(existing.risk_keywords or []) | set(risk_keywords)
            existing.risk_keywords = sorted(merged)
        db.flush()
        return existing

    pending = PendingApi(
        api_path=api_path,
        first_seen_at=now,
        last_seen_at=now,
        seen_count=1,
        auto_classification=auto_classification,
        verified_org_count=verified_org_count,
        verified_org_list=verified_org_list or [],
        in_official_docs=in_official_docs,
        review_status=ReviewStatus.PENDING,
        model_list=[model_repo_id] if model_repo_id else [],
        risk_keywords=risk_keywords or [],
        matched_namespace_rule=matched_namespace_rule,
        documentation_url=documentation_url,
        sample_callsites=[sample_callsite] if sample_callsite else [],
        created_from_job_id=job_id,
    )
    db.add(pending)
    append_audit(
        db,
        action="pending_registered",
        api_path=api_path,
        actor="system",
        detail=f"classification={auto_classification.value}, job_id={job_id}",
    )
    db.flush()
    return pending


def to_record(pending: PendingApi) -> PendingApiRecord:
    """DB 모델 → Pydantic 응답 모델 (15.1절 PendingApiRecord)"""
    return PendingApiRecord(
        api_path=pending.api_path,
        first_seen_at=pending.first_seen_at,
        last_seen_at=pending.last_seen_at,
        seen_count=pending.seen_count,
        auto_classification=PendingClassification(pending.auto_classification),
        verified_org_count=pending.verified_org_count,
        verified_org_list=list(pending.verified_org_list or []),
        in_official_docs=pending.in_official_docs,
        review_status=ReviewStatus(pending.review_status),
        model_list=list(pending.model_list or []),
        risk_keywords=list(pending.risk_keywords or []),
        matched_namespace_rule=pending.matched_namespace_rule,
        documentation_url=pending.documentation_url,
        sample_callsites=list(pending.sample_callsites or []),
        created_from_job_id=pending.created_from_job_id,
    )
