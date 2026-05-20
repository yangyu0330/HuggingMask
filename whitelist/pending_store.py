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


def _ensure_utc(ts: datetime | None) -> datetime | None:
    """SQLite는 DateTime(timezone=True)을 저장은 받지만 읽을 때 tzinfo를 잃는다.
    우리 정책상 모든 timestamp는 UTC이므로, naive로 읽힌 값에 UTC tzinfo를 다시 부착한다.
    PostgreSQL 환경에서는 이미 tzinfo가 있어서 no-op.
    """
    if ts is None:
        return None
    if ts.tzinfo is None:
        return ts.replace(tzinfo=timezone.utc)
    return ts


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

    호출자가 ``verified_org_count``/``verified_org_list``/``in_official_docs``를
    명시하지 않은 경우 (기본값) 모듈 2 캐시(``data/org_analysis_cache``)와
    모듈 1 결과 DB(``ApprovedApi``)에서 자동으로 채운다.
    """
    # ── mod1/mod2 캐시에서 자동 채움 (호출자가 명시 안 한 경우만) ──
    if verified_org_count == 0 and verified_org_list is None:
        from whitelist.cache_loader import get_org_cache
        org_cache = get_org_cache()
        verified_org_count = org_cache.lookup_verified_org_count(api_path)
        if verified_org_count > 0:
            verified_org_list = org_cache.lookup_org_list(api_path)
    if not in_official_docs:
        from whitelist.cache_loader import is_in_official_docs as _is_in_docs
        in_official_docs = _is_in_docs(db, api_path)

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
        first_seen_at=_ensure_utc(pending.first_seen_at),
        last_seen_at=_ensure_utc(pending.last_seen_at),
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


# ─────────────────────────────────────────────
# 외부 upsert — PendingApiRecord 전체를 손실 없이 반영 (15.2절)
# ─────────────────────────────────────────────

def upsert_pending_record(
    db: Session,
    record: PendingApiRecord,
) -> PendingApi:
    """외부(analyzer 등)가 보낸 PendingApiRecord를 그대로 upsert.

    `upsert_pending()`은 검증 흐름 중 자동 등록에 최적화된 함수로
    축약 인자만 받는다. 이 함수는 15.1절 PendingApiRecord 전체를
    손실 없이 반영한다 (양유상 PR #9 리뷰 요청 2번).

    정책:
      - created_from_job_id는 record 값을 사용 (호출자가 설정한 배치 ID)
      - first_seen_at / last_seen_at / seen_count는 record 값 그대로 반영
      - model_list / sample_callsites / verified_org_list 전체 보존
      - 이 엔드포인트는 review_status=PENDING만 허용 (보안 게이트 원칙).
        PENDING이 아닌 값은 호출자가 이 endpoint 외 경로(/review)로 가야 함.

    Raises:
        ValueError: review_status가 PENDING이 아닐 경우
    """
    if record.review_status != ReviewStatus.PENDING:
        raise ValueError(
            f"/pending/upsert는 review_status=PENDING만 허용합니다. "
            f"받은 값={record.review_status.value}. "
            f"다른 상태로 전환하려면 /review endpoint를 사용하세요."
        )

    from whitelist.audit import append_audit

    existing = get_pending(db, record.api_path)
    if existing:
        # 업데이트 — record 값으로 덮어쓴다 (외부가 명시적으로 보낸 값이 우선)
        existing.first_seen_at = record.first_seen_at
        existing.last_seen_at = record.last_seen_at
        existing.seen_count = record.seen_count
        existing.auto_classification = record.auto_classification
        existing.verified_org_count = record.verified_org_count
        existing.verified_org_list = list(record.verified_org_list)
        existing.in_official_docs = record.in_official_docs
        existing.review_status = record.review_status
        existing.model_list = list(record.model_list)
        existing.risk_keywords = list(record.risk_keywords)
        existing.matched_namespace_rule = record.matched_namespace_rule
        existing.documentation_url = record.documentation_url
        existing.sample_callsites = list(record.sample_callsites)
        existing.created_from_job_id = record.created_from_job_id
        db.flush()
        return existing

    pending = PendingApi(
        api_path=record.api_path,
        first_seen_at=record.first_seen_at,
        last_seen_at=record.last_seen_at,
        seen_count=record.seen_count,
        auto_classification=record.auto_classification,
        verified_org_count=record.verified_org_count,
        verified_org_list=list(record.verified_org_list),
        in_official_docs=record.in_official_docs,
        review_status=record.review_status,
        model_list=list(record.model_list),
        risk_keywords=list(record.risk_keywords),
        matched_namespace_rule=record.matched_namespace_rule,
        documentation_url=record.documentation_url,
        sample_callsites=list(record.sample_callsites),
        created_from_job_id=record.created_from_job_id,
    )
    db.add(pending)
    append_audit(
        db,
        action="pending_upserted",
        api_path=record.api_path,
        actor="system",
        detail=f"external upsert, job_id={record.created_from_job_id}",
    )
    db.flush()
    return pending
