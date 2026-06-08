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
    FeedbackReportResponse, PendingClassification, ReviewStatus, WhitelistSource,
)
from whitelist.pending_store import get_pending, upsert_pending
from whitelist.rules import (
    PERMANENTLY_BLOCKED_APIS, SLA_HOURS, WHITELIST_VERSION, documentation_url_for,
)
from whitelist.tables import ApprovedApi, FeedbackReport


logger = logging.getLogger(__name__)

# 오탐 자동학습 — 사람 검토 없이 ALLOWED로 자동 승격하기 위한 최소 verified org 수.
AUTO_LEARN_MIN_VERIFIED_ORGS = 3


def _auto_learn_eligible(
    api_path: str,
    classification: PendingClassification,
    org_count: int,
    risk_keywords: list[str],
) -> bool:
    """오탐 보고를 사람 검토 없이 ALLOWED로 자동 승격할지 판정.

    핵심 안전 원칙: **보고 행위 자체는 신뢰하지 않는다**(악의적 보고/계정 탈취로
    위험 API를 승격하는 것을 막기 위해). 위조 불가능한 *외부* 증거가 모두 충족될
    때만 True:
      - 영구 차단 목록이 아님
      - 네임스페이스 규칙이 AUTO_APPROVE(예: torch.nn.*)로 분류한 안전 API
        (os/subprocess/pickle/importlib/ctypes 등 위험 네임스페이스는 BLOCKED라
        절대 AUTO_APPROVE가 안 됨)
      - 함수명에 exec/io 위험 키워드 없음
      - verified org(mod2, google/meta 등) N개 이상이 실제 모델에서 사용

    ``in_official_docs``(mod1)는 ApprovedApi(INITIAL/AUTO_CRAWL) 등재 여부인데,
    그게 True면 submit_feedback이 "이미 승인됨"으로 조기 return하므로 이 시점엔
    항상 False다 → 자동학습 증거로 쓸 수 없어 org_count(mod2)에 의존한다.

    이 조건은 `os.system` 같은 위험 API에는 절대 충족되지 않는다(네임스페이스
    BLOCKED + 영구차단).
    """
    if api_path in PERMANENTLY_BLOCKED_APIS:
        return False
    if classification is not PendingClassification.AUTO_APPROVE:
        return False
    if risk_keywords:
        return False
    return org_count >= AUTO_LEARN_MIN_VERIFIED_ORGS


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

    # 모듈 1·2 캐시 기반 자동 채움
    # - in_official_docs: ApprovedApi(source=INITIAL/AUTO_CRAWL)에 등록되어 있는가
    # - verified_org_count: mod2 캐시에서 이 API를 쓰는 verified org 수
    from whitelist.cache_loader import get_org_cache, is_in_official_docs

    in_official = is_in_official_docs(db, api_path)
    org_count = get_org_cache().lookup_verified_org_count(api_path)
    permanently_blocked = api_path in PERMANENTLY_BLOCKED_APIS
    # 수동 거부로 DB에 is_blocked=True인 API는 auto-learn으로 재허용되면 안 된다.
    # (양유상 PR #56: reject된 차단을 verified-org 근거로 is_blocked=False로
    #  덮어쓰는 우회를 막는다.)
    db_blocked = approved is not None and approved.is_blocked
    auto_rejected = permanently_blocked or db_blocked
    auto_learned = (not auto_rejected) and _auto_learn_eligible(
        api_path, classification, org_count, danger
    )

    if auto_rejected:
        sla = SLA_HOURS[PendingClassification.BLOCKED]
        review_status = ReviewStatus.REJECTED
        classification = PendingClassification.BLOCKED
    elif auto_learned:
        sla = 0
        review_status = ReviewStatus.APPROVED
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
        verified_org_count=org_count,
        estimated_response_hours=sla,
        review_status=review_status,
        auto_rejected=auto_rejected,
    )
    db.add(report)

    if auto_learned:
        # 위조 불가능한 외부 증거(공식 문서 + verified org 다수 + 안전
        # 네임스페이스 + 위험 키워드 0)만으로 화이트리스트에 자동 승격.
        # 보고 행위 자체는 신뢰하지 않으므로 악의적 보고로는 도달 불가.
        db.merge(ApprovedApi(
            api_path=api_path,
            namespace=api_path.split(".")[0],
            source=WhitelistSource.AUTO_CRAWL,
            matched_rule=matched,
            source_version=WHITELIST_VERSION,
            reviewer_id="auto-learn",
            review_note=(
                f"auto-approved via feedback {report.report_id}: "
                f"{org_count} verified orgs (mod2), AUTO_APPROVE namespace"
            ),
            is_blocked=False,
        ))
        # 같은 API가 이전 whitelist check로 이미 PENDING이면 stale로 남지 않도록
        # APPROVED로 해소한다(양유상 PR #56: 자동승인 후 pending 큐에서 reject되어
        # is_blocked=True로 되돌아가는 상태 충돌 방지).
        existing_pending = get_pending(db, api_path)
        if existing_pending is not None:
            existing_pending.review_status = ReviewStatus.APPROVED
        append_audit(
            db,
            action="feedback_auto_approved",
            api_path=api_path,
            actor="auto-learn",
            detail=(
                f"report_id={report.report_id}, verified_org_count={org_count}, "
                f"classification=AUTO_APPROVE, namespace_rule={matched}"
            ),
        )
        # 다음 append_audit가 방금 추가한 행을 tail로 보도록 flush (autoflush=False
        # 환경에서 두 감사 행이 같은 prev_hash를 공유해 체인이 깨지는 것 방지).
        db.flush()
    elif not auto_rejected:
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
            f"auto_rejected={auto_rejected}, auto_learned={auto_learned}, sla={sla}h"
        ),
    )
    db.commit()

    if auto_rejected:
        if permanently_blocked:
            message = (
                f"'{api_path}'는 영구 차단 목록에 등록된 API로, "
                f"자동 거부되었습니다. 다른 접근 방식을 사용하세요."
            )
        else:
            message = (
                f"'{api_path}'는 보안 담당자가 이미 차단(거부)한 API로, "
                f"자동 거부되었습니다. 재허용은 정식 리뷰가 필요합니다."
            )
    elif auto_learned:
        message = (
            f"'{api_path}'는 verified org {org_count}개 실사용 + 안전 네임스페이스 "
            f"근거로 화이트리스트에 자동 승인되었습니다 (사람 검토 불필요)."
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
