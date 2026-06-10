"""리뷰 대기 감축 — pending API 재분류 + 안전 항목(빌트인/로컬 데이터연산) 자동 승인.

분류 규칙(LIBRARY_ROOTS + BENIGN_LEAF_NAMES)을 기존 pending 에 소급 적용한다.
AUTO_APPROVE 가 된 항목만 일괄 승인하고 위험/미지 라이브러리 API 는 검토 대기로 남긴다.
스크립트(scripts/reclassify_pending.py)와 대시보드 엔드포인트가 공통으로 사용한다.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from whitelist.engine import _Classifier, apply_review_decision
from whitelist.models import PendingClassification, ReviewStatus
from whitelist.tables import PendingApi

_AUTO_NOTE = (
    "builtin/local-data-op auto-approved by classifier rule "
    "(LIBRARY_ROOTS + BENIGN_LEAF_NAMES)"
)


def _reclassify(classifier: _Classifier, api_path: str) -> PendingClassification:
    base, _ = classifier.match_namespace(api_path)
    risk = classifier.find_risk_keywords(api_path)
    return classifier.escalate(base, risk)


def reclassify_pending(
    db: Session,
    *,
    apply: bool = False,
    reviewer_id: str = "auto-reclassify",
) -> dict:
    """PENDING 을 재분류. ``apply`` 면 AUTO_APPROVE 항목을 일괄 승인.

    반환: {scanned, counts, auto_approve_candidates, samples[, approved]}
    """
    classifier = _Classifier()
    rows = (
        db.execute(select(PendingApi).where(PendingApi.review_status == ReviewStatus.PENDING))
        .scalars()
        .all()
    )

    counts: dict[str, int] = {}
    auto: list[str] = []
    for row in rows:
        new = _reclassify(classifier, row.api_path)
        counts[new.value] = counts.get(new.value, 0) + 1
        if new is PendingClassification.AUTO_APPROVE:
            auto.append(row.api_path)

    result: dict = {
        "scanned": len(rows),
        "counts": counts,
        "auto_approve_candidates": len(auto),
        "samples": auto[:25],
    }

    if apply:
        approved = 0
        for api_path in auto:
            decision = apply_review_decision(
                db,
                api_path,
                decision="approve",
                reviewer_id=reviewer_id,
                review_note=_AUTO_NOTE,
            )
            if getattr(decision, "applied", False):
                approved += 1
        db.commit()
        result["approved"] = approved
        result["remaining"] = len(rows) - approved

    return result
