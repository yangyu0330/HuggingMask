"""기존 pending API 재분류 + 자동승인 대상 일괄 승인 — 리뷰 대기 감축.

분류 규칙 개선(빌트인/로컬 데이터연산은 화이트리스트 제어 대상 아님 → AUTO_APPROVE)을
기존에 쌓인 pending 에 소급 적용한다. 재분류 후 AUTO_APPROVE 가 된 항목만 일괄 승인하고,
위험/미지 라이브러리 API 는 그대로 검토 대기로 남긴다(보안 보존).

    python scripts/reclassify_pending.py            # dry-run (요약만, 변경 없음)
    python scripts/reclassify_pending.py --apply    # 실제 재분류 + 자동승인 반영

각 승인은 ReviewDecisionLog 에 reviewer_id="auto-reclassify" 로 감사 기록된다.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import select

from whitelist.database import SessionLocal, init_db
from whitelist.engine import _Classifier, apply_review_decision
from whitelist.models import PendingClassification, ReviewStatus
from whitelist.tables import PendingApi


def _reclassify(classifier: _Classifier, api_path: str) -> PendingClassification:
    base, _ = classifier.match_namespace(api_path)
    risk = classifier.find_risk_keywords(api_path)
    return classifier.escalate(base, risk)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true", help="실제 재분류+자동승인 반영")
    args = parser.parse_args()

    init_db()
    db = SessionLocal()
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

    print(f"PENDING {len(rows)}개 재분류: {counts}")
    print(f"자동승인 대상(빌트인/로컬 데이터연산): {len(auto)}개")

    if not args.apply:
        print("\n(dry-run) 실제 반영하려면 --apply. 자동승인 예시:")
        for api in auto[:25]:
            print("   ", api)
        return

    approved = 0
    for api_path in auto:
        result = apply_review_decision(
            db,
            api_path,
            decision="approve",
            reviewer_id="auto-reclassify",
            review_note="builtin/local-data-op auto-approved by classifier rule (LIBRARY_ROOTS + BENIGN_LEAF_NAMES)",
        )
        if getattr(result, "applied", False):
            approved += 1
    db.commit()
    print(f"\n승인 완료: {approved}개 → 리뷰 대기에서 제거. (위험/미지 API는 그대로 검토 대기)")


if __name__ == "__main__":
    main()
