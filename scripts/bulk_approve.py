"""
일괄 자동 승인 스크립트 — Pending API 중 AUTO_APPROVE 분류만 일괄 승인.

원본 ``adaptive-whitelist-engine/bulk_approve.py``를 HuggingMask 인터페이스
정의서 v1.0에 맞춰 적응:
- API base ``/api/v1`` → ``/internal/v1``
- enum: lowercase → uppercase (``auto_approve`` → ``AUTO_APPROVE``,
  ``pending`` → ``PENDING``)
- 키: ``danger_keywords_found`` → ``risk_keywords``

상세설계 5.3절 기준:
- AUTO_APPROVE: 안전 namespace + 위험 키워드 없음 → 자동 승인
- CONDITIONAL: 보안 담당자 리뷰 필요
- MANUAL: 반드시 사람 판단
- BLOCKED: 승인 불가

이 스크립트는 AUTO_APPROVE만 일괄 승인한다 (보안 게이트 원칙).

사용:
    python scripts/bulk_approve.py [--api http://127.0.0.1:8000]
"""

from __future__ import annotations

import argparse
import sys

import httpx


DEFAULT_API_BASE = "http://127.0.0.1:8000/internal/v1"


def get_stats(client: httpx.Client, base: str) -> dict:
    r = client.get(f"{base}/stats")
    r.raise_for_status()
    return r.json()


def bulk_approve_auto(
    client: httpx.Client, base: str, reviewer_id: str = "auto_system",
) -> int:
    """AUTO_APPROVE 분류된 PENDING API만 일괄 승인."""
    total_approved = 0
    page = 0
    while True:
        # PENDING + AUTO_APPROVE만 조회. 승인하면 PENDING에서 빠지니 항상 offset 0.
        r = client.get(
            f"{base}/pending",
            params={
                "classification": "AUTO_APPROVE",
                "review_status": "PENDING",
                "limit": 50,
                "offset": 0,
            },
        )
        r.raise_for_status()
        items = r.json().get("items", [])
        if not items:
            break

        page += 1
        print(f"  페이지 {page}: {len(items)}개 자동 승인 중...")

        for item in items:
            client.post(
                f"{base}/review",
                json={
                    "api_path": item["api_path"],
                    "decision": "approve",
                    "reviewer_id": reviewer_id,
                    "review_note": "namespace rule auto-approved (AUTO_APPROVE)",
                },
            )
            total_approved += 1
    return total_approved


def main() -> int:
    p = argparse.ArgumentParser(description="HuggingMask Pending AUTO_APPROVE 일괄 승인")
    p.add_argument("--api", default=DEFAULT_API_BASE, help="API base URL")
    p.add_argument("--reviewer-id", default="auto_system")
    args = p.parse_args()

    print("=" * 60)
    print("  HuggingMask 일괄 자동 승인")
    print("=" * 60)

    with httpx.Client(timeout=120) as client:
        try:
            stats = get_stats(client, args.api)
        except httpx.HTTPError as e:
            print(f"오류: 서버 연결 실패 ({args.api}) — {e}", file=sys.stderr)
            return 1

        print(f"\n현재 상태:")
        print(f"  승인: {stats['approved_active']}개")
        print(f"  대기: {stats['pending_review']}개")
        print(f"  차단: {stats['blocked']}개")
        print(f"  whitelist_version: {stats.get('whitelist_version', '-')}\n")

        n = bulk_approve_auto(client, args.api, reviewer_id=args.reviewer_id)
        print(f"\n→ {n}개 자동 승인 완료")

        stats = get_stats(client, args.api)
        print("=" * 60)
        print(f"  최종 결과:")
        print(f"  승인: {stats['approved_active']}개")
        print(f"  대기: {stats['pending_review']}개 (수동 리뷰 필요)")
        print(f"  차단: {stats['blocked']}개")
        print("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
