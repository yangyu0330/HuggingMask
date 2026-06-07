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


def _apply_review(
    client: httpx.Client, base: str, api_path: str, reviewer_id: str, note: str,
) -> bool:
    """단건 승인 요청 후 실제 적용 여부 반환.

    HTTP 상태와 응답의 ``applied`` 플래그를 모두 확인한다. 500 응답이나
    ``applied: false``를 성공으로 잘못 카운트하지 않기 위함.
    """
    resp = client.post(
        f"{base}/review",
        json={
            "api_path": api_path,
            "decision": "approve",
            "reviewer_id": reviewer_id,
            "review_note": note,
        },
    )
    try:
        resp.raise_for_status()
    except httpx.HTTPError:
        return False
    try:
        body = resp.json()
    except ValueError:
        return False
    return body.get("applied") is True


def collect_pending_auto_approve(
    client: httpx.Client, base: str,
) -> list[dict]:
    """AUTO_APPROVE + PENDING 전부를 read-only로 수집.

    승인 작업과 수집을 분리한다 (Issue #28). 동일 루프에서 offset=0
    재조회로 승인하면 첫 페이지 50개가 전부 실패할 때 그 50개가 ``failed``에
    묶이면서 ``targets``가 빈 셋이 되어 51번째 이후 PENDING 항목까지
    스킵될 수 있다. 수집 단계는 목록을 변경하지 않으므로 offset 페이지네이션이
    안정적이며, 모든 초기 PENDING 항목이 정확히 한 번씩 승인 시도된다.
    """
    collected: list[dict] = []
    offset = 0
    while True:
        r = client.get(
            f"{base}/pending",
            params={
                "classification": "AUTO_APPROVE",
                "review_status": "PENDING",
                "limit": 50,
                "offset": offset,
            },
        )
        r.raise_for_status()
        items = r.json().get("items", [])
        if not items:
            break
        collected.extend(items)
        offset += 50
    return collected


def bulk_approve_auto(
    client: httpx.Client, base: str, reviewer_id: str = "auto_system",
) -> int:
    """AUTO_APPROVE 분류된 PENDING API만 일괄 승인."""
    pending = collect_pending_auto_approve(client, base)
    if not pending:
        return 0

    print(f"  대상 수집 {len(pending)}개. 승인 시도 중...")

    total_approved = 0
    failed_count = 0
    for item in pending:
        applied = _apply_review(
            client, base, item["api_path"], reviewer_id,
            "namespace rule auto-approved (AUTO_APPROVE)",
        )
        if applied:
            total_approved += 1
        else:
            failed_count += 1
            print(
                f"    경고: 승인 실패 — {item['api_path']} (스킵)",
                file=sys.stderr,
            )

    if failed_count:
        print(
            f"  실패 {failed_count}개 (PENDING에 남음, 운영자 수동 확인 필요)",
            file=sys.stderr,
        )
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
