"""
조건부 API 네임스페이스 단위 일괄 승인 — CONDITIONAL 분류 중 안전한
namespace + 위험 키워드 없음 항목만 승인.

원본 ``adaptive-whitelist-engine/bulk_conditional.py``를 HuggingMask
인터페이스 정의서 v1.0에 맞춰 적응:
- API base ``/api/v1`` → ``/internal/v1``
- enum 대문자 (``review_status="PENDING"`` 등)
- 키: ``danger_keywords_found`` → ``risk_keywords``

승인 대상 (상세설계 3.4절):
- ``torch.optim.*``, ``torch.cuda.*``, ``torch.amp.*``, ``torch.backends.*``
- ``transformers.*``, ``numpy.*`` (포함하되 위험 키워드 있으면 제외)

위험 키워드(load/save/exec/system 등)가 함수명에 있으면 스킵.

사용:
    python scripts/bulk_conditional.py [--api http://127.0.0.1:8000]
"""

from __future__ import annotations

import argparse
import os
import sys

import httpx


DEFAULT_API_BASE = "http://127.0.0.1:8000/internal/v1"

SAFE_NAMESPACES: tuple[str, ...] = (
    "torch.optim.", "torch.cuda.", "torch.amp.", "torch.backends.",
    "transformers.", "numpy.",
)

# 함수명에 이 키워드 포함 시 자동 승인 스킵 (사람 리뷰)
SKIP_KEYWORDS: frozenset[str] = frozenset({
    "load", "save", "dump", "open", "write", "read",
    "download", "fetch", "upload",
    "exec", "eval", "compile",
    "system", "popen", "call", "run", "spawn",
})


def collect_pending(client: httpx.Client, base: str) -> list[dict]:
    """CONDITIONAL + PENDING 전체를 read-only로 수집.

    승인 작업을 수집과 분리한다. 같은 루프에서 승인하면 PENDING 목록이
    줄어들면서 ``offset += 50``이 아직 처리 안 한 항목을 건너뛴다.
    수집 단계는 목록을 변경하지 않으므로 offset 페이지네이션이 안정적이다.
    """
    collected: list[dict] = []
    offset = 0
    while True:
        r = client.get(
            f"{base}/pending",
            params={
                "classification": "CONDITIONAL",
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


def _is_safe_conditional(item: dict) -> bool:
    path = item["api_path"]
    if not any(path.startswith(ns) for ns in SAFE_NAMESPACES):
        return False
    func_name = path.rsplit(".", 1)[-1].lower()
    tokens = set(func_name.split("_"))
    if tokens & SKIP_KEYWORDS:
        return False
    if item.get("risk_keywords"):
        return False
    return True


def _apply_review(
    client: httpx.Client, base: str, api_path: str, reviewer_id: str,
) -> bool:
    """단건 승인 후 실제 적용 여부 반환 (HTTP 상태 + applied 플래그 확인)."""
    resp = client.post(
        f"{base}/review",
        json={
            "api_path": api_path,
            "decision": "approve",
            "reviewer_id": reviewer_id,
            "review_note": "safe conditional namespace - bulk approved",
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


def main() -> int:
    p = argparse.ArgumentParser(
        description="HuggingMask CONDITIONAL 안전 namespace 일괄 승인",
    )
    p.add_argument("--api", default=DEFAULT_API_BASE)
    p.add_argument("--reviewer-id", default="auto_system")
    p.add_argument(
        "--internal-token",
        default=os.environ.get("HUGGINGMASK_INTERNAL_API_TOKEN"),
        help="X-Internal-Token 헤더 (기본: $HUGGINGMASK_INTERNAL_API_TOKEN)",
    )
    args = p.parse_args()
    _headers = {"X-Internal-Token": args.internal_token} if args.internal_token else {}
    if args.internal_token:
        _headers["X-Reviewer-Id"] = args.reviewer_id

    with httpx.Client(timeout=120, headers=_headers) as client:
        try:
            stats = client.get(f"{args.api}/stats").json()
        except httpx.HTTPError as e:
            print(f"오류: 서버 연결 실패 — {e}", file=sys.stderr)
            return 1

        print(
            f"시작: 승인={stats['approved_active']} | "
            f"대기={stats['pending_review']} | "
            f"version={stats.get('whitelist_version', '-')}",
        )

        # 1단계: 대상 목록을 먼저 안정적으로 수집 (read-only).
        pending = collect_pending(client, args.api)

        approved, skipped, failed = 0, 0, 0
        # 2단계: 수집한 목록을 필터링 후 승인.
        for item in pending:
            if not _is_safe_conditional(item):
                skipped += 1
                continue
            if _apply_review(client, args.api, item["api_path"], args.reviewer_id):
                approved += 1
            else:
                failed += 1
                print(
                    f"  경고: 승인 실패 — {item['api_path']}",
                    file=sys.stderr,
                )
            if approved and approved % 500 == 0:
                print(f"  진행: {approved}개 승인, {skipped}개 스킵")

        stats = client.get(f"{args.api}/stats").json()
        print(
            f"\n완료! 승인={stats['approved_active']} | "
            f"대기={stats['pending_review']} | "
            f"신규승인={approved}개 | 스킵={skipped}개 | 실패={failed}개",
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
