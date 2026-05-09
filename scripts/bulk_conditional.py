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


def main() -> int:
    p = argparse.ArgumentParser(
        description="HuggingMask CONDITIONAL 안전 namespace 일괄 승인",
    )
    p.add_argument("--api", default=DEFAULT_API_BASE)
    p.add_argument("--reviewer-id", default="auto_system")
    args = p.parse_args()

    with httpx.Client(timeout=120) as client:
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

        approved, skipped, offset = 0, 0, 0
        while True:
            r = client.get(
                f"{args.api}/pending",
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

            for item in items:
                path = item["api_path"]
                # 안전 namespace 체크
                if not any(path.startswith(ns) for ns in SAFE_NAMESPACES):
                    skipped += 1
                    continue
                # 위험 키워드 체크 (함수명 last component)
                func_name = path.rsplit(".", 1)[-1].lower()
                tokens = set(func_name.split("_"))
                if tokens & SKIP_KEYWORDS:
                    skipped += 1
                    continue
                # risk_keywords 필드(있으면) 직접 검사
                if item.get("risk_keywords"):
                    skipped += 1
                    continue

                client.post(
                    f"{args.api}/review",
                    json={
                        "api_path": path,
                        "decision": "approve",
                        "reviewer_id": args.reviewer_id,
                        "review_note": "safe conditional namespace - bulk approved",
                    },
                )
                approved += 1

            offset += 50
            if approved and approved % 500 == 0:
                print(f"  진행: {approved}개 승인, {skipped}개 스킵")

        stats = client.get(f"{args.api}/stats").json()
        print(
            f"\n완료! 승인={stats['approved_active']} | "
            f"대기={stats['pending_review']} | "
            f"신규승인={approved}개 | 스킵={skipped}개",
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
