"""프록시 다운로드 게이트 — 받기 전에 검사하고, 안전하면 통과·저장 아니면 차단.

HuggingMask 제품 thesis("신뢰가 아니라 행위로 판정")를 다운로드 경로에 적용한다:
클라이언트가 모델을 받기 전에 프록시가 코드/config/전처리를 **먼저** 검사
(``skip_weights`` — 가중치 GB는 안 받음)하고,

- DENY        → 가중치까지 받지 않고 격리(QUARANTINED). 다운로드 차단.
- APPROVE     → acquire(다운로드 허용) + Nexus 역할 저장소(``acquired_models``)에 기록.
- REVIEW      → 사람 검토 보류(PENDING).

즉 악성 코드는 **무거운 가중치를 받기도 전에** 코드 단계에서 걸러진다.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from whitelist.audit import append_audit
from whitelist.model_inspector import inspect_model_repo
from whitelist.tables import AcquiredModel


def _enum_value(value) -> str:
    return value.value if hasattr(value, "value") else str(value)


def _first_block_reason(resp) -> str | None:
    for r in resp.artifact_results:
        if _enum_value(r.status) == "BLOCK":
            for e in (r.reason_entries or []):
                return f"{r.artifact.file_name}: {e.code}"
            return r.artifact.file_name
    return None


def gate_model(repo_id: str, *, db: Session, revision: str = "main") -> dict:
    """다운로드 게이트 — 받기 전에 경량 검사(skip_weights) 후 판정·기록."""
    repo_id = (repo_id or "").strip()
    if not repo_id:
        return {"ok": False, "error": "repo_id를 입력하세요.", "error_code": "EMPTY_REPO_ID"}

    # 1) 다운로드 전 경량 검사(코드/config/전처리 — 가중치 제외)
    out = inspect_model_repo(repo_id, db=db, revision=revision, skip_weights=True)
    if not out.get("ok"):
        return out  # 다운로드 실패 등은 그대로 전달

    resp = out["response"]
    decision = _enum_value(resp.overall_decision)
    blocked = len(getattr(resp, "blocked_artifact_ids", []) or [])
    validated = int(out.get("validated_count", 0) or 0)

    if decision == "DENY":
        status, allowed = "QUARANTINED", False
    elif decision == "APPROVE":
        status, allowed = "ACQUIRED", True
    else:  # REVIEW_REQUIRED 등 — 사람 검토 전엔 미배포
        status, allowed = "PENDING", False
    reason = _first_block_reason(resp)

    # 2) Nexus 역할 저장소 기록 — 같은 (repo, revision)은 최신 판정으로 갱신
    record = db.execute(
        select(AcquiredModel).where(
            AcquiredModel.repo_id == repo_id,
            AcquiredModel.revision == revision,
        )
    ).scalar_one_or_none()
    if record is None:
        record = AcquiredModel(repo_id=repo_id, revision=revision)
        db.add(record)
    record.status = status
    record.decision = decision
    record.validated_count = validated
    record.blocked_count = blocked
    record.reason = reason

    append_audit(
        db,
        action=f"proxy_gate_{status.lower()}",
        api_path=repo_id,
        actor="proxy-gate",
        detail=f"decision={decision} validated={validated} blocked={blocked}",
    )
    db.commit()

    return {
        "ok": True,
        "repo_id": repo_id,
        "revision": revision,
        "allowed": allowed,
        "status": status,
        "decision": decision,
        "validated_count": validated,
        "blocked_count": blocked,
        "reason": reason,
        "response": resp,  # 대시보드가 파이프라인 가시화도 그릴 수 있게
    }


def list_acquired(db: Session, *, limit: int = 100) -> list[dict]:
    """저장소 목록(최신순) — 대시보드 게이트 탭용."""
    rows = (
        db.execute(
            select(AcquiredModel).order_by(AcquiredModel.acquired_at.desc()).limit(limit)
        )
        .scalars()
        .all()
    )
    return [
        {
            "repo_id": r.repo_id,
            "revision": r.revision,
            "status": r.status,
            "decision": r.decision,
            "validated_count": r.validated_count,
            "blocked_count": r.blocked_count,
            "reason": r.reason,
            "acquired_at": r.acquired_at.isoformat() if r.acquired_at else None,
        }
        for r in rows
    ]
