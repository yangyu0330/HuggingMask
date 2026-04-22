"""
감사 로그 — append-only + SHA256 해시 체인

상세설계 9.2절 / HuggingMask 인터페이스 정의서 reason code AUDIT_LOG_WRITTEN.

체인 규칙:
  prev_hash  = 직전 항목의 entry_hash (없으면 GENESIS)
  entry_hash = SHA256(prev_hash || action || api_path || actor || timestamp || detail)

이 값을 다음 항목의 prev_hash로 사용. 사후 변조 시 entry_hash 재계산이 깨진다.
"""

import hashlib
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from whitelist.tables import AuditLog


GENESIS_HASH = "GENESIS"


def _canonical_timestamp(ts: datetime) -> str:
    """SQLite의 DateTime(timezone=True)은 읽을 때 tzinfo를 잃는다.
    INSERT 시 해시와 SELECT 후 재계산 해시가 일치하도록 UTC naive로 정규화.
    """
    if ts.tzinfo is not None:
        ts = ts.astimezone(timezone.utc).replace(tzinfo=None)
    return ts.isoformat()


def compute_entry_hash(
    prev_hash: str,
    action: str,
    api_path: str,
    actor: str,
    timestamp: datetime,
    detail: str | None,
) -> str:
    payload = "|".join([
        prev_hash, action, api_path, actor,
        _canonical_timestamp(timestamp), detail or "",
    ])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def append_audit(
    db: Session,
    action: str,
    api_path: str,
    actor: str,
    detail: str | None = None,
) -> AuditLog:
    """체인의 마지막에 로그를 추가한다."""
    last_log = db.execute(
        select(AuditLog).order_by(AuditLog.id.desc()).limit(1)
    ).scalar_one_or_none()
    prev_hash = last_log.entry_hash if last_log else GENESIS_HASH

    now = datetime.now(timezone.utc)
    entry_hash = compute_entry_hash(prev_hash, action, api_path, actor, now, detail)

    log = AuditLog(
        timestamp=now,
        action=action,
        api_path=api_path,
        actor=actor,
        detail=detail,
        prev_hash=prev_hash,
        entry_hash=entry_hash,
    )
    db.add(log)
    return log


def verify_audit_chain(db: Session) -> tuple[bool, list[str]]:
    """전체 체인 무결성 검증.

    Returns:
        (is_valid, errors): 통과 여부와 위반 사항 목록
    """
    logs = list(db.execute(
        select(AuditLog).order_by(AuditLog.id.asc())
    ).scalars().all())

    errors: list[str] = []
    expected_prev = GENESIS_HASH

    for log in logs:
        if log.prev_hash != expected_prev:
            errors.append(
                f"#{log.id}: prev_hash 불일치 "
                f"(저장={log.prev_hash[:12]}..., 기대={expected_prev[:12]}...)"
            )

        recomputed = compute_entry_hash(
            log.prev_hash, log.action, log.api_path,
            log.actor, log.timestamp, log.detail,
        )
        if recomputed != log.entry_hash:
            errors.append(
                f"#{log.id}: entry_hash 변조 의심 "
                f"(저장={log.entry_hash[:12]}..., 재계산={recomputed[:12]}...)"
            )

        expected_prev = log.entry_hash

    return (len(errors) == 0, errors)
