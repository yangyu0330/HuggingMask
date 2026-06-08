"""
감사 로그 — append-only + HMAC-SHA256 해시 체인

상세설계 9.2절 / HuggingMask 인터페이스 정의서 reason code AUDIT_LOG_WRITTEN.

체인 규칙:
  prev_hash  = 직전 항목의 entry_hash (없으면 GENESIS)
  entry_hash = HMAC-SHA256(key, prev_hash || action || api_path || actor || timestamp || detail)

이 값을 다음 항목의 prev_hash로 사용.

왜 HMAC인가:
  평문 SHA256 체인은 한 행을 변조하면 그 이후 entry_hash를 "공개 알고리즘으로"
  전부 재계산해 일관된 가짜 체인을 만들 수 있다(키가 없으므로). HMAC은 서버가
  보유한 비밀 키(HUGGINGMASK_AUDIT_HMAC_KEY) 없이는 재계산이 불가능하므로
  변조 후 위조가 막힌다.

알려진 한계(정직 고지):
  - 꼬리 절단(마지막 N개 행 DELETE)은 in-DB 체인만으로는 탐지 불가하다. 남은
    프리픽스는 여전히 유효하기 때문. 완전한 방지는 외부 앵커(서명된 head 포인터/
    카운트의 out-of-band 보관)가 필요하며 이는 후속 과제다.
  - 기본 키(dev)를 쓰면 위조 방지가 무력하다 — 운영에서는 반드시 환경변수로
    비밀 키를 주입해야 한다.
"""

import hashlib
import hmac
import os
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from whitelist.tables import AuditLog


GENESIS_HASH = "GENESIS"

_DEFAULT_AUDIT_HMAC_KEY = "dev-only-audit-hmac-key"


def _audit_hmac_key() -> bytes:
    """감사 체인 HMAC 키. 운영에서는 HUGGINGMASK_AUDIT_HMAC_KEY를 주입한다."""
    return os.getenv("HUGGINGMASK_AUDIT_HMAC_KEY", _DEFAULT_AUDIT_HMAC_KEY).encode("utf-8")


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
    return hmac.new(
        _audit_hmac_key(), payload.encode("utf-8"), hashlib.sha256
    ).hexdigest()


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
    # 같은 트랜잭션에서 append_audit가 연달아 호출돼도 다음 호출이 방금 추가한
    # 행을 tail로 보도록 flush한다(autoflush=False 환경에서 두 행이 같은
    # prev_hash를 공유해 체인이 깨지는 잠복 버그 방지).
    db.flush()
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
