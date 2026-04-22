"""앱 시작 시 시드 로드 — 초기 145개 API를 ApprovedApi에 등록"""

import logging

from sqlalchemy import select

from whitelist.audit import append_audit
from whitelist.database import SessionLocal, init_db
from whitelist.models import WhitelistSource
from whitelist.rules import WHITELIST_VERSION
from whitelist.seed import get_seed_with_namespaces
from whitelist.tables import ApprovedApi


logger = logging.getLogger(__name__)


def load_seed_if_empty() -> int:
    """ApprovedApi 테이블이 비어있을 때만 시드 로드. 추가된 개수 반환."""
    db = SessionLocal()
    try:
        existing = db.execute(select(ApprovedApi).limit(1)).scalar_one_or_none()
        if existing is not None:
            logger.info("시드 로드 스킵 — 기존 데이터 존재")
            return 0

        added = 0
        for api_path, namespace in get_seed_with_namespaces():
            db.add(ApprovedApi(
                api_path=api_path,
                namespace=namespace,
                source=WhitelistSource.INITIAL,
                matched_rule=namespace + ".*",
                source_version=WHITELIST_VERSION,
                is_blocked=False,
            ))
            added += 1

        append_audit(
            db, action="seed_loaded", api_path="*",
            actor="system", detail=f"version={WHITELIST_VERSION}, count={added}",
        )
        db.commit()
        logger.info("시드 로드 완료: %d개 API 추가", added)
        return added
    finally:
        db.close()


def init_whitelist() -> None:
    """앱 시작 훅 — 테이블 생성 + 시드 로드"""
    init_db()
    load_seed_if_empty()
