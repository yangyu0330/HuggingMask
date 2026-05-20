"""
mod1 / mod2 캐시 → ``ApprovedApi`` / ``PendingApi`` 자동 반영 hook

mod1 결과는 영속(ApprovedApi 테이블)이라 DB 조회로 끝나지만,
mod2 결과는 "현재 미등록 API의 verified org 사용 현황"이라
JSON 캐시(``data/org_analysis_cache/latest_analysis.json``)를 메모리에 두고
``upsert_pending`` 호출 시 자동으로 채운다.

Public API:
    - ``get_org_cache()`` — 메모리 싱글턴 (지연 로드)
    - ``apply_crawl_results_to_db(classified, db, *, allow_classifications)``
        : mod1 결과 중 자동 등록 대상을 ``ApprovedApi(source=AUTO_CRAWL)``로 추가
    - ``is_in_official_docs(api_path, db)`` — DB의 AUTO_CRAWL/INITIAL 등록 여부
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from sqlalchemy import select
from sqlalchemy.orm import Session


logger = logging.getLogger(__name__)


DEFAULT_ORG_CACHE_PATH = Path("data/org_analysis_cache/latest_analysis.json")


# ─────────────────────────────────────────────
# Org 캐시 메모리 싱글턴
# ─────────────────────────────────────────────

@dataclass
class OrgCache:
    """``data/org_analysis_cache/latest_analysis.json``을 메모리에 둔다.

    캐시 파일이 없거나 깨졌으면 빈 캐시로 동작 (degrade gracefully).
    파일이 갱신되면 ``reload()`` 호출로 다시 읽는다.
    """

    cache_path: Path = field(default_factory=lambda: DEFAULT_ORG_CACHE_PATH)
    analyzed_at: datetime | None = None
    _by_api: dict[str, dict[str, Any]] = field(default_factory=dict)

    def reload(self) -> None:
        """디스크에서 캐시 다시 읽기."""
        self._by_api.clear()
        self.analyzed_at = None
        if not self.cache_path.exists():
            logger.info("Org 캐시 파일 없음: %s", self.cache_path)
            return
        try:
            data = json.loads(self.cache_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as e:
            logger.warning("Org 캐시 파싱 실패: %s — %s", self.cache_path, e)
            return

        analyzed_iso = data.get("analyzed_at")
        if analyzed_iso:
            try:
                self.analyzed_at = datetime.fromisoformat(analyzed_iso)
            except ValueError:
                pass

        for item in data.get("unregistered_apis", []):
            api_path = item.get("api_path")
            if not api_path:
                continue
            self._by_api[api_path] = {
                "used_by_orgs": list(item.get("used_by_orgs", [])),
                "used_by_models": list(item.get("used_by_models", [])),
                "total_count": int(item.get("total_count", 0)),
            }
        logger.info(
            "Org 캐시 로드: %d개 미등록 API (%s)",
            len(self._by_api),
            self.analyzed_at.isoformat() if self.analyzed_at else "no-timestamp",
        )

    def lookup_verified_org_count(self, api_path: str) -> int:
        entry = self._by_api.get(api_path)
        return len(entry["used_by_orgs"]) if entry else 0

    def lookup_org_list(self, api_path: str) -> list[str]:
        entry = self._by_api.get(api_path)
        return list(entry["used_by_orgs"]) if entry else []

    def lookup_models(self, api_path: str) -> list[str]:
        entry = self._by_api.get(api_path)
        return list(entry["used_by_models"]) if entry else []

    def __contains__(self, api_path: str) -> bool:
        return api_path in self._by_api

    def size(self) -> int:
        return len(self._by_api)


_cache: OrgCache | None = None


def get_org_cache(cache_path: Path | str | None = None) -> OrgCache:
    """메모리 싱글턴. 첫 호출 시 디스크에서 로드.

    경로를 명시적으로 바꾸려면 ``reset_org_cache(new_path)`` 후 호출.
    """
    global _cache
    if _cache is None:
        path = Path(cache_path) if cache_path else DEFAULT_ORG_CACHE_PATH
        _cache = OrgCache(cache_path=path)
        _cache.reload()
    return _cache


def reset_org_cache(cache_path: Path | str | None = None) -> OrgCache:
    """싱글턴 재설정 (테스트용 또는 캐시 파일 갱신 후)."""
    global _cache
    path = Path(cache_path) if cache_path else DEFAULT_ORG_CACHE_PATH
    _cache = OrgCache(cache_path=path)
    _cache.reload()
    return _cache


# ─────────────────────────────────────────────
# DB 조회 — 공식 문서 등록 여부
# ─────────────────────────────────────────────

def is_in_official_docs(db: Session, api_path: str) -> bool:
    """``ApprovedApi.source`` 가 INITIAL 또는 AUTO_CRAWL 인지 검사.

    수동 승인(MANUAL_REVIEW)은 "공식 문서 등록"으로 보지 않는다 — mod1 실제
    크롤 결과만 반영하기 위함 (상세설계 7.2절 in_official_docs 정의).
    """
    from whitelist.models import WhitelistSource
    from whitelist.tables import ApprovedApi

    row = db.execute(
        select(ApprovedApi).where(
            ApprovedApi.api_path == api_path,
            ApprovedApi.source.in_(
                [WhitelistSource.INITIAL, WhitelistSource.AUTO_CRAWL]
            ),
            ApprovedApi.is_blocked == False,  # noqa: E712
        )
    ).scalar_one_or_none()
    return row is not None


# ─────────────────────────────────────────────
# mod1 결과 → ApprovedApi 자동 등록
# ─────────────────────────────────────────────

# 자동 등록 대상 분류 (보수적 기본값: AUTO_APPROVE만)
DEFAULT_AUTO_REGISTER_CLASSIFICATIONS: tuple[str, ...] = ("AUTO_APPROVE",)


def apply_crawl_results_to_db(
    classified: dict[str, list[Any]],
    db: Session,
    *,
    allow_classifications: Iterable[str] = DEFAULT_AUTO_REGISTER_CLASSIFICATIONS,
    source_version: str | None = None,
    actor: str = "mod1-crawler",
    dry_run: bool = False,
) -> dict[str, int]:
    """mod1 ``classify_crawled_apis()`` 결과를 ApprovedApi에 자동 등록.

    Args:
        classified: mod1_doc_crawler.classify_crawled_apis() 반환값
            ({"AUTO_APPROVE": [ExtractedApi, ...], "CONDITIONAL": [...], ...})
        db: SQLAlchemy 세션
        allow_classifications: 자동 등록을 허용할 분류 목록.
            기본은 ("AUTO_APPROVE",) — CONDITIONAL/MANUAL/BLOCKED는 사람 게이트.
        source_version: ``ApprovedApi.source_version``. None이면 현재 WHITELIST_VERSION.
        actor: audit log actor.
        dry_run: True면 DB 변경 없이 카운트만 반환.

    Returns:
        {"added": N, "skipped": N, "blocked_by_perm": N}
    """
    from whitelist.audit import append_audit
    from whitelist.models import WhitelistSource
    from whitelist.rules import PERMANENTLY_BLOCKED_APIS, WHITELIST_VERSION
    from whitelist.tables import ApprovedApi

    allow_set = set(allow_classifications)
    src_version = source_version or WHITELIST_VERSION
    counts = {"added": 0, "skipped": 0, "blocked_by_perm": 0}

    for cls_name, items in classified.items():
        if cls_name not in allow_set:
            counts["skipped"] += len(items)
            continue
        for api in items:
            full_path = getattr(api, "full_path", None)
            namespace = getattr(api, "namespace", None) or (
                full_path.rsplit(".", 1)[0] if full_path and "." in full_path else full_path
            )
            if not full_path:
                continue
            # 영구 차단 목록은 절대 자동 등록하지 않음 (방어적 — 분류기가 이미 BLOCKED로 분류했어야 함)
            if full_path in PERMANENTLY_BLOCKED_APIS:
                counts["blocked_by_perm"] += 1
                continue
            existing = db.execute(
                select(ApprovedApi).where(ApprovedApi.api_path == full_path)
            ).scalar_one_or_none()
            if existing is not None:
                counts["skipped"] += 1
                continue
            if dry_run:
                counts["added"] += 1
                continue

            db.add(ApprovedApi(
                api_path=full_path,
                namespace=namespace,
                source=WhitelistSource.AUTO_CRAWL,
                matched_rule=(namespace + ".*") if namespace else None,
                source_version=src_version,
                is_blocked=False,
            ))
            append_audit(
                db,
                action="crawl_auto_approved",
                api_path=full_path,
                actor=actor,
                detail=f"classification={cls_name}, source_version={src_version}",
            )
            counts["added"] += 1

    if not dry_run:
        db.flush()
    logger.info(
        "mod1 자동 등록: added=%d, skipped=%d, blocked_by_perm=%d (dry_run=%s)",
        counts["added"], counts["skipped"], counts["blocked_by_perm"], dry_run,
    )
    return counts


__all__ = [
    "OrgCache", "get_org_cache", "reset_org_cache",
    "is_in_official_docs", "apply_crawl_results_to_db",
    "DEFAULT_AUTO_REGISTER_CLASSIFICATIONS", "DEFAULT_ORG_CACHE_PATH",
]
