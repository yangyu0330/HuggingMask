"""
화이트리스트 엔진 — API 경로 → 4-state 판정

판정 우선순위 (whitelist/engine.md:21):
  1. 명시적 BLOCKED (PERMANENTLY_BLOCKED_APIS / DB의 is_blocked=True)
  2. ALLOWED (DB의 ApprovedApi)
  3. 분류기 매칭 → PENDING (자동 분류 권고와 함께 pending_store 등록)
  4. 매칭 안 됨 → UNKNOWN

핵심: 코드 등급(A/B-1/B-2/C)은 결정하지 않는다 (양유상 책임).
이 엔진은 단지 per-API status만 반환한다.
"""

import logging
import re
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from whitelist.audit import append_audit
from whitelist.models import (
    ModelRef, PendingClassification,
    WhitelistCheckRequest, WhitelistCheckResponse,
    WhitelistSource, WhitelistStatus,
)
from whitelist.pending_store import upsert_pending
from whitelist.rules import (
    DANGER_KEYWORDS, DANGER_KEYWORDS_EXEC, DANGER_KEYWORDS_IO,
    NAMESPACE_RULES, PERMANENTLY_BLOCKED_APIS,
    WHITELIST_VERSION, documentation_url_for,
)
from whitelist.tables import ApprovedApi


logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────
# 분류기 (어떤 분류 권고를 줄지 결정하는 결정론 규칙)
# ─────────────────────────────────────────────

class _Classifier:
    """네임스페이스 longest-prefix + 위험 키워드 격상.

    이 분류 결과는 PendingApiRecord.auto_classification 권고값이 된다.
    실제 ALLOWED/BLOCKED 응답에는 영향을 주지 않는다 (게이트는 사람).
    """

    def __init__(self) -> None:
        self._sorted_rules = sorted(
            NAMESPACE_RULES.items(),
            key=lambda x: len(x[0]), reverse=True,
        )

    def match_namespace(
        self, api_path: str,
    ) -> tuple[PendingClassification, str | None]:
        """longest-prefix match. 매칭 안 되면 (MANUAL, None)"""
        for prefix, classification in self._sorted_rules:
            if api_path.startswith(prefix) or api_path == prefix.rstrip("."):
                return classification, prefix.rstrip(".") + ".*"
        return PendingClassification.MANUAL, None

    def find_risk_keywords(self, api_path: str) -> list[str]:
        """함수명에서 위험 키워드 토큰 탐지"""
        func_name = api_path.rsplit(".", 1)[-1] if "." in api_path else api_path
        tokens = set(func_name.lower().split("_"))
        camel = set(
            t.lower() for t in re.findall(r"[A-Z]?[a-z]+|[A-Z]+(?=[A-Z]|$)", func_name)
        )
        all_tokens = tokens | camel
        found = []
        for kw in DANGER_KEYWORDS:
            if kw in all_tokens or kw in func_name.lower():
                found.append(kw)
        return sorted(set(found))

    def escalate(
        self, base: PendingClassification, danger: list[str],
    ) -> PendingClassification:
        """위험 키워드 기반 격상.
        AUTO_APPROVE + I/O → MANUAL
        AUTO_APPROVE/CONDITIONAL + EXEC → MANUAL
        """
        if base == PendingClassification.BLOCKED or not danger:
            return base
        has_exec = bool(set(danger) & DANGER_KEYWORDS_EXEC)
        has_io = bool(set(danger) & DANGER_KEYWORDS_IO)
        if has_exec and base in (
            PendingClassification.AUTO_APPROVE, PendingClassification.CONDITIONAL,
        ):
            return PendingClassification.MANUAL
        if has_io and base == PendingClassification.AUTO_APPROVE:
            return PendingClassification.MANUAL
        return base


# ─────────────────────────────────────────────
# 메인 엔진
# ─────────────────────────────────────────────

class WhitelistEngine:
    """4-state 판정 + 자동 pending 등록"""

    def __init__(self, version: str = WHITELIST_VERSION) -> None:
        self._version = version
        self._classifier = _Classifier()

    @property
    def version(self) -> str:
        return self._version

    def check_batch(
        self,
        request: WhitelistCheckRequest,
        db: Session,
    ) -> list[WhitelistCheckResponse]:
        """API 목록을 일괄 판정하고 응답 배열 반환.

        인터페이스 정의서 14.2 — 응답은 wrapper 없이 배열.
        request_id/job_id 추적은 audit log에 남는다.

        side effect: UNKNOWN/PENDING 분류 결과는 자동으로 pending_store에 upsert된다.
        """
        results: list[WhitelistCheckResponse] = []
        for api_path in request.apis:
            results.append(self.check_single(
                api_path=api_path.strip(),
                db=db,
                job_id=request.job_id,
                model=request.model,
            ))
        db.commit()
        return results

    def check_single(
        self,
        api_path: str,
        db: Session,
        job_id: str,
        model: ModelRef | None = None,
    ) -> WhitelistCheckResponse:
        """단일 API 판정 — 우선순위에 따라 4-state 결정"""
        if not api_path:
            return self._make_response(
                api_path="", status=WhitelistStatus.UNKNOWN,
                source=WhitelistSource.NA, review_required=True,
                reason="빈 API 경로",
            )

        # ── 1순위: 명시적 BLOCKED (영구 차단 목록) ──
        if api_path in PERMANENTLY_BLOCKED_APIS:
            return self._make_response(
                api_path=api_path,
                status=WhitelistStatus.BLOCKED,
                matched_rule=None,
                source=WhitelistSource.INITIAL,
                review_required=False,
                reason="명시적 위험 API",
            )

        # ── 1순위: DB의 is_blocked=True (수동 거부 결과) ──
        approved = db.execute(
            select(ApprovedApi).where(ApprovedApi.api_path == api_path)
        ).scalar_one_or_none()
        if approved and approved.is_blocked:
            return self._make_response(
                api_path=api_path,
                status=WhitelistStatus.BLOCKED,
                matched_rule=approved.matched_rule,
                source=WhitelistSource(approved.source),
                review_required=False,
                reason="수동 리뷰 결과 거부",
            )

        # ── 2순위: ALLOWED (DB 등록) ──
        if approved and not approved.is_blocked:
            return self._make_response(
                api_path=api_path,
                status=WhitelistStatus.ALLOWED,
                matched_rule=approved.matched_rule or approved.namespace + ".*",
                source=WhitelistSource(approved.source),
                review_required=False,
                reason="화이트리스트 허용 규칙 일치",
            )

        # ── 3·4순위: 미등록 — 분류 후 PENDING 또는 UNKNOWN ──
        base_classification, matched_rule = self._classifier.match_namespace(api_path)
        risk_keywords = self._classifier.find_risk_keywords(api_path)
        final_classification = self._classifier.escalate(base_classification, risk_keywords)

        # 미등록이지만 namespace 매칭됐다 → PENDING (분류 권고 있음)
        if matched_rule is not None:
            upsert_pending(
                db,
                api_path=api_path,
                auto_classification=final_classification,
                job_id=job_id,
                model_repo_id=model.repo_id if model else "",
                risk_keywords=risk_keywords,
                matched_namespace_rule=matched_rule,
                documentation_url=documentation_url_for(api_path),
            )
            reason = f"미등록 API — 분류 권고={final_classification.value}"
            if risk_keywords:
                reason += f" (위험 키워드: {', '.join(risk_keywords)})"
            return self._make_response(
                api_path=api_path,
                status=WhitelistStatus.PENDING,
                matched_rule=matched_rule,
                source=WhitelistSource.NA,
                review_required=True,
                reason=reason,
            )

        # namespace 매칭도 안 됨 → UNKNOWN
        # 그래도 pending에 등록은 한다 (보안 담당자가 봐야 하므로)
        upsert_pending(
            db,
            api_path=api_path,
            auto_classification=PendingClassification.MANUAL,
            job_id=job_id,
            model_repo_id=model.repo_id if model else "",
            risk_keywords=risk_keywords,
            matched_namespace_rule=None,
            documentation_url=None,
        )
        return self._make_response(
            api_path=api_path,
            status=WhitelistStatus.UNKNOWN,
            matched_rule=None,
            source=WhitelistSource.NA,
            review_required=True,
            reason="미등록 API (네임스페이스 매칭 없음)",
        )

    def _make_response(
        self,
        api_path: str,
        status: WhitelistStatus,
        source: WhitelistSource,
        review_required: bool,
        reason: str,
        matched_rule: str | None = None,
    ) -> WhitelistCheckResponse:
        return WhitelistCheckResponse(
            api_path=api_path,
            status=status,
            matched_rule=matched_rule,
            source=source,
            whitelist_version=self._version,
            review_required=review_required,
            reason=reason,
        )


# ─────────────────────────────────────────────
# 싱글턴
# ─────────────────────────────────────────────

_engine: WhitelistEngine | None = None


def get_engine() -> WhitelistEngine:
    global _engine
    if _engine is None:
        _engine = WhitelistEngine()
    return _engine


# ─────────────────────────────────────────────
# 보안 담당자 리뷰 판정 적용 (모듈 4)
# ─────────────────────────────────────────────

def apply_review_decision(
    db: Session,
    api_path: str,
    decision: str,  # "approve" | "reject" | "defer" | "conditional"
    reviewer_id: str,
    review_note: str = "",
    condition: str | None = None,
) -> bool:
    """Pending API에 대한 보안 담당자 판정을 DB에 반영.

    - approve / conditional: ApprovedApi에 등록 (is_blocked=False)
    - reject: ApprovedApi에 등록 (is_blocked=True)
    - defer: review_status를 PENDING으로 유지

    Returns: 적용 성공 여부 (해당 pending 없으면 False)
    """
    from whitelist.pending_store import get_pending
    from whitelist.tables import ApprovedApi

    pending = get_pending(db, api_path)
    if not pending:
        return False

    namespace = api_path.rsplit(".", 1)[0] if "." in api_path else api_path
    matched = pending.matched_namespace_rule

    if decision in ("approve", "conditional"):
        note = review_note
        if decision == "conditional":
            note = f"[조건부] {condition or ''} — {review_note}".strip(" —")
        db.merge(ApprovedApi(
            api_path=api_path,
            namespace=namespace,
            source=WhitelistSource.MANUAL_REVIEW,
            matched_rule=matched,
            source_version=WHITELIST_VERSION,
            reviewer_id=reviewer_id,
            review_note=note,
            is_blocked=False,
        ))
        from whitelist.models import ReviewStatus as RS
        pending.review_status = RS.APPROVED

    elif decision == "reject":
        db.merge(ApprovedApi(
            api_path=api_path,
            namespace=namespace,
            source=WhitelistSource.MANUAL_REVIEW,
            matched_rule=matched,
            source_version=WHITELIST_VERSION,
            reviewer_id=reviewer_id,
            review_note=review_note,
            is_blocked=True,
        ))
        from whitelist.models import ReviewStatus as RS
        pending.review_status = RS.REJECTED

    elif decision == "defer":
        from whitelist.models import ReviewStatus as RS
        pending.review_status = RS.DEFERRED

    else:
        return False

    append_audit(
        db, action=f"review_{decision}", api_path=api_path,
        actor=reviewer_id, detail=review_note,
    )
    db.flush()
    return True
