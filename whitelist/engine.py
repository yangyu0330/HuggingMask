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

import json
import logging
import re
import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from whitelist.audit import append_audit
from whitelist.models import (
    ModelRef, PendingClassification, ReviewDecision, ReviewDecisionResult,
    ReviewStatus,
    WhitelistCheckRequest, WhitelistCheckResponse,
    WhitelistSource, WhitelistStatus,
)
from whitelist.pending_store import upsert_pending
from whitelist.rules import (
    BENIGN_LEAF_NAMES, DANGER_KEYWORDS, DANGER_KEYWORDS_EXEC, DANGER_KEYWORDS_IO,
    LIBRARY_ROOTS, NAMESPACE_RULES, PERMANENTLY_BLOCKED_APIS,
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
        """longest-prefix match. 매칭 안 되면 라이브러리 루트 여부로 분기."""
        for prefix, classification in self._sorted_rules:
            if api_path.startswith(prefix) or api_path == prefix.rstrip("."):
                return classification, prefix.rstrip(".") + ".*"
        # 루트가 제어 대상 라이브러리가 아니고(로컬 변수/빌트인) 리프가 명시적 양성
        # 빌트인·데이터 연산이면 화이트리스트 제어 대상 외부 API 가 아님 → 자동 승인 권고.
        # 미지 라이브러리(`my_lib.UnknownClass`)·모호 메서드(`conn.send`)는 MANUAL 유지.
        # 위험 키워드는 escalate()에서 한 번 더 MANUAL 로 격상된다(이중 안전).
        root = api_path.split(".", 1)[0]
        leaf = api_path.rsplit(".", 1)[-1]
        if root not in LIBRARY_ROOTS and leaf in BENIGN_LEAF_NAMES:
            return PendingClassification.AUTO_APPROVE, "builtin/local-data-op"
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
    review_id: str | None = None,
    source_evidence: list[str] | None = None,
) -> ReviewDecisionResult:
    """Apply a security-owner decision to a pending API candidate."""
    from whitelist.pending_store import get_pending
    from whitelist.tables import ApprovedApi, ReviewDecisionLog

    try:
        parsed_decision = ReviewDecision(decision)
    except ValueError:
        return ReviewDecisionResult(
            api_path=api_path,
            decision=ReviewDecision.DEFER,
            applied=False,
            message=f"unsupported review decision: {decision}",
        )

    reviewer_id = reviewer_id.strip()
    review_note = review_note.strip()
    requested_evidence = list(source_evidence or [])
    if not reviewer_id or not review_note:
        return ReviewDecisionResult(
            api_path=api_path,
            decision=parsed_decision,
            applied=False,
            message="reviewer_id and review_note are required",
        )

    resolved_review_id = (review_id or f"rev-{uuid.uuid4()}").strip()
    existing_decision = db.get(ReviewDecisionLog, resolved_review_id)
    if existing_decision is not None:
        if (
            existing_decision.api_path == api_path
            and existing_decision.decision == parsed_decision.value
            and existing_decision.reviewer_id == reviewer_id
            and existing_decision.review_note == review_note
            and existing_decision.condition == condition
            and list(existing_decision.source_evidence or []) == requested_evidence
        ):
            return ReviewDecisionResult(
                api_path=api_path,
                decision=parsed_decision,
                applied=True,
                message="review decision already applied",
                review_id=resolved_review_id,
                final_review_status=ReviewStatus(existing_decision.final_review_status),
                audit_event_id=existing_decision.audit_log_id,
                audit_event_hash=existing_decision.audit_entry_hash,
            )
        return ReviewDecisionResult(
            api_path=api_path,
            decision=parsed_decision,
            applied=False,
            message="review_id already exists for a different review payload",
            review_id=resolved_review_id,
        )

    pending = get_pending(db, api_path)
    if not pending:
        return ReviewDecisionResult(
            api_path=api_path,
            decision=parsed_decision,
            applied=False,
            message="pending API not found",
            review_id=resolved_review_id,
        )

    current_status = ReviewStatus(pending.review_status)
    if current_status is not ReviewStatus.PENDING:
        return ReviewDecisionResult(
            api_path=api_path,
            decision=parsed_decision,
            applied=False,
            message=f"pending API is already {current_status.value}",
            review_id=resolved_review_id,
            final_review_status=current_status,
        )

    namespace = api_path.rsplit(".", 1)[0] if "." in api_path else api_path
    matched = pending.matched_namespace_rule
    evidence = list(requested_evidence)
    evidence.extend([
        f"created_from_job_id={pending.created_from_job_id}",
        f"auto_classification={pending.auto_classification}",
        f"matched_namespace_rule={matched or ''}",
    ])
    if pending.documentation_url:
        evidence.append(f"documentation_url={pending.documentation_url}")
    if pending.model_list:
        evidence.append("model_list=" + ",".join(pending.model_list))

    if parsed_decision in (ReviewDecision.APPROVE, ReviewDecision.CONDITIONAL):
        note = review_note
        if parsed_decision is ReviewDecision.CONDITIONAL:
            note = f"[conditional] {condition or ''} - {review_note}".strip(" -")
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
        final_status = ReviewStatus.APPROVED
        pending.review_status = final_status

    elif parsed_decision is ReviewDecision.REJECT:
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
        final_status = ReviewStatus.REJECTED
        pending.review_status = final_status

    elif parsed_decision is ReviewDecision.DEFER:
        final_status = ReviewStatus.DEFERRED
        pending.review_status = final_status

    else:
        return ReviewDecisionResult(
            api_path=api_path,
            decision=parsed_decision,
            applied=False,
            message=f"unsupported review decision: {decision}",
            review_id=resolved_review_id,
        )

    detail = json.dumps(
        {
            "review_id": resolved_review_id,
            "decision": parsed_decision.value,
            "final_review_status": final_status.value,
            "reviewer_id": reviewer_id,
            "review_note": review_note,
            "condition": condition,
            "source_evidence": evidence,
        },
        ensure_ascii=False,
        sort_keys=True,
    )

    audit_log = append_audit(
        db, action=f"review_{parsed_decision.value}", api_path=api_path,
        actor=reviewer_id, detail=detail,
    )
    db.flush()
    db.add(ReviewDecisionLog(
        review_id=resolved_review_id,
        api_path=api_path,
        decision=parsed_decision.value,
        reviewer_id=reviewer_id,
        review_note=review_note,
        condition=condition,
        source_evidence=requested_evidence,
        final_review_status=final_status,
        audit_log_id=audit_log.id,
        audit_entry_hash=audit_log.entry_hash,
    ))
    db.flush()
    return ReviewDecisionResult(
        api_path=api_path,
        decision=parsed_decision,
        applied=True,
        message=f"review decision applied: {parsed_decision.value}",
        review_id=resolved_review_id,
        final_review_status=final_status,
        audit_event_id=audit_log.id,
        audit_event_hash=audit_log.entry_hash,
    )
