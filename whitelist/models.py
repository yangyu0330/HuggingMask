"""
Pydantic 스키마 — HuggingMask 인터페이스 정의서 v1.0 14·15장 정확 일치

참고 위치 (docs/HuggingMask_인터페이스정의서_v1_0_Notion.md):
- ModelRef:               7.1절 (275행)
- WhitelistCheckRequest:  14.1절 (859행)
- WhitelistCheckResponse: 14.2절 (896행)
- PendingApiRecord:       15.1절 (946행)
- PendingApiUpsertRequest:15.2절 (999행)
- 공통 enum:              5.1~5.8절 (151행)

이 파일의 필드명/타입은 인터페이스 문서와 글자 단위로 맞춘다.
analyzer/code validator가 보내는 페이로드를 그대로 받기 위해서다.
"""

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field


# ─────────────────────────────────────────────
# 공통 enum (인터페이스 정의서 5장)
# ─────────────────────────────────────────────

class WhitelistStatus(str, Enum):
    """WhitelistCheckResponse.status — 4-state (14.2절)"""
    ALLOWED = "ALLOWED"
    BLOCKED = "BLOCKED"
    UNKNOWN = "UNKNOWN"
    PENDING = "PENDING"


class WhitelistSource(str, Enum):
    """WhitelistCheckResponse.source — 규칙의 출처"""
    INITIAL = "INITIAL"
    AUTO_CRAWL = "AUTO_CRAWL"
    MANUAL_REVIEW = "MANUAL_REVIEW"
    NA = "N/A"  # status=UNKNOWN/PENDING일 때


class PendingClassification(str, Enum):
    """5.5절 — pending API 자동 분류 권고값"""
    AUTO_APPROVE = "AUTO_APPROVE"
    CONDITIONAL = "CONDITIONAL"
    MANUAL = "MANUAL"
    BLOCKED = "BLOCKED"


class ReviewStatus(str, Enum):
    """5.6절 — pending review 상태"""
    PENDING = "PENDING"
    UNDER_REVIEW = "UNDER_REVIEW"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    DEFERRED = "DEFERRED"


class ReviewDecision(str, Enum):
    """Security owner decision applied to a pending API candidate."""
    APPROVE = "approve"
    CONDITIONAL = "conditional"
    REJECT = "reject"
    DEFER = "defer"


class EndpointMode(str, Enum):
    """ModelRef.endpoint_mode"""
    HF_ENDPOINT_PROXY = "HF_ENDPOINT_PROXY"
    DIRECT = "DIRECT"


# ─────────────────────────────────────────────
# 7.1절 ModelRef
# ─────────────────────────────────────────────

class ModelRef(BaseModel):
    repo_id: str
    revision: str
    source_host: str
    source_url: str
    requested_by: str
    requested_at: str  # RFC3339 — 인터페이스에서 string으로 정의
    endpoint_mode: EndpointMode = EndpointMode.HF_ENDPOINT_PROXY


# ─────────────────────────────────────────────
# 14.1절 WhitelistCheckRequest
# ─────────────────────────────────────────────

class WhitelistCheckRequest(BaseModel):
    schema_version: str = "1.0"
    request_id: str
    job_id: str
    model: ModelRef
    apis: list[str]


# ─────────────────────────────────────────────
# 14.2절 WhitelistCheckResponse (단건)
# ─────────────────────────────────────────────

class WhitelistCheckResponse(BaseModel):
    api_path: str
    status: WhitelistStatus
    matched_rule: str | None = None
    source: WhitelistSource
    whitelist_version: str
    review_required: bool
    reason: str


# NOTE: 인터페이스 정의서 14.2는 응답이 배열(`WhitelistCheckResponse[]`)로 정의된다.
# request_id/job_id 추적은 응답 body가 아닌 audit log + 헤더로 처리한다.
# (양유상 PR #9 리뷰: 2026-04-21)


# ─────────────────────────────────────────────
# 15.1절 PendingApiRecord (15개 필드)
# ─────────────────────────────────────────────

class PendingApiRecord(BaseModel):
    api_path: str
    first_seen_at: datetime
    last_seen_at: datetime
    seen_count: int
    auto_classification: PendingClassification
    verified_org_count: int = 0
    verified_org_list: list[str] = Field(default_factory=list)
    in_official_docs: bool = False
    review_status: ReviewStatus = ReviewStatus.PENDING
    model_list: list[str] = Field(default_factory=list)
    risk_keywords: list[str] = Field(default_factory=list)
    matched_namespace_rule: str | None = None
    documentation_url: str | None = None
    sample_callsites: list[str] = Field(default_factory=list)
    created_from_job_id: str


# ─────────────────────────────────────────────
# 15.2절 PendingApiUpsertRequest
# ─────────────────────────────────────────────

class PendingApiUpsertRequest(BaseModel):
    schema_version: str = "1.0"
    request_id: str
    job_id: str
    record: PendingApiRecord


class ReviewDecisionRequest(BaseModel):
    """Canonical review decision request for pending API promotion."""
    api_path: str = Field(min_length=1)
    decision: ReviewDecision
    reviewer_id: str = Field(min_length=1)
    review_note: str = Field(min_length=1)
    review_id: str | None = None
    condition: str | None = None
    source_evidence: list[str] = Field(default_factory=list)


class ReviewDecisionResult(BaseModel):
    api_path: str
    decision: ReviewDecision
    applied: bool
    message: str
    review_id: str | None = None
    final_review_status: ReviewStatus | None = None
    audit_event_id: int | None = None
    audit_event_hash: str | None = None


# ─────────────────────────────────────────────
# 모듈 5 — 오탐 피드백 루프 (HuggingMask 스펙엔 없으나 자체 확장)
# ─────────────────────────────────────────────

class FeedbackReportRequest(BaseModel):
    """개발자 오탐 보고"""
    blocked_api: str
    model_id: str
    purpose: str
    reporter_id: str


class FeedbackReportResponse(BaseModel):
    report_id: str
    blocked_api: str
    auto_classification: PendingClassification
    in_official_docs: bool
    verified_org_count: int
    estimated_response_hours: int
    review_status: ReviewStatus
    auto_rejected: bool
    message: str
