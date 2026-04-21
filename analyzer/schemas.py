"""Minimal schema helpers for early code-validation tests.

This module intentionally does not replace the final Analyzer Core schema
ownership. It only fixes the shared dataclass/enum contract needed by the
current code-validation implementation stages.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field, is_dataclass
from enum import Enum
from typing import Any

SCHEMA_VERSION = "1.0"


class StringEnum(str, Enum):
    """Enum that serializes to the interface document's string value."""

    def __str__(self) -> str:
        return self.value


class FileKind(StringEnum):
    SAFETENSORS = "SAFETENSORS"
    PICKLE = "PICKLE"
    PYTHON = "PYTHON"
    CONFIG_JSON = "CONFIG_JSON"
    TOKENIZER_CONFIG_JSON = "TOKENIZER_CONFIG_JSON"
    OTHER = "OTHER"


class ValidationStatus(StringEnum):
    PASS = "PASS"
    BLOCK = "BLOCK"
    PENDING_REVIEW = "PENDING_REVIEW"
    ERROR = "ERROR"
    SKIPPED = "SKIPPED"


class ReviewAction(StringEnum):
    NONE = "NONE"
    AUTO_APPROVE = "AUTO_APPROVE"
    AUTO_APPROVE_REGENERATED = "AUTO_APPROVE_REGENERATED"
    SECURITY_OWNER_GATE = "SECURITY_OWNER_GATE"
    MANUAL_REVIEW_REQUIRED = "MANUAL_REVIEW_REQUIRED"
    BLOCK_IMMEDIATELY = "BLOCK_IMMEDIATELY"
    AUTO_LOG_REVIEW = "AUTO_LOG_REVIEW"


class CodeGrade(StringEnum):
    A = "A"
    B1 = "B-1"
    B2 = "B-2"
    C = "C"
    NA = "N/A"


class RouteKind(StringEnum):
    SAFETENSORS_FAST_PATH = "SAFETENSORS_FAST_PATH"
    PICKLE_PATH_A = "PICKLE_PATH_A"
    PICKLE_PATH_B = "PICKLE_PATH_B"
    CODE_AST_SCAN = "CODE_AST_SCAN"
    CODE_RESTRICTED_RUNTIME = "CODE_RESTRICTED_RUNTIME"
    CODE_SANDBOX_RUNTIME = "CODE_SANDBOX_RUNTIME"
    CONFIG_SCHEMA_VALIDATION = "CONFIG_SCHEMA_VALIDATION"


class OverallDecision(StringEnum):
    APPROVE = "APPROVE"
    APPROVE_WITH_TRANSFORM = "APPROVE_WITH_TRANSFORM"
    DENY = "DENY"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    ERROR = "ERROR"


class Serializable:
    def to_dict(self) -> dict[str, Any]:
        return to_jsonable(self)


def to_jsonable(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value):
        return {key: to_jsonable(item) for key, item in asdict(value).items()}
    if isinstance(value, list):
        return [to_jsonable(item) for item in value]
    if isinstance(value, tuple):
        return [to_jsonable(item) for item in value]
    if isinstance(value, dict):
        return {key: to_jsonable(item) for key, item in value.items()}
    return value


def build_policy_fingerprint(
    policy_version: str,
    whitelist_version: str,
    opcode_policy_version: str,
    config_schema_version: str,
    runtime_profile_version: str,
) -> str:
    return "|".join(
        [
            policy_version,
            whitelist_version,
            opcode_policy_version,
            config_schema_version,
            runtime_profile_version,
        ]
    )


@dataclass
class ModelRef(Serializable):
    repo_id: str
    revision: str
    source_host: str
    source_url: str
    requested_at: str
    endpoint_mode: str
    requested_by: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ModelRef":
        return cls(**data)


@dataclass
class PolicyInfo(Serializable):
    policy_version: str
    whitelist_version: str
    opcode_policy_version: str
    config_schema_version: str
    runtime_profile_version: str
    policy_fingerprint: str | None = None

    def __post_init__(self) -> None:
        if self.policy_fingerprint is None:
            self.policy_fingerprint = build_policy_fingerprint(
                self.policy_version,
                self.whitelist_version,
                self.opcode_policy_version,
                self.config_schema_version,
                self.runtime_profile_version,
            )

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "PolicyInfo":
        return cls(**data)


@dataclass
class RuntimeContext(Serializable):
    sandbox_runtime: str
    network_disabled: bool
    read_only_fs: bool
    compare_mode: str
    allow_cache_lookup: bool
    generate_mlbom: bool
    write_audit_log: bool

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RuntimeContext":
        return cls(**data)


@dataclass
class ArtifactRef(Serializable):
    artifact_id: str
    repo_path: str
    file_name: str
    file_kind: FileKind
    detected_extension: str
    media_type: str | None
    size_bytes: int
    sha256: str
    source_url: str
    temp_local_path: str
    referenced_by: list[str] = field(default_factory=list)
    is_generated: bool = False

    def __post_init__(self) -> None:
        self.file_kind = FileKind(self.file_kind)
        expected_artifact_id = f"sha256:{self.sha256}"
        if self.artifact_id != expected_artifact_id:
            raise ValueError("artifact_id must be 'sha256:' plus sha256")
        if len(self.sha256) != 64 or any(ch not in "0123456789abcdef" for ch in self.sha256):
            raise ValueError("sha256 must be a 64-character lowercase hex digest")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ArtifactRef":
        payload = dict(data)
        payload["file_kind"] = FileKind(payload["file_kind"])
        return cls(**payload)


@dataclass
class ReasonEntry(Serializable):
    code: str
    severity: str
    message: str
    evidence: list[str]
    review_required: bool

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ReasonEntry":
        return cls(**data)


@dataclass
class ArtifactValidationResult(Serializable):
    artifact: ArtifactRef
    route_kind: RouteKind
    status: ValidationStatus
    grade: CodeGrade
    review_action: ReviewAction
    cache_key: str
    cache_hit: bool
    reason_entries: list[ReasonEntry]
    details: dict[str, Any]
    started_at: str
    finished_at: str

    def __post_init__(self) -> None:
        if isinstance(self.artifact, dict):
            self.artifact = ArtifactRef.from_dict(self.artifact)
        self.route_kind = RouteKind(self.route_kind)
        self.status = ValidationStatus(self.status)
        self.grade = CodeGrade(self.grade)
        self.review_action = ReviewAction(self.review_action)
        self.reason_entries = [
            entry if isinstance(entry, ReasonEntry) else ReasonEntry.from_dict(entry)
            for entry in self.reason_entries
        ]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ArtifactValidationResult":
        return cls(**data)


@dataclass
class ValidationJobRequest(Serializable):
    request_id: str
    job_id: str
    model: ModelRef
    policy: PolicyInfo
    runtime_context: RuntimeContext
    artifacts: list[ArtifactRef]
    requested_routes: list[RouteKind]
    stop_on_first_block: bool
    schema_version: str = SCHEMA_VERSION
    notes: str | None = None

    def __post_init__(self) -> None:
        if isinstance(self.model, dict):
            self.model = ModelRef.from_dict(self.model)
        if isinstance(self.policy, dict):
            self.policy = PolicyInfo.from_dict(self.policy)
        if isinstance(self.runtime_context, dict):
            self.runtime_context = RuntimeContext.from_dict(self.runtime_context)
        self.artifacts = [
            artifact if isinstance(artifact, ArtifactRef) else ArtifactRef.from_dict(artifact)
            for artifact in self.artifacts
        ]
        self.requested_routes = [RouteKind(route) for route in self.requested_routes]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ValidationJobRequest":
        return cls(**data)


@dataclass
class ValidationJobResponse(Serializable):
    request_id: str
    job_id: str
    overall_decision: OverallDecision
    overall_status: ValidationStatus
    release_action: str
    artifact_results: list[ArtifactValidationResult]
    approved_artifact_ids: list[str]
    blocked_artifact_ids: list[str]
    pending_artifact_ids: list[str]
    generated_artifacts: list[ArtifactRef]
    report_id: str
    report_path: str
    reason_entries: list[ReasonEntry]
    created_at: str
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        self.overall_decision = OverallDecision(self.overall_decision)
        self.overall_status = ValidationStatus(self.overall_status)
        self.artifact_results = [
            result
            if isinstance(result, ArtifactValidationResult)
            else ArtifactValidationResult.from_dict(result)
            for result in self.artifact_results
        ]
        self.generated_artifacts = [
            artifact if isinstance(artifact, ArtifactRef) else ArtifactRef.from_dict(artifact)
            for artifact in self.generated_artifacts
        ]
        self.reason_entries = [
            entry if isinstance(entry, ReasonEntry) else ReasonEntry.from_dict(entry)
            for entry in self.reason_entries
        ]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ValidationJobResponse":
        return cls(**data)

