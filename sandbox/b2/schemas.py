"""Dataclasses for B-2 sandbox input manifests.

The manifest is host-side evidence that fixes the exact set of verified files
allowed into a future gVisor run. It is not a runner contract for executing
Docker/runsc.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from analyzer.schemas import Serializable, StringEnum, to_jsonable

B2_MANIFEST_SCHEMA_VERSION = "1.0"
B2_SCHEMA_VERSION = "1.0"
B2_INPUT_MANIFEST_FILENAME = "b2_input_manifest.json"
B2_DEFAULT_IMPORT_ROOT = "/sandbox/input"


class B2Decision(StringEnum):
    NOT_RUN = "NOT_RUN"
    SANDBOX_INFRA_ERROR = "SANDBOX_INFRA_ERROR"
    BLOCKED_RUNTIME_INVALID = "BLOCKED_RUNTIME_INVALID"
    BLOCKED_SECURITY_EVENT = "BLOCKED_SECURITY_EVENT"
    FUNCTIONAL_REVIEW_REQUIRED = "FUNCTIONAL_REVIEW_REQUIRED"
    FORWARD_SKIPPED_REVIEW = "FORWARD_SKIPPED_REVIEW"
    HIGH_RISK_REVIEW = "HIGH_RISK_REVIEW"
    B2_SANDBOX_OBSERVED_CLEAN = "B2_SANDBOX_OBSERVED_CLEAN"
    B2_POLICY_REVIEW_REQUIRED = "B2_POLICY_REVIEW_REQUIRED"
    LOG_INCOMPLETE = "LOG_INCOMPLETE"
    ERROR = "ERROR"


class RunnerDiagnosticsStatus(StringEnum):
    PRESENT_VALID = "present_valid"
    MISSING = "missing"
    MALFORMED = "malformed"
    NONCE_MISMATCH = "nonce_mismatch"


class B2ManifestContentKind(StringEnum):
    PYTHON = "PYTHON"
    JSON_SUPPORT = "JSON_SUPPORT"
    TEXT_SUPPORT = "TEXT_SUPPORT"


class B2ManifestErrorCode(StringEnum):
    MISSING_SOURCE = "MISSING_SOURCE"
    HASH_MISMATCH = "HASH_MISMATCH"
    SIZE_MISMATCH = "SIZE_MISMATCH"
    PATH_ESCAPE = "PATH_ESCAPE"
    UNTRUSTED_LOCAL_PATH = "UNTRUSTED_LOCAL_PATH"
    INVALID_REPO_PATH = "INVALID_REPO_PATH"
    UNRESOLVED_DEPENDENCY = "UNRESOLVED_DEPENDENCY"
    DEPENDENCY_NOT_VALIDATED = "DEPENDENCY_NOT_VALIDATED"
    DEPENDENCY_STATIC_RISK = "DEPENDENCY_STATIC_RISK"
    DUPLICATE_PATH = "DUPLICATE_PATH"


@dataclass(frozen=True)
class B2Target(Serializable):
    source: str
    target_module: str
    target_class: str | None = None
    auto_map_key: str | None = None
    primary_repo_path: str = ""
    import_root: str = B2_DEFAULT_IMPORT_ROOT


@dataclass
class B2ManifestFile(Serializable):
    path: str
    sha256: str
    size_bytes: int
    role: str
    ast_grade: str
    content_kind: str = B2ManifestContentKind.PYTHON.value
    import_allowed: bool = False
    target_allowed: bool = False
    is_primary: bool = False
    validation_status: str | None = None
    unknown_apis: list[str] = field(default_factory=list)
    risk_flags: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.content_kind = B2ManifestContentKind(self.content_kind).value


@dataclass
class B2InputManifest(Serializable):
    schema_version: str
    request_id: str
    job_id: str
    primary_artifact_id: str
    primary_repo_path: str
    revision: str
    policy_version: str
    grade: str
    target: B2Target
    manifest_sha256: str
    files: list[B2ManifestFile]

    def __post_init__(self) -> None:
        if isinstance(self.target, dict):
            self.target = B2Target(**self.target)
        self.files = [item if isinstance(item, B2ManifestFile) else B2ManifestFile(**item) for item in self.files]

    def to_dict(self) -> dict[str, Any]:
        return to_jsonable(self)


@dataclass(frozen=True)
class B2RuntimePolicy(Serializable):
    require_runsc_strace: bool = True
    log_incomplete_action: str = "review"


@dataclass
class RuntimeEvidence(Serializable):
    runtime: str | None = None
    image_ref: str | None = None
    network_mode: str | None = None
    rootfs_readonly: bool | None = None
    cap_drop_all: bool | None = None
    no_new_privileges: bool | None = None
    non_root_user: bool | None = None
    pids_limit: int | None = None
    memory_limit: str | int | None = None
    cpu_limit: str | int | None = None
    env_allowlist_ok: bool | None = None
    mounts_ok: bool | None = None


@dataclass
class ExecutionEvidence(Serializable):
    manifest_verified: bool | None = None
    import_status: str = "not_run"
    instantiate_status: str = "not_run"
    forward_status: str = "not_run"
    exit_code: int | None = None
    timeout: bool = False
    oom_killed: bool = False
    pids_limit_hit: bool = False


@dataclass
class SecurityEvents(Serializable):
    network_events: list[dict[str, Any]] = field(default_factory=list)
    unexpected_execve: list[dict[str, Any]] = field(default_factory=list)
    blocked_writes: list[dict[str, Any]] = field(default_factory=list)
    secret_path_access: list[dict[str, Any]] = field(default_factory=list)
    blocked_reads: list[dict[str, Any]] = field(default_factory=list)
    review_events: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class ManifestEvidence(Serializable):
    host_manifest_sha256: str | None = None
    manifest_errors: list[str] = field(default_factory=list)
    input_hash_errors: list[str] = field(default_factory=list)


@dataclass
class B2RunnerResult(Serializable):
    schema_version: str = B2_SCHEMA_VERSION
    request_id: str = ""
    nonce: str = ""
    manifest_verified: bool = False
    import_status: str = "skipped"
    instantiate_status: str = "skipped"
    forward_status: str = "skipped"
    exception_class: str | None = None
    exception_message: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "B2RunnerResult":
        return cls(**data)


@dataclass
class B2SandboxCheck(Serializable):
    schema_version: str
    request_id: str | None
    job_id: str | None
    artifact_id: str
    repo_path: str
    grade: str
    sandbox_runtime: str | None
    profile: str
    decision: B2Decision
    deployable: bool
    runtime_evidence: RuntimeEvidence
    execution: ExecutionEvidence
    security_events: SecurityEvents
    manifest_evidence: ManifestEvidence
    artifacts: dict[str, str]
    policy_gate: dict[str, Any]
    created_at: str
    reason: str | None = None

    def __post_init__(self) -> None:
        self.decision = B2Decision(self.decision)
        if isinstance(self.runtime_evidence, dict):
            self.runtime_evidence = RuntimeEvidence(**self.runtime_evidence)
        if isinstance(self.execution, dict):
            self.execution = ExecutionEvidence(**self.execution)
        if isinstance(self.security_events, dict):
            self.security_events = SecurityEvents(**self.security_events)
        if isinstance(self.manifest_evidence, dict):
            self.manifest_evidence = ManifestEvidence(**self.manifest_evidence)

    def to_dict(self) -> dict[str, Any]:
        return to_jsonable(self)
