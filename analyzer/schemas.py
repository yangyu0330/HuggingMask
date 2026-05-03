from __future__ import annotations
from typing import Any, Literal
from pydantic import BaseModel, Field

FileKind = Literal["SAFETENSORS", "PICKLE", "PYTHON", "CONFIG_JSON", "TOKENIZER_CONFIG_JSON", "OTHER"]
ValidationStatus = Literal["PASS", "BLOCK", "PENDING_REVIEW", "ERROR", "SKIPPED"]

class ArtifactRef(BaseModel):
    artifact_id: str
    repo_path: str
    file_name: str
    file_kind: FileKind
    detected_extension: str
    size_bytes: int
    sha256: str
    source_url: str
    temp_local_path: str
    referenced_by: list[str] = Field(default_factory=list)
    is_generated: bool = False

class ValidationJobRequest(BaseModel):
    request_id: str
    job_id: str
    artifacts: list[ArtifactRef]
    policy_fingerprint: str
    enable_path_b: bool = False

class ReasonEntry(BaseModel):
    code: str
    message: str

class ArtifactValidationResult(BaseModel):
    artifact: ArtifactRef
    status: ValidationStatus
    reason_entries: list[ReasonEntry] = Field(default_factory=list)
    detail: dict[str, Any] = Field(default_factory=dict)
    generated_artifact: ArtifactRef | None = None

class ValidationJobResponse(BaseModel):
    request_id: str
    job_id: str
    overall_status: Literal["PASS", "BLOCK"]
    artifact_results: list[ArtifactValidationResult]