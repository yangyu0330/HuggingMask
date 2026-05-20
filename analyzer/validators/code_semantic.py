"""Preprocessing metadata semantic inventory and fail-closed gate.

This validator does not import or execute model code. It records tokenizer /
processor metadata that must be reviewed by later semantic checks and keeps
baseline-less checks out of the PASS path.
"""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping, Protocol

from analyzer.schemas import (
    ArtifactRef,
    ArtifactValidationResult,
    CodeGrade,
    FileKind,
    PolicyInfo,
    ReasonEntry,
    ReviewAction,
    RouteKind,
    ValidationStatus,
)

SANDBOX_FUZZ_EVIDENCE_SCHEMA_VERSION = "preprocessing-sandbox-fuzz-evidence.v1"

PREPROCESSING_METADATA_FILE_KINDS = {
    FileKind.TOKENIZER_CONFIG_JSON,
    FileKind.TOKENIZER_JSON,
    FileKind.SPECIAL_TOKENS_MAP_JSON,
    FileKind.ADDED_TOKENS_JSON,
    FileKind.VOCAB_JSON,
    FileKind.MERGES_TXT,
    FileKind.PREPROCESSOR_CONFIG_JSON,
    FileKind.PROCESSOR_CONFIG_JSON,
    FileKind.CHAT_TEMPLATE_JINJA,
}


@dataclass(frozen=True)
class SemanticFuzzRunnerConfig:
    """Opt-in sandbox fuzz runner contract.

    This config is evidence metadata only. The default semantic validator never
    imports processor/tokenizer code or executes this runner.
    """

    revision_pin: str
    offline_mode: bool = True
    network_disabled: bool = True
    read_only_snapshot: bool = True
    sandbox_runtime: str = "gvisor"
    cpu_budget_cores: float = 1.0
    memory_budget_mb: int = 512
    time_budget_ms: int = 10_000
    require_phase0_import_closure_passed: bool = True

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class SemanticFuzzPrerequisites:
    """Static gates that must be satisfied before sandbox fuzzing is eligible."""

    phase0_static_validation_passed: bool
    python_import_closure_status: str
    python_import_closure_artifact_ids: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class SemanticFuzzRuntimeEvent:
    event_type: str
    message: str
    severity: str = "INFO"
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class SemanticFuzzOutputSnapshot:
    output_key: str
    shape: list[int | str] = field(default_factory=list)
    dtype: str | None = None
    token_count: int | None = None
    special_token_mask: list[int] = field(default_factory=list)
    offset_mapping: list[list[int]] = field(default_factory=list)
    media_placeholder_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class SemanticFuzzCaseEvidence:
    case_id: str
    input_kind: str
    input_hash: str
    media_placeholder_count: int = 0
    outputs: list[SemanticFuzzOutputSnapshot] = field(default_factory=list)
    runtime_events: list[SemanticFuzzRuntimeEvent] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class SemanticFuzzBaselineDiff:
    baseline_available: bool = False
    baseline_revision_pin: str | None = None
    baseline_input_hash: str | None = None
    output_diffs: list[dict[str, Any]] = field(default_factory=list)
    runtime_event_diffs: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class SemanticFuzzResult:
    """Serializable evidence produced by a future opt-in sandbox fuzz runner."""

    target_kind: str
    runner_config: SemanticFuzzRunnerConfig
    prerequisites: SemanticFuzzPrerequisites
    cases: list[SemanticFuzzCaseEvidence] = field(default_factory=list)
    baseline_diff: SemanticFuzzBaselineDiff = field(default_factory=SemanticFuzzBaselineDiff)
    runtime_events: list[SemanticFuzzRuntimeEvent] = field(default_factory=list)
    status: str = "EVIDENCE_ONLY"
    schema_version: str = SANDBOX_FUZZ_EVIDENCE_SCHEMA_VERSION
    review_required: bool = True

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class PreprocessingSemanticFuzzRunner(Protocol):
    """Interface for a future opt-in tokenizer/processor sandbox fuzz runner."""

    def run(
        self,
        *,
        artifact: ArtifactRef,
        metadata_source: str | bytes,
        runner_config: SemanticFuzzRunnerConfig,
        prerequisites: SemanticFuzzPrerequisites,
        baseline_metadata_source: str | bytes | None = None,
    ) -> SemanticFuzzResult:
        """Return evidence only; this result must not auto-approve validation."""

_JSON_FILE_KINDS = {
    FileKind.TOKENIZER_CONFIG_JSON,
    FileKind.TOKENIZER_JSON,
    FileKind.SPECIAL_TOKENS_MAP_JSON,
    FileKind.ADDED_TOKENS_JSON,
    FileKind.VOCAB_JSON,
    FileKind.PREPROCESSOR_CONFIG_JSON,
    FileKind.PROCESSOR_CONFIG_JSON,
}

_KEY_FIELDS_BY_KIND = {
    FileKind.TOKENIZER_JSON: (
        "version",
        "model",
        "normalizer",
        "pre_tokenizer",
        "post_processor",
        "decoder",
        "added_tokens",
    ),
    FileKind.TOKENIZER_CONFIG_JSON: (
        "tokenizer_class",
        "auto_map",
        "model_max_length",
        "padding_side",
        "truncation_side",
        "split_special_tokens",
        "clean_up_tokenization_spaces",
        "bos_token",
        "eos_token",
        "unk_token",
        "sep_token",
        "pad_token",
        "cls_token",
        "mask_token",
        "additional_special_tokens",
        "added_tokens_decoder",
        "chat_template",
    ),
    FileKind.SPECIAL_TOKENS_MAP_JSON: (
        "bos_token",
        "eos_token",
        "unk_token",
        "sep_token",
        "pad_token",
        "cls_token",
        "mask_token",
        "additional_special_tokens",
    ),
    FileKind.ADDED_TOKENS_JSON: ("added_tokens",),
    FileKind.VOCAB_JSON: ("vocab_size",),
    FileKind.PREPROCESSOR_CONFIG_JSON: (
        "do_resize",
        "size",
        "crop_size",
        "do_rescale",
        "rescale_factor",
        "do_normalize",
        "image_mean",
        "image_std",
        "channel_order",
        "data_format",
        "input_data_format",
        "image_processor_type",
        "processor_class",
        "sampling_rate",
        "padding_value",
        "feature_size",
        "return_attention_mask",
        "max_length",
        "truncation",
        "padding",
    ),
    FileKind.PROCESSOR_CONFIG_JSON: (
        "processor_class",
        "tokenizer_class",
        "image_processor_class",
        "feature_extractor_class",
        "chat_template",
    ),
}

_CHAT_TEMPLATE_HINTS = (
    "chat_template",
    "system",
    "user",
    "assistant",
    "tool",
    "tools",
    "document",
    "documents",
    "add_generation_prompt",
)

_HIDDEN_SYSTEM_HINTS = (
    "ignore previous",
    "ignore the previous",
    "ignore all previous",
    "developer message",
    "always comply",
    "bypass",
    "disable safety",
    "jailbreak",
)

_PATH_OR_NETWORK_HINTS = (
    "http://",
    "https://",
    "file://",
    "../",
    "..\\",
    "/etc/",
    "c:\\",
)

_SPECIAL_TOKEN_KEYS = (
    "bos_token",
    "eos_token",
    "unk_token",
    "sep_token",
    "pad_token",
    "cls_token",
    "mask_token",
    "additional_special_tokens",
)

_CORE_SPECIAL_TOKEN_KEYS = (
    "bos_token",
    "eos_token",
    "unk_token",
    "sep_token",
    "pad_token",
    "cls_token",
    "mask_token",
)

_TOKENIZER_OPTION_KEYS = (
    "model_max_length",
    "padding_side",
    "truncation_side",
    "split_special_tokens",
    "clean_up_tokenization_spaces",
)

_TOKENIZER_INVARIANT_FILE_KINDS = {
    FileKind.TOKENIZER_CONFIG_JSON,
    FileKind.TOKENIZER_JSON,
    FileKind.SPECIAL_TOKENS_MAP_JSON,
    FileKind.ADDED_TOKENS_JSON,
}

_PROCESSOR_INVARIANT_FILE_KINDS = {
    FileKind.PREPROCESSOR_CONFIG_JSON,
    FileKind.PROCESSOR_CONFIG_JSON,
}

_MODEL_MAX_LENGTH_REVIEW_THRESHOLD = 1_000_000
_IMAGE_DIMENSION_REVIEW_THRESHOLD = 100_000
_AUDIO_SAMPLING_RATE_REVIEW_THRESHOLD = 384_000
_AUDIO_FEATURE_SIZE_REVIEW_THRESHOLD = 100_000
_AUDIO_MAX_LENGTH_REVIEW_THRESHOLD = 10_000_000

_ADDED_TOKEN_OPTION_KEYS = (
    "id",
    "content",
    "special",
    "single_word",
    "lstrip",
    "rstrip",
    "normalized",
)

_IMAGE_METADATA_KEYS = (
    "do_resize",
    "size",
    "crop_size",
    "do_rescale",
    "rescale_factor",
    "do_normalize",
    "image_mean",
    "image_std",
    "channel_order",
    "data_format",
    "input_data_format",
    "do_convert_rgb",
    "resample",
)

_IMAGE_HINT_KEYS = (
    "image_processor_type",
    "processor_class",
    "image_processor_class",
    "backend",
    "use_fast",
    "data_format",
    "input_data_format",
    "channel_order",
)

_IMAGE_DETECTION_KEYS = (
    "do_resize",
    "size",
    "crop_size",
    "do_rescale",
    "rescale_factor",
    "image_mean",
    "image_std",
    "channel_order",
    "data_format",
    "input_data_format",
    "image_processor_type",
    "image_processor_class",
    "do_convert_rgb",
    "resample",
)

_AUDIO_METADATA_KEYS = (
    "sampling_rate",
    "padding_value",
    "do_normalize",
    "feature_size",
    "return_attention_mask",
    "max_length",
    "truncation",
    "padding",
    "pad_to_multiple_of",
)

_AUDIO_DETECTION_KEYS = (
    "sampling_rate",
    "padding_value",
    "feature_size",
    "return_attention_mask",
    "max_length",
    "truncation",
    "padding",
    "pad_to_multiple_of",
)

_PROCESSOR_CLASS_KEYS = (
    "processor_class",
    "tokenizer_class",
    "image_processor_class",
    "feature_extractor_class",
)

_PROCESSOR_COMPONENT_KEYS = (
    "tokenizer",
    "image_processor",
    "feature_extractor",
    "audio_processor",
    "video_processor",
    "processor",
)

_PROCESSOR_CLASS_TO_COMPONENT_KEY = {
    "tokenizer_class": "tokenizer",
    "image_processor_class": "image_processor",
    "feature_extractor_class": "feature_extractor",
}

_MEDIA_TEMPLATE_HINTS = (
    "<image",
    "<video",
    "<audio",
    "image",
    "images",
    "video",
    "videos",
    "audio",
    "audios",
    "pixel_values",
    "input_features",
)

_CHANNEL_ORDER_VALUES = {"rgb", "bgr", "rgba", "grayscale", "gray", "l"}
_DATA_FORMAT_VALUES = {"channels_first", "channels_last", "none"}


def is_preprocessing_metadata_kind(file_kind: FileKind | str) -> bool:
    return FileKind(file_kind) in PREPROCESSING_METADATA_FILE_KINDS


def validate_preprocessing_metadata_artifact(
    artifact: ArtifactRef,
    source: str | bytes,
    policy: PolicyInfo | None = None,
    *,
    baseline_source: str | bytes | None = None,
    sandbox_fuzz_result: SemanticFuzzResult | Mapping[str, Any] | None = None,
) -> ArtifactValidationResult:
    """Build semantic inventory and keep uncertain metadata in review."""

    started_at = _utc_now()
    file_kind = FileKind(artifact.file_kind)
    source_text = _to_source_text(source)
    baseline_text = _to_source_text(baseline_source) if baseline_source is not None else None

    parse_error: str | None = None
    payload: Any = None
    if file_kind in _JSON_FILE_KINDS:
        try:
            payload = json.loads(source_text)
        except json.JSONDecodeError as exc:
            parse_error = str(exc)

    inventory = _build_inventory(
        artifact=artifact,
        source_text=source_text,
        payload=payload,
        parse_error=parse_error,
    )
    semantic_findings = _build_semantic_findings(
        file_kind=file_kind,
        source_text=source_text,
        payload=payload,
        baseline_text=baseline_text,
        parse_error=parse_error,
    )
    sandbox_fuzz = _normalize_sandbox_fuzz_result(sandbox_fuzz_result)
    if sandbox_fuzz is not None:
        semantic_findings.append(_sandbox_fuzz_review_finding(sandbox_fuzz))
        semantic_findings = _dedupe_findings(semantic_findings)

    check_status = _semantic_check_status(
        baseline_text=baseline_text,
        source_text=source_text,
        parse_error=parse_error,
        findings=semantic_findings,
    )
    grade, status, review_action, reason_code = _decision_for_semantic_status(check_status, semantic_findings)

    details = {
        "semantic_check": {
            "status": check_status,
            "baseline_available": baseline_text is not None,
            "baseline_sha256": _sha256_text(baseline_text) if baseline_text is not None else None,
            "policy": "metadata_inventory_fail_closed",
        },
        "semantic_inventory": inventory,
        "semantic_findings": semantic_findings,
        "semantic_finding_codes": _semantic_finding_codes(semantic_findings),
        "sandbox_fuzz": sandbox_fuzz or _sandbox_fuzz_not_run(),
        "pending_api_refs": [],
        "review_queue_entry_id": None,
        "effective_output_artifact_id": None,
        "effective_status": status.value,
    }

    return ArtifactValidationResult(
        artifact=artifact,
        route_kind=RouteKind.PREPROCESSING_SEMANTIC_SCAN,
        status=status,
        grade=grade,
        review_action=review_action,
        cache_key=_build_cache_key(artifact, policy),
        cache_hit=False,
        reason_entries=[
            ReasonEntry(
                code=reason_code,
                severity="HIGH" if grade is CodeGrade.C else "MEDIUM",
                message=_reason_message(reason_code),
                evidence=[artifact.repo_path],
                review_required=status is not ValidationStatus.PASS,
            )
        ],
        details=details,
        started_at=started_at,
        finished_at=_utc_now(),
    )


def _build_inventory(
    *,
    artifact: ArtifactRef,
    source_text: str,
    payload: Any,
    parse_error: str | None,
) -> dict[str, Any]:
    file_kind = FileKind(artifact.file_kind)
    inventory: dict[str, Any] = {
        "metadata_kind": file_kind.value,
        "repo_path": artifact.repo_path,
        "sha256": artifact.sha256,
        "content_hash": _sha256_text(source_text),
        "parse_error": parse_error,
        "key_fields": {},
        "special_token_map": _empty_special_token_map_inventory(),
        "added_tokens": _empty_added_tokens_inventory(),
        "vocab_size": None,
        "merge_rule_count": None,
        "model_max_length": None,
        "padding_side": None,
        "truncation_side": None,
        "split_special_tokens": None,
        "clean_up_tokenization_spaces": None,
        "tokenizer_options": {},
        "image": _empty_image_inventory(),
        "audio": _empty_audio_inventory(),
        "processor": _empty_processor_inventory(),
    }

    if parse_error is not None:
        return inventory

    if isinstance(payload, dict):
        inventory["key_fields"] = _extract_key_fields(file_kind, payload)
        inventory.update(_extract_tokenizer_metadata_inventory(file_kind, payload))
        inventory.update(_extract_processor_metadata_inventory(file_kind, payload))
        chat_template = payload.get("chat_template")
        if isinstance(chat_template, str):
            inventory["chat_template"] = _chat_template_inventory(chat_template)
    elif isinstance(payload, list) and file_kind is FileKind.ADDED_TOKENS_JSON:
        added_tokens = _added_tokens_inventory(payload)
        inventory["added_tokens"] = added_tokens
        inventory["key_fields"] = {"added_tokens": {"count": added_tokens["count"]}}
    elif file_kind is FileKind.CHAT_TEMPLATE_JINJA:
        inventory["chat_template"] = _chat_template_inventory(source_text)
    elif file_kind is FileKind.MERGES_TXT:
        merge_rules = _merge_rules_inventory(source_text)
        inventory["merge_rule_count"] = merge_rules["count"]
        inventory["merge_rules"] = merge_rules
        inventory["key_fields"] = {"merge_rule_count": merge_rules["count"]}

    return inventory


def _extract_key_fields(file_kind: FileKind, payload: dict[str, Any]) -> dict[str, Any]:
    if file_kind is FileKind.VOCAB_JSON:
        return {"vocab_size": len(payload)}
    if file_kind is FileKind.ADDED_TOKENS_JSON:
        added_tokens = _added_tokens_inventory(payload)
        return {"added_tokens": {"count": added_tokens["count"]}}

    fields: dict[str, Any] = {}
    for key in _KEY_FIELDS_BY_KIND.get(file_kind, ()):
        if key not in payload:
            continue
        value = payload[key]
        if key == "added_tokens" and isinstance(value, list):
            fields[key] = {"count": len(value)}
        elif key == "added_tokens_decoder" and isinstance(value, dict):
            fields[key] = {"count": len(value)}
        elif key == "chat_template" and isinstance(value, str):
            fields[key] = _chat_template_inventory(value)
        elif isinstance(value, dict):
            fields[key] = {"type": value.get("type"), "keys": sorted(value.keys())[:20]}
        elif isinstance(value, list):
            fields[key] = {"count": len(value), "values": value[:20]}
        else:
            fields[key] = value
    return fields


def _extract_tokenizer_metadata_inventory(file_kind: FileKind, payload: dict[str, Any]) -> dict[str, Any]:
    special_token_map = _special_token_map_inventory(file_kind, payload)
    added_tokens = _added_tokens_for_file_kind(file_kind, payload)
    vocab_size = _vocab_size_for_file_kind(file_kind, payload)
    merge_rule_count = _merge_rule_count_for_file_kind(file_kind, payload)
    tokenizer_options = _tokenizer_options_inventory(payload)

    return {
        "special_token_map": special_token_map,
        "added_tokens": added_tokens,
        "vocab_size": vocab_size,
        "merge_rule_count": merge_rule_count,
        "model_max_length": tokenizer_options["model_max_length"],
        "padding_side": tokenizer_options["padding_side"],
        "truncation_side": tokenizer_options["truncation_side"],
        "split_special_tokens": tokenizer_options["split_special_tokens"],
        "clean_up_tokenization_spaces": tokenizer_options["clean_up_tokenization_spaces"],
        "tokenizer_options": tokenizer_options,
    }


def _extract_processor_metadata_inventory(file_kind: FileKind, payload: dict[str, Any]) -> dict[str, Any]:
    if file_kind not in {FileKind.PREPROCESSOR_CONFIG_JSON, FileKind.PROCESSOR_CONFIG_JSON}:
        return {
            "image": _empty_image_inventory(),
            "audio": _empty_audio_inventory(),
            "processor": _empty_processor_inventory(),
        }

    return {
        "image": _image_inventory(payload),
        "audio": _audio_inventory(payload),
        "processor": _processor_inventory(payload),
    }


def _empty_image_inventory() -> dict[str, Any]:
    return {
        "fields": {},
        "hints": {},
    }


def _empty_audio_inventory() -> dict[str, Any]:
    return {
        "fields": {},
    }


def _empty_processor_inventory() -> dict[str, Any]:
    return {
        "classes": {},
        "component_refs": {},
        "has_chat_template": False,
        "chat_template": None,
    }


def _image_inventory(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "fields": _select_present_fields(payload, _IMAGE_METADATA_KEYS),
        "hints": _select_present_fields(payload, _IMAGE_HINT_KEYS),
    }


def _audio_inventory(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "fields": _select_present_fields(payload, _AUDIO_METADATA_KEYS),
    }


def _processor_inventory(payload: dict[str, Any]) -> dict[str, Any]:
    chat_template = payload.get("chat_template")
    inventory = _empty_processor_inventory()
    inventory["classes"] = _select_present_fields(payload, _PROCESSOR_CLASS_KEYS)
    inventory["component_refs"] = _processor_component_refs(payload)
    inventory["has_chat_template"] = isinstance(chat_template, str)
    if isinstance(chat_template, str):
        inventory["chat_template"] = _chat_template_inventory(chat_template)
    return inventory


def _processor_component_refs(payload: dict[str, Any]) -> dict[str, Any]:
    refs: dict[str, Any] = {}
    for key in _PROCESSOR_COMPONENT_KEYS:
        if key not in payload:
            continue
        refs[key] = _summarize_component_ref(payload[key])
    return refs


def _summarize_component_ref(value: Any) -> Any:
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        class_keys = (
            "type",
            "class",
            "processor_class",
            "tokenizer_class",
            "image_processor_class",
            "feature_extractor_class",
            "pretrained_model_name_or_path",
            "name_or_path",
        )
        summary = {key: value.get(key) for key in class_keys if key in value}
        if not summary:
            summary["keys"] = sorted(value.keys())[:20]
        return summary
    if isinstance(value, list):
        return {
            "count": len(value),
            "values": [_summarize_component_ref(item) for item in value[:20]],
        }
    return {"value": value}


def _select_present_fields(payload: dict[str, Any], keys: tuple[str, ...]) -> dict[str, Any]:
    return {key: payload[key] for key in keys if key in payload}


def _empty_special_token_map_inventory() -> dict[str, Any]:
    return {
        "count": 0,
        "tokens": {},
        "additional_special_tokens_count": 0,
        "special_added_tokens_count": 0,
    }


def _empty_added_tokens_inventory() -> dict[str, Any]:
    return {
        "count": 0,
        "tokens": [],
        "special_count": 0,
        "lstrip_count": 0,
        "rstrip_count": 0,
        "normalized_false_count": 0,
    }


def _special_token_map_inventory(file_kind: FileKind, payload: dict[str, Any]) -> dict[str, Any]:
    inventory = _empty_special_token_map_inventory()
    tokens: dict[str, Any] = {}

    for key in _SPECIAL_TOKEN_KEYS:
        if key not in payload:
            continue
        tokens[key] = _summarize_token_value(payload[key])

    if file_kind is FileKind.TOKENIZER_JSON:
        special_added_tokens = [
            _summarize_added_token(item)
            for item in payload.get("added_tokens", [])
            if isinstance(item, dict) and item.get("special") is True
        ]
        if special_added_tokens:
            tokens["special_added_tokens"] = special_added_tokens[:50]
            inventory["special_added_tokens_count"] = len(special_added_tokens)

    inventory["tokens"] = tokens
    inventory["count"] = len(tokens)
    additional = tokens.get("additional_special_tokens")
    if isinstance(additional, dict):
        inventory["additional_special_tokens_count"] = int(additional.get("count") or 0)
    return inventory


def _summarize_token_value(value: Any) -> Any:
    if isinstance(value, str):
        return {"content": value}
    if isinstance(value, list):
        return {
            "count": len(value),
            "values": [_summarize_token_value(item) for item in value[:50]],
        }
    if isinstance(value, dict):
        summary = {key: value.get(key) for key in _ADDED_TOKEN_OPTION_KEYS if key in value}
        if "content" not in summary and "__type" in value:
            summary["type"] = value.get("__type")
        if not summary:
            summary["keys"] = sorted(value.keys())[:20]
        return summary
    return {"value": value}


def _added_tokens_for_file_kind(file_kind: FileKind, payload: dict[str, Any]) -> dict[str, Any]:
    if file_kind is FileKind.TOKENIZER_JSON and "added_tokens" in payload:
        return _added_tokens_inventory(payload["added_tokens"])
    if file_kind is FileKind.TOKENIZER_CONFIG_JSON and "added_tokens_decoder" in payload:
        return _added_tokens_inventory(payload["added_tokens_decoder"])
    if file_kind is FileKind.ADDED_TOKENS_JSON:
        return _added_tokens_inventory(payload)
    return _empty_added_tokens_inventory()


def _added_tokens_inventory(value: Any) -> dict[str, Any]:
    if isinstance(value, list):
        tokens = [_summarize_added_token(item) for item in value[:50]]
        count = len(value)
    elif isinstance(value, dict):
        tokens = [_summarize_added_token(item, key=key) for key, item in list(value.items())[:50]]
        count = len(value)
    else:
        tokens = []
        count = None

    special_count = sum(1 for item in tokens if item.get("special") is True)
    lstrip_count = sum(1 for item in tokens if item.get("lstrip") is True)
    rstrip_count = sum(1 for item in tokens if item.get("rstrip") is True)
    normalized_false_count = sum(1 for item in tokens if item.get("normalized") is False)
    return {
        "count": count,
        "tokens": tokens,
        "sample_limit": 50,
        "special_count": special_count,
        "lstrip_count": lstrip_count,
        "rstrip_count": rstrip_count,
        "normalized_false_count": normalized_false_count,
    }


def _summarize_added_token(value: Any, *, key: str | None = None) -> dict[str, Any]:
    if key is not None and isinstance(value, int) and not isinstance(value, bool):
        return {"id": value, "content": key}
    if isinstance(value, dict):
        summary = {name: value.get(name) for name in _ADDED_TOKEN_OPTION_KEYS if name in value}
        if key is not None:
            summary["key"] = key
        if "content" not in summary:
            content = value.get("content") or value.get("token")
            if content is not None:
                summary["content"] = content
        return summary
    if isinstance(value, str):
        summary = {"content": value}
        if key is not None:
            summary["key"] = key
        return summary
    summary = {"value": value}
    if key is not None:
        summary["key"] = key
    return summary


def _vocab_size_for_file_kind(file_kind: FileKind, payload: dict[str, Any]) -> int | None:
    if file_kind is FileKind.VOCAB_JSON:
        return len(payload)
    model = payload.get("model")
    if isinstance(model, dict):
        vocab = model.get("vocab")
        if isinstance(vocab, dict):
            return len(vocab)
        if isinstance(vocab, list):
            return len(vocab)
    return None


def _merge_rule_count_for_file_kind(file_kind: FileKind, payload: dict[str, Any]) -> int | None:
    model = payload.get("model")
    if isinstance(model, dict):
        merges = model.get("merges")
        if isinstance(merges, list):
            return len(merges)
    return None


def _merge_rules_inventory(source_text: str) -> dict[str, Any]:
    rules = [
        line.strip()
        for line in source_text.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    return {
        "count": len(rules),
        "sample": rules[:50],
        "sample_limit": 50,
    }


def _tokenizer_options_inventory(payload: dict[str, Any]) -> dict[str, Any]:
    options = {key: payload.get(key) for key in _TOKENIZER_OPTION_KEYS}

    truncation = payload.get("truncation")
    if isinstance(truncation, dict):
        options["model_max_length"] = options["model_max_length"] or truncation.get("max_length")
        options["truncation_side"] = options["truncation_side"] or truncation.get("direction")

    padding = payload.get("padding")
    if isinstance(padding, dict):
        options["padding_side"] = options["padding_side"] or padding.get("direction")

    return options


def _chat_template_inventory(template: str) -> dict[str, Any]:
    lowered = template.lower()
    hint_details = _chat_template_hint_details(lowered)
    return {
        "sha256": _sha256_text(template),
        "length": len(template),
        "line_count": len(template.splitlines()) or 1,
        "hints": [hint for hint in _CHAT_TEMPLATE_HINTS if hint in lowered],
        "hint_details": hint_details,
        "role_hints": [key for key, present in hint_details.items() if present],
        "contains_jinja_control": "{%" in template or "{{" in template,
    }


def _chat_template_hint_details(lowered_template: str) -> dict[str, bool]:
    return {
        "system": "system" in lowered_template,
        "user": "user" in lowered_template,
        "assistant": "assistant" in lowered_template,
        "tool": "tool" in lowered_template or "tools" in lowered_template,
        "document": "document" in lowered_template or "documents" in lowered_template,
        "add_generation_prompt": "add_generation_prompt" in lowered_template,
    }


def _build_semantic_findings(
    *,
    file_kind: FileKind,
    source_text: str,
    payload: Any,
    baseline_text: str | None,
    parse_error: str | None,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []

    if baseline_text is None:
        findings.append(
            _finding(
                "BASELINE_MISSING",
                "MEDIUM",
                "No baseline metadata is available; semantic preservation cannot be proven.",
            )
        )
    elif _sha256_text(source_text) != _sha256_text(baseline_text):
        findings.append(
            _finding(
                "SEMANTIC_BASELINE_DELTA",
                "MEDIUM",
                "Metadata differs from the supplied baseline and requires semantic review.",
            )
        )

    if parse_error is not None:
        findings.append(_finding("SEMANTIC_PARSE_ERROR", "HIGH", parse_error))
        return findings

    templates = _extract_chat_templates(file_kind, source_text, payload)
    for template in templates:
        findings.extend(_chat_template_findings(template))

    findings.extend(_tokenizer_invariant_findings(file_kind, payload))
    findings.extend(_processor_invariant_findings(file_kind, payload))

    lowered = source_text.lower()
    if any(hint in lowered for hint in _PATH_OR_NETWORK_HINTS):
        findings.append(
            _finding(
                "NETWORK_OR_PATH_REVIEW",
                "MEDIUM",
                "Metadata contains network or filesystem path-like literals.",
            )
        )

    return _dedupe_findings(findings)


def _tokenizer_invariant_findings(file_kind: FileKind, payload: Any) -> list[dict[str, Any]]:
    if file_kind not in _TOKENIZER_INVARIANT_FILE_KINDS:
        return []
    if not isinstance(payload, (dict, list)):
        return []

    findings: list[dict[str, Any]] = []
    if isinstance(payload, dict):
        findings.extend(_special_token_collision_findings(payload))
        findings.extend(_tokenizer_option_invariant_findings(payload))
    findings.extend(_added_token_invariant_findings(file_kind, payload))
    return findings


def _special_token_collision_findings(payload: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    core_tokens = _collect_core_special_token_contents(payload)
    by_content: dict[str, list[str]] = {}
    for key, content in core_tokens.items():
        if content == "":
            continue
        by_content.setdefault(content, []).append(key)

    for content, keys in by_content.items():
        if len(keys) > 1:
            findings.append(
                _finding(
                    "TOKENIZER_SPECIAL_TOKEN_COLLISION",
                    "MEDIUM",
                    f"special token {content!r} is assigned to {', '.join(sorted(keys))}",
                )
            )

    additional_tokens = _collect_additional_special_token_contents(payload)
    core_contents = set(core_tokens.values())
    collisions = sorted({content for content in additional_tokens if content in core_contents and content != ""})
    if collisions:
        findings.append(
            _finding(
                "TOKENIZER_ADDITIONAL_SPECIAL_TOKEN_COLLISION",
                "MEDIUM",
                f"additional_special_tokens overlap core special tokens: {', '.join(collisions)}",
            )
        )

    return findings


def _collect_core_special_token_contents(payload: dict[str, Any]) -> dict[str, str]:
    tokens: dict[str, str] = {}
    for key in _CORE_SPECIAL_TOKEN_KEYS:
        if key not in payload:
            continue
        for content in _token_contents(payload[key]):
            tokens[key] = content
            break
    return tokens


def _collect_additional_special_token_contents(payload: dict[str, Any]) -> list[str]:
    if "additional_special_tokens" not in payload:
        return []
    return _token_contents(payload["additional_special_tokens"])


def _token_contents(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        content = value.get("content") or value.get("token")
        if isinstance(content, str):
            return [content]
        nested_values: list[str] = []
        for item in value.values():
            nested_values.extend(_token_contents(item))
        return nested_values
    if isinstance(value, list):
        output: list[str] = []
        for item in value:
            output.extend(_token_contents(item))
        return output
    return []


def _tokenizer_option_invariant_findings(payload: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []

    if payload.get("split_special_tokens") is True:
        findings.append(
            _finding(
                "TOKENIZER_SPLIT_SPECIAL_TOKENS_ENABLED",
                "MEDIUM",
                "split_special_tokens=True can change control token boundaries.",
            )
        )

    model_max_length = _extract_model_max_length(payload)
    if model_max_length is not None and not _is_valid_model_max_length(model_max_length):
        findings.append(
            _finding(
                "TOKENIZER_MODEL_MAX_LENGTH_ABNORMAL",
                "MEDIUM",
                f"model_max_length is abnormal: {model_max_length!r}",
            )
        )

    for key in ("padding_side", "truncation_side"):
        side = _extract_side_option(payload, key)
        if side is not None and not _is_valid_side(side):
            findings.append(
                _finding(
                    f"TOKENIZER_INVALID_{key.upper()}",
                    "MEDIUM",
                    f"{key} must be left or right, got {side!r}",
                )
            )

    return findings


def _extract_model_max_length(payload: dict[str, Any]) -> Any:
    if "model_max_length" in payload:
        return payload["model_max_length"]
    truncation = payload.get("truncation")
    if isinstance(truncation, dict) and "max_length" in truncation:
        return truncation["max_length"]
    return None


def _is_valid_model_max_length(value: Any) -> bool:
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        numeric = value
    elif isinstance(value, str) and value.strip().isdigit():
        numeric = int(value.strip())
    else:
        return False
    return 0 < numeric <= _MODEL_MAX_LENGTH_REVIEW_THRESHOLD


def _extract_side_option(payload: dict[str, Any], key: str) -> Any:
    if key in payload:
        return payload[key]
    if key == "padding_side":
        padding = payload.get("padding")
        if isinstance(padding, dict):
            return padding.get("direction")
    if key == "truncation_side":
        truncation = payload.get("truncation")
        if isinstance(truncation, dict):
            return truncation.get("direction")
    return None


def _is_valid_side(value: Any) -> bool:
    return isinstance(value, str) and value.lower() in {"left", "right"}


def _added_token_invariant_findings(file_kind: FileKind, payload: dict[str, Any] | list[Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    tokens = _collect_added_token_records(file_kind, payload)
    findings.extend(_added_token_duplicate_findings(tokens))
    findings.extend(_added_token_option_findings(tokens))
    return findings


def _collect_added_token_records(file_kind: FileKind, payload: dict[str, Any] | list[Any]) -> list[dict[str, Any]]:
    if file_kind is FileKind.TOKENIZER_JSON and isinstance(payload, dict):
        return _added_token_records(payload.get("added_tokens"))
    if file_kind is FileKind.TOKENIZER_CONFIG_JSON and isinstance(payload, dict):
        return _added_token_records(payload.get("added_tokens_decoder"))
    if file_kind is FileKind.ADDED_TOKENS_JSON:
        return _added_token_records(payload)
    return []


def _added_token_records(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [_added_token_record(item, key=None) for item in value]
    if isinstance(value, dict):
        return [_added_token_record(item, key=key) for key, item in value.items()]
    return []


def _added_token_record(value: Any, *, key: str | None) -> dict[str, Any]:
    record: dict[str, Any] = {"key": key, "id": None, "content": None, "options": {}}
    if key is not None and isinstance(value, int) and not isinstance(value, bool):
        record["id"] = value
        record["content"] = key
        return record
    if key is not None and str(key).isdigit():
        record["id"] = int(str(key))
    if isinstance(value, dict):
        if "id" in value:
            record["id"] = value["id"]
        content = value.get("content") or value.get("token")
        if isinstance(content, str):
            record["content"] = content
        record["options"] = {name: value.get(name) for name in _ADDED_TOKEN_OPTION_KEYS if name in value}
        return record
    if isinstance(value, str):
        record["content"] = value
        return record
    record["content"] = str(value) if value is not None else None
    return record


def _added_token_duplicate_findings(tokens: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    ids: dict[Any, int] = {}
    contents: dict[str, int] = {}
    duplicate_ids: set[Any] = set()
    duplicate_contents: set[str] = set()

    for token in tokens:
        token_id = token.get("id")
        if token_id is not None:
            if token_id in ids:
                duplicate_ids.add(token_id)
            ids[token_id] = ids.get(token_id, 0) + 1
        content = token.get("content")
        if isinstance(content, str) and content != "":
            if content in contents:
                duplicate_contents.add(content)
            contents[content] = contents.get(content, 0) + 1

    if duplicate_ids:
        findings.append(
            _finding(
                "TOKENIZER_ADDED_TOKEN_DUPLICATE_ID",
                "MEDIUM",
                f"added token ids are duplicated: {', '.join(str(item) for item in sorted(duplicate_ids, key=str))}",
            )
        )
    if duplicate_contents:
        findings.append(
            _finding(
                "TOKENIZER_ADDED_TOKEN_DUPLICATE_CONTENT",
                "MEDIUM",
                "added token contents are duplicated: "
                + ", ".join(repr(item) for item in sorted(duplicate_contents)),
            )
        )

    return findings


def _added_token_option_findings(tokens: list[dict[str, Any]]) -> list[dict[str, Any]]:
    risky_options: dict[str, list[str]] = {"lstrip": [], "rstrip": [], "normalized": []}
    for token in tokens:
        options = token.get("options") or {}
        content = str(token.get("content") or token.get("key") or token.get("id"))
        if options.get("lstrip") is True:
            risky_options["lstrip"].append(content)
        if options.get("rstrip") is True:
            risky_options["rstrip"].append(content)
        if options.get("normalized") is False:
            risky_options["normalized"].append(content)

    findings: list[dict[str, Any]] = []
    for option, contents in risky_options.items():
        if not contents:
            continue
        finding_code = (
            "TOKENIZER_ADDED_TOKEN_NORMALIZED_FALSE"
            if option == "normalized"
            else f"TOKENIZER_ADDED_TOKEN_{option.upper()}_ENABLED"
        )
        findings.append(
            _finding(
                finding_code,
                "MEDIUM",
                f"AddedToken {option} risk option is present for: {', '.join(contents[:20])}",
            )
        )
    return findings


def _processor_invariant_findings(file_kind: FileKind, payload: Any) -> list[dict[str, Any]]:
    if file_kind not in _PROCESSOR_INVARIANT_FILE_KINDS or not isinstance(payload, dict):
        return []

    findings: list[dict[str, Any]] = []
    if file_kind is FileKind.PROCESSOR_CONFIG_JSON:
        findings.extend(_processor_component_invariant_findings(payload))
        findings.extend(_processor_chat_template_media_findings(payload))
    findings.extend(_image_invariant_findings(payload))
    findings.extend(_audio_invariant_findings(payload))
    return findings


def _processor_component_invariant_findings(payload: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []

    invalid_class_keys = [
        key for key in _PROCESSOR_CLASS_KEYS if key in payload and not _is_non_empty_string(payload[key])
    ]
    if invalid_class_keys:
        findings.append(
            _finding(
                "PROCESSOR_CLASS_REFERENCE_INVALID",
                "MEDIUM",
                f"processor class fields must be non-empty strings: {', '.join(sorted(invalid_class_keys))}",
            )
        )

    missing_components = [
        component_key
        for class_key, component_key in _PROCESSOR_CLASS_TO_COMPONENT_KEY.items()
        if class_key in payload and component_key not in payload
    ]
    if missing_components:
        findings.append(
            _finding(
                "PROCESSOR_COMPONENT_REF_MISSING",
                "MEDIUM",
                f"declared processor classes are missing component refs: {', '.join(sorted(missing_components))}",
            )
        )

    invalid_components = [
        key
        for key in _PROCESSOR_COMPONENT_KEYS
        if key in payload and not _is_valid_component_ref(payload[key])
    ]
    if invalid_components:
        findings.append(
            _finding(
                "PROCESSOR_COMPONENT_REF_INVALID",
                "MEDIUM",
                f"processor component refs have invalid type/value: {', '.join(sorted(invalid_components))}",
            )
        )

    return findings


def _processor_chat_template_media_findings(payload: dict[str, Any]) -> list[dict[str, Any]]:
    template = payload.get("chat_template")
    if not isinstance(template, str):
        return []
    lowered = template.lower()
    hints = sorted({hint for hint in _MEDIA_TEMPLATE_HINTS if hint in lowered})
    if not hints:
        return []
    return [
        _finding(
            "PROCESSOR_CHAT_TEMPLATE_MEDIA_LITERAL",
            "MEDIUM",
            f"processor chat_template contains media-related literals: {', '.join(hints[:20])}",
        )
    ]


def _image_invariant_findings(payload: dict[str, Any]) -> list[dict[str, Any]]:
    if not _looks_like_image_config(payload):
        return []

    findings: list[dict[str, Any]] = []
    if not _is_valid_image_dimension_spec(payload.get("size")):
        findings.append(_finding("IMAGE_SIZE_INVALID", "MEDIUM", "image size is missing or invalid."))
    if not _is_valid_image_dimension_spec(payload.get("crop_size")):
        findings.append(_finding("IMAGE_CROP_SIZE_INVALID", "MEDIUM", "image crop_size is missing or invalid."))

    if payload.get("do_normalize") is True or "image_mean" in payload:
        if not _is_valid_image_stat(payload.get("image_mean"), allow_zero=True):
            findings.append(_finding("IMAGE_MEAN_INVALID", "MEDIUM", "image_mean length or value range is invalid."))
    if payload.get("do_normalize") is True or "image_std" in payload:
        if not _is_valid_image_stat(payload.get("image_std"), allow_zero=False):
            findings.append(_finding("IMAGE_STD_INVALID", "MEDIUM", "image_std length or value range is invalid."))

    if payload.get("do_rescale") is True or "rescale_factor" in payload:
        if not _is_valid_positive_number(payload.get("rescale_factor"), maximum=10.0):
            findings.append(
                _finding("IMAGE_RESCALE_FACTOR_INVALID", "MEDIUM", "rescale_factor is missing or invalid.")
            )

    invalid_bool_fields = [
        key for key in ("do_resize", "do_rescale", "do_normalize") if key in payload and not isinstance(payload[key], bool)
    ]
    if invalid_bool_fields:
        findings.append(
            _finding(
                "IMAGE_BOOL_FIELD_INVALID",
                "MEDIUM",
                f"image boolean fields have invalid type: {', '.join(sorted(invalid_bool_fields))}",
            )
        )

    invalid_format_fields = [
        key
        for key in ("channel_order", "data_format", "input_data_format")
        if key in payload and not _is_valid_image_format(key, payload[key])
    ]
    if invalid_format_fields:
        findings.append(
            _finding(
                "IMAGE_FORMAT_INVALID",
                "MEDIUM",
                f"image channel/data format fields are invalid: {', '.join(sorted(invalid_format_fields))}",
            )
        )

    return findings


def _audio_invariant_findings(payload: dict[str, Any]) -> list[dict[str, Any]]:
    if not _looks_like_audio_config(payload):
        return []

    findings: list[dict[str, Any]] = []
    if not _is_valid_positive_int(payload.get("sampling_rate"), maximum=_AUDIO_SAMPLING_RATE_REVIEW_THRESHOLD):
        findings.append(
            _finding("AUDIO_SAMPLING_RATE_INVALID", "MEDIUM", "sampling_rate is missing or invalid.")
        )
    if "padding_value" in payload and not _is_number(payload["padding_value"]):
        findings.append(
            _finding("AUDIO_PADDING_VALUE_INVALID", "MEDIUM", "padding_value must be numeric.")
        )
    if "feature_size" in payload and not _is_valid_positive_int(
        payload["feature_size"], maximum=_AUDIO_FEATURE_SIZE_REVIEW_THRESHOLD
    ):
        findings.append(
            _finding("AUDIO_FEATURE_SIZE_INVALID", "MEDIUM", "feature_size must be a positive bounded integer.")
        )
    if "max_length" in payload and not _is_valid_positive_int(
        payload["max_length"], maximum=_AUDIO_MAX_LENGTH_REVIEW_THRESHOLD
    ):
        findings.append(
            _finding("AUDIO_MAX_LENGTH_INVALID", "MEDIUM", "max_length must be a positive bounded integer.")
        )

    invalid_type_fields: list[str] = []
    if "truncation" in payload and not isinstance(payload["truncation"], (bool, str)):
        invalid_type_fields.append("truncation")
    if "padding" in payload and not isinstance(payload["padding"], (bool, str)):
        invalid_type_fields.append("padding")
    if "return_attention_mask" in payload and not isinstance(payload["return_attention_mask"], bool):
        invalid_type_fields.append("return_attention_mask")
    if invalid_type_fields:
        findings.append(
            _finding(
                "AUDIO_FIELD_TYPE_INVALID",
                "MEDIUM",
                f"audio option fields have invalid type: {', '.join(sorted(invalid_type_fields))}",
            )
        )

    return findings


def _looks_like_image_config(payload: dict[str, Any]) -> bool:
    return any(key in payload for key in _IMAGE_DETECTION_KEYS)


def _looks_like_audio_config(payload: dict[str, Any]) -> bool:
    return any(key in payload for key in _AUDIO_DETECTION_KEYS)


def _is_valid_component_ref(value: Any) -> bool:
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, dict):
        return bool(value)
    if isinstance(value, list):
        return bool(value)
    return False


def _is_non_empty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _is_valid_image_dimension_spec(value: Any) -> bool:
    if _is_valid_positive_int(value, maximum=_IMAGE_DIMENSION_REVIEW_THRESHOLD):
        return True
    if isinstance(value, dict):
        return bool(value) and all(
            _is_valid_positive_int(item, maximum=_IMAGE_DIMENSION_REVIEW_THRESHOLD) for item in value.values()
        )
    if isinstance(value, list):
        return bool(value) and all(
            _is_valid_positive_int(item, maximum=_IMAGE_DIMENSION_REVIEW_THRESHOLD) for item in value
        )
    return False


def _is_valid_image_stat(value: Any, *, allow_zero: bool) -> bool:
    if not isinstance(value, list) or len(value) not in {1, 3, 4}:
        return False
    for item in value:
        if not _is_number(item):
            return False
        numeric = float(item)
        if allow_zero:
            if numeric < -10.0 or numeric > 10.0:
                return False
        elif numeric <= 0.0 or numeric > 10.0:
            return False
    return True


def _is_valid_positive_number(value: Any, *, maximum: float) -> bool:
    return _is_number(value) and 0.0 < float(value) <= maximum


def _is_valid_positive_int(value: Any, *, maximum: int) -> bool:
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        numeric = value
    elif isinstance(value, str) and value.strip().isdigit():
        numeric = int(value.strip())
    else:
        return False
    return 0 < numeric <= maximum


def _is_number(value: Any) -> bool:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    try:
        return math.isfinite(float(value))
    except OverflowError:
        return False


def _is_valid_image_format(key: str, value: Any) -> bool:
    if not isinstance(value, str):
        return False
    normalized = value.lower()
    if key == "channel_order":
        return normalized in _CHANNEL_ORDER_VALUES
    return normalized in _DATA_FORMAT_VALUES


def _extract_chat_templates(file_kind: FileKind, source_text: str, payload: Any) -> list[str]:
    if file_kind is FileKind.CHAT_TEMPLATE_JINJA:
        return [source_text]
    if isinstance(payload, dict) and isinstance(payload.get("chat_template"), str):
        return [payload["chat_template"]]
    return []


def _chat_template_findings(template: str) -> list[dict[str, Any]]:
    lowered = template.lower()
    findings = [
        _finding(
            "CHAT_TEMPLATE_PRESENT",
            "INFO",
            "Chat template controls how messages become model input.",
        )
    ]
    if "system" in lowered:
        findings.append(_finding("CHAT_TEMPLATE_SYSTEM_ROLE_LITERAL", "INFO", "System role literal is present."))
    if "user" in lowered:
        findings.append(_finding("CHAT_TEMPLATE_USER_ROLE_LITERAL", "INFO", "User role literal is present."))
    if "assistant" in lowered:
        findings.append(
            _finding("CHAT_TEMPLATE_ASSISTANT_ROLE_LITERAL", "INFO", "Assistant role literal is present.")
        )
    if "tool" in lowered or "tools" in lowered:
        findings.append(_finding("CHAT_TEMPLATE_TOOL_BRANCH_PRESENT", "INFO", "Tool branch/literal is present."))
    if "document" in lowered or "documents" in lowered:
        findings.append(
            _finding("CHAT_TEMPLATE_DOCUMENT_BRANCH_PRESENT", "INFO", "Document/RAG branch literal is present.")
        )
    if "add_generation_prompt" in lowered:
        findings.append(
            _finding(
                "CHAT_TEMPLATE_GENERATION_PROMPT_CHANGED",
                "INFO",
                "Generation prompt control is present in the template.",
            )
        )
        findings.append(
            _finding(
                "CHAT_TEMPLATE_ADD_GENERATION_PROMPT_PRESENT",
                "INFO",
                "add_generation_prompt control is present in the template.",
            )
        )
    if "system" in lowered and any(hint in lowered for hint in _HIDDEN_SYSTEM_HINTS):
        findings.append(
            _finding(
                "CHAT_TEMPLATE_HIDDEN_SYSTEM_INJECTION",
                "HIGH",
                "Template contains system-role text with hidden-instruction indicators.",
            )
        )
    return findings


def _semantic_check_status(
    *,
    baseline_text: str | None,
    source_text: str,
    parse_error: str | None,
    findings: list[dict[str, Any]],
) -> str:
    if parse_error is not None:
        return "ERROR"
    if any(item["code"] == "CHAT_TEMPLATE_HIDDEN_SYSTEM_INJECTION" for item in findings):
        return "FAILED"
    if baseline_text is None:
        return "BASELINE_MISSING"
    if _sha256_text(source_text) != _sha256_text(baseline_text):
        return "REVIEW"
    if _has_review_findings(findings):
        return "REVIEW"
    return "PASSED"


def _decision_for_semantic_status(
    check_status: str,
    findings: list[dict[str, Any]],
) -> tuple[CodeGrade, ValidationStatus, ReviewAction, str]:
    if check_status == "PASSED":
        return CodeGrade.B1, ValidationStatus.PASS, ReviewAction.AUTO_APPROVE, "SEMANTIC_CHECK_PASSED"
    if check_status == "FAILED":
        return (
            CodeGrade.C,
            ValidationStatus.PENDING_REVIEW,
            ReviewAction.MANUAL_REVIEW_REQUIRED,
            _primary_reason_code(findings),
        )
    if check_status == "ERROR":
        return CodeGrade.B2, ValidationStatus.PENDING_REVIEW, ReviewAction.SECURITY_OWNER_GATE, "SEMANTIC_PARSE_ERROR"
    if check_status == "BASELINE_MISSING":
        return CodeGrade.B2, ValidationStatus.PENDING_REVIEW, ReviewAction.SECURITY_OWNER_GATE, "BASELINE_MISSING"
    return CodeGrade.B2, ValidationStatus.PENDING_REVIEW, ReviewAction.SECURITY_OWNER_GATE, "SEMANTIC_REVIEW_REQUIRED"


def _primary_reason_code(findings: list[dict[str, Any]]) -> str:
    for finding in findings:
        if finding.get("severity") == "HIGH":
            return str(finding.get("code"))
    return "SEMANTIC_REVIEW_REQUIRED"


def _has_review_findings(findings: list[dict[str, Any]]) -> bool:
    ignored_codes = {"BASELINE_MISSING", "SEMANTIC_BASELINE_DELTA"}
    for finding in findings:
        if finding.get("code") in ignored_codes:
            continue
        if finding.get("severity") in {"LOW", "MEDIUM", "HIGH"}:
            return True
    return False


def _semantic_finding_codes(findings: list[dict[str, Any]]) -> list[str]:
    codes: list[str] = []
    for finding in findings:
        code = finding.get("code")
        if isinstance(code, str) and code not in codes:
            codes.append(code)
    return codes


def _normalize_sandbox_fuzz_result(
    sandbox_fuzz_result: SemanticFuzzResult | Mapping[str, Any] | None,
) -> dict[str, Any] | None:
    if sandbox_fuzz_result is None:
        return None
    if isinstance(sandbox_fuzz_result, SemanticFuzzResult):
        return sandbox_fuzz_result.to_dict()
    if isinstance(sandbox_fuzz_result, Mapping):
        return dict(sandbox_fuzz_result)
    return {
        "schema_version": SANDBOX_FUZZ_EVIDENCE_SCHEMA_VERSION,
        "status": "ERROR",
        "review_required": True,
        "runtime_events": [
            {
                "event_type": "invalid_sandbox_fuzz_result",
                "severity": "HIGH",
                "message": "sandbox fuzz result must be a SemanticFuzzResult or mapping",
                "metadata": {},
            }
        ],
    }


def _sandbox_fuzz_not_run() -> dict[str, Any]:
    return {
        "schema_version": SANDBOX_FUZZ_EVIDENCE_SCHEMA_VERSION,
        "status": "NOT_RUN",
        "review_required": False,
        "runner_interface": "opt_in_only",
        "default_validation_path_imports_untrusted_processor": False,
    }


def _sandbox_fuzz_review_finding(sandbox_fuzz: dict[str, Any]) -> dict[str, Any]:
    status = str(sandbox_fuzz.get("status") or "UNKNOWN")
    cases = sandbox_fuzz.get("cases", [])
    case_count = len(cases) if isinstance(cases, list) else 0
    baseline_diff = sandbox_fuzz.get("baseline_diff", {})
    baseline_available = (
        baseline_diff.get("baseline_available")
        if isinstance(baseline_diff, dict)
        else None
    )
    return _finding(
        "SANDBOX_FUZZ_EVIDENCE_REVIEW",
        "MEDIUM",
        (
            "Sandbox fuzz evidence is opt-in review evidence only; "
            f"status={status}, cases={case_count}, baseline_available={baseline_available}."
        ),
    )


def _finding(code: str, severity: str, evidence: str) -> dict[str, Any]:
    return {
        "code": code,
        "severity": severity,
        "evidence": [evidence],
        "recommended_action": "review preprocessing semantic impact",
    }


def _dedupe_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    deduped: list[dict[str, Any]] = []
    seen: set[str] = set()
    for finding in findings:
        code = str(finding.get("code"))
        if code in seen:
            continue
        seen.add(code)
        deduped.append(finding)
    return deduped


def _reason_message(code: str) -> str:
    return {
        "BASELINE_MISSING": "baseline is missing, semantic preservation cannot be proven",
        "SEMANTIC_PARSE_ERROR": "preprocessing metadata could not be parsed",
        "CHAT_TEMPLATE_HIDDEN_SYSTEM_INJECTION": "chat template contains hidden system-instruction indicators",
        "SEMANTIC_REVIEW_REQUIRED": "preprocessing metadata requires semantic review",
        "SEMANTIC_CHECK_PASSED": "preprocessing semantic check passed against baseline",
    }.get(code, "preprocessing metadata requires semantic review")


def _to_source_text(source: str | bytes | None) -> str:
    if source is None:
        return ""
    if isinstance(source, bytes):
        return source.decode("utf-8", errors="replace")
    return source


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _build_cache_key(artifact: ArtifactRef, policy: PolicyInfo | None) -> str:
    policy_fingerprint = getattr(policy, "policy_fingerprint", None) or "no-policy"
    return f"{artifact.sha256}:{artifact.file_kind.value}:{policy_fingerprint}:preprocessing-semantic"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
