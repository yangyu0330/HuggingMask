"""Preprocessing metadata semantic inventory and fail-closed gate.

This validator does not import or execute model code.  It records tokenizer /
processor metadata that must be reviewed by later semantic checks and keeps
baseline-less checks out of the PASS path.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from typing import Any

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
        "sampling_rate",
        "padding_value",
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

# 커스텀 코드(trust_remote_code) 참조 필드 — 전처리 메타데이터가 이 필드를
# 가지면 모델 로드 시 저장소의 임의 .py가 실행될 수 있다. tokenizer_config.json /
# config.json은 config_validator가 별도로 링크 코드까지 스캔하지만,
# processor_config.json / preprocessor_config.json / special_tokens_map.json 등
# 2차 메타데이터는 이 의미 검사만 거치므로, 여기서 명시적 finding으로 surface해야
# BASELINE_MISSING 노이즈에 묻히지 않는다 (적대검증 2026-06-08 HIGH).
_CUSTOM_CODE_CLASS_KEYS = (
    "processor_class",
    "image_processor_class",
    "video_processor_class",
    "feature_extractor_class",
    "tokenizer_class",
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

_TOKENIZER_OPTION_KEYS = (
    "model_max_length",
    "padding_side",
    "truncation_side",
    "split_special_tokens",
    "clean_up_tokenization_spaces",
)

_ADDED_TOKEN_OPTION_KEYS = (
    "id",
    "content",
    "special",
    "single_word",
    "lstrip",
    "rstrip",
    "normalized",
)


def is_preprocessing_metadata_kind(file_kind: FileKind | str) -> bool:
    return FileKind(file_kind) in PREPROCESSING_METADATA_FILE_KINDS


def validate_preprocessing_metadata_artifact(
    artifact: ArtifactRef,
    source: str | bytes,
    policy: PolicyInfo | None = None,
    *,
    baseline_source: str | bytes | None = None,
) -> ArtifactValidationResult:
    """Build semantic inventory and keep uncertain metadata in review."""

    started_at = _utc_now()
    file_kind = FileKind(artifact.file_kind)
    source_text = _to_source_text(source)
    # 자동화 A: baseline 미지정이면 known-good 레지스트리 조회 — 등록된 정상본과 sha256
    # 일치 시 자기 자신을 baseline 으로 사용해 semantic preserved(자동 통과)로 처리한다.
    if baseline_source is None:
        from analyzer.validators.baseline_registry import lookup_baseline_source

        baseline_source = lookup_baseline_source(source_text)
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
    }

    if parse_error is not None:
        return inventory

    if isinstance(payload, dict):
        inventory["key_fields"] = _extract_key_fields(file_kind, payload)
        inventory.update(_extract_tokenizer_metadata_inventory(file_kind, payload))
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
    tokenizer_options = _tokenizer_options_inventory(file_kind, payload)

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


def _tokenizer_options_inventory(file_kind: FileKind, payload: dict[str, Any]) -> dict[str, Any]:
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
        "system": _contains_hint(lowered_template, "system"),
        "user": _contains_hint(lowered_template, "user"),
        "assistant": _contains_hint(lowered_template, "assistant"),
        "tool": _contains_hint(lowered_template, "tool") or _contains_hint(lowered_template, "tools"),
        "document": _contains_hint(lowered_template, "document") or _contains_hint(lowered_template, "documents"),
        "add_generation_prompt": "add_generation_prompt" in lowered_template,
    }


def _contains_hint(text: str, hint: str) -> bool:
    return hint in text


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

    findings.extend(_custom_code_findings(payload))

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


def _custom_code_findings(payload: Any) -> list[dict[str, Any]]:
    """전처리 메타데이터의 커스텀 코드(trust_remote_code) 참조를 명시적 finding으로.

    탐지 대상:
      - ``auto_map``  : Auto* 클래스를 ``module.Class`` 커스텀 코드에 매핑
      - ``custom_pipelines`` : ``impl: "module.Class"`` 커스텀 파이프라인
      - ``*_class`` 값에 ``.``(module 경로) 포함 — 인라인 커스텀 클래스 참조

    참조된 모듈/심볼 문자열을 evidence로 모아, 후속 리뷰/링크 스캔이
    어떤 코드를 봐야 하는지 알 수 있게 한다.
    """
    if not isinstance(payload, dict):
        return []

    references: list[str] = []

    auto_map = payload.get("auto_map")
    if isinstance(auto_map, dict) and auto_map:
        references.extend(sorted(_collect_code_refs(auto_map.values())))
    elif isinstance(auto_map, str) and auto_map:
        references.append(auto_map)

    custom_pipelines = payload.get("custom_pipelines")
    if isinstance(custom_pipelines, dict) and custom_pipelines:
        references.extend(sorted(_collect_code_refs(custom_pipelines.values())))

    for key in _CUSTOM_CODE_CLASS_KEYS:
        value = payload.get(key)
        if isinstance(value, str) and "." in value:
            references.append(f"{key}={value}")

    if not references:
        return []

    deduped_refs = sorted(dict.fromkeys(references))
    return [
        _finding(
            "PREPROCESSING_CUSTOM_CODE_REF",
            "HIGH",
            "preprocessing metadata references custom code (trust_remote_code): "
            + ", ".join(deduped_refs[:20]),
        )
    ]


def _collect_code_refs(values: Any) -> list[str]:
    """auto_map / custom_pipelines 값에서 ``module.Class`` 문자열을 평탄화 추출."""
    refs: list[str] = []
    for value in values:
        if isinstance(value, str):
            if value:
                refs.append(value)
        elif isinstance(value, (list, tuple)):
            refs.extend(item for item in value if isinstance(item, str) and item)
        elif isinstance(value, dict):
            refs.extend(_collect_code_refs(value.values()))
    return refs


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
    # HIGH 심각도 finding(숨은 시스템 주입 / 커스텀 코드 참조 등)은 baseline
    # 유무와 무관하게 FAILED로 격상 — BASELINE_MISSING 노이즈에 묻히지 않게.
    if any(item.get("severity") == "HIGH" for item in findings):
        return "FAILED"
    if baseline_text is None:
        # 자동화 B(opt-in): baseline 없어도 '실행 위협' finding 이 0(BASELINE_MISSING 외
        # 다른 finding 없음)이면 구조적으로 안전 → 의미 불변식 통과로 본다.
        # HIGH(커스텀코드/인젝션)는 위에서 이미 FAILED, MEDIUM(네트워크/경로)이 있으면
        # 검토대기 유지. baseline-proven(A)과 구분되는 별도 PASS 코드로 감사 가시성 유지.
        if _invariants_pass_enabled():
            other = [f for f in findings if f.get("code") != "BASELINE_MISSING"]
            if not other:
                return "INVARIANTS_OK"
        return "BASELINE_MISSING"
    if _sha256_text(source_text) != _sha256_text(baseline_text):
        return "REVIEW"
    return "PASSED"


def _invariants_pass_enabled() -> bool:
    """B 계층(baseline 없이 구조 안전 시 자동 통과) 활성 여부 — opt-in."""
    return os.getenv("HUGGINGMASK_PREPROCESSING_INVARIANTS", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _decision_for_semantic_status(
    check_status: str,
    findings: list[dict[str, Any]],
) -> tuple[CodeGrade, ValidationStatus, ReviewAction, str]:
    if check_status == "PASSED":
        return CodeGrade.B1, ValidationStatus.PASS, ReviewAction.AUTO_APPROVE, "SEMANTIC_CHECK_PASSED"
    if check_status == "INVARIANTS_OK":
        return CodeGrade.B2, ValidationStatus.PASS, ReviewAction.AUTO_APPROVE, "PREPROCESSING_INVARIANTS_OK"
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
        "PREPROCESSING_CUSTOM_CODE_REF": "preprocessing metadata references custom code (trust_remote_code) requiring review",
        "SEMANTIC_REVIEW_REQUIRED": "preprocessing metadata requires semantic review",
        "SEMANTIC_CHECK_PASSED": "preprocessing semantic check passed against baseline",
        "PREPROCESSING_INVARIANTS_OK": "no baseline, but structurally safe (no custom code / injection / network-path); passed invariant checks",
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
