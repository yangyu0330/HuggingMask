import json

from analyzer.validators.code_context import (
    BLOCK,
    REVIEW,
    SAFE,
    analyze_contextual_api_calls,
    analyze_env_call,
    analyze_file_mutation_call,
    analyze_open_call,
    analyze_os_call,
    analyze_path_call,
)


def _const(value: str) -> dict[str, object]:
    return {"kind": "constant_str", "value": value}


def _dynamic(name: str) -> dict[str, object]:
    return {"kind": "name", "value": name, "source": "function_arg"}


def _user_input(name: str) -> dict[str, object]:
    return {"kind": "name", "value": name, "source": "user_input", "is_user_input": True}


def test_analyze_open_call_resource_read_in_preprocessing_is_safe() -> None:
    finding = analyze_open_call(
        "open",
        {"api": "open", "args": [_const("vocab.json"), _const("r")]},
        file_role="PREPROCESSING",
    )
    assert finding.decision == SAFE
    assert finding.reason_code == "OPEN_RESOURCE_READ_SAFE"


def test_analyze_open_call_dynamic_read_is_review() -> None:
    finding = analyze_open_call(
        "open",
        {"api": "open", "args": [_dynamic("path"), _const("r")]},
        file_role="MODELING",
    )
    assert finding.decision == REVIEW
    assert finding.reason_code == "OPEN_USER_INPUT_PATH_REVIEW"


def test_analyze_open_call_write_mode_is_block() -> None:
    finding = analyze_open_call(
        "open",
        {"api": "open", "args": [_user_input("user_path"), _const("w")]},
        file_role="PREPROCESSING",
    )
    assert finding.decision == BLOCK
    assert finding.reason_code == "OPEN_WRITE_MODE_BLOCK"


def test_analyze_path_read_text_resource_is_safe() -> None:
    finding = analyze_path_call(
        "pathlib.Path.read_text",
        {
            "api": "pathlib.Path.read_text",
            "path_arg": _const("tokenizer_config.json"),
        },
        file_role="PREPROCESSING",
    )
    assert finding.decision == SAFE
    assert finding.reason_code == "PATH_READ_RESOURCE_SAFE"


def test_analyze_path_write_text_is_block() -> None:
    finding = analyze_path_call(
        "pathlib.Path.write_text",
        {"api": "pathlib.Path.write_text", "path_arg": _const("out.txt")},
        file_role="MODELING",
    )
    assert finding.decision == BLOCK
    assert finding.category == "file_mutation"


def test_analyze_path_open_mode_is_same_rule_as_open() -> None:
    finding = analyze_path_call(
        "pathlib.Path.open",
        {
            "api": "pathlib.Path.open",
            "path_arg": _const("vocab.json"),
            "args": [_const("w")],
        },
        file_role="PREPROCESSING",
    )
    assert finding.decision == BLOCK
    assert finding.reason_code == "OPEN_WRITE_MODE_BLOCK"


def test_analyze_os_path_helper_constant_join_is_safe() -> None:
    finding = analyze_os_call(
        "os.path.join",
        {"api": "os.path.join", "args": [_const("a"), _const("b")]},
        file_role="MODELING",
    )
    assert finding.decision == SAFE
    assert finding.category == "path_helper"


def test_analyze_os_path_helper_user_input_is_review() -> None:
    finding = analyze_os_call(
        "os.path.join",
        {"api": "os.path.join", "args": [_user_input("in_path"), _const("b")]},
        file_role="MODELING",
    )
    assert finding.decision == REVIEW
    assert finding.reason_code == "PATH_HELPER_USER_INPUT_REVIEW"


def test_analyze_env_call_always_review_and_keeps_sensitive_flow_evidence() -> None:
    finding = analyze_env_call(
        "os.getenv",
        {
            "api": "os.getenv",
            "args": [_const("HF_TOKEN")],
            "usage_tags": ["token", "network"],
        },
        file_role="MODELING",
    )
    assert finding.decision == REVIEW
    assert finding.reason_code == "ENV_ACCESS_SENSITIVE_FLOW_REVIEW"
    assert any("usage_tags=network,token" == item for item in finding.evidence)


def test_analyze_file_mutation_call_is_block() -> None:
    finding = analyze_file_mutation_call(
        "os.remove",
        {"api": "os.remove", "args": [_dynamic("path")]},
        file_role="MODELING",
    )
    assert finding.decision == BLOCK
    assert finding.reason_code == "FILE_MUTATION_BLOCK"


def test_dispatcher_routes_api_types_and_summary_decision() -> None:
    contextual_apis = [
        "open",
        "pathlib.Path.read_text",
        "os.path.join",
        "os.getenv",
        "pathlib.Path.write_text",
        "requests.get",
        "os.system",
    ]
    ast_call_metadata = [
        {"api": "open", "args": [_const("vocab.json"), _const("r")]},
        {"api": "pathlib.Path.read_text", "path_arg": _const("tokenizer.json")},
        {"api": "os.path.join", "args": [_const("a"), _const("b")]},
        {"api": "os.getenv", "args": [_const("HOME")]},
        {"api": "pathlib.Path.write_text", "path_arg": _const("tmp.txt"), "args": [_const("x")]},
        {"api": "requests.get", "args": [_const("https://example.com")]},
        {"api": "os.system", "args": [_const("echo hi")]},
    ]

    scan = analyze_contextual_api_calls(
        contextual_apis,
        ast_call_metadata,
        file_role="PREPROCESSING",
    )

    assert scan.summary_decision == BLOCK
    assert any(item.api == "open" and item.decision == SAFE for item in scan.open_calls)
    assert any(item.api == "pathlib.Path.read_text" and item.decision == SAFE for item in scan.open_calls)
    assert any(item.api == "os.path.join" and item.decision == SAFE for item in scan.path_helper_calls)
    assert any(item.api == "os.getenv" and item.decision == REVIEW for item in scan.env_access_calls)
    assert any(item.api == "pathlib.Path.write_text" and item.decision == BLOCK for item in scan.file_mutation_calls)
    assert any(item.api == "requests.get" and item.decision == BLOCK for item in scan.network_calls)
    assert any(item.api == "os.system" and item.decision == BLOCK for item in scan.command_exec_calls)
    assert any(item.api == "os.getenv" for item in scan.os_calls)
    assert any(item.api == "os.path.join" for item in scan.os_calls)


def test_context_api_scan_payload_is_json_serializable() -> None:
    scan = analyze_contextual_api_calls(
        ["open"],
        [{"api": "open", "args": [_const("tokenizer.json"), _const("r")]}],
        file_role="PREPROCESSING",
    )
    payload = scan.to_dict()
    assert payload["summary_decision"] == SAFE
    json.loads(json.dumps(payload))
