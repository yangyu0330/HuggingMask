import json

from analyzer.validators.code_api import scan_api_policy
from analyzer.validators.code_api_policy import build_in_memory_whitelist_lookup
from analyzer.validators.code_ast import extract_ast_candidates


def test_alias_resolution_from_stage4_ast_scan_result() -> None:
    source = (
        "import torch.nn.functional as F\n"
        "from torch import nn\n"
        "import os\n"
        "def run(x):\n"
        "    y = F.relu(x)\n"
        "    z = nn.Linear(4, 2)(x)\n"
        "    os.system('echo hi')\n"
        "    return y, z\n"
    )
    ast_scan = extract_ast_candidates("modeling_demo.py", source)
    result = scan_api_policy(ast_scan)

    assert result.alias_resolution["F.relu"] == "torch.nn.functional.relu"
    assert result.alias_resolution["nn.Linear"] == "torch.nn.Linear"
    assert result.alias_resolution["os.system"] == "os.system"
    assert "torch.nn.functional.relu" in result.allowed_apis
    assert "torch.nn.Linear" in result.allowed_apis
    assert "os.system" in result.blocked_apis


def test_blocked_and_risk_api_take_priority_over_allow_lookup() -> None:
    source = (
        "import os\n"
        "import requests\n"
        "import torch\n"
        "def run():\n"
        "    os.system('echo hi')\n"
        "    requests.get('https://example.com')\n"
        "    torch.load('weights.pt')\n"
    )
    ast_scan = extract_ast_candidates("modeling_risk.py", source)
    lookup = build_in_memory_whitelist_lookup(
        allowed_exact={"os.system", "requests.get", "torch.load"},
        whitelist_version="wl-test",
    )
    result = scan_api_policy(ast_scan, whitelist_lookup=lookup)

    assert "os.system" in result.blocked_apis
    assert "requests.get" in result.blocked_apis
    assert "torch.load" in result.blocked_apis
    assert "os.system" not in result.allowed_apis
    assert "requests.get" not in result.allowed_apis
    assert "torch.load" not in result.allowed_apis


def test_contextual_apis_are_not_name_only_blocked_in_stage5() -> None:
    source = (
        "import os\n"
        "from pathlib import Path\n"
        "def run():\n"
        "    open('vocab.json', 'r')\n"
        "    Path('x').open('r')\n"
        "    Path('x').read_text()\n"
        "    Path('x').write_text('ok')\n"
        "    os.path.join('a', 'b')\n"
        "    os.getenv('HOME')\n"
        "    os.environ.get('HOME')\n"
    )
    ast_scan = extract_ast_candidates("modeling_context.py", source)
    result = scan_api_policy(ast_scan)
    contextual = set(result.contextual_apis)

    assert "open" in contextual
    assert "os.path.join" in contextual
    assert "os.getenv" in contextual
    assert "os.environ.get" in contextual
    assert "pathlib.Path.open" in contextual
    assert "pathlib.Path.read_text" in contextual
    assert "pathlib.Path.write_text" in contextual
    assert "open" not in result.blocked_apis
    assert "os.path.join" not in result.blocked_apis
    assert "pathlib.Path.open" not in result.blocked_apis


def test_unregistered_api_is_collected_as_pending_candidate() -> None:
    source = (
        "import torch\n"
        "def run(x):\n"
        "    return torch.special.expit(x)\n"
    )
    ast_scan = extract_ast_candidates("modeling_unknown.py", source)
    result = scan_api_policy(ast_scan)

    assert "torch.special.expit" in result.unregistered_apis
    assert "torch.special.expit" in result.pending_api_refs
    assert "torch.special.expit" not in result.allowed_apis


def test_unresolved_call_with_dynamic_pattern_hits_step1_first() -> None:
    source = (
        "def run(module, name):\n"
        "    fn = getattr(module, name)\n"
        "    return fn()\n"
    )
    ast_scan = extract_ast_candidates("modeling_dynamic.py", source)
    result = scan_api_policy(ast_scan)

    assert "fn" in result.blocked_apis
    assert result.blocked_reason_by_api["fn"] == "UNRESOLVED_WITH_DYNAMIC_OR_OBFUSCATION"


def test_result_payload_is_json_serializable() -> None:
    source = (
        "import torch\n"
        "def run(x):\n"
        "    return torch.special.expit(x)\n"
    )
    ast_scan = extract_ast_candidates("modeling_payload.py", source)
    result = scan_api_policy(ast_scan)
    payload = result.to_dict()
    json.loads(json.dumps(payload))
    assert payload["pending_api_refs"] == ["torch.special.expit"]
