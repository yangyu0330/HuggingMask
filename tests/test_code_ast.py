import json

from analyzer.validators.code_ast import extract_ast_candidates


def test_import_function_method_class_and_call_candidates_are_extracted() -> None:
    source = (
        "import torch.nn.functional as F\n"
        "from pathlib import Path\n"
        "class DemoModel:\n"
        "    def __init__(self):\n"
        "        pass\n"
        "    def forward(self, x):\n"
        "        return F.relu(x)\n"
        "def helper(x):\n"
        "    return x\n"
    )
    result = extract_ast_candidates("modeling_demo.py", source)

    assert "torch.nn.functional" in result.imports
    assert "pathlib" in result.imports
    assert result.classes == ["DemoModel"]
    assert "DemoModel.__init__" in result.methods
    assert "DemoModel.forward" in result.methods
    assert result.functions == ["helper"]
    assert "F.relu" in result.raw_api_calls
    assert result.method_flags["has_init"] is True
    assert result.method_flags["has_forward"] is True


def test_base_class_list_is_extracted() -> None:
    source = (
        "import torch.nn as nn\n"
        "class DemoModel(nn.Module):\n"
        "    def forward(self, x):\n"
        "        return x\n"
    )
    result = extract_ast_candidates("modeling_base.py", source)
    assert "torch.nn.Module" in result.base_classes


def test_dangerous_import_candidates_are_extracted() -> None:
    source = (
        "import subprocess\n"
        "import socket\n"
        "import requests\n"
        "from urllib import parse\n"
        "import httpx\n"
    )
    result = extract_ast_candidates("imports.py", source)
    assert result.dangerous_imports == ["httpx", "requests", "socket", "subprocess", "urllib"]


def test_dangerous_call_candidates_are_extracted() -> None:
    source = (
        "import os\n"
        "import subprocess\n"
        "import numpy as np\n"
        "import pickle as pkl\n"
        "import torch\n"
        "def run(x):\n"
        "    eval('1+1')\n"
        "    exec('a=1')\n"
        "    compile('1+1', '<x>', 'eval')\n"
        "    __import__('json')\n"
        "    os.system('echo hi')\n"
        "    os.popen('echo hi')\n"
        "    subprocess.Popen(['echo','x'])\n"
        "    np.load('x.npy')\n"
        "    pkl.load(None)\n"
        "    torch.load('x.pt')\n"
        "    return x\n"
    )
    result = extract_ast_candidates("danger_calls.py", source)

    assert "eval" in result.dangerous_calls
    assert "exec" in result.dangerous_calls
    assert "compile" in result.dangerous_calls
    assert "__import__" in result.dangerous_calls
    assert "os.system" in result.dangerous_calls
    assert "os.popen" in result.dangerous_calls
    assert "subprocess.Popen" in result.dangerous_calls
    assert "numpy.load" in result.dangerous_calls
    assert "pickle.load" in result.dangerous_calls
    assert "torch.load" in result.dangerous_calls


def test_dynamic_pattern_candidates_are_extracted() -> None:
    source = (
        "def f(obj, n, b, d):\n"
        "    getattr(obj, 'x')\n"
        "    setattr(obj, 'x', 1)\n"
        "    delattr(obj, 'x')\n"
        "    globals()\n"
        "    locals()\n"
        "    type(n, b, d)\n"
        "if True:\n"
        "    import json\n"
    )
    result = extract_ast_candidates("dynamic.py", source)
    assert "getattr" in result.dynamic_patterns
    assert "setattr" in result.dynamic_patterns
    assert "delattr" in result.dynamic_patterns
    assert "globals" in result.dynamic_patterns
    assert "locals" in result.dynamic_patterns
    assert "type(name,bases,dict)" in result.dynamic_patterns
    assert "conditional_import" in result.dynamic_patterns


def test_obfuscation_pattern_candidates_are_extracted() -> None:
    source = (
        "def f():\n"
        "    chr(65)\n"
        "    ord('A')\n"
        "    bytes([65, 66]).decode('utf-8')\n"
    )
    result = extract_ast_candidates("obf.py", source)
    assert "chr" in result.obfuscation_patterns
    assert "ord" in result.obfuscation_patterns
    assert "bytes.decode" in result.obfuscation_patterns


def test_contextual_api_candidates_are_extracted_without_decision() -> None:
    source = (
        "import os\n"
        "from pathlib import Path\n"
        "def f():\n"
        "    open('vocab.json', 'r')\n"
        "    Path('x').open('r')\n"
        "    Path('x').read_text()\n"
        "    os.path.join('a', 'b')\n"
        "    os.getenv('HOME')\n"
        "    os.environ.get('HOME')\n"
    )
    result = extract_ast_candidates("contextual.py", source)
    assert "open" in result.contextual_api_candidates
    assert "Path.open" in result.contextual_api_candidates
    assert "Path.read_text" in result.contextual_api_candidates
    assert "os.path.join" in result.contextual_api_candidates
    assert "os.getenv" in result.contextual_api_candidates
    assert "os.environ.get" in result.contextual_api_candidates
    assert "open" not in result.dangerous_calls
    assert "os.path.join" not in result.dangerous_calls
    assert "Path.open" not in result.dangerous_calls


def test_parse_error_is_reported() -> None:
    result = extract_ast_candidates("broken.py", "def broken(:\n")
    assert result.parse_error is not None
    assert result.imports == []
    assert result.raw_api_calls == []
    assert result.dangerous_calls == []
    assert result.contextual_api_candidates == []


def test_result_payload_is_json_serializable() -> None:
    result = extract_ast_candidates("simple.py", "def f(x):\n    return x\n")
    payload = result.to_dict()
    json.loads(json.dumps(payload))
    assert payload["functions"] == ["f"]
    assert payload["repo_path"] == "simple.py"

