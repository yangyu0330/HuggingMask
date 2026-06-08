"""코드 AST 데이터플로우 보강(#3) 회귀 테스트.

표적 우회(변수 별칭 / getattr 리터럴 / 문자열 조립 함수명)를 정적 정확매칭으로
해소해 dynamic/PENDING이 아니라 BLOCK으로 끌어올린다. 안전 코드 오탐은 없어야 함.
"""
import pytest

from analyzer.classifier import build_artifact_ref
from analyzer.schemas import ValidationStatus
from analyzer.validators.code_ast import extract_ast_candidates
from analyzer.validators.code_validator import validate_python_artifact


# ── AST 레벨: 우회가 dangerous_calls로 해소되는가 ──────────────────────────
@pytest.mark.parametrize("src,expected", [
    ('import os\ngetattr(os, "system")("id")\n', "os.system"),          # getattr 리터럴
    ('import os\ngetattr(os, "sys" + "tem")("id")\n', "os.system"),     # 문자열 조립
    ('import os\ns = os.system\ns("id")\n', "os.system"),               # 변수 별칭
    ('e = eval\ne("1+1")\n', "eval"),                                   # 위험 leaf 별칭
    ('getattr(__builtins__, "eval")("1")\n', "__builtins__.eval"),      # builtins getattr
    ('import os\nm = os\ngetattr(m, "system")("id")\n', "os.system"),   # 객체 별칭 + getattr
])
def test_evasion_resolved_to_dangerous_call(src, expected):
    result = extract_ast_candidates("m.py", src)
    assert expected in result.dangerous_calls, result.dangerous_calls


def test_string_concat_attr_flagged_as_obfuscation():
    result = extract_ast_candidates("m.py", 'import os\ngetattr(os, "sys" + "tem")("x")\n')
    assert "getattr_string_concat" in result.obfuscation_patterns


# ── 오탐 방지: 안전 코드는 dangerous_calls 비어 있어야 ───────────────────────
@pytest.mark.parametrize("src", [
    "class M:\n    def forward(self, x):\n        return self.fc(x)\n",
    "class M:\n    def f(self):\n        return getattr(self, 'forward')()\n",   # 동적이지만 benign
    "import torch\nx = torch.nn.Linear(8, 8)\n",
    "def g(o, n):\n    return getattr(o, n)\n",  # 비상수 attr → 해소 불가, dangerous 아님
])
def test_safe_code_not_flagged_dangerous(src):
    result = extract_ast_candidates("m.py", src)
    assert result.dangerous_calls == [], result.dangerous_calls


# ── 스코프/순서 정밀도: 별칭 오탐 방지(양유상 PR #57 리뷰 재현) ──────────────
@pytest.mark.parametrize("src", [
    # 다른 함수의 지역 alias가 콜백 파라미터 f(...)를 오염시키면 안 됨
    "import os\n"
    "def apply_callback(f, x):\n"
    "    return f(x)\n"
    "def unused_helper():\n"
    "    f = os.system\n"
    "    return f\n",
    # 파라미터 shadowing은 전역 alias보다 우선
    "import os\n"
    "f = os.system\n"
    "def forward(f, x):\n"
    "    return f(x)\n",
    # 호출 뒤의 alias 대입은 앞선 호출에 적용되면 안 됨
    "import os\n"
    "def forward(x):\n"
    "    f = lambda y: y\n"
    "    return f(x)\n"
    "f = os.system\n",
    # 조건부 재대입은 승격하지 않음(불확실 → 미해소)
    "import os\n"
    "def run(flag, x):\n"
    "    f = print\n"
    "    if flag:\n"
    "        f = os.system\n"
    "    return f(x)\n",
    # 람다 파라미터 shadowing
    "import os\n"
    "f = os.system\n"
    "g = lambda f: f(1)\n",
    # 컴프리헨션 타깃 shadowing
    "import os\n"
    "f = os.system\n"
    "ys = [f(1) for f in items]\n",
])
def test_alias_scope_and_order_no_false_positive(src):
    result = extract_ast_candidates("m.py", src)
    assert result.dangerous_calls == [], result.dangerous_calls


def test_alias_chain_resolves_in_straight_line():
    # 직선 실행에서 별칭 체이닝(t = s = os.system)은 여전히 승격되어야 함
    result = extract_ast_candidates("m.py", "import os\ns = os.system\nt = s\nt('x')\n")
    assert "os.system" in result.dangerous_calls, result.dangerous_calls


# ── e2e: 우회가 통합 검증기에서 BLOCK 되는가 ────────────────────────────────
@pytest.mark.parametrize("body", [
    'import os\n        return getattr(os, "system")(d)',
    'import os\n        f = os.system\n        return f(d)',
    'import os\n        return getattr(os, "sys" + "tem")(d)',
])
def test_evasion_blocks_end_to_end(body):
    src = (
        "from torch import nn\n"
        "class M(nn.Module):\n"
        "    def forward(self, d):\n"
        f"        {body}\n"
    )
    ref = build_artifact_ref("modeling_x.py", content=src)
    res = validate_python_artifact(ref, source=src)
    assert res.status is ValidationStatus.BLOCK, (res.status, body)
