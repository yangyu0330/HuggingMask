"""분류기 — 빌트인/로컬 데이터연산 자동승인 규칙 회귀.

LIBRARY_ROOTS 가 아닌 루트 + BENIGN_LEAF_NAMES 리프 → AUTO_APPROVE.
미지 라이브러리(UnknownClass)·모호 메서드(send)·위험 키워드(write)는 그대로 MANUAL.
실제 라이브러리 API 는 기존 namespace/위험 규칙대로.
"""

import pytest

from whitelist.engine import _Classifier
from whitelist.models import PendingClassification


@pytest.fixture(scope="module")
def classify():
    c = _Classifier()

    def _classify(api_path: str) -> PendingClassification:
        base, _ = c.match_namespace(api_path)
        risk = c.find_risk_keywords(api_path)
        return c.escalate(base, risk)

    return _classify


@pytest.mark.parametrize(
    "api_path",
    ["type", "len", "t.append", "t.extend", "vocab.update", "x.copy", "items.get", "s.split"],
)
def test_benign_builtin_or_local_auto_approves(classify, api_path):
    assert classify(api_path) is PendingClassification.AUTO_APPROVE


@pytest.mark.parametrize(
    "api_path",
    [
        "writer.write",                 # 위험 키워드(IO)
        "x.load_state",                 # load 키워드
        "my_custom_lib.UnknownClass",   # 미지 라이브러리 클래스 — 보수적 검토
        "conn.send",                    # 모호 메서드(네트워크 가능)
        "torch.utils.data.DataLoader",  # 라이브러리 namespace = MANUAL
        "shutil.copy",                  # 라이브러리 루트, namespace 미정의 → MANUAL
    ],
)
def test_dangerous_or_unknown_stays_manual(classify, api_path):
    assert classify(api_path) is PendingClassification.MANUAL


def test_safe_namespace_still_auto(classify):
    assert classify("torch.nn.Linear") is PendingClassification.AUTO_APPROVE


def test_blocked_namespace_still_blocked(classify):
    assert classify("os.system") is PendingClassification.BLOCKED
