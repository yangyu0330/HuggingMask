"""
mock_hf 픽스처 통합 테스트 — 코드 검증자(양유상) ↔ 화이트리스트 엔진(김민우) 흐름

검증하는 것:
  - hm-04 (악성 코드): 우리 엔진이 builtins.__import__를 BLOCKED로 신호 → 코드 검증자가 등급 C로 판정 가능
  - hm-05 (안전 코드 + 악성 config): 우리 엔진이 BLOCKED 신호 안 줘야 (모두 ALLOWED/PENDING) → 차단은 config 검증자 책임

책임 경계 검증 (engine.md:21):
  우리 엔진은 코드 등급(A/B-1/B-2/C)을 결정하지 않는다.
  단지 per-API status만 반환한다. 등급은 양유상의 코드 검증자가 결정한다.
"""

from pathlib import Path

import pytest

from tests.integration._simulated_code_validator import extract_apis
from whitelist.engine import WhitelistEngine
from whitelist.models import (
    EndpointMode, ModelRef, WhitelistCheckRequest, WhitelistStatus,
    WhitelistSource,
)
from whitelist.rules import WHITELIST_VERSION
from whitelist.tables import ApprovedApi


REPO_ROOT = Path(__file__).resolve().parent.parent.parent
MOCK_HF = REPO_ROOT / "mock_hf"


def _seed_initial(db):
    """시드 145개 API를 인메모리 DB에 로드 (production bootstrap.py와 동일)"""
    from whitelist.seed import get_seed_with_namespaces
    for api_path, namespace in get_seed_with_namespaces():
        db.add(ApprovedApi(
            api_path=api_path, namespace=namespace,
            source=WhitelistSource.INITIAL,
            matched_rule=namespace + ".*",
            source_version=WHITELIST_VERSION,
            is_blocked=False,
        ))
    db.commit()


def _make_request(repo_id: str, apis: list[str]) -> WhitelistCheckRequest:
    import uuid
    return WhitelistCheckRequest(
        schema_version="1.0",
        request_id=str(uuid.uuid4()),
        job_id=str(uuid.uuid4()),
        model=ModelRef(
            repo_id=repo_id, revision="main",
            source_host="huggingface.co",
            source_url=f"https://huggingface.co/{repo_id}",
            requested_by="test", requested_at="2026-04-20T09:00:00Z",
            endpoint_mode=EndpointMode.HF_ENDPOINT_PROXY,
        ),
        apis=apis,
    )


# ─────────────────────────────────────────────
# AST 추출기 단위 검증 — 시뮬레이션 코드가 의도대로 동작하는지
# ─────────────────────────────────────────────

class TestSimulatedExtractor:

    def test_resolves_aliased_imports(self):
        src = "from torch import nn\nx = nn.Linear(2, 2)"
        apis = extract_apis(src)
        assert "torch.nn" in apis
        assert "torch.nn.Linear" in apis

    def test_normalizes_bare_builtins(self):
        """__import__는 builtins.__import__로 정규화되어야 우리 엔진이 차단할 수 있다"""
        src = '_ = __import__("os")'
        apis = extract_apis(src)
        assert "builtins.__import__" in apis

    def test_extracts_class_bases(self):
        src = "from torch import nn\nclass M(nn.Module): pass"
        apis = extract_apis(src)
        assert "torch.nn.Module" in apis

    def test_syntax_error_safe(self):
        assert extract_apis("def broken(:") == set()


# ─────────────────────────────────────────────
# hm-04 통합 — 악성 코드 시나리오
# ─────────────────────────────────────────────

class TestHM04MaliciousCode:
    """expected_result.json:
        expected_overall_decision: DENY
        expected_grade: C
        expected_reason_codes: [DANGEROUS_CALL]

    우리 엔진의 책임: builtins.__import__가 BLOCKED로 응답되어야 함.
    그래야 양유상의 코드 검증자가 등급 C → DENY로 판정 가능.
    """

    @pytest.fixture
    def evil_source(self) -> str:
        path = MOCK_HF / "hm-04-bad-py-import" / "modeling_evil.py"
        return path.read_text(encoding="utf-8")

    def test_extractor_finds_dangerous_import_call(self, evil_source):
        """선결: AST 추출기가 __import__를 잡아낼 수 있는가"""
        apis = extract_apis(evil_source)
        assert "builtins.__import__" in apis

    def test_engine_blocks_dangerous_call(self, db_session, evil_source):
        _seed_initial(db_session)
        engine = WhitelistEngine()

        apis = sorted(extract_apis(evil_source))
        req = _make_request("hm-04-bad-py-import", apis)
        resp = engine.check_batch(req, db_session)

        by_path = {r.api_path: r for r in resp}

        # 핵심: dangerous call이 BLOCKED 신호를 받아야 함
        assert "builtins.__import__" in by_path
        assert by_path["builtins.__import__"].status == WhitelistStatus.BLOCKED, \
            f"기대: BLOCKED, 실제: {by_path['builtins.__import__'].status}"

    def test_at_least_one_blocked_signals_grade_c(self, db_session, evil_source):
        """양유상의 등급 결정 로직 시뮬레이션 — BLOCKED 하나라도 있으면 grade C"""
        _seed_initial(db_session)
        engine = WhitelistEngine()

        apis = sorted(extract_apis(evil_source))
        req = _make_request("hm-04-bad-py-import", apis)
        resp = engine.check_batch(req, db_session)

        blocked = [r for r in resp if r.status == WhitelistStatus.BLOCKED]
        assert len(blocked) >= 1, "BLOCKED API 없음 — 코드 검증자가 등급 C 판정 불가"

        # expected_result.json의 reason_code는 'DANGEROUS_CALL'.
        # 우리 응답의 reason 문구로 코드 검증자가 매핑할 수 있다.
        assert any("위험" in r.reason for r in blocked)

    def test_safe_apis_in_evil_file_still_allowed(self, db_session, evil_source):
        """악성 파일에 섞여있는 정상 API(torch.nn.Linear)는 여전히 ALLOWED여야 함"""
        _seed_initial(db_session)
        engine = WhitelistEngine()

        apis = sorted(extract_apis(evil_source))
        req = _make_request("hm-04-bad-py-import", apis)
        resp = engine.check_batch(req, db_session)

        by_path = {r.api_path: r for r in resp}
        assert by_path["torch.nn.Linear"].status == WhitelistStatus.ALLOWED


# ─────────────────────────────────────────────
# hm-05 통합 — 안전 코드 + 악성 config 시나리오
# ─────────────────────────────────────────────

class TestHM05SafeCodeBadConfig:
    """expected_result.json:
        expected_overall_decision: DENY
        expected_primary_stage: VALIDATE_CONFIG    ← 우리 엔진 아님!
        expected_grade: N/A
        expected_reason_codes: [CONFIG_TRIGGER_FIELD_FOUND]

    우리 엔진의 책임: 코드 자체는 안전하므로 BLOCKED 신호를 주면 안 됨.
    차단은 config 검증자(박용담)가 auto_map을 보고 결정한다.

    이 테스트는 우리 엔진이 책임 경계를 지키는지 검증한다 (engine.md:21).
    """

    @pytest.fixture
    def safe_source(self) -> str:
        path = MOCK_HF / "hm-05-bad-config-automap" / "modeling_safe.py"
        return path.read_text(encoding="utf-8")

    def test_no_blocked_signals_from_safe_code(self, db_session, safe_source):
        """안전 코드는 BLOCKED가 0개여야 함 — 차단은 우리 영역 아님"""
        _seed_initial(db_session)
        engine = WhitelistEngine()

        apis = sorted(extract_apis(safe_source))
        req = _make_request("hm-05-bad-config-automap", apis)
        resp = engine.check_batch(req, db_session)

        blocked = [r for r in resp if r.status == WhitelistStatus.BLOCKED]
        assert blocked == [], (
            f"안전 코드에서 BLOCKED 발생 — 책임 경계 위반: "
            f"{[(r.api_path, r.reason) for r in blocked]}"
        )

    def test_all_signals_are_allowed_or_pending(self, db_session, safe_source):
        """안전 코드의 모든 API는 ALLOWED 또는 (미등록이면) PENDING"""
        _seed_initial(db_session)
        engine = WhitelistEngine()

        apis = sorted(extract_apis(safe_source))
        req = _make_request("hm-05-bad-config-automap", apis)
        resp = engine.check_batch(req, db_session)

        valid_states = {WhitelistStatus.ALLOWED, WhitelistStatus.PENDING}
        for r in resp:
            assert r.status in valid_states, \
                f"{r.api_path}: 예상치 못한 status={r.status}"


# ─────────────────────────────────────────────
# expected_result.json 자동 검증
# ─────────────────────────────────────────────

class TestExpectedResultAlignment:
    """mock_hf의 expected_result.json과 우리 엔진 출력이 정합성을 갖는지.

    여기선 '우리 엔진이 코드 검증자에게 충분한 신호를 주는가'만 검증.
    실제 overall_decision, grade, reason_codes 결정은 양유상의 책임.
    """

    @pytest.mark.parametrize("scenario,source_file,must_have_blocked", [
        ("hm-04-bad-py-import", "modeling_evil.py", True),   # 악성 → BLOCKED 있어야
        ("hm-05-bad-config-automap", "modeling_safe.py", False),  # 안전 → BLOCKED 없어야
    ])
    def test_blocked_signal_alignment(
        self, db_session, scenario, source_file, must_have_blocked,
    ):
        _seed_initial(db_session)
        engine = WhitelistEngine()

        source = (MOCK_HF / scenario / source_file).read_text(encoding="utf-8")
        apis = sorted(extract_apis(source))
        req = _make_request(scenario, apis)
        resp = engine.check_batch(req, db_session)

        has_blocked = any(r.status == WhitelistStatus.BLOCKED for r in resp)

        if must_have_blocked:
            assert has_blocked, (
                f"{scenario}: 악성 시나리오인데 우리 엔진이 BLOCKED 신호 없음. "
                f"코드 검증자가 등급 C 판정 불가 → expected_result.json 위반"
            )
        else:
            assert not has_blocked, (
                f"{scenario}: 안전 코드인데 BLOCKED 발생 → 책임 경계 위반. "
                f"우리 엔진은 차단 신호 주면 안 됨 (차단은 다른 검증자 책임)"
            )
