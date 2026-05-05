"""
양유상 코드 검증자 ↔ 우리 화이트리스트 엔진 end-to-end 통합 테스트.

흐름:
  1) mock_hf의 .py 소스 → ``extract_ast_candidates`` → AstScanResult
  2) ``WhitelistEngineLookup`` + ``build_compatible_policy`` 주입
  3) ``scan_api_policy(ast_scan, policy=, whitelist_lookup=)`` 호출
  4) 양유상의 ApiScanResult가 우리 정책 + 우리 lookup 기준으로 분류됐는지 검증
  5) 미등록 API가 자동으로 PendingApi 테이블에 등록됐는지 검증

이 테스트는 ``tests/integration/test_mock_hf_scenarios.py``의 시뮬레이션 stub과
달리 양유상 production 코드(``analyzer/validators/code_*.py``)를 그대로 호출한다.
"""

from pathlib import Path

import pytest

from analyzer.validators.code_api import scan_api_policy
from analyzer.validators.code_ast import extract_ast_candidates
from whitelist.engine import WhitelistEngine
from whitelist.integration import WhitelistEngineLookup, build_compatible_policy
from whitelist.models import (
    EndpointMode, ModelRef, WhitelistSource,
)
from whitelist.pending_store import get_pending
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


@pytest.fixture
def model_ref_e2e() -> ModelRef:
    return ModelRef(
        repo_id="e2e/test", revision="main",
        source_host="huggingface.co",
        source_url="https://huggingface.co/e2e/test",
        requested_by="e2e", requested_at="2026-05-06T00:00:00Z",
        endpoint_mode=EndpointMode.HF_ENDPOINT_PROXY,
    )


# ─────────────────────────────────────────────
# hm-04 (악성 코드) — production 코드 양유상 ↔ 우리 통합
# ─────────────────────────────────────────────

class TestHM04ViaYangyuPipeline:

    @pytest.fixture
    def evil_source(self) -> str:
        path = MOCK_HF / "hm-04-bad-py-import" / "modeling_evil.py"
        return path.read_text(encoding="utf-8")

    def test_yangyu_pipeline_blocks_dangerous_call(
        self, db_session, evil_source, model_ref_e2e,
    ):
        """end-to-end: extract_ast → scan_api_policy(우리 정책+lookup) → BLOCKED 신호 확인"""
        _seed_initial(db_session)
        ast_scan = extract_ast_candidates(
            "hm-04-bad-py-import/modeling_evil.py", evil_source,
        )
        engine = WhitelistEngine()
        policy = build_compatible_policy()

        with WhitelistEngineLookup(
            db_session, engine, job_id="e2e-hm04", model=model_ref_e2e,
        ) as lookup:
            result = scan_api_policy(ast_scan, policy=policy, whitelist_lookup=lookup)

        # 양유상 자체 정책 + 우리 PERMANENTLY_BLOCKED 통합 → 위험 호출 BLOCKED
        # (양유상 risk_exact엔 __import__가 있고, 우리 PERMANENTLY_BLOCKED엔 builtins.__import__)
        assert any(
            api == "__import__" or api == "builtins.__import__" or api.startswith("subprocess.")
            for api in result.blocked_apis
        ), f"위험 호출 BLOCKED 감지 실패. blocked={result.blocked_apis}"

    def test_safe_apis_in_evil_file_still_allowed(
        self, db_session, evil_source, model_ref_e2e,
    ):
        """악성 파일에 섞인 정상 API(torch.nn.Linear)는 ALLOWED로 분류"""
        _seed_initial(db_session)
        ast_scan = extract_ast_candidates(
            "hm-04-bad-py-import/modeling_evil.py", evil_source,
        )
        policy = build_compatible_policy()

        with WhitelistEngineLookup(
            db_session, WhitelistEngine(),
            job_id="e2e-hm04", model=model_ref_e2e,
        ) as lookup:
            result = scan_api_policy(ast_scan, policy=policy, whitelist_lookup=lookup)

        # 시드된 torch.nn.Linear가 used_apis에 있으면 allowed에 들어가야 함
        if "torch.nn.Linear" in result.used_apis:
            assert "torch.nn.Linear" in result.allowed_apis


# ─────────────────────────────────────────────
# hm-05 (안전 코드 + 악성 config) — 우리 엔진은 BLOCKED 신호 주면 안 됨
# ─────────────────────────────────────────────

class TestHM05ViaYangyuPipeline:

    @pytest.fixture
    def safe_source(self) -> str:
        path = MOCK_HF / "hm-05-bad-config-automap" / "modeling_safe.py"
        return path.read_text(encoding="utf-8")

    def test_safe_code_no_blocked_from_lookup(
        self, db_session, safe_source, model_ref_e2e,
    ):
        """안전 코드는 우리 lookup이 BLOCKED 신호를 주면 안 됨 (책임 경계).

        config trigger 차단은 박용담 config_validator의 책임이다.
        """
        _seed_initial(db_session)
        ast_scan = extract_ast_candidates(
            "hm-05-bad-config-automap/modeling_safe.py", safe_source,
        )
        policy = build_compatible_policy()

        with WhitelistEngineLookup(
            db_session, WhitelistEngine(),
            job_id="e2e-hm05", model=model_ref_e2e,
        ) as lookup:
            result = scan_api_policy(ast_scan, policy=policy, whitelist_lookup=lookup)

        # 양유상의 dynamic/obfuscation 정책 때문에 unresolved 호출이 BLOCKED 될 수
        # 있으나, 우리 lookup이 직접 BLOCKED 시킨 건 없어야 함.
        # 검증: 5번 단계(우리 lookup)에 도달한 API는 모두 ALLOWED 또는 unregistered.
        for api in result.allowed_apis:
            # ALLOWED는 우리가 True 반환한 것
            assert api in result.used_apis
        for api in result.blocked_apis:
            # BLOCKED는 양유상의 1·2·3번 정책에서 잡힌 것 (우리 lookup이 아님)
            reason = result.blocked_reason_by_api.get(api, "")
            assert reason in {
                "UNRESOLVED_WITH_DYNAMIC_OR_OBFUSCATION",
                "BLOCKED_BY_POLICY",
                "RISK_CATEGORY_BLOCK",
            }


# ─────────────────────────────────────────────
# 자동 PENDING 등록 검증 (어댑터의 핵심 부수효과)
# ─────────────────────────────────────────────

class TestAutoPendingRegistration:

    def test_unregistered_apis_become_pending_after_context_exit(
        self, db_session, model_ref_e2e,
    ):
        """양유상 검증 후 unregistered였던 API가 PendingApi에 자동 등록됨"""
        _seed_initial(db_session)
        # torch.nn.SomeBrandNewLayer는 시드 안 됨 (namespace 매칭은 됨 → AUTO_APPROVE 권고)
        source = (
            "from torch import nn\n"
            "class M(nn.Module):\n"
            "    def __init__(self):\n"
            "        super().__init__()\n"
            "        self.x = nn.SomeBrandNewLayer(2, 2)\n"
        )
        ast_scan = extract_ast_candidates("test/m.py", source)
        policy = build_compatible_policy()

        with WhitelistEngineLookup(
            db_session, WhitelistEngine(),
            job_id="auto-pending-1", model=model_ref_e2e,
        ) as lookup:
            scan_api_policy(ast_scan, policy=policy, whitelist_lookup=lookup)

        # context 종료 후 PendingApi 등록 확인
        p = get_pending(db_session, "torch.nn.SomeBrandNewLayer")
        assert p is not None, "scan_api_policy 후 unregistered가 PENDING으로 등록 안 됨"
        assert p.created_from_job_id == "auto-pending-1"
        assert p.matched_namespace_rule == "torch.nn.*"

    def test_already_seeded_api_does_not_create_pending(
        self, db_session, model_ref_e2e,
    ):
        """시드된 API는 ALLOWED → PENDING 생성 안 됨"""
        _seed_initial(db_session)
        source = (
            "from torch import nn\n"
            "class M(nn.Module):\n"
            "    def __init__(self):\n"
            "        super().__init__()\n"
            "        self.fc = nn.Linear(2, 2)  # 시드 포함\n"
        )
        ast_scan = extract_ast_candidates("test/m.py", source)
        policy = build_compatible_policy()

        with WhitelistEngineLookup(
            db_session, WhitelistEngine(),
            job_id="seeded-1", model=model_ref_e2e,
        ) as lookup:
            scan_api_policy(ast_scan, policy=policy, whitelist_lookup=lookup)

        # torch.nn.Linear는 시드되어 있으니 PENDING 생성 안 됨
        assert get_pending(db_session, "torch.nn.Linear") is None
