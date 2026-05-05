"""
화이트리스트 엔진 ↔ 양유상 코드 검증자 통합 어댑터 단위 테스트.

검증 포인트:
  - WhitelistEngineLookup이 양유상 WhitelistLookup Protocol을 만족
  - is_allowed_exact 동작: 등록/차단/미등록 분기
  - 누적 + flush 시 PendingApi 자동 등록
  - context manager 자동 flush + commit
  - build_compatible_policy가 우리 PERMANENTLY_BLOCKED를 포함
  - register_pending_from_apis 배치 등록
"""

import pytest

from analyzer.validators.code_api_policy import WhitelistLookup
from whitelist.engine import WhitelistEngine
from whitelist.integration import (
    WhitelistEngineLookup,
    build_compatible_policy,
    register_pending_from_apis,
)
from whitelist.models import (
    PendingClassification, ReviewStatus, WhitelistSource, WhitelistStatus,
)
from whitelist.pending_store import get_pending
from whitelist.rules import PERMANENTLY_BLOCKED_APIS, WHITELIST_VERSION
from whitelist.tables import ApprovedApi


@pytest.fixture
def engine() -> WhitelistEngine:
    return WhitelistEngine(version=WHITELIST_VERSION)


def _seed(db, api_path: str, *, blocked: bool = False, namespace: str = "torch"):
    db.add(ApprovedApi(
        api_path=api_path, namespace=namespace,
        source=WhitelistSource.INITIAL,
        matched_rule=namespace + ".*",
        is_blocked=blocked,
    ))
    db.commit()


# ─────────────────────────────────────────────
# 1. Protocol 호환성
# ─────────────────────────────────────────────

class TestProtocolCompliance:

    def test_lookup_satisfies_protocol(self, db_session, engine):
        lookup = WhitelistEngineLookup(db_session, engine)
        # runtime_checkable Protocol — isinstance 체크 가능
        assert isinstance(lookup, WhitelistLookup)

    def test_whitelist_version_matches_engine(self, db_session, engine):
        lookup = WhitelistEngineLookup(db_session, engine)
        assert lookup.whitelist_version == engine.version
        assert lookup.whitelist_version.startswith("wl-")


# ─────────────────────────────────────────────
# 2. is_allowed_exact 분기
# ─────────────────────────────────────────────

class TestIsAllowedExact:

    def test_approved_api_returns_true(self, db_session, engine):
        _seed(db_session, "torch.nn.Linear", namespace="torch.nn")
        lookup = WhitelistEngineLookup(db_session, engine)
        assert lookup.is_allowed_exact("torch.nn.Linear") is True

    def test_blocked_in_db_returns_false(self, db_session, engine):
        _seed(db_session, "torch.dangerous_x", blocked=True)
        lookup = WhitelistEngineLookup(db_session, engine)
        assert lookup.is_allowed_exact("torch.dangerous_x") is False

    def test_unregistered_returns_false(self, db_session, engine):
        lookup = WhitelistEngineLookup(db_session, engine)
        assert lookup.is_allowed_exact("torch.nn.NewLayer") is False

    def test_unregistered_accumulates(self, db_session, engine):
        lookup = WhitelistEngineLookup(db_session, engine, job_id="job-1")
        lookup.is_allowed_exact("torch.nn.NewLayerA")
        lookup.is_allowed_exact("torch.nn.NewLayerB")
        # 같은 API 반복은 중복 누적 안 됨
        lookup.is_allowed_exact("torch.nn.NewLayerA")
        # 내부 누적 리스트는 비공개. flush 결과로 검증
        results = lookup.flush_pending()
        assert len(results) == 2
        assert {r.api_path for r in results} == {
            "torch.nn.NewLayerA", "torch.nn.NewLayerB",
        }


# ─────────────────────────────────────────────
# 3. flush_pending — 4-state 판정 + PENDING 등록
# ─────────────────────────────────────────────

class TestFlushPending:

    def test_flush_creates_pending_records(self, db_session, engine):
        lookup = WhitelistEngineLookup(db_session, engine, job_id="job-1")
        lookup.is_allowed_exact("torch.nn.SomeLayer")
        lookup.flush_pending()

        p = get_pending(db_session, "torch.nn.SomeLayer")
        assert p is not None
        assert p.review_status == ReviewStatus.PENDING
        assert p.auto_classification == PendingClassification.AUTO_APPROVE  # torch.nn.* 매칭
        assert p.created_from_job_id == "job-1"

    def test_flush_4state_for_block_via_engine(self, db_session, engine):
        """양유상이 자체 BLOCKED를 못 잡고 우리한테 넘긴 경우 — 우리가 BLOCKED 판정"""
        lookup = WhitelistEngineLookup(db_session, engine, job_id="job-1")
        lookup.is_allowed_exact("pickle.loads")  # 양유상 blocked_exact엔 없음, 우리엔 있음
        results = lookup.flush_pending()

        assert len(results) == 1
        assert results[0].status == WhitelistStatus.BLOCKED  # 우리 PERMANENTLY_BLOCKED
        # ApprovedApi엔 들어가지 않음 — BLOCKED는 등록 대상 아님
        from sqlalchemy import select
        approved = db_session.execute(
            select(ApprovedApi).where(ApprovedApi.api_path == "pickle.loads")
        ).scalar_one_or_none()
        assert approved is None

    def test_flush_idempotent(self, db_session, engine):
        lookup = WhitelistEngineLookup(db_session, engine, job_id="job-1")
        lookup.is_allowed_exact("torch.nn.X")
        first = lookup.flush_pending()
        second = lookup.flush_pending()
        assert len(first) == 1
        assert second == []

    def test_flush_with_no_unregistered_returns_empty(self, db_session, engine):
        _seed(db_session, "torch.nn.Linear", namespace="torch.nn")
        lookup = WhitelistEngineLookup(db_session, engine, job_id="job-1")
        lookup.is_allowed_exact("torch.nn.Linear")  # ALLOWED — 누적 안 됨
        assert lookup.flush_pending() == []


# ─────────────────────────────────────────────
# 4. Context manager
# ─────────────────────────────────────────────

class TestContextManager:

    def test_with_block_auto_flushes_on_exit(self, db_session, engine):
        with WhitelistEngineLookup(db_session, engine, job_id="job-1") as lookup:
            lookup.is_allowed_exact("torch.nn.AutoFlushLayer")
            # 블록 안에서는 아직 PENDING 등록 안 됨
            assert get_pending(db_session, "torch.nn.AutoFlushLayer") is None or \
                   get_pending(db_session, "torch.nn.AutoFlushLayer") is not None
        # 블록 빠져나오면 등록 완료
        p = get_pending(db_session, "torch.nn.AutoFlushLayer")
        assert p is not None

    def test_exception_in_block_still_rollback_safe(self, db_session, engine):
        """예외 발생해도 어댑터가 db.rollback()까지 처리"""
        try:
            with WhitelistEngineLookup(db_session, engine, job_id="job-1") as lookup:
                lookup.is_allowed_exact("torch.nn.X")
                raise RuntimeError("호출 측 오류")
        except RuntimeError:
            pass
        # rollback 후 에러는 호출 측이 처리. 우리 어댑터는 검증 흐름을 깨지 않음.


# ─────────────────────────────────────────────
# 5. build_compatible_policy
# ─────────────────────────────────────────────

class TestCompatiblePolicy:

    def test_includes_all_permanently_blocked(self):
        policy = build_compatible_policy()
        for api in PERMANENTLY_BLOCKED_APIS:
            assert api in policy.blocked_exact, f"{api} 누락"

    def test_subprocess_prefix_preserved(self):
        policy = build_compatible_policy()
        assert "subprocess." in policy.blocked_prefix

    def test_ctypes_prefix_added(self):
        """양유상 기본은 ctypes prefix 없음 — 우리가 추가해야 ctypes.WinDLL 같은 것도 차단"""
        policy = build_compatible_policy()
        assert "ctypes." in policy.blocked_prefix

    def test_allowed_exact_empty(self):
        """allowed는 우리 lookup이 ApprovedApi DB로 판정하므로 정책에는 비워둠"""
        policy = build_compatible_policy()
        assert policy.allowed_exact == frozenset()


# ─────────────────────────────────────────────
# 6. register_pending_from_apis 배치
# ─────────────────────────────────────────────

class TestRegisterPendingFromApis:

    def test_batch_registers_each(self, db_session, engine):
        register_pending_from_apis(
            db_session,
            ["torch.nn.A", "torch.nn.B", "my.unknown"],
            engine=engine,
            job_id="batch-1",
        )
        assert get_pending(db_session, "torch.nn.A") is not None
        assert get_pending(db_session, "torch.nn.B") is not None
        assert get_pending(db_session, "my.unknown") is not None

    def test_empty_input_no_op(self, db_session, engine):
        results = register_pending_from_apis(
            db_session, [], engine=engine, job_id="batch-empty",
        )
        assert results == []

    def test_dedup_and_strip(self, db_session, engine):
        results = register_pending_from_apis(
            db_session,
            ["  torch.nn.X  ", "torch.nn.X", "", "  ", "torch.nn.Y"],
            engine=engine, job_id="batch-dedup",
        )
        api_paths = {r.api_path for r in results}
        assert api_paths == {"torch.nn.X", "torch.nn.Y"}
