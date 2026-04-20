"""
Whitelist Engine 테스트 — tests/test_whitelist_engine.md 명세 구현

검증 포인트 (test_whitelist_engine.md 기준):
- block 규칙은 allow 규칙보다 우선한다.
- unknown API는 pending record로 남아야 한다.
- 같은 API가 반복 등장하면 seen_count가 증가해야 한다.
- AUTO_APPROVE 분류는 실제 승인 상태와 분리해서 검증한다.
"""

import pytest

from whitelist.engine import WhitelistEngine, get_engine
from whitelist.models import (
    PendingClassification, ReviewStatus, WhitelistSource, WhitelistStatus,
)
from whitelist.pending_store import get_pending
from whitelist.rules import WHITELIST_VERSION
from whitelist.tables import ApprovedApi


@pytest.fixture
def engine() -> WhitelistEngine:
    # singleton 캐시 회피 — 매 테스트 새 인스턴스
    return WhitelistEngine(version=WHITELIST_VERSION)


def _seed_approved(db, api_path: str, namespace: str = "torch"):
    db.add(ApprovedApi(
        api_path=api_path, namespace=namespace,
        source=WhitelistSource.INITIAL,
        matched_rule=namespace + ".*",
        is_blocked=False,
    ))
    db.commit()


# ─────────────────────────────────────────────
# 1. ALLOWED 판정
# ─────────────────────────────────────────────

class TestAllowed:

    def test_seeded_api_is_allowed(self, db_session, engine, check_request_factory):
        _seed_approved(db_session, "torch.nn.Linear", "torch.nn")
        req = check_request_factory(["torch.nn.Linear"])
        resp = engine.check_batch(req, db_session)

        assert len(resp.results) == 1
        r = resp.results[0]
        assert r.status == WhitelistStatus.ALLOWED
        assert r.source == WhitelistSource.INITIAL
        assert r.review_required is False
        assert r.whitelist_version == WHITELIST_VERSION

    def test_response_envelope_propagates_request_ids(
        self, db_session, engine, check_request_factory,
    ):
        req = check_request_factory(["torch.nn.Linear"])
        resp = engine.check_batch(req, db_session)
        assert resp.request_id == req.request_id
        assert resp.job_id == req.job_id
        assert resp.whitelist_version == WHITELIST_VERSION


# ─────────────────────────────────────────────
# 2. BLOCKED 판정 (block > allow 우선순위 — engine.md:21)
# ─────────────────────────────────────────────

class TestBlocked:

    @pytest.mark.parametrize("api", [
        "torch.load", "pickle.load", "pickle.loads", "numpy.load",
        "os.system", "subprocess.run", "subprocess.Popen",
        "builtins.eval", "builtins.exec", "builtins.__import__",
        "importlib.import_module", "yaml.unsafe_load",
    ])
    def test_permanently_blocked(self, db_session, engine, check_request_factory, api):
        req = check_request_factory([api])
        resp = engine.check_batch(req, db_session)
        r = resp.results[0]
        assert r.status == WhitelistStatus.BLOCKED
        assert r.source == WhitelistSource.INITIAL
        assert "위험" in r.reason

    def test_block_overrides_allow(self, db_session, engine, check_request_factory):
        """ApprovedApi에 등록되어 있어도 PERMANENTLY_BLOCKED는 BLOCKED 우선"""
        _seed_approved(db_session, "torch.load", "torch")
        req = check_request_factory(["torch.load"])
        resp = engine.check_batch(req, db_session)
        assert resp.results[0].status == WhitelistStatus.BLOCKED

    def test_db_blocked_entry(self, db_session, engine, check_request_factory):
        """수동 거부 결과(is_blocked=True)도 BLOCKED 반환"""
        db_session.add(ApprovedApi(
            api_path="torch.dangerous_custom",
            namespace="torch",
            source=WhitelistSource.MANUAL_REVIEW,
            is_blocked=True,
        ))
        db_session.commit()

        req = check_request_factory(["torch.dangerous_custom"])
        resp = engine.check_batch(req, db_session)
        assert resp.results[0].status == WhitelistStatus.BLOCKED
        assert resp.results[0].source == WhitelistSource.MANUAL_REVIEW


# ─────────────────────────────────────────────
# 3. PENDING 판정 (namespace 매칭 + 미등록)
# ─────────────────────────────────────────────

class TestPending:

    def test_unknown_api_in_known_namespace(
        self, db_session, engine, check_request_factory,
    ):
        """torch.nn.* 매칭되지만 DB 미등록 → PENDING"""
        req = check_request_factory(["torch.nn.NewLayer"])
        resp = engine.check_batch(req, db_session)

        r = resp.results[0]
        assert r.status == WhitelistStatus.PENDING
        assert r.matched_rule == "torch.nn.*"
        assert r.review_required is True

    def test_pending_record_created(
        self, db_session, engine, check_request_factory,
    ):
        """PENDING 응답 시 pending_apis에 레코드 자동 생성"""
        req = check_request_factory(["torch.nn.NovelLayer"])
        engine.check_batch(req, db_session)

        p = get_pending(db_session, "torch.nn.NovelLayer")
        assert p is not None
        assert p.seen_count == 1
        assert p.auto_classification == PendingClassification.AUTO_APPROVE
        assert p.review_status == ReviewStatus.PENDING  # 자동 승인 권고도 PENDING 유지!
        assert p.matched_namespace_rule == "torch.nn.*"
        assert p.created_from_job_id == req.job_id

    def test_repeated_api_increments_seen_count(
        self, db_session, engine, check_request_factory,
    ):
        """test_whitelist_engine.md:23 — 반복 등장 시 seen_count 증가"""
        for _ in range(3):
            req = check_request_factory(["torch.nn.RepeatedLayer"])
            engine.check_batch(req, db_session)

        p = get_pending(db_session, "torch.nn.RepeatedLayer")
        assert p.seen_count == 3

    def test_model_list_accumulates(
        self, db_session, engine, model_ref, check_request_factory,
    ):
        """다른 모델에서 같은 API 사용 시 model_list 누적"""
        from whitelist.models import EndpointMode, ModelRef as MR
        import uuid
        from whitelist.models import WhitelistCheckRequest

        for repo in ["org/model-a", "org/model-b", "org/model-a"]:
            req = WhitelistCheckRequest(
                schema_version="1.0",
                request_id=str(uuid.uuid4()),
                job_id=str(uuid.uuid4()),
                model=MR(
                    repo_id=repo, revision="main",
                    source_host="huggingface.co",
                    source_url=f"https://huggingface.co/{repo}",
                    requested_by="dev", requested_at="2026-04-20T09:00:00Z",
                    endpoint_mode=EndpointMode.HF_ENDPOINT_PROXY,
                ),
                apis=["torch.nn.MultiSourceLayer"],
            )
            engine.check_batch(req, db_session)

        p = get_pending(db_session, "torch.nn.MultiSourceLayer")
        assert set(p.model_list) == {"org/model-a", "org/model-b"}  # 중복 제거

    def test_documentation_url_inferred(
        self, db_session, engine, check_request_factory,
    ):
        req = check_request_factory(["torch.nn.SomeNewClass"])
        engine.check_batch(req, db_session)
        p = get_pending(db_session, "torch.nn.SomeNewClass")
        assert p.documentation_url is not None
        assert "pytorch.org" in p.documentation_url


# ─────────────────────────────────────────────
# 4. UNKNOWN 판정 (네임스페이스 매칭 안 됨)
# ─────────────────────────────────────────────

class TestUnknown:

    def test_unknown_namespace(self, db_session, engine, check_request_factory):
        req = check_request_factory(["my_custom_lib.SomeClass"])
        resp = engine.check_batch(req, db_session)
        r = resp.results[0]
        assert r.status == WhitelistStatus.UNKNOWN
        assert r.matched_rule is None
        assert r.review_required is True

    def test_unknown_still_creates_pending(
        self, db_session, engine, check_request_factory,
    ):
        """UNKNOWN도 보안 담당자 큐에 들어가야 함 (MANUAL 권고)"""
        req = check_request_factory(["my_custom_lib.UnknownClass"])
        engine.check_batch(req, db_session)

        p = get_pending(db_session, "my_custom_lib.UnknownClass")
        assert p is not None
        assert p.auto_classification == PendingClassification.MANUAL


# ─────────────────────────────────────────────
# 5. 위험 키워드 격상 (분류 권고에만 영향, 응답 status에는 영향 X)
# ─────────────────────────────────────────────

class TestRiskKeywordEscalation:

    def test_load_keyword_escalates_recommendation(
        self, db_session, engine, check_request_factory,
    ):
        """torch.nn.Module.load_state_dict — AUTO_APPROVE → MANUAL 격상"""
        req = check_request_factory(["torch.nn.Module.load_state_dict"])
        resp = engine.check_batch(req, db_session)

        # 응답 status는 PENDING (미등록이지만 namespace 매칭 됨)
        assert resp.results[0].status == WhitelistStatus.PENDING

        # auto_classification은 MANUAL로 격상되어야 함
        p = get_pending(db_session, "torch.nn.Module.load_state_dict")
        assert p.auto_classification == PendingClassification.MANUAL
        assert "load" in p.risk_keywords


# ─────────────────────────────────────────────
# 6. 자동 승인 권고 ≠ 실제 승인 (test_whitelist_engine.md:24)
# ─────────────────────────────────────────────

class TestAutoApproveIsRecommendationOnly:

    def test_auto_approve_pending_is_not_in_approved_table(
        self, db_session, engine, check_request_factory,
    ):
        """AUTO_APPROVE로 분류돼도 ApprovedApi에 들어가지 않는다"""
        req = check_request_factory(["torch.nn.SomeBrandNewLayer"])
        engine.check_batch(req, db_session)

        # ApprovedApi에는 없어야 함
        from sqlalchemy import select
        approved = db_session.execute(
            select(ApprovedApi).where(ApprovedApi.api_path == "torch.nn.SomeBrandNewLayer")
        ).scalar_one_or_none()
        assert approved is None

        # 다음 check 시에도 여전히 PENDING이지 ALLOWED 아님
        req2 = check_request_factory(["torch.nn.SomeBrandNewLayer"])
        resp = engine.check_batch(req2, db_session)
        assert resp.results[0].status == WhitelistStatus.PENDING


# ─────────────────────────────────────────────
# 7. 결정론성 (보안 시스템 핵심 요건)
# ─────────────────────────────────────────────

class TestDeterminism:

    def test_same_input_same_output(self, db_session, engine, check_request_factory):
        """100회 반복 분류해도 같은 결과"""
        statuses = set()
        for _ in range(100):
            req = check_request_factory(["torch.nn.Linear"])
            _seed_approved(db_session, "torch.nn.Linear", "torch.nn") if not db_session.execute(
                __import__("sqlalchemy").select(ApprovedApi)
                .where(ApprovedApi.api_path == "torch.nn.Linear")
            ).scalar_one_or_none() else None
            resp = engine.check_batch(req, db_session)
            statuses.add(resp.results[0].status)
        assert len(statuses) == 1

    def test_order_independence(self, db_session, engine, check_request_factory):
        import random
        apis = ["torch.load", "torch.nn.Linear", "numpy.array",
                "subprocess.run", "torch.nn.functional.relu"]
        _seed_approved(db_session, "torch.nn.Linear", "torch.nn")
        _seed_approved(db_session, "torch.nn.functional.relu", "torch.nn.functional")

        baseline = {}
        req = check_request_factory(apis.copy())
        for r in engine.check_batch(req, db_session).results:
            baseline[r.api_path] = r.status

        for _ in range(10):
            shuffled = apis.copy()
            random.shuffle(shuffled)
            req = check_request_factory(shuffled)
            resp = engine.check_batch(req, db_session)
            for r in resp.results:
                assert r.status == baseline[r.api_path]


# ─────────────────────────────────────────────
# 8. 통합 시나리오 — 인터페이스 정의서 예시 (14.1)
# ─────────────────────────────────────────────

class TestSpecExample:
    """문서 870-892행 예시와 동일 입력에서 932-940행 패턴이 나와야 함"""

    def test_spec_example_three_apis(self, db_session, engine, check_request_factory):
        _seed_approved(db_session, "torch.nn.Linear", "torch.nn")
        req = check_request_factory([
            "torch.nn.Linear",
            "torch.load",
            "torch.nn.functional.scaled_dot_product_attention",  # 시드 안 함
        ])
        resp = engine.check_batch(req, db_session)
        by_path = {r.api_path: r for r in resp.results}

        assert by_path["torch.nn.Linear"].status == WhitelistStatus.ALLOWED
        assert by_path["torch.load"].status == WhitelistStatus.BLOCKED
        # 시드 안 했으니 PENDING (namespace는 매칭됨)
        assert by_path["torch.nn.functional.scaled_dot_product_attention"].status == WhitelistStatus.PENDING
