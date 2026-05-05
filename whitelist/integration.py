"""
양유상 코드 검증자 ↔ 우리 화이트리스트 엔진 통합 어댑터.

양유상 측은 ``analyzer/validators/code_api_policy.py``의 ``WhitelistLookup``
프로토콜(``whitelist_version`` 속성 + ``is_allowed_exact(api) -> bool``)만
요구한다. 그 단일 hook 위에 4-state 판정과 PENDING 자동 등록을 얹는다.

설계 원칙:
- 양유상 코드를 수정하지 않는다. ``scan_api_policy``의 5번 단계에서
  ``lookup.is_allowed_exact()`` 한 번 호출되는 구조를 그대로 활용한다.
- 양유상의 1·2·3번 정책(자체 BLOCKED/RISK)이 우리의 PERMANENTLY_BLOCKED를
  놓치지 않도록 ``build_compatible_policy()``로 우리 영구 차단 목록을 주입한다.
- ``is_allowed_exact()``이 False를 반환한 API는 누적해뒀다가 context manager
  종료 시점에 ``engine.check_batch()``로 PENDING 등록 + commit한다.
"""

from __future__ import annotations

from typing import Iterable

from sqlalchemy import select
from sqlalchemy.orm import Session

from analyzer.validators.code_api_policy import (
    ApiPolicy,
    DEFAULT_POLICY_VERSION,
    default_api_policy,
)
from whitelist.engine import WhitelistEngine, get_engine
from whitelist.models import (
    ModelRef, WhitelistCheckRequest, WhitelistCheckResponse,
)
from whitelist.rules import PERMANENTLY_BLOCKED_APIS
from whitelist.tables import ApprovedApi


# ─────────────────────────────────────────────
# 정책 호환 — 우리 영구 차단을 양유상 ApiPolicy에 주입
# ─────────────────────────────────────────────

# 양유상 기본 prefix(subprocess.)에 추가로 우리가 차단하고 싶은 prefix들.
# 양유상의 raw_api_calls는 normalize되지 않은 채 들어오므로
# (예: __import__는 'builtins.' 없이) 양유상 기본 정책을 보존하면서
# 우리 PERMANENTLY_BLOCKED_APIS만 추가로 union하는 전략을 쓴다.
_EXTRA_BLOCKED_PREFIX: tuple[str, ...] = (
    "ctypes.",
    "os.exec",
    "os.spawn",
)


def build_compatible_policy(
    *, policy_version: str = DEFAULT_POLICY_VERSION,
) -> ApiPolicy:
    """양유상 기본 ApiPolicy + 우리 PERMANENTLY_BLOCKED_APIS 합집합.

    양유상 기본 정책이 raw 호출(``__import__``, ``eval`` 등)을 잡고
    우리 정책이 ``builtins.__import__``, ``pickle.loads``, ``ctypes.*`` 같은
    fully-qualified 또는 prefix 차단을 담당한다. allowed는 비워두고 우리
    lookup이 DB로 판정한다.
    """
    base = default_api_policy(policy_version=policy_version)
    return ApiPolicy(
        policy_version=base.policy_version,
        allowed_exact=frozenset(),  # 우리 lookup이 ApprovedApi DB로 판정
        blocked_exact=base.blocked_exact | frozenset(PERMANENTLY_BLOCKED_APIS),
        blocked_prefix=tuple(sorted(set(base.blocked_prefix) | set(_EXTRA_BLOCKED_PREFIX))),
        risk_exact=base.risk_exact | frozenset(PERMANENTLY_BLOCKED_APIS),
        risk_prefix=tuple(sorted(set(base.risk_prefix) | set(_EXTRA_BLOCKED_PREFIX))),
        contextual_exact=base.contextual_exact,
        contextual_prefix=base.contextual_prefix,
    )


# ─────────────────────────────────────────────
# WhitelistLookup 어댑터
# ─────────────────────────────────────────────

class WhitelistEngineLookup:
    """양유상 ``WhitelistLookup`` Protocol 만족 어댑터.

    역할:
      - ``is_allowed_exact(api)`` : ``ApprovedApi``에 등록(is_blocked=False)이면 True
      - 미등록 API는 누적했다가 context 종료 시 ``engine.check_batch()``로 일괄
        PENDING 등록 (4-state 판정 + classifier 권고 + audit log + commit)

    사용 예::

        with WhitelistEngineLookup(db, engine, job_id, model) as lookup:
            result = scan_api_policy(ast_scan, whitelist_lookup=lookup)
        # __exit__에서 누적 미등록이 PENDING으로 등록되고 db.commit()
    """

    def __init__(
        self,
        db: Session,
        engine: WhitelistEngine | None = None,
        job_id: str = "",
        model: ModelRef | None = None,
    ) -> None:
        self._db = db
        self._engine = engine or get_engine()
        self._job_id = job_id
        self._model = model
        self._unregistered_apis: list[str] = []
        self._flushed = False

    # Protocol 요구사항
    @property
    def whitelist_version(self) -> str:
        return self._engine.version

    def is_allowed_exact(self, api: str) -> bool:
        """ApprovedApi에 등록되고 차단되지 않은 경우만 True.

        False인 경우 ``api``를 누적해두고, ``flush_pending()`` 또는 context
        종료 시점에 PENDING으로 일괄 등록한다.
        """
        approved = self._db.execute(
            select(ApprovedApi).where(ApprovedApi.api_path == api)
        ).scalar_one_or_none()
        if approved is not None and not approved.is_blocked:
            return True
        if api not in self._unregistered_apis:
            self._unregistered_apis.append(api)
        return False

    # 직접 호출용
    def flush_pending(self) -> list[WhitelistCheckResponse]:
        """누적된 미등록 API들을 4-state 판정 + PENDING 등록.

        멱등하다: 두 번 호출해도 두 번째는 빈 리스트 반환.
        ``engine.check_batch()``가 내부적으로 ``db.commit()``을 호출한다.
        """
        if self._flushed or not self._unregistered_apis:
            self._flushed = True
            return []
        request = WhitelistCheckRequest(
            schema_version="1.0",
            request_id=f"{self._job_id}-pending-flush" if self._job_id else "pending-flush",
            job_id=self._job_id,
            model=self._model or _placeholder_model(),
            apis=list(self._unregistered_apis),
        )
        results = self._engine.check_batch(request, self._db)
        self._unregistered_apis.clear()
        self._flushed = True
        return results

    # context manager
    def __enter__(self) -> "WhitelistEngineLookup":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        # 예외 발생 시에도 누적된 PENDING은 등록한다 (감사 가시성 우선).
        # 단, 호출 측에서 명시적 롤백을 원하면 flush_pending() 전에 직접 처리.
        try:
            self.flush_pending()
        except Exception:
            # 어댑터 단계 실패가 검증 흐름 자체를 깨뜨리지 않도록.
            self._db.rollback()
            raise


# ─────────────────────────────────────────────
# 후처리 헬퍼 — orchestrator 결과에서 PENDING 등록
# ─────────────────────────────────────────────

def register_pending_from_apis(
    db: Session,
    api_paths: Iterable[str],
    *,
    engine: WhitelistEngine | None = None,
    job_id: str = "",
    model: ModelRef | None = None,
) -> list[WhitelistCheckResponse]:
    """양유상 ApiScanResult.pending_api_refs 같은 외부 결과를 받아 PENDING 등록.

    ``WhitelistEngineLookup``을 쓰지 않고 양유상 검증을 끝낸 뒤
    배치로만 등록하고 싶을 때 사용.
    """
    api_list = sorted({a.strip() for a in api_paths if a and a.strip()})
    if not api_list:
        return []
    eng = engine or get_engine()
    request = WhitelistCheckRequest(
        schema_version="1.0",
        request_id=f"{job_id}-batch" if job_id else "batch",
        job_id=job_id,
        model=model or _placeholder_model(),
        apis=api_list,
    )
    return eng.check_batch(request, db)


# ─────────────────────────────────────────────
# 내부 헬퍼
# ─────────────────────────────────────────────

def _placeholder_model() -> ModelRef:
    """ModelRef 미주입 시 placeholder.

    인터페이스 정의서 7.1은 ModelRef 모든 필드를 필수로 두지만, 통합 흐름에서
    검증 단위가 모델 단위가 아닐 수도 있어 안전한 fallback을 둔다.
    audit log에는 그대로 기록되어 origin 추적은 가능.
    """
    from whitelist.models import EndpointMode
    return ModelRef(
        repo_id="unknown",
        revision="unknown",
        source_host="unknown",
        source_url="",
        requested_by="integration",
        requested_at="1970-01-01T00:00:00Z",
        endpoint_mode=EndpointMode.HF_ENDPOINT_PROXY,
    )


__all__ = [
    "WhitelistEngineLookup",
    "build_compatible_policy",
    "register_pending_from_apis",
]
