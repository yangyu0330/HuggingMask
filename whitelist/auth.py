"""내부 API 인증 — opt-in 공유 시크릿 토큰.

``/internal/*`` 엔드포인트(검증 요청, 화이트리스트 review/approve, audit 등)는
지금까지 ``Depends(get_db)``만 있고 인증이 없어, 프록시에 도달 가능한 누구나
PENDING API를 자가 승인할 수 있었다(권한 상승). 이를 막되 기존 동작을 깨지
않도록 **opt-in**으로 설계한다.

정책:
  - 환경변수 ``HUGGINGMASK_INTERNAL_API_TOKEN``이 설정돼 있으면 ``/internal/*``
    엔드포인트는 ``X-Internal-Token`` 헤더(또는 ``Authorization: Bearer <token>``)
    로 일치하는 토큰을 요구한다. 불일치/누락 시 401.
  - 미설정(기본)이면 인증 비활성 — 기존 테스트/대시보드/호출자와 호환.
  - 토큰 비교는 ``hmac.compare_digest``로 상수시간(타이밍 공격 방지).

주의: 인증을 켜면 ``/dashboard`` UI의 JS가 ``/internal/v1/*``을 직접 호출하므로
운영자는 UI/프록시에 토큰 주입을 별도로 구성해야 한다. ``/health``·``/``·
``/dashboard`` 자체는 인증 대상이 아니다.
"""

from __future__ import annotations

import hmac
import os

from fastapi import Header, HTTPException, status

_ENV_TOKEN = "HUGGINGMASK_INTERNAL_API_TOKEN"


def _expected_token() -> str:
    return os.getenv(_ENV_TOKEN, "").strip()


def require_internal_token(
    x_internal_token: str | None = Header(default=None),
    authorization: str | None = Header(default=None),
) -> None:
    """``/internal/*`` 보호용 FastAPI 의존성.

    토큰 미설정이면 통과(no-op). 설정돼 있으면 헤더 토큰 일치를 강제.
    """
    expected = _expected_token()
    if not expected:
        return  # 인증 비활성 (기본)

    provided = x_internal_token
    if not provided and authorization:
        scheme, _, value = authorization.partition(" ")
        if scheme.lower() == "bearer":
            provided = value.strip()

    if not provided or not hmac.compare_digest(provided, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid or missing internal API token",
        )
