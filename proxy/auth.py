"""내부 API 인증 — opt-in 공유 시크릿 토큰.

``/internal/*`` 엔드포인트(검증 요청, 화이트리스트 review/approve, audit 등)는
지금까지 ``Depends(get_db)``만 있고 인증이 없어, 프록시에 도달 가능한 누구나
PENDING API를 자가 승인할 수 있었다(권한 상승). 이를 막되 기존 동작을 깨지
않도록 **opt-in**으로 설계한다.

정책:
  - ``HUGGINGMASK_INTERNAL_API_TOKEN`` **미설정(unset)** → 인증 비활성(no-op).
    기존 테스트/대시보드/호출자와 호환.
  - 설정됐고 유효한 값 → ``X-Internal-Token``(또는 ``Authorization: Bearer``)
    헤더가 일치해야 통과. 불일치/누락 → 401.
  - **설정됐는데 빈 문자열/공백** → 운영자가 "켰다"고 믿는데 실제로는 열린
    상태가 되는 fail-open이므로, 그렇게 두지 않고 fail-closed(503)로 거부한다.
    (양유상 PR #54 리뷰 P1)
  - 토큰 비교는 ``hmac.compare_digest``로 상수시간(타이밍 공격 방지).

범위 한계(정직 고지 — 양유상 P3):
  이 모듈은 transport-level 최소 보호다. ``/internal/v1/review``의
  ``reviewer_id``는 여전히 payload 신뢰이므로, 공유 시크릿을 아는 주체는 임의
  ``reviewer_id``를 보낼 수 있다. "보안 담당자가 승인했다"는 정체성 보장은
  후속 작업(인증 계층에서 reviewer identity 도출)이 필요하다.

위치(양유상 P4): proxy(FastAPI 진입점)의 transport auth이므로 whitelist 정책
모듈이 아니라 ``proxy/auth.py``에 둔다.
"""

from __future__ import annotations

import hmac
import os

from fastapi import Header, HTTPException, status

_ENV_TOKEN = "HUGGINGMASK_INTERNAL_API_TOKEN"


def require_internal_token(
    x_internal_token: str | None = Header(default=None),
    authorization: str | None = Header(default=None),
) -> None:
    """``/internal/*`` 보호용 FastAPI 의존성.

    토큰 미설정이면 통과(no-op). 빈/공백이면 fail-closed(503). 설정돼 있으면
    헤더 토큰 일치를 강제.
    """
    raw = os.getenv(_ENV_TOKEN)
    if raw is None:
        return  # 인증 비활성(기본, opt-in)

    expected = raw.strip()
    if not expected:
        # unset과 blank를 구분: blank는 운영자 오인 → 열린 상태로 두지 않는다.
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                f"{_ENV_TOKEN} is set but blank — refusing to serve internal API "
                "without a valid token. Unset the variable to disable auth."
            ),
        )

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
