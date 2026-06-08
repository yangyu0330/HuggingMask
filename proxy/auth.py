"""Internal API authentication helpers.

The internal API uses opt-in shared-token transport authentication:

* ``HUGGINGMASK_INTERNAL_API_TOKEN`` unset: auth is disabled for local/backward
  compatibility.
* token set to a non-blank value: callers must send ``X-Internal-Token`` or
  ``Authorization: Bearer`` with the same value.
* token set to blank/whitespace: fail closed with 503.

Review decisions add a small principal abstraction. When token auth is enabled,
``X-Reviewer-Id`` is treated as the authenticated reviewer principal and review
payloads must match it. When token auth is disabled, review routes keep the
legacy body fallback.
"""

from __future__ import annotations

from dataclasses import dataclass
import hmac
import os
import re

from fastapi import Header, HTTPException, status

_ENV_TOKEN = "HUGGINGMASK_INTERNAL_API_TOKEN"
_REVIEWER_ID_HEADER = "X-Reviewer-Id"
_REVIEWER_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$")


@dataclass(frozen=True)
class InternalReviewerPrincipal:
    """Authenticated identity for internal review decisions."""

    reviewer_id: str
    source: str = _REVIEWER_ID_HEADER


def _expected_internal_token() -> str | None:
    raw = os.getenv(_ENV_TOKEN)
    if raw is None:
        return None

    expected = raw.strip()
    if not expected:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                f"{_ENV_TOKEN} is set but blank - refusing to serve internal API "
                "without a valid token. Unset the variable to disable auth."
            ),
        )
    return expected


def require_internal_token(
    x_internal_token: str | None = Header(default=None),
    authorization: str | None = Header(default=None),
) -> None:
    """FastAPI dependency for opt-in internal API transport protection."""
    expected = _expected_internal_token()
    if expected is None:
        return

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


def normalize_reviewer_id(value: str | None) -> str | None:
    """Return the canonical reviewer id form accepted for audit identity."""
    if value is None:
        return None
    reviewer_id = value.strip()
    if not reviewer_id or not _REVIEWER_ID_RE.fullmatch(reviewer_id):
        return None
    return reviewer_id


def get_internal_reviewer_principal(
    x_reviewer_id: str | None = Header(default=None, alias=_REVIEWER_ID_HEADER),
) -> InternalReviewerPrincipal | None:
    """Derive reviewer principal for authenticated internal callers."""
    if _expected_internal_token() is None:
        return None

    reviewer_id = normalize_reviewer_id(x_reviewer_id)
    if reviewer_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"missing or invalid {_REVIEWER_ID_HEADER}",
        )
    return InternalReviewerPrincipal(reviewer_id=reviewer_id)


def resolve_reviewer_id_for_review(
    body_reviewer_id: str,
    principal: InternalReviewerPrincipal | None,
) -> str:
    """Validate body reviewer_id against the authenticated reviewer principal."""
    requested = normalize_reviewer_id(body_reviewer_id)
    if requested is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                "reviewer_id must be 1-128 chars using letters, numbers, "
                ". _ : @ or -"
            ),
        )

    if principal is None:
        return requested

    if requested != principal.reviewer_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="reviewer_id does not match authenticated reviewer principal",
        )
    return principal.reviewer_id
