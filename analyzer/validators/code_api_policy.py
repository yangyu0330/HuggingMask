"""Stage-5 API policy seeds and lightweight whitelist adapter.

This module keeps only deterministic policy data and test-friendly lookup
adapters. It does not implement a persistent whitelist DB, pending store, or
review queue integration.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

DEFAULT_POLICY_VERSION = "policy-2026.04.20"
DEFAULT_WHITELIST_VERSION = "wl-inmemory-stage5"

_DEFAULT_ALLOWED_EXACT = frozenset(
    {
        "torch.nn.Linear",
        "torch.nn.Embedding",
        "torch.nn.LayerNorm",
        "torch.nn.functional.relu",
        "torch.nn.functional.softmax",
        "torch.Tensor.view",
    }
)

_DEFAULT_BLOCKED_EXACT = frozenset(
    {
        "torch.load",
        "pickle.load",
        "numpy.load",
        "os.system",
    }
)

_DEFAULT_BLOCKED_PREFIX = (
    "subprocess.",
)

_DEFAULT_RISK_EXACT = frozenset(
    {
        "eval",
        "exec",
        "compile",
        "__import__",
        "os.system",
        "torch.load",
        "pickle.load",
        "numpy.load",
    }
)

_DEFAULT_RISK_PREFIX = (
    "subprocess.",
    "requests.",
    "urllib.",
    "httpx.",
    "socket.",
    "os.exec",
    "os.spawn",
)

_DEFAULT_CONTEXTUAL_EXACT = frozenset(
    {
        "open",
        "os.remove",
        "os.unlink",
        "os.rename",
        "os.replace",
        "os.rmdir",
        "os.getenv",
        "os.environ.get",
        "Path.open",
        "Path.read_text",
        "Path.write_text",
        "pathlib.Path.open",
        "pathlib.Path.read_text",
        "pathlib.Path.write_text",
        "shutil.rmtree",
    }
)

_DEFAULT_CONTEXTUAL_PREFIX = (
    "os.path.",
)


@dataclass(frozen=True)
class ApiPolicy:
    """Deterministic API classification policy for stage-5."""

    policy_version: str = DEFAULT_POLICY_VERSION
    allowed_exact: frozenset[str] = _DEFAULT_ALLOWED_EXACT
    blocked_exact: frozenset[str] = _DEFAULT_BLOCKED_EXACT
    blocked_prefix: tuple[str, ...] = _DEFAULT_BLOCKED_PREFIX
    risk_exact: frozenset[str] = _DEFAULT_RISK_EXACT
    risk_prefix: tuple[str, ...] = _DEFAULT_RISK_PREFIX
    contextual_exact: frozenset[str] = _DEFAULT_CONTEXTUAL_EXACT
    contextual_prefix: tuple[str, ...] = _DEFAULT_CONTEXTUAL_PREFIX


@runtime_checkable
class WhitelistLookup(Protocol):
    """Minimal exact-match whitelist lookup protocol."""

    whitelist_version: str

    def is_allowed_exact(self, api: str) -> bool:
        ...


@dataclass
class InMemoryWhitelistLookup:
    """Simple in-memory whitelist adapter for tests and early integration."""

    allowed_exact: set[str] = field(default_factory=set)
    whitelist_version: str = DEFAULT_WHITELIST_VERSION

    def is_allowed_exact(self, api: str) -> bool:
        return api in self.allowed_exact


def default_api_policy(*, policy_version: str = DEFAULT_POLICY_VERSION) -> ApiPolicy:
    return ApiPolicy(policy_version=policy_version)


def build_in_memory_whitelist_lookup(
    *,
    allowed_exact: set[str] | frozenset[str] | None = None,
    whitelist_version: str = DEFAULT_WHITELIST_VERSION,
) -> InMemoryWhitelistLookup:
    return InMemoryWhitelistLookup(
        allowed_exact=set(allowed_exact or set()),
        whitelist_version=whitelist_version,
    )


def matches_exact_or_prefix(api: str, exact: frozenset[str], prefix: tuple[str, ...]) -> bool:
    if api in exact:
        return True
    return any(api.startswith(item) for item in prefix)


def is_blocked_by_policy(api: str, policy: ApiPolicy) -> bool:
    return matches_exact_or_prefix(api, policy.blocked_exact, policy.blocked_prefix)


def is_risk_category_api(api: str, policy: ApiPolicy) -> bool:
    return matches_exact_or_prefix(api, policy.risk_exact, policy.risk_prefix)


def is_contextual_api(api: str, policy: ApiPolicy) -> bool:
    return matches_exact_or_prefix(api, policy.contextual_exact, policy.contextual_prefix)
