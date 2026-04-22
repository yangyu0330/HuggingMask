"""Adaptive Whitelist Engine — HuggingMask 김민우

API allow/block/unknown/pending 판정과 pending 저장을 담당한다.

설계 원칙 (whitelist/engine.md):
- 명시적 block 규칙은 allow 규칙보다 우선한다.
- unknown API는 pending 등록 대상으로 넘긴다.
- 결과에는 항상 whitelist_version을 포함한다.
- 자동 분류는 권고이며 실제 승인은 review_status=APPROVED 이후에만 수행한다.
"""

from whitelist.engine import WhitelistEngine, get_engine
from whitelist.rules import WHITELIST_VERSION

__all__ = ["WhitelistEngine", "get_engine", "WHITELIST_VERSION"]
