"""전처리/메타 파일 baseline 레지스트리 — 알려진 정상본(known-good) sha256 등록부.

전처리 의미 검증은 '정상 기준본(baseline)'과 비교해 변조 여부를 증명한다. 그 baseline 이
없으면 BASELINE_MISSING 으로 자동 통과 불가(검토대기)였다. 이 레지스트리는 자동화의 A 계층:

  * 인기 base 모델(bert-base, gpt2 등)의 tokenizer/config sha256 을 미리 등록(seed).
  * verified org 에서 처음 본 정상 전처리를 등록(TOFU) 할 수도 있다.
  * 검사 시 파일 sha256 이 등록부에 있으면 → 그 파일을 '정상 기준 확인됨'으로 보고,
    자기 자신을 baseline 으로 사용(sha256 자기-일치 → semantic preserved → PASS).

같은 토크나이저는 수많은 파인튜닝 모델에서 내용이 동일(=같은 sha256)하므로, 적은 시드로도
대부분의 전처리가 자동 통과된다.

레지스트리 파일 경로는 ``HUGGINGMASK_BASELINE_REGISTRY`` 로 덮어쓸 수 있다(기본:
``analyzer/assets/preprocessing_baselines.json``).
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_DEFAULT_PATH = (
    Path(__file__).resolve().parents[2] / "analyzer" / "assets" / "preprocessing_baselines.json"
)


def _registry_path() -> Path:
    override = os.getenv("HUGGINGMASK_BASELINE_REGISTRY")
    return Path(override) if override else _DEFAULT_PATH


def sha256_of(source: str | bytes) -> str:
    data = source.encode("utf-8") if isinstance(source, str) else source
    return hashlib.sha256(data).hexdigest()


# in-process 캐시 — 파일은 변경 빈도가 낮다. reload() 로 강제 갱신.
_cache: dict[str, Any] | None = None


def _load() -> dict[str, Any]:
    global _cache
    if _cache is None:
        try:
            raw = json.loads(_registry_path().read_text(encoding="utf-8"))
            entries = raw.get("sha256")
            _cache = entries if isinstance(entries, dict) else {}
        except Exception:  # noqa: BLE001 — 레지스트리 없거나 깨지면 빈 등록부(=전부 검토대기)
            _cache = {}
    return _cache


def reload() -> None:
    """레지스트리 파일을 다시 읽도록 캐시 무효화."""
    global _cache
    _cache = None


def is_known_baseline(source: str | bytes) -> bool:
    """파일 내용 sha256 이 등록된 정상본 목록에 있으면 True."""
    return sha256_of(source) in _load()


def lookup_baseline_source(source: str | bytes) -> str | bytes | None:
    """등록된 정상본과 sha256 일치 시 그 source 를 baseline 으로 반환(자기-일치 → preserved).

    미등록이면 None(→ 기존대로 BASELINE_MISSING → 검토대기 또는 의미 불변식 검사로 위임).
    """
    return source if is_known_baseline(source) else None


def register_baseline(
    source: str | bytes,
    *,
    repo_id: str = "",
    file_name: str = "",
    note: str = "",
    persist: bool = True,
) -> str:
    """정상본을 레지스트리에 등록(TOFU/시드). sha256 을 반환한다."""
    digest = sha256_of(source)
    store = _load()
    if digest not in store:
        store[digest] = {
            "repo_id": repo_id,
            "file_name": file_name,
            "note": note,
            "registered_at": datetime.now(timezone.utc).isoformat(),
        }
        if persist:
            _save(store)
    return digest


def _save(store: dict[str, Any]) -> None:
    path = _registry_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    doc = {
        "version": 1,
        "description": "Known-good preprocessing/metadata file sha256 (seeded + TOFU)",
        "sha256": store,
    }
    path.write_text(json.dumps(doc, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
