import json
from pathlib import Path
from typing import Any

CACHE_FILE = Path("cache_store.json")


def _load() -> dict[str, Any]:
    if CACHE_FILE.exists():
        return json.loads(CACHE_FILE.read_text(encoding="utf-8"))
    return {}


def _save(data: dict[str, Any]) -> None:
    CACHE_FILE.write_text(
        json.dumps(data, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def get_cache(cache_key: str):
    return _load().get(cache_key)


def set_cache(cache_key: str, result: dict[str, Any]) -> None:
    data = _load()
    data[cache_key] = result
    _save(data)