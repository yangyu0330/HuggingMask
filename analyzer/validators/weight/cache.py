from __future__ import annotations

import copy
import hashlib
import hmac
import json
import os
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[3]
CACHE_FILE = PROJECT_ROOT / ".cache" / "weight_validator_cache.json"


def _cache_dir() -> Path:
    return CACHE_FILE.parent


def _lock_file() -> Path:
    return CACHE_FILE.with_suffix(CACHE_FILE.suffix + ".lock")


_DEFAULT_HMAC_KEY = "dev-only-weight-cache-hmac-key"


def _hmac_key() -> bytes:
    # 운영 환경에서는 WEIGHT_CACHE_HMAC_KEY 환경변수를 주입하는 것을 권장.
    key = os.getenv("WEIGHT_CACHE_HMAC_KEY")
    if key:
        return key.encode("utf-8")
    # env 미설정 → dev 기본 키. 기본 키는 공개값이라 누구나 위조 캐시 엔트리에
    # 유효 서명을 만들어 검증 우회 PASS를 주입할 수 있다. 운영에서는
    # HUGGINGMASK_REQUIRE_CACHE_KEY를 켜서 기본 키 사용 자체를 차단한다.
    if os.getenv("HUGGINGMASK_REQUIRE_CACHE_KEY", "").strip().lower() in {"1", "true", "yes", "on"}:
        raise RuntimeError(
            "WEIGHT_CACHE_HMAC_KEY가 설정되지 않았습니다. 운영 환경에서는 "
            "기본(dev) 캐시 서명 키를 사용할 수 없습니다 (위조 캐시 주입 위험)."
        )
    return _DEFAULT_HMAC_KEY.encode("utf-8")


def _canonical_json(obj: Any) -> bytes:
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _signature(cache_key: str, result: dict[str, Any]) -> str:
    payload = {
        "cache_key": cache_key,
        "result": result,
    }

    return hmac.new(
        _hmac_key(),
        _canonical_json(payload),
        hashlib.sha256,
    ).hexdigest()


def _valid_signature(cache_key: str, result: dict[str, Any], signature: str) -> bool:
    expected = _signature(cache_key, result)
    return hmac.compare_digest(expected, signature)


@contextmanager
def _file_lock():
    _cache_dir().mkdir(parents=True, exist_ok=True)

    lock_path = _lock_file()

    with lock_path.open("a+b") as lock_fp:
        lock_fp.seek(0)
        lock_fp.write(b"0")
        lock_fp.flush()
        lock_fp.seek(0)

        if os.name == "nt":
            import msvcrt

            msvcrt.locking(lock_fp.fileno(), msvcrt.LK_LOCK, 1)
            try:
                yield
            finally:
                lock_fp.seek(0)
                msvcrt.locking(lock_fp.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(lock_fp.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(lock_fp.fileno(), fcntl.LOCK_UN)


def _empty_store() -> dict[str, Any]:
    return {
        "version": 1,
        "entries": {},
    }


def _load_unlocked() -> dict[str, Any]:
    if not CACHE_FILE.exists():
        return _empty_store()

    try:
        data = json.loads(CACHE_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return _empty_store()

    if not isinstance(data, dict):
        return _empty_store()

    if data.get("version") != 1:
        return _empty_store()

    entries = data.get("entries")
    if not isinstance(entries, dict):
        return _empty_store()

    return data


def _save_unlocked(data: dict[str, Any]) -> None:
    _cache_dir().mkdir(parents=True, exist_ok=True)

    fd, tmp_name = tempfile.mkstemp(
        prefix=".weight-cache-",
        suffix=".tmp",
        dir=str(_cache_dir()),
        text=True,
    )

    tmp_path = Path(tmp_name)

    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fp:
            json.dump(data, fp, indent=2, ensure_ascii=False)
            fp.write("\n")

        os.replace(tmp_path, CACHE_FILE)

    finally:
        if tmp_path.exists():
            tmp_path.unlink(missing_ok=True)


def get_cache(cache_key: str):
    with _file_lock():
        data = _load_unlocked()
        entry = data.get("entries", {}).get(cache_key)

        if not isinstance(entry, dict):
            return None

        result = entry.get("result")
        signature = entry.get("signature")

        if not isinstance(result, dict):
            return None

        if not isinstance(signature, str):
            return None

        if not _valid_signature(cache_key, result, signature):
            return None

        return copy.deepcopy(result)


def set_cache(cache_key: str, result: dict[str, Any]) -> None:
    with _file_lock():
        data = _load_unlocked()
        entries = data.setdefault("entries", {})

        safe_result = copy.deepcopy(result)

        entries[cache_key] = {
            "result": safe_result,
            "signature": _signature(cache_key, safe_result),
        }

        _save_unlocked(data)