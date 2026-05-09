from datetime import datetime, timezone


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def build_cache_key(sha256: str, file_kind: str, policy_fingerprint: str):
    return f"{sha256}:{file_kind}:{policy_fingerprint}"


def artifact_id_from_sha256(sha256: str):
    return f"sha256:{sha256}"